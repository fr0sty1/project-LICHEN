//! Async TCP client for the LICHEN simulator node server.
//!
//! Wire format: each message is framed with a 4-byte LE length prefix.
//! The first byte of the body is the message type (matches
//! `python/src/lichen/sim/protocol.py`). The client must send REGISTER
//! before any TX / RX / TIME messages.

use std::borrow::Cow;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

// Message type constants
const MSG_OK: u8 = 0x00;
const MSG_REGISTER: u8 = 0x01;
const MSG_TX: u8 = 0x10;
const MSG_TX_DONE: u8 = 0x11;
const MSG_TX_FAIL: u8 = 0x12;
const MSG_RX: u8 = 0x20;
const MSG_RX_OK: u8 = 0x21;
const MSG_RX_TIMEOUT: u8 = 0x22;
const MSG_TIME: u8 = 0x30;
const MSG_TIME_OK: u8 = 0x31;
const MSG_ERR: u8 = 0xFF;

/// Maximum message size to prevent DoS via unbounded allocation.
/// 128 KiB is generous for any legitimate simulator message (covers
/// max RX_OK of ~65.5 KiB).
const MAX_MSG_LEN: usize = 128 * 1024;

/// Errors returned by [`SimClient`].
#[derive(Debug)]
#[non_exhaustive]
pub enum SimError {
    Io(std::io::Error),
    /// Server returned an ERR response.
    Server {
        code: u8,
        message: Cow<'static, str>,
    },
    /// Response did not match the expected message type.
    Protocol(&'static str),
    /// Simulator rejected the TX (TX_FAIL).
    TxFailed,
}

impl std::fmt::Display for SimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SimError::Io(e) => write!(f, "I/O error: {e}"),
            SimError::Server { code, message } => write!(f, "server error {code}: {message}"),
            SimError::Protocol(s) => write!(f, "protocol error: {s}"),
            SimError::TxFailed => write!(f, "TX_FAIL from simulator"),
        }
    }
}

impl From<std::io::Error> for SimError {
    fn from(e: std::io::Error) -> Self {
        SimError::Io(e)
    }
}

impl std::error::Error for SimError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Async TCP client for the LICHEN node server.
///
/// Call [`SimClient::connect`] to connect and register, then use
/// [`transmit`](SimClient::transmit) / [`receive`](SimClient::receive) in a
/// loop. The protocol is strictly request → response: do not call both
/// concurrently from different tasks without external synchronisation.
#[derive(Debug)]
pub struct SimClient {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    /// Set when a protocol error leaves the stream in an inconsistent state.
    /// Once poisoned, all further operations will fail.
    poisoned: bool,
}

impl SimClient {
    /// Connect to `addr`, send REGISTER, and await the server's OK.
    pub async fn connect(
        addr: SocketAddr,
        sim_id: &str,
        node_id: &str,
        x: f64,
        y: f64,
        z: f64,
    ) -> Result<Self, SimError> {
        let stream = TcpStream::connect(addr).await?;
        let (r, w) = stream.into_split();
        let mut client = Self {
            reader: BufReader::new(r),
            writer: w,
            poisoned: false,
        };
        client.register(sim_id, node_id, x, y, z).await?;
        Ok(client)
    }

    async fn register(
        &mut self,
        sim_id: &str,
        node_id: &str,
        x: f64,
        y: f64,
        z: f64,
    ) -> Result<(), SimError> {
        let sid = sim_id.as_bytes();
        let nid = node_id.as_bytes();
        if sid.len() > u8::MAX as usize {
            return Err(SimError::Protocol("sim_id exceeds 255 bytes"));
        }
        if nid.len() > u8::MAX as usize {
            return Err(SimError::Protocol("node_id exceeds 255 bytes"));
        }
        let mut body = Vec::with_capacity(1 + 1 + sid.len() + 1 + nid.len() + 24);
        body.push(MSG_REGISTER);
        body.push(sid.len() as u8);
        body.extend_from_slice(sid);
        body.push(nid.len() as u8);
        body.extend_from_slice(nid);
        body.extend_from_slice(&x.to_le_bytes());
        body.extend_from_slice(&y.to_le_bytes());
        body.extend_from_slice(&z.to_le_bytes());
        self.send_msg(&body).await?;

        let resp = self.recv_msg().await?;
        match resp.first().copied() {
            Some(MSG_OK) => Ok(()),
            Some(MSG_ERR) => Err(parse_err(&resp[1..])),
            _ => Err(SimError::Protocol("unexpected response to REGISTER")),
        }
    }

    /// Transmit `payload` over the simulated radio.
    ///
    /// Returns airtime in microseconds on success.
    pub async fn transmit(&mut self, payload: &[u8]) -> Result<u32, SimError> {
        if payload.len() > u16::MAX as usize {
            return Err(SimError::Protocol("payload exceeds 65535 bytes"));
        }
        let mut body = Vec::with_capacity(3 + payload.len());
        body.push(MSG_TX);
        body.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        body.extend_from_slice(payload);
        self.send_msg(&body).await?;

        let resp = self.recv_msg().await?;
        match resp.first().copied() {
            Some(MSG_TX_DONE) => {
                if resp.len() < 5 {
                    return Err(SimError::Protocol("TX_DONE too short"));
                }
                Ok(u32::from_le_bytes(resp[1..5].try_into().unwrap()))
            }
            Some(MSG_TX_FAIL) => Err(SimError::TxFailed),
            Some(MSG_ERR) => Err(parse_err(&resp[1..])),
            _ => Err(SimError::Protocol("unexpected response to TX")),
        }
    }

    /// Wait up to `timeout_ms` for an incoming frame.
    ///
    /// Returns `None` on timeout, `Some((payload, rssi, snr))` on success.
    pub async fn receive(
        &mut self,
        timeout_ms: u32,
    ) -> Result<Option<(Vec<u8>, i16, i16)>, SimError> {
        let mut body = [0u8; 5];
        body[0] = MSG_RX;
        body[1..5].copy_from_slice(&timeout_ms.to_le_bytes());
        self.send_msg(&body).await?;

        let resp = self.recv_msg().await?;
        match resp.first().copied() {
            Some(MSG_RX_OK) => {
                if resp.len() < 3 {
                    return Err(SimError::Protocol("RX_OK too short"));
                }
                let plen = u16::from_le_bytes([resp[1], resp[2]]) as usize;
                if resp.len() < 3 + plen + 4 {
                    return Err(SimError::Protocol("RX_OK truncated"));
                }
                let payload = resp[3..3 + plen].to_vec();
                let rssi = i16::from_le_bytes([resp[3 + plen], resp[4 + plen]]);
                let snr = i16::from_le_bytes([resp[5 + plen], resp[6 + plen]]);
                Ok(Some((payload, rssi, snr)))
            }
            Some(MSG_RX_TIMEOUT) => Ok(None),
            Some(MSG_ERR) => Err(parse_err(&resp[1..])),
            _ => Err(SimError::Protocol("unexpected response to RX")),
        }
    }

    /// Query current simulation time in microseconds.
    pub async fn time_us(&mut self) -> Result<u64, SimError> {
        self.send_msg(&[MSG_TIME]).await?;

        let resp = self.recv_msg().await?;
        match resp.first().copied() {
            Some(MSG_TIME_OK) => {
                if resp.len() < 9 {
                    return Err(SimError::Protocol("TIME_OK too short"));
                }
                Ok(u64::from_le_bytes(resp[1..9].try_into().unwrap()))
            }
            Some(MSG_ERR) => Err(parse_err(&resp[1..])),
            _ => Err(SimError::Protocol("unexpected response to TIME")),
        }
    }

    async fn send_msg(&mut self, body: &[u8]) -> Result<(), SimError> {
        if self.poisoned {
            return Err(SimError::Protocol(
                "connection poisoned by prior protocol error",
            ));
        }
        self.writer
            .write_all(&(body.len() as u32).to_le_bytes())
            .await?;
        self.writer.write_all(body).await?;
        Ok(())
    }

    async fn recv_msg(&mut self) -> Result<Vec<u8>, SimError> {
        if self.poisoned {
            return Err(SimError::Protocol(
                "connection poisoned by prior protocol error",
            ));
        }
        let mut len_bytes = [0u8; 4];
        self.reader.read_exact(&mut len_bytes).await?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        // SECURITY: Bound allocation to prevent DoS from malicious length values.
        // If the message is too large, we've consumed the 4-byte header but cannot
        // safely read the body (could be gigabytes). Mark connection poisoned to
        // prevent desync on subsequent calls.
        if len > MAX_MSG_LEN {
            self.poisoned = true;
            return Err(SimError::Protocol("message too large"));
        }
        let mut body = vec![0u8; len];
        self.reader.read_exact(&mut body).await?;
        Ok(body)
    }
}

fn parse_err(payload: &[u8]) -> SimError {
    if payload.len() < 2 {
        return SimError::Protocol("ERR response too short");
    }
    let code = payload[0];
    let msg_len = payload[1] as usize;
    let message: Cow<'static, str> = if payload.len() >= 2 + msg_len {
        Cow::Owned(String::from_utf8_lossy(&payload[2..2 + msg_len]).into_owned())
    } else {
        Cow::Borrowed("(truncated)")
    };
    SimError::Server { code, message }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_err_well_formed() {
        // code=4, msg="hello"
        let payload = [4u8, 5, b'h', b'e', b'l', b'l', b'o'];
        let e = parse_err(&payload);
        match e {
            SimError::Server { code, message } => {
                assert_eq!(code, 4);
                assert_eq!(message.as_ref(), "hello");
            }
            _ => assert!(matches!(e, SimError::Server { .. })),
        }
    }

    #[test]
    fn parse_err_too_short() {
        let e = parse_err(&[]);
        assert!(matches!(e, SimError::Protocol(_)));
    }
}
