// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Simulation radio that bridges to lichen-sim via TCP.
//!
//! Allows running Rust firmware in QEMU/Renode with packet transfer
//! through lichen-sim's simulated RF medium.
//!
//! Protocol matches LichenSubGHz.cs (Renode peripheral):
//! - TX: [len:4][0x10][payload_len:2][payload] → [len:4][0x11][airtime:4]
//! - RX: [len:4][0x24][timeout_us:4] → [len:4][0x27][len:2][payload][rssi:2][snr:2] or [len:4][0x28]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use lichen_hal::{ChannelConfig, Radio, RadioConfig, RadioError, RxPacket};
use sha2::{Digest, Sha256};

/// Radio that connects to lichen-sim for packet transfer.
///
/// Use this when running firmware in QEMU or other emulators that don't
/// simulate real LoRa hardware.
pub struct SimRadio {
    stream: TcpStream,
    config: RadioConfig,
}

/// Type alias for SimRadio errors using the common RadioError type.
/// Uses std::io::Error as the bus error type for connection errors.
pub type SimError = RadioError<std::io::Error>;

/// Configuration for connecting and registering with lichen-sim.
///
/// Controls timeouts used during the TCP connect and registration handshake.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    /// Maximum time to wait for the TCP connection to be established.
    /// `None` uses the OS default.
    pub connect_timeout: Option<Duration>,
    /// Maximum time to wait for each read response during registration.
    /// Must be non-zero.
    pub read_timeout: Duration,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Some(Duration::from_secs(5)),
            read_timeout: Duration::from_millis(100),
        }
    }
}

/// Parse an MSG_ERR (0xFF) response body and return a descriptive message.
fn parse_server_error(payload: &[u8]) -> String {
    if payload.len() < 2 {
        return format!("server error (truncated, {} bytes)", payload.len());
    }
    let code = payload[0];
    let msg_len = payload[1] as usize;
    if payload.len() < 2 + msg_len {
        format!("server error {} (truncated message)", code)
    } else {
        let msg = String::from_utf8_lossy(&payload[2..2 + msg_len]);
        format!("server error {}: {}", code, msg)
    }
}

impl SimRadio {
    /// Connect to lichen-sim with the given configuration.
    ///
    /// Default address is 127.0.0.1:5555.
    pub fn connect_with_config(host: &str, port: u16, cfg: &ConnectConfig) -> Result<Self, SimError> {
        let addr = format!("{}:{}", host, port);
        let stream = if let Some(timeout) = cfg.connect_timeout {
            let dur = std::time::Instant::now() + timeout;
            // Use the per-socket timeout for connect via TcpStream::connect_timeout
            // on nightly or through socket2. For stable, we use set_write_timeout
            // as a coarse approximation and connect normally.
            let s = TcpStream::connect_timeout(
                &addr.parse().map_err(|e| RadioError::Bus(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?,
                timeout,
            )
            .map_err(RadioError::Bus)?;
            s
        } else {
            TcpStream::connect(&addr).map_err(RadioError::Bus)?
        };
        stream.set_nodelay(true).map_err(RadioError::Bus)?;
        stream
            .set_read_timeout(Some(cfg.read_timeout))
            .map_err(RadioError::Bus)?;

        Ok(Self {
            stream,
            config: RadioConfig::default(),
        })
    }

    /// Connect to lichen-sim.
    ///
    /// Default address is 127.0.0.1:5555. Uses 5-second connect timeout and
    /// 100ms read timeout.
    pub fn connect(host: &str, port: u16) -> Result<Self, SimError> {
        Self::connect_with_config(host, port, &ConnectConfig::default())
    }

    /// Connect and register this node with the simulator before using the radio.
    ///
    /// Uses default connect/read timeouts (5s connect, 100ms read).
    pub fn connect_registered(
        host: &str,
        port: u16,
        sim_id: &str,
        node_id: &str,
        position: (f64, f64, f64),
    ) -> Result<Self, SimError> {
        Self::connect_registered_with_config(host, port, sim_id, node_id, position, &ConnectConfig::default())
    }

    /// Connect and register this node with explicit configuration.
    ///
    /// The `cfg` parameter controls TCP connect timeout and registration
    /// read timeout. Server error responses (MSG_ERR) are parsed and the
    /// diagnostic code/message is included in the returned error description.
    pub fn connect_registered_with_config(
        host: &str,
        port: u16,
        sim_id: &str,
        node_id: &str,
        position: (f64, f64, f64),
        cfg: &ConnectConfig,
    ) -> Result<Self, SimError> {
        let mut radio = Self::connect_with_config(host, port, cfg)?;
        if sim_id.len() > u8::MAX as usize || node_id.len() > u8::MAX as usize {
            return Err(RadioError::Protocol);
        }

        let mut message = Vec::with_capacity(2 + sim_id.len() + node_id.len() + 24);
        message.push(0x01); // MSG_REGISTER
        message.push(sim_id.len() as u8);
        message.extend_from_slice(sim_id.as_bytes());
        message.push(node_id.len() as u8);
        message.extend_from_slice(node_id.as_bytes());
        message.extend_from_slice(&position.0.to_le_bytes());
        message.extend_from_slice(&position.1.to_le_bytes());
        message.extend_from_slice(&position.2.to_le_bytes());
        radio.send_message(&message)?;

        let response = radio.recv_message()?;
        match response.first().copied() {
            Some(0x00) => Ok(radio),
            Some(0xFF) => {
                let diag = parse_server_error(&response[1..]);
                eprintln!("[sim] registration rejected: {}", diag);
                Err(RadioError::Protocol)
            }
            Some(b) => {
                eprintln!("[sim] unexpected registration response byte: 0x{:02x}", b);
                Err(RadioError::Protocol)
            }
            None => {
                eprintln!("[sim] empty registration response");
                Err(RadioError::Protocol)
            }
        }
    }

    /// Connect to default lichen-sim address (127.0.0.1:5555).
    pub fn connect_default() -> Result<Self, SimError> {
        Self::connect("127.0.0.1", 5555)
    }

    fn send_message(&mut self, msg: &[u8]) -> Result<(), SimError> {
        // Length prefix (little-endian u32)
        let len = msg.len() as u32;
        self.stream
            .write_all(&len.to_le_bytes())
            .map_err(RadioError::Bus)?;
        self.stream.write_all(msg).map_err(RadioError::Bus)?;
        self.stream.flush().map_err(RadioError::Bus)?;
        Ok(())
    }

    fn recv_message(&mut self) -> Result<Vec<u8>, SimError> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(RadioError::Bus)?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len == 0 {
            return Ok(Vec::new());
        }
        if len > 1024 {
            return Err(RadioError::Protocol);
        }

        // Read payload
        let mut data = vec![0u8; len];
        self.stream.read_exact(&mut data).map_err(RadioError::Bus)?;
        Ok(data)
    }
}

impl Radio for SimRadio {
    type Error = SimError;

    async fn transmit(&mut self, channel: u8, payload: &[u8]) -> Result<(), Self::Error> {
        if payload.len() > u16::MAX as usize {
            return Err(RadioError::Protocol);
        }
        let mut msg = Vec::with_capacity(3 + payload.len());
        msg.push(0x10);
        msg.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        msg.extend_from_slice(payload);

        self.send_message(&msg)?;

        let resp = self.recv_message()?;
        if resp.is_empty() || resp[0] != 0x11 {
            return Err(RadioError::Protocol);
        }

        let hash = Sha256::digest(payload);
        eprintln!(
            "[TX ch={}] len={} hash={} hex={}",
            channel,
            payload.len(),
            hex::encode(&hash[..8]),
            hex::encode(payload)
        );

        Ok(())
    }

    async fn receive(
        &mut self,
        channel: u8,
        buf: &mut [u8],
        timeout_ms: u32,
    ) -> Result<Option<RxPacket>, Self::Error> {
        let timeout_us = (timeout_ms as u64) * 1000;
        let timeout_us = timeout_us.min(u32::MAX as u64) as u32;

        let read_timeout = Duration::from_millis(timeout_ms as u64 + 1000);
        self.stream
            .set_read_timeout(Some(read_timeout))
            .map_err(RadioError::Bus)?;

        let mut msg = [0u8; 5];
        msg[0] = 0x24;
        msg[1..5].copy_from_slice(&timeout_us.to_le_bytes());
        self.send_message(&msg)?;

        let resp = self.recv_message()?;

        if resp.is_empty() {
            return Err(RadioError::Protocol);
        }

        match resp[0] {
            0x27 => {
                if resp.len() < 3 {
                    return Err(RadioError::Protocol);
                }

                let payload_len = u16::from_le_bytes([resp[1], resp[2]]) as usize;
                if resp.len() < 3 + payload_len + 4 {
                    return Err(RadioError::Protocol);
                }

                if payload_len > buf.len() {
                    return Err(RadioError::Protocol);
                }
                buf[..payload_len].copy_from_slice(&resp[3..3 + payload_len]);

                let rssi_offset = 3 + payload_len;
                let rssi = i16::from_le_bytes([resp[rssi_offset], resp[rssi_offset + 1]]);
                let snr = i16::from_le_bytes([resp[rssi_offset + 2], resp[rssi_offset + 3]]);

                let hash = Sha256::digest(&buf[..payload_len]);
                eprintln!(
                    "[RX ch={}] len={} rssi={} snr={} hash={} hex={}",
                    channel,
                    payload_len,
                    rssi,
                    snr,
                    hex::encode(&hash[..8]),
                    hex::encode(&buf[..payload_len])
                );

                Ok(Some(RxPacket {
                    len: payload_len,
                    rssi: Some(rssi),
                    snr: Some(snr.clamp(i8::MIN as i16, i8::MAX as i16) as i8),
                }))
            }
            0x28 => Ok(None),
            _ => Err(RadioError::Protocol),
        }
    }

    fn configure(&mut self, config: &RadioConfig) {
        self.config = *config;
    }

    async fn configure_channels(&mut self, _channels: &[ChannelConfig]) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn cca(&mut self, channel: u8, _threshold_dbm: i8) -> Result<bool, Self::Error> {
        eprintln!("[CCA ch={}] clear", channel);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn sim_radio_error_display() {
        let err: SimError = RadioError::Protocol;
        assert!(format!("{:?}", err).contains("Protocol"));
    }

    #[test]
    fn connect_registered_sends_register_before_returning() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0u8; 4];
            stream.read_exact(&mut length).unwrap();
            let mut message = vec![0u8; u32::from_le_bytes(length) as usize];
            stream.read_exact(&mut message).unwrap();

            let mut expected = vec![0x01, 4];
            expected.extend_from_slice(b"mesh");
            expected.push(6);
            expected.extend_from_slice(b"rust-1");
            expected.extend_from_slice(&1.5f64.to_le_bytes());
            expected.extend_from_slice(&(-2.0f64).to_le_bytes());
            expected.extend_from_slice(&3.25f64.to_le_bytes());
            assert_eq!(message, expected);

            stream.write_all(&1u32.to_le_bytes()).unwrap();
            stream.write_all(&[0x00]).unwrap();
        });

        SimRadio::connect_registered("127.0.0.1", port, "mesh", "rust-1", (1.5, -2.0, 3.25))
            .unwrap();
        server.join().unwrap();
    }

    #[test]
    fn connect_registered_reports_server_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // consume the REGISTER message
            let mut length = [0u8; 4];
            stream.read_exact(&mut length).unwrap();
            let mut message = vec![0u8; u32::from_le_bytes(length) as usize];
            stream.read_exact(&mut message).unwrap();
            assert_eq!(message[0], 0x01);

            // respond with MSG_ERR: code=4, msg="duplicate node"
            let err_body = [0xFF, 4, 13, b'd', b'u', b'p', b'l', b'i', b'c', b'a', b't', b'e', b' ', b'n', b'o', b'd', b'e'];
            let len = err_body.len() as u32;
            let mut resp = Vec::from(len.to_le_bytes());
            resp.extend_from_slice(&err_body);
            stream.write_all(&resp).unwrap();
        });

        let result = SimRadio::connect_registered("127.0.0.1", port, "mesh", "rust-1", (1.5, -2.0, 3.25));
        assert!(result.is_err());
        server.join().unwrap();
    }

    #[test]
    fn parse_server_error_well_formed() {
        let payload = [4u8, 5, b'h', b'e', b'l', b'l', b'o'];
        let msg = parse_server_error(&payload);
        assert!(msg.contains("error 4"));
        assert!(msg.contains("hello"));
    }

    #[test]
    fn parse_server_error_truncated() {
        let msg = parse_server_error(&[]);
        assert!(msg.contains("truncated"));
        assert!(msg.contains("0"));
    }

    #[test]
    fn connect_config_defaults() {
        let cfg = ConnectConfig::default();
        assert_eq!(cfg.connect_timeout, Some(Duration::from_secs(5)));
        assert_eq!(cfg.read_timeout, Duration::from_millis(100));
    }
}
