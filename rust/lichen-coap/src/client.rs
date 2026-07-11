//! Async UDP CoAP client (requires `tokio` feature).
//!
//! Sends a single CoAP request and waits for a response, with a 5-second
//! timeout.  Supports GET, POST, and PUT with optional CBOR payloads.
//!
//! This is intentionally minimal — no retransmission logic, no Observe, no
//! block-wise transfer.  It is suitable for CLI and TUI tools that talk to a
//! local LICHEN node over the loopback or LAN.

use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use crate::codec::CoapBuilder;
use crate::message::{MessageCode, MessageType};

const TIMEOUT_S: u64 = 5;
/// Content-Format value for CBOR (RFC 7049).
const CONTENT_FORMAT_CBOR: u16 = 60;

/// A decoded CoAP response.
#[derive(Debug)]
pub struct Response {
    /// Raw CoAP code byte (class in upper 3 bits, detail in lower 5).
    pub code: u8,
    /// Response payload (empty if none).
    pub payload: Vec<u8>,
}

impl Response {
    /// True for 2.xx success codes.
    pub fn is_success(&self) -> bool {
        self.code >> 5 == 2
    }

    /// Human-readable code string, e.g. `"2.05"`.
    pub fn code_str(&self) -> String {
        format!("{}.{:02}", self.code >> 5, self.code & 0x1f)
    }
}

/// GET coap://[addr][path].
pub async fn get(addr: SocketAddr, path: &str) -> std::io::Result<Response> {
    request(addr, MessageCode::GET, path, None).await
}

/// POST coap://[addr][path] with CBOR body.
pub async fn post(addr: SocketAddr, path: &str, body: &[u8]) -> std::io::Result<Response> {
    request(addr, MessageCode::POST, path, Some(body)).await
}

/// PUT coap://[addr][path] with CBOR body.
pub async fn put(addr: SocketAddr, path: &str, body: &[u8]) -> std::io::Result<Response> {
    request(addr, MessageCode::PUT, path, Some(body)).await
}

/// DELETE coap://[addr][path].
pub async fn delete(addr: SocketAddr, path: &str) -> std::io::Result<Response> {
    request(addr, MessageCode::DELETE, path, None).await
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

async fn request(
    addr: SocketAddr,
    code: MessageCode,
    path: &str,
    payload: Option<&[u8]>,
) -> std::io::Result<Response> {
    let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;

    let mid = mid_from_time();
    let token = [0x4c, 0x49, 0x43, 0x48]; // "LICH"
    let frame = encode(code, mid, &token, path, payload)?;

    sock.send(&frame).await?;

    let mut buf = vec![0u8; 1280];
    let n = timeout(Duration::from_secs(TIMEOUT_S), sock.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "CoAP timeout"))??;

    decode(&buf[..n])
}

/// Build a CoAP message using CoapBuilder.
fn encode(
    code: MessageCode,
    mid: u16,
    token: &[u8],
    path: &str,
    payload: Option<&[u8]>,
) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 256];

    let mut builder = CoapBuilder::new(&mut buf, MessageType::Confirmable, code, mid, token)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

    // Add Uri-Path options for each path segment
    for seg in path.trim_start_matches('/').split('/') {
        if !seg.is_empty() {
            builder
                .uri_path(seg)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        }
    }

    // Add Content-Format (CBOR) and payload when body is present
    if let Some(p) = payload {
        if !p.is_empty() {
            builder
                .content_format(CONTENT_FORMAT_CBOR)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
            builder
                .payload(p)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        }
    }

    let len = builder.finish();
    buf.truncate(len);
    Ok(buf)
}

/// Parse a CoAP response.  Returns code + payload; ignores option values.
fn decode(data: &[u8]) -> std::io::Result<Response> {
    if data.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response too short",
        ));
    }
    let tkl = (data[0] & 0x0f) as usize;
    if tkl > 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid TKL (>8 is reserved)",
        ));
    }
    let code = data[1];

    if 4 + tkl > data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response too short for token",
        ));
    }
    let payload_start = skip_options(data, 4 + tkl)?;
    Ok(Response {
        code,
        payload: data[payload_start..].to_vec(),
    })
}

/// Walk past CoAP options and return the index of the first payload byte.
/// Returns `data.len()` if there is no payload marker.
fn skip_options(data: &[u8], mut i: usize) -> std::io::Result<usize> {
    while i < data.len() {
        if data[i] == 0xff {
            return Ok(i + 1);
        }
        let delta_nibble = (data[i] >> 4) & 0x0f;
        let len_nibble = data[i] & 0x0f;
        i += 1;

        // Extended delta
        i += match delta_nibble {
            13 => { i += 1; 0 }
            14 => { i += 2; 0 }
            15 => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData, "reserved option delta 15")),
            _ => 0,
        };

        // Extended length
        let opt_len = match len_nibble {
            13 => {
                let v = *data.get(i).ok_or_else(|| trunc())? as usize + 13;
                i += 1;
                v
            }
            14 => {
                let hi = *data.get(i).ok_or_else(|| trunc())? as usize;
                let lo = *data.get(i + 1).ok_or_else(|| trunc())? as usize;
                i += 2;
                (hi << 8 | lo) + 269
            }
            15 => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData, "reserved option length 15")),
            n => n as usize,
        };

        i = i.checked_add(opt_len).ok_or_else(|| trunc())?;
        if i > data.len() {
            return Err(trunc());
        }
    }
    Ok(data.len())
}

fn trunc() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated CoAP option")
}

/// Generate a pseudo-random 16-bit message ID from the system clock.
fn mid_from_time() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0x1234)
}
