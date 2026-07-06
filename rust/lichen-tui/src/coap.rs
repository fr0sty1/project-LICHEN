//! Minimal UDP CoAP GET client (RFC 7252 §4).
//!
//! Sends a NON GET, waits up to 2 s for a 2.05 Content response, and returns
//! the raw payload bytes. No retransmission; callers poll on their own schedule.

use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU16, Ordering},
};
use tokio::{
    net::UdpSocket,
    time::{timeout, Duration},
};

static NEXT_ID: AtomicU16 = AtomicU16::new(1);

/// Send a NON GET to `node` at `path` (e.g. `"status"`), return payload bytes.
pub async fn get(node: SocketAddr, path: &str) -> Result<Vec<u8>, String> {
    let bind = if node.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    sock.send_to(&build_get(path), node)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 1500];
    match timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => extract_payload(&buf[..n]),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timeout".into()),
    }
}

// ── wire format ───────────────────────────────────────────────────────────────

fn build_get(path: &str) -> Vec<u8> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    // NON (T=1), GET (0.01), TKL=1, token=0x00
    let mut p = vec![0x51, 0x01, (id >> 8) as u8, id as u8, 0x00];
    // Uri-Path option (11) — one entry per path segment
    let mut prev: u16 = 0;
    for seg in path.trim_matches('/').split('/').filter(|s| !s.is_empty()) {
        // CoAP options are delta-encoded: delta is 11 for first Uri-Path segment
        // (option number 11), 0 for subsequent segments (same option number).
        let delta = 11 - prev;
        p.push((delta as u8) << 4 | seg.len() as u8);
        p.extend_from_slice(seg.as_bytes());
        prev = 11;
    }
    p
}

fn extract_payload(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 4 {
        return Err("response too short".into());
    }
    let code = data[1];
    let mut pos = 4 + (data[0] & 0x0F) as usize; // skip header + token
                                                 // Scan past options to the payload marker (0xFF)
    while pos < data.len() {
        let b = data[pos] as usize;
        if b == 0xFF {
            pos += 1;
            break;
        }
        pos += 1;
        let dext = match b >> 4 {
            13 => 1,
            14 => 2,
            _ => 0,
        };
        let lext = match b & 0x0F {
            13 => 1,
            14 => 2,
            _ => 0,
        };
        let olen = match b & 0x0F {
            13 => data.get(pos + dext).copied().unwrap_or(0) as usize + 13,
            14 => {
                let hi = data.get(pos + dext).copied().unwrap_or(0) as usize;
                let lo = data.get(pos + dext + 1).copied().unwrap_or(0) as usize;
                (hi << 8 | lo) + 269
            }
            n => n,
        };
        pos += dext + lext + olen;
    }
    if code != 0x45 {
        // 2.05 Content
        return Err(format!("{}.{:02}", code >> 5, code & 0x1f));
    }
    Ok(data[pos..].to_vec())
}
