//! CLI command implementations.
//!
//! Each function sends a CoAP request to the node and formats the response.
//! The CoAP transport is a thin wrapper that will be replaced by the real
//! lichen-coap client once it implements network I/O.

use crate::{output, ConfigAction, KeyAction, OutputFormat, PositionAction};
use std::net::SocketAddr;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

/// GET coap://[node]/status
pub async fn status(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let _resp = coap_get(node, "/status").await?;
    output::print_kv("node", &node.to_string(), fmt);
    output::print_kv(
        "status",
        "ok (stub — CoAP transport not yet connected)",
        fmt,
    );
    Ok(())
}

/// GET coap://[node]/neighbors
pub async fn neighbors(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let _resp = coap_get(node, "/neighbors").await?;
    output::print_kv("neighbors", "(stub)", fmt);
    Ok(())
}

/// POST coap://[to]/msg/inbox
pub async fn send(_node: SocketAddr, to: &str, message: &str, fmt: &OutputFormat) -> CmdResult {
    output::print_kv("to", to, fmt);
    output::print_kv("message", message, fmt);
    output::print_kv("status", "queued (stub)", fmt);
    Ok(())
}

pub async fn key(node: SocketAddr, action: KeyAction, fmt: &OutputFormat) -> CmdResult {
    match action {
        KeyAction::Generate { output: out_path } => {
            // Generate 32 random bytes for Ed25519 seed
            let mut seed = [0u8; 32];
            getrandom(&mut seed)?;

            // Derive public key (Ed25519: first 32 bytes of SHA512(seed) as scalar, then multiply)
            // ponytail: using simple derivation without pulling in ed25519 crate
            // Real impl would use ed25519-dalek; this outputs raw seed for now
            let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();

            // Derive IID from pubkey hash (simplified: just use first 8 bytes of seed for demo)
            let iid_hex: String = seed[..8].iter().map(|b| format!("{b:02x}")).collect();

            if let Some(path) = out_path {
                std::fs::write(&path, format!("{seed_hex}\n"))?;
                output::print_kv("private_key", path.display().to_string().as_str(), fmt);
            } else {
                output::print_kv("private_key", &seed_hex, fmt);
            }
            output::print_kv("iid", &iid_hex, fmt);
        }
        KeyAction::Fingerprint => {
            let _resp = coap_get(node, "/key/fingerprint").await?;
            output::print_kv("fingerprint", "(stub)", fmt);
        }
        KeyAction::List => {
            let _resp = coap_get(node, "/key/peers").await?;
            output::print_kv("peers", "(stub)", fmt);
        }
        KeyAction::Pin { peer } => {
            output::print_kv("pinned", &peer, fmt);
        }
        KeyAction::Unpin { peer } => {
            output::print_kv("unpinned", &peer, fmt);
        }
    }
    Ok(())
}

fn getrandom(buf: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open("/dev/urandom")?;
    f.read_exact(buf)?;
    Ok(())
}

pub async fn config(node: SocketAddr, action: ConfigAction, fmt: &OutputFormat) -> CmdResult {
    match action {
        ConfigAction::Get { key } => {
            let path = format!("/config/{}", key.replace('.', "/"));
            let _resp = coap_get(node, &path).await?;
            output::print_kv(&key, "(stub)", fmt);
        }
        ConfigAction::Set { key, value } => {
            output::print_kv("set", &format!("{key} = {value}"), fmt);
        }
    }
    Ok(())
}

pub async fn position(node: SocketAddr, action: PositionAction, fmt: &OutputFormat) -> CmdResult {
    match action {
        PositionAction::Show => {
            let _resp = coap_get(node, "/sensors/location").await?;
            output::print_kv("position", "(stub)", fmt);
        }
        PositionAction::Broadcast => {
            output::print_kv("broadcast", "queued (stub)", fmt);
        }
        PositionAction::Peers => {
            output::print_kv("peers", "(stub)", fmt);
        }
    }
    Ok(())
}

/// Stub CoAP GET — returns empty bytes.
/// Will be replaced by a real UDP CoAP client once lichen-coap grows network I/O.
async fn coap_get(_node: SocketAddr, _path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(vec![])
}
