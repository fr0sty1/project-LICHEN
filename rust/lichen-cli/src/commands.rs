//! CLI command implementations.
//!
//! Each function sends a CoAP request to the node and formats the response.
//! The CoAP transport is a thin wrapper that will be replaced by the real
//! lichen-coap client once it implements network I/O.

use crate::{ConfigAction, KeyAction, OutputFormat, PositionAction, output};
use std::net::SocketAddr;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

/// GET coap://[node]/status
pub async fn status(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let _resp = coap_get(node, "/status").await?;
    output::print_kv("node", &node.to_string(), fmt);
    output::print_kv("status", "ok (stub — CoAP transport not yet connected)", fmt);
    Ok(())
}

/// GET coap://[node]/neighbors
pub async fn neighbors(node: SocketAddr, fmt: &OutputFormat) -> CmdResult {
    let _resp = coap_get(node, "/neighbors").await?;
    output::print_kv("neighbors", "(stub)", fmt);
    Ok(())
}

/// POST coap://[to]/msg/inbox
pub async fn send(
    _node: SocketAddr,
    to: &str,
    message: &str,
    fmt: &OutputFormat,
) -> CmdResult {
    output::print_kv("to", to, fmt);
    output::print_kv("message", message, fmt);
    output::print_kv("status", "queued (stub)", fmt);
    Ok(())
}

pub async fn key(node: SocketAddr, action: KeyAction, fmt: &OutputFormat) -> CmdResult {
    match action {
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

pub async fn position(
    node: SocketAddr,
    action: PositionAction,
    fmt: &OutputFormat,
) -> CmdResult {
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
