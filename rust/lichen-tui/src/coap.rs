// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Thin adapter over the shared `lichen-coap` UDP client.
//!
//! The TUI previously carried its own minimal NON GET client that hand-rolled
//! the CoAP wire format with no MID/token validation. It now reuses
//! `lichen-coap` (CON messages with RFC 7252 §4.4/§5.3.1 MID + token
//! validation) and only adapts the result to the payload-or-error string the
//! background poller expects.

use std::net::SocketAddr;

/// Send a CoAP GET to `node` at `path` (e.g. `"status"`), returning the
/// response payload on success.
pub async fn get(node: SocketAddr, path: &str) -> Result<Vec<u8>, String> {
    let resp = lichen_coap::client::get(node, path)
        .await
        .map_err(|e| e.to_string())?;
    if resp.is_success() {
        Ok(resp.payload)
    } else {
        Err(format!("CoAP {}", resp.code_str()))
    }
}
