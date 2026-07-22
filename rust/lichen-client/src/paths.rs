// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! CoAP resource paths exposed by the LICHEN firmware.
//!
//! Centralizing the paths keeps client apps from drifting onto stale or
//! never-implemented endpoints. For example, the messaging inbox is
//! [`MSG_INBOX`] (`/msg/inbox`) — the firmware never exposed the legacy
//! `/messages` path some early clients used. The CLI was updated to use
//! only supported paths (`/status/neighbors` not `/presence` or `/neighbors`).
//!
//! Sources: `lichen/subsys/lichen/coap/`, `spec/11-lci.md`, `spec/12-apps.md`.

/// Node status snapshot (GET, Observable).
pub const STATUS: &str = "/status";

/// Neighbor / link-quality table (GET).
pub const STATUS_NEIGHBORS: &str = "/status/neighbors";

/// Read the inbox (GET, Observable).
pub const MSG_INBOX: &str = "/msg/inbox";

/// Send a message (POST) or read sent messages (GET).
pub const MSG_SENT: &str = "/msg/sent";

/// Acknowledge a received message (POST `{id}`).
pub const MSG_ACK: &str = "/msg/ack";

/// Peer link-key table (GET). Per-key detail is `/keys/{iid}`.
pub const KEYS: &str = "/keys";

/// Per-peer key resource `/keys/{iid}` (GET detail, PUT pin, DELETE unpin).
/// `iid` is the peer's interface identifier as `xxxx:xxxx:xxxx:xxxx`.
pub fn keys_iid(iid: &str) -> String {
    format!("/keys/{iid}")
}

// --- Position sharing (spec §18.2) -----------------------------------------

/// Query a node's current position (GET, `application/senml+cbor`). §18.2.2.
pub const SENSORS_LOCATION: &str = "/sensors/location";

/// Broadcast this node's position beacon (PUT, `application/senml+cbor`). §18.2.1.
pub const POS: &str = "/pos";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messaging_paths_match_firmware_resources() {
        assert_eq!(MSG_INBOX, "/msg/inbox");
        assert_eq!(MSG_SENT, "/msg/sent");
    }
}
