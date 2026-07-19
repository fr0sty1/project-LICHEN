// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! CoAP resource paths exposed by the LICHEN firmware.
//!
//! Centralizing the paths keeps client apps from drifting onto stale or
//! never-implemented endpoints. For example, the messaging inbox is
//! [`MSG_INBOX`] (`/msg/inbox`) — the firmware never exposed the legacy
//! `/messages` path some early clients used.
//!
//! Sources: `lichen/subsys/lichen/coap/coap_msg.c`, `spec/12-apps.md` §18.1.

/// Node status snapshot (GET, Observable).
pub const STATUS: &str = "/status";

/// Neighbor / link-quality table (GET).
pub const STATUS_NEIGHBORS: &str = "/status/neighbors";

/// Send a message (POST) or read the inbox (GET, Observable).
pub const MSG_INBOX: &str = "/msg/inbox";

/// Read the list of sent messages (GET).
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
// NOTE: these resources are specified but not yet served by the firmware; the
// `lichen-client` position codec targets them so clients are ready in advance.

/// Query a node's current position (GET, `application/senml+cbor`). §18.2.2.
pub const SENSORS_LOCATION: &str = "/sensors/location";

/// Broadcast this node's position beacon (PUT, `application/senml+cbor`). §18.2.1.
pub const POS: &str = "/pos";
