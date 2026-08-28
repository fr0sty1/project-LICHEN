// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! CoAP resource paths exposed by the LICHEN firmware.
//!
//! Centralizing the paths keeps client apps from drifting onto stale or
//! never-implemented endpoints. For example, the messaging inbox is
//! [`MSG_INBOX`] (`/msg/inbox`) - the firmware never exposed the legacy
//! `/messages` path some early clients used. Neighbor tables live at
//! [`STATUS_NEIGHBORS`]; application presence is [`PRESENCE`].
//!
//! Sources: `lichen/subsys/lichen/coap/`, `spec/11-lci.md`, `spec/12-apps.md`.

/// Node status snapshot (GET, Observable).
pub const STATUS: &str = "/status";

/// Neighbor / link-quality table (GET).
pub const STATUS_NEIGHBORS: &str = "/status/neighbors";

/// Routing table (GET). §17.5.3.
pub const STATUS_ROUTES: &str = "/status/routes";

/// Queue latency/drop statistics (GET, Observable).
/// Per spec/appendix-bufferbloat.md "Measuring Queue Latency".
pub const STATUS_QUEUES: &str = "/status/queues";

/// Node configuration document (GET). §17.5.2.
pub const CONFIG: &str = "/config";

/// Radio configuration document (GET). §17.5.2.
pub const CONFIG_RADIO: &str = "/config/radio";

/// Read-only node identity document (GET). §17.5.2.
pub const CONFIG_IDENTITY: &str = "/config/identity";

/// Send a message (POST) or read the inbox (GET, Observable). §18.1.2 / §17.5.7.
pub const MSG_INBOX: &str = "/msg/inbox";

/// Sent-message archive (GET). Local-admin POST is an LCI alias for send.
pub const MSG_SENT: &str = "/msg/sent";

/// Delivery receipt (POST `{id, status, ts}`). §18.1.2.
pub const MSG_ACK: &str = "/msg/ack";

/// Canned-message catalog (GET). §18.1.3.
pub const MSG_CANNED: &str = "/msg/canned";

/// Per-message sent archive path `/msg/sent/{id}`.
pub fn msg_sent_id(id: u64) -> String {
    format!("/msg/sent/{id}")
}

/// Peer link-key table (GET). Per-key detail is `/keys/{iid}`.
pub const KEYS: &str = "/keys";

/// Per-peer key resource `/keys/{iid}` (GET detail, PUT pin, DELETE unpin).
/// `iid` is the peer's interface identifier as `xxxx:xxxx:xxxx:xxxx`.
pub fn keys_iid(iid: &str) -> String {
    format!("/keys/{iid}")
}

/// Node telemetry (GET, `application/senml+cbor`). Returns packet TX/RX counts,
/// TX failures, RX accept/drop rates, packet rate, uptime, density.
pub const METRICS: &str = "/metrics";

// --- Position sharing (spec §18.2) -----------------------------------------

/// Query a node's current position (GET, `application/senml+cbor`). §18.2.2.
pub const SENSORS_LOCATION: &str = "/sensors/location";

/// Broadcast this node's position beacon (PUT, `application/senml+cbor`). §18.2.1.
pub const POS: &str = "/pos";

// --- Waypoint sharing (spec §18.3) -----------------------------------------

/// Create or share a waypoint (POST, `application/cbor`). §18.3.2.
pub const WAYPOINTS: &str = "/waypoints";

// --- Dead Drop (spec §18.9, LCI §17.5.8) ------------------------------------

/// Store-and-forward dead drop collection (POST to create, GET to list,
/// Observable). §18.9.
pub const DEADDROP: &str = "/deaddrop";

/// A specific dead drop `/deaddrop/{id}`; `id` is the 6-hex drop ID.
pub fn deaddrop_id(id: &str) -> String {
    format!("/deaddrop/{id}")
}

// --- Presence and status (spec §18.5) --------------------------------------

/// Own presence document (GET/PUT, Observable). §18.5.2.
pub const PRESENCE: &str = "/presence";

/// Presence cache of known nodes (GET, Observable). §18.5.2.
pub const PRESENCE_CACHE: &str = "/presence/cache";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messaging_paths_match_firmware_resources() {
        assert_eq!(MSG_INBOX, "/msg/inbox");
        assert_eq!(MSG_SENT, "/msg/sent");
        assert_eq!(MSG_ACK, "/msg/ack");
        assert_eq!(MSG_CANNED, "/msg/canned");
        assert_eq!(msg_sent_id(42), "/msg/sent/42");
    }

    #[test]
    fn identity_path_matches_lci_spec() {
        assert_eq!(CONFIG, "/config");
        assert_eq!(CONFIG_RADIO, "/config/radio");
        assert_eq!(CONFIG_IDENTITY, "/config/identity");
    }

    #[test]
    fn waypoint_path_matches_application_spec() {
        assert_eq!(WAYPOINTS, "/waypoints");
    }

    #[test]
    fn presence_paths_match_application_spec() {
        assert_eq!(PRESENCE, "/presence");
        assert_eq!(PRESENCE_CACHE, "/presence/cache");
    }

    #[test]
    fn deaddrop_paths_match_application_spec() {
        assert_eq!(DEADDROP, "/deaddrop");
        assert_eq!(deaddrop_id("7f3a9c"), "/deaddrop/7f3a9c");
    }
}
