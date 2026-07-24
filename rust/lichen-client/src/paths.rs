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
///
/// Returns `Err` if `iid` contains characters other than `[0-9a-fA-F:]`.
/// This prevents path-segment injection through a user-controlled IID.
pub fn keys_iid(iid: &str) -> Result<String, &'static str> {
    if !iid.is_empty()
        && iid
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':')
    {
        let mut s = String::with_capacity(6 + iid.len());
        s.push('/');
        s.push_str("keys/");
        s.push_str(iid);
        Ok(s)
    } else {
        Err("invalid IID: expected hex digit or colon characters only")
    }
}

// --- Confessions / anonymous board (spec §18.9) -----------------------------

/// Post or read confessions (POST text/SenML, GET SenML count). §18.9.
pub const CONFESSIONS: &str = "/confessions";

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

    #[test]
    fn keys_iid_accepts_hex_iid() {
        let path = keys_iid("abcd:ef01:2345:6789").unwrap();
        assert_eq!(path, "/keys/abcd:ef01:2345:6789");
    }

    #[test]
    fn keys_iid_accepts_uppercase_hex() {
        let path = keys_iid("ABCD:EF01:2345:6789").unwrap();
        assert_eq!(path, "/keys/ABCD:EF01:2345:6789");
    }

    #[test]
    fn keys_iid_rejects_slash() {
        assert!(keys_iid("abcd/ef01").is_err());
    }

    #[test]
    fn keys_iid_rejects_query_chars() {
        assert!(keys_iid("abcd?evil=true").is_err());
        assert!(keys_iid("abcd&evil=true").is_err());
        assert!(keys_iid("abcd=evil").is_err());
    }

    #[test]
    fn keys_iid_rejects_space() {
        assert!(keys_iid("abcd ef01").is_err());
    }

    #[test]
    fn keys_iid_rejects_empty() {
        assert!(keys_iid("").is_err());
    }
}
