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

/// Send a message (POST) or read the inbox (GET, Observable).
pub const MSG_INBOX: &str = "/msg/inbox";

/// Read the list of sent messages (GET).
pub const MSG_SENT: &str = "/msg/sent";

/// Acknowledge a received message (POST `{id}`).
pub const MSG_ACK: &str = "/msg/ack";
