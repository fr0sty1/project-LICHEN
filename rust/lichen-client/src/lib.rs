// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Shared client-side domain types and wire codecs for LICHEN applications.
//!
//! Every LICHEN client app (CLI, TUI, and future desktop/mobile GUIs) speaks
//! CoAP + CBOR to a local node. This crate owns the domain data models and
//! their CBOR (de)serialization so all apps agree on the on-wire contract the
//! firmware exposes, instead of each app re-deriving — and drifting from — it.
//!
//! The wire format mirrors the firmware CoAP resources under
//! `lichen/subsys/lichen/coap/` and the application spec (`spec/12-apps.md`).
//! Transport (UDP/SLIP/BLE) is intentionally out of scope here; apps pair
//! these types with a CoAP transport such as `lichen-coap`.

pub mod msg;
pub mod paths;
pub mod pos;

mod error;
pub use error::Error;
