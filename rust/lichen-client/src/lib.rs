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

pub mod checkin;
pub mod config;
pub mod deaddrop;
pub mod identity;
pub mod keys;
pub mod keystore;
pub mod link_format;
pub mod msg;
pub mod paths;
pub mod pos;
pub mod presence;
pub mod radio_config;
pub mod rangetest;
pub mod status;
pub mod waypoint;

mod error;
pub use error::Error;

// Re-export key types for convenience
pub use checkin::{
    CheckIn, CheckInStatus, RollcallMissing, RollcallRequest, RollcallResponder, RollcallStatus,
    CHECKIN_STATUS_VALUES, DEFAULT_TIMEOUT_S, MAX_CHECKINS, MAX_ROLLCALLS, MAX_TIMEOUT_S,
};
#[cfg(feature = "tokio")]
pub use config::{ConfigClient, ConfigClientError};
pub use config::{ConfigUpdate, ConfigUpdateError, NodeConfig, NodeRole};
pub use deaddrop::{
    clamp_ttl, code, decode_senml_pack, encode_senml_pack, extract_ttl, is_drop_id, AddDropParams,
    Clock, DeadDropStore, DropFilter, DropView, GetResponse, PickupOutcome, PostOutcome,
    PostRequest, Privacy, SenmlRecord, StorageInfo, DEFAULT_TTL, MAX_DROP_SIZE, MAX_TTL,
    POSTS_PER_HOUR, STORAGE_BR, STORAGE_LEAF,
};
pub use identity::{IdentityAddresses, NodeIdentity};
#[cfg(feature = "tokio")]
pub use identity::{IdentityClient, IdentityClientError};
#[cfg(feature = "tokio")]
pub use keystore::KeyStoreClient;
pub use keystore::{validate_iid, IidError, KeyStoreError};
pub use link_format::{parse_link_format, Capabilities, LinkFormatError};
pub use radio_config::{RadioConfig, RadioConfigUpdate};
#[cfg(feature = "tokio")]
pub use radio_config::{RadioConfigClient, RadioConfigClientError};
