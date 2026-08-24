//! CoAP resources for gateway coordination (GCP-6.4).
//!
//! Implements `/.well-known/lichen-gw/*` resources per spec section
//! 08-gateway-coordination.md GCP-6.4:
//!
//! | Method | Path          | Description                  | Payload Format |
//! |--------|---------------|------------------------------|----------------|
//! | GET    | /info         | Gateway info & capabilities  | SenML/CBOR     |
//! | GET    | /slots        | Current slot allocation      | CBOR map       |
//! | POST   | /slots        | Claim or update slots        | CBOR claim obj |
//! | GET    | /channels     | Channel ownership map        | CBOR map       |
//! | POST   | /handoff      | Node handoff request         | Node EUI+state |
//! | GET    | /nodes        | Node registry query          | SenML list     |
//!
//! All CoAP messages use OSCORE (PSK or signature context per mode).
//!
//! SECURITY: Resources that modify state (POST /slots, POST /handoff) MUST
//! verify OSCORE authentication before processing. Unauthenticated requests
//! enable slot hijacking and node theft attacks.
//!
//! # Relationship to slot module
//!
//! The `slot` module provides internal slot allocation logic (SlotAllocator,
//! conflict resolution). This module provides CBOR wire format encoding for
//! CoAP resources. Use `slot::AllocationMode` for internal logic and
//! `resources::SlotMap` for wire format.

use ciborium::Value;
use lichen_link::keys::Seed;
use schnorr48::{derive_keypair, sign, verify};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::{
    fs,
    fs::OpenOptions,
    io::{Read, Write},
};
use zeroize::Zeroizing;

use crate::handoff::{HandoffRequest, NodeRegistry};
use crate::slot;
use crate::trust::SIGNATURE_LEN;

// ─── CBOR map keys (short integers for constrained links) ────────────────────

// GatewayInfo keys
const KEY_IID: i64 = 1;
const KEY_CAPABILITIES: i64 = 2;
const KEY_SLOT_MAP: i64 = 3;
const KEY_SUPERFRAME_DURATION: i64 = 4;
const KEY_FEDERATION_MODES: i64 = 5;
const KEY_SUPERFRAME_EPOCH: i64 = 6;
const KEY_TIME_SOURCE: i64 = 7;

// Capabilities subkeys
const KEY_CAP_MAX_SLOTS: i64 = 1;
const KEY_CAP_GPS_SYNC: i64 = 2;
const KEY_CAP_BACKBONE_IPV6: i64 = 3;
const KEY_CAP_LR_FHSS: i64 = 4;
const KEY_CAP_CHANNELS: i64 = 5;
const KEY_CAP_MAX_NODES: i64 = 6;

// Slot map subkeys
const KEY_MAP_MODE: i64 = 1;
const KEY_MAP_OWNED: i64 = 2;
const KEY_MAP_GATEWAY_COUNT: i64 = 3;
const KEY_MAP_ORDINAL: i64 = 4;
const KEY_MAP_START: i64 = 5;
const KEY_MAP_COUNT: i64 = 6;

// Slot claim keys
const KEY_CLAIM_IID: i64 = 1;
const KEY_CLAIM_SLOTS: i64 = 2;
const KEY_CLAIM_SUPERFRAME_ID: i64 = 3;
const KEY_CLAIM_TIMESTAMP: i64 = 4;
const KEY_CLAIM_GATEWAY_COUNT: i64 = 5;
const KEY_CLAIM_ORDINAL: i64 = 6;
const KEY_CLAIM_SIGNATURE: i64 = 7;
const KEY_CLAIM_SEQUENCE: i64 = 8;

// Channel map keys
const KEY_CHANNEL_ID: i64 = 1;
const KEY_CHANNEL_FREQUENCY: i64 = 2;
const KEY_CHANNEL_OWNER: i64 = 3;

// ─── Federation mode enum ────────────────────────────────────────────────────

/// Federation authentication mode (GCP-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FederationMode {
    /// Pre-shared key (closed federation).
    Psk = 0,
    /// Ed25519 signatures (open federation).
    Ed25519 = 1,
}

impl From<FederationMode> for u8 {
    fn from(m: FederationMode) -> u8 {
        m as u8
    }
}

impl TryFrom<u8> for FederationMode {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Psk),
            1 => Ok(Self::Ed25519),
            _ => Err(()),
        }
    }
}

// ─── Re-export allocation mode from slot module ─────────────────────────────

/// Re-export AllocationMode from slot module for CBOR encoding.
pub use slot::AllocationMode;

/// Convert AllocationMode to wire format value.
pub fn allocation_mode_to_wire(mode: AllocationMode) -> u8 {
    match mode {
        AllocationMode::Interleaved => 0,
        AllocationMode::Contiguous => 1,
    }
}

/// Convert wire format value to AllocationMode.
pub fn allocation_mode_from_wire(v: u8) -> AllocationMode {
    match v {
        1 => AllocationMode::Contiguous,
        _ => AllocationMode::Interleaved,
    }
}

// ─── Resource error type ─────────────────────────────────────────────────────

/// Error type for CoAP resource operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    /// Invalid CBOR encoding.
    InvalidCbor,
    /// Expected CBOR map but got something else.
    ExpectedMap,
    /// Missing required field.
    MissingField(&'static str),
    /// Invalid field type.
    InvalidFieldType(&'static str),
    /// Invalid IPv6 address length.
    InvalidAddress,
    /// Signature verification failed.
    InvalidSignature,
    /// Slot conflict (overlapping claims).
    SlotConflict,
    /// Request not authenticated with OSCORE.
    Unauthorized,
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCbor => write!(f, "invalid CBOR"),
            Self::ExpectedMap => write!(f, "expected CBOR map"),
            Self::MissingField(name) => write!(f, "missing field: {}", name),
            Self::InvalidFieldType(name) => write!(f, "invalid type for field: {}", name),
            Self::InvalidAddress => write!(f, "invalid IPv6 address"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::SlotConflict => write!(f, "slot conflict"),
            Self::Unauthorized => write!(f, "unauthorized"),
        }
    }
}

impl std::error::Error for ResourceError {}

// ─── Gateway capabilities ────────────────────────────────────────────────────

/// Gateway capabilities for discovery response.
///
/// Advertises what features this gateway supports, enabling other gateways
/// to make coordination decisions (e.g., elect time master based on GPS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayCapabilities {
    /// Slots per superframe.
    pub max_slots: u16,
    /// GPS time sync available.
    pub gps_sync: bool,
    /// Backbone IPv6 connectivity.
    pub backbone_ipv6: bool,
    /// LR-FHSS support.
    pub lr_fhss: bool,
    /// Number of LoRa channels.
    pub channels: u8,
    /// Maximum nodes supported.
    pub max_nodes: u16,
}

impl Default for GatewayCapabilities {
    fn default() -> Self {
        Self {
            max_slots: 60,
            gps_sync: false,
            backbone_ipv6: true,
            lr_fhss: false,
            channels: 8,
            max_nodes: 256,
        }
    }
}

impl GatewayCapabilities {
    /// Encode as CBOR map with integer keys.
    pub fn to_cbor_map(&self) -> Vec<(Value, Value)> {
        vec![
            (
                Value::Integer(KEY_CAP_MAX_SLOTS.into()),
                Value::Integer((self.max_slots as i64).into()),
            ),
            (
                Value::Integer(KEY_CAP_GPS_SYNC.into()),
                Value::Bool(self.gps_sync),
            ),
            (
                Value::Integer(KEY_CAP_BACKBONE_IPV6.into()),
                Value::Bool(self.backbone_ipv6),
            ),
            (
                Value::Integer(KEY_CAP_LR_FHSS.into()),
                Value::Bool(self.lr_fhss),
            ),
            (
                Value::Integer(KEY_CAP_CHANNELS.into()),
                Value::Integer((self.channels as i64).into()),
            ),
            (
                Value::Integer(KEY_CAP_MAX_NODES.into()),
                Value::Integer((self.max_nodes as i64).into()),
            ),
        ]
    }

    /// Decode from CBOR map.
    pub fn from_cbor_map(map: &[(Value, Value)]) -> Result<Self, ResourceError> {
        let mut caps = Self::default();

        for (k, v) in map {
            let key = match k {
                Value::Integer(i) => i128::from(*i) as i64,
                _ => continue,
            };
            match key {
                KEY_CAP_MAX_SLOTS => {
                    if let Value::Integer(i) = v {
                        caps.max_slots = u16::try_from(i128::from(*i))
                            .map_err(|_| ResourceError::InvalidFieldType("max_slots"))?;
                    }
                }
                KEY_CAP_GPS_SYNC => {
                    if let Value::Bool(b) = v {
                        caps.gps_sync = *b;
                    }
                }
                KEY_CAP_BACKBONE_IPV6 => {
                    if let Value::Bool(b) = v {
                        caps.backbone_ipv6 = *b;
                    }
                }
                KEY_CAP_LR_FHSS => {
                    if let Value::Bool(b) = v {
                        caps.lr_fhss = *b;
                    }
                }
                KEY_CAP_CHANNELS => {
                    if let Value::Integer(i) = v {
                        caps.channels = u8::try_from(i128::from(*i))
                            .map_err(|_| ResourceError::InvalidFieldType("channels"))?;
                    }
                }
                KEY_CAP_MAX_NODES => {
                    if let Value::Integer(i) = v {
                        caps.max_nodes = u16::try_from(i128::from(*i))
                            .map_err(|_| ResourceError::InvalidFieldType("max_nodes"))?;
                    }
                }
                _ => {}
            }
        }

        if caps.max_slots == 0
            || u32::from(caps.max_slots) > slot::MAX_SLOTS_PER_SUPERFRAME
            || caps.channels == 0
        {
            return Err(ResourceError::InvalidFieldType("capabilities"));
        }
        Ok(caps)
    }
}

// ─── Slot map ────────────────────────────────────────────────────────────────

/// Slot allocation map for discovery response.
///
/// Describes which TDMA slots this gateway owns and the overall allocation
/// strategy. Used for slot conflict detection and resolution (GCP-6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotMap {
    /// Allocation mode.
    pub mode: AllocationMode,
    /// Total gateways in federation.
    pub gateway_count: u8,
    /// This gateway's ordinal (0-indexed).
    pub ordinal: u8,
    /// Contiguous mode: start slot.
    pub start_slot: Option<u16>,
    /// Contiguous mode: number of slots.
    pub slot_count: Option<u16>,
    /// Explicit post-conflict ownership override.
    pub owned: Option<Vec<u16>>,
}

impl Default for SlotMap {
    fn default() -> Self {
        Self {
            mode: AllocationMode::Interleaved,
            gateway_count: 1,
            ordinal: 0,
            start_slot: None,
            slot_count: None,
            owned: None,
        }
    }
}

impl SlotMap {
    /// Return list of slot indices owned by this gateway.
    pub fn owned_slots(&self, max_slots: u16) -> Vec<u16> {
        if self.validate(max_slots).is_err() {
            return Vec::new();
        }
        if let Some(owned) = &self.owned {
            return owned.clone();
        }
        match self.mode {
            AllocationMode::Interleaved => {
                let mut slots = Vec::new();
                let mut slot = self.ordinal as u16;
                while slot < max_slots {
                    slots.push(slot);
                    slot += self.gateway_count as u16;
                }
                slots
            }
            AllocationMode::Contiguous => {
                let start = self.start_slot.unwrap_or(0);
                let count = self.slot_count.unwrap_or(0);
                (start..start.saturating_add(count))
                    .filter(|&s| s < max_slots)
                    .collect()
            }
        }
    }

    /// Encode as CBOR map with integer keys.
    pub fn to_cbor_map(&self, max_slots: u16) -> Vec<(Value, Value)> {
        let owned = self.owned_slots(max_slots);
        let owned_values: Vec<Value> = owned
            .iter()
            .map(|&s| Value::Integer((s as i64).into()))
            .collect();

        let mut result = vec![
            (
                Value::Integer(KEY_MAP_MODE.into()),
                Value::Integer((allocation_mode_to_wire(self.mode) as i64).into()),
            ),
            (
                Value::Integer(KEY_MAP_GATEWAY_COUNT.into()),
                Value::Integer((self.gateway_count as i64).into()),
            ),
            (
                Value::Integer(KEY_MAP_ORDINAL.into()),
                Value::Integer((self.ordinal as i64).into()),
            ),
            (
                Value::Integer(KEY_MAP_OWNED.into()),
                Value::Array(owned_values),
            ),
        ];

        if self.mode == AllocationMode::Contiguous {
            if let Some(start) = self.start_slot {
                result.push((
                    Value::Integer(KEY_MAP_START.into()),
                    Value::Integer((start as i64).into()),
                ));
            }
            if let Some(count) = self.slot_count {
                result.push((
                    Value::Integer(KEY_MAP_COUNT.into()),
                    Value::Integer((count as i64).into()),
                ));
            }
        }

        result
    }

    /// Decode from CBOR map.
    pub fn from_cbor_map(map: &[(Value, Value)]) -> Result<Self, ResourceError> {
        let mut slot_map = Self::default();
        let mut seen_mode = false;
        let mut seen_gateway_count = false;
        let mut seen_ordinal = false;

        for (k, v) in map {
            let key = match k {
                Value::Integer(i) => i128::from(*i) as i64,
                _ => continue,
            };
            match key {
                KEY_MAP_MODE => {
                    let Value::Integer(i) = v else {
                        return Err(ResourceError::InvalidFieldType("slot_mode"));
                    };
                    let mode = u8::try_from(i128::from(*i))
                        .map_err(|_| ResourceError::InvalidFieldType("slot_mode"))?;
                    slot_map.mode = match mode {
                        0 => AllocationMode::Interleaved,
                        1 => AllocationMode::Contiguous,
                        _ => return Err(ResourceError::InvalidFieldType("slot_mode")),
                    };
                    seen_mode = true;
                }
                KEY_MAP_GATEWAY_COUNT => {
                    let Value::Integer(i) = v else {
                        return Err(ResourceError::InvalidFieldType("gateway_count"));
                    };
                    slot_map.gateway_count = u8::try_from(i128::from(*i))
                        .map_err(|_| ResourceError::InvalidFieldType("gateway_count"))?;
                    seen_gateway_count = true;
                }
                KEY_MAP_ORDINAL => {
                    let Value::Integer(i) = v else {
                        return Err(ResourceError::InvalidFieldType("ordinal"));
                    };
                    slot_map.ordinal = u8::try_from(i128::from(*i))
                        .map_err(|_| ResourceError::InvalidFieldType("ordinal"))?;
                    seen_ordinal = true;
                }
                KEY_MAP_START => {
                    let Value::Integer(i) = v else {
                        return Err(ResourceError::InvalidFieldType("start_slot"));
                    };
                    slot_map.start_slot = Some(
                        u16::try_from(i128::from(*i))
                            .map_err(|_| ResourceError::InvalidFieldType("start_slot"))?,
                    );
                }
                KEY_MAP_COUNT => {
                    let Value::Integer(i) = v else {
                        return Err(ResourceError::InvalidFieldType("slot_count"));
                    };
                    slot_map.slot_count = Some(
                        u16::try_from(i128::from(*i))
                            .map_err(|_| ResourceError::InvalidFieldType("slot_count"))?,
                    );
                }
                KEY_MAP_OWNED => {
                    let Value::Array(values) = v else {
                        return Err(ResourceError::InvalidFieldType("owned_slots"));
                    };
                    let mut owned = Vec::with_capacity(values.len());
                    for value in values {
                        let Value::Integer(integer) = value else {
                            return Err(ResourceError::InvalidFieldType("owned_slots"));
                        };
                        owned.push(
                            u16::try_from(i128::from(*integer))
                                .map_err(|_| ResourceError::InvalidFieldType("owned_slots"))?,
                        );
                    }
                    slot_map.owned = Some(owned);
                }
                _ => {}
            }
        }

        if !seen_mode || !seen_gateway_count || !seen_ordinal {
            return Err(ResourceError::MissingField("slot_map_dimensions"));
        }
        if slot_map.gateway_count == 0 || slot_map.ordinal >= slot_map.gateway_count {
            return Err(ResourceError::InvalidFieldType("slot_map"));
        }
        match slot_map.mode {
            AllocationMode::Interleaved
                if slot_map.start_slot.is_some() || slot_map.slot_count.is_some() =>
            {
                return Err(ResourceError::InvalidFieldType("slot_map"));
            }
            AllocationMode::Contiguous
                if slot_map.start_slot.is_none() || slot_map.slot_count.is_none() =>
            {
                return Err(ResourceError::MissingField("contiguous_slot_range"));
            }
            _ => {}
        }
        Ok(slot_map)
    }

    fn validate(&self, max_slots: u16) -> Result<(), ResourceError> {
        if max_slots == 0 || self.gateway_count == 0 || self.ordinal >= self.gateway_count {
            return Err(ResourceError::InvalidFieldType("slot_map"));
        }
        if let Some(owned) = &self.owned {
            if owned.iter().any(|slot| *slot >= max_slots)
                || owned.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(ResourceError::InvalidFieldType("owned_slots"));
            }
        }
        if self.mode == AllocationMode::Contiguous {
            let start = self
                .start_slot
                .ok_or(ResourceError::MissingField("start_slot"))?;
            let count = self
                .slot_count
                .ok_or(ResourceError::MissingField("slot_count"))?;
            let end = start
                .checked_add(count)
                .ok_or(ResourceError::InvalidFieldType("slot_range"))?;
            if count == 0 || start >= max_slots || end > max_slots {
                return Err(ResourceError::InvalidFieldType("slot_range"));
            }
        }
        Ok(())
    }
}

// ─── Gateway info ────────────────────────────────────────────────────────────

/// Gateway info response for GET /.well-known/lichen-gw/info.
///
/// This is the primary discovery response payload. Gateways multicast
/// this periodically and on-change via CoAP Observe.
#[derive(Debug, Clone)]
pub struct GatewayInfo {
    /// Gateway's IPv6 address (link-local or global).
    pub iid: [u8; 16],
    /// Gateway capabilities.
    pub capabilities: GatewayCapabilities,
    /// Slot allocation map.
    pub slot_map: SlotMap,
    /// Superframe length in seconds.
    pub superframe_duration_s: u16,
    /// Supported federation modes.
    pub federation_modes: Vec<FederationMode>,
    /// Unix timestamp of current superframe start.
    pub superframe_epoch: Option<i64>,
    /// Time source: "gps", "backbone", or "local".
    pub time_source: String,
}

impl Default for GatewayInfo {
    fn default() -> Self {
        Self {
            iid: [0u8; 16],
            capabilities: GatewayCapabilities::default(),
            slot_map: SlotMap::default(),
            superframe_duration_s: 60,
            federation_modes: vec![FederationMode::Psk, FederationMode::Ed25519],
            superframe_epoch: None,
            time_source: "local".to_string(),
        }
    }
}

impl GatewayInfo {
    /// Create a new gateway info with the given IID.
    pub fn new(iid: [u8; 16]) -> Self {
        Self {
            iid,
            ..Default::default()
        }
    }

    /// Encode as CBOR for transmission.
    pub fn encode(&self) -> Vec<u8> {
        let modes: Vec<Value> = self
            .federation_modes
            .iter()
            .map(|&m| Value::Integer((m as i64).into()))
            .collect();

        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Integer(KEY_IID.into()),
                Value::Bytes(self.iid.to_vec()),
            ),
            (
                Value::Integer(KEY_CAPABILITIES.into()),
                Value::Map(self.capabilities.to_cbor_map()),
            ),
            (
                Value::Integer(KEY_SLOT_MAP.into()),
                Value::Map(self.slot_map.to_cbor_map(self.capabilities.max_slots)),
            ),
            (
                Value::Integer(KEY_SUPERFRAME_DURATION.into()),
                Value::Integer((self.superframe_duration_s as i64).into()),
            ),
            (
                Value::Integer(KEY_FEDERATION_MODES.into()),
                Value::Array(modes),
            ),
            (
                Value::Integer(KEY_TIME_SOURCE.into()),
                Value::Text(self.time_source.clone()),
            ),
        ];

        if let Some(epoch) = self.superframe_epoch {
            entries.push((
                Value::Integer(KEY_SUPERFRAME_EPOCH.into()),
                Value::Integer(epoch.into()),
            ));
        }

        let value = Value::Map(entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    /// Decode from CBOR payload.
    pub fn decode(payload: &[u8]) -> Result<Self, ResourceError> {
        let value: Value =
            ciborium::from_reader(payload).map_err(|_| ResourceError::InvalidCbor)?;

        let map = match value {
            Value::Map(m) => m,
            _ => return Err(ResourceError::ExpectedMap),
        };

        let mut info = Self::default();

        for (k, v) in map {
            let key = match k {
                Value::Integer(i) => i128::from(i) as i64,
                _ => continue,
            };
            match key {
                KEY_IID => {
                    if let Value::Bytes(b) = v {
                        if b.len() == 16 {
                            info.iid.copy_from_slice(&b);
                        } else {
                            return Err(ResourceError::InvalidAddress);
                        }
                    }
                }
                KEY_CAPABILITIES => {
                    if let Value::Map(m) = v {
                        info.capabilities = GatewayCapabilities::from_cbor_map(&m)?;
                    }
                }
                KEY_SLOT_MAP => {
                    if let Value::Map(m) = v {
                        info.slot_map = SlotMap::from_cbor_map(&m)?;
                    }
                }
                KEY_SUPERFRAME_DURATION => {
                    if let Value::Integer(i) = v {
                        info.superframe_duration_s = u16::try_from(i128::from(i))
                            .map_err(|_| ResourceError::InvalidFieldType("superframe_duration"))?;
                    }
                }
                KEY_FEDERATION_MODES => {
                    if let Value::Array(arr) = v {
                        info.federation_modes = arr
                            .iter()
                            .filter_map(|v| {
                                if let Value::Integer(i) = v {
                                    u8::try_from(i128::from(*i))
                                        .ok()
                                        .and_then(|mode| FederationMode::try_from(mode).ok())
                                } else {
                                    None
                                }
                            })
                            .collect();
                    }
                }
                KEY_SUPERFRAME_EPOCH => {
                    if let Value::Integer(i) = v {
                        info.superframe_epoch =
                            Some(i64::try_from(i128::from(i)).map_err(|_| {
                                ResourceError::InvalidFieldType("superframe_epoch")
                            })?);
                    }
                }
                KEY_TIME_SOURCE => {
                    if let Value::Text(t) = v {
                        info.time_source = t;
                    }
                }
                _ => {}
            }
        }

        if info.superframe_duration_s == 0 {
            return Err(ResourceError::InvalidFieldType("superframe_duration"));
        }
        info.slot_map.validate(info.capabilities.max_slots)?;
        Ok(info)
    }
}

// ─── Slot claim ──────────────────────────────────────────────────────────────

/// Slot claim message for POST /.well-known/lichen-gw/slots.
///
/// Per GCP-6.2, gateways claim slots via POST to /slots on peer gateways.
/// The claim MUST be signed with the gateway's Ed25519 key (Schnorr48).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotClaim {
    /// Gateway Interface Identifier (8 bytes).
    pub gateway_iid: [u8; 8],
    /// Slot indices being claimed (sorted ascending).
    pub slots: Vec<u32>,
    /// Current superframe number.
    pub superframe_id: u64,
    /// Monotonic per-gateway sequence within a superframe.
    pub claim_sequence: u32,
    /// Unix timestamp of claim (for replay protection).
    pub timestamp: Option<i64>,
    /// Total gateways in federation (for interleaved mode).
    pub gateway_count: Option<u8>,
    /// This gateway's ordinal position (for interleaved mode).
    pub ordinal: Option<u8>,
    /// 48-byte Schnorr signature.
    pub signature: Option<[u8; 48]>,
}

impl SlotClaim {
    /// Create a new slot claim.
    pub fn new(
        gateway_iid: [u8; 8],
        slots: Vec<u32>,
        superframe_id: u64,
        claim_sequence: u32,
    ) -> Self {
        Self {
            gateway_iid,
            slots,
            superframe_id,
            claim_sequence,
            timestamp: None,
            gateway_count: None,
            ordinal: None,
            signature: None,
        }
    }

    /// Add current timestamp.
    pub fn with_timestamp(mut self) -> Self {
        self.timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs() as i64);
        self
    }

    /// Add federation parameters for interleaved mode.
    pub fn with_federation(mut self, gateway_count: u8, ordinal: u8) -> Self {
        self.gateway_count = Some(gateway_count);
        self.ordinal = Some(ordinal);
        self
    }

    /// Encode as CBOR for transmission (including signature if present).
    pub fn encode(&self) -> Vec<u8> {
        let slots: Vec<Value> = self
            .slots
            .iter()
            .map(|&s| Value::Integer((s as i64).into()))
            .collect();

        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Integer(KEY_CLAIM_IID.into()),
                Value::Bytes(self.gateway_iid.to_vec()),
            ),
            (Value::Integer(KEY_CLAIM_SLOTS.into()), Value::Array(slots)),
            (
                Value::Integer(KEY_CLAIM_SUPERFRAME_ID.into()),
                Value::Integer(self.superframe_id.into()),
            ),
            (
                Value::Integer(KEY_CLAIM_SEQUENCE.into()),
                Value::Integer(self.claim_sequence.into()),
            ),
        ];

        if let Some(ts) = self.timestamp {
            entries.push((
                Value::Integer(KEY_CLAIM_TIMESTAMP.into()),
                Value::Integer(ts.into()),
            ));
        }
        if let Some(gc) = self.gateway_count {
            entries.push((
                Value::Integer(KEY_CLAIM_GATEWAY_COUNT.into()),
                Value::Integer((gc as i64).into()),
            ));
        }
        if let Some(ord) = self.ordinal {
            entries.push((
                Value::Integer(KEY_CLAIM_ORDINAL.into()),
                Value::Integer((ord as i64).into()),
            ));
        }
        if let Some(sig) = &self.signature {
            entries.push((
                Value::Integer(KEY_CLAIM_SIGNATURE.into()),
                Value::Bytes(sig.to_vec()),
            ));
        }

        let value = Value::Map(entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    /// Encode for signing (excludes signature field).
    /// Uses deterministic CBOR encoding per RFC 8949 Section 4.2.
    pub fn encode_canonical(&self) -> Vec<u8> {
        // Build map entries in sorted key order (deterministic)
        let slots: Vec<Value> = self
            .slots
            .iter()
            .map(|&s| Value::Integer((s as i64).into()))
            .collect();

        let mut entries: Vec<(i64, Value)> = vec![
            (KEY_CLAIM_IID, Value::Bytes(self.gateway_iid.to_vec())),
            (KEY_CLAIM_SLOTS, Value::Array(slots)),
            (
                KEY_CLAIM_SUPERFRAME_ID,
                Value::Integer(self.superframe_id.into()),
            ),
            (
                KEY_CLAIM_SEQUENCE,
                Value::Integer(self.claim_sequence.into()),
            ),
        ];

        if let Some(ts) = self.timestamp {
            entries.push((KEY_CLAIM_TIMESTAMP, Value::Integer(ts.into())));
        }
        if let Some(gc) = self.gateway_count {
            entries.push((KEY_CLAIM_GATEWAY_COUNT, Value::Integer((gc as i64).into())));
        }
        if let Some(ord) = self.ordinal {
            entries.push((KEY_CLAIM_ORDINAL, Value::Integer((ord as i64).into())));
        }

        // Sort by key (already sorted since we use sequential keys)
        entries.sort_by_key(|(k, _)| *k);

        let map: Vec<(Value, Value)> = entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect();

        let value = Value::Map(map);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    /// Decode from CBOR payload.
    pub fn decode(payload: &[u8]) -> Result<Self, ResourceError> {
        let value: Value =
            ciborium::from_reader(payload).map_err(|_| ResourceError::InvalidCbor)?;

        let map = match value {
            Value::Map(m) => m,
            _ => return Err(ResourceError::ExpectedMap),
        };

        let mut gateway_iid: Option<[u8; 8]> = None;
        let mut slots: Vec<u32> = Vec::new();
        let mut superframe_id: Option<u64> = None;
        let mut claim_sequence: Option<u32> = None;
        let mut timestamp: Option<i64> = None;
        let mut gateway_count: Option<u8> = None;
        let mut ordinal: Option<u8> = None;
        let mut signature: Option<[u8; 48]> = None;

        for (k, v) in map {
            let key = match k {
                Value::Integer(i) => i128::from(i) as i64,
                _ => continue,
            };
            match key {
                KEY_CLAIM_IID => {
                    if let Value::Bytes(b) = v {
                        if b.len() == 8 {
                            let mut iid = [0u8; 8];
                            iid.copy_from_slice(&b);
                            gateway_iid = Some(iid);
                        } else {
                            return Err(ResourceError::InvalidAddress);
                        }
                    }
                }
                KEY_CLAIM_SLOTS => {
                    if let Value::Array(arr) = v {
                        for item in arr {
                            if let Value::Integer(i) = item {
                                slots.push(
                                    u32::try_from(i128::from(i))
                                        .map_err(|_| ResourceError::InvalidFieldType("slots"))?,
                                );
                            } else {
                                return Err(ResourceError::InvalidFieldType("slots"));
                            }
                        }
                    } else {
                        return Err(ResourceError::InvalidFieldType("slots"));
                    }
                }
                KEY_CLAIM_SUPERFRAME_ID => {
                    if let Value::Integer(i) = v {
                        superframe_id = Some(
                            u64::try_from(i128::from(i))
                                .map_err(|_| ResourceError::InvalidFieldType("superframe_id"))?,
                        );
                    } else {
                        return Err(ResourceError::InvalidFieldType("superframe_id"));
                    }
                }
                KEY_CLAIM_SEQUENCE => {
                    if let Value::Integer(i) = v {
                        claim_sequence = Some(
                            u32::try_from(i128::from(i))
                                .map_err(|_| ResourceError::InvalidFieldType("claim_sequence"))?,
                        );
                    } else {
                        return Err(ResourceError::InvalidFieldType("claim_sequence"));
                    }
                }
                KEY_CLAIM_TIMESTAMP => {
                    if let Value::Integer(i) = v {
                        timestamp = Some(
                            i64::try_from(i128::from(i))
                                .map_err(|_| ResourceError::InvalidFieldType("timestamp"))?,
                        );
                    }
                }
                KEY_CLAIM_GATEWAY_COUNT => {
                    if let Value::Integer(i) = v {
                        gateway_count = Some(
                            u8::try_from(i128::from(i))
                                .map_err(|_| ResourceError::InvalidFieldType("gateway_count"))?,
                        );
                    }
                }
                KEY_CLAIM_ORDINAL => {
                    if let Value::Integer(i) = v {
                        ordinal = Some(
                            u8::try_from(i128::from(i))
                                .map_err(|_| ResourceError::InvalidFieldType("ordinal"))?,
                        );
                    }
                }
                KEY_CLAIM_SIGNATURE => {
                    if let Value::Bytes(b) = v {
                        if b.len() == 48 {
                            let mut sig = [0u8; 48];
                            sig.copy_from_slice(&b);
                            signature = Some(sig);
                        } else {
                            return Err(ResourceError::InvalidSignature);
                        }
                    } else {
                        return Err(ResourceError::InvalidSignature);
                    }
                }
                _ => {}
            }
        }

        let gateway_iid = gateway_iid.ok_or(ResourceError::MissingField("gateway_iid"))?;
        let superframe_id = superframe_id.ok_or(ResourceError::MissingField("superframe_id"))?;
        let claim_sequence = claim_sequence.ok_or(ResourceError::MissingField("claim_sequence"))?;
        match (gateway_count, ordinal) {
            (Some(0), _) | (Some(_), None) | (None, Some(_)) => {
                return Err(ResourceError::InvalidFieldType("claim_dimensions"));
            }
            (Some(count), Some(index)) if index >= count => {
                return Err(ResourceError::InvalidFieldType("claim_dimensions"));
            }
            _ => {}
        }

        Ok(Self {
            gateway_iid,
            slots,
            superframe_id,
            claim_sequence,
            timestamp,
            gateway_count,
            ordinal,
            signature,
        })
    }

    /// Convert an untrusted decoded resource payload into the structurally
    /// bounded form accepted by the stateful signature/replay verifier.
    pub fn into_raw(self, slots_per_superframe: u32) -> Result<slot::RawSlotClaim, ResourceError> {
        let signature = self
            .signature
            .ok_or(ResourceError::MissingField("signature"))?;
        slot::RawSlotClaim::new(
            self.gateway_iid,
            self.slots,
            self.superframe_id,
            self.claim_sequence,
            signature,
            slots_per_superframe,
        )
        .map_err(|_| ResourceError::InvalidFieldType("slot_claim"))
    }
}

// ─── Channel info ────────────────────────────────────────────────────────────

/// Channel ownership entry for GET /.well-known/lichen-gw/channels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelInfo {
    /// Channel ID (0-15).
    pub channel_id: u8,
    /// Channel frequency in Hz.
    pub frequency_hz: u32,
    /// Owner gateway IID (last 8 bytes of IPv6 address), or None if unowned.
    pub owner_iid: Option<[u8; 8]>,
}

impl ChannelInfo {
    /// Encode as CBOR map entry.
    pub fn to_cbor_map(&self) -> Vec<(Value, Value)> {
        let mut entries = vec![
            (
                Value::Integer(KEY_CHANNEL_ID.into()),
                Value::Integer((self.channel_id as i64).into()),
            ),
            (
                Value::Integer(KEY_CHANNEL_FREQUENCY.into()),
                Value::Integer((self.frequency_hz as i64).into()),
            ),
        ];
        if let Some(owner) = &self.owner_iid {
            entries.push((
                Value::Integer(KEY_CHANNEL_OWNER.into()),
                Value::Bytes(owner.to_vec()),
            ));
        }
        entries
    }
}

/// Channel map for GET /.well-known/lichen-gw/channels response.
#[derive(Debug, Clone, Default)]
pub struct ChannelMap {
    /// List of channels.
    pub channels: Vec<ChannelInfo>,
}

impl ChannelMap {
    /// Encode as CBOR for transmission.
    pub fn encode(&self) -> Vec<u8> {
        let entries: Vec<Value> = self
            .channels
            .iter()
            .map(|c| Value::Map(c.to_cbor_map()))
            .collect();

        let value = Value::Array(entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

// ─── Node list (SenML format) ────────────────────────────────────────────────

/// Node list entry for GET /.well-known/lichen-gw/nodes response.
///
/// Uses SenML format per RFC 8428.
#[derive(Debug, Clone)]
pub struct NodeEntry {
    /// Node IPv6 address.
    pub address: [u8; 16],
    /// Last seen timestamp (Unix epoch).
    pub last_seen: f64,
    /// Current DAO sequence.
    pub dao_sequence: u32,
    /// Is node busy (in active transaction).
    pub busy: bool,
}

/// Encode node registry as SenML/CBOR for GET /nodes response.
pub fn encode_nodes_senml(registry: &NodeRegistry) -> Vec<u8> {
    // SenML pack: array of records
    // Each record is a map with keys per RFC 8428:
    // "bn" = base name, "n" = name, "v" = value, "t" = time
    let nodes = registry.list_nodes();
    let mut records: Vec<Value> = Vec::with_capacity(nodes.len() + 1);

    // Base record with base name
    let base_record = Value::Map(vec![(
        Value::Text("bn".to_string()),
        Value::Text("urn:lichen:gw:nodes:".to_string()),
    )]);
    records.push(base_record);

    for addr in nodes {
        if let Some(entry) = registry.get(&addr) {
            // Format address as hex string for SenML name
            let addr_hex: String = addr.iter().map(|b| format!("{:02x}", b)).collect();

            let mut record_entries = vec![
                (Value::Text("n".to_string()), Value::Text(addr_hex)),
                (Value::Text("t".to_string()), Value::Float(entry.last_seen)),
                (
                    Value::Text("vs".to_string()),
                    Value::Text(format!("seq={}", entry.dao_sequence)),
                ),
            ];

            if entry.busy {
                record_entries.push((Value::Text("vb".to_string()), Value::Bool(true)));
            }

            records.push(Value::Map(record_entries));
        }
    }

    let value = Value::Array(records);
    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf).expect("CBOR encoding should not fail");
    buf
}

// ─── Resource handler trait ──────────────────────────────────────────────────

/// CoAP method for resource dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoapMethod {
    Get,
    Post,
    Put,
    Delete,
}

/// Result of handling a CoAP request.
#[derive(Debug)]
pub struct CoapResponse {
    /// Response code (2.xx for success, 4.xx for client error, 5.xx for server error).
    pub code: u8,
    /// Response payload (CBOR encoded).
    pub payload: Zeroizing<Vec<u8>>,
    /// Content format (60 for CBOR, 112 for SenML+CBOR).
    pub content_format: u16,
}

impl CoapResponse {
    /// 2.05 Content response.
    pub fn content(payload: Vec<u8>, content_format: u16) -> Self {
        Self {
            code: 0x45, // 2.05 Content
            payload: Zeroizing::new(payload),
            content_format,
        }
    }

    /// 2.04 Changed response.
    pub fn changed(payload: Vec<u8>) -> Self {
        Self {
            code: 0x44, // 2.04 Changed
            payload: Zeroizing::new(payload),
            content_format: 60, // CBOR
        }
    }

    /// 4.00 Bad Request.
    pub fn bad_request(message: &str) -> Self {
        Self {
            code: 0x80, // 4.00 Bad Request
            payload: Zeroizing::new(message.as_bytes().to_vec()),
            content_format: 0, // text/plain
        }
    }

    /// 4.01 Unauthorized.
    pub fn unauthorized() -> Self {
        Self {
            code: 0x81, // 4.01 Unauthorized
            payload: Zeroizing::new(Vec::new()),
            content_format: 0,
        }
    }

    /// 4.04 Not Found.
    pub fn not_found() -> Self {
        Self {
            code: 0x84, // 4.04 Not Found
            payload: Zeroizing::new(Vec::new()),
            content_format: 0,
        }
    }

    /// 4.05 Method Not Allowed.
    pub fn method_not_allowed() -> Self {
        Self {
            code: 0x85, // 4.05 Method Not Allowed
            payload: Zeroizing::new(Vec::new()),
            content_format: 0,
        }
    }

    /// 5.00 Internal Server Error.
    pub fn internal_error(message: &str) -> Self {
        Self {
            code: 0xA0, // 5.00 Internal Server Error
            payload: Zeroizing::new(message.as_bytes().to_vec()),
            content_format: 0,
        }
    }
}

/// Content format constants.
pub const CONTENT_FORMAT_CBOR: u16 = 60;
pub const CONTENT_FORMAT_SENML_CBOR: u16 = 112;

// ─── Gateway coordinator ─────────────────────────────────────────────────────

/// Gateway coordinator state for GCP-6.4 resources.
///
/// Holds the gateway's coordination state and handles CoAP resource requests.
#[derive(Debug)]
pub struct GatewayCoordinator {
    /// This gateway's info.
    pub info: GatewayInfo,
    /// Node registry.
    pub node_registry: NodeRegistry,
    /// Channel map.
    pub channel_map: ChannelMap,
    /// Peer slot claims (for conflict detection).
    peer_claims: Vec<slot::VerifiedSlotClaim>,
    slot_verifier: slot::SlotClaimVerifier,
    slots_per_superframe: u32,
    replay_persistence: Option<SlotReplayPersistence>,
}

#[derive(Debug)]
struct SlotReplayPersistence {
    path: PathBuf,
    generation_floor_path: PathBuf,
    sealing_seed: Zeroizing<[u8; 32]>,
}

const COORDINATOR_STATE_MAGIC: &[u8; 8] = b"LCHNGCS1";
const COORDINATOR_STATE_VERSION: u16 = 1;
const COORDINATOR_STATE_SEAL_DOMAIN: &[u8] = b"LICHEN-GCP-COORDINATOR-STATE-v1";

struct PersistedCoordinatorState {
    verifier: slot::SlotClaimVerifier,
    peer_claims: Vec<slot::VerifiedSlotClaim>,
    owned: Option<Vec<u16>>,
}

fn coordinator_state_max_len(
    max_gateways: usize,
    slots_per_superframe: u32,
) -> Result<usize, slot::SlotError> {
    let slots =
        usize::try_from(slots_per_superframe).map_err(|_| slot::SlotError::ArithmeticOverflow)?;
    let replay_entries = max_gateways
        .checked_mul(8 + 8 + 4)
        .ok_or(slot::SlotError::ArithmeticOverflow)?;
    let owned = slots
        .checked_mul(2)
        .and_then(|value| value.checked_add(1 + 4))
        .ok_or(slot::SlotError::ArithmeticOverflow)?;
    let peer_entry = slots
        .checked_mul(4)
        .and_then(|value| value.checked_add(8 + 8 + 4 + 4))
        .ok_or(slot::SlotError::ArithmeticOverflow)?;
    let peers = max_gateways
        .checked_mul(peer_entry)
        .and_then(|value| value.checked_add(4))
        .ok_or(slot::SlotError::ArithmeticOverflow)?;
    let fixed_header: usize = 8 + 2 + 16 + 4 + 8 + 4 + 4;
    fixed_header
        .checked_add(replay_entries)
        .and_then(|value| value.checked_add(owned))
        .and_then(|value| value.checked_add(peers))
        .and_then(|value| value.checked_add(SIGNATURE_LEN))
        .ok_or(slot::SlotError::ArithmeticOverflow)
}

fn validate_semantic_slot_state(
    verifier: &slot::SlotClaimVerifier,
    peer_claims: &[slot::VerifiedSlotClaim],
    owned: Option<&[u16]>,
    slots_per_superframe: u32,
) -> Result<(), slot::SlotError> {
    let slot_limit =
        u16::try_from(slots_per_superframe).map_err(|_| slot::SlotError::InvalidDimensions)?;
    if let Some(owned) = owned {
        if owned.len() > slots_per_superframe as usize
            || owned.iter().any(|slot| *slot >= slot_limit)
            || owned.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(slot::SlotError::CorruptState);
        }
    }
    if peer_claims.len() > verifier.snapshot().max_gateways {
        return Err(slot::SlotError::CorruptState);
    }
    let mut peer_iids = std::collections::HashSet::with_capacity(peer_claims.len());
    for claim in peer_claims {
        if !peer_iids.insert(*claim.gateway_iid())
            || claim.slots().len() > slots_per_superframe as usize
            || claim
                .slots()
                .iter()
                .any(|slot| *slot >= slots_per_superframe)
            || claim.slots().windows(2).any(|pair| pair[0] >= pair[1])
            || verifier.highwater(claim.gateway_iid())
                != Some((claim.superframe_id(), claim.claim_sequence()))
        {
            return Err(slot::SlotError::CorruptState);
        }
    }
    Ok(())
}

fn encode_coordinator_state(
    local_iid: &[u8; 16],
    slots_per_superframe: u32,
    verifier: &slot::SlotClaimVerifier,
    peer_claims: &[slot::VerifiedSlotClaim],
    owned: Option<&[u16]>,
) -> Result<Vec<u8>, slot::SlotError> {
    validate_semantic_slot_state(verifier, peer_claims, owned, slots_per_superframe)?;
    let snapshot = verifier.snapshot();
    let mut payload = Vec::with_capacity(coordinator_state_max_len(
        snapshot.max_gateways,
        slots_per_superframe,
    )?);
    payload.extend_from_slice(COORDINATOR_STATE_MAGIC);
    payload.extend_from_slice(&COORDINATOR_STATE_VERSION.to_be_bytes());
    payload.extend_from_slice(local_iid);
    payload.extend_from_slice(&slots_per_superframe.to_be_bytes());
    payload.extend_from_slice(&snapshot.generation.to_be_bytes());
    payload.extend_from_slice(&(snapshot.max_gateways as u32).to_be_bytes());
    payload.extend_from_slice(&(snapshot.entries.len() as u32).to_be_bytes());
    for (iid, superframe, sequence) in snapshot.entries {
        payload.extend_from_slice(&iid);
        payload.extend_from_slice(&superframe.to_be_bytes());
        payload.extend_from_slice(&sequence.to_be_bytes());
    }
    match owned {
        Some(owned) => {
            payload.push(1);
            payload.extend_from_slice(&(owned.len() as u32).to_be_bytes());
            for slot in owned {
                payload.extend_from_slice(&slot.to_be_bytes());
            }
        }
        None => {
            payload.push(0);
            payload.extend_from_slice(&0u32.to_be_bytes());
        }
    }
    payload.extend_from_slice(&(peer_claims.len() as u32).to_be_bytes());
    for claim in peer_claims {
        payload.extend_from_slice(claim.gateway_iid());
        payload.extend_from_slice(&claim.superframe_id().to_be_bytes());
        payload.extend_from_slice(&claim.claim_sequence().to_be_bytes());
        payload.extend_from_slice(&(claim.slots().len() as u32).to_be_bytes());
        for claimed_slot in claim.slots() {
            payload.extend_from_slice(&claimed_slot.to_be_bytes());
        }
    }
    Ok(payload)
}

fn coordinator_state_transcript(payload: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(COORDINATOR_STATE_SEAL_DOMAIN.len() + payload.len());
    transcript.extend_from_slice(COORDINATOR_STATE_SEAL_DOMAIN);
    transcript.extend_from_slice(payload);
    transcript
}

fn coordinator_state_seal(payload: &[u8], sealing_seed: &[u8; 32]) -> [u8; SIGNATURE_LEN] {
    let (private, public) = derive_keypair(&Seed::new(*sealing_seed));
    sign(&private, &public, &coordinator_state_transcript(payload))
}

fn verify_coordinator_state_seal(
    payload: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    sealing_seed: &[u8; 32],
) -> bool {
    let (_, public) = derive_keypair(&Seed::new(*sealing_seed));
    verify(&public, &coordinator_state_transcript(payload), signature)
}

fn save_coordinator_state_atomic(
    path: &Path,
    local_iid: &[u8; 16],
    slots_per_superframe: u32,
    verifier: &slot::SlotClaimVerifier,
    peer_claims: &[slot::VerifiedSlotClaim],
    owned: Option<&[u16]>,
    sealing_seed: &[u8; 32],
) -> Result<(), slot::SlotError> {
    let payload = encode_coordinator_state(
        local_iid,
        slots_per_superframe,
        verifier,
        peer_claims,
        owned,
    )?;
    let seal = coordinator_state_seal(&payload, sealing_seed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(slot::SlotError::CorruptState)?;
    let temp_path = path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        verifier.generation()
    ));
    let result = (|| -> Result<(), slot::SlotError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|error| slot::SlotError::StorageIo(error.to_string()))?;
        file.write_all(&payload)
            .and_then(|_| file.write_all(&seal))
            .and_then(|_| file.sync_all())
            .map_err(|error| slot::SlotError::StorageIo(error.to_string()))?;
        fs::rename(&temp_path, path)
            .map_err(|error| slot::SlotError::StorageIo(error.to_string()))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| slot::SlotError::StorageIo(error.to_string()))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
    result
}

struct CoordinatorStateCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CoordinatorStateCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], slot::SlotError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(slot::SlotError::CorruptState)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(slot::SlotError::CorruptState)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], slot::SlotError> {
        self.take(N)?
            .try_into()
            .map_err(|_| slot::SlotError::CorruptState)
    }

    fn u8(&mut self) -> Result<u8, slot::SlotError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, slot::SlotError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, slot::SlotError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, slot::SlotError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn load_coordinator_state(
    path: &Path,
    expected_local_iid: &[u8; 16],
    slots_per_superframe: u32,
    max_gateways: usize,
    minimum_generation: u64,
    sealing_seed: &[u8; 32],
) -> Result<PersistedCoordinatorState, slot::SlotError> {
    let maximum_len = coordinator_state_max_len(max_gateways, slots_per_superframe)?;
    let mut file = fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            slot::SlotError::MissingState
        } else {
            slot::SlotError::StorageIo(error.to_string())
        }
    })?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((maximum_len + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| slot::SlotError::StorageIo(error.to_string()))?;
    if bytes.len() > maximum_len
        || bytes.len() < 8 + 2 + 16 + 4 + 8 + 4 + 4 + 1 + 4 + 4 + SIGNATURE_LEN
    {
        return Err(slot::SlotError::CorruptState);
    }
    let payload_len = bytes
        .len()
        .checked_sub(SIGNATURE_LEN)
        .ok_or(slot::SlotError::CorruptState)?;
    let (payload, signature) = bytes.split_at(payload_len);
    let signature: &[u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| slot::SlotError::CorruptState)?;
    if !verify_coordinator_state_seal(payload, signature, sealing_seed) {
        return Err(slot::SlotError::IntegrityFailure);
    }

    let mut cursor = CoordinatorStateCursor::new(payload);
    if cursor.take(8)? != COORDINATOR_STATE_MAGIC
        || cursor.u16()? != COORDINATOR_STATE_VERSION
        || cursor.array::<16>()? != *expected_local_iid
        || cursor.u32()? != slots_per_superframe
    {
        return Err(slot::SlotError::CorruptState);
    }
    let generation = cursor.u64()?;
    if generation < minimum_generation {
        return Err(slot::SlotError::RollbackDetected {
            stored: generation,
            minimum: minimum_generation,
        });
    }
    let stored_capacity = cursor.u32()? as usize;
    if stored_capacity != max_gateways {
        return Err(slot::SlotError::CorruptState);
    }
    let replay_count = cursor.u32()? as usize;
    if replay_count > stored_capacity {
        return Err(slot::SlotError::CorruptState);
    }
    let mut replay_entries = Vec::with_capacity(replay_count);
    for _ in 0..replay_count {
        replay_entries.push((cursor.array()?, cursor.u64()?, cursor.u32()?));
    }
    let owned_present = cursor.u8()?;
    let owned_count = cursor.u32()? as usize;
    if owned_count > slots_per_superframe as usize || (owned_present == 0 && owned_count != 0) {
        return Err(slot::SlotError::CorruptState);
    }
    let owned = match owned_present {
        0 => None,
        1 => {
            let mut slots = Vec::with_capacity(owned_count);
            for _ in 0..owned_count {
                slots.push(cursor.u16()?);
            }
            Some(slots)
        }
        _ => return Err(slot::SlotError::CorruptState),
    };
    let peer_count = cursor.u32()? as usize;
    if peer_count > stored_capacity {
        return Err(slot::SlotError::CorruptState);
    }
    let mut peer_claims = Vec::with_capacity(peer_count);
    for _ in 0..peer_count {
        let iid = cursor.array()?;
        let superframe = cursor.u64()?;
        let sequence = cursor.u32()?;
        let slot_count = cursor.u32()? as usize;
        if slot_count > slots_per_superframe as usize {
            return Err(slot::SlotError::CorruptState);
        }
        let mut claimed_slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            claimed_slots.push(cursor.u32()?);
        }
        peer_claims.push(slot::VerifiedSlotClaim::restore(
            iid,
            claimed_slots,
            superframe,
            sequence,
            slots_per_superframe,
        )?);
    }
    if !cursor.is_empty() {
        return Err(slot::SlotError::CorruptState);
    }
    let verifier = slot::SlotClaimVerifier::restore(slot::SlotReplaySnapshot {
        generation,
        max_gateways: stored_capacity,
        entries: replay_entries,
    })?;
    validate_semantic_slot_state(
        &verifier,
        &peer_claims,
        owned.as_deref(),
        slots_per_superframe,
    )?;
    Ok(PersistedCoordinatorState {
        verifier,
        peer_claims,
        owned,
    })
}

fn load_generation_floor(path: &Path) -> Result<u64, slot::SlotError> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            slot::SlotError::MissingState
        } else {
            slot::SlotError::StorageIo(error.to_string())
        }
    })?;
    if metadata.len() != 8 {
        return Err(slot::SlotError::CorruptState);
    }
    let bytes = fs::read(path).map_err(|error| slot::SlotError::StorageIo(error.to_string()))?;
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| slot::SlotError::CorruptState)?;
    Ok(u64::from_be_bytes(bytes))
}

fn save_generation_floor_atomic(path: &Path, generation: u64) -> Result<(), slot::SlotError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(slot::SlotError::CorruptState)?;
    let temp_path = path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        generation
    ));
    let result = (|| -> Result<(), slot::SlotError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|error| slot::SlotError::StorageIo(error.to_string()))?;
        file.write_all(&generation.to_be_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|error| slot::SlotError::StorageIo(error.to_string()))?;
        fs::rename(&temp_path, path)
            .map_err(|error| slot::SlotError::StorageIo(error.to_string()))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| slot::SlotError::StorageIo(error.to_string()))?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
    result
}

impl GatewayCoordinator {
    /// Create an explicitly ephemeral coordinator for tests/simulations.
    pub fn new_ephemeral(
        iid: [u8; 16],
        slots_per_superframe: u32,
        max_gateways: usize,
    ) -> Result<Self, slot::SlotError> {
        let verifier = slot::SlotClaimVerifier::new_ephemeral(max_gateways)?;
        Self::with_verifier(iid, slots_per_superframe, verifier, None)
    }

    /// Provision new durable replay state. Existing files fail closed.
    pub fn provision_persistent(
        iid: [u8; 16],
        slots_per_superframe: u32,
        max_gateways: usize,
        replay_path: &Path,
        generation_floor_path: &Path,
        sealing_seed: &[u8; 32],
    ) -> Result<Self, slot::SlotError> {
        if replay_path.exists() {
            return Err(slot::SlotError::CorruptState);
        }
        let verifier = slot::SlotClaimVerifier::new_ephemeral(max_gateways)?;
        let mut coordinator = Self::with_verifier(iid, slots_per_superframe, verifier, None)?;
        save_coordinator_state_atomic(
            replay_path,
            &coordinator.info.iid,
            slots_per_superframe,
            &coordinator.slot_verifier,
            &coordinator.peer_claims,
            coordinator.info.slot_map.owned.as_deref(),
            sealing_seed,
        )?;
        save_generation_floor_atomic(
            generation_floor_path,
            coordinator.slot_verifier.generation(),
        )?;
        coordinator.replay_persistence = Some(SlotReplayPersistence {
            path: replay_path.to_path_buf(),
            generation_floor_path: generation_floor_path.to_path_buf(),
            sealing_seed: Zeroizing::new(*sealing_seed),
        });
        Ok(coordinator)
    }

    /// Open durable replay state, verifying integrity and a separately kept
    /// minimum generation floor before serving coordination resources.
    pub fn load_persistent(
        iid: [u8; 16],
        slots_per_superframe: u32,
        max_gateways: usize,
        replay_path: &Path,
        generation_floor_path: &Path,
        sealing_seed: &[u8; 32],
    ) -> Result<Self, slot::SlotError> {
        let minimum_generation = load_generation_floor(generation_floor_path)?;
        let restored = load_coordinator_state(
            replay_path,
            &iid,
            slots_per_superframe,
            max_gateways,
            minimum_generation,
            sealing_seed,
        )?;
        let mut coordinator = Self::with_verifier(
            iid,
            slots_per_superframe,
            restored.verifier,
            Some(SlotReplayPersistence {
                path: replay_path.to_path_buf(),
                generation_floor_path: generation_floor_path.to_path_buf(),
                sealing_seed: Zeroizing::new(*sealing_seed),
            }),
        )?;
        coordinator.peer_claims = restored.peer_claims;
        coordinator.info.slot_map.owned = restored.owned;
        Ok(coordinator)
    }

    fn with_verifier(
        iid: [u8; 16],
        slots_per_superframe: u32,
        verifier: slot::SlotClaimVerifier,
        replay_persistence: Option<SlotReplayPersistence>,
    ) -> Result<Self, slot::SlotError> {
        if slots_per_superframe == 0 || slots_per_superframe > slot::MAX_SLOTS_PER_SUPERFRAME {
            return Err(slot::SlotError::InvalidDimensions);
        }
        // Initialize default channels (EU868 frequencies)
        let channels = vec![
            ChannelInfo {
                channel_id: 0,
                frequency_hz: 868_100_000,
                owner_iid: None,
            },
            ChannelInfo {
                channel_id: 1,
                frequency_hz: 868_300_000,
                owner_iid: None,
            },
            ChannelInfo {
                channel_id: 2,
                frequency_hz: 868_500_000,
                owner_iid: None,
            },
            ChannelInfo {
                channel_id: 3,
                frequency_hz: 867_100_000,
                owner_iid: None,
            },
            ChannelInfo {
                channel_id: 4,
                frequency_hz: 867_300_000,
                owner_iid: None,
            },
            ChannelInfo {
                channel_id: 5,
                frequency_hz: 867_500_000,
                owner_iid: None,
            },
            ChannelInfo {
                channel_id: 6,
                frequency_hz: 867_700_000,
                owner_iid: None,
            },
            ChannelInfo {
                channel_id: 7,
                frequency_hz: 867_900_000,
                owner_iid: None,
            },
        ];

        Ok(Self {
            info: GatewayInfo::new(iid),
            node_registry: NodeRegistry::new(),
            channel_map: ChannelMap { channels },
            peer_claims: Vec::new(),
            slot_verifier: verifier,
            slots_per_superframe,
            replay_persistence,
        })
    }

    pub fn slot_replay_generation(&self) -> u64 {
        self.slot_verifier.generation()
    }

    /// Handle GET /info request.
    pub fn handle_get_info(&self) -> CoapResponse {
        let payload = self.info.encode();
        // Use SenML+CBOR content format per spec
        CoapResponse::content(payload, CONTENT_FORMAT_SENML_CBOR)
    }

    /// Handle GET /slots request.
    pub fn handle_get_slots(&self) -> CoapResponse {
        let slots = self
            .info
            .slot_map
            .owned_slots(self.info.capabilities.max_slots);
        let slots_values: Vec<Value> = slots
            .iter()
            .map(|&s| Value::Integer((s as i64).into()))
            .collect();

        let map = vec![
            (
                Value::Integer(KEY_MAP_MODE.into()),
                Value::Integer((allocation_mode_to_wire(self.info.slot_map.mode) as i64).into()),
            ),
            (
                Value::Integer(KEY_MAP_OWNED.into()),
                Value::Array(slots_values),
            ),
            (
                Value::Integer(KEY_MAP_GATEWAY_COUNT.into()),
                Value::Integer((self.info.slot_map.gateway_count as i64).into()),
            ),
            (
                Value::Integer(KEY_MAP_ORDINAL.into()),
                Value::Integer((self.info.slot_map.ordinal as i64).into()),
            ),
        ];

        let value = Value::Map(map);
        let mut payload = Vec::new();
        ciborium::into_writer(&value, &mut payload).expect("CBOR encoding should not fail");

        CoapResponse::content(payload, CONTENT_FORMAT_CBOR)
    }

    fn commit_slot_state(
        &mut self,
        verifier: slot::SlotClaimVerifier,
        peer_claims: Vec<slot::VerifiedSlotClaim>,
        owned: Option<Vec<u16>>,
    ) -> Result<(), slot::SlotError> {
        if let Some(persistence) = &self.replay_persistence {
            save_coordinator_state_atomic(
                &persistence.path,
                &self.info.iid,
                self.slots_per_superframe,
                &verifier,
                &peer_claims,
                owned.as_deref(),
                &persistence.sealing_seed,
            )?;
            save_generation_floor_atomic(
                &persistence.generation_floor_path,
                verifier.generation(),
            )?;
        }
        self.slot_verifier = verifier;
        self.peer_claims = peer_claims;
        self.info.slot_map.owned = owned;
        Ok(())
    }

    /// Handle POST /slots request (slot claim).
    ///
    /// SECURITY: OSCORE authentication is mandatory for every state mutation.
    pub fn handle_post_slots(
        &mut self,
        payload: &[u8],
        oscore_verified: bool,
        peer_pubkey: Option<&[u8; 32]>,
        current_superframe: u64,
    ) -> CoapResponse {
        if !oscore_verified {
            return CoapResponse::unauthorized();
        }
        let Some(peer_pubkey) = peer_pubkey else {
            return CoapResponse::unauthorized();
        };

        let claim = match SlotClaim::decode(payload) {
            Ok(c) => c,
            Err(e) => return CoapResponse::bad_request(&e.to_string()),
        };
        let raw_claim = match claim.into_raw(self.slots_per_superframe) {
            Ok(claim) => claim,
            Err(error) => return CoapResponse::bad_request(&error.to_string()),
        };
        let mut candidate_verifier = self.slot_verifier.clone();
        let claim = match candidate_verifier.verify(raw_claim, peer_pubkey, current_superframe) {
            Ok(claim) => claim,
            Err(_) => return CoapResponse::unauthorized(),
        };
        let mut candidate_peer_claims = self.peer_claims.clone();
        let mut candidate_owned = self.info.slot_map.owned.clone();

        // Check for slot conflicts with our owned slots
        let our_slots: std::collections::HashSet<u16> = self
            .info
            .slot_map
            .owned_slots(self.info.capabilities.max_slots)
            .into_iter()
            .collect();
        let claimed_slots: std::collections::HashSet<u16> = claim
            .slots()
            .iter()
            .filter_map(|slot| u16::try_from(*slot).ok())
            .collect();
        let overlap: Vec<u16> = our_slots.intersection(&claimed_slots).copied().collect();
        let mut reallocated_slots: Option<Vec<u16>> = None;

        if !overlap.is_empty() {
            // Conflict resolution: lowest IID wins (GCP-6.3)
            // Use slot module's comparison function for consistent IID ordering
            let our_iid: [u8; 8] = self.info.iid[8..16].try_into().unwrap();
            let their_iid = *claim.gateway_iid();

            if slot::compare_iids(&our_iid, &their_iid) == std::cmp::Ordering::Less {
                if self
                    .commit_slot_state(candidate_verifier, candidate_peer_claims, candidate_owned)
                    .is_err()
                {
                    return CoapResponse::internal_error("slot state persistence failed");
                }
                // We win, reject their claim
                let reject = Value::Map(vec![
                    (
                        Value::Text("status".to_string()),
                        Value::Text("rejected".to_string()),
                    ),
                    (
                        Value::Text("reason".to_string()),
                        Value::Text("slot_conflict".to_string()),
                    ),
                    (
                        Value::Text("conflicting_slots".to_string()),
                        Value::Array(
                            overlap
                                .iter()
                                .map(|&s| Value::Integer((s as i64).into()))
                                .collect(),
                        ),
                    ),
                ]);
                let mut payload = Vec::new();
                ciborium::into_writer(&reject, &mut payload).unwrap();
                return CoapResponse::content(payload, CONTENT_FORMAT_CBOR);
            }
            // They win. Relinquish every overlapping slot before returning
            // success, then replace it from slots not occupied by any current
            // peer claim. The updated map is what subsequent GETs and TX
            // admission observe.
            let mut retained: Vec<u16> = our_slots.difference(&claimed_slots).copied().collect();
            retained.sort_unstable();
            let mut occupied: Vec<u32> = retained.iter().copied().map(u32::from).collect();
            occupied.extend(claim.slots().iter().copied());
            for peer_claim in &self.peer_claims {
                if peer_claim.superframe_id() == current_superframe
                    && peer_claim.gateway_iid() != claim.gateway_iid()
                {
                    occupied.extend(peer_claim.slots().iter().copied());
                }
            }
            occupied.sort_unstable();
            occupied.dedup();
            let replacements =
                slot::find_next_available(overlap.len(), &occupied, self.slots_per_superframe)
                    .unwrap_or_default();
            retained.extend(
                replacements
                    .into_iter()
                    .filter_map(|slot| u16::try_from(slot).ok()),
            );
            retained.sort_unstable();
            retained.dedup();
            candidate_owned = Some(retained.clone());
            reallocated_slots = Some(retained);
        }

        // Accept the claim and store it
        if let Some(existing) = candidate_peer_claims
            .iter_mut()
            .find(|existing| existing.gateway_iid() == claim.gateway_iid())
        {
            *existing = claim;
        } else {
            candidate_peer_claims.push(claim);
        }
        if self
            .commit_slot_state(candidate_verifier, candidate_peer_claims, candidate_owned)
            .is_err()
        {
            return CoapResponse::internal_error("slot state persistence failed");
        }

        // Return success
        let mut accept_fields = vec![(
            Value::Text("status".to_string()),
            Value::Text("accepted".to_string()),
        )];
        if let Some(slots) = reallocated_slots {
            accept_fields.push((
                Value::Text("local_slots".to_string()),
                Value::Array(
                    slots
                        .into_iter()
                        .map(|slot| Value::Integer(i64::from(slot).into()))
                        .collect(),
                ),
            ));
        }
        let accept = Value::Map(accept_fields);
        let mut payload = Vec::new();
        ciborium::into_writer(&accept, &mut payload).unwrap();

        CoapResponse::changed(payload)
    }

    /// Handle GET /channels request.
    pub fn handle_get_channels(&self) -> CoapResponse {
        let payload = self.channel_map.encode();
        CoapResponse::content(payload, CONTENT_FORMAT_CBOR)
    }

    /// Handle POST /handoff request.
    ///
    /// SECURITY: Caller MUST verify OSCORE authentication before calling
    /// when `require_oscore` is true.
    pub fn handle_post_handoff(&mut self, payload: &[u8], oscore_verified: bool) -> CoapResponse {
        let (response, staged) = self.stage_post_handoff(payload, oscore_verified);
        let Some(address) = staged else {
            return response;
        };
        // This compatibility entry point has no protected transport outcome
        // with which to finish the transaction. Never report a successful
        // transfer while stranding the source node in `busy` state.
        self.rollback_staged_handoff(&address);
        CoapResponse::internal_error("handoff requires transactional runtime dispatch")
    }

    /// Stage a handoff without releasing node ownership. The returned address
    /// must be committed only after the protected response transport succeeds,
    /// or rolled back on every failure.
    pub fn stage_post_handoff(
        &mut self,
        payload: &[u8],
        oscore_verified: bool,
    ) -> (CoapResponse, Option<[u8; 16]>) {
        if !oscore_verified {
            return (CoapResponse::unauthorized(), None);
        }

        let request = match HandoffRequest::decode(payload) {
            Ok(r) => r,
            Err(e) => return (CoapResponse::bad_request(&e.to_string()), None),
        };

        let response = self.node_registry.stage_handoff_request(&request);
        let staged = (response.status == crate::handoff::HandoffRejectReason::Success)
            .then_some(request.node_address);
        let encoded = response.encode();
        (
            CoapResponse {
                code: 0x44,
                payload: encoded,
                content_format: CONTENT_FORMAT_CBOR,
            },
            staged,
        )
    }

    pub fn commit_staged_handoff(&mut self, address: &[u8; 16]) -> bool {
        self.node_registry.commit_staged_handoff(address)
    }

    pub fn rollback_staged_handoff(&mut self, address: &[u8; 16]) -> bool {
        self.node_registry.rollback_staged_handoff(address)
    }

    /// Handle GET /nodes request.
    pub fn handle_get_nodes(&self) -> CoapResponse {
        let payload = encode_nodes_senml(&self.node_registry);
        CoapResponse::content(payload, CONTENT_FORMAT_SENML_CBOR)
    }

    /// Route a CoAP request to the appropriate handler.
    ///
    /// `path` is the URI path (e.g., "info", "slots", "channels", "handoff", "nodes").
    /// `oscore_verified` indicates whether the request was authenticated via OSCORE.
    pub fn handle_request(
        &mut self,
        method: CoapMethod,
        path: &str,
        payload: &[u8],
        oscore_verified: bool,
        peer_pubkey: Option<&[u8; 32]>,
        current_superframe: u64,
    ) -> CoapResponse {
        match (method, path) {
            (CoapMethod::Get, "info") => self.handle_get_info(),
            (CoapMethod::Get, "slots") => self.handle_get_slots(),
            (CoapMethod::Post, "slots") => {
                self.handle_post_slots(payload, oscore_verified, peer_pubkey, current_superframe)
            }
            (CoapMethod::Get, "channels") => self.handle_get_channels(),
            (CoapMethod::Post, "handoff") => self.handle_post_handoff(payload, oscore_verified),
            (CoapMethod::Get, "nodes") => self.handle_get_nodes(),
            (CoapMethod::Get, _) | (CoapMethod::Post, _) => CoapResponse::not_found(),
            _ => CoapResponse::method_not_allowed(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_link::keys::Seed;
    use schnorr48::{derive_keypair, sign};

    fn coordinator(iid: [u8; 16]) -> GatewayCoordinator {
        GatewayCoordinator::new_ephemeral(iid, 60, 64).unwrap()
    }

    fn signed_slot_claim(
        seed_bytes: [u8; 32],
        slots: Vec<u32>,
        superframe: u64,
        sequence: u32,
    ) -> (SlotClaim, [u8; 32]) {
        let (private, public) = derive_keypair(&Seed::new(seed_bytes));
        let pubkey = *public.as_bytes();
        let iid = crate::trust::iid_from_pubkey(&pubkey);
        let transcript = slot::slot_claim_transcript(&iid, &slots, superframe, sequence).unwrap();
        let signature = sign(&private, &public, &transcript);
        let mut claim = SlotClaim::new(iid, slots, superframe, sequence);
        claim.signature = Some(signature);
        (claim, pubkey)
    }

    fn coordinator_state_paths(name: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "lichen-gateway-coordinator-{name}-{}",
            std::process::id()
        ));
        (base.with_extension("state"), base.with_extension("floor"))
    }
    use crate::handoff::HandoffResponse;

    #[test]
    fn gateway_capabilities_roundtrip() {
        let caps = GatewayCapabilities {
            max_slots: 120,
            gps_sync: true,
            backbone_ipv6: true,
            lr_fhss: false,
            channels: 16,
            max_nodes: 512,
        };

        let cbor_map = caps.to_cbor_map();
        let decoded = GatewayCapabilities::from_cbor_map(&cbor_map).unwrap();

        assert_eq!(decoded.max_slots, 120);
        assert!(decoded.gps_sync);
        assert!(decoded.backbone_ipv6);
        assert!(!decoded.lr_fhss);
        assert_eq!(decoded.channels, 16);
        assert_eq!(decoded.max_nodes, 512);
    }

    #[test]
    fn slot_map_interleaved_owned_slots() {
        let slot_map = SlotMap {
            mode: AllocationMode::Interleaved,
            gateway_count: 3,
            ordinal: 1,
            start_slot: None,
            slot_count: None,
            owned: None,
        };

        let owned = slot_map.owned_slots(12);
        assert_eq!(owned, vec![1, 4, 7, 10]);
    }

    #[test]
    fn slot_map_contiguous_owned_slots() {
        let slot_map = SlotMap {
            mode: AllocationMode::Contiguous,
            gateway_count: 2,
            ordinal: 0,
            start_slot: Some(10),
            slot_count: Some(5),
            owned: None,
        };

        let owned = slot_map.owned_slots(60);
        assert_eq!(owned, vec![10, 11, 12, 13, 14]);
    }

    #[test]
    fn slot_map_rejects_zero_overflow_and_invalid_dimensions() {
        let map = |gateway_count: i64, ordinal: i64| {
            vec![
                (
                    Value::Integer(KEY_MAP_MODE.into()),
                    Value::Integer(0.into()),
                ),
                (
                    Value::Integer(KEY_MAP_GATEWAY_COUNT.into()),
                    Value::Integer(gateway_count.into()),
                ),
                (
                    Value::Integer(KEY_MAP_ORDINAL.into()),
                    Value::Integer(ordinal.into()),
                ),
            ]
        };
        assert!(SlotMap::from_cbor_map(&map(0, 0)).is_err());
        assert!(SlotMap::from_cbor_map(&map(256, 0)).is_err());
        assert!(SlotMap::from_cbor_map(&map(-1, 0)).is_err());
        assert!(SlotMap::from_cbor_map(&map(2, 2)).is_err());

        let invalid_range = SlotMap {
            mode: AllocationMode::Contiguous,
            gateway_count: 1,
            ordinal: 0,
            start_slot: Some(59),
            slot_count: Some(2),
            owned: None,
        };
        assert!(invalid_range.validate(60).is_err());
        assert!(invalid_range.owned_slots(60).is_empty());
    }

    #[test]
    fn gateway_info_encode_decode() {
        let mut info = GatewayInfo::new([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ]);
        info.superframe_epoch = Some(1720001000);
        info.time_source = "gps".to_string();

        let encoded = info.encode();
        let decoded = GatewayInfo::decode(&encoded).unwrap();

        assert_eq!(decoded.iid, info.iid);
        assert_eq!(decoded.superframe_epoch, Some(1720001000));
        assert_eq!(decoded.time_source, "gps");
        assert_eq!(decoded.federation_modes.len(), 2);
    }

    #[test]
    fn slot_claim_encode_decode() {
        let claim = SlotClaim::new(
            [0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            vec![0, 3, 6, 9],
            42,
            7,
        )
        .with_federation(3, 0);

        let encoded = claim.encode();
        let decoded = SlotClaim::decode(&encoded).unwrap();

        assert_eq!(decoded.gateway_iid, claim.gateway_iid);
        assert_eq!(decoded.slots, vec![0, 3, 6, 9]);
        assert_eq!(decoded.superframe_id, 42);
        assert_eq!(decoded.claim_sequence, 7);
        assert_eq!(decoded.gateway_count, Some(3));
        assert_eq!(decoded.ordinal, Some(0));
    }

    #[test]
    fn slot_claim_canonical_encoding() {
        let claim = SlotClaim::new(
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            vec![0, 1, 2],
            100,
            0,
        );

        let canonical1 = claim.encode_canonical();
        let canonical2 = claim.encode_canonical();

        // Deterministic encoding should produce identical output
        assert_eq!(canonical1, canonical2);
    }

    #[test]
    fn gateway_coordinator_get_info() {
        let iid = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];
        let coordinator = coordinator(iid);

        let response = coordinator.handle_get_info();
        assert_eq!(response.code, 0x45); // 2.05 Content
        assert_eq!(response.content_format, CONTENT_FORMAT_SENML_CBOR);

        // Verify we can decode the response
        let info = GatewayInfo::decode(&response.payload).unwrap();
        assert_eq!(info.iid, iid);
    }

    #[test]
    fn gateway_coordinator_get_slots() {
        let iid = [0u8; 16];
        let mut coordinator = coordinator(iid);
        coordinator.info.slot_map = SlotMap {
            mode: AllocationMode::Interleaved,
            gateway_count: 2,
            ordinal: 0,
            start_slot: None,
            slot_count: None,
            owned: None,
        };

        let response = coordinator.handle_get_slots();
        assert_eq!(response.code, 0x45); // 2.05 Content
        assert_eq!(response.content_format, CONTENT_FORMAT_CBOR);
    }

    #[test]
    fn gateway_coordinator_post_slots_requires_oscore() {
        let iid = [0u8; 16];
        let mut coordinator = coordinator(iid);
        // Set contiguous mode owning slots 0-29, so slots 30+ are not ours
        coordinator.info.slot_map = SlotMap {
            mode: AllocationMode::Contiguous,
            gateway_count: 2,
            ordinal: 0,
            start_slot: Some(0),
            slot_count: Some(30),
            owned: None,
        };

        // Claim slots 30, 31, 32 which we don't own (no conflict)
        let (claim, pubkey) = signed_slot_claim([0x31; 32], vec![30, 31, 32], 1, 0);
        let payload = claim.encode();

        // Without OSCORE, should return 4.01 Unauthorized
        let response = coordinator.handle_post_slots(&payload, false, Some(&pubkey), 1);
        assert_eq!(response.code, 0x81); // 4.01 Unauthorized

        // With OSCORE, should succeed (no conflict, claim accepted)
        let response = coordinator.handle_post_slots(&payload, true, Some(&pubkey), 1);
        assert_eq!(response.code, 0x44); // 2.04 Changed
    }

    #[test]
    fn gateway_coordinator_slot_conflict_resolution() {
        // Create coordinator with lower IID
        let lower_iid = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let mut coordinator = coordinator(lower_iid);
        coordinator.info.slot_map = SlotMap {
            mode: AllocationMode::Contiguous,
            gateway_count: 2,
            ordinal: 0,
            start_slot: Some(0),
            slot_count: Some(30),
            owned: None,
        };

        // Higher IID gateway claims overlapping slots
        let (claim, pubkey) = signed_slot_claim([0x41; 32], vec![10, 11, 12], 1, 0);
        let payload = claim.encode();

        let response = coordinator.handle_post_slots(&payload, true, Some(&pubkey), 1);
        // We have lower IID, so we should reject their claim
        assert_eq!(response.code, 0x45); // 2.05 Content (rejection payload)

        // Decode response to verify rejection
        let value: Value = ciborium::from_reader(response.payload.as_slice()).unwrap();
        if let Value::Map(m) = value {
            let status = m.iter().find_map(|(k, v)| {
                if let (Value::Text(key), Value::Text(val)) = (k, v) {
                    if key == "status" {
                        return Some(val.clone());
                    }
                }
                None
            });
            assert_eq!(status, Some("rejected".to_string()));
        } else {
            panic!("expected map response");
        }
    }

    #[test]
    fn lower_iid_peer_forces_complete_local_reallocation() {
        let mut local_address = [0u8; 16];
        local_address[8..].fill(0xff);
        let mut coordinator = coordinator(local_address);
        coordinator.info.slot_map = SlotMap {
            mode: AllocationMode::Contiguous,
            gateway_count: 2,
            ordinal: 0,
            start_slot: Some(0),
            slot_count: Some(30),
            owned: None,
        };
        let (claim, pubkey) = signed_slot_claim([0x51; 32], vec![10, 11, 12], 1, 0);
        let response = coordinator.handle_post_slots(&claim.encode(), true, Some(&pubkey), 1);
        assert_eq!(response.code, 0x44);

        let local_slots = coordinator
            .info
            .slot_map
            .owned_slots(coordinator.info.capabilities.max_slots);
        assert_eq!(local_slots.len(), 30);
        assert!(local_slots.iter().all(|slot| ![10, 11, 12].contains(slot)));
        assert!(local_slots.contains(&30));
        assert!(local_slots.contains(&31));
        assert!(local_slots.contains(&32));
        assert_eq!(coordinator.peer_claims.len(), 1);

        let Value::Map(fields) = ciborium::from_reader(response.payload.as_slice()).unwrap() else {
            panic!("expected accepted response map");
        };
        assert!(fields.iter().any(|(key, value)| {
            matches!(key, Value::Text(text) if text == "local_slots")
                && matches!(value, Value::Array(slots) if slots.len() == 30)
        }));
    }

    #[test]
    fn accepted_slot_semantics_and_replay_floor_survive_restart_together() {
        let (state_path, floor_path) = coordinator_state_paths("restart");
        let sealing_seed = [0x71; 32];
        let mut local_address = [0u8; 16];
        local_address[8..].fill(0xff);
        let mut coordinator = GatewayCoordinator::provision_persistent(
            local_address,
            60,
            4,
            &state_path,
            &floor_path,
            &sealing_seed,
        )
        .unwrap();
        coordinator.info.slot_map = SlotMap {
            mode: AllocationMode::Contiguous,
            gateway_count: 2,
            ordinal: 0,
            start_slot: Some(0),
            slot_count: Some(30),
            owned: None,
        };
        let (claim, pubkey) = signed_slot_claim([0x52; 32], vec![10, 11, 12], 4, 0);
        assert_eq!(
            coordinator
                .handle_post_slots(&claim.encode(), true, Some(&pubkey), 4)
                .code,
            0x44
        );
        let accepted_owned = coordinator.info.slot_map.owned.clone();
        let accepted_generation = coordinator.slot_replay_generation();
        drop(coordinator);

        let mut restored = GatewayCoordinator::load_persistent(
            local_address,
            60,
            4,
            &state_path,
            &floor_path,
            &sealing_seed,
        )
        .unwrap();
        assert_eq!(restored.slot_replay_generation(), accepted_generation);
        assert_eq!(restored.info.slot_map.owned, accepted_owned);
        assert_eq!(restored.peer_claims.len(), 1);
        assert_eq!(restored.peer_claims[0].slots(), &[10, 11, 12]);
        assert_eq!(
            restored
                .handle_post_slots(&claim.encode(), true, Some(&pubkey), 4)
                .code,
            0x81
        );

        fs::remove_file(state_path).unwrap();
        fs::remove_file(floor_path).unwrap();
    }

    #[test]
    fn slot_state_write_failure_does_not_consume_verified_claim() {
        let (state_path, floor_path) = coordinator_state_paths("write-failure");
        let sealing_seed = [0x73; 32];
        let mut coordinator = GatewayCoordinator::provision_persistent(
            [0u8; 16],
            60,
            4,
            &state_path,
            &floor_path,
            &sealing_seed,
        )
        .unwrap();
        let original_generation = coordinator.slot_replay_generation();
        let original_owned = coordinator.info.slot_map.owned.clone();
        let original_path = coordinator
            .replay_persistence
            .as_ref()
            .unwrap()
            .path
            .clone();
        coordinator.replay_persistence.as_mut().unwrap().path = state_path
            .with_extension("missing-parent")
            .join("coordinator.state");
        let (claim, pubkey) = signed_slot_claim([0x53; 32], vec![40], 9, 0);
        assert_eq!(
            coordinator
                .handle_post_slots(&claim.encode(), true, Some(&pubkey), 9)
                .code,
            0xa0
        );
        assert_eq!(coordinator.slot_replay_generation(), original_generation);
        assert!(coordinator.peer_claims.is_empty());
        assert_eq!(coordinator.info.slot_map.owned, original_owned);

        coordinator.replay_persistence.as_mut().unwrap().path = original_path;
        assert_eq!(
            coordinator
                .handle_post_slots(&claim.encode(), true, Some(&pubkey), 9)
                .code,
            0x45
        );
        assert!(coordinator.slot_replay_generation() > original_generation);
        fs::remove_file(state_path).unwrap();
        fs::remove_file(floor_path).unwrap();
    }

    #[test]
    fn gateway_coordinator_get_channels() {
        let iid = [0u8; 16];
        let coordinator = coordinator(iid);

        let response = coordinator.handle_get_channels();
        assert_eq!(response.code, 0x45); // 2.05 Content
        assert_eq!(response.content_format, CONTENT_FORMAT_CBOR);

        // Should have 8 default channels
        let value: Value = ciborium::from_reader(response.payload.as_slice()).unwrap();
        if let Value::Array(arr) = value {
            assert_eq!(arr.len(), 8);
        } else {
            panic!("expected array response");
        }
    }

    #[test]
    fn gateway_coordinator_post_handoff() {
        use crate::handoff::NodeRegistryEntry;

        let iid = [0u8; 16];
        let mut coordinator = coordinator(iid);

        // Register a node
        let node_addr = [
            0x02u8, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        ];
        let mut entry = NodeRegistryEntry::new(node_addr);
        entry.dao_sequence = 42;
        entry.path_sequence = 10;
        coordinator.node_registry.register(entry);

        // Request handoff
        let request = HandoffRequest::new(node_addr, 1720001000);
        let payload = request.encode();

        let (response, staged) = coordinator.stage_post_handoff(&payload, true);
        assert_eq!(response.code, 0x44); // 2.04 Changed

        // Ownership remains until the protected response transport succeeds.
        assert_eq!(staged, Some(node_addr));
        assert!(coordinator.node_registry.get(&node_addr).unwrap().busy);

        // Decode response to verify success
        let handoff_response = HandoffResponse::decode(&response.payload).unwrap();
        assert_eq!(
            handoff_response.status,
            crate::handoff::HandoffRejectReason::Success
        );
        assert_eq!(handoff_response.dao_sequence, Some(42));
        assert!(coordinator.commit_staged_handoff(&node_addr));
        assert!(!coordinator.node_registry.contains(&node_addr));
    }

    #[test]
    fn non_transactional_handoff_dispatch_rolls_back_staged_node() {
        use crate::handoff::NodeRegistryEntry;

        let node_addr = [0x02; 16];
        let mut coordinator = coordinator([0u8; 16]);
        coordinator
            .node_registry
            .register(NodeRegistryEntry::new(node_addr));
        let payload = HandoffRequest::new(node_addr, 1).encode();

        let response = coordinator.handle_post_handoff(&payload, true);
        assert_eq!(response.code, 0xa0);
        let entry = coordinator.node_registry.get(&node_addr).unwrap();
        assert!(!entry.busy);
    }

    #[test]
    fn gateway_coordinator_get_nodes() {
        use crate::handoff::NodeRegistryEntry;

        let iid = [0u8; 16];
        let mut coordinator = coordinator(iid);

        // Register some nodes
        for i in 0..3 {
            let mut addr = [0x02u8; 16];
            addr[15] = i;
            let mut entry = NodeRegistryEntry::new(addr);
            entry.dao_sequence = i as u32 * 10;
            entry.last_seen = 1720001000.0 + i as f64;
            coordinator.node_registry.register(entry);
        }

        let response = coordinator.handle_get_nodes();
        assert_eq!(response.code, 0x45); // 2.05 Content
        assert_eq!(response.content_format, CONTENT_FORMAT_SENML_CBOR);

        // Decode SenML pack
        let value: Value = ciborium::from_reader(response.payload.as_slice()).unwrap();
        if let Value::Array(arr) = value {
            // Base record + 3 node records
            assert_eq!(arr.len(), 4);
        } else {
            panic!("expected array response");
        }
    }

    #[test]
    fn gateway_coordinator_routing() {
        let iid = [0u8; 16];
        let mut coordinator = coordinator(iid);

        // Test routing
        let response = coordinator.handle_request(CoapMethod::Get, "info", &[], false, None, 0);
        assert_eq!(response.code, 0x45);

        let response = coordinator.handle_request(CoapMethod::Get, "unknown", &[], false, None, 0);
        assert_eq!(response.code, 0x84); // 4.04 Not Found

        let response = coordinator.handle_request(CoapMethod::Delete, "info", &[], false, None, 0);
        assert_eq!(response.code, 0x85); // 4.05 Method Not Allowed
    }
}
