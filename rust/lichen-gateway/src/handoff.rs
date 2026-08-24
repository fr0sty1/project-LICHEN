//! Node handoff protocol for multi-gateway coordination (GCP-7).
//!
//! Per spec section 08-gateway-coordination.md GCP-7, when a node moves between
//! gateways (detected via better parent/RSSI):
//!
//! 1. Node sends DAO to new Gateway B
//! 2. B sends POST /handoff to A (via backbone) with node details
//! 3. A releases node from its registry, sends confirmation
//! 4. B confirms handoff to node via CoAP
//! 5. Routes updated in RPL DODAG
//!
//! State transferred includes:
//! - Node IPv6 address (derived from Ed25519 IID)
//! - Recent sequence numbers (DAO, OSCORE sender/recipient)
//! - Security contexts (OSCORE parameters, replay windows)
//! - Path sequence and freshness state
//!
//! SECURITY: Handoff messages MUST be authenticated via OSCORE (PSK mode for
//! closed federation, signatures for open federation per GCP-3). Unauthenticated
//! handoff requests enable node hijacking attacks.
//!
//! SECURITY: Sequence numbers MUST be transferred accurately. Gaps cause replay
//! acceptance; duplicates cause legitimate messages to be rejected. The receiving
//! gateway MUST use a sequence number strictly greater than the transferred value.

use std::collections::HashMap;

use ciborium::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// IPv6 address (128 bits).
pub type Ipv6Addr = [u8; 16];

/// Error type for handoff protocol operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffError {
    /// Invalid CBOR encoding.
    InvalidCbor,
    /// Expected CBOR map but got something else.
    ExpectedMap,
    /// Missing required field.
    MissingField(&'static str),
    /// Invalid field type.
    InvalidFieldType(&'static str),
    /// Invalid IPv6 address.
    InvalidAddress,
    /// Malformed OSCORE state.
    MalformedOscoreState(String),
    /// Malformed freshness state.
    MalformedFreshnessState(String),
    /// Cannot accept failed handoff.
    HandoffFailed(HandoffRejectReason),
    /// Success response missing required field.
    MissingSuccessField(&'static str),
    /// A transferred replay/nonce sequence cannot be advanced safely.
    SequenceExhausted(&'static str),
}

impl std::fmt::Display for HandoffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCbor => write!(f, "invalid CBOR"),
            Self::ExpectedMap => write!(f, "expected CBOR map"),
            Self::MissingField(name) => write!(f, "missing field: {}", name),
            Self::InvalidFieldType(name) => write!(f, "invalid type for field: {}", name),
            Self::InvalidAddress => write!(f, "invalid IPv6 address"),
            Self::MalformedOscoreState(msg) => write!(f, "malformed OSCORE state: {}", msg),
            Self::MalformedFreshnessState(msg) => write!(f, "malformed freshness state: {}", msg),
            Self::HandoffFailed(reason) => {
                write!(f, "cannot accept failed handoff: {:?}", reason)
            }
            Self::MissingSuccessField(name) => {
                write!(f, "success response missing {}", name)
            }
            Self::SequenceExhausted(name) => write!(f, "handoff sequence exhausted: {name}"),
        }
    }
}

impl std::error::Error for HandoffError {}

/// Reasons a handoff request may be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandoffRejectReason {
    /// Success (not an error).
    Success = 0,
    /// Node not found in source gateway's registry.
    NodeNotFound = 1,
    /// Node is currently in active communication (retry later).
    NodeBusy = 2,
    /// Authentication failed (OSCORE verification).
    AuthFailed = 3,
    /// Malformed request payload.
    MalformedRequest = 4,
    /// Source gateway internal error.
    InternalError = 5,
    /// Rate limited (too many handoff requests).
    RateLimited = 6,
}

impl TryFrom<u8> for HandoffRejectReason {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::NodeNotFound),
            2 => Ok(Self::NodeBusy),
            3 => Ok(Self::AuthFailed),
            4 => Ok(Self::MalformedRequest),
            5 => Ok(Self::InternalError),
            6 => Ok(Self::RateLimited),
            _ => Err(()),
        }
    }
}

// CBOR map keys for handoff request/response (short keys for constrained links)
// Request keys
const KEY_NODE_ADDR: i64 = 1;
const KEY_DAO_SEQ: i64 = 2;
const KEY_PATH_SEQ: i64 = 3;
const KEY_OSCORE_PARAMS: i64 = 4;
const KEY_OSCORE_SENDER_SEQ: i64 = 5;
const KEY_OSCORE_REPLAY: i64 = 6;
const KEY_FRESHNESS: i64 = 7;
const KEY_PARENTS: i64 = 8;
const KEY_RSSI: i64 = 9;
const KEY_TIMESTAMP: i64 = 10;

// Response keys (use 100+ to avoid collision with request keys)
const KEY_STATUS: i64 = 100;
const KEY_MESSAGE: i64 = 101;

// OSCORE parameters subkeys
const KEY_OSCORE_SECRET: i64 = 1;
const KEY_OSCORE_SALT: i64 = 2;
const KEY_OSCORE_SENDER_ID: i64 = 3;
const KEY_OSCORE_RECIPIENT_ID: i64 = 4;
const KEY_OSCORE_ALG: i64 = 5;
const KEY_OSCORE_HASHFUN: i64 = 6;
const KEY_OSCORE_WINDOW: i64 = 7;
const KEY_OSCORE_ID_CTX: i64 = 8;

/// OSCORE security context state for handoff transfer.
///
/// Contains all parameters needed to reconstruct an equivalent security
/// context on the receiving gateway.
///
/// SECURITY: master_secret is sensitive. This structure should only exist
/// transiently during handoff and MUST be protected by OSCORE transport.
/// Zeroized on drop to prevent secret leakage.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct OscoreState {
    pub master_secret: Vec<u8>,
    pub master_salt: Vec<u8>,
    pub sender_id: Vec<u8>,
    pub recipient_id: Vec<u8>,
    pub algorithm: i64,
    pub hashfun: String,
    pub window_size: u32,
    pub id_context: Option<Vec<u8>>,
    pub sender_sequence: u64,
    pub replay_index: u64,
    pub replay_bitfield: u64,
}

impl OscoreState {
    /// Encode as CBOR value (partial map entries for embedding in response).
    fn to_cbor_entries(&self) -> Vec<(Value, Value)> {
        let mut params: Vec<(Value, Value)> = vec![
            (
                Value::Integer(KEY_OSCORE_SECRET.into()),
                Value::Bytes(self.master_secret.clone()),
            ),
            (
                Value::Integer(KEY_OSCORE_SALT.into()),
                Value::Bytes(self.master_salt.clone()),
            ),
            (
                Value::Integer(KEY_OSCORE_SENDER_ID.into()),
                Value::Bytes(self.sender_id.clone()),
            ),
            (
                Value::Integer(KEY_OSCORE_RECIPIENT_ID.into()),
                Value::Bytes(self.recipient_id.clone()),
            ),
            (
                Value::Integer(KEY_OSCORE_ALG.into()),
                Value::Integer(self.algorithm.into()),
            ),
            (
                Value::Integer(KEY_OSCORE_HASHFUN.into()),
                Value::Text(self.hashfun.clone()),
            ),
            (
                Value::Integer(KEY_OSCORE_WINDOW.into()),
                Value::Integer((self.window_size as i64).into()),
            ),
        ];
        if let Some(ref ctx) = self.id_context {
            params.push((
                Value::Integer(KEY_OSCORE_ID_CTX.into()),
                Value::Bytes(ctx.clone()),
            ));
        }

        vec![
            (Value::Integer(KEY_OSCORE_PARAMS.into()), Value::Map(params)),
            (
                Value::Integer(KEY_OSCORE_SENDER_SEQ.into()),
                Value::Integer((self.sender_sequence as i64).into()),
            ),
            (
                Value::Integer(KEY_OSCORE_REPLAY.into()),
                Value::Array(vec![
                    Value::Integer((self.replay_index as i64).into()),
                    Value::Integer((self.replay_bitfield as i64).into()),
                ]),
            ),
        ]
    }

    /// Decode from CBOR map.
    fn from_cbor_map(map: &[(Value, Value)]) -> Result<Self, HandoffError> {
        // Get params submap
        let params = cbor_get_map(map, KEY_OSCORE_PARAMS)
            .ok_or_else(|| HandoffError::MalformedOscoreState("missing params".into()))?;

        let mut master_secret =
            zeroize::Zeroizing::new(cbor_get_bytes(params, KEY_OSCORE_SECRET).ok_or_else(
                || HandoffError::MalformedOscoreState("missing master_secret".into()),
            )?);
        let mut master_salt = zeroize::Zeroizing::new(
            cbor_get_bytes(params, KEY_OSCORE_SALT)
                .ok_or_else(|| HandoffError::MalformedOscoreState("missing master_salt".into()))?,
        );
        let mut sender_id = zeroize::Zeroizing::new(
            cbor_get_bytes(params, KEY_OSCORE_SENDER_ID)
                .ok_or_else(|| HandoffError::MalformedOscoreState("missing sender_id".into()))?,
        );
        let mut recipient_id = zeroize::Zeroizing::new(
            cbor_get_bytes(params, KEY_OSCORE_RECIPIENT_ID)
                .ok_or_else(|| HandoffError::MalformedOscoreState("missing recipient_id".into()))?,
        );
        let algorithm = cbor_get_int(params, KEY_OSCORE_ALG)
            .ok_or_else(|| HandoffError::MalformedOscoreState("missing algorithm".into()))?;
        let hashfun = cbor_get_text(params, KEY_OSCORE_HASHFUN)
            .ok_or_else(|| HandoffError::MalformedOscoreState("missing hashfun".into()))?;
        let window_size = cbor_get_int(params, KEY_OSCORE_WINDOW)
            .ok_or_else(|| HandoffError::MalformedOscoreState("missing window_size".into()))?
            as u32;
        let mut id_context = cbor_get_bytes(params, KEY_OSCORE_ID_CTX).map(zeroize::Zeroizing::new);

        let sender_sequence = cbor_get_int(map, KEY_OSCORE_SENDER_SEQ)
            .ok_or_else(|| HandoffError::MalformedOscoreState("missing sender_sequence".into()))?
            as u64;

        let replay = cbor_get_array(map, KEY_OSCORE_REPLAY)
            .ok_or_else(|| HandoffError::MalformedOscoreState("missing replay".into()))?;
        if replay.len() != 2 {
            return Err(HandoffError::MalformedOscoreState(
                "replay must be [index, bitfield]".into(),
            ));
        }
        let replay_index = match &replay[0] {
            Value::Integer(i) => i128::from(*i) as u64,
            _ => {
                return Err(HandoffError::MalformedOscoreState(
                    "replay_index must be integer".into(),
                ))
            }
        };
        let replay_bitfield = match &replay[1] {
            Value::Integer(i) => i128::from(*i) as u64,
            _ => {
                return Err(HandoffError::MalformedOscoreState(
                    "replay_bitfield must be integer".into(),
                ))
            }
        };

        Ok(Self {
            master_secret: core::mem::take(&mut *master_secret),
            master_salt: core::mem::take(&mut *master_salt),
            sender_id: core::mem::take(&mut *sender_id),
            recipient_id: core::mem::take(&mut *recipient_id),
            algorithm,
            hashfun,
            window_size,
            id_context: id_context
                .as_mut()
                .map(|context| core::mem::take(&mut **context)),
            sender_sequence,
            replay_index,
            replay_bitfield,
        })
    }
}

fn zeroize_cbor_value(value: &mut Value) {
    match value {
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::Text(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_cbor_value),
        Value::Map(entries) => entries.iter_mut().for_each(|(key, value)| {
            zeroize_cbor_value(key);
            zeroize_cbor_value(value);
        }),
        Value::Tag(_, value) => zeroize_cbor_value(value),
        _ => {}
    }
}

struct SecretCborValue(Value);

impl Drop for SecretCborValue {
    fn drop(&mut self) {
        zeroize_cbor_value(&mut self.0);
    }
}

// Helper functions for CBOR map access (avoid lifetime issues with closures)
fn cbor_get_int(map: &[(Value, Value)], key: i64) -> Option<i64> {
    for (k, v) in map {
        if let Value::Integer(ki) = k {
            if i128::from(*ki) == key as i128 {
                if let Value::Integer(vi) = v {
                    return Some(i128::from(*vi) as i64);
                }
            }
        }
    }
    None
}

fn cbor_get_bytes(map: &[(Value, Value)], key: i64) -> Option<Vec<u8>> {
    for (k, v) in map {
        if let Value::Integer(ki) = k {
            if i128::from(*ki) == key as i128 {
                if let Value::Bytes(b) = v {
                    return Some(b.clone());
                }
            }
        }
    }
    None
}

fn cbor_get_text(map: &[(Value, Value)], key: i64) -> Option<String> {
    for (k, v) in map {
        if let Value::Integer(ki) = k {
            if i128::from(*ki) == key as i128 {
                if let Value::Text(t) = v {
                    return Some(t.clone());
                }
            }
        }
    }
    None
}

fn cbor_get_map(map: &[(Value, Value)], key: i64) -> Option<&[(Value, Value)]> {
    for (k, v) in map {
        if let Value::Integer(ki) = k {
            if i128::from(*ki) == key as i128 {
                if let Value::Map(m) = v {
                    return Some(m.as_slice());
                }
            }
        }
    }
    None
}

fn cbor_get_array(map: &[(Value, Value)], key: i64) -> Option<&[Value]> {
    for (k, v) in map {
        if let Value::Integer(ki) = k {
            if i128::from(*ki) == key as i128 {
                if let Value::Array(a) = v {
                    return Some(a.as_slice());
                }
            }
        }
    }
    None
}

/// DAO freshness tracking state for handoff transfer.
#[derive(Debug, Clone, PartialEq)]
pub struct FreshnessState {
    pub sequence: u32,
    pub active_until: Option<f64>,
    pub retain_until: f64,
    pub updated_at: f64,
}

impl FreshnessState {
    /// Encode as CBOR map.
    fn to_cbor_map(&self) -> Value {
        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Text("seq".into()),
                Value::Integer((self.sequence as i64).into()),
            ),
            (
                Value::Text("retain".into()),
                Value::Float(self.retain_until),
            ),
            (Value::Text("updated".into()), Value::Float(self.updated_at)),
        ];
        if let Some(active) = self.active_until {
            entries.push((Value::Text("active".into()), Value::Float(active)));
        }
        Value::Map(entries)
    }

    /// Decode from CBOR map.
    fn from_cbor_map(map: &[(Value, Value)]) -> Result<Self, HandoffError> {
        let get_int = |key: &str| -> Option<i128> {
            for (k, v) in map {
                if let Value::Text(t) = k {
                    if t == key {
                        if let Value::Integer(i) = v {
                            return Some(i128::from(*i));
                        }
                    }
                }
            }
            None
        };

        let get_float = |key: &str| -> Option<f64> {
            for (k, v) in map {
                if let Value::Text(t) = k {
                    if t == key {
                        if let Value::Float(f) = v {
                            return Some(*f);
                        }
                    }
                }
            }
            None
        };

        let sequence = get_int("seq")
            .ok_or_else(|| HandoffError::MalformedFreshnessState("missing seq".into()))?
            as u32;
        let retain_until = get_float("retain")
            .ok_or_else(|| HandoffError::MalformedFreshnessState("missing retain".into()))?;
        let updated_at = get_float("updated")
            .ok_or_else(|| HandoffError::MalformedFreshnessState("missing updated".into()))?;
        let active_until = get_float("active");

        Ok(Self {
            sequence,
            active_until,
            retain_until,
            updated_at,
        })
    }
}

/// POST /handoff request payload from new gateway to old gateway.
///
/// Sent by Gateway B (new) to Gateway A (old) to request node state
/// transfer. Gateway A should:
/// 1. Verify authentication (OSCORE)
/// 2. Check if node is in its registry
/// 3. Check if node is not in active communication
/// 4. Extract and package state
/// 5. Release node from registry
/// 6. Send HandoffResponse with state
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffRequest {
    pub node_address: Ipv6Addr,
    pub timestamp: i64,
    pub rssi: Option<i32>,
}

impl HandoffRequest {
    /// Create a new handoff request.
    pub fn new(node_address: Ipv6Addr, timestamp: i64) -> Self {
        Self {
            node_address,
            timestamp,
            rssi: None,
        }
    }

    /// Create a new handoff request with RSSI.
    pub fn with_rssi(node_address: Ipv6Addr, timestamp: i64, rssi: i32) -> Self {
        Self {
            node_address,
            timestamp,
            rssi: Some(rssi),
        }
    }

    /// Encode as CBOR for transmission.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries: Vec<(Value, Value)> = vec![
            (
                Value::Integer(KEY_NODE_ADDR.into()),
                Value::Bytes(self.node_address.to_vec()),
            ),
            (
                Value::Integer(KEY_TIMESTAMP.into()),
                Value::Integer(self.timestamp.into()),
            ),
        ];
        if let Some(rssi) = self.rssi {
            entries.push((
                Value::Integer(KEY_RSSI.into()),
                Value::Integer((rssi as i64).into()),
            ));
        }

        let value = Value::Map(entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    /// Decode from CBOR payload.
    pub fn decode(payload: &[u8]) -> Result<Self, HandoffError> {
        let value =
            SecretCborValue(ciborium::from_reader(payload).map_err(|_| HandoffError::InvalidCbor)?);

        let map = match &value.0 {
            Value::Map(m) => m,
            _ => return Err(HandoffError::ExpectedMap),
        };

        let mut node_address: Option<Ipv6Addr> = None;
        let mut timestamp: Option<i64> = None;
        let mut rssi: Option<i32> = None;

        for (k, v) in map {
            let key = match k {
                Value::Integer(i) => i128::from(*i),
                _ => continue,
            };

            match key as i64 {
                KEY_NODE_ADDR => {
                    if let Value::Bytes(b) = v {
                        if b.len() == 16 {
                            let mut addr = [0u8; 16];
                            addr.copy_from_slice(b);
                            node_address = Some(addr);
                        } else {
                            return Err(HandoffError::InvalidAddress);
                        }
                    } else {
                        return Err(HandoffError::InvalidFieldType("node_address"));
                    }
                }
                KEY_TIMESTAMP => {
                    if let Value::Integer(i) = v {
                        timestamp = Some(i128::from(*i) as i64);
                    } else {
                        return Err(HandoffError::InvalidFieldType("timestamp"));
                    }
                }
                KEY_RSSI => {
                    if let Value::Integer(i) = v {
                        rssi = Some(i128::from(*i) as i32);
                    } else {
                        return Err(HandoffError::InvalidFieldType("rssi"));
                    }
                }
                _ => {}
            }
        }

        let node_address = node_address.ok_or(HandoffError::MissingField("node_address"))?;
        let timestamp = timestamp.ok_or(HandoffError::MissingField("timestamp"))?;

        Ok(Self {
            node_address,
            timestamp,
            rssi,
        })
    }
}

/// POST /handoff response payload from old gateway to new gateway.
///
/// On success, contains all state needed for the new gateway to take
/// over responsibility for the node. On failure, contains rejection
/// reason.
#[derive(Debug, Clone, PartialEq)]
pub struct HandoffResponse {
    pub status: HandoffRejectReason,
    pub message: String,

    // State fields (only present on success)
    pub node_address: Option<Ipv6Addr>,
    pub dao_sequence: Option<u32>,
    pub path_sequence: Option<u32>,
    pub oscore_state: Option<OscoreState>,
    pub freshness: Option<FreshnessState>,
    pub parents: Vec<Ipv6Addr>,
}

impl HandoffResponse {
    /// Create a successful handoff response with state transfer.
    pub fn success(node_address: Ipv6Addr, dao_sequence: u32, path_sequence: u32) -> Self {
        Self {
            status: HandoffRejectReason::Success,
            message: String::new(),
            node_address: Some(node_address),
            dao_sequence: Some(dao_sequence),
            path_sequence: Some(path_sequence),
            oscore_state: None,
            freshness: None,
            parents: Vec::new(),
        }
    }

    /// Create an error response.
    pub fn error(reason: HandoffRejectReason, message: impl Into<String>) -> Self {
        Self {
            status: reason,
            message: message.into(),
            node_address: None,
            dao_sequence: None,
            path_sequence: None,
            oscore_state: None,
            freshness: None,
            parents: Vec::new(),
        }
    }

    /// Add OSCORE state to a success response.
    pub fn with_oscore(mut self, state: OscoreState) -> Self {
        self.oscore_state = Some(state);
        self
    }

    /// Add freshness state to a success response.
    pub fn with_freshness(mut self, state: FreshnessState) -> Self {
        self.freshness = Some(state);
        self
    }

    /// Add parents to a success response.
    pub fn with_parents(mut self, parents: Vec<Ipv6Addr>) -> Self {
        self.parents = parents;
        self
    }

    /// Encode as CBOR for transmission.
    pub fn encode(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut entries: Vec<(Value, Value)> = vec![(
            Value::Integer(KEY_STATUS.into()),
            Value::Integer((self.status as i64).into()),
        )];

        if !self.message.is_empty() {
            entries.push((
                Value::Integer(KEY_MESSAGE.into()),
                Value::Text(self.message.clone()),
            ));
        }

        if self.status == HandoffRejectReason::Success {
            if let Some(addr) = self.node_address {
                entries.push((
                    Value::Integer(KEY_NODE_ADDR.into()),
                    Value::Bytes(addr.to_vec()),
                ));
            }
            if let Some(seq) = self.dao_sequence {
                entries.push((
                    Value::Integer(KEY_DAO_SEQ.into()),
                    Value::Integer((seq as i64).into()),
                ));
            }
            if let Some(seq) = self.path_sequence {
                entries.push((
                    Value::Integer(KEY_PATH_SEQ.into()),
                    Value::Integer((seq as i64).into()),
                ));
            }
            if let Some(ref oscore) = self.oscore_state {
                entries.extend(oscore.to_cbor_entries());
            }
            if let Some(ref fresh) = self.freshness {
                entries.push((Value::Integer(KEY_FRESHNESS.into()), fresh.to_cbor_map()));
            }
            if !self.parents.is_empty() {
                let parent_values: Vec<Value> = self
                    .parents
                    .iter()
                    .map(|p| Value::Bytes(p.to_vec()))
                    .collect();
                entries.push((
                    Value::Integer(KEY_PARENTS.into()),
                    Value::Array(parent_values),
                ));
            }
        }

        let mut value = Value::Map(entries);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).expect("CBOR encoding should not fail");
        zeroize_cbor_value(&mut value);
        zeroize::Zeroizing::new(buf)
    }

    /// Decode from CBOR payload.
    pub fn decode(payload: &[u8]) -> Result<Self, HandoffError> {
        let value =
            SecretCborValue(ciborium::from_reader(payload).map_err(|_| HandoffError::InvalidCbor)?);

        let map = match &value.0 {
            Value::Map(m) => m,
            _ => return Err(HandoffError::ExpectedMap),
        };

        let map_slice = map.as_slice();

        // Helper to get integer value by key
        let get_int = |key: i64| -> Option<i128> {
            for (k, v) in map_slice {
                if let Value::Integer(ki) = k {
                    if i128::from(*ki) == key as i128 {
                        if let Value::Integer(vi) = v {
                            return Some(i128::from(*vi));
                        }
                    }
                }
            }
            None
        };

        let get_text = |key: i64| -> Option<String> {
            for (k, v) in map_slice {
                if let Value::Integer(ki) = k {
                    if i128::from(*ki) == key as i128 {
                        if let Value::Text(t) = v {
                            return Some(t.clone());
                        }
                    }
                }
            }
            None
        };

        let get_bytes = |key: i64| -> Option<Vec<u8>> {
            for (k, v) in map_slice {
                if let Value::Integer(ki) = k {
                    if i128::from(*ki) == key as i128 {
                        if let Value::Bytes(b) = v {
                            return Some(b.clone());
                        }
                    }
                }
            }
            None
        };

        let status_raw = get_int(KEY_STATUS).ok_or(HandoffError::MissingField("status"))? as u8;
        let status = HandoffRejectReason::try_from(status_raw)
            .map_err(|_| HandoffError::InvalidFieldType("status"))?;

        let message = get_text(KEY_MESSAGE).unwrap_or_default();

        if status != HandoffRejectReason::Success {
            return Ok(Self::error(status, message));
        }

        // Parse success response with state
        let node_address = if let Some(b) = get_bytes(KEY_NODE_ADDR) {
            if b.len() == 16 {
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&b);
                Some(addr)
            } else {
                return Err(HandoffError::InvalidAddress);
            }
        } else {
            None
        };

        let dao_sequence = get_int(KEY_DAO_SEQ).map(|i| i as u32);
        let path_sequence = get_int(KEY_PATH_SEQ).map(|i| i as u32);

        // Check for OSCORE state
        let oscore_state = {
            let mut has_oscore = false;
            for (k, _) in map_slice {
                if let Value::Integer(ki) = k {
                    if i128::from(*ki) == KEY_OSCORE_PARAMS as i128 {
                        has_oscore = true;
                        break;
                    }
                }
            }
            if has_oscore {
                Some(OscoreState::from_cbor_map(map_slice)?)
            } else {
                None
            }
        };

        // Check for freshness state
        let freshness = {
            let mut fresh_map: Option<&[(Value, Value)]> = None;
            for (k, v) in map_slice {
                if let Value::Integer(ki) = k {
                    if i128::from(*ki) == KEY_FRESHNESS as i128 {
                        if let Value::Map(m) = v {
                            fresh_map = Some(m.as_slice());
                        }
                    }
                }
            }
            fresh_map.map(FreshnessState::from_cbor_map).transpose()?
        };

        // Parse parents
        let mut parents = Vec::new();
        for (k, v) in map_slice {
            if let Value::Integer(ki) = k {
                if i128::from(*ki) == KEY_PARENTS as i128 {
                    if let Value::Array(arr) = v {
                        for item in arr {
                            if let Value::Bytes(b) = item {
                                if b.len() == 16 {
                                    let mut addr = [0u8; 16];
                                    addr.copy_from_slice(b);
                                    parents.push(addr);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            status,
            message,
            node_address,
            dao_sequence,
            path_sequence,
            oscore_state,
            freshness,
            parents,
        })
    }
}

/// State tracked per node in a gateway's registry.
///
/// This is the internal state that gets exported during handoff.
#[derive(Debug, Clone)]
pub struct NodeRegistryEntry {
    pub address: Ipv6Addr,
    pub dao_sequence: u32,
    pub path_sequence: u32,
    pub oscore_state: Option<OscoreState>,
    pub freshness: Option<FreshnessState>,
    pub parents: Vec<Ipv6Addr>,
    pub last_seen: f64,
    pub busy: bool,
}

impl NodeRegistryEntry {
    /// Create a new registry entry with default values.
    pub fn new(address: Ipv6Addr) -> Self {
        Self {
            address,
            dao_sequence: 0,
            path_sequence: 0,
            oscore_state: None,
            freshness: None,
            parents: Vec::new(),
            last_seen: 0.0,
            busy: false,
        }
    }
}

/// Gateway-side node registry for handoff protocol.
///
/// Tracks nodes that have joined via this gateway and their state.
/// Provides extraction for handoff and registration for incoming nodes.
#[derive(Debug, Default)]
pub struct NodeRegistry {
    nodes: HashMap<Ipv6Addr, NodeRegistryEntry>,
}

impl NodeRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Register a node or update its state.
    pub fn register(&mut self, entry: NodeRegistryEntry) {
        self.nodes.insert(entry.address, entry);
    }

    /// Remove a node from the registry, returning its entry if present.
    pub fn unregister(&mut self, address: &Ipv6Addr) -> Option<NodeRegistryEntry> {
        self.nodes.remove(address)
    }

    /// Get a node's registry entry.
    pub fn get(&self, address: &Ipv6Addr) -> Option<&NodeRegistryEntry> {
        self.nodes.get(address)
    }

    /// Get a mutable reference to a node's registry entry.
    pub fn get_mut(&mut self, address: &Ipv6Addr) -> Option<&mut NodeRegistryEntry> {
        self.nodes.get_mut(address)
    }

    /// Check if a node is registered.
    pub fn contains(&self, address: &Ipv6Addr) -> bool {
        self.nodes.contains_key(address)
    }

    /// Mark a node as busy (in active transaction) or not.
    pub fn set_busy(&mut self, address: &Ipv6Addr, busy: bool) {
        if let Some(entry) = self.nodes.get_mut(address) {
            entry.busy = busy;
        }
    }

    /// Stage a handoff request from another gateway.
    ///
    /// This is the core handoff logic on the source gateway side:
    /// 1. Check if node exists in registry
    /// 2. Check if node is busy
    /// 3. Extract state
    /// 4. Mark the node busy while the protected response is sent
    /// 5. Return success response with state
    ///
    /// SECURITY: Caller MUST verify OSCORE authentication before calling.
    /// This method assumes the request is from a trusted peer gateway.
    pub fn stage_handoff_request(&mut self, request: &HandoffRequest) -> HandoffResponse {
        let address = &request.node_address;

        let entry = match self.get(address) {
            Some(e) => e,
            None => {
                return HandoffResponse::error(
                    HandoffRejectReason::NodeNotFound,
                    format!("node {:02x?} not in registry", address),
                );
            }
        };

        if entry.busy {
            return HandoffResponse::error(
                HandoffRejectReason::NodeBusy,
                format!(
                    "node {:02x?} is in active transaction, retry later",
                    address
                ),
            );
        }

        // Extract state before removing
        let response =
            HandoffResponse::success(entry.address, entry.dao_sequence, entry.path_sequence);

        let response = if let Some(ref oscore) = entry.oscore_state {
            response.with_oscore(oscore.clone())
        } else {
            response
        };

        let response = if let Some(ref fresh) = entry.freshness {
            response.with_freshness(fresh.clone())
        } else {
            response
        };

        let response = if !entry.parents.is_empty() {
            response.with_parents(entry.parents.clone())
        } else {
            response
        };

        self.set_busy(address, true);

        response
    }

    /// Compatibility entry point; stages but never releases ownership.
    pub fn handle_handoff_request(&mut self, request: &HandoffRequest) -> HandoffResponse {
        self.stage_handoff_request(request)
    }

    /// Release ownership only after the staged response has been protected
    /// and accepted by the transport boundary.
    pub fn commit_staged_handoff(&mut self, address: &Ipv6Addr) -> bool {
        self.nodes.get(address).is_some_and(|entry| entry.busy)
            && self.unregister(address).is_some()
    }

    /// Make a staged handoff retryable after any response failure.
    pub fn rollback_staged_handoff(&mut self, address: &Ipv6Addr) -> bool {
        let Some(entry) = self.nodes.get_mut(address) else {
            return false;
        };
        if !entry.busy {
            return false;
        }
        entry.busy = false;
        true
    }

    /// Accept a successful handoff response from another gateway.
    ///
    /// Called on the new gateway after receiving a success response.
    /// Registers the node with transferred state.
    ///
    /// SECURITY: The receiving gateway MUST increment sequence numbers
    /// before using them to prevent replay attacks from in-flight messages.
    pub fn accept_handoff(&mut self, response: &HandoffResponse) -> Result<(), HandoffError> {
        if response.status != HandoffRejectReason::Success {
            return Err(HandoffError::HandoffFailed(response.status));
        }

        let node_address = response
            .node_address
            .ok_or(HandoffError::MissingSuccessField("node_address"))?;
        let dao_sequence = response
            .dao_sequence
            .ok_or(HandoffError::MissingSuccessField("dao_sequence"))?;
        let path_sequence = response
            .path_sequence
            .ok_or(HandoffError::MissingSuccessField("path_sequence"))?;

        // SECURITY: Increment sequence numbers to ensure no replay of
        // in-flight messages from before the handoff. A gap of 1 is the
        // minimum safe increment; production may want a larger margin.
        let safe_dao_seq = dao_sequence
            .checked_add(1)
            .ok_or(HandoffError::SequenceExhausted("dao_sequence"))?;
        let safe_path_seq = path_sequence
            .checked_add(1)
            .ok_or(HandoffError::SequenceExhausted("path_sequence"))?;

        // SECURITY: For OSCORE, increment sender sequence to prevent
        // nonce reuse. The replay window can be used as-is since it
        // tracks received messages (which haven't changed).
        let oscore_state = response
            .oscore_state
            .as_ref()
            .map(|state| {
                let sender_sequence = state
                    .sender_sequence
                    .checked_add(1)
                    .ok_or(HandoffError::SequenceExhausted("oscore_sender_sequence"))?;
                Ok(OscoreState {
                    master_secret: state.master_secret.clone(),
                    master_salt: state.master_salt.clone(),
                    sender_id: state.sender_id.clone(),
                    recipient_id: state.recipient_id.clone(),
                    algorithm: state.algorithm,
                    hashfun: state.hashfun.clone(),
                    window_size: state.window_size,
                    id_context: state.id_context.clone(),
                    sender_sequence,
                    replay_index: state.replay_index,
                    replay_bitfield: state.replay_bitfield,
                })
            })
            .transpose()?;

        let mut entry = NodeRegistryEntry::new(node_address);
        entry.dao_sequence = safe_dao_seq;
        entry.path_sequence = safe_path_seq;
        entry.oscore_state = oscore_state;
        entry.freshness = response.freshness.clone();
        entry.parents = response.parents.clone();

        self.register(entry);

        Ok(())
    }

    /// List all registered node addresses.
    pub fn list_nodes(&self) -> Vec<Ipv6Addr> {
        self.nodes.keys().copied().collect()
    }

    /// Get the number of registered nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(suffix: u8) -> Ipv6Addr {
        [
            0x02, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, suffix,
        ]
    }

    #[test]
    fn handoff_request_minimal_roundtrip() {
        let addr = test_addr(0xf0);
        let request = HandoffRequest::new(addr, 1720001000);

        let encoded = request.encode();
        let decoded = HandoffRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.node_address, addr);
        assert_eq!(decoded.timestamp, 1720001000);
        assert!(decoded.rssi.is_none());
    }

    #[test]
    fn handoff_request_with_rssi_roundtrip() {
        let addr = test_addr(0x11);
        let request = HandoffRequest::with_rssi(addr, 1720001234, -75);

        let encoded = request.encode();
        let decoded = HandoffRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.node_address, addr);
        assert_eq!(decoded.timestamp, 1720001234);
        assert_eq!(decoded.rssi, Some(-75));
    }

    #[test]
    fn handoff_response_error_roundtrip() {
        let response =
            HandoffResponse::error(HandoffRejectReason::NodeNotFound, "node not in registry");

        let encoded = response.encode();
        let decoded = HandoffResponse::decode(&encoded).unwrap();

        assert_eq!(decoded.status, HandoffRejectReason::NodeNotFound);
        assert_eq!(decoded.message, "node not in registry");
        assert!(decoded.node_address.is_none());
    }

    #[test]
    fn handoff_response_success_minimal_roundtrip() {
        let addr = test_addr(0xf0);
        let response = HandoffResponse::success(addr, 42, 10);

        let encoded = response.encode();
        let decoded = HandoffResponse::decode(&encoded).unwrap();

        assert_eq!(decoded.status, HandoffRejectReason::Success);
        assert_eq!(decoded.node_address, Some(addr));
        assert_eq!(decoded.dao_sequence, Some(42));
        assert_eq!(decoded.path_sequence, Some(10));
    }

    #[test]
    fn handoff_response_success_full_roundtrip() {
        let addr = test_addr(0xef);
        let parent1 = test_addr(0x44);
        let parent2 = test_addr(0x88);

        let oscore = OscoreState {
            master_secret: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            master_salt: vec![0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40],
            sender_id: vec![0x00],
            recipient_id: vec![0x01],
            algorithm: 10,
            hashfun: "SHA-256".into(),
            window_size: 32,
            id_context: None,
            sender_sequence: 12345,
            replay_index: 100,
            replay_bitfield: 4294967295,
        };

        let freshness = FreshnessState {
            sequence: 42,
            active_until: Some(1720010000.0),
            retain_until: 1720020000.0,
            updated_at: 1720001000.0,
        };

        let response = HandoffResponse::success(addr, 100, 50)
            .with_oscore(oscore.clone())
            .with_freshness(freshness.clone())
            .with_parents(vec![parent1, parent2]);

        let encoded = response.encode();
        let decoded = HandoffResponse::decode(&encoded).unwrap();

        assert_eq!(decoded.status, HandoffRejectReason::Success);
        assert_eq!(decoded.node_address, Some(addr));
        assert_eq!(decoded.dao_sequence, Some(100));
        assert_eq!(decoded.path_sequence, Some(50));

        let dec_oscore = decoded.oscore_state.unwrap();
        assert_eq!(dec_oscore.master_secret, oscore.master_secret);
        assert_eq!(dec_oscore.sender_sequence, 12345);
        assert_eq!(dec_oscore.replay_bitfield, 4294967295);

        let dec_fresh = decoded.freshness.unwrap();
        assert_eq!(dec_fresh.sequence, 42);
        assert!((dec_fresh.active_until.unwrap() - 1720010000.0).abs() < 0.001);

        assert_eq!(decoded.parents.len(), 2);
        assert_eq!(decoded.parents[0], parent1);
        assert_eq!(decoded.parents[1], parent2);
    }

    #[test]
    fn node_registry_basic_operations() {
        let mut registry = NodeRegistry::new();
        let addr = test_addr(0x42);

        assert!(!registry.contains(&addr));
        assert_eq!(registry.len(), 0);

        let mut entry = NodeRegistryEntry::new(addr);
        entry.dao_sequence = 10;
        registry.register(entry);

        assert!(registry.contains(&addr));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get(&addr).unwrap().dao_sequence, 10);

        let removed = registry.unregister(&addr);
        assert!(removed.is_some());
        assert!(!registry.contains(&addr));
    }

    #[test]
    fn node_registry_handoff_flow() {
        let mut source_registry = NodeRegistry::new();
        let mut dest_registry = NodeRegistry::new();

        let addr = test_addr(0x42);
        let mut entry = NodeRegistryEntry::new(addr);
        entry.dao_sequence = 42;
        entry.path_sequence = 10;
        source_registry.register(entry);

        // Simulate handoff request from destination gateway
        let request = HandoffRequest::new(addr, 1720001000);
        let response = source_registry.handle_handoff_request(&request);

        assert_eq!(response.status, HandoffRejectReason::Success);
        assert!(source_registry.get(&addr).unwrap().busy);

        // Destination accepts handoff
        dest_registry.accept_handoff(&response).unwrap();

        assert!(dest_registry.contains(&addr));
        assert!(source_registry.commit_staged_handoff(&addr));
        assert!(!source_registry.contains(&addr));
        let new_entry = dest_registry.get(&addr).unwrap();

        // SECURITY: Sequence numbers should be incremented
        assert_eq!(new_entry.dao_sequence, 43);
        assert_eq!(new_entry.path_sequence, 11);
    }

    #[test]
    fn node_registry_handoff_busy_node() {
        let mut registry = NodeRegistry::new();
        let addr = test_addr(0x42);

        let mut entry = NodeRegistryEntry::new(addr);
        entry.busy = true;
        registry.register(entry);

        let request = HandoffRequest::new(addr, 1720001000);
        let response = registry.handle_handoff_request(&request);

        assert_eq!(response.status, HandoffRejectReason::NodeBusy);
        // Node should still be in registry
        assert!(registry.contains(&addr));
    }

    #[test]
    fn node_registry_handoff_not_found() {
        let mut registry = NodeRegistry::new();
        let addr = test_addr(0x42);

        let request = HandoffRequest::new(addr, 1720001000);
        let response = registry.handle_handoff_request(&request);

        assert_eq!(response.status, HandoffRejectReason::NodeNotFound);
    }

    #[test]
    fn handoff_request_decode_invalid_cbor() {
        let result = HandoffRequest::decode(&[0xff, 0xff]);
        assert!(matches!(result, Err(HandoffError::InvalidCbor)));
    }

    #[test]
    fn handoff_request_decode_not_map() {
        // CBOR array [1, 2, 3]
        let cbor_array = [0x83, 0x01, 0x02, 0x03];
        let result = HandoffRequest::decode(&cbor_array);
        assert!(matches!(result, Err(HandoffError::ExpectedMap)));
    }

    #[test]
    fn sequence_increment_on_accept() {
        // Test that sequence numbers are properly incremented per GCP-7 security requirement
        let transferred_dao = 100u32;
        let transferred_path = 50u32;
        let transferred_oscore_seq = 12345u64;

        let oscore = OscoreState {
            master_secret: vec![0; 16],
            master_salt: vec![0; 8],
            sender_id: vec![0],
            recipient_id: vec![1],
            algorithm: 10,
            hashfun: "SHA-256".into(),
            window_size: 32,
            id_context: None,
            sender_sequence: transferred_oscore_seq,
            replay_index: 100,
            replay_bitfield: 0,
        };

        let addr = test_addr(0x42);
        let response =
            HandoffResponse::success(addr, transferred_dao, transferred_path).with_oscore(oscore);

        let mut registry = NodeRegistry::new();
        registry.accept_handoff(&response).unwrap();

        let entry = registry.get(&addr).unwrap();
        // Per GCP-7: increment by 1 minimum to prevent replay
        assert_eq!(entry.dao_sequence, transferred_dao + 1);
        assert_eq!(entry.path_sequence, transferred_path + 1);
        assert_eq!(
            entry.oscore_state.as_ref().unwrap().sender_sequence,
            transferred_oscore_seq + 1
        );
    }

    #[test]
    fn handoff_sequence_boundaries_advance_once_or_reject_atomically() {
        let addr = test_addr(0x43);
        let oscore = |sender_sequence| OscoreState {
            master_secret: vec![0; 16],
            master_salt: vec![0; 8],
            sender_id: vec![0],
            recipient_id: vec![1],
            algorithm: 10,
            hashfun: "SHA-256".into(),
            window_size: 32,
            id_context: None,
            sender_sequence,
            replay_index: 0,
            replay_bitfield: 0,
        };

        let boundary = HandoffResponse::success(addr, u32::MAX - 1, u32::MAX - 1)
            .with_oscore(oscore(u64::MAX - 1));
        let mut registry = NodeRegistry::new();
        registry.accept_handoff(&boundary).unwrap();
        let accepted = registry.get(&addr).unwrap();
        assert_eq!(accepted.dao_sequence, u32::MAX);
        assert_eq!(accepted.path_sequence, u32::MAX);
        assert_eq!(
            accepted.oscore_state.as_ref().unwrap().sender_sequence,
            u64::MAX
        );

        for (response, exhausted) in [
            (HandoffResponse::success(addr, u32::MAX, 0), "dao_sequence"),
            (HandoffResponse::success(addr, 0, u32::MAX), "path_sequence"),
            (
                HandoffResponse::success(addr, 0, 0).with_oscore(oscore(u64::MAX)),
                "oscore_sender_sequence",
            ),
        ] {
            let mut registry = NodeRegistry::new();
            assert_eq!(
                registry.accept_handoff(&response),
                Err(HandoffError::SequenceExhausted(exhausted))
            );
            assert!(!registry.contains(&addr));
        }
    }
}
