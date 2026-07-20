//! RPL routing table, DAO management, and source-routing header (RFC 6550 §6.7, RFC 6554).
//!
//! Ports `python/src/lichen/rpl/routing.py` and `python/src/lichen/rpl/dao.py`.
//!
//! - `RoutingTable` maps a /128 target to the ordered hop path from root to target.
//! - `DaoManager` builds DAOs (non-root) and assembles routes from incoming DAOs (root).
//! - `SourceRoutingHeader` encodes/decodes the RFC 6554 SRH wire format.

#[cfg(feature = "std")]
use std::{
    collections::{HashMap, HashSet},
    vec,
    vec::Vec,
};

#[cfg(feature = "std")]
use crate::message::{
    Dao, DaoEnvelopeError, OptionIter, RplError, RplTarget, SignedDaoEnvelope, TransitInfo,
    OPT_RPL_TARGET, OPT_RPL_TARGET_DESCRIPTOR, OPT_TRANSIT_INFO,
};
#[cfg(feature = "std")]
use lichen_hal::{
    storage::{
        open_redundant, provision_redundant, update_redundant, RedundantOpenError,
        RedundantProvisionError, RedundantUpdateError, RedundantValue,
    },
    NonVolatile,
};
#[cfg(feature = "std")]
use lichen_link::{identity::iid_from_pubkey, keys::PublicKey, schnorr};
#[cfg(feature = "std")]
use sha2::{Digest, Sha256, Sha512};

#[cfg(feature = "std")]
fn seq_is_newer(new_seq: u8, old_seq: u8) -> bool {
    match (new_seq < 128, old_seq < 128) {
        (true, true) => (1..=16).contains(&(new_seq.wrapping_sub(old_seq) & 0x7f)),
        (true, false) => 256 + u16::from(new_seq) - u16::from(old_seq) <= 16,
        (false, true) => 256 + u16::from(old_seq) - u16::from(new_seq) > 16,
        (false, false) => (1..=16).contains(&new_seq.wrapping_sub(old_seq)),
    }
}

#[cfg(feature = "std")]
fn increment_lollipop(sequence: u8) -> u8 {
    match sequence {
        127 | 255 => 0,
        _ => sequence + 1,
    }
}
#[cfg(feature = "std")]
use lichen_core::error::{BufferTooSmall, TooShort};

#[cfg(feature = "std")]
const MAX_CHAIN: usize = 64;
#[cfg(feature = "std")]
const MAX_DAO_UPDATES: usize = 16;
/// Maximum installed routes. New state is rejected when this limit is reached.
#[cfg(feature = "std")]
pub const MAX_ROUTES: usize = 256;
/// Maximum remembered DAO origins used for replay rejection.
#[cfg(feature = "std")]
pub const MAX_DAO_ORIGINS: usize = 256;

/// Durable replay state for one authenticated DAO origin.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaoOriginHighWater {
    pub public_key: [u8; 32],
    pub origin_sequence: u64,
    pub signed_dao_sha256: [u8; 32],
}

#[cfg(feature = "std")]
pub const DAO_ORIGIN_DOMAIN: &[u8] = b"LICHEN-DAO-ORIGIN-v1";
#[cfg(feature = "std")]
const DAO_TX_KEYS: [&str; 2] = ["rpl.tx.a", "rpl.tx.b"];
#[cfg(feature = "std")]
const DAO_RX_KEYS: [&str; 2] = ["rpl.rx.a", "rpl.rx.b"];
#[cfg(feature = "std")]
const DAO_TX_MAGIC: [u8; 4] = *b"DTX1";
#[cfg(feature = "std")]
const DAO_RX_MAGIC: [u8; 4] = *b"DRX1";
#[cfg(feature = "std")]
const HIGH_WATER_ENTRY_LEN: usize = 72;
#[cfg(feature = "std")]
const HIGH_WATER_PAYLOAD_LEN: usize = 2 + MAX_DAO_ORIGINS * HIGH_WATER_ENTRY_LEN;
#[cfg(feature = "std")]
const SLOT_OVERHEAD: usize = 24;
#[cfg(feature = "std")]
const DAO_TX_HEADER_LEN: usize = 42;
/// Maximum complete signed DAO retained for exact retransmission.
#[cfg(feature = "std")]
pub const MAX_SIGNED_DAO_LEN: usize = 255;
#[cfg(feature = "std")]
const DAO_TX_PAYLOAD_LEN: usize = DAO_TX_HEADER_LEN + MAX_SIGNED_DAO_LEN;
#[cfg(feature = "std")]
type HighWaterMap = HashMap<[u8; 32], ([u8; 32], u64)>;

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoMalformed {
    MissingSignature,
    DuplicateSignature,
    NonTerminalSignature,
    InvalidOptionLength,
    UnknownOption(u8),
    InvalidDao,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoVerifyError {
    Malformed(DaoMalformed),
    UnknownKey,
    WrongInstance,
    WrongDodag,
    IidMismatch,
    BadSignature,
}

#[cfg(feature = "std")]
#[derive(Debug)]
/// Low-level signature-verified DAO capability.
///
/// This proves cryptography only. Callers must supply a previously authorized
/// key from an external authenticated pin store and separately enforce routing
/// semantics. Application code should use its node-level root handler.
pub struct SignatureVerifiedDao<'a> {
    envelope: SignedDaoEnvelope<'a>,
    origin: [u8; 16],
    public_key: [u8; 32],
    signed_dao_sha256: [u8; 32],
}

#[cfg(feature = "std")]
impl<'a> SignatureVerifiedDao<'a> {
    /// Verify using a key supplied by an external authenticated pin store.
    /// Packet input must never choose `pinned_key` directly.
    pub fn verify_signature(
        wire: &'a [u8],
        origin: [u8; 16],
        rpl_instance_id: u8,
        active_dodag_id: [u8; 16],
        pinned_key: Option<PublicKey>,
    ) -> Result<Self, DaoVerifyError> {
        let dao = Dao::from_bytes(wire)
            .map_err(|_| DaoVerifyError::Malformed(DaoMalformed::InvalidDao))?;
        if dao.flags != 0 || wire[2] != 0 {
            return Err(DaoVerifyError::Malformed(DaoMalformed::InvalidDao));
        }
        if dao.rpl_instance_id != rpl_instance_id {
            return Err(DaoVerifyError::WrongInstance);
        }
        if dao.dodag_id.is_some_and(|dodag| dodag != active_dodag_id) {
            return Err(DaoVerifyError::WrongDodag);
        }
        let envelope = SignedDaoEnvelope::from_bytes(wire).map_err(map_envelope_error)?;
        let pinned_key = pinned_key.ok_or(DaoVerifyError::UnknownKey)?;
        if origin[8..] != iid_from_pubkey(&pinned_key) {
            return Err(DaoVerifyError::IidMismatch);
        }
        let digest = dao_origin_digest(
            origin,
            envelope.dao.dodag_id.unwrap_or(active_dodag_id),
            envelope.origin.origin_sequence,
            envelope.unsigned_bytes,
        );
        if !schnorr::verify(&pinned_key, &digest, envelope.origin.signature) {
            return Err(DaoVerifyError::BadSignature);
        }
        Ok(Self {
            envelope,
            origin,
            public_key: *pinned_key.as_bytes(),
            signed_dao_sha256: Sha256::digest(wire).into(),
        })
    }

    pub fn wire(&self) -> &'a [u8] {
        self.envelope.signed_bytes
    }
}

#[cfg(feature = "std")]
fn map_envelope_error(error: DaoEnvelopeError) -> DaoVerifyError {
    let malformed = match error {
        DaoEnvelopeError::MissingSignature => DaoMalformed::MissingSignature,
        DaoEnvelopeError::DuplicateSignature => DaoMalformed::DuplicateSignature,
        DaoEnvelopeError::NonTerminalSignature => DaoMalformed::NonTerminalSignature,
        DaoEnvelopeError::InvalidOptionLength => DaoMalformed::InvalidOptionLength,
        DaoEnvelopeError::UnknownOption(option) => DaoMalformed::UnknownOption(option),
        DaoEnvelopeError::Rpl(_) => DaoMalformed::InvalidDao,
    };
    DaoVerifyError::Malformed(malformed)
}

#[cfg(feature = "std")]
pub fn dao_origin_digest(
    origin: [u8; 16],
    dodag_id: [u8; 16],
    origin_sequence: u64,
    unsigned_dao: &[u8],
) -> [u8; 64] {
    Sha512::new()
        .chain_update(DAO_ORIGIN_DOMAIN)
        .chain_update(origin)
        .chain_update(dodag_id)
        .chain_update(origin_sequence.to_be_bytes())
        .chain_update(unsigned_dao)
        .finalize()
        .into()
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoPersistentOpenError<E> {
    Missing,
    Corrupt,
    AlreadyProvisioned,
    Storage(E),
    KeyMismatch,
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub enum DaoProvisionError<E> {
    Open(DaoPersistentOpenError<E>),
    Storage(E),
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub struct DaoTxState {
    current: RedundantValue,
    public_key: [u8; 32],
    last_reserved: u64,
    last_signed_dao: Vec<u8>,
}

#[cfg(feature = "std")]
impl DaoTxState {
    pub fn provision<S: NonVolatile>(
        storage: &mut S,
        expected_key: PublicKey,
    ) -> Result<Self, DaoProvisionError<S::Error>> {
        match Self::open(storage, expected_key) {
            Ok(_) => {
                return Err(DaoProvisionError::Open(
                    DaoPersistentOpenError::AlreadyProvisioned,
                ))
            }
            Err(DaoPersistentOpenError::Missing) => {}
            Err(DaoPersistentOpenError::Storage(error)) => {
                return Err(DaoProvisionError::Storage(error))
            }
            Err(error) => return Err(DaoProvisionError::Open(error)),
        }
        let payload = encode_tx_state(expected_key.as_bytes(), 0, &[]).unwrap();
        let mut record = vec![0u8; DAO_TX_HEADER_LEN + SLOT_OVERHEAD];
        provision_redundant(storage, DAO_TX_KEYS, DAO_TX_MAGIC, &payload, &mut record).map_err(
            |error| match error {
                RedundantProvisionError::Exists => {
                    DaoProvisionError::Open(DaoPersistentOpenError::Corrupt)
                }
                RedundantProvisionError::Storage(error) => DaoProvisionError::Storage(error),
            },
        )?;
        Self::open(storage, expected_key).map_err(DaoProvisionError::Open)
    }

    pub fn open<S: NonVolatile>(
        storage: &S,
        expected_key: PublicKey,
    ) -> Result<Self, DaoPersistentOpenError<S::Error>> {
        let mut a = vec![0u8; DAO_TX_PAYLOAD_LEN + SLOT_OVERHEAD];
        let mut b = vec![0u8; DAO_TX_PAYLOAD_LEN + SLOT_OVERHEAD];
        let mut payload = vec![0u8; DAO_TX_PAYLOAD_LEN];
        let current = open_redundant(
            storage,
            DAO_TX_KEYS,
            DAO_TX_MAGIC,
            &mut a,
            &mut b,
            &mut payload,
        )
        .map_err(map_open_error)?;
        if current.len < DAO_TX_HEADER_LEN {
            return Err(DaoPersistentOpenError::Corrupt);
        }
        let public_key: [u8; 32] = payload[..32].try_into().unwrap();
        if public_key != *expected_key.as_bytes() {
            return Err(DaoPersistentOpenError::KeyMismatch);
        }
        let signed_len = u16::from_be_bytes(payload[40..42].try_into().unwrap()) as usize;
        if signed_len > MAX_SIGNED_DAO_LEN || current.len != DAO_TX_HEADER_LEN + signed_len {
            return Err(DaoPersistentOpenError::Corrupt);
        }
        Ok(Self {
            current,
            public_key,
            last_reserved: u64::from_be_bytes(payload[32..40].try_into().unwrap()),
            last_signed_dao: payload[DAO_TX_HEADER_LEN..current.len].to_vec(),
        })
    }

    pub fn is_for_public_key(&self, public_key: &PublicKey) -> bool {
        self.public_key == *public_key.as_bytes()
    }

    /// Last complete signed DAO durably finalized for exact retransmission.
    pub fn last_signed_dao(&self) -> Option<&[u8]> {
        (!self.last_signed_dao.is_empty()).then_some(self.last_signed_dao.as_slice())
    }

    pub fn reserve_next<S: NonVolatile>(
        &mut self,
        storage: &mut S,
    ) -> Result<u64, DaoTxError<S::Error>> {
        let next = self
            .last_reserved
            .checked_add(1)
            .ok_or(DaoTxError::Exhausted)?;
        let payload = encode_tx_state(&self.public_key, next, &self.last_signed_dao)
            .ok_or(DaoTxError::Oversized)?;
        let mut record = vec![0u8; DAO_TX_PAYLOAD_LEN + SLOT_OVERHEAD];
        self.current = update_redundant(
            storage,
            DAO_TX_KEYS,
            DAO_TX_MAGIC,
            self.current,
            &payload,
            &mut record,
        )
        .map_err(map_tx_update_error)?;
        self.last_reserved = next;
        Ok(next)
    }

    /// Persist exact signed bytes for `sequence` before they may be transmitted.
    pub fn finalize_signed<S: NonVolatile>(
        &mut self,
        storage: &mut S,
        sequence: u64,
        signed_dao: &[u8],
    ) -> Result<(), DaoTxError<S::Error>> {
        if sequence != self.last_reserved {
            return Err(DaoTxError::InvalidState);
        }
        if signed_dao.len() > MAX_SIGNED_DAO_LEN {
            return Err(DaoTxError::Oversized);
        }
        let envelope =
            SignedDaoEnvelope::from_bytes(signed_dao).map_err(|_| DaoTxError::Encoding)?;
        if envelope.origin.origin_sequence != sequence {
            return Err(DaoTxError::InvalidState);
        }
        if SignedDaoEnvelope::from_bytes(&self.last_signed_dao)
            .ok()
            .is_some_and(|envelope| envelope.origin.origin_sequence == sequence)
        {
            return Err(DaoTxError::InvalidState);
        }
        let payload =
            encode_tx_state(&self.public_key, sequence, signed_dao).ok_or(DaoTxError::Oversized)?;
        let mut record = vec![0u8; DAO_TX_PAYLOAD_LEN + SLOT_OVERHEAD];
        self.current = update_redundant(
            storage,
            DAO_TX_KEYS,
            DAO_TX_MAGIC,
            self.current,
            &payload,
            &mut record,
        )
        .map_err(map_tx_update_error)?;
        self.last_signed_dao.clear();
        self.last_signed_dao.extend_from_slice(signed_dao);
        Ok(())
    }
}

#[cfg(feature = "std")]
fn encode_tx_state(public_key: &[u8; 32], sequence: u64, signed_dao: &[u8]) -> Option<Vec<u8>> {
    if signed_dao.len() > MAX_SIGNED_DAO_LEN {
        return None;
    }
    let mut payload = vec![0u8; DAO_TX_HEADER_LEN + signed_dao.len()];
    payload[..32].copy_from_slice(public_key);
    payload[32..40].copy_from_slice(&sequence.to_be_bytes());
    payload[40..42].copy_from_slice(&(signed_dao.len() as u16).to_be_bytes());
    payload[DAO_TX_HEADER_LEN..].copy_from_slice(signed_dao);
    Some(payload)
}

#[cfg(feature = "std")]
fn map_tx_update_error<E>(error: RedundantUpdateError<E>) -> DaoTxError<E> {
    match error {
        RedundantUpdateError::Storage(error) => DaoTxError::Persistence(error),
        RedundantUpdateError::Stale => DaoTxError::Stale,
        RedundantUpdateError::Exhausted => DaoTxError::Exhausted,
        RedundantUpdateError::Corrupt => DaoTxError::Corrupt,
    }
}

#[cfg(feature = "std")]
fn map_rx_update_error<E>(error: RedundantUpdateError<E>) -> DaoProcessError<E> {
    match error {
        RedundantUpdateError::Storage(error) => DaoProcessError::Persistence(error),
        RedundantUpdateError::Stale => DaoProcessError::Stale,
        RedundantUpdateError::Exhausted => DaoProcessError::Exhausted,
        RedundantUpdateError::Corrupt => DaoProcessError::Corrupt,
    }
}

#[cfg(feature = "std")]
fn map_open_error<E>(error: RedundantOpenError<E>) -> DaoPersistentOpenError<E> {
    match error {
        RedundantOpenError::Missing => DaoPersistentOpenError::Missing,
        RedundantOpenError::Corrupt | RedundantOpenError::BufferTooSmall => {
            DaoPersistentOpenError::Corrupt
        }
        RedundantOpenError::Storage(error) => DaoPersistentOpenError::Storage(error),
    }
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub enum DaoTxError<E> {
    Persistence(E),
    Stale,
    Corrupt,
    Exhausted,
    Oversized,
    InvalidState,
    KeyMismatch,
    NotJoined,
    InvalidOrigin,
    Encoding,
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub struct DaoRxState {
    current: RedundantValue,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoProcessOutcome {
    Applied,
    Duplicate,
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub enum DaoProcessError<E> {
    Replay,
    Persistence(E),
    Stale,
    Exhausted,
    Corrupt,
    RouteRejected,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaoProcessTiming {
    pub now_seconds: u64,
    pub lifetime_unit_seconds: u64,
    pub max_deadline_seconds: u64,
}
/// Maximum target-to-parent edges retained by a root.
#[cfg(feature = "std")]
pub const MAX_PARENT_EDGES: usize = 256;
/// Maximum per-target Path Sequence freshness records.
#[cfg(feature = "std")]
pub const MAX_PATH_SEQUENCES: usize = 256;
#[cfg(all(feature = "std", test))]
const DEFAULT_LIFETIME_UNIT_SECONDS: u64 = 60;
/// Keep expired freshness state long enough to reject delayed replays. Once this
/// finite window passes, the oldest inactive record may be reclaimed at capacity;
/// deployments needing a longer replay horizon must persist freshness externally.
#[cfg(feature = "std")]
const FRESHNESS_TOMBSTONE_RETENTION_SECONDS: u64 = 60 * 60;

// ── Source Routing Header (RFC 6554) ─────────────────────────────────────────

/// RFC 6554 Source Routing Header, routing type 3 (uncompressed).
///
/// `addresses` are the hops still to visit; `segments_left` counts how many remain.
#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub struct SourceRoutingHeader {
    pub segments_left: u8,
    pub addresses: Vec<[u8; 16]>,
}

#[cfg(feature = "std")]
impl SourceRoutingHeader {
    /// Encode to the SRH wire format: 6 fixed bytes + 16 bytes per address.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, RplError> {
        let needed = 6 + self.addresses.len() * 16;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = 3; // routing type
        out[1] = self.segments_left;
        out[2] = 0; // CmprI
        out[3] = 0; // CmprE
        out[4] = 0; // reserved
        out[5] = 0;
        for (i, addr) in self.addresses.iter().enumerate() {
            out[6 + i * 16..6 + (i + 1) * 16].copy_from_slice(addr);
        }
        Ok(needed)
    }

    /// Parse from SRH wire bytes (starting at the routing-type byte).
    pub fn from_bytes(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < 6 {
            return Err(TooShort::new(6, data.len()).into());
        }
        if data[0] != 3 {
            return Err(RplError::BadRoutingType(data[0]));
        }
        // SECURITY: Reject compressed SRHs (CmprI/CmprE > 0 per RFC 6554 Section 3).
        // We only support uncompressed addresses (16 bytes each). Compressed SRHs
        // would be parsed incorrectly, leading to misrouted packets.
        if data[2] != 0 || data[3] != 0 {
            return Err(RplError::InvalidOption);
        }
        let addr_bytes = &data[6..];
        if !addr_bytes.len().is_multiple_of(16) {
            // Address bytes must be a multiple of 16; partial trailing address is invalid.
            return Err(RplError::InvalidOption);
        }
        let addresses: Vec<[u8; 16]> = addr_bytes
            .chunks_exact(16)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        Ok(Self {
            segments_left: data[1],
            addresses,
        })
    }
}

// ── Routing table ─────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteEntryState {
    Fresh,
    Stale,
    Expired,
}

#[cfg(feature = "std")]
impl RouteEntryState {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Fresh, Self::Fresh)
                | (Self::Fresh, Self::Stale)
                | (Self::Fresh, Self::Expired)
                | (Self::Stale, Self::Fresh)
                | (Self::Stale, Self::Stale)
                | (Self::Stale, Self::Expired)
                | (Self::Expired, Self::Expired)
        )
    }
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRouteEntryTransition {
    pub from: RouteEntryState,
    pub to: RouteEntryState,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    pub path: Vec<[u8; 16]>,
    pub state: RouteEntryState,
}

#[cfg(feature = "std")]
impl RouteEntry {
    pub fn fresh(path: &[[u8; 16]]) -> Self {
        Self {
            path: path.to_vec(),
            state: RouteEntryState::Fresh,
        }
    }

    fn transition_to(&mut self, next: RouteEntryState) -> Result<(), InvalidRouteEntryTransition> {
        if self.state.can_transition_to(next) {
            self.state = next;
            Ok(())
        } else {
            Err(InvalidRouteEntryTransition {
                from: self.state,
                to: next,
            })
        }
    }

    pub fn mark_stale(&mut self) -> Result<(), InvalidRouteEntryTransition> {
        self.transition_to(RouteEntryState::Stale)
    }

    pub fn mark_expired(&mut self) -> Result<(), InvalidRouteEntryTransition> {
        self.transition_to(RouteEntryState::Expired)
    }

    pub fn refresh(&mut self, path: &[[u8; 16]]) -> Result<(), InvalidRouteEntryTransition> {
        if self.state == RouteEntryState::Expired {
            return Err(InvalidRouteEntryTransition {
                from: self.state,
                to: RouteEntryState::Fresh,
            });
        }
        self.path = path.to_vec();
        self.transition_to(RouteEntryState::Fresh)
    }

    pub fn is_usable(&self) -> bool {
        self.state != RouteEntryState::Expired
    }
}

/// Root-side map from target address to the ordered hop list `[h1, ..., target]`.
///
/// The first element is the root's direct neighbour; the last is the target.
/// A single-hop target has a one-element path containing only itself.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct RoutingTable {
    routes: HashMap<[u8; 16], RouteEntry>,
}

#[cfg(feature = "std")]
impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a route, returning `false` if a new entry would exceed capacity.
    pub fn add_route(&mut self, target: [u8; 16], path: &[[u8; 16]]) -> bool {
        if !self.routes.contains_key(&target) && self.routes.len() == MAX_ROUTES {
            return false;
        }
        match self.routes.get_mut(&target) {
            Some(entry) if entry.state != RouteEntryState::Expired => {
                entry
                    .refresh(path)
                    .expect("fresh or stale route entry can refresh");
            }
            _ => {
                self.routes.insert(target, RouteEntry::fresh(path));
            }
        }
        true
    }

    pub fn remove_route(&mut self, target: &[u8; 16]) {
        self.routes.remove(target);
    }

    pub fn mark_stale(
        &mut self,
        target: &[u8; 16],
    ) -> Option<Result<(), InvalidRouteEntryTransition>> {
        self.routes.get_mut(target).map(RouteEntry::mark_stale)
    }

    pub fn mark_expired(
        &mut self,
        target: &[u8; 16],
    ) -> Option<Result<(), InvalidRouteEntryTransition>> {
        self.routes.get_mut(target).map(RouteEntry::mark_expired)
    }

    pub fn entry_state(&self, target: &[u8; 16]) -> Option<RouteEntryState> {
        self.routes.get(target).map(|entry| entry.state)
    }

    /// Return the path for `target`, or `None` if no route is known.
    pub fn lookup(&self, target: &[u8; 16]) -> Option<&[[u8; 16]]> {
        self.routes
            .get(target)
            .filter(|entry| entry.is_usable())
            .map(|entry| entry.path.as_slice())
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

// ── DAO manager ───────────────────────────────────────────────────────────────

/// Builds DAOs (non-root nodes) and assembles source routes from incoming DAOs (root).
///
/// On the root, `routing_table` is updated in place as DAOs arrive.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct DaoManager {
    node_address: [u8; 16],
    is_root: bool,
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    routing_table: RoutingTable,
    dao_sequence: u8,
    path_sequence: u8,
    parent_map: HashMap<[u8; 16], Vec<[u8; 16]>>,
    edge_expiry: HashMap<([u8; 16], [u8; 16]), Option<u64>>,
    /// Last accepted DAOSequence and replay-retention deadline per DAO origin.
    origin_seq_map: HashMap<[u8; 16], Freshness>,
    /// Last accepted Transit Path Sequence per target (route freshness).
    path_seq_map: HashMap<[u8; 16], Freshness>,
    /// Strict authenticated origin sequence. Never expires or evicts.
    origin_high_water: HighWaterMap,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug)]
struct Freshness {
    sequence: u8,
    active_until: Option<u64>,
    retain_until: u64,
    updated_at: u64,
}

#[cfg(feature = "std")]
impl Freshness {
    fn new(sequence: u8, active_until: Option<u64>, now_seconds: u64) -> Self {
        let retain_until = active_until
            .unwrap_or(u64::MAX)
            .max(now_seconds)
            .saturating_add(FRESHNESS_TOMBSTONE_RETENTION_SECONDS);
        Self {
            sequence,
            active_until,
            retain_until,
            updated_at: now_seconds,
        }
    }

    fn is_reclaimable(self, now_seconds: u64) -> bool {
        self.active_until
            .is_some_and(|deadline| deadline <= now_seconds)
            && self.retain_until <= now_seconds
    }
}

#[cfg(feature = "std")]
#[derive(Clone, Copy)]
struct DaoUpdate {
    target: [u8; 16],
    parent: [u8; 16],
    path_sequence: u8,
    path_lifetime: u8,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy)]
struct DaoTiming {
    now_seconds: u64,
    lifetime_unit_seconds: u64,
    max_deadline_seconds: u64,
}

#[cfg(feature = "std")]
impl DaoManager {
    pub fn new(node_address: [u8; 16], rpl_instance_id: u8, dodag_id: [u8; 16]) -> Self {
        Self {
            node_address,
            is_root: false,
            rpl_instance_id,
            dodag_id,
            routing_table: RoutingTable::new(),
            dao_sequence: 240,
            path_sequence: 240,
            parent_map: HashMap::new(),
            edge_expiry: HashMap::new(),
            origin_seq_map: HashMap::new(),
            path_seq_map: HashMap::new(),
            origin_high_water: HashMap::new(),
        }
    }

    fn as_root(node_address: [u8; 16], rpl_instance_id: u8, dodag_id: [u8; 16]) -> Self {
        let mut m = Self::new(node_address, rpl_instance_id, dodag_id);
        m.is_root = true;
        m
    }

    fn staged(&self) -> Self {
        Self {
            node_address: self.node_address,
            is_root: self.is_root,
            rpl_instance_id: self.rpl_instance_id,
            dodag_id: self.dodag_id,
            routing_table: self.routing_table.clone(),
            dao_sequence: self.dao_sequence,
            path_sequence: self.path_sequence,
            parent_map: self.parent_map.clone(),
            edge_expiry: self.edge_expiry.clone(),
            origin_seq_map: self.origin_seq_map.clone(),
            path_seq_map: self.path_seq_map.clone(),
            origin_high_water: self.origin_high_water.clone(),
        }
    }

    pub fn provision_root<S: NonVolatile>(
        storage: &mut S,
        node_address: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> Result<(Self, DaoRxState), DaoProvisionError<S::Error>> {
        match Self::open_root(storage, node_address, rpl_instance_id, dodag_id) {
            Ok(_) => {
                return Err(DaoProvisionError::Open(
                    DaoPersistentOpenError::AlreadyProvisioned,
                ))
            }
            Err(DaoPersistentOpenError::Missing) => {}
            Err(DaoPersistentOpenError::Storage(error)) => {
                return Err(DaoProvisionError::Storage(error))
            }
            Err(error) => return Err(DaoProvisionError::Open(error)),
        }
        let payload = [0u8; 2];
        let mut record = vec![0u8; payload.len() + SLOT_OVERHEAD];
        provision_redundant(storage, DAO_RX_KEYS, DAO_RX_MAGIC, &payload, &mut record).map_err(
            |error| match error {
                RedundantProvisionError::Exists => {
                    DaoProvisionError::Open(DaoPersistentOpenError::Corrupt)
                }
                RedundantProvisionError::Storage(error) => DaoProvisionError::Storage(error),
            },
        )?;
        Self::open_root(storage, node_address, rpl_instance_id, dodag_id)
            .map_err(DaoProvisionError::Open)
    }

    pub fn open_root<S: NonVolatile>(
        storage: &S,
        node_address: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> Result<(Self, DaoRxState), DaoPersistentOpenError<S::Error>> {
        let mut a = vec![0u8; HIGH_WATER_PAYLOAD_LEN + SLOT_OVERHEAD];
        let mut b = vec![0u8; HIGH_WATER_PAYLOAD_LEN + SLOT_OVERHEAD];
        let mut payload = vec![0u8; HIGH_WATER_PAYLOAD_LEN];
        let current = open_redundant(
            storage,
            DAO_RX_KEYS,
            DAO_RX_MAGIC,
            &mut a,
            &mut b,
            &mut payload,
        )
        .map_err(map_open_error)?;
        let origin_high_water =
            decode_high_water(&payload[..current.len]).ok_or(DaoPersistentOpenError::Corrupt)?;
        let mut manager = Self::as_root(node_address, rpl_instance_id, dodag_id);
        manager.origin_high_water = origin_high_water;
        Ok((manager, DaoRxState { current }))
    }

    /// Process a signature-verified DAO for its exact origin `/128` Target.
    pub fn process_signature_verified<S: NonVolatile>(
        &mut self,
        verified: &SignatureVerifiedDao<'_>,
        rx_state: &mut DaoRxState,
        storage: &mut S,
        timing: DaoProcessTiming,
    ) -> Result<DaoProcessOutcome, DaoProcessError<S::Error>> {
        let sequence = verified.envelope.origin.origin_sequence;
        let mut duplicate = false;
        if let Some((hash, previous)) = self.origin_high_water.get(&verified.public_key) {
            if sequence < *previous
                || (sequence == *previous && *hash != verified.signed_dao_sha256)
            {
                return Err(DaoProcessError::Replay);
            }
            if sequence == *previous {
                duplicate = true;
            }
        } else if self.origin_high_water.len() == MAX_DAO_ORIGINS {
            return Err(DaoProcessError::RouteRejected);
        }

        let dao = verified.envelope.dao.clone();
        if !Self::has_exact_origin_target(&dao, verified.envelope.unsigned_bytes, verified.origin) {
            return Err(DaoProcessError::RouteRejected);
        }
        let Some((updates, update_count)) =
            self.extract_updates(&dao, verified.envelope.unsigned_bytes)
        else {
            return Err(DaoProcessError::RouteRejected);
        };
        if duplicate
            && updates[..update_count]
                .iter()
                .flatten()
                .any(|update| self.path_seq_map.contains_key(&update.target))
        {
            return Ok(DaoProcessOutcome::Duplicate);
        }
        let mut proposed = self.staged();
        if !proposed.process_dao_inner(
            dao,
            updates,
            update_count,
            verified.origin,
            DaoTiming {
                now_seconds: timing.now_seconds,
                lifetime_unit_seconds: timing.lifetime_unit_seconds,
                max_deadline_seconds: timing.max_deadline_seconds,
            },
        ) {
            return Err(DaoProcessError::RouteRejected);
        }
        if duplicate {
            *self = proposed;
            return Ok(DaoProcessOutcome::Duplicate);
        }
        proposed
            .origin_high_water
            .insert(verified.public_key, (verified.signed_dao_sha256, sequence));
        let mut payload = vec![0u8; HIGH_WATER_PAYLOAD_LEN];
        let len = encode_high_water(&proposed.origin_high_water, &mut payload)
            .ok_or(DaoProcessError::RouteRejected)?;
        let mut record = vec![0u8; HIGH_WATER_PAYLOAD_LEN + SLOT_OVERHEAD];
        rx_state.current = update_redundant(
            storage,
            DAO_RX_KEYS,
            DAO_RX_MAGIC,
            rx_state.current,
            &payload[..len],
            &mut record,
        )
        .map_err(map_rx_update_error)?;
        *self = proposed;
        Ok(DaoProcessOutcome::Applied)
    }

    fn has_exact_origin_target(dao: &Dao, dao_bytes: &[u8], origin: [u8; 16]) -> bool {
        let mut target = None;
        for option in OptionIter::new(dao.options_tail(dao_bytes)) {
            let Ok(option) = option else {
                return false;
            };
            match option.opt_type {
                OPT_RPL_TARGET => {
                    if target.is_some() {
                        return false;
                    }
                    let Ok(parsed) = RplTarget::from_bytes(option.data) else {
                        return false;
                    };
                    target = Some(parsed);
                }
                OPT_RPL_TARGET_DESCRIPTOR => return false,
                _ => {}
            }
        }
        target.is_some_and(|target| target.prefix_len == 128 && target.prefix == origin)
    }

    pub fn routing_table(&self) -> &RoutingTable {
        &self.routing_table
    }

    /// Build a DAO advertising this node with `parent_addr` as transit.
    ///
    /// Returns the encoded bytes: DAO base + RPL Target option + Transit Info option.
    pub fn build_dao(&mut self, parent_addr: [u8; 16]) -> Vec<u8> {
        self.build_dao_with_lifetime(parent_addr, 255)
    }

    /// Build a DAO with an explicit Path Lifetime; zero creates a No-Path DAO.
    pub fn build_dao_with_lifetime(&mut self, parent_addr: [u8; 16], path_lifetime: u8) -> Vec<u8> {
        self.build_dao_inner(parent_addr, path_lifetime, true)
    }

    /// Build another copy of the current logical path update without advancing its
    /// Path Sequence. The DAOSequence still advances so root replay checks remain valid.
    pub fn build_dao_copy_with_lifetime(
        &mut self,
        parent_addr: [u8; 16],
        path_lifetime: u8,
    ) -> Vec<u8> {
        self.build_dao_inner(parent_addr, path_lifetime, false)
    }

    fn build_dao_inner(
        &mut self,
        parent_addr: [u8; 16],
        path_lifetime: u8,
        advance_path_sequence: bool,
    ) -> Vec<u8> {
        self.dao_sequence = increment_lollipop(self.dao_sequence);
        if advance_path_sequence {
            self.path_sequence = increment_lollipop(self.path_sequence);
        }
        let dao = Dao {
            rpl_instance_id: self.rpl_instance_id,
            ack_requested: false,
            flags: 0,
            dao_sequence: self.dao_sequence,
            dodag_id: Some(self.dodag_id),
        };

        let mut buf = [0u8; 64]; // DAO(20) + Target(20) + TransitInfo(22) = 62
        let mut pos = dao
            .write_to(&mut buf)
            .expect("DAO base (20 bytes) fits in 64-byte buffer");

        let target = RplTarget {
            prefix_len: 128,
            prefix: self.node_address,
        };
        let mut tmp = [0u8; 24];
        let n = target
            .write_to(&mut tmp)
            .expect("RPL Target option (19 bytes) fits in 24-byte buffer");
        buf[pos..pos + n].copy_from_slice(&tmp[..n]);
        pos += n;

        let transit = TransitInfo {
            path_control: 0,
            path_sequence: self.path_sequence,
            path_lifetime,
            parent_address: parent_addr,
        };
        pos += transit
            .write_to(&mut buf[pos..])
            .expect("TransitInfo option (22 bytes) fits in remaining buffer");

        buf[..pos].to_vec()
    }

    /// Process a received DAO on the root. Returns `true` if a route was installed.
    ///
    /// `dao_bytes` is the raw DAO wire bytes (base object + options).
    ///
    /// Compatibility wrapper: the first target is treated as the DAO origin and time
    /// does not advance. Receivers that know the packet origin must use [`Self::process_dao_at`].
    #[cfg(test)]
    fn process_dao(&mut self, dao_bytes: &[u8]) -> bool {
        let Ok(dao) = Dao::from_bytes(dao_bytes) else {
            return false;
        };
        let Some((updates, update_count)) = self.extract_updates(&dao, dao_bytes) else {
            return false;
        };
        let Some(origin) = updates[..update_count]
            .iter()
            .flatten()
            .next()
            .map(|update| update.target)
        else {
            return false;
        };
        self.process_dao_inner(
            dao,
            updates,
            update_count,
            origin,
            DaoTiming {
                now_seconds: 0,
                lifetime_unit_seconds: DEFAULT_LIFETIME_UNIT_SECONDS,
                max_deadline_seconds: u64::MAX,
            },
        )
    }

    /// Process a DAO from `origin` at monotonic `now_seconds`.
    ///
    /// Finite Path Lifetimes are measured in `lifetime_unit_seconds`. The caller
    /// should pass the active DODAG Configuration Lifetime Unit. A zero unit fails closed.
    #[cfg(test)]
    fn process_dao_at(
        &mut self,
        dao_bytes: &[u8],
        origin: [u8; 16],
        now_seconds: u64,
        lifetime_unit_seconds: u64,
    ) -> bool {
        if !self.is_root {
            return false;
        }
        let Ok(dao) = Dao::from_bytes(dao_bytes) else {
            return false;
        };
        let Some((updates, update_count)) = self.extract_updates(&dao, dao_bytes) else {
            return false;
        };
        self.process_dao_inner(
            dao,
            updates,
            update_count,
            origin,
            DaoTiming {
                now_seconds,
                lifetime_unit_seconds,
                max_deadline_seconds: u64::MAX,
            },
        )
    }

    pub fn origin_high_water(&self) -> Vec<DaoOriginHighWater> {
        let mut snapshot: Vec<_> = self
            .origin_high_water
            .iter()
            .map(|(public_key, (hash, sequence))| DaoOriginHighWater {
                public_key: *public_key,
                origin_sequence: *sequence,
                signed_dao_sha256: *hash,
            })
            .collect();
        snapshot.sort_unstable_by_key(|entry| entry.public_key);
        snapshot
    }

    fn process_dao_inner(
        &mut self,
        dao: Dao,
        updates: [Option<DaoUpdate>; MAX_DAO_UPDATES],
        update_count: usize,
        origin: [u8; 16],
        timing: DaoTiming,
    ) -> bool {
        let DaoTiming {
            now_seconds,
            lifetime_unit_seconds,
            max_deadline_seconds,
        } = timing;
        if !self.is_root {
            return false;
        }
        if dao.rpl_instance_id != self.rpl_instance_id
            || dao
                .dodag_id
                .is_some_and(|dodag_id| dodag_id != self.dodag_id)
        {
            return false;
        }
        if self
            .origin_seq_map
            .get(&origin)
            .is_some_and(|last| !seq_is_newer(dao.dao_sequence, last.sequence))
        {
            return false;
        }

        // All cloned state is bounded by the public limits above. Build and validate
        // the complete proposal so grouped updates and cycle rejection stay atomic.
        let mut proposed_parents = self.parent_map.clone();
        let mut proposed_expiry = self.edge_expiry.clone();
        let mut proposed_path_sequences = self.path_seq_map.clone();
        let mut proposed_origin_sequences = self.origin_seq_map.clone();
        proposed_expiry.retain(|_, deadline| Self::is_active(*deadline, now_seconds));
        proposed_parents.retain(|target, parents| {
            parents.retain(|parent| proposed_expiry.contains_key(&(*target, *parent)));
            !parents.is_empty()
        });

        let mut updated_targets = HashSet::new();
        for update in updates[..update_count].iter().flatten() {
            if updated_targets.insert(update.target) {
                if let Some(last) = proposed_path_sequences.get(&update.target) {
                    if update.path_sequence == last.sequence {
                        // Equal sequence denotes another copy of the same logical update.
                        // It may add redundant paths, but cannot revive an expired target.
                        if !proposed_parents.contains_key(&update.target) {
                            return false;
                        }
                    } else if seq_is_newer(update.path_sequence, last.sequence) {
                        if let Some(parents) = proposed_parents.remove(&update.target) {
                            for parent in parents {
                                proposed_expiry.remove(&(update.target, parent));
                            }
                        }
                    } else {
                        return false;
                    }
                }
            }
            if update.path_lifetime != 255 && lifetime_unit_seconds == 0 {
                return false;
            }
            let expires_at = if matches!(update.path_lifetime, 0 | 255) {
                None
            } else {
                let lifetime = u64::from(update.path_lifetime.max(1));
                let Some(deadline) = lifetime
                    .checked_mul(lifetime_unit_seconds)
                    .and_then(|duration| now_seconds.checked_add(duration))
                else {
                    return false;
                };
                if deadline > max_deadline_seconds {
                    return false;
                }
                Some(deadline)
            };
            if update.path_lifetime != 0 {
                let parents = proposed_parents.entry(update.target).or_default();
                if parents.contains(&update.parent) {
                    // Equal-sequence copies must be additive; accepting changed lifetime
                    // data for an existing edge would let stale data overwrite it.
                    if proposed_path_sequences
                        .get(&update.target)
                        .is_some_and(|last| last.sequence == update.path_sequence)
                    {
                        return false;
                    }
                } else {
                    parents.push(update.parent);
                    parents.sort_unstable();
                }
                proposed_expiry.insert((update.target, update.parent), expires_at);
            }
        }
        for target in &updated_targets {
            let active_until = Self::target_active_until(*target, &proposed_expiry);
            let sequence = updates[..update_count]
                .iter()
                .flatten()
                .find(|update| update.target == *target)
                .expect("updated target has an update")
                .path_sequence;
            if !proposed_path_sequences.contains_key(target)
                && !Self::make_freshness_room(
                    &mut proposed_path_sequences,
                    MAX_PATH_SEQUENCES,
                    now_seconds,
                )
            {
                return false;
            }
            proposed_path_sequences
                .insert(*target, Freshness::new(sequence, active_until, now_seconds));
        }
        if !proposed_origin_sequences.contains_key(&origin)
            && !Self::make_freshness_room(
                &mut proposed_origin_sequences,
                MAX_DAO_ORIGINS,
                now_seconds,
            )
        {
            return false;
        }
        let origin_active_until = updates[..update_count]
            .iter()
            .flatten()
            .map(|update| Self::target_active_until(update.target, &proposed_expiry))
            .fold(Some(now_seconds), Self::max_deadline);
        proposed_origin_sequences.insert(
            origin,
            Freshness::new(dao.dao_sequence, origin_active_until, now_seconds),
        );
        if proposed_expiry.len() > MAX_PARENT_EDGES
            || proposed_path_sequences.len() > MAX_PATH_SEQUENCES
            || proposed_origin_sequences.len() > MAX_DAO_ORIGINS
        {
            return false;
        }
        if Self::contains_cycle(&proposed_parents) {
            return false;
        }

        let Some(proposed_routes) =
            Self::rebuilt_routes(self.node_address, &proposed_parents, &self.routing_table)
        else {
            return false;
        };
        self.parent_map = proposed_parents;
        self.edge_expiry = proposed_expiry;
        self.path_seq_map = proposed_path_sequences;
        self.origin_seq_map = proposed_origin_sequences;
        self.routing_table = proposed_routes;
        true
    }

    /// Expire finite paths at monotonic `now_seconds` and rebuild dependent routes.
    pub fn expire_routes(&mut self, now_seconds: u64) -> bool {
        let mut edge_expiry = self.edge_expiry.clone();
        let mut parent_map = self.parent_map.clone();
        edge_expiry.retain(|_, deadline| Self::is_active(*deadline, now_seconds));
        parent_map.retain(|target, parents| {
            parents.retain(|parent| edge_expiry.contains_key(&(*target, *parent)));
            !parents.is_empty()
        });
        let Some(routes) =
            Self::rebuilt_routes(self.node_address, &parent_map, &self.routing_table)
        else {
            return false;
        };
        self.edge_expiry = edge_expiry;
        self.parent_map = parent_map;
        self.routing_table = routes;
        true
    }

    fn is_active(deadline: Option<u64>, now_seconds: u64) -> bool {
        deadline.is_none_or(|deadline| deadline > now_seconds)
    }

    fn target_active_until(
        target: [u8; 16],
        expiry: &HashMap<([u8; 16], [u8; 16]), Option<u64>>,
    ) -> Option<u64> {
        expiry
            .iter()
            .filter_map(|((edge_target, _), deadline)| {
                (*edge_target == target).then_some(*deadline)
            })
            .fold(Some(0), Self::max_deadline)
    }

    fn max_deadline(left: Option<u64>, right: Option<u64>) -> Option<u64> {
        match (left, right) {
            (Some(left), Some(right)) => Some(left.max(right)),
            _ => None,
        }
    }

    fn make_freshness_room(
        map: &mut HashMap<[u8; 16], Freshness>,
        limit: usize,
        now_seconds: u64,
    ) -> bool {
        if map.len() < limit {
            return true;
        }
        let candidate = map
            .iter()
            .filter(|(_, freshness)| freshness.is_reclaimable(now_seconds))
            .min_by_key(|(key, freshness)| (freshness.updated_at, **key))
            .map(|(key, _)| *key);
        candidate.is_some_and(|key| map.remove(&key).is_some())
    }

    fn extract_updates(
        &self,
        dao: &Dao,
        dao_bytes: &[u8],
    ) -> Option<([Option<DaoUpdate>; MAX_DAO_UPDATES], usize)> {
        let options = dao.options_tail(dao_bytes);
        let mut updates = [None; MAX_DAO_UPDATES];
        let mut update_count = 0;
        let mut targets = [None; MAX_DAO_UPDATES];
        let mut target_count = 0;
        let mut transits = core::array::from_fn(|_| None);
        let mut transit_count = 0;
        for opt in OptionIter::new(options) {
            let opt = opt.ok()?;
            match opt.opt_type {
                OPT_RPL_TARGET => {
                    if transit_count != 0 {
                        Self::finish_group(
                            &mut updates,
                            &mut update_count,
                            &targets,
                            target_count,
                            &transits,
                            transit_count,
                        )?;
                        targets = [None; MAX_DAO_UPDATES];
                        target_count = 0;
                        transits = core::array::from_fn(|_| None);
                        transit_count = 0;
                    }
                    let parsed = RplTarget::from_bytes(opt.data).ok()?;
                    if parsed.prefix_len != 128 || target_count == MAX_DAO_UPDATES {
                        return None;
                    }
                    targets[target_count] = Some(parsed.prefix);
                    target_count += 1;
                }
                OPT_TRANSIT_INFO => {
                    if target_count == 0 {
                        return None;
                    }
                    // Current /128 profile has no external-prefix egress semantics.
                    if opt.data[0] != 0 {
                        return None;
                    }
                    let parsed = TransitInfo::from_bytes(opt.data).ok()?;
                    if transits[..transit_count].iter().flatten().any(|first| {
                        first.path_sequence != parsed.path_sequence
                            || first.path_lifetime != parsed.path_lifetime
                    }) {
                        return None;
                    }
                    if !transits[..transit_count]
                        .iter()
                        .flatten()
                        .any(|transit| transit.parent_address == parsed.parent_address)
                    {
                        if transit_count == MAX_DAO_UPDATES {
                            return None;
                        }
                        transits[transit_count] = Some(parsed);
                        transit_count += 1;
                    }
                }
                _ => {}
            }
        }
        Self::finish_group(
            &mut updates,
            &mut update_count,
            &targets,
            target_count,
            &transits,
            transit_count,
        )?;
        Some((updates, update_count))
    }

    fn finish_group(
        updates: &mut [Option<DaoUpdate>; MAX_DAO_UPDATES],
        update_count: &mut usize,
        targets: &[Option<[u8; 16]>; MAX_DAO_UPDATES],
        target_count: usize,
        transits: &[Option<TransitInfo>; MAX_DAO_UPDATES],
        transit_count: usize,
    ) -> Option<()> {
        if target_count == 0
            || transit_count == 0
            || *update_count + target_count.checked_mul(transit_count)? > MAX_DAO_UPDATES
        {
            return None;
        }
        for target in targets[..target_count].iter().flatten() {
            if updates[..*update_count]
                .iter()
                .flatten()
                .any(|update| update.target == *target)
            {
                return None;
            }
            for transit in transits[..transit_count].iter().flatten() {
                updates[*update_count] = Some(DaoUpdate {
                    target: *target,
                    parent: transit.parent_address,
                    path_sequence: transit.path_sequence,
                    path_lifetime: transit.path_lifetime,
                });
                *update_count += 1;
            }
        }
        Some(())
    }

    fn contains_cycle(parent_map: &HashMap<[u8; 16], Vec<[u8; 16]>>) -> bool {
        let mut remaining: HashSet<[u8; 16]> = parent_map.keys().copied().collect();
        loop {
            let before = remaining.len();
            let current = remaining.clone();
            remaining.retain(|target| {
                parent_map[target]
                    .iter()
                    .any(|parent| current.contains(parent))
            });
            if remaining.is_empty() || remaining.len() == before {
                return !remaining.is_empty();
            }
        }
    }

    fn rebuilt_routes(
        root: [u8; 16],
        parent_map: &HashMap<[u8; 16], Vec<[u8; 16]>>,
        routing_table: &RoutingTable,
    ) -> Option<RoutingTable> {
        let mut targets: Vec<[u8; 16]> = parent_map.keys().copied().collect();
        targets.sort_unstable();
        let mut routes = HashMap::with_capacity(targets.len().min(MAX_ROUTES));
        for target in targets {
            if let Some(path) = Self::assemble_path(root, parent_map, target) {
                if routes.len() == MAX_ROUTES {
                    return None;
                }
                let mut entry = routing_table
                    .routes
                    .get(&target)
                    .filter(|entry| entry.state != RouteEntryState::Expired)
                    .cloned()
                    .unwrap_or_else(|| RouteEntry::fresh(&path));
                entry
                    .refresh(&path)
                    .expect("fresh or stale route entry can refresh");
                routes.insert(target, entry);
            }
        }
        Some(RoutingTable { routes })
    }

    /// Walk target → parent → … → root and return the reversed downward path.
    ///
    /// Returns `None` if the chain is incomplete or contains a loop.
    fn assemble_path(
        root: [u8; 16],
        parent_map: &HashMap<[u8; 16], Vec<[u8; 16]>>,
        target: [u8; 16],
    ) -> Option<Vec<[u8; 16]>> {
        let mut chain: Vec<[u8; 16]> = Vec::new();
        let mut visited: HashSet<[u8; 16]> = HashSet::new();
        Self::assemble_path_from(root, parent_map, target, &mut chain, &mut visited)
            .then_some(())?;
        chain.reverse();
        Some(chain)
    }

    fn assemble_path_from(
        root: [u8; 16],
        parent_map: &HashMap<[u8; 16], Vec<[u8; 16]>>,
        node: [u8; 16],
        chain: &mut Vec<[u8; 16]>,
        visited: &mut HashSet<[u8; 16]>,
    ) -> bool {
        if node == root {
            return true;
        }
        if chain.len() == MAX_CHAIN || !visited.insert(node) {
            return false;
        }
        chain.push(node);

        let mut parents = parent_map.get(&node).cloned().unwrap_or_default();
        parents.sort_unstable();
        for parent in parents {
            if Self::assemble_path_from(root, parent_map, parent, chain, visited) {
                return true;
            }
        }

        chain.pop();
        visited.remove(&node);
        false
    }
}

#[cfg(feature = "std")]
fn encode_high_water(map: &HighWaterMap, out: &mut [u8]) -> Option<usize> {
    if map.len() > MAX_DAO_ORIGINS {
        return None;
    }
    let len = 2 + map.len() * HIGH_WATER_ENTRY_LEN;
    if out.len() < len {
        return None;
    }
    out[..2].copy_from_slice(&(map.len() as u16).to_be_bytes());
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_unstable_by_key(|(key, _)| **key);
    for (index, (key, (hash, sequence))) in entries.into_iter().enumerate() {
        let offset = 2 + index * HIGH_WATER_ENTRY_LEN;
        out[offset..offset + 32].copy_from_slice(key);
        out[offset + 32..offset + 40].copy_from_slice(&sequence.to_be_bytes());
        out[offset + 40..offset + 72].copy_from_slice(hash);
    }
    Some(len)
}

#[cfg(feature = "std")]
fn decode_high_water(data: &[u8]) -> Option<HighWaterMap> {
    if data.len() < 2 {
        return None;
    }
    let count = u16::from_be_bytes(data[..2].try_into().ok()?) as usize;
    if count > MAX_DAO_ORIGINS || data.len() != 2 + count * HIGH_WATER_ENTRY_LEN {
        return None;
    }
    let mut map = HashMap::with_capacity(count);
    for index in 0..count {
        let offset = 2 + index * HIGH_WATER_ENTRY_LEN;
        let key = data[offset..offset + 32].try_into().ok()?;
        let sequence = u64::from_be_bytes(data[offset + 32..offset + 40].try_into().ok()?);
        let hash = data[offset + 40..offset + 72].try_into().ok()?;
        if sequence == 0 || map.insert(key, (hash, sequence)).is_some() {
            return None;
        }
    }
    Some(map)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use lichen_hal::storage::mem::MemStorage;
    use lichen_link::{identity::Identity, keys::Seed, link_layer::LinkLayer};
    use std::{vec, vec::Vec};

    fn ll(iid: u8) -> [u8; 16] {
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid]
    }

    fn dodag_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = 0xfd;
        id[15] = 1;
        id
    }

    fn addr(value: u16) -> [u8; 16] {
        let mut address = ll(0);
        address[14..].copy_from_slice(&value.to_be_bytes());
        address
    }

    fn verified_dao(identity: &Identity, sequence: u64, parent: [u8; 16]) -> (Vec<u8>, [u8; 16]) {
        let mut origin = [0u8; 16];
        origin[..2].copy_from_slice(&[0xfe, 0x80]);
        origin[8..].copy_from_slice(&identity.iid);
        let mut sender = DaoManager::new(origin, 0, dodag_id());
        let unsigned = sender.build_dao(parent);
        let digest = dao_origin_digest(origin, dodag_id(), sequence, &unsigned);
        let signature = LinkLayer::new(identity.clone()).sign_digest(&digest);
        let mut wire = unsigned;
        let offset = wire.len();
        wire.resize(offset + crate::message::DAO_ORIGIN_SIGNATURE_LEN, 0);
        crate::message::DaoOriginSignature::write_to(sequence, &signature, &mut wire[offset..])
            .unwrap();
        (wire, origin)
    }

    #[test]
    fn routing_table_add_lookup_remove() {
        let mut table = RoutingTable::new();
        let target = ll(3);
        let path = [ll(2), ll(3)];
        assert!(table.add_route(target, &path));

        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup(&target), Some(path.as_slice()));

        table.remove_route(&target);
        assert!(table.lookup(&target).is_none());
        assert!(table.is_empty());
    }

    #[test]
    fn route_entry_state_machine_allows_stale_refresh_and_rejects_expired_refresh() {
        let mut entry = RouteEntry::fresh(&[ll(2), ll(3)]);
        assert_eq!(entry.state, RouteEntryState::Fresh);

        entry.mark_stale().unwrap();
        assert_eq!(entry.state, RouteEntryState::Stale);

        entry.refresh(&[ll(4), ll(3)]).unwrap();
        assert_eq!(entry.state, RouteEntryState::Fresh);
        assert_eq!(entry.path, [ll(4), ll(3)]);

        entry.mark_expired().unwrap();
        assert_eq!(
            entry.refresh(&[ll(2), ll(3)]),
            Err(InvalidRouteEntryTransition {
                from: RouteEntryState::Expired,
                to: RouteEntryState::Fresh,
            })
        );
    }

    #[test]
    fn routing_table_hides_expired_routes_but_keeps_state_visible() {
        let mut table = RoutingTable::new();
        let target = ll(3);
        assert!(table.add_route(target, &[ll(2), ll(3)]));

        table.mark_stale(&target).unwrap().unwrap();
        assert_eq!(table.entry_state(&target), Some(RouteEntryState::Stale));
        assert!(table.lookup(&target).is_some());

        table.mark_expired(&target).unwrap().unwrap();
        assert_eq!(table.entry_state(&target), Some(RouteEntryState::Expired));
        assert!(table.lookup(&target).is_none());

        assert!(table.add_route(target, &[ll(4), ll(3)]));
        assert_eq!(table.entry_state(&target), Some(RouteEntryState::Fresh));
        assert_eq!(table.lookup(&target).unwrap(), &[ll(4), ll(3)]);
    }

    #[test]
    fn srh_encode_decode_roundtrip() {
        let addresses: Vec<[u8; 16]> = [ll(2), ll(3)].into_iter().collect();
        let srh = SourceRoutingHeader {
            segments_left: 2,
            addresses: addresses.clone(),
        };
        let mut buf = [0u8; 38]; // 6 + 2*16
        let n = srh.write_to(&mut buf).unwrap();
        assert_eq!(n, 38);
        assert_eq!(buf[0], 3); // routing type
        assert_eq!(buf[1], 2); // segments_left

        let decoded = SourceRoutingHeader::from_bytes(&buf[..n]).unwrap();
        assert_eq!(decoded.segments_left, 2);
        assert_eq!(decoded.addresses, addresses);
    }

    #[test]
    fn srh_encode_buffer_too_small() {
        let addresses: Vec<[u8; 16]> = [ll(2), ll(3)].into_iter().collect();
        let srh = SourceRoutingHeader {
            segments_left: 2,
            addresses,
        };
        let mut buf = [0u8; 37]; // one byte short of needed 38
        assert!(matches!(
            srh.write_to(&mut buf),
            Err(RplError::BufferTooSmall(_))
        ));
    }

    #[test]
    fn srh_wrong_type_returns_error() {
        let mut buf = [0u8; 6];
        buf[0] = 0; // routing type 0, not 3
        assert_eq!(
            SourceRoutingHeader::from_bytes(&buf),
            Err(RplError::BadRoutingType(0))
        );
    }

    #[test]
    fn build_dao_produces_valid_options() {
        let mut mgr = DaoManager::new(ll(2), 0, dodag_id());
        let dao_bytes = mgr.build_dao(ll(1));

        // Parse the DAO base
        let dao = Dao::from_bytes(&dao_bytes).unwrap();
        assert_eq!(dao.dao_sequence, 241);
        assert_eq!(dao.dodag_id, Some(dodag_id()));

        // Parse options
        let options_data = dao.options_tail(&dao_bytes);
        let mut found_target = false;
        let mut found_transit = false;
        for opt in OptionIter::new(options_data) {
            let opt = opt.unwrap();
            match opt.opt_type {
                OPT_RPL_TARGET => {
                    found_target = true;
                    let t = RplTarget::from_bytes(opt.data).unwrap();
                    assert_eq!(t.prefix, ll(2)); // advertises itself
                }
                OPT_TRANSIT_INFO => {
                    found_transit = true;
                    let ti = TransitInfo::from_bytes(opt.data).unwrap();
                    assert_eq!(ti.parent_address, ll(1)); // via parent 1
                    assert_eq!(ti.path_sequence, 241);
                }
                _ => {}
            }
        }
        assert!(found_target);
        assert!(found_transit);
    }

    #[test]
    fn root_process_single_hop_dao_installs_route() {
        let root_addr = ll(1);
        let mut root = DaoManager::as_root(root_addr, 0, dodag_id());

        // Node ll(2) sends DAO: target=ll(2), parent=root
        let mut node2 = DaoManager::new(ll(2), 0, dodag_id());
        let dao = node2.build_dao(root_addr);

        assert!(root.process_dao(&dao));
        // Single-hop path: [ll(2)]
        let path = root.routing_table.lookup(&ll(2)).unwrap();
        assert_eq!(path, &[ll(2)]);
    }

    #[test]
    fn root_process_two_hop_dao_assembles_full_path() {
        let root_addr = ll(1);
        let mut root = DaoManager::as_root(root_addr, 0, dodag_id());

        // Node ll(2) sends DAO: target=ll(2), parent=root
        let mut node2 = DaoManager::new(ll(2), 0, dodag_id());
        root.process_dao(&node2.build_dao(root_addr));

        // Node ll(3) sends DAO: target=ll(3), parent=ll(2)
        let mut node3 = DaoManager::new(ll(3), 0, dodag_id());
        root.process_dao(&node3.build_dao(ll(2)));

        // Two-hop path: root → ll(2) → ll(3)
        let path = root.routing_table.lookup(&ll(3)).unwrap();
        assert_eq!(path, &[ll(2), ll(3)]);
    }

    #[test]
    fn incomplete_chain_does_not_install_route() {
        let root_addr = ll(1);
        let mut root = DaoManager::as_root(root_addr, 0, dodag_id());

        // ll(3) sends DAO pointing to ll(2), but ll(2) hasn't sent a DAO yet.
        let mut node3 = DaoManager::new(ll(3), 0, dodag_id());
        root.process_dao(&node3.build_dao(ll(2)));

        assert!(root.routing_table.lookup(&ll(3)).is_none());
    }

    #[test]
    fn dao_sequence_increments() {
        let mut mgr = DaoManager::new(ll(2), 0, dodag_id());
        let d1 = Dao::from_bytes(&mgr.build_dao(ll(1))).unwrap();
        let d2 = Dao::from_bytes(&mgr.build_dao(ll(1))).unwrap();
        assert_eq!(d2.dao_sequence, d1.dao_sequence + 1);
    }

    #[test]
    fn dao_sequence_rolls_from_127_to_zero() {
        let mut mgr = DaoManager::new(ll(2), 0, dodag_id());
        mgr.dao_sequence = 126;

        assert_eq!(
            Dao::from_bytes(&mgr.build_dao(ll(1))).unwrap().dao_sequence,
            127
        );
        assert_eq!(
            Dao::from_bytes(&mgr.build_dao(ll(1))).unwrap().dao_sequence,
            0
        );
    }

    #[test]
    fn dao_sequence_rolls_from_255_to_zero() {
        let mut mgr = DaoManager::new(ll(2), 0, dodag_id());
        mgr.dao_sequence = 254;

        assert_eq!(
            Dao::from_bytes(&mgr.build_dao(ll(1))).unwrap().dao_sequence,
            255
        );
        assert_eq!(
            Dao::from_bytes(&mgr.build_dao(ll(1))).unwrap().dao_sequence,
            0
        );
    }

    #[test]
    fn dao_sequence_comparison_handles_lollipop() {
        assert!(super::seq_is_newer(16, 0));
        assert!(!super::seq_is_newer(17, 0));
        assert!(super::seq_is_newer(255, 239));
        assert!(!super::seq_is_newer(255, 238));
        assert!(super::seq_is_newer(5, 250));
        assert!(!super::seq_is_newer(5, 240));
        assert!(super::seq_is_newer(5, 120));
        assert!(super::seq_is_newer(240, 120));
        assert!(super::seq_is_newer(0, 255));
        assert!(super::seq_is_newer(0, 127));
        assert!(!super::seq_is_newer(127, 0));
        assert!(!super::seq_is_newer(0, 128));
        assert!(super::seq_is_newer(1, 127));
        assert!(super::seq_is_newer(128, 120));
        assert!(super::seq_is_newer(129, 127));
        assert!(!super::seq_is_newer(100, 100));
    }

    fn global_dao_wire_with_lifetime(
        instance: u8,
        sequence: u8,
        target: [u8; 16],
        parent: [u8; 16],
        lifetime: u8,
    ) -> Vec<u8> {
        global_dao_wire_with_sequences(instance, sequence, sequence, target, parent, lifetime)
    }

    fn global_dao_wire_with_sequences(
        instance: u8,
        dao_sequence: u8,
        path_sequence: u8,
        target: [u8; 16],
        parent: [u8; 16],
        lifetime: u8,
    ) -> Vec<u8> {
        let mut wire = vec![instance, 0, 0, dao_sequence, OPT_RPL_TARGET, 18, 0, 128];
        wire.extend_from_slice(&target);
        wire.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0, path_sequence, lifetime]);
        wire.extend_from_slice(&parent);
        wire
    }

    fn global_dao_wire(instance: u8, sequence: u8, target: [u8; 16], parent: [u8; 16]) -> Vec<u8> {
        global_dao_wire_with_lifetime(instance, sequence, target, parent, 255)
    }

    #[test]
    fn root_accepts_global_dao_without_dodag_id() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let wire = global_dao_wire(0, 1, ll(2), ll(1));

        assert!(root.process_dao(&wire));
        assert_eq!(root.routing_table.lookup(&ll(2)), Some(&[ll(2)][..]));
    }

    #[test]
    fn transit_path_sequence_not_dao_sequence_controls_freshness() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        assert!(root.process_dao(&global_dao_wire_with_sequences(
            0,
            250,
            240,
            ll(2),
            ll(1),
            255,
        )));
        assert!(!root.process_dao(&global_dao_wire_with_sequences(
            0,
            251,
            240,
            ll(2),
            ll(1),
            255,
        )));
        assert!(root.process_dao(&global_dao_wire_with_sequences(
            0,
            251,
            241,
            ll(2),
            ll(1),
            255,
        )));
    }

    #[test]
    fn dao_replay_is_tracked_per_origin_before_any_target_mutation() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let first = global_dao_wire_with_sequences(0, 10, 10, ll(2), ll(1), 10);
        assert!(root.process_dao_at(&first, ll(20), 100, 1));

        let other_origin = global_dao_wire_with_sequences(0, 10, 11, ll(2), ll(1), 10);
        assert!(root.process_dao_at(&other_origin, ll(21), 101, 1));

        let stale_origin = global_dao_wire_with_sequences(0, 10, 12, ll(3), ll(1), 10);
        assert!(!root.process_dao_at(&stale_origin, ll(20), 102, 1));
        assert!(!root.parent_map.contains_key(&ll(3)));
        assert!(!root.path_seq_map.contains_key(&ll(3)));
        assert_eq!(root.origin_seq_map.get(&ll(20)).unwrap().sequence, 10);
    }

    #[test]
    fn finite_path_lifetime_expires_edge_and_dependent_routes() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let parent = global_dao_wire_with_lifetime(0, 1, ll(2), ll(1), 1);
        let child = global_dao_wire_with_lifetime(0, 1, ll(3), ll(2), 2);
        assert!(root.process_dao_at(&parent, ll(2), 100, 10));
        assert!(root.process_dao_at(&child, ll(3), 100, 10));
        assert_eq!(root.routing_table.lookup(&ll(3)), Some(&[ll(2), ll(3)][..]));

        root.expire_routes(109);
        assert!(root.routing_table.lookup(&ll(3)).is_some());
        root.expire_routes(110);
        assert!(!root.parent_map.contains_key(&ll(2)));
        assert!(root.parent_map.contains_key(&ll(3)));
        assert!(root.routing_table.lookup(&ll(2)).is_none());
        assert!(root.routing_table.lookup(&ll(3)).is_none());
    }

    #[test]
    fn route_expiry_retains_freshness_and_rejects_replay() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let dao = global_dao_wire_with_sequences(0, 240, 240, ll(2), ll(1), 1);
        assert!(root.process_dao_at(&dao, ll(20), 100, 10));

        assert!(root.expire_routes(110));
        assert!(root.routing_table.lookup(&ll(2)).is_none());
        assert!(!root.parent_map.contains_key(&ll(2)));
        assert!(!root.edge_expiry.contains_key(&(ll(2), ll(1))));
        assert_eq!(root.origin_seq_map.get(&ll(20)).unwrap().sequence, 240);
        assert_eq!(root.path_seq_map.get(&ll(2)).unwrap().sequence, 240);

        assert!(!root.process_dao_at(&dao, ll(20), 111, 10));
        let stale_path = global_dao_wire_with_sequences(0, 241, 240, ll(2), ll(1), 1);
        assert!(!root.process_dao_at(&stale_path, ll(20), 111, 10));
        assert!(root.routing_table.lookup(&ll(2)).is_none());
        assert!(!root.parent_map.contains_key(&ll(2)));
    }

    #[test]
    fn infinite_path_lifetime_has_no_deadline() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let dao = global_dao_wire(0, 255, ll(2), ll(1));

        assert!(root.process_dao_at(&dao, ll(20), 100, 0));
        root.expire_routes(u64::MAX);

        assert_eq!(root.routing_table.lookup(&ll(2)), Some(&[ll(2)][..]));
        assert_eq!(root.edge_expiry.get(&(ll(2), ll(1))), Some(&None));
        assert_eq!(root.origin_seq_map.get(&ll(20)).unwrap().sequence, 255);
        assert_eq!(root.path_seq_map.get(&ll(2)).unwrap().sequence, 255);
    }

    #[test]
    fn zero_lifetime_unit_fails_without_mutation() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let dao = global_dao_wire_with_lifetime(0, 1, ll(2), ll(1), 1);

        assert!(!root.process_dao_at(&dao, ll(2), 100, 0));
        assert!(root.parent_map.is_empty());
        assert!(root.origin_seq_map.is_empty());
        assert!(root.path_seq_map.is_empty());
    }

    #[test]
    fn local_path_sequence_advances_per_generation_and_explicit_copy_reuses_it() {
        let mut mgr = DaoManager::new(ll(2), 0, dodag_id());
        let path_sequence = |wire: &[u8]| {
            let dao = Dao::from_bytes(wire).unwrap();
            OptionIter::new(dao.options_tail(wire))
                .find_map(|option| {
                    let option = option.ok()?;
                    (option.opt_type == OPT_TRANSIT_INFO)
                        .then(|| TransitInfo::from_bytes(option.data).unwrap().path_sequence)
                })
                .unwrap()
        };

        assert_eq!(path_sequence(&mgr.build_dao(ll(1))), 241);
        assert_eq!(path_sequence(&mgr.build_dao(ll(1))), 242);
        assert_eq!(path_sequence(&mgr.build_dao_with_lifetime(ll(1), 10)), 243);
        assert_eq!(
            path_sequence(&mgr.build_dao_copy_with_lifetime(ll(3), 10)),
            243
        );
        assert_eq!(path_sequence(&mgr.build_dao_with_lifetime(ll(1), 0)), 244);
        assert_eq!(path_sequence(&mgr.build_dao(ll(1))), 245);
    }

    #[test]
    fn reboot_equal_bootstrap_makes_progress_on_next_send() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let mut first_boot = DaoManager::new(ll(2), 0, dodag_id());
        assert!(root.process_dao(&first_boot.build_dao(ll(1))));

        let mut rebooted = DaoManager::new(ll(2), 0, dodag_id());
        assert!(!root.process_dao(&rebooted.build_dao(ll(1))));
        assert!(root.process_dao(&rebooted.build_dao(ll(1))));
        assert_eq!(root.path_seq_map.get(&ll(2)).unwrap().sequence, 242);
    }

    #[test]
    fn foreign_dao_scope_is_rejected_before_mutation() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let foreign_instance = global_dao_wire(1, 1, ll(2), ll(1));
        assert!(!root.process_dao(&foreign_instance));
        assert!(root.parent_map.is_empty());
        assert!(root.path_seq_map.is_empty());

        let mut wrong_dodag = DaoManager::new(ll(2), 0, {
            let mut id = dodag_id();
            id[15] = 2;
            id
        });
        assert!(!root.process_dao(&wrong_dodag.build_dao(ll(1))));
        assert!(root.parent_map.is_empty());
        assert!(root.path_seq_map.is_empty());

        let valid = global_dao_wire(0, 1, ll(2), ll(1));
        assert!(root.process_dao(&valid));
    }

    #[test]
    fn zero_lifetime_withdraws_edge_and_routes_but_accepts_rollover() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        assert!(root.process_dao(&global_dao_wire(0, 254, ll(2), ll(1))));
        assert!(root.process_dao(&global_dao_wire(0, 1, ll(3), ll(2))));
        assert_eq!(root.routing_table.lookup(&ll(3)), Some(&[ll(2), ll(3)][..]));

        let withdrawal = global_dao_wire_with_lifetime(0, 255, ll(2), ll(1), 0);
        assert!(root.process_dao(&withdrawal));
        assert!(!root.parent_map.contains_key(&ll(2)));
        assert_eq!(root.path_seq_map.get(&ll(2)).unwrap().sequence, 255);
        assert!(root.routing_table.lookup(&ll(2)).is_none());
        assert!(root.routing_table.lookup(&ll(3)).is_none());
        assert!(!root.process_dao(&withdrawal));

        assert!(root.process_dao(&global_dao_wire(0, 0, ll(2), ll(1))));
        assert_eq!(root.routing_table.lookup(&ll(3)), Some(&[ll(2), ll(3)][..]));
    }

    #[test]
    fn cycle_is_rejected_without_mutating_routes_or_freshness() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        assert!(root.process_dao(&global_dao_wire(0, 1, ll(2), ll(1))));
        assert!(root.process_dao(&global_dao_wire(0, 1, ll(3), ll(2))));

        assert!(!root.process_dao(&global_dao_wire(0, 2, ll(2), ll(3))));
        assert_eq!(
            root.parent_map.get(&ll(2)).map(Vec::as_slice),
            Some(&[ll(1)][..])
        );
        assert_eq!(root.path_seq_map.get(&ll(2)).unwrap().sequence, 1);
        assert_eq!(root.routing_table.lookup(&ll(2)), Some(&[ll(2)][..]));
        assert_eq!(root.routing_table.lookup(&ll(3)), Some(&[ll(2), ll(3)][..]));
    }

    #[test]
    fn malformed_target_cannot_be_replaced_by_a_later_valid_target() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let valid = global_dao_wire(0, 1, ll(2), ll(1));
        let mut wire = vec![0, 0, 0, 1, OPT_RPL_TARGET, 18, 0, 129];
        wire.extend_from_slice(&ll(3));
        wire.extend_from_slice(&valid[4..]);

        assert!(!root.process_dao(&wire));
        assert!(root.parent_map.is_empty());
        assert!(root.path_seq_map.is_empty());
    }

    #[test]
    fn malformed_transit_cannot_be_replaced_by_a_later_valid_transit() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let valid = global_dao_wire(0, 1, ll(2), ll(1));
        let mut wire = valid[..24].to_vec();
        wire.extend_from_slice(&[OPT_TRANSIT_INFO, 3, 0, 0, 0]);
        wire.extend_from_slice(&valid[24..]);

        assert!(!root.process_dao(&wire));
        assert!(root.parent_map.is_empty());
        assert!(root.path_seq_map.is_empty());
    }

    #[test]
    fn duplicate_target_is_rejected_but_multiple_transits_are_accepted() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let valid = global_dao_wire(0, 1, ll(2), ll(1));

        let mut duplicate_target = valid[..24].to_vec();
        duplicate_target.extend_from_slice(&valid[4..]);
        assert!(!root.process_dao(&duplicate_target));

        let mut duplicate_transit = valid.clone();
        duplicate_transit.extend_from_slice(&valid[24..]);
        assert!(root.process_dao(&duplicate_transit));
        assert_eq!(
            root.parent_map.get(&ll(2)).map(Vec::as_slice),
            Some(&[ll(1)][..])
        );
    }

    #[test]
    fn all_transit_parents_are_retained_and_selected_deterministically() {
        fn install(parent_order: [[u8; 16]; 2]) -> DaoManager {
            let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
            assert!(root.process_dao(&global_dao_wire(0, 1, ll(2), ll(1))));
            assert!(root.process_dao(&global_dao_wire(0, 1, ll(3), ll(1))));

            let mut dao = global_dao_wire(0, 1, ll(4), parent_order[0]);
            dao.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0, 1, 255]);
            dao.extend_from_slice(&parent_order[1]);
            assert!(root.process_dao(&dao));
            root
        }

        let forward = install([ll(2), ll(3)]);
        let reverse = install([ll(3), ll(2)]);

        assert_eq!(
            forward.parent_map.get(&ll(4)).map(Vec::as_slice),
            Some(&[ll(2), ll(3)][..])
        );
        assert_eq!(
            reverse.parent_map.get(&ll(4)).map(Vec::as_slice),
            Some(&[ll(2), ll(3)][..])
        );
        assert_eq!(
            forward.routing_table.lookup(&ll(4)),
            Some(&[ll(2), ll(4)][..])
        );
        assert_eq!(
            reverse.routing_table.lookup(&ll(4)),
            Some(&[ll(2), ll(4)][..])
        );
    }

    #[test]
    fn equal_path_sequence_adds_only_a_distinct_live_parent() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        assert!(root.process_dao(&global_dao_wire(0, 1, ll(2), ll(1))));
        assert!(root.process_dao(&global_dao_wire(0, 1, ll(3), ll(1))));

        let first = global_dao_wire_with_sequences(0, 10, 10, ll(4), ll(2), 10);
        assert!(root.process_dao_at(&first, ll(4), 100, 1));
        let redundant = global_dao_wire_with_sequences(0, 11, 10, ll(4), ll(3), 20);
        assert!(root.process_dao_at(&redundant, ll(4), 101, 1));
        assert_eq!(root.parent_map.get(&ll(4)), Some(&vec![ll(2), ll(3)]));

        let conflicting = global_dao_wire_with_sequences(0, 12, 10, ll(4), ll(2), 30);
        assert!(!root.process_dao_at(&conflicting, ll(4), 102, 1));
        assert_eq!(root.edge_expiry.get(&(ll(4), ll(2))), Some(&Some(110)));
        assert_eq!(root.edge_expiry.get(&(ll(4), ll(3))), Some(&Some(121)));
    }

    #[test]
    fn equal_path_sequence_cannot_revive_an_expired_target() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let first = global_dao_wire_with_sequences(0, 10, 10, ll(2), ll(1), 1);
        assert!(root.process_dao_at(&first, ll(2), 100, 1));
        assert!(root.expire_routes(101));

        let replay = global_dao_wire_with_sequences(0, 11, 10, ll(2), ll(3), 1);
        assert!(!root.process_dao_at(&replay, ll(2), 101, 1));
        assert!(!root.parent_map.contains_key(&ll(2)));
    }

    #[test]
    fn route_assembly_tries_later_parent_when_first_chain_is_incomplete() {
        let root = ll(1);
        let mut parents = HashMap::new();
        parents.insert(ll(3), vec![root]);
        parents.insert(ll(4), vec![ll(2), ll(3)]);

        assert_eq!(
            DaoManager::assemble_path(root, &parents, ll(4)),
            Some(vec![ll(3), ll(4)])
        );

        parents.insert(ll(4), vec![ll(3), ll(2)]);
        assert_eq!(
            DaoManager::assemble_path(root, &parents, ll(4)),
            Some(vec![ll(3), ll(4)])
        );
    }

    #[test]
    fn route_rebuild_replaces_full_table_before_installing_desired_routes() {
        let root = ll(1);
        let mut table = RoutingTable::new();
        for value in 0..MAX_ROUTES as u16 {
            assert!(table.add_route(addr(value), &[addr(value)]));
        }
        let desired = addr(300);
        let parents = HashMap::from([(desired, vec![root])]);

        let rebuilt = DaoManager::rebuilt_routes(root, &parents, &table).unwrap();
        assert_eq!(rebuilt.len(), 1);
        assert_eq!(rebuilt.lookup(&desired), Some(&[desired][..]));
        assert!(rebuilt.lookup(&addr(0)).is_none());
    }

    #[test]
    fn route_capacity_failure_is_observable_and_atomic() {
        let root = ll(1);
        let mut table = RoutingTable::new();
        for value in 0..MAX_ROUTES as u16 {
            assert!(table.add_route(addr(value), &[addr(value)]));
        }
        assert!(!table.add_route(addr(300), &[addr(300)]));
        assert_eq!(table.len(), MAX_ROUTES);

        let parents: HashMap<_, _> = (0..=MAX_ROUTES as u16)
            .map(|value| (addr(value), vec![root]))
            .collect();
        assert!(DaoManager::rebuilt_routes(root, &parents, &table).is_none());
        assert_eq!(table.len(), MAX_ROUTES);
        assert_eq!(table.lookup(&addr(0)), Some(&[addr(0)][..]));
    }

    #[test]
    fn multiple_target_transit_groups_are_applied_atomically() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let first = global_dao_wire(0, 240, ll(2), ll(1));
        let second = global_dao_wire(0, 241, ll(3), ll(2));
        let mut wire = first;
        wire.extend_from_slice(&second[4..]);

        assert!(root.process_dao(&wire));
        assert_eq!(root.routing_table.lookup(&ll(2)), Some(&[ll(2)][..]));
        assert_eq!(root.routing_table.lookup(&ll(3)), Some(&[ll(2), ll(3)][..]));
    }

    #[test]
    fn malformed_group_order_is_rejected_immediately() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let valid = global_dao_wire(0, 240, ll(2), ll(1));
        let mut transit_first = valid[..4].to_vec();
        transit_first.extend_from_slice(&valid[24..]);
        transit_first.extend_from_slice(&valid[4..24]);
        assert!(!root.process_dao(&transit_first));

        assert!(!root.process_dao(&valid[..24]));
        assert!(root.parent_map.is_empty());
        assert!(root.path_seq_map.is_empty());
    }

    #[test]
    fn non_host_target_prefix_is_rejected() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let mut wire = global_dao_wire(0, 1, ll(2), ll(1));
        wire[7] = 64;

        assert!(!root.process_dao(&wire));
        assert!(root.parent_map.is_empty());
        assert!(root.path_seq_map.is_empty());
    }

    #[test]
    fn bounded_state_rejects_new_entries_at_capacity() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        for value in 0..MAX_DAO_ORIGINS as u16 {
            root.origin_seq_map
                .insert(addr(value), Freshness::new(1, None, 0));
        }
        let dao = global_dao_wire(0, 1, addr(300), ll(1));
        assert!(!root.process_dao_at(&dao, addr(300), 0, 1));
        assert_eq!(root.origin_seq_map.len(), MAX_DAO_ORIGINS);
        assert!(root.parent_map.is_empty());

        let mut table = RoutingTable::new();
        for value in 0..MAX_ROUTES as u16 {
            assert!(table.add_route(addr(value), &[addr(value)]));
        }
        assert!(!table.add_route(addr(300), &[addr(300)]));
        assert_eq!(table.len(), MAX_ROUTES);
        assert!(table.lookup(&addr(300)).is_none());

        let mut edge_full = DaoManager::as_root(ll(1), 0, dodag_id());
        for value in 0..MAX_PARENT_EDGES as u16 {
            edge_full.parent_map.insert(addr(value), vec![ll(1)]);
            edge_full
                .edge_expiry
                .insert((addr(value), ll(1)), Some(1_000));
        }
        let dao = global_dao_wire(0, 1, addr(300), ll(1));
        assert!(!edge_full.process_dao_at(&dao, addr(300), 0, 1));
        assert_eq!(edge_full.parent_map.len(), MAX_PARENT_EDGES);
        assert!(!edge_full.parent_map.contains_key(&addr(300)));

        let mut paths_full = DaoManager::as_root(ll(1), 0, dodag_id());
        for value in 0..MAX_PATH_SEQUENCES as u16 {
            paths_full
                .path_seq_map
                .insert(addr(value), Freshness::new(1, None, 0));
        }
        let withdrawal = global_dao_wire_with_lifetime(0, 1, addr(300), ll(1), 0);
        assert!(!paths_full.process_dao_at(&withdrawal, addr(300), 0, 1));
        assert_eq!(paths_full.path_seq_map.len(), MAX_PATH_SEQUENCES);
        assert!(!paths_full.path_seq_map.contains_key(&addr(300)));
    }

    #[test]
    fn freshness_capacity_retains_tombstones_then_evicts_oldest_inactive() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        for value in 0..MAX_DAO_ORIGINS as u16 {
            root.origin_seq_map
                .insert(addr(value), Freshness::new(1, Some(10), u64::from(value)));
        }
        let dao = global_dao_wire_with_lifetime(0, 1, addr(300), ll(1), 1);

        assert!(!root.process_dao_at(&dao, addr(300), 3_609, 1));
        assert!(root.origin_seq_map.contains_key(&addr(0)));
        assert!(root.process_dao_at(&dao, addr(300), 3_610, 1));
        assert!(!root.origin_seq_map.contains_key(&addr(0)));
        assert!(root.origin_seq_map.contains_key(&addr(300)));
    }

    #[test]
    fn target_freshness_reclamation_fails_closed_until_tombstone_expires() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        for value in 0..MAX_PATH_SEQUENCES as u16 {
            root.path_seq_map
                .insert(addr(value), Freshness::new(1, Some(10), 0));
        }
        let withdrawal = global_dao_wire_with_sequences(0, 1, 1, addr(300), ll(1), 0);

        assert!(!root.process_dao_at(&withdrawal, addr(300), 3_609, 1));
        assert!(root.process_dao_at(&withdrawal, addr(300), 3_610, 1));
        assert_eq!(root.path_seq_map.len(), MAX_PATH_SEQUENCES);
        assert!(root.path_seq_map.contains_key(&addr(300)));
    }

    #[test]
    fn persistent_state_missing_corrupt_and_tx_max_fail_closed() {
        let mut storage = MemStorage::new();
        let key = PublicKey::new([7; 32]);
        assert_eq!(
            DaoTxState::open(&storage, key),
            Err(DaoPersistentOpenError::Missing)
        );
        assert!(matches!(
            DaoManager::open_root(&storage, ll(1), 0, dodag_id()),
            Err(DaoPersistentOpenError::Missing)
        ));
        storage.set_raw(DAO_TX_KEYS[0], b"torn");
        assert_eq!(
            DaoTxState::open(&storage, key),
            Err(DaoPersistentOpenError::Corrupt)
        );

        let mut storage = MemStorage::new();
        storage.set_raw(DAO_RX_KEYS[0], b"torn");
        assert!(matches!(
            DaoManager::open_root(&storage, ll(1), 0, dodag_id()),
            Err(DaoPersistentOpenError::Corrupt)
        ));

        let mut storage = MemStorage::new();
        let tx = DaoTxState::provision(&mut storage, key).unwrap();
        let payload = encode_tx_state(key.as_bytes(), u64::MAX, &[]).unwrap();
        let mut record = vec![0u8; payload.len() + SLOT_OVERHEAD];
        update_redundant(
            &mut storage,
            DAO_TX_KEYS,
            DAO_TX_MAGIC,
            tx.current,
            &payload,
            &mut record,
        )
        .unwrap();
        let mut tx = DaoTxState::open(&storage, key).unwrap();
        assert_eq!(tx.reserve_next(&mut storage), Err(DaoTxError::Exhausted));
        let mut tx = DaoTxState::open(&storage, key).unwrap();
        assert_eq!(tx.reserve_next(&mut storage), Err(DaoTxError::Exhausted));
    }

    #[test]
    fn rx_write_failure_leaves_all_ram_and_durable_state_unchanged() {
        let identity = Identity::from_seed(Seed::new([0x31; 32]));
        let (wire, origin) = verified_dao(&identity, 1, ll(1));
        let verified = SignatureVerifiedDao::verify_signature(
            &wire,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        let mut storage = MemStorage::new();
        let (mut root, mut state) =
            DaoManager::provision_root(&mut storage, ll(1), 0, dodag_id()).unwrap();
        storage.fail_next_write();
        assert!(matches!(
            root.process_signature_verified(
                &verified,
                &mut state,
                &mut storage,
                DaoProcessTiming {
                    now_seconds: 0,
                    lifetime_unit_seconds: 60,
                    max_deadline_seconds: u64::MAX,
                },
            ),
            Err(DaoProcessError::Persistence(_))
        ));
        assert!(root.origin_high_water().is_empty());
        assert!(root.routing_table().lookup(&ll(2)).is_none());
        let (rebooted, _) = DaoManager::open_root(&storage, ll(1), 0, dodag_id()).unwrap();
        assert!(rebooted.origin_high_water().is_empty());
    }

    #[test]
    fn duplicate_after_persisted_crash_reconstructs_route_without_write() {
        let identity = Identity::from_seed(Seed::new([0x32; 32]));
        let (wire, origin) = verified_dao(&identity, 9, ll(1));
        let verified = SignatureVerifiedDao::verify_signature(
            &wire,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        let mut storage = MemStorage::new();
        let (_, state) = DaoManager::provision_root(&mut storage, ll(1), 0, dodag_id()).unwrap();

        let mut table = HashMap::new();
        table.insert(
            *identity.pubkey.as_bytes(),
            (Sha256::digest(&wire).into(), 9),
        );
        let mut payload = vec![0u8; HIGH_WATER_PAYLOAD_LEN];
        let len = encode_high_water(&table, &mut payload).unwrap();
        let mut record = vec![0u8; len + SLOT_OVERHEAD];
        update_redundant(
            &mut storage,
            DAO_RX_KEYS,
            DAO_RX_MAGIC,
            state.current,
            &payload[..len],
            &mut record,
        )
        .unwrap();
        let before_a = storage.raw(DAO_RX_KEYS[0]).map(<[u8]>::to_vec);
        let before_b = storage.raw(DAO_RX_KEYS[1]).map(<[u8]>::to_vec);

        let (mut rebooted, mut rebooted_state) =
            DaoManager::open_root(&storage, ll(1), 0, dodag_id()).unwrap();
        assert_eq!(
            rebooted.process_signature_verified(
                &verified,
                &mut rebooted_state,
                &mut storage,
                DaoProcessTiming {
                    now_seconds: 0,
                    lifetime_unit_seconds: 60,
                    max_deadline_seconds: u64::MAX,
                }
            ),
            Ok(DaoProcessOutcome::Duplicate)
        );
        assert_eq!(
            rebooted.routing_table().lookup(&origin),
            Some([origin].as_slice())
        );
        assert_eq!(storage.raw(DAO_RX_KEYS[0]), before_a.as_deref());
        assert_eq!(storage.raw(DAO_RX_KEYS[1]), before_b.as_deref());
    }

    #[test]
    fn tx_stale_handle_cannot_reuse_sequence_and_exact_dao_survives_reboot() {
        let identity = Identity::from_seed(Seed::new([0x41; 32]));
        let (wire, _) = verified_dao(&identity, 1, ll(1));
        let mut storage = MemStorage::new();
        let mut first = DaoTxState::provision(&mut storage, identity.pubkey).unwrap();
        let mut stale = DaoTxState::open(&storage, identity.pubkey).unwrap();

        let sequence = first.reserve_next(&mut storage).unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(stale.reserve_next(&mut storage), Err(DaoTxError::Stale));
        first
            .finalize_signed(&mut storage, sequence, &wire)
            .unwrap();
        let mut rebooted = DaoTxState::open(&storage, identity.pubkey).unwrap();
        assert_eq!(rebooted.last_signed_dao(), Some(wire.as_slice()));

        assert_eq!(rebooted.reserve_next(&mut storage), Ok(2));
        let reopened = DaoTxState::open(&storage, identity.pubkey).unwrap();
        assert_eq!(reopened.last_reserved, 2);
        assert_eq!(reopened.last_signed_dao(), Some(wire.as_slice()));
    }

    #[test]
    fn tx_finalize_failure_consumes_sequence_without_returnable_new_dao() {
        let identity = Identity::from_seed(Seed::new([0x42; 32]));
        let (wire, _) = verified_dao(&identity, 1, ll(1));
        let mut storage = MemStorage::new();
        let mut state = DaoTxState::provision(&mut storage, identity.pubkey).unwrap();
        let sequence = state.reserve_next(&mut storage).unwrap();
        storage.fail_next_write();
        assert!(matches!(
            state.finalize_signed(&mut storage, sequence, &wire),
            Err(DaoTxError::Persistence(_))
        ));
        let mut reopened = DaoTxState::open(&storage, identity.pubkey).unwrap();
        assert_eq!(reopened.last_reserved, 1);
        assert_eq!(reopened.last_signed_dao(), None);
        assert_eq!(reopened.reserve_next(&mut storage), Ok(2));
        assert_eq!(
            reopened.finalize_signed(&mut storage, 2, &[0u8; MAX_SIGNED_DAO_LEN + 1],),
            Err(DaoTxError::Oversized)
        );
        let mut reopened = DaoTxState::open(&storage, identity.pubkey).unwrap();
        assert_eq!(reopened.last_signed_dao(), None);
        assert_eq!(reopened.reserve_next(&mut storage), Ok(3));
    }

    #[test]
    fn tx_state_rejects_key_rotation_and_storage_transplant() {
        let first = Identity::from_seed(Seed::new([0x44; 32]));
        let second = Identity::from_seed(Seed::new([0x45; 32]));
        let (wire, _) = verified_dao(&first, 1, ll(1));
        let mut storage = MemStorage::new();
        let mut state = DaoTxState::provision(&mut storage, first.pubkey).unwrap();
        let sequence = state.reserve_next(&mut storage).unwrap();
        state
            .finalize_signed(&mut storage, sequence, &wire)
            .unwrap();
        assert_eq!(state.last_signed_dao(), Some(wire.as_slice()));
        assert_eq!(
            DaoTxState::open(&storage, second.pubkey),
            Err(DaoPersistentOpenError::KeyMismatch)
        );

        let mut transplanted = MemStorage::new();
        for key in DAO_TX_KEYS {
            if let Some(record) = storage.raw(key) {
                transplanted.set_raw(key, record);
            }
        }
        assert_eq!(
            DaoTxState::open(&transplanted, second.pubkey),
            Err(DaoPersistentOpenError::KeyMismatch)
        );
    }

    #[test]
    fn dao_open_and_provision_propagate_read_failures() {
        let key = PublicKey::new([0x46; 32]);
        let mut tx_storage = MemStorage::new();
        tx_storage.fail_next_read();
        assert_eq!(
            DaoTxState::open(&tx_storage, key),
            Err(DaoPersistentOpenError::Storage(
                lichen_hal::storage::mem::MemStorageError
            ))
        );
        tx_storage.fail_next_read();
        assert_eq!(
            DaoTxState::provision(&mut tx_storage, key),
            Err(DaoProvisionError::Storage(
                lichen_hal::storage::mem::MemStorageError
            ))
        );

        let mut rx_storage = MemStorage::new();
        rx_storage.fail_next_read();
        assert!(matches!(
            DaoManager::open_root(&rx_storage, ll(1), 0, dodag_id()),
            Err(DaoPersistentOpenError::Storage(_))
        ));
        rx_storage.fail_next_read();
        assert!(matches!(
            DaoManager::provision_root(&mut rx_storage, ll(1), 0, dodag_id()),
            Err(DaoProvisionError::Storage(_))
        ));
        assert!(rx_storage.raw(DAO_RX_KEYS[0]).is_none());
        assert!(rx_storage.raw(DAO_RX_KEYS[1]).is_none());
    }

    #[test]
    fn rx_stale_handle_cannot_overwrite_newer_replay_floor() {
        let identity = Identity::from_seed(Seed::new([0x43; 32]));
        let (wire_one, origin) = verified_dao(&identity, 1, ll(1));
        let (wire_two, _) = verified_dao(&identity, 2, ll(1));
        let verified_one = SignatureVerifiedDao::verify_signature(
            &wire_one,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        let verified_two = SignatureVerifiedDao::verify_signature(
            &wire_two,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        let mut storage = MemStorage::new();
        let (mut first, mut first_state) =
            DaoManager::provision_root(&mut storage, ll(1), 0, dodag_id()).unwrap();
        let (mut stale, mut stale_state) =
            DaoManager::open_root(&storage, ll(1), 0, dodag_id()).unwrap();
        let timing = DaoProcessTiming {
            now_seconds: 0,
            lifetime_unit_seconds: 60,
            max_deadline_seconds: u64::MAX,
        };

        assert_eq!(
            first
                .process_signature_verified(&verified_one, &mut first_state, &mut storage, timing,),
            Ok(DaoProcessOutcome::Applied)
        );
        assert_eq!(
            stale
                .process_signature_verified(&verified_two, &mut stale_state, &mut storage, timing,),
            Err(DaoProcessError::Stale)
        );
        assert!(stale.origin_high_water().is_empty());
        assert!(stale.routing_table().lookup(&origin).is_none());
        let (reopened, _) = DaoManager::open_root(&storage, ll(1), 0, dodag_id()).unwrap();
        assert_eq!(reopened.origin_high_water()[0].origin_sequence, 1);
    }

    #[test]
    fn fresh_same_iid_different_prefix_target_rejects_without_mutation() {
        let identity = Identity::from_seed(Seed::new([0x47; 32]));
        let (wire, origin) = verified_dao(&identity, 1, ll(1));
        let verified = SignatureVerifiedDao::verify_signature(
            &wire,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        let mut storage = MemStorage::new();
        let (mut root, mut state) =
            DaoManager::provision_root(&mut storage, ll(1), 0, dodag_id()).unwrap();
        let timing = DaoProcessTiming {
            now_seconds: 0,
            lifetime_unit_seconds: 60,
            max_deadline_seconds: u64::MAX,
        };
        assert_eq!(
            root.process_signature_verified(&verified, &mut state, &mut storage, timing),
            Ok(DaoProcessOutcome::Applied)
        );

        let mut other_prefix = origin;
        other_prefix[0] ^= 0x03;
        let mut sender = DaoManager::new(other_prefix, 0, dodag_id());
        let unsigned = sender.build_dao(ll(1));
        let digest = dao_origin_digest(origin, dodag_id(), 2, &unsigned);
        let signature = LinkLayer::new(identity.clone()).sign_digest(&digest);
        let mut changed = unsigned;
        let offset = changed.len();
        changed.resize(offset + crate::message::DAO_ORIGIN_SIGNATURE_LEN, 0);
        crate::message::DaoOriginSignature::write_to(2, &signature, &mut changed[offset..])
            .unwrap();
        let changed = SignatureVerifiedDao::verify_signature(
            &changed,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        let before_high_water = root.origin_high_water();
        let before_a = storage.raw(DAO_RX_KEYS[0]).map(<[u8]>::to_vec);
        let before_b = storage.raw(DAO_RX_KEYS[1]).map(<[u8]>::to_vec);
        let before_route = root
            .routing_table()
            .lookup(&origin)
            .map(<[[u8; 16]]>::to_vec);
        assert_eq!(
            root.process_signature_verified(&changed, &mut state, &mut storage, timing),
            Err(DaoProcessError::RouteRejected)
        );
        assert_eq!(root.origin_high_water(), before_high_water);
        assert_eq!(storage.raw(DAO_RX_KEYS[0]), before_a.as_deref());
        assert_eq!(storage.raw(DAO_RX_KEYS[1]), before_b.as_deref());
        assert_eq!(
            root.routing_table().lookup(&origin),
            before_route.as_deref()
        );
        assert!(root.routing_table().lookup(&other_prefix).is_none());
    }

    #[test]
    fn context_precedes_option_framing_and_replay_precedes_prefix_semantics() {
        let identity = Identity::from_seed(Seed::new([0x48; 32]));
        let (wire, origin) = verified_dao(&identity, 2, ll(1));
        let mut wrong_context = wire.clone();
        wrong_context[0] = 1;
        let dao = Dao::from_bytes(&wrong_context).unwrap();
        let option_offset = wrong_context.len() - dao.options_tail(&wrong_context).len();
        wrong_context[option_offset + 1] = u8::MAX;
        assert!(matches!(
            SignatureVerifiedDao::verify_signature(
                &wrong_context,
                origin,
                0,
                dodag_id(),
                Some(identity.pubkey),
            ),
            Err(DaoVerifyError::WrongInstance)
        ));

        let verified = SignatureVerifiedDao::verify_signature(
            &wire,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        let mut storage = MemStorage::new();
        let (mut root, mut state) =
            DaoManager::provision_root(&mut storage, ll(1), 0, dodag_id()).unwrap();
        let timing = DaoProcessTiming {
            now_seconds: 0,
            lifetime_unit_seconds: 60,
            max_deadline_seconds: u64::MAX,
        };
        assert_eq!(
            root.process_signature_verified(&verified, &mut state, &mut storage, timing),
            Ok(DaoProcessOutcome::Applied)
        );

        let envelope = SignedDaoEnvelope::from_bytes(&wire).unwrap();
        let mut non_128 = envelope.unsigned_bytes.to_vec();
        let dao = Dao::from_bytes(&non_128).unwrap();
        let target_offset = non_128.len() - dao.options_tail(&non_128).len();
        non_128[target_offset + 3] = 64;
        let digest = dao_origin_digest(origin, dodag_id(), 1, &non_128);
        let signature = LinkLayer::new(identity.clone()).sign_digest(&digest);
        let offset = non_128.len();
        non_128.resize(offset + crate::message::DAO_ORIGIN_SIGNATURE_LEN, 0);
        crate::message::DaoOriginSignature::write_to(1, &signature, &mut non_128[offset..])
            .unwrap();
        let non_128 = SignatureVerifiedDao::verify_signature(
            &non_128,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        assert_eq!(
            root.process_signature_verified(&non_128, &mut state, &mut storage, timing),
            Err(DaoProcessError::Replay)
        );
    }

    #[test]
    fn replay_does_not_expire_routes_and_key_capacity_fails_closed() {
        let identity = Identity::from_seed(Seed::new([0x33; 32]));
        let mut origin = [0u8; 16];
        origin[..2].copy_from_slice(&[0xfe, 0x80]);
        origin[8..].copy_from_slice(&identity.iid);
        let mut sender = DaoManager::new(origin, 0, dodag_id());
        let unsigned = sender.build_dao_with_lifetime(ll(1), 1);
        let sign = |unsigned: &[u8]| {
            let digest = dao_origin_digest(origin, dodag_id(), 1, unsigned);
            let signature = LinkLayer::new(identity.clone()).sign_digest(&digest);
            let mut wire = unsigned.to_vec();
            let offset = wire.len();
            wire.resize(offset + crate::message::DAO_ORIGIN_SIGNATURE_LEN, 0);
            crate::message::DaoOriginSignature::write_to(1, &signature, &mut wire[offset..])
                .unwrap();
            wire
        };
        let wire = sign(&unsigned);
        let verified = SignatureVerifiedDao::verify_signature(
            &wire,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        let mut storage = MemStorage::new();
        let (mut root, mut state) =
            DaoManager::provision_root(&mut storage, ll(1), 0, dodag_id()).unwrap();
        assert_eq!(
            root.process_signature_verified(
                &verified,
                &mut state,
                &mut storage,
                DaoProcessTiming {
                    now_seconds: 0,
                    lifetime_unit_seconds: 1,
                    max_deadline_seconds: u64::MAX,
                },
            ),
            Ok(DaoProcessOutcome::Applied)
        );

        let mut changed = unsigned;
        changed[3] ^= 1;
        let changed = sign(&changed);
        let changed = SignatureVerifiedDao::verify_signature(
            &changed,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        assert_eq!(
            root.process_signature_verified(
                &changed,
                &mut state,
                &mut storage,
                DaoProcessTiming {
                    now_seconds: 100,
                    lifetime_unit_seconds: 1,
                    max_deadline_seconds: u64::MAX,
                },
            ),
            Err(DaoProcessError::Replay)
        );
        assert!(root.routing_table().lookup(&origin).is_some());

        root.origin_high_water = (0..MAX_DAO_ORIGINS)
            .map(|index| {
                let mut key = [0u8; 32];
                key[..8].copy_from_slice(&(index as u64).to_be_bytes());
                (key, ([0u8; 32], 1))
            })
            .collect();
        let other = Identity::from_seed(Seed::new([0x34; 32]));
        let (other_wire, other_origin) = verified_dao(&other, 1, ll(1));
        let other_verified = SignatureVerifiedDao::verify_signature(
            &other_wire,
            other_origin,
            0,
            dodag_id(),
            Some(other.pubkey),
        )
        .unwrap();
        assert_eq!(
            root.process_signature_verified(
                &other_verified,
                &mut state,
                &mut storage,
                DaoProcessTiming {
                    now_seconds: 0,
                    lifetime_unit_seconds: 1,
                    max_deadline_seconds: u64::MAX,
                },
            ),
            Err(DaoProcessError::RouteRejected)
        );
        assert_eq!(root.origin_high_water.len(), MAX_DAO_ORIGINS);
    }
}
