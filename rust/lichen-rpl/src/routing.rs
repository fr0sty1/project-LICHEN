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
const LOLLIPOP_CIRCULAR_BIT: u8 = 128;
#[cfg(feature = "std")]
const LOLLIPOP_SEQUENCE_WINDOW: u8 = 16;

#[cfg(feature = "std")]
fn seq_is_newer(new_seq: u8, old_seq: u8) -> bool {
    match (
        new_seq < LOLLIPOP_CIRCULAR_BIT,
        old_seq < LOLLIPOP_CIRCULAR_BIT,
    ) {
        (true, true) => new_seq > old_seq,
        (false, false) => {
            let diff = new_seq.wrapping_sub(old_seq) & 0x7F;
            diff > 0 && diff <= LOLLIPOP_SEQUENCE_WINDOW
        }
        (true, false) => true,
        (false, true) => false,
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
const MAX_DAO_UPDATES: usize = 64;
/// Maximum complete route hops allowed by the LICHEN RPL profile.
#[cfg(feature = "std")]
pub const MAX_ROUTE_HOPS: usize = 8;
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
const DAO_ADMISSION_KEYS: [&str; 2] = ["rpl.admit.a", "rpl.admit.b"];
#[cfg(feature = "std")]
// Provisional, unshipped scope-bound format. No migration from DTX1 is supported.
const DAO_TX_MAGIC: [u8; 4] = *b"DTX2";
#[cfg(feature = "std")]
// Provisional, unshipped scope-bound format. DRX1 records fail closed; scope and
// high-water state must never be fabricated or discarded by automatic migration.
const DAO_RX_MAGIC: [u8; 4] = *b"DRX2";
#[cfg(feature = "std")]
// Provisional, unshipped scope-bound format. There is intentionally no migration
// or admission-removal path: an operator must explicitly reprovision invalid state.
const DAO_ADMISSION_MAGIC: [u8; 4] = *b"DAD1";
#[cfg(all(feature = "std", test))]
const DAO_RX_LEGACY_MAGIC: [u8; 4] = *b"DRX1";
#[cfg(feature = "std")]
const HIGH_WATER_ENTRY_LEN: usize = 72;
#[cfg(feature = "std")]
const HIGH_WATER_SCOPE_LEN: usize = 16 + 1 + 16;
#[cfg(feature = "std")]
const HIGH_WATER_HEADER_LEN: usize = HIGH_WATER_SCOPE_LEN + 2;
#[cfg(feature = "std")]
const HIGH_WATER_PAYLOAD_LEN: usize =
    HIGH_WATER_HEADER_LEN + MAX_DAO_ORIGINS * HIGH_WATER_ENTRY_LEN;
#[cfg(feature = "std")]
const SLOT_OVERHEAD: usize = 24;
#[cfg(feature = "std")]
const DAO_TX_HEADER_LEN: usize = 75;
/// Maximum complete signed DAO retained for exact retransmission.
#[cfg(feature = "std")]
pub const MAX_SIGNED_DAO_LEN: usize = 255;
#[cfg(feature = "std")]
const DAO_TX_PAYLOAD_LEN: usize = DAO_TX_HEADER_LEN + MAX_SIGNED_DAO_LEN;
#[cfg(feature = "std")]
const DAO_ADMISSION_HEADER_LEN: usize = HIGH_WATER_SCOPE_LEN + 2;
#[cfg(feature = "std")]
const DAO_ADMISSION_PAYLOAD_LEN: usize = DAO_ADMISSION_HEADER_LEN + MAX_DAO_ORIGINS * 32;
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

    pub fn origin_iid(&self) -> [u8; 8] {
        self.origin[8..].try_into().unwrap()
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
    ScopeMismatch,
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
    local_origin: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    last_reserved: u64,
    last_signed_dao: Vec<u8>,
}

#[cfg(feature = "std")]
impl DaoTxState {
    pub fn provision<S: NonVolatile>(
        storage: &mut S,
        expected_key: PublicKey,
        local_origin: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> Result<Self, DaoProvisionError<S::Error>> {
        match Self::open(
            storage,
            expected_key,
            local_origin,
            rpl_instance_id,
            dodag_id,
        ) {
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
        let payload = encode_tx_state(
            expected_key.as_bytes(),
            local_origin,
            rpl_instance_id,
            dodag_id,
            0,
            &[],
        )
        .unwrap();
        let mut record = vec![0u8; DAO_TX_HEADER_LEN + SLOT_OVERHEAD];
        provision_redundant(storage, DAO_TX_KEYS, DAO_TX_MAGIC, &payload, &mut record).map_err(
            |error| match error {
                RedundantProvisionError::Exists => {
                    DaoProvisionError::Open(DaoPersistentOpenError::Corrupt)
                }
                RedundantProvisionError::Storage(error) => DaoProvisionError::Storage(error),
            },
        )?;
        Self::open(
            storage,
            expected_key,
            local_origin,
            rpl_instance_id,
            dodag_id,
        )
        .map_err(DaoProvisionError::Open)
    }

    pub fn open<S: NonVolatile>(
        storage: &S,
        expected_key: PublicKey,
        local_origin: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
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
        if payload[32..48] != local_origin
            || payload[48] != rpl_instance_id
            || payload[49..65] != dodag_id
        {
            return Err(DaoPersistentOpenError::ScopeMismatch);
        }
        let signed_len = u16::from_be_bytes(payload[73..75].try_into().unwrap()) as usize;
        if signed_len > MAX_SIGNED_DAO_LEN || current.len != DAO_TX_HEADER_LEN + signed_len {
            return Err(DaoPersistentOpenError::Corrupt);
        }
        Ok(Self {
            current,
            public_key,
            local_origin,
            rpl_instance_id,
            dodag_id,
            last_reserved: u64::from_be_bytes(payload[65..73].try_into().unwrap()),
            last_signed_dao: payload[DAO_TX_HEADER_LEN..current.len].to_vec(),
        })
    }

    pub fn is_for_scope(
        &self,
        public_key: &PublicKey,
        local_origin: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> bool {
        self.public_key == *public_key.as_bytes()
            && self.local_origin == local_origin
            && self.rpl_instance_id == rpl_instance_id
            && self.dodag_id == dodag_id
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
        let payload = encode_tx_state(
            &self.public_key,
            self.local_origin,
            self.rpl_instance_id,
            self.dodag_id,
            next,
            &self.last_signed_dao,
        )
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
        let payload = encode_tx_state(
            &self.public_key,
            self.local_origin,
            self.rpl_instance_id,
            self.dodag_id,
            sequence,
            signed_dao,
        )
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
        self.last_signed_dao.clear();
        self.last_signed_dao.extend_from_slice(signed_dao);
        Ok(())
    }

    /// Clear exact retry bytes after successful transmission.
    pub fn clear_transmitted<S: NonVolatile>(
        &mut self,
        storage: &mut S,
    ) -> Result<(), DaoTxError<S::Error>> {
        if self.last_signed_dao.is_empty() {
            return Err(DaoTxError::InvalidState);
        }
        let payload = encode_tx_state(
            &self.public_key,
            self.local_origin,
            self.rpl_instance_id,
            self.dodag_id,
            self.last_reserved,
            &[],
        )
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
        self.last_signed_dao.clear();
        Ok(())
    }
}

#[cfg(feature = "std")]
fn encode_tx_state(
    public_key: &[u8; 32],
    local_origin: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    sequence: u64,
    signed_dao: &[u8],
) -> Option<Vec<u8>> {
    if signed_dao.len() > MAX_SIGNED_DAO_LEN {
        return None;
    }
    let mut payload = vec![0u8; DAO_TX_HEADER_LEN + signed_dao.len()];
    payload[..32].copy_from_slice(public_key);
    payload[32..48].copy_from_slice(&local_origin);
    payload[48] = rpl_instance_id;
    payload[49..65].copy_from_slice(&dodag_id);
    payload[65..73].copy_from_slice(&sequence.to_be_bytes());
    payload[73..75].copy_from_slice(&(signed_dao.len() as u16).to_be_bytes());
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
#[derive(Debug, PartialEq, Eq)]
pub struct DaoAdmissionState {
    current: RedundantValue,
    node_address: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    admitted: HashSet<[u8; 32]>,
}

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub enum DaoAdmissionUpdateError<E> {
    Persistence(E),
    Stale,
    Exhausted,
    Corrupt,
    Capacity,
}

#[cfg(feature = "std")]
impl DaoAdmissionState {
    pub fn provision<S: NonVolatile>(
        storage: &mut S,
        node_address: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> Result<Self, DaoProvisionError<S::Error>> {
        match Self::open(storage, node_address, rpl_instance_id, dodag_id) {
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
        let payload = encode_admissions(node_address, rpl_instance_id, dodag_id, &HashSet::new())
            .expect("empty admission set fits fixed header");
        let mut record = vec![0u8; payload.len() + SLOT_OVERHEAD];
        provision_redundant(
            storage,
            DAO_ADMISSION_KEYS,
            DAO_ADMISSION_MAGIC,
            &payload,
            &mut record,
        )
        .map_err(|error| match error {
            RedundantProvisionError::Exists => {
                DaoProvisionError::Open(DaoPersistentOpenError::Corrupt)
            }
            RedundantProvisionError::Storage(error) => DaoProvisionError::Storage(error),
        })?;
        Self::open(storage, node_address, rpl_instance_id, dodag_id)
            .map_err(DaoProvisionError::Open)
    }

    pub fn open<S: NonVolatile>(
        storage: &S,
        node_address: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> Result<Self, DaoPersistentOpenError<S::Error>> {
        let mut a = vec![0u8; DAO_ADMISSION_PAYLOAD_LEN + SLOT_OVERHEAD];
        let mut b = vec![0u8; DAO_ADMISSION_PAYLOAD_LEN + SLOT_OVERHEAD];
        let mut payload = vec![0u8; DAO_ADMISSION_PAYLOAD_LEN];
        let current = open_redundant(
            storage,
            DAO_ADMISSION_KEYS,
            DAO_ADMISSION_MAGIC,
            &mut a,
            &mut b,
            &mut payload,
        )
        .map_err(map_open_error)?;
        let admitted = decode_admissions(
            &payload[..current.len],
            node_address,
            rpl_instance_id,
            dodag_id,
        )
        .map_err(|error| match error {
            AdmissionDecodeError::ScopeMismatch => DaoPersistentOpenError::ScopeMismatch,
            AdmissionDecodeError::Corrupt => DaoPersistentOpenError::Corrupt,
        })?;
        Ok(Self {
            current,
            node_address,
            rpl_instance_id,
            dodag_id,
            admitted,
        })
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.admitted.contains(key)
    }

    pub fn len(&self) -> usize {
        self.admitted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.admitted.is_empty()
    }

    pub fn admit<S: NonVolatile>(
        &mut self,
        storage: &mut S,
        key: [u8; 32],
    ) -> Result<(), DaoAdmissionUpdateError<S::Error>> {
        if self.admitted.contains(&key) {
            return Ok(());
        }
        if self.admitted.len() == MAX_DAO_ORIGINS {
            return Err(DaoAdmissionUpdateError::Capacity);
        }
        let mut proposed = self.admitted.clone();
        proposed.insert(key);
        let payload = encode_admissions(
            self.node_address,
            self.rpl_instance_id,
            self.dodag_id,
            &proposed,
        )
        .ok_or(DaoAdmissionUpdateError::Corrupt)?;
        let mut record = vec![0u8; DAO_ADMISSION_PAYLOAD_LEN + SLOT_OVERHEAD];
        let current = update_redundant(
            storage,
            DAO_ADMISSION_KEYS,
            DAO_ADMISSION_MAGIC,
            self.current,
            &payload,
            &mut record,
        )
        .map_err(|error| match error {
            RedundantUpdateError::Storage(error) => DaoAdmissionUpdateError::Persistence(error),
            RedundantUpdateError::Stale => DaoAdmissionUpdateError::Stale,
            RedundantUpdateError::Exhausted => DaoAdmissionUpdateError::Exhausted,
            RedundantUpdateError::Corrupt => DaoAdmissionUpdateError::Corrupt,
        })?;
        self.current = current;
        self.admitted = proposed;
        Ok(())
    }
}

#[cfg(feature = "std")]
fn encode_admissions(
    node_address: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    admitted: &HashSet<[u8; 32]>,
) -> Option<Vec<u8>> {
    if admitted.len() > MAX_DAO_ORIGINS {
        return None;
    }
    let mut keys: Vec<_> = admitted.iter().copied().collect();
    keys.sort_unstable();
    let mut payload = vec![0u8; DAO_ADMISSION_HEADER_LEN + keys.len() * 32];
    payload[..16].copy_from_slice(&node_address);
    payload[16] = rpl_instance_id;
    payload[17..33].copy_from_slice(&dodag_id);
    payload[33..35].copy_from_slice(&(keys.len() as u16).to_be_bytes());
    for (index, key) in keys.iter().enumerate() {
        let start = DAO_ADMISSION_HEADER_LEN + index * 32;
        payload[start..start + 32].copy_from_slice(key);
    }
    Some(payload)
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionDecodeError {
    ScopeMismatch,
    Corrupt,
}

#[cfg(feature = "std")]
fn decode_admissions(
    payload: &[u8],
    node_address: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
) -> Result<HashSet<[u8; 32]>, AdmissionDecodeError> {
    if payload.len() < DAO_ADMISSION_HEADER_LEN {
        return Err(AdmissionDecodeError::Corrupt);
    }
    if payload[..16] != node_address
        || payload[16] != rpl_instance_id
        || payload[17..33] != dodag_id
    {
        return Err(AdmissionDecodeError::ScopeMismatch);
    }
    let count = u16::from_be_bytes(
        payload[33..35]
            .try_into()
            .map_err(|_| AdmissionDecodeError::Corrupt)?,
    ) as usize;
    if count > MAX_DAO_ORIGINS || payload.len() != DAO_ADMISSION_HEADER_LEN + count * 32 {
        return Err(AdmissionDecodeError::Corrupt);
    }
    let mut admitted = HashSet::with_capacity(count);
    for index in 0..count {
        let start = DAO_ADMISSION_HEADER_LEN + index * 32;
        let key = payload[start..start + 32]
            .try_into()
            .map_err(|_| AdmissionDecodeError::Corrupt)?;
        if !admitted.insert(key) {
            return Err(AdmissionDecodeError::Corrupt);
        }
    }
    Ok(admitted)
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

#[doc(hidden)]
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaoDiagnosticLimits {
    pub max_targets: usize,
    pub max_candidates_per_target: usize,
    pub max_candidates: usize,
}

#[doc(hidden)]
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoDiagnosticError {
    Rejected,
}

#[doc(hidden)]
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaoDiagnosticDisposition {
    Active,
    Withdrawn,
    Expired,
}

#[doc(hidden)]
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaoDiagnosticCandidate {
    pub parent: [u8; 16],
    pub external: bool,
    pub path_control: u8,
    pub path_lifetime: u8,
    pub installed_at: u64,
    pub expires_at: Option<u64>,
}

#[doc(hidden)]
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaoDiagnosticSelectedCandidate {
    pub parent: [u8; 16],
    pub preference_subfield: u8,
    pub path: Vec<[u8; 16]>,
}

#[doc(hidden)]
#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaoDiagnosticTarget {
    pub prefix_length: u8,
    pub prefix: [u8; 16],
    pub descriptor: Option<u32>,
    pub sequence_authority: [u8; 16],
    pub path_sequence: u8,
    pub disposition: DaoDiagnosticDisposition,
    pub candidates: Vec<DaoDiagnosticCandidate>,
    pub selected_candidate: Option<DaoDiagnosticSelectedCandidate>,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy)]
struct DaoStateLimits {
    max_targets: usize,
    max_candidates_per_target: usize,
    max_candidates: usize,
}

#[cfg(feature = "std")]
impl DaoStateLimits {
    const PRODUCTION: Self = Self {
        max_targets: MAX_PATH_SEQUENCES,
        max_candidates_per_target: MAX_PARENT_EDGES,
        max_candidates: MAX_PARENT_EDGES,
    };
}
/// Maximum target-to-parent edges retained by a root.
#[cfg(feature = "std")]
pub const MAX_PARENT_EDGES: usize = 256;
/// Maximum per-target Path Sequence freshness records.
#[cfg(feature = "std")]
pub const MAX_PATH_SEQUENCES: usize = 256;
/// LICHEN's fixed RPL profile activates all eight Path Control bits (PCS=7).
#[cfg(feature = "std")]
pub const PATH_CONTROL_SIZE: u8 = 7;
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
        if self.addresses.len() > MAX_ROUTE_HOPS
            || usize::from(self.segments_left) > self.addresses.len()
        {
            return Err(RplError::InvalidOption);
        }
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
            return Err(RplError::InvalidOption);
        }
        let addresses: Vec<[u8; 16]> = addr_bytes
            .chunks_exact(16)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        let segments_left = data[1];
        if (segments_left as usize) > addresses.len() {
            return Err(RplError::InvalidOption);
        }
        Ok(Self {
            segments_left,
            addresses,
        })
    }

    pub fn from_route(route: &[[u8; 16]]) -> Result<Self, RplError> {
        let remaining = route.len().checked_sub(1).ok_or(RplError::InvalidOption)?;
        if remaining == 0 || remaining > u8::MAX as usize {
            return Err(RplError::InvalidOption);
        }
        let addresses = route[1..].to_vec();
        Ok(Self {
            segments_left: remaining as u8,
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

/// Canonical IPv6 route prefix.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteTarget {
    prefix: [u8; 16],
    prefix_len: u8,
}

#[cfg(feature = "std")]
impl RouteTarget {
    pub fn new(mut prefix: [u8; 16], prefix_len: u8) -> Option<Self> {
        if prefix_len > 128 {
            return None;
        }
        let whole_bytes = usize::from(prefix_len / 8);
        let remaining_bits = prefix_len % 8;
        let used_bytes = whole_bytes + usize::from(remaining_bits != 0);
        if remaining_bits != 0 {
            prefix[whole_bytes] &= u8::MAX << (8 - remaining_bits);
        }
        prefix[used_bytes..].fill(0);
        Some(Self { prefix, prefix_len })
    }

    pub const fn host(address: [u8; 16]) -> Self {
        Self {
            prefix: address,
            prefix_len: 128,
        }
    }

    pub const fn prefix(&self) -> &[u8; 16] {
        &self.prefix
    }

    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn contains(&self, address: &[u8; 16]) -> bool {
        let whole_bytes = usize::from(self.prefix_len / 8);
        if self.prefix[..whole_bytes] != address[..whole_bytes] {
            return false;
        }
        let remaining_bits = self.prefix_len % 8;
        remaining_bits == 0
            || (self.prefix[whole_bytes] ^ address[whole_bytes]) & (u8::MAX << (8 - remaining_bits))
                == 0
    }
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

/// Root-side map from route target to an ordered root-to-egress hop list.
///
/// Host routes use `/128` targets and keep the existing `[h1, ..., target]`
/// path shape. Prefix routes store a path to their egress, never to the
/// canonical prefix address.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct RoutingTable {
    routes: HashMap<RouteTarget, RouteEntry>,
    prefix_route_count: usize,
    rpl_managed_hosts: HashSet<[u8; 16]>,
    rpl_managed_prefixes: HashMap<RouteTarget, [u8; 16]>,
    unavailable_managed_prefixes: HashSet<RouteTarget>,
}

#[cfg(feature = "std")]
impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a route, returning `false` if a new entry would exceed capacity.
    pub fn add_route(&mut self, target: [u8; 16], path: &[[u8; 16]]) -> bool {
        self.add_target_route(RouteTarget::host(target), path)
    }

    /// Add a non-host prefix route to its egress path.
    pub fn add_prefix_route(
        &mut self,
        target: RouteTarget,
        egress: [u8; 16],
        path: &[[u8; 16]],
    ) -> bool {
        if target.prefix_len == 128
            || path.last() != Some(&egress)
            || path.iter().any(|hop| hop == target.prefix())
        {
            return false;
        }
        let was_managed = self.rpl_managed_prefixes.get(&target) == Some(&egress);
        let is_managed = was_managed || self.rpl_managed_hosts.contains(&egress);
        if !self.add_target_route(target, path) {
            return false;
        }
        if is_managed {
            self.rpl_managed_prefixes.insert(target, egress);
        } else {
            self.rpl_managed_prefixes.remove(&target);
        }
        self.unavailable_managed_prefixes.remove(&target);
        true
    }

    fn add_target_route(&mut self, target: RouteTarget, path: &[[u8; 16]]) -> bool {
        if path.len() > MAX_ROUTE_HOPS {
            return false;
        }
        let is_new = !self.routes.contains_key(&target);
        if is_new && self.routes.len() == MAX_ROUTES {
            return false;
        }
        match self.routes.get_mut(&target) {
            Some(entry) if entry.state != RouteEntryState::Expired => {
                let r = entry.refresh(path);
                debug_assert!(r.is_ok(), "fresh or stale route entry can refresh");
            }
            _ => {
                self.routes.insert(target, RouteEntry::fresh(path));
            }
        }
        if is_new && target.prefix_len < 128 {
            self.prefix_route_count += 1;
        }
        true
    }

    pub fn remove_route(&mut self, target: &[u8; 16]) {
        self.routes.remove(&RouteTarget::host(*target));
    }

    pub fn remove_prefix_route(&mut self, target: RouteTarget) {
        if target.prefix_len < 128 && self.routes.remove(&target).is_some() {
            self.prefix_route_count -= 1;
            self.rpl_managed_prefixes.remove(&target);
            self.unavailable_managed_prefixes.remove(&target);
        }
    }

    pub fn mark_stale(
        &mut self,
        target: &[u8; 16],
    ) -> Option<Result<(), InvalidRouteEntryTransition>> {
        self.routes
            .get_mut(&RouteTarget::host(*target))
            .map(RouteEntry::mark_stale)
    }

    pub fn mark_expired(
        &mut self,
        target: &[u8; 16],
    ) -> Option<Result<(), InvalidRouteEntryTransition>> {
        self.routes
            .get_mut(&RouteTarget::host(*target))
            .map(RouteEntry::mark_expired)
    }

    pub fn entry_state(&self, target: &[u8; 16]) -> Option<RouteEntryState> {
        self.routes
            .get(&RouteTarget::host(*target))
            .map(|entry| entry.state)
    }

    pub fn mark_prefix_expired(
        &mut self,
        target: RouteTarget,
    ) -> Option<Result<(), InvalidRouteEntryTransition>> {
        (target.prefix_len < 128)
            .then(|| self.routes.get_mut(&target).map(RouteEntry::mark_expired))
            .flatten()
    }

    /// Return the longest-prefix path for `target`, or `None` if no route is known.
    pub fn lookup(&self, target: &[u8; 16]) -> Option<&[[u8; 16]]> {
        if self.prefix_route_count == 0 {
            return self
                .routes
                .get(&RouteTarget::host(*target))
                .filter(|entry| entry.is_usable())
                .map(|entry| entry.path.as_slice());
        }
        self.routes
            .iter()
            .filter(|(route_target, entry)| route_target.contains(target) && entry.is_usable())
            .max_by_key(|(route_target, _)| route_target.prefix_len)
            .map(|(_, entry)| entry.path.as_slice())
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
    parent_map: HashMap<[u8; 16], [u8; 16]>,
    dao_seq_map: HashMap<[u8; 16], u8>,
    last_dao_ts: u32,
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
            last_built_dao: None,
            parent_map: HashMap::new(),
            dao_seq_map: HashMap::new(),
            last_dao_ts: 0,
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
            last_built_dao: self.last_built_dao,
            parent_map: self.parent_map.clone(),
            edge_expiry: self.edge_expiry.clone(),
            origin_seq_map: self.origin_seq_map.clone(),
            path_seq_map: self.path_seq_map.clone(),
            candidate_map: self.candidate_map.clone(),
            descriptor_map: self.descriptor_map.clone(),
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
        let mut payload = [0u8; HIGH_WATER_HEADER_LEN];
        encode_high_water(
            node_address,
            rpl_instance_id,
            dodag_id,
            &HashMap::new(),
            &mut payload,
        )
        .expect("empty scoped replay state fits fixed header");
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
        let persisted = &payload[..current.len];
        if persisted.len() < HIGH_WATER_HEADER_LEN {
            return Err(DaoPersistentOpenError::Corrupt);
        }
        if persisted[..16] != node_address
            || persisted[16] != rpl_instance_id
            || persisted[17..HIGH_WATER_SCOPE_LEN] != dodag_id
        {
            return Err(DaoPersistentOpenError::ScopeMismatch);
        }
        let origin_high_water =
            decode_high_water(persisted).ok_or(DaoPersistentOpenError::Corrupt)?;
        let mut manager = Self::as_root(node_address, rpl_instance_id, dodag_id);
        manager.origin_high_water = origin_high_water;
        Ok((manager, DaoRxState { current }))
    }

    /// Process a verified DAO received from an authenticated immediate sender.
    /// Sender-to-target authorization (per IPv6/IID identity rules) precedes replay and any route mutation.
    pub fn process_signature_verified<S: NonVolatile>(
        &mut self,
        verified: &SignatureVerifiedDao<'_>,
        authenticated_sender_iid: [u8; 8],
        rx_state: &mut DaoRxState,
        storage: &mut S,
        timing: DaoProcessTiming,
    ) -> Result<DaoProcessOutcome, DaoProcessError<S::Error>> {
        self.process_signature_verified_inner(
            verified,
            authenticated_sender_iid,
            rx_state,
            storage,
            timing,
            true,
        )
    }

    /// Process a signature-verified DAO while retaining RFC lollipop freshness.
    ///
    /// This stricter component mode is for compatibility paths that do not treat
    /// the authenticated 64-bit origin sequence as route/path freshness authority.
    pub fn process_signature_verified_with_lollipop<S: NonVolatile>(
        &mut self,
        verified: &SignatureVerifiedDao<'_>,
        authenticated_sender_iid: [u8; 8],
        rx_state: &mut DaoRxState,
        storage: &mut S,
        timing: DaoProcessTiming,
    ) -> Result<DaoProcessOutcome, DaoProcessError<S::Error>> {
        self.process_signature_verified_inner(
            verified,
            authenticated_sender_iid,
            rx_state,
            storage,
            timing,
            false,
        )
    }

    fn process_signature_verified_inner<S: NonVolatile>(
        &mut self,
        verified: &SignatureVerifiedDao<'_>,
        authenticated_sender_iid: [u8; 8],
        rx_state: &mut DaoRxState,
        storage: &mut S,
        timing: DaoProcessTiming,
        skip_dao_sequence_check: bool,
    ) -> Result<DaoProcessOutcome, DaoProcessError<S::Error>> {
        let sequence = verified.envelope.origin.origin_sequence;

        let dao = verified.envelope.dao.clone();
        if !Self::has_exact_origin_target(&dao, verified.envelope.unsigned_bytes, verified.origin) {
            return Err(DaoProcessError::RouteRejected);
        }
        let Some((updates, update_count)) =
            self.extract_updates(&dao, verified.envelope.unsigned_bytes)
        else {
            return Err(DaoProcessError::RouteRejected);
        };
        if !Self::sender_is_authorized(
            &updates,
            update_count,
            verified.origin,
            self.node_address,
            authenticated_sender_iid,
        ) {
            return Err(DaoProcessError::RouteRejected);
        }

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
        if duplicate
            && updates[..update_count]
                .iter()
                .flatten()
                .any(|update| self.path_seq_map.contains_key(&update.target))
        {
            return Ok(DaoProcessOutcome::Duplicate);
        }
        let mut proposed = self.staged();
        if proposed
            .process_dao_inner(
                dao,
                updates,
                update_count,
                verified.origin,
                skip_dao_sequence_check,
                DaoTiming {
                    now_seconds: timing.now_seconds,
                    lifetime_unit_seconds: timing.lifetime_unit_seconds,
                    max_deadline_seconds: timing.max_deadline_seconds,
                },
                DaoStateLimits::PRODUCTION,
            )
            .is_err()
        {
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
        let len = encode_high_water(
            self.node_address,
            self.rpl_instance_id,
            self.dodag_id,
            &proposed.origin_high_water,
            &mut payload,
        )
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

    fn sender_is_authorized(
        updates: &[Option<DaoUpdate>; MAX_DAO_UPDATES],
        update_count: usize,
        origin: [u8; 16],
        root: [u8; 16],
        sender_iid: [u8; 8],
    ) -> bool {
        let link_local_origin = origin[0] == 0xfe && origin[1] & 0xc0 == 0x80;
        if link_local_origin && origin[8..] != sender_iid {
            return false;
        }
        let mut found_origin = false;
        for update in updates[..update_count].iter().flatten() {
            if update.target != origin {
                continue;
            }
            found_origin = true;
            if link_local_origin && update.parent != root {
                return false;
            }
            if update.parent[8..] == root[8..] && origin[8..] != sender_iid {
                return false;
            }
        }
        found_origin
    }

    fn has_exact_origin_target(dao: &Dao, dao_bytes: &[u8], origin: [u8; 16]) -> bool {
        let mut target = None;
        for option in OptionIter::new(dao.options_tail(dao_bytes)) {
            let Ok(option) = option else {
                return false;
            };
            if option.opt_type == OPT_RPL_TARGET {
                if target.is_some() {
                    return false;
                }
                let Ok(parsed) = RplTarget::from_bytes(option.data) else {
                    return false;
                };
                target = Some(parsed);
            }
        }
        target.is_some_and(|target| target.prefix_len == 128 && target.prefix == origin)
    }

    pub fn routing_table(&self) -> &RoutingTable {
        &self.routing_table
    }

    #[doc(hidden)]
    pub fn diagnostic_root(
        node_address: [u8; 16],
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
    ) -> Self {
        Self::as_root(node_address, rpl_instance_id, dodag_id)
    }

    #[doc(hidden)]
    pub fn process_route_state_diagnostic(
        &mut self,
        dao_bytes: &[u8],
        sequence_authority: [u8; 16],
        timing: DaoProcessTiming,
        limits: DaoDiagnosticLimits,
    ) -> Result<bool, DaoDiagnosticError> {
        if limits.max_targets == 0
            || limits.max_candidates_per_target == 0
            || limits.max_candidates == 0
        {
            return Err(DaoDiagnosticError::Rejected);
        }
        let dao = Dao::from_bytes(dao_bytes).map_err(|_| DaoDiagnosticError::Rejected)?;
        let (updates, update_count) = self
            .extract_updates(&dao, dao_bytes)
            .ok_or(DaoDiagnosticError::Rejected)?;
        self.process_dao_inner(
            dao,
            updates,
            update_count,
            sequence_authority,
            true,
            DaoTiming {
                now_seconds: timing.now_seconds,
                lifetime_unit_seconds: timing.lifetime_unit_seconds,
                max_deadline_seconds: timing.max_deadline_seconds,
            },
            DaoStateLimits {
                max_targets: limits.max_targets,
                max_candidates_per_target: limits.max_candidates_per_target,
                max_candidates: limits.max_candidates,
            },
        )
        .map_err(|()| DaoDiagnosticError::Rejected)
    }

    #[doc(hidden)]
    pub fn route_state_diagnostic(
        &self,
        sequence_authority: [u8; 16],
        lifetime_unit_seconds: u64,
    ) -> Vec<DaoDiagnosticTarget> {
        let mut targets: Vec<_> = self
            .path_seq_map
            .iter()
            .filter_map(|(target, freshness)| {
                let candidates = self.candidate_map.get(target)?;
                let disposition = if self.parent_map.contains_key(target) {
                    DaoDiagnosticDisposition::Active
                } else if candidates
                    .first()
                    .is_some_and(|candidate| candidate.path_lifetime == 0)
                {
                    DaoDiagnosticDisposition::Withdrawn
                } else {
                    DaoDiagnosticDisposition::Expired
                };
                let candidates = candidates
                    .iter()
                    .map(|candidate| {
                        let expires_at = match candidate.path_lifetime {
                            0 | 255 => None,
                            lifetime => freshness.updated_at.checked_add(
                                u64::from(lifetime).checked_mul(lifetime_unit_seconds)?,
                            ),
                        };
                        Some(DaoDiagnosticCandidate {
                            parent: candidate.parent,
                            external: false,
                            path_control: candidate.path_control,
                            path_lifetime: candidate.path_lifetime,
                            installed_at: freshness.updated_at,
                            expires_at,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?;
                let selected_candidate = if disposition == DaoDiagnosticDisposition::Active {
                    self.routing_table.lookup(target).and_then(|path| {
                        let parent = if path.len() == 1 {
                            self.node_address
                        } else {
                            path[path.len() - 2]
                        };
                        let candidate = self
                            .candidate_map
                            .get(target)?
                            .iter()
                            .find(|candidate| candidate.parent == parent)?;
                        Some(DaoDiagnosticSelectedCandidate {
                            parent,
                            preference_subfield: Self::path_control_rank(candidate.path_control)?
                                + 1,
                            path: path.to_vec(),
                        })
                    })
                } else {
                    None
                };
                Some(DaoDiagnosticTarget {
                    prefix_length: 128,
                    prefix: *target,
                    descriptor: self.descriptor_map.get(target).copied().flatten(),
                    sequence_authority,
                    path_sequence: freshness.sequence,
                    disposition,
                    candidates,
                    selected_candidate,
                })
            })
            .collect();
        targets.sort_unstable_by_key(|target| target.prefix);
        targets
    }

    /// Build a DAO advertising this node with `parent_addr` as transit.
    ///
    /// Returns the encoded bytes: DAO base + RPL Target option + Transit Info option.
    pub fn build_dao(&mut self, parent_addr: [u8; 16]) -> Vec<u8> {
        self.build_dao_with_lifetime(parent_addr, 255)
    }

    /// Build a DAO with an explicit Path Lifetime; zero creates a No-Path DAO.
    pub fn build_dao_with_lifetime(&mut self, parent_addr: [u8; 16], path_lifetime: u8) -> Vec<u8> {
        self.dao_sequence = increment_lollipop(self.dao_sequence);
        self.path_sequence = increment_lollipop(self.path_sequence);
        let wire = self.build_dao_inner(parent_addr, path_lifetime);
        self.last_built_dao = Some((parent_addr, path_lifetime));
        wire
    }

    /// Build another copy of the current logical path update without advancing its
    /// Path Sequence. The DAOSequence still advances so root replay checks remain valid.
    pub fn build_dao_copy_with_lifetime(
        &mut self,
        parent_addr: [u8; 16],
        path_lifetime: u8,
    ) -> Option<Vec<u8>> {
        if self.last_built_dao != Some((parent_addr, path_lifetime)) {
            return None;
        }
        self.dao_sequence = increment_lollipop(self.dao_sequence);
        Some(self.build_dao_inner(parent_addr, path_lifetime))
    }

    fn build_dao_inner(&self, parent_addr: [u8; 16], path_lifetime: u8) -> Vec<u8> {
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
            path_control: 0x80,
            path_sequence: self.path_sequence,
            path_lifetime,
            parent_address: parent_addr,
        };
        pos += transit
            .write_to(&mut buf[pos..])
            .expect("TransitInfo option (22 bytes) fits in remaining buffer");

        buf[..pos].to_vec()
    }

    /// Process a received DAO on the root. Returns `true` if route state changed.
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
            false,
            DaoTiming {
                now_seconds: 0,
                lifetime_unit_seconds: DEFAULT_LIFETIME_UNIT_SECONDS,
                max_deadline_seconds: u64::MAX,
            },
            DaoStateLimits::PRODUCTION,
        )
        .unwrap_or(false)
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
            false,
            DaoTiming {
                now_seconds,
                lifetime_unit_seconds,
                max_deadline_seconds: u64::MAX,
            },
            DaoStateLimits::PRODUCTION,
        )
        .unwrap_or(false)
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

    #[allow(
        clippy::too_many_arguments,
        reason = "transactional DAO inputs keep parsed updates, authority, timing, and limits explicit"
    )]
    fn process_dao_inner(
        &mut self,
        dao: Dao,
        updates: [Option<DaoUpdate>; MAX_DAO_UPDATES],
        update_count: usize,
        origin: [u8; 16],
        skip_dao_sequence_check: bool,
        timing: DaoTiming,
        limits: DaoStateLimits,
    ) -> Result<bool, ()> {
        let DaoTiming {
            now_seconds,
            lifetime_unit_seconds,
            max_deadline_seconds,
        } = timing;
        if !self.is_root {
            return Err(());
        }
        if dao.rpl_instance_id != self.rpl_instance_id
            || dao
                .dodag_id
                .is_some_and(|dodag_id| dodag_id != self.dodag_id)
        {
            return Err(());
        }
        if !skip_dao_sequence_check
            && self
                .origin_seq_map
                .get(&origin)
                .is_some_and(|last| !seq_is_newer(dao.dao_sequence, last.sequence))
        {
            return Err(());
        }

        // All cloned state is bounded by the public limits above. Build and validate
        // the complete proposal so grouped updates and cycle rejection stay atomic.
        let mut proposed_parents = self.parent_map.clone();
        let mut proposed_expiry = self.edge_expiry.clone();
        let mut proposed_path_sequences = self.path_seq_map.clone();
        let mut proposed_origin_sequences = self.origin_seq_map.clone();
        let mut proposed_candidates = self.candidate_map.clone();
        let mut proposed_descriptors = self.descriptor_map.clone();
        proposed_expiry.retain(|_, deadline| Self::is_active(*deadline, now_seconds));
        proposed_parents.retain(|target, parents| {
            parents.retain(|parent| proposed_expiry.contains_key(&(*target, *parent)));
            !parents.is_empty()
        });

        let mut incoming_candidates: HashMap<[u8; 16], Vec<DaoCandidate>> = HashMap::new();
        let mut incoming_descriptors = HashMap::new();
        for update in updates[..update_count].iter().flatten() {
            if incoming_descriptors
                .insert(update.target, update.descriptor)
                .is_some_and(|descriptor| descriptor != update.descriptor)
            {
                return Err(());
            }
            incoming_candidates
                .entry(update.target)
                .or_default()
                .push(DaoCandidate {
                    parent: update.parent,
                    path_control: update.path_control,
                    path_lifetime: update.path_lifetime,
                });
        }
        for candidates in incoming_candidates.values_mut() {
            candidates.sort_unstable();
            candidates.dedup();
        }
        if incoming_candidates
            .values()
            .flatten()
            .any(|candidate| Self::path_control_rank(candidate.path_control).is_none())
        {
            return Err(());
        }
        if lifetime_unit_seconds == 0
            && updates[..update_count]
                .iter()
                .flatten()
                .any(|update| update.path_lifetime != 255)
        {
            return Err(());
        }

        let incoming_targets: HashSet<[u8; 16]> = incoming_candidates.keys().copied().collect();
        let mut changed_targets = HashSet::new();
        for (target, candidates) in &incoming_candidates {
            let sequence = updates[..update_count]
                .iter()
                .flatten()
                .find(|update| update.target == *target)
                .expect("candidate target has an update")
                .path_sequence;
            if let Some(last) = proposed_path_sequences.get(target) {
                if sequence == last.sequence {
                    if proposed_candidates.get(target) != Some(candidates)
                        || proposed_descriptors.get(target).copied().flatten()
                            != incoming_descriptors[target]
                    {
                        return Err(());
                    }
                    continue;
                }
                if !seq_is_newer(sequence, last.sequence) {
                    return Err(());
                }
                if let Some(parents) = proposed_parents.remove(target) {
                    for parent in parents {
                        proposed_expiry.remove(&(*target, parent));
                    }
                }
            }
            proposed_candidates.insert(*target, candidates.clone());
            proposed_descriptors.insert(*target, incoming_descriptors[target]);
            changed_targets.insert(*target);
        }
        for update in updates[..update_count].iter().flatten() {
            if !changed_targets.contains(&update.target) {
                continue;
            }
            let expires_at = if matches!(update.path_lifetime, 0 | 255) {
                None
            } else {
                let lifetime = u64::from(update.path_lifetime.max(1));
                let Some(deadline) = lifetime
                    .checked_mul(lifetime_unit_seconds)
                    .and_then(|duration| now_seconds.checked_add(duration))
                else {
                    return Err(());
                };
                if deadline > max_deadline_seconds {
                    return Err(());
                }
                Some(deadline)
            };
            if update.path_lifetime != 0 {
                let parents = proposed_parents.entry(update.target).or_default();
                if !parents.contains(&update.parent) {
                    parents.push(update.parent);
                    parents.sort_unstable();
                }
                proposed_expiry.insert((update.target, update.parent), expires_at);
            }
        }
        for target in &changed_targets {
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
                    limits.max_targets,
                    now_seconds,
                    &incoming_targets,
                )
            {
                return Err(());
            }
            proposed_path_sequences
                .insert(*target, Freshness::new(sequence, active_until, now_seconds));
        }
        proposed_candidates.retain(|target, _| proposed_path_sequences.contains_key(target));
        proposed_descriptors.retain(|target, _| proposed_path_sequences.contains_key(target));
        if !proposed_origin_sequences.contains_key(&origin)
            && !Self::make_freshness_room(
                &mut proposed_origin_sequences,
                MAX_DAO_ORIGINS,
                now_seconds,
                &HashSet::new(),
            )
        {
            return Err(());
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
        if proposed_expiry.len() > limits.max_candidates
            || proposed_candidates
                .values()
                .any(|candidates| candidates.len() > limits.max_candidates_per_target)
            || proposed_path_sequences.len() > limits.max_targets
            || proposed_origin_sequences.len() > MAX_DAO_ORIGINS
        {
            return Err(());
        }
        if Self::contains_cycle(&proposed_parents) {
            return Err(());
        }

        let Some(proposed_routes) = Self::rebuilt_routes(
            self.node_address,
            &proposed_parents,
            &proposed_candidates,
            &self.routing_table,
            &changed_targets,
        ) else {
            return Err(());
        };
        let route_state_changed = !changed_targets.is_empty()
            || proposed_parents != self.parent_map
            || proposed_expiry != self.edge_expiry
            || proposed_routes.routes != self.routing_table.routes;
        self.parent_map = proposed_parents;
        self.edge_expiry = proposed_expiry;
        self.path_seq_map = proposed_path_sequences;
        self.origin_seq_map = proposed_origin_sequences;
        self.candidate_map = proposed_candidates;
        self.descriptor_map = proposed_descriptors;
        self.routing_table = proposed_routes;
        Ok(route_state_changed)
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
        let Some(routes) = Self::rebuilt_routes(
            self.node_address,
            &parent_map,
            &self.candidate_map,
            &self.routing_table,
            &HashSet::new(),
        ) else {
            return false;
        };
        let route_state_changed = edge_expiry != self.edge_expiry
            || parent_map != self.parent_map
            || routes.routes != self.routing_table.routes;
        self.edge_expiry = edge_expiry;
        self.parent_map = parent_map;
        self.routing_table = routes;
        route_state_changed
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
        protected: &HashSet<[u8; 16]>,
    ) -> bool {
        if map.len() < limit {
            return true;
        }
        let candidate = map
            .iter()
            .filter(|(target, freshness)| {
                !protected.contains(*target) && freshness.is_reclaimable(now_seconds)
            })
            .min_by_key(|(key, freshness)| (freshness.updated_at, **key))
            .map(|(key, _)| *key);
        candidate.is_some_and(|key| map.remove(&key).is_some())
    }

    fn extract_updates(
        &self,
        dao: &Dao,
        dao_bytes: &[u8],
    ) -> Option<([Option<DaoUpdate>; MAX_DAO_UPDATES], usize)> {
        if dao.flags != 0 || dao_bytes.get(2).copied()? != 0 {
            return None;
        }
        let options = dao.options_tail(dao_bytes);
        let mut updates = [None; MAX_DAO_UPDATES];
        let mut update_count = 0;
        let mut targets = [None; MAX_DAO_UPDATES];
        let mut descriptors = [None; MAX_DAO_UPDATES];
        let mut target_count = 0;
        let mut transits = core::array::from_fn(|_| None);
        let mut transit_count = 0;
        let mut descriptor_allowed = false;
        for opt in OptionIter::new(options) {
            let opt = opt.ok()?;
            match opt.opt_type {
                OPT_RPL_TARGET => {
                    if transit_count != 0 {
                        Self::finish_group(
                            &mut updates,
                            &mut update_count,
                            &targets,
                            &descriptors,
                            target_count,
                            &transits,
                            transit_count,
                        )?;
                        targets = [None; MAX_DAO_UPDATES];
                        descriptors = [None; MAX_DAO_UPDATES];
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
                    descriptor_allowed = true;
                }
                OPT_RPL_TARGET_DESCRIPTOR => {
                    if !descriptor_allowed || opt.data.len() != 4 {
                        return None;
                    }
                    descriptors[target_count - 1] = Some(u32::from_be_bytes(
                        opt.data.try_into().expect("descriptor length checked"),
                    ));
                    descriptor_allowed = false;
                }
                OPT_TRANSIT_INFO => {
                    descriptor_allowed = false;
                    if target_count == 0 {
                        return None;
                    }
                    // Current /128 profile has no external-prefix egress semantics.
                    if opt.data.first().copied()? != 0 {
                        return None;
                    }
                    let parsed = TransitInfo::from_bytes(opt.data).ok()?;
                    if transits[..transit_count].iter().flatten().any(|first| {
                        first.path_sequence != parsed.path_sequence
                            || first.path_lifetime != parsed.path_lifetime
                    }) {
                        return None;
                    }
                    if let Some(existing) = transits[..transit_count]
                        .iter()
                        .flatten()
                        .find(|transit| transit.parent_address == parsed.parent_address)
                    {
                        if existing != &parsed {
                            return None;
                        }
                    } else {
                        if transit_count == MAX_DAO_UPDATES {
                            return None;
                        }
                        transits[transit_count] = Some(parsed);
                        transit_count += 1;
                    }
                }
                _ => return None,
            }
        }
        Self::finish_group(
            &mut updates,
            &mut update_count,
            &targets,
            &descriptors,
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
        descriptors: &[Option<u32>; MAX_DAO_UPDATES],
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
        for (target_index, target) in targets[..target_count].iter().enumerate() {
            let target = target.as_ref()?;
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
                    path_control: transit.path_control,
                    path_sequence: transit.path_sequence,
                    path_lifetime: transit.path_lifetime,
                    descriptor: descriptors[target_index],
                });
                *update_count += 1;
            }
        }
        self.last_dao_ts = self.last_dao_ts.wrapping_add(1);
    }

    /// Walk target → parent → … → root and return the reversed downward path.
    ///
    /// Returns `None` if the chain is incomplete or contains a loop.
    #[cfg(test)]
    fn assemble_path(
        root: [u8; 16],
        parent_map: &HashMap<[u8; 16], Vec<[u8; 16]>>,
        candidate_map: &HashMap<[u8; 16], Vec<DaoCandidate>>,
        target: [u8; 16],
    ) -> Option<Vec<[u8; 16]>> {
        Self::assemble_path_checked(root, parent_map, candidate_map, target)
            .ok()
            .flatten()
    }

    fn assemble_path_checked(
        root: [u8; 16],
        parent_map: &HashMap<[u8; 16], Vec<[u8; 16]>>,
        candidate_map: &HashMap<[u8; 16], Vec<DaoCandidate>>,
        target: [u8; 16],
    ) -> Result<Option<Vec<[u8; 16]>>, ()> {
        let mut chain: Vec<[u8; 16]> = Vec::new();
        let mut visited: HashSet<[u8; 16]> = HashSet::new();
        if !Self::assemble_path_from(
            root,
            parent_map,
            candidate_map,
            target,
            &mut chain,
            &mut visited,
        )? {
            return Ok(None);
        }
        chain.reverse();
        Ok(Some(chain))
    }

    fn assemble_path_from(
        root: [u8; 16],
        parent_map: &HashMap<[u8; 16], Vec<[u8; 16]>>,
        candidate_map: &HashMap<[u8; 16], Vec<DaoCandidate>>,
        node: [u8; 16],
        chain: &mut Vec<[u8; 16]>,
        visited: &mut HashSet<[u8; 16]>,
    ) -> Result<bool, ()> {
        if node == root {
            return Ok(true);
        }
        if chain.len() == MAX_ROUTE_HOPS {
            return Err(());
        }
        if !visited.insert(node) {
            return Ok(false);
        }
        chain.push(node);

        let Some(active_parents) = parent_map.get(&node) else {
            return Ok(false);
        };
        let Some(candidates) = candidate_map.get(&node) else {
            return Ok(false);
        };
        let mut choices = Vec::new();
        let mut exceeded_limit = false;
        for candidate in candidates {
            if !active_parents.contains(&candidate.parent) {
                continue;
            }
            let Some(rank) = Self::path_control_rank(candidate.path_control) else {
                continue;
            };
            let mut parent_chain = chain.clone();
            let mut parent_visited = visited.clone();
            match Self::assemble_path_from(
                root,
                parent_map,
                candidate_map,
                candidate.parent,
                &mut parent_chain,
                &mut parent_visited,
            ) {
                Ok(true) => {
                    parent_chain.reverse();
                    choices.push((rank, parent_chain));
                }
                Ok(false) => {}
                Err(()) => exceeded_limit = true,
            }
        }
        if exceeded_limit {
            return Err(());
        }
        let Some((_, mut selected)) = choices
            .into_iter()
            .min_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)))
        else {
            return Ok(false);
        };
        selected.reverse();
        *chain = selected;
        Ok(true)
    }

    fn path_control_rank(path_control: u8) -> Option<u8> {
        let active_mask = u8::MAX << (7 - PATH_CONTROL_SIZE);
        let masked = path_control & active_mask;
        [6, 4, 2, 0]
            .into_iter()
            .position(|shift| masked & (0x03 << shift) != 0)
            .map(|rank| rank as u8)
    }
}

#[cfg(feature = "std")]
fn encode_high_water(
    node_address: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    map: &HighWaterMap,
    out: &mut [u8],
) -> Option<usize> {
    if map.len() > MAX_DAO_ORIGINS {
        return None;
    }
    let len = HIGH_WATER_HEADER_LEN + map.len() * HIGH_WATER_ENTRY_LEN;
    if out.len() < len {
        return None;
    }
    out[..16].copy_from_slice(&node_address);
    out[16] = rpl_instance_id;
    out[17..HIGH_WATER_SCOPE_LEN].copy_from_slice(&dodag_id);
    out[HIGH_WATER_SCOPE_LEN..HIGH_WATER_HEADER_LEN]
        .copy_from_slice(&(map.len() as u16).to_be_bytes());
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_unstable_by_key(|(key, _)| **key);
    for (index, (key, (hash, sequence))) in entries.into_iter().enumerate() {
        let offset = HIGH_WATER_HEADER_LEN + index * HIGH_WATER_ENTRY_LEN;
        out[offset..offset + 32].copy_from_slice(key);
        out[offset + 32..offset + 40].copy_from_slice(&sequence.to_be_bytes());
        out[offset + 40..offset + 72].copy_from_slice(hash);
    }
    Some(len)
}

#[cfg(feature = "std")]
fn decode_high_water(data: &[u8]) -> Option<HighWaterMap> {
    if data.len() < HIGH_WATER_HEADER_LEN {
        return None;
    }
    let count = u16::from_be_bytes(
        data[HIGH_WATER_SCOPE_LEN..HIGH_WATER_HEADER_LEN]
            .try_into()
            .ok()?,
    ) as usize;
    if count > MAX_DAO_ORIGINS || data.len() != HIGH_WATER_HEADER_LEN + count * HIGH_WATER_ENTRY_LEN
    {
        return None;
    }
    let mut map = HashMap::with_capacity(count);
    for index in 0..count {
        let offset = HIGH_WATER_HEADER_LEN + index * HIGH_WATER_ENTRY_LEN;
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

    fn tx_provision(storage: &mut MemStorage, key: PublicKey) -> DaoTxState {
        DaoTxState::provision(storage, key, ll(2), 0, dodag_id()).unwrap()
    }

    fn tx_open(
        storage: &MemStorage,
        key: PublicKey,
    ) -> Result<DaoTxState, DaoPersistentOpenError<lichen_hal::storage::mem::MemStorageError>> {
        DaoTxState::open(storage, key, ll(2), 0, dodag_id())
    }

    fn addr(value: u16) -> [u8; 16] {
        let mut address = ll(0);
        address[14..].copy_from_slice(&value.to_be_bytes());
        address
    }

    fn candidates_for(
        parents: &HashMap<[u8; 16], Vec<[u8; 16]>>,
    ) -> HashMap<[u8; 16], Vec<DaoCandidate>> {
        parents
            .iter()
            .map(|(target, parents)| {
                (
                    *target,
                    parents
                        .iter()
                        .map(|parent| DaoCandidate {
                            parent: *parent,
                            path_control: 0x80,
                            path_lifetime: 255,
                        })
                        .collect(),
                )
            })
            .collect()
    }

    fn assert_freshness_maps_equal(
        actual: &HashMap<[u8; 16], Freshness>,
        expected: &HashMap<[u8; 16], Freshness>,
    ) {
        assert_eq!(actual.len(), expected.len());
        for (target, expected) in expected {
            let actual = actual.get(target).unwrap();
            assert_eq!(actual.sequence, expected.sequence);
            assert_eq!(actual.active_until, expected.active_until);
            assert_eq!(actual.retain_until, expected.retain_until);
            assert_eq!(actual.updated_at, expected.updated_at);
        }
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

    fn verified_dao_with_path_sequence(
        identity: &Identity,
        sequence: u64,
        path_sequence: u8,
        parent: [u8; 16],
    ) -> (Vec<u8>, [u8; 16]) {
        let (wire, origin) = verified_dao(identity, sequence, parent);
        let mut unsigned = SignedDaoEnvelope::from_bytes(&wire)
            .unwrap()
            .unsigned_bytes
            .to_vec();
        unsigned[44] = path_sequence;
        let digest = dao_origin_digest(origin, dodag_id(), sequence, &unsigned);
        let signature = LinkLayer::new(identity.clone()).sign_digest(&digest);
        let offset = unsigned.len();
        unsigned.resize(offset + crate::message::DAO_ORIGIN_SIGNATURE_LEN, 0);
        crate::message::DaoOriginSignature::write_to(sequence, &signature, &mut unsigned[offset..])
            .unwrap();
        (unsigned, origin)
    }

    fn verified_grouped_dao(
        identity: &Identity,
        origin_sequence: u64,
        dao_sequence: u8,
        path_sequence: u8,
        candidates: &[([u8; 16], u8, u8)],
    ) -> (Vec<u8>, [u8; 16]) {
        let mut origin = dodag_id();
        origin[8..].copy_from_slice(&identity.iid);
        let mut unsigned = vec![0, 0, 0, dao_sequence, OPT_RPL_TARGET, 18, 0, 128];
        unsigned.extend_from_slice(&origin);
        for (parent, path_control, path_lifetime) in candidates {
            unsigned.extend_from_slice(&[
                OPT_TRANSIT_INFO,
                20,
                0,
                *path_control,
                path_sequence,
                *path_lifetime,
            ]);
            unsigned.extend_from_slice(parent);
        }
        let digest = dao_origin_digest(origin, dodag_id(), origin_sequence, &unsigned);
        let signature = LinkLayer::new(identity.clone()).sign_digest(&digest);
        let offset = unsigned.len();
        unsigned.resize(offset + crate::message::DAO_ORIGIN_SIGNATURE_LEN, 0);
        crate::message::DaoOriginSignature::write_to(
            origin_sequence,
            &signature,
            &mut unsigned[offset..],
        )
        .unwrap();
        (unsigned, origin)
    }

    fn process_verified_grouped(
        root: &mut DaoManager,
        state: &mut DaoRxState,
        storage: &mut MemStorage,
        identity: &Identity,
        wire: &[u8],
        origin: [u8; 16],
        now_seconds: u64,
    ) -> Result<DaoProcessOutcome, DaoProcessError<lichen_hal::storage::mem::MemStorageError>> {
        let verified = SignatureVerifiedDao::verify_signature(
            wire,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        root.process_signature_verified(
            &verified,
            identity.iid,
            state,
            storage,
            DaoProcessTiming {
                now_seconds,
                lifetime_unit_seconds: 1,
                max_deadline_seconds: u64::MAX,
            },
        )
    }

    fn sign_unsigned_dao(
        identity: &Identity,
        origin_sequence: u64,
        origin: [u8; 16],
        unsigned: &[u8],
    ) -> Vec<u8> {
        let digest = dao_origin_digest(origin, dodag_id(), origin_sequence, unsigned);
        let signature = LinkLayer::new(identity.clone()).sign_digest(&digest);
        let mut wire = unsigned.to_vec();
        let offset = wire.len();
        wire.resize(offset + crate::message::DAO_ORIGIN_SIGNATURE_LEN, 0);
        crate::message::DaoOriginSignature::write_to(
            origin_sequence,
            &signature,
            &mut wire[offset..],
        )
        .unwrap();
        wire
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
    fn route_target_canonicalizes_prefix() {
        let all = [0xff; 16];
        assert_eq!(RouteTarget::new(all, 0).unwrap().prefix, [0; 16]);

        let mut prefix64 = [0xff; 16];
        prefix64[8..].fill(0);
        assert_eq!(RouteTarget::new(all, 64).unwrap().prefix, prefix64);

        let mut prefix127 = [0xff; 16];
        prefix127[15] = 0xfe;
        assert_eq!(RouteTarget::new(all, 127).unwrap().prefix, prefix127);
        assert_eq!(RouteTarget::new(all, 128), Some(RouteTarget::host(all)));
        assert_eq!(RouteTarget::new(all, 129), None);

        let mut equivalent = [0xff; 16];
        equivalent[8] = 0x80;
        equivalent[9..].fill(0);
        assert_eq!(RouteTarget::new(all, 65), RouteTarget::new(equivalent, 65));
    }

    #[test]
    fn routing_table_uses_longest_prefix_match() {
        let mut table = RoutingTable::new();
        let default = RouteTarget::new([0xff; 16], 0).unwrap();
        let mut network = [0u8; 16];
        network[..8].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 1]);
        let prefix64 = RouteTarget::new(network, 64).unwrap();
        let mut pair = network;
        pair[15] = 2;
        let prefix127 = RouteTarget::new(pair, 127).unwrap();
        let mut host = pair;
        host[15] = 3;

        assert!(!table.add_prefix_route(prefix64, *prefix64.prefix(), &[*prefix64.prefix()]));
        assert!(table.add_prefix_route(default, ll(10), &[ll(10)]));
        assert!(table.add_prefix_route(prefix64, ll(11), &[ll(11)]));
        assert!(table.add_prefix_route(prefix127, ll(12), &[ll(12)]));
        assert!(table.add_route(host, &[ll(13)]));

        assert_eq!(table.lookup(&host), Some([ll(13)].as_slice()));
        assert_eq!(table.lookup(&pair), Some([ll(12)].as_slice()));
        let mut network_host = network;
        network_host[15] = 99;
        assert_eq!(table.lookup(&network_host), Some([ll(11)].as_slice()));
        assert_eq!(table.lookup(&ll(99)), Some([ll(10)].as_slice()));

        table.mark_expired(&host).unwrap().unwrap();
        assert_eq!(table.lookup(&host), Some([ll(12)].as_slice()));
        table.remove_route(&host);
        assert_eq!(table.lookup(&host), Some([ll(12)].as_slice()));
        table.mark_prefix_expired(prefix127).unwrap().unwrap();
        assert_eq!(table.lookup(&host), Some([ll(11)].as_slice()));
        assert_eq!(table.lookup(&network_host), Some([ll(11)].as_slice()));
    }

    #[test]
    fn dao_rebuild_preserves_prefix_routes_and_shared_capacity() {
        let root = ll(1);
        let prefix = RouteTarget::new([0xfd; 16], 64).unwrap();
        let mut table = RoutingTable::new();
        assert!(table.add_prefix_route(prefix, ll(9), &[ll(9)]));

        let mut parents = HashMap::new();
        parents.insert(ll(2), vec![root]);
        let rebuilt = DaoManager::rebuilt_routes(
            root,
            &parents,
            &candidates_for(&parents),
            &table,
            &HashSet::new(),
        )
        .unwrap();
        let mut prefix_destination = [0xfd; 16];
        prefix_destination[8..].fill(1);
        assert_eq!(
            rebuilt.lookup(&prefix_destination),
            Some([ll(9)].as_slice())
        );
        assert_eq!(rebuilt.lookup(&ll(2)), Some([ll(2)].as_slice()));

        let rebuilt = DaoManager::rebuilt_routes(
            root,
            &HashMap::new(),
            &HashMap::new(),
            &rebuilt,
            &HashSet::new(),
        )
        .unwrap();
        assert_eq!(
            rebuilt.lookup(&prefix_destination),
            Some([ll(9)].as_slice())
        );

        let full_parents: HashMap<[u8; 16], Vec<[u8; 16]>> = (0..MAX_ROUTES as u16)
            .map(|value| (addr(value), vec![root]))
            .collect();
        assert!(DaoManager::rebuilt_routes(
            root,
            &full_parents,
            &candidates_for(&full_parents),
            &table,
            &HashSet::new()
        )
        .is_none());
    }

    #[test]
    fn dao_rebuild_reconciles_only_rpl_managed_prefix_egress() {
        let root = ll(1);
        let managed_target = RouteTarget::new([0xfd; 16], 64).unwrap();
        let static_target = RouteTarget::new([0x20; 16], 64).unwrap();
        let managed_egress = ll(2);
        let static_egress = ll(9);
        let mut table = RoutingTable::new();
        assert!(table.add_prefix_route(managed_target, managed_egress, &[managed_egress]));
        assert!(table.add_prefix_route(static_target, static_egress, &[static_egress]));

        let initial_parents = HashMap::from([(managed_egress, vec![root])]);
        table = DaoManager::rebuilt_routes(
            root,
            &initial_parents,
            &candidates_for(&initial_parents),
            &table,
            &HashSet::new(),
        )
        .unwrap();
        assert_eq!(
            table.rpl_managed_prefixes.get(&managed_target),
            Some(&managed_egress)
        );
        assert!(!table.rpl_managed_prefixes.contains_key(&static_target));

        let relay = ll(3);
        let reparented = HashMap::from([(relay, vec![root]), (managed_egress, vec![relay])]);
        table = DaoManager::rebuilt_routes(
            root,
            &reparented,
            &candidates_for(&reparented),
            &table,
            &HashSet::new(),
        )
        .unwrap();
        assert_eq!(
            table.lookup(managed_target.prefix()),
            Some([relay, managed_egress].as_slice())
        );
        assert_eq!(
            table.lookup(static_target.prefix()),
            Some([static_egress].as_slice())
        );

        table = DaoManager::rebuilt_routes(
            root,
            &HashMap::new(),
            &HashMap::new(),
            &table,
            &HashSet::new(),
        )
        .unwrap();
        assert_eq!(table.lookup(managed_target.prefix()), None);
        assert_eq!(
            table.lookup(static_target.prefix()),
            Some([static_egress].as_slice())
        );
        assert_eq!(
            table.routes.get(&managed_target).map(|entry| entry.state),
            Some(RouteEntryState::Expired)
        );

        let returning_relay = ll(4);
        let returned = HashMap::from([
            (returning_relay, vec![root]),
            (managed_egress, vec![returning_relay]),
        ]);
        table = DaoManager::rebuilt_routes(
            root,
            &returned,
            &candidates_for(&returned),
            &table,
            &HashSet::new(),
        )
        .unwrap();
        assert_eq!(
            table.lookup(managed_target.prefix()),
            Some([returning_relay, managed_egress].as_slice())
        );
        assert_eq!(
            table.routes.get(&managed_target).map(|entry| entry.state),
            Some(RouteEntryState::Fresh)
        );
        assert_eq!(
            table.lookup(static_target.prefix()),
            Some([static_egress].as_slice())
        );
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
    fn routing_table_accepts_eight_hops_and_rejects_nine_atomically() {
        let target = ll(10);
        let eight = [ll(2), ll(3), ll(4), ll(5), ll(6), ll(7), ll(8), ll(10)];
        let nine = [
            ll(2),
            ll(3),
            ll(4),
            ll(5),
            ll(6),
            ll(7),
            ll(8),
            ll(9),
            ll(10),
        ];
        let mut table = RoutingTable::new();

        assert!(table.add_route(target, &eight));
        assert!(!table.add_route(target, &nine));
        assert_eq!(table.lookup(&target), Some(eight.as_slice()));
        assert_eq!(table.len(), 1);
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
    fn srh_accepts_eight_hops_and_rejects_nine_or_excess_segments() {
        let eight = [ll(2), ll(3), ll(4), ll(5), ll(6), ll(7), ll(8), ll(9)];
        let nine = [
            ll(2),
            ll(3),
            ll(4),
            ll(5),
            ll(6),
            ll(7),
            ll(8),
            ll(9),
            ll(10),
        ];
        let valid = SourceRoutingHeader {
            segments_left: 8,
            addresses: eight.to_vec(),
        };
        let mut valid_wire = [0u8; 6 + 8 * 16];
        let valid_len = valid.write_to(&mut valid_wire).unwrap();
        assert_eq!(
            SourceRoutingHeader::from_bytes(&valid_wire[..valid_len]),
            Ok(valid)
        );

        let oversized = SourceRoutingHeader {
            segments_left: 9,
            addresses: nine.to_vec(),
        };
        let mut oversized_wire = [0u8; 6 + 9 * 16];
        assert_eq!(
            oversized.write_to(&mut oversized_wire),
            Err(RplError::InvalidOption)
        );
        oversized_wire[0] = 3;
        oversized_wire[1] = 9;
        for (index, address) in nine.iter().enumerate() {
            oversized_wire[6 + index * 16..6 + (index + 1) * 16].copy_from_slice(address);
        }
        assert_eq!(
            SourceRoutingHeader::from_bytes(&oversized_wire),
            Err(RplError::InvalidOption)
        );

        valid_wire[1] = 9;
        assert_eq!(
            SourceRoutingHeader::from_bytes(&valid_wire),
            Err(RplError::InvalidOption)
        );
        let excess_segments = SourceRoutingHeader {
            segments_left: 9,
            addresses: eight.to_vec(),
        };
        assert_eq!(
            excess_segments.write_to(&mut valid_wire),
            Err(RplError::InvalidOption)
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
    fn dao_route_assembly_accepts_eight_hops_and_rejects_nine_atomically() {
        let root_addr = ll(1);
        let nodes = [
            ll(2),
            ll(3),
            ll(4),
            ll(5),
            ll(6),
            ll(7),
            ll(8),
            ll(9),
            ll(10),
        ];
        let eight = [ll(2), ll(3), ll(4), ll(5), ll(6), ll(7), ll(8), ll(9)];
        let mut root = DaoManager::as_root(root_addr, 0, dodag_id());

        for (index, node) in nodes[..8].iter().enumerate() {
            let parent = if index == 0 {
                root_addr
            } else {
                nodes[index - 1]
            };
            let mut sender = DaoManager::new(*node, 0, dodag_id());
            assert!(root.process_dao(&sender.build_dao(parent)));
        }
        assert_eq!(root.routing_table.lookup(&ll(9)), Some(eight.as_slice()));

        let mut ninth = DaoManager::new(ll(10), 0, dodag_id());
        assert!(!root.process_dao(&ninth.build_dao(ll(9))));
        assert_eq!(root.routing_table.lookup(&ll(10)), None);
        assert_eq!(root.routing_table.lookup(&ll(9)), Some(eight.as_slice()));
        assert!(!root.parent_map.contains_key(&ll(10)));
        assert!(!root.path_seq_map.contains_key(&ll(10)));
    }

    #[test]
    fn mixed_valid_and_overlong_candidate_snapshot_is_rejected_atomically() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        for node in 2..=9 {
            let parent = if node == 2 { ll(1) } else { ll(node - 1) };
            assert!(root.process_dao(&global_dao_wire(0, 1, ll(node), parent)));
        }
        let before_parents = root.parent_map.clone();
        let before_expiry = root.edge_expiry.clone();
        let before_paths = root.path_seq_map.clone();
        let before_origins = root.origin_seq_map.clone();
        let before_candidates = root.candidate_map.clone();
        let before_descriptors = root.descriptor_map.clone();
        let before_routes = root.routing_table.routes.clone();

        let mut mixed = global_dao_wire_with_sequences(0, 2, 2, ll(20), ll(1), 255);
        mixed.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0x40, 2, 255]);
        mixed.extend_from_slice(&ll(9));

        assert!(!root.process_dao_at(&mixed, ll(20), 100, 1));
        assert_eq!(root.parent_map, before_parents);
        assert_eq!(root.edge_expiry, before_expiry);
        assert_freshness_maps_equal(&root.path_seq_map, &before_paths);
        assert_freshness_maps_equal(&root.origin_seq_map, &before_origins);
        assert_eq!(root.candidate_map, before_candidates);
        assert_eq!(root.descriptor_map, before_descriptors);
        assert_eq!(root.routing_table.routes, before_routes);
        assert!(!root.parent_map.contains_key(&ll(20)));
        assert!(root.routing_table.lookup(&ll(20)).is_none());
    }

    #[test]
    fn expiry_drops_stale_route_from_mixed_overlong_candidate_state() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        for node in 2..=9 {
            let parent = if node == 2 { ll(1) } else { ll(node - 1) };
            root.parent_map.insert(ll(node), vec![parent]);
            root.edge_expiry.insert((ll(node), parent), Some(10));
        }
        root.parent_map.insert(ll(20), vec![ll(1), ll(9)]);
        root.edge_expiry.insert((ll(20), ll(1)), Some(10));
        root.edge_expiry.insert((ll(20), ll(9)), Some(10));
        root.candidate_map = candidates_for(&root.parent_map);
        assert!(root.routing_table.add_route(ll(20), &[ll(20)]));

        assert!(root.expire_routes(10));
        assert!(root.parent_map.is_empty());
        assert!(root.edge_expiry.is_empty());
        assert!(root.routing_table.lookup(&ll(20)).is_none());
        assert_eq!(root.routing_table.entry_state(&ll(20)), None);
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
        wire.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0x80, path_sequence, lifetime]);
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
            252,
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
    fn local_path_sequence_advances_per_generation_and_exact_copy_reuses_it() {
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
            path_sequence(&mgr.build_dao_copy_with_lifetime(ll(1), 10).unwrap()),
            243
        );
        assert_eq!(path_sequence(&mgr.build_dao_with_lifetime(ll(1), 0)), 244);
        assert_eq!(path_sequence(&mgr.build_dao(ll(1))), 245);
    }

    #[test]
    fn dao_copy_requires_exact_prior_update_without_mutating_counters() {
        let mut mgr = DaoManager::new(ll(2), 0, dodag_id());
        let initial_counters = (mgr.dao_sequence, mgr.path_sequence);

        assert_eq!(mgr.build_dao_copy_with_lifetime(ll(1), 10), None);
        assert_eq!((mgr.dao_sequence, mgr.path_sequence), initial_counters);

        let update = mgr.build_dao_with_lifetime(ll(1), 10);
        let (update_dao_sequence, update_path_sequence) = {
            let dao = Dao::from_bytes(&update).unwrap();
            let transit = OptionIter::new(dao.options_tail(&update))
                .map(Result::unwrap)
                .find(|option| option.opt_type == OPT_TRANSIT_INFO)
                .map(|option| TransitInfo::from_bytes(option.data).unwrap())
                .unwrap();
            (dao.dao_sequence, transit.path_sequence)
        };
        let update_counters = (mgr.dao_sequence, mgr.path_sequence);

        assert_eq!(mgr.build_dao_copy_with_lifetime(ll(3), 10), None);
        assert_eq!((mgr.dao_sequence, mgr.path_sequence), update_counters);
        assert_eq!(mgr.build_dao_copy_with_lifetime(ll(1), 11), None);
        assert_eq!((mgr.dao_sequence, mgr.path_sequence), update_counters);

        let exact = mgr.build_dao_copy_with_lifetime(ll(1), 10).unwrap();
        let exact_dao = Dao::from_bytes(&exact).unwrap();
        let exact_transit = OptionIter::new(exact_dao.options_tail(&exact))
            .map(Result::unwrap)
            .find(|option| option.opt_type == OPT_TRANSIT_INFO)
            .map(|option| TransitInfo::from_bytes(option.data).unwrap())
            .unwrap();
        assert_eq!(
            exact_dao.dao_sequence,
            increment_lollipop(update_dao_sequence)
        );
        assert_eq!(exact_transit.path_sequence, update_path_sequence);
        assert_eq!(mgr.path_sequence, update_counters.1);

        mgr.build_dao_with_lifetime(ll(3), 11);
        let replaced_counters = (mgr.dao_sequence, mgr.path_sequence);
        assert_eq!(mgr.build_dao_copy_with_lifetime(ll(1), 10), None);
        assert_eq!((mgr.dao_sequence, mgr.path_sequence), replaced_counters);
        assert!(mgr.build_dao_copy_with_lifetime(ll(3), 11).is_some());
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
    fn target_descriptor_grammar_is_explicit_and_atomic() {
        const DESCRIPTOR: [u8; 6] = [OPT_RPL_TARGET_DESCRIPTOR, 4, 1, 2, 3, 4];
        let valid = global_dao_wire(0, 1, ll(2), ll(1));

        let mut with_descriptor = valid.clone();
        with_descriptor.splice(24..24, DESCRIPTOR);
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        assert!(root.process_dao(&with_descriptor));
        assert_eq!(root.routing_table.lookup(&ll(2)), Some(&[ll(2)][..]));

        let malformed = [
            {
                let mut wire = valid.clone();
                wire.splice(4..4, DESCRIPTOR);
                wire
            },
            {
                let mut wire = valid.clone();
                wire.extend_from_slice(&DESCRIPTOR);
                wire
            },
            {
                let mut wire = valid.clone();
                wire.splice(24..24, DESCRIPTOR);
                wire.splice(30..30, DESCRIPTOR);
                wire
            },
            {
                let mut wire = valid;
                wire.splice(24..24, [OPT_RPL_TARGET_DESCRIPTOR, 3, 1, 2, 3]);
                wire
            },
        ];
        for wire in malformed {
            let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
            assert!(!root.process_dao(&wire));
            assert!(root.parent_map.is_empty());
            assert!(root.candidate_map.is_empty());
            assert!(root.path_seq_map.is_empty());
        }
    }

    #[test]
    fn equal_path_sequence_descriptor_mutations_are_rejected_without_mutation() {
        const FIRST: [u8; 6] = [OPT_RPL_TARGET_DESCRIPTOR, 4, 1, 2, 3, 4];
        const SECOND: [u8; 6] = [OPT_RPL_TARGET_DESCRIPTOR, 4, 5, 6, 7, 8];

        let with_descriptor = |dao_sequence, descriptor: [u8; 6]| {
            let mut wire = global_dao_wire_with_sequences(0, dao_sequence, 10, ll(2), ll(1), 10);
            wire.splice(24..24, descriptor);
            wire
        };
        let assert_unchanged =
            |root: &DaoManager,
             parents: &HashMap<[u8; 16], Vec<[u8; 16]>>,
             expiry: &HashMap<([u8; 16], [u8; 16]), Option<u64>>,
             paths: &HashMap<[u8; 16], Freshness>,
             origins: &HashMap<[u8; 16], Freshness>,
             candidates: &HashMap<[u8; 16], Vec<DaoCandidate>>,
             descriptors: &HashMap<[u8; 16], Option<u32>>,
             routes: &HashMap<RouteTarget, RouteEntry>| {
                assert_eq!(&root.parent_map, parents);
                assert_eq!(&root.edge_expiry, expiry);
                assert_freshness_maps_equal(&root.path_seq_map, paths);
                assert_freshness_maps_equal(&root.origin_seq_map, origins);
                assert_eq!(&root.candidate_map, candidates);
                assert_eq!(&root.descriptor_map, descriptors);
                assert_eq!(&root.routing_table.routes, routes);
            };

        let mut described = DaoManager::as_root(ll(1), 0, dodag_id());
        assert!(described.process_dao_at(&with_descriptor(10, FIRST), ll(2), 100, 1));
        let described_state = (
            described.parent_map.clone(),
            described.edge_expiry.clone(),
            described.path_seq_map.clone(),
            described.origin_seq_map.clone(),
            described.candidate_map.clone(),
            described.descriptor_map.clone(),
            described.routing_table.routes.clone(),
        );

        assert!(!described.process_dao_at(&with_descriptor(11, SECOND), ll(2), 101, 1));
        assert_unchanged(
            &described,
            &described_state.0,
            &described_state.1,
            &described_state.2,
            &described_state.3,
            &described_state.4,
            &described_state.5,
            &described_state.6,
        );
        let removed = global_dao_wire_with_sequences(0, 11, 10, ll(2), ll(1), 10);
        assert!(!described.process_dao_at(&removed, ll(2), 101, 1));
        assert_unchanged(
            &described,
            &described_state.0,
            &described_state.1,
            &described_state.2,
            &described_state.3,
            &described_state.4,
            &described_state.5,
            &described_state.6,
        );

        let mut undescribed = DaoManager::as_root(ll(1), 0, dodag_id());
        let initial = global_dao_wire_with_sequences(0, 10, 10, ll(2), ll(1), 10);
        assert!(undescribed.process_dao_at(&initial, ll(2), 100, 1));
        let undescribed_state = (
            undescribed.parent_map.clone(),
            undescribed.edge_expiry.clone(),
            undescribed.path_seq_map.clone(),
            undescribed.origin_seq_map.clone(),
            undescribed.candidate_map.clone(),
            undescribed.descriptor_map.clone(),
            undescribed.routing_table.routes.clone(),
        );
        assert!(!undescribed.process_dao_at(&with_descriptor(11, FIRST), ll(2), 101, 1));
        assert_unchanged(
            &undescribed,
            &undescribed_state.0,
            &undescribed_state.1,
            &undescribed_state.2,
            &undescribed_state.3,
            &undescribed_state.4,
            &undescribed_state.5,
            &undescribed_state.6,
        );
    }

    #[test]
    fn signed_dao_accepts_valid_target_descriptor() {
        const DESCRIPTOR: [u8; 6] = [OPT_RPL_TARGET_DESCRIPTOR, 4, 1, 2, 3, 4];
        let identity = Identity::from_seed(Seed::new([0x37; 32]));
        let (wire, origin) = verified_grouped_dao(&identity, 1, 1, 10, &[(ll(1), 0x80, 10)]);
        let mut unsigned = SignedDaoEnvelope::from_bytes(&wire)
            .unwrap()
            .unsigned_bytes
            .to_vec();
        unsigned.splice(24..24, DESCRIPTOR);
        let wire = sign_unsigned_dao(&identity, 1, origin, &unsigned);
        let mut storage = MemStorage::new();
        let (mut root, mut state) =
            DaoManager::provision_root(&mut storage, ll(1), 0, dodag_id()).unwrap();

        assert_eq!(
            process_verified_grouped(
                &mut root,
                &mut state,
                &mut storage,
                &identity,
                &wire,
                origin,
                100,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        assert_eq!(root.routing_table().lookup(&origin), Some(&[origin][..]));
    }

    #[test]
    fn path_control_requires_an_active_bit_and_rejects_atomically() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        assert!(root.process_dao(&global_dao_wire(0, 1, ll(2), ll(1))));
        let before_parents = root.parent_map.clone();
        let before_candidates = root.candidate_map.clone();
        let before_routes = root.routing_table.routes.clone();
        let mut invalid = global_dao_wire_with_sequences(0, 2, 2, ll(3), ll(1), 10);
        invalid.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0, 2, 10]);
        invalid.extend_from_slice(&ll(2));

        assert!(!root.process_dao_at(&invalid, ll(3), 100, 1));
        assert_eq!(root.parent_map, before_parents);
        assert_eq!(root.candidate_map, before_candidates);
        assert_eq!(root.routing_table.routes, before_routes);
        assert!(!root.path_seq_map.contains_key(&ll(3)));
    }

    #[test]
    fn path_control_preference_precedes_complete_path_lexicographic_tie_break() {
        let root_address = ll(1);
        let mut root = DaoManager::as_root(root_address, 0, dodag_id());
        for (target, parent) in [
            (ll(8), root_address),
            (ll(9), root_address),
            (ll(2), ll(9)),
            (ll(3), ll(8)),
        ] {
            assert!(root.process_dao(&global_dao_wire(0, 1, target, parent)));
        }

        let mut preferred = global_dao_wire_with_sequences(0, 1, 1, ll(4), ll(2), 255);
        preferred[27] = 0x20;
        preferred.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0x40, 1, 255]);
        preferred.extend_from_slice(&ll(3));
        assert!(root.process_dao(&preferred));
        assert_eq!(
            root.routing_table.lookup(&ll(4)),
            Some(&[ll(8), ll(3), ll(4)][..])
        );

        let mut tied = global_dao_wire_with_sequences(0, 2, 2, ll(4), ll(2), 255);
        tied[27] = 0x40;
        tied.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0x80, 2, 255]);
        tied.extend_from_slice(&ll(3));
        assert!(root.process_dao(&tied));
        assert_eq!(
            root.routing_table.lookup(&ll(4)),
            Some(&[ll(8), ll(3), ll(4)][..])
        );
    }

    #[test]
    fn all_transit_parents_are_retained_and_selected_deterministically() {
        fn install(parent_order: [[u8; 16]; 2]) -> DaoManager {
            let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
            assert!(root.process_dao(&global_dao_wire(0, 1, ll(2), ll(1))));
            assert!(root.process_dao(&global_dao_wire(0, 1, ll(3), ll(1))));

            let mut dao = global_dao_wire(0, 1, ll(4), parent_order[0]);
            dao.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0x80, 1, 255]);
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
    fn equal_path_sequence_accepts_only_an_exact_snapshot() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        assert!(root.process_dao(&global_dao_wire(0, 1, ll(2), ll(1))));
        assert!(root.process_dao(&global_dao_wire(0, 1, ll(3), ll(1))));

        let first = global_dao_wire_with_sequences(0, 10, 10, ll(4), ll(2), 10);
        assert!(root.process_dao_at(&first, ll(4), 100, 1));
        let target_updated_at = root.path_seq_map[&ll(4)].updated_at;
        root.routing_table.mark_stale(&ll(4)).unwrap().unwrap();

        let mut exact = first.clone();
        exact[3] = 11;
        assert!(!root.process_dao_at(&exact, ll(4), 105, 1));
        assert_eq!(root.parent_map.get(&ll(4)), Some(&vec![ll(2)]));
        assert_eq!(root.edge_expiry.get(&(ll(4), ll(2))), Some(&Some(110)));
        assert_eq!(root.path_seq_map[&ll(4)].updated_at, target_updated_at);
        assert_eq!(root.origin_seq_map[&ll(4)].sequence, 11);
        assert_eq!(
            root.routing_table.entry_state(&ll(4)),
            Some(RouteEntryState::Stale)
        );

        let added_parent = global_dao_wire_with_sequences(0, 12, 10, ll(4), ll(3), 10);
        assert!(!root.process_dao_at(&added_parent, ll(4), 106, 1));

        let changed_lifetime = global_dao_wire_with_sequences(0, 12, 10, ll(4), ll(2), 20);
        assert!(!root.process_dao_at(&changed_lifetime, ll(4), 106, 1));

        let mut changed_control = global_dao_wire_with_sequences(0, 12, 10, ll(4), ll(2), 10);
        changed_control[27] = 0x40;
        assert!(!root.process_dao_at(&changed_control, ll(4), 106, 1));

        assert_eq!(root.origin_seq_map[&ll(4)].sequence, 11);
        assert_eq!(root.parent_map.get(&ll(4)), Some(&vec![ll(2)]));
        assert_eq!(root.edge_expiry.get(&(ll(4), ll(2))), Some(&Some(110)));
        assert!(!root.edge_expiry.contains_key(&(ll(4), ll(3))));

        let mut expired = exact;
        expired[3] = 12;
        assert!(root.process_dao_at(&expired, ll(4), 110, 1));
        assert_eq!(root.origin_seq_map[&ll(4)].sequence, 12);
        assert!(root.routing_table.lookup(&ll(4)).is_none());
    }

    #[test]
    fn newer_path_sequence_replaces_complete_candidate_snapshot() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        for parent in [ll(2), ll(3), ll(4)] {
            assert!(root.process_dao(&global_dao_wire(0, 1, parent, ll(1))));
        }
        let first = global_dao_wire_with_sequences(0, 10, 10, ll(5), ll(2), 10);
        assert!(root.process_dao_at(&first, ll(5), 100, 1));

        let mut replacement = global_dao_wire_with_sequences(0, 11, 11, ll(5), ll(3), 20);
        replacement.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0x80, 11, 20]);
        replacement.extend_from_slice(&ll(4));
        assert!(root.process_dao_at(&replacement, ll(5), 101, 1));
        assert_eq!(root.parent_map.get(&ll(5)), Some(&vec![ll(3), ll(4)]));
        assert!(!root.edge_expiry.contains_key(&(ll(5), ll(2))));
        assert_eq!(root.edge_expiry.get(&(ll(5), ll(3))), Some(&Some(121)));
        assert_eq!(root.edge_expiry.get(&(ll(5), ll(4))), Some(&Some(121)));

        let addition = global_dao_wire_with_sequences(0, 12, 11, ll(5), ll(2), 20);
        assert!(!root.process_dao_at(&addition, ll(5), 102, 1));
        assert_eq!(root.parent_map.get(&ll(5)), Some(&vec![ll(3), ll(4)]));
        assert_eq!(root.origin_seq_map[&ll(5)].sequence, 11);
    }

    #[test]
    fn equal_path_sequence_cannot_revive_an_expired_target() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let first = global_dao_wire_with_sequences(0, 10, 10, ll(2), ll(1), 1);
        assert!(root.process_dao_at(&first, ll(2), 100, 1));
        assert!(root.expire_routes(101));

        let mut exact = first.clone();
        exact[3] = 11;
        assert!(!root.process_dao_at(&exact, ll(2), 101, 1));
        assert_eq!(root.origin_seq_map[&ll(2)].sequence, 11);
        assert!(!root.parent_map.contains_key(&ll(2)));

        let replay = global_dao_wire_with_sequences(0, 12, 10, ll(2), ll(3), 1);
        assert!(!root.process_dao_at(&replay, ll(2), 101, 1));
        assert!(!root.parent_map.contains_key(&ll(2)));
    }

    #[test]
    fn equal_path_sequence_does_not_revive_an_expired_route_entry() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let first = global_dao_wire_with_sequences(0, 10, 10, ll(2), ll(1), 10);
        assert!(root.process_dao_at(&first, ll(2), 100, 1));
        root.routing_table.mark_expired(&ll(2)).unwrap().unwrap();

        let mut exact = first;
        exact[3] = 11;
        assert!(!root.process_dao_at(&exact, ll(2), 105, 1));
        assert_eq!(root.origin_seq_map[&ll(2)].sequence, 11);
        assert_eq!(
            root.routing_table.entry_state(&ll(2)),
            Some(RouteEntryState::Expired)
        );
    }

    #[test]
    fn ancestor_reparenting_rebuilds_expired_descendant_without_panic() {
        let mut root = DaoManager::as_root(ll(1), 0, dodag_id());
        let mut alternate = DaoManager::new(ll(4), 0, dodag_id());
        let mut parent = DaoManager::new(ll(2), 0, dodag_id());
        let mut child = DaoManager::new(ll(3), 0, dodag_id());
        assert!(root.process_dao(&alternate.build_dao(ll(1))));
        assert!(root.process_dao(&parent.build_dao(ll(1))));
        assert!(root.process_dao(&child.build_dao(ll(2))));
        root.routing_table.mark_expired(&ll(3)).unwrap().unwrap();

        assert!(root.process_dao(&parent.build_dao(ll(4))));
        assert_eq!(
            root.routing_table.lookup(&ll(3)),
            Some(&[ll(4), ll(2), ll(3)][..])
        );
    }

    #[test]
    fn route_assembly_tries_later_parent_when_first_chain_is_incomplete() {
        let root = ll(1);
        let mut parents = HashMap::new();
        parents.insert(ll(3), vec![root]);
        parents.insert(ll(4), vec![ll(2), ll(3)]);

        assert_eq!(
            DaoManager::assemble_path(root, &parents, &candidates_for(&parents), ll(4)),
            Some(vec![ll(3), ll(4)])
        );

        parents.insert(ll(4), vec![ll(3), ll(2)]);
        assert_eq!(
            DaoManager::assemble_path(root, &parents, &candidates_for(&parents), ll(4)),
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

        let rebuilt = DaoManager::rebuilt_routes(
            root,
            &parents,
            &candidates_for(&parents),
            &table,
            &HashSet::new(),
        )
        .unwrap();
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
        assert!(DaoManager::rebuilt_routes(
            root,
            &parents,
            &candidates_for(&parents),
            &table,
            &HashSet::new()
        )
        .is_none());
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
    fn withdrawn_multi_parent_snapshot_does_not_consume_active_capacity() {
        let authority = ll(9);
        let limits = DaoDiagnosticLimits {
            max_targets: 1,
            max_candidates_per_target: 2,
            max_candidates: 1,
        };
        let timing = |now_seconds| DaoProcessTiming {
            now_seconds,
            lifetime_unit_seconds: 1,
            max_deadline_seconds: u64::MAX,
        };
        let mut root = DaoManager::diagnostic_root(ll(1), 0, dodag_id());
        let mut withdrawal = global_dao_wire_with_sequences(0, 1, 1, ll(2), ll(1), 0);
        withdrawal.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0x40, 1, 0]);
        withdrawal.extend_from_slice(&ll(3));

        assert_eq!(
            root.process_route_state_diagnostic(&withdrawal, authority, timing(0), limits),
            Ok(true)
        );
        assert_eq!(root.candidate_map[&ll(2)].len(), 2);
        assert!(root.edge_expiry.is_empty());

        let install = global_dao_wire_with_sequences(0, 2, 1, ll(4), ll(1), 255);
        assert_eq!(
            root.process_route_state_diagnostic(&install, authority, timing(3_601), limits),
            Ok(true)
        );
        assert!(!root.path_seq_map.contains_key(&ll(2)));
        assert!(!root.candidate_map.contains_key(&ll(2)));
        assert!(!root.descriptor_map.contains_key(&ll(2)));
        assert_eq!(root.path_seq_map.len(), 1);
        assert_eq!(root.edge_expiry.len(), 1);
        assert_eq!(root.routing_table.lookup(&ll(4)), Some(&[ll(4)][..]));
    }

    #[test]
    fn grouped_five_target_four_transit_withdrawal_uses_no_active_capacity() {
        let targets = [ll(20), ll(21), ll(22), ll(23), ll(24)];
        let parents = [ll(2), ll(3), ll(4), ll(5)];
        let mut wire = vec![0, 0, 0, 1];
        for target in targets {
            wire.extend_from_slice(&[OPT_RPL_TARGET, 18, 0, 128]);
            wire.extend_from_slice(&target);
        }
        for (index, parent) in parents.into_iter().enumerate() {
            wire.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0x80 >> (index * 2), 10, 0]);
            wire.extend_from_slice(&parent);
        }

        let mut root = DaoManager::diagnostic_root(ll(1), 0, dodag_id());
        assert_eq!(
            root.process_route_state_diagnostic(
                &wire,
                ll(9),
                DaoProcessTiming {
                    now_seconds: 100,
                    lifetime_unit_seconds: 1,
                    max_deadline_seconds: u64::MAX,
                },
                DaoDiagnosticLimits {
                    max_targets: 5,
                    max_candidates_per_target: 4,
                    max_candidates: 1,
                },
            ),
            Ok(true)
        );
        assert_eq!(root.path_seq_map.len(), 5);
        assert_eq!(root.candidate_map.len(), 5);
        for target in targets {
            assert_eq!(root.path_seq_map[&target].sequence, 10);
            assert_eq!(root.candidate_map[&target].len(), 4);
        }
        assert!(root.parent_map.is_empty());
        assert!(root.edge_expiry.is_empty());
        assert!(root.routing_table.is_empty());
    }

    #[test]
    fn persistent_state_missing_corrupt_and_tx_max_fail_closed() {
        let mut storage = MemStorage::new();
        let key = PublicKey::new([7; 32]);
        assert_eq!(tx_open(&storage, key), Err(DaoPersistentOpenError::Missing));
        assert!(matches!(
            DaoManager::open_root(&storage, ll(1), 0, dodag_id()),
            Err(DaoPersistentOpenError::Missing)
        ));
        storage.set_raw(DAO_TX_KEYS[0], b"torn");
        assert_eq!(tx_open(&storage, key), Err(DaoPersistentOpenError::Corrupt));

        let mut storage = MemStorage::new();
        storage.set_raw(DAO_RX_KEYS[0], b"torn");
        assert!(matches!(
            DaoManager::open_root(&storage, ll(1), 0, dodag_id()),
            Err(DaoPersistentOpenError::Corrupt)
        ));

        let mut storage = MemStorage::new();
        let tx = tx_provision(&mut storage, key);
        let payload = encode_tx_state(key.as_bytes(), ll(2), 0, dodag_id(), u64::MAX, &[]).unwrap();
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
        let mut tx = tx_open(&storage, key).unwrap();
        assert_eq!(tx.reserve_next(&mut storage), Err(DaoTxError::Exhausted));
        let mut tx = tx_open(&storage, key).unwrap();
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
                verified.origin_iid(),
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
    fn dao_admissions_round_trip_and_are_bound_to_exact_scope() {
        let key = Identity::from_seed(Seed::new([0x32; 32])).pubkey;
        let mut storage = MemStorage::new();
        let mut admissions =
            DaoAdmissionState::provision(&mut storage, ll(1), 0, dodag_id()).unwrap();
        admissions.admit(&mut storage, *key.as_bytes()).unwrap();

        let reopened = DaoAdmissionState::open(&storage, ll(1), 0, dodag_id()).unwrap();
        assert_eq!(reopened.len(), 1);
        assert!(reopened.contains(key.as_bytes()));
        assert_eq!(
            DaoAdmissionState::open(&storage, ll(2), 0, dodag_id()),
            Err(DaoPersistentOpenError::ScopeMismatch)
        );
        assert_eq!(
            DaoAdmissionState::open(&storage, ll(1), 1, dodag_id()),
            Err(DaoPersistentOpenError::ScopeMismatch)
        );
        assert_eq!(
            DaoAdmissionState::open(&storage, ll(1), 0, ll(9)),
            Err(DaoPersistentOpenError::ScopeMismatch)
        );
    }

    #[test]
    fn duplicate_dao_admission_keys_are_corrupt() {
        let key = *Identity::from_seed(Seed::new([0x33; 32])).pubkey.as_bytes();
        let mut payload = vec![0u8; DAO_ADMISSION_HEADER_LEN + 64];
        payload[..16].copy_from_slice(&ll(1));
        payload[16] = 0;
        payload[17..33].copy_from_slice(&dodag_id());
        payload[33..35].copy_from_slice(&2u16.to_be_bytes());
        payload[35..67].copy_from_slice(&key);
        payload[67..99].copy_from_slice(&key);
        let mut storage = MemStorage::new();
        let mut record = vec![0u8; payload.len() + SLOT_OVERHEAD];
        provision_redundant(
            &mut storage,
            DAO_ADMISSION_KEYS,
            DAO_ADMISSION_MAGIC,
            &payload,
            &mut record,
        )
        .unwrap();

        assert_eq!(
            DaoAdmissionState::open(&storage, ll(1), 0, dodag_id()),
            Err(DaoPersistentOpenError::Corrupt)
        );
    }

    #[test]
    fn fresh_authenticated_sequence_persists_unchanged_path_snapshot() {
        let identity = Identity::from_seed(Seed::new([0x33; 32]));
        let (first_wire, origin) = verified_dao(&identity, 1, ll(1));
        let sign = |unsigned: &[u8], sequence: u64| {
            let digest = dao_origin_digest(origin, dodag_id(), sequence, unsigned);
            let signature = LinkLayer::new(identity.clone()).sign_digest(&digest);
            let mut wire = unsigned.to_vec();
            let offset = wire.len();
            wire.resize(offset + crate::message::DAO_ORIGIN_SIGNATURE_LEN, 0);
            crate::message::DaoOriginSignature::write_to(sequence, &signature, &mut wire[offset..])
                .unwrap();
            wire
        };
        let mut second_unsigned = SignedDaoEnvelope::from_bytes(&first_wire)
            .unwrap()
            .unsigned_bytes
            .to_vec();
        second_unsigned[3] = increment_lollipop(second_unsigned[3]);
        let second_wire = sign(&second_unsigned, 2);
        let first = SignatureVerifiedDao::verify_signature(
            &first_wire,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        let second = SignatureVerifiedDao::verify_signature(
            &second_wire,
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
            root.process_signature_verified(
                &first,
                first.origin_iid(),
                &mut state,
                &mut storage,
                timing,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        let path = root.routing_table().lookup(&origin).unwrap().to_vec();
        assert_eq!(
            root.process_signature_verified(
                &second,
                second.origin_iid(),
                &mut state,
                &mut storage,
                timing,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        assert_eq!(root.routing_table().lookup(&origin), Some(path.as_slice()));
        assert_eq!(root.origin_high_water()[0].origin_sequence, 2);

        let (reopened, _) = DaoManager::open_root(&storage, ll(1), 0, dodag_id()).unwrap();
        assert_eq!(reopened.origin_high_water()[0].origin_sequence, 2);
    }

    #[test]
    fn signature_verified_grouped_path_sequence_controls_complete_snapshot() {
        let identity = Identity::from_seed(Seed::new([0x34; 32]));
        let mut storage = MemStorage::new();
        let (mut root, mut state) =
            DaoManager::provision_root(&mut storage, ll(1), 0, dodag_id()).unwrap();
        let first_candidates = [(ll(1), 0x80, 10), (ll(2), 0x40, 10)];
        let (first, origin) = verified_grouped_dao(&identity, 1, 250, 10, &first_candidates);
        assert_eq!(
            process_verified_grouped(
                &mut root,
                &mut state,
                &mut storage,
                &identity,
                &first,
                origin,
                100,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        let first_updated_at = root.path_seq_map[&origin].updated_at;
        let first_deadlines = root.edge_expiry.clone();

        let reordered_candidates = [(ll(2), 0x40, 10), (ll(1), 0x80, 10)];
        let (reordered, _) = verified_grouped_dao(&identity, 2, 1, 10, &reordered_candidates);
        assert_eq!(
            process_verified_grouped(
                &mut root,
                &mut state,
                &mut storage,
                &identity,
                &reordered,
                origin,
                105,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        assert_eq!(root.path_seq_map[&origin].updated_at, first_updated_at);
        assert_eq!(root.edge_expiry, first_deadlines);
        let before_rejections_a = storage.raw(DAO_RX_KEYS[0]).map(<[u8]>::to_vec);
        let before_rejections_b = storage.raw(DAO_RX_KEYS[1]).map(<[u8]>::to_vec);

        let rejected = [
            (
                10,
                vec![(ll(1), 0x80, 10), (ll(2), 0x40, 10), (ll(3), 0x20, 10)],
            ),
            (10, vec![(ll(1), 0x80, 10)]),
            (10, vec![(ll(1), 0x80, 10), (ll(2), 0x20, 10)]),
            (10, vec![(ll(1), 0x80, 20), (ll(2), 0x40, 20)]),
            (9, reordered_candidates.to_vec()),
            (40, reordered_candidates.to_vec()),
            (10, vec![(ll(1), 0x80, 0), (ll(2), 0x40, 0)]),
        ];
        for (path_sequence, candidates) in rejected {
            let (wire, _) = verified_grouped_dao(&identity, 3, 2, path_sequence, &candidates);
            assert_eq!(
                process_verified_grouped(
                    &mut root,
                    &mut state,
                    &mut storage,
                    &identity,
                    &wire,
                    origin,
                    106,
                ),
                Err(DaoProcessError::RouteRejected)
            );
            assert_eq!(root.origin_high_water()[0].origin_sequence, 2);
            assert_eq!(root.edge_expiry, first_deadlines);
            assert_eq!(storage.raw(DAO_RX_KEYS[0]), before_rejections_a.as_deref());
            assert_eq!(storage.raw(DAO_RX_KEYS[1]), before_rejections_b.as_deref());
        }
        let (reopened, _) = DaoManager::open_root(&storage, ll(1), 0, dodag_id()).unwrap();
        assert_eq!(reopened.origin_high_water()[0].origin_sequence, 2);

        let replacement_candidates = [(ll(3), 0x80, 20)];
        let (replacement, _) = verified_grouped_dao(&identity, 3, 3, 11, &replacement_candidates);
        assert_eq!(
            process_verified_grouped(
                &mut root,
                &mut state,
                &mut storage,
                &identity,
                &replacement,
                origin,
                110,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        assert_eq!(root.parent_map.get(&origin), Some(&vec![ll(3)]));
        assert!(!root.edge_expiry.contains_key(&(origin, ll(1))));
        assert!(!root.edge_expiry.contains_key(&(origin, ll(2))));

        let (withdrawal, _) = verified_grouped_dao(&identity, 4, 4, 12, &[(ll(3), 0x80, 0)]);
        assert_eq!(
            process_verified_grouped(
                &mut root,
                &mut state,
                &mut storage,
                &identity,
                &withdrawal,
                origin,
                120,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        assert!(!root.parent_map.contains_key(&origin));

        let reinstall_candidates = [(ll(1), 0x80, 1)];
        let (reinstall, _) = verified_grouped_dao(&identity, 5, 5, 13, &reinstall_candidates);
        assert_eq!(
            process_verified_grouped(
                &mut root,
                &mut state,
                &mut storage,
                &identity,
                &reinstall,
                origin,
                200,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        let reinstall_updated_at = root.path_seq_map[&origin].updated_at;
        assert!(root.expire_routes(201));

        let (expired_equal, _) = verified_grouped_dao(&identity, 6, 6, 13, &reinstall_candidates);
        assert_eq!(
            process_verified_grouped(
                &mut root,
                &mut state,
                &mut storage,
                &identity,
                &expired_equal,
                origin,
                201,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        assert!(!root.parent_map.contains_key(&origin));
        assert!(root.routing_table().lookup(&origin).is_none());
        assert_eq!(root.path_seq_map[&origin].updated_at, reinstall_updated_at);
        assert_eq!(root.origin_high_water()[0].origin_sequence, 6);
    }

    #[test]
    fn signature_verified_path_capacity_rejection_is_atomic() {
        let identity = Identity::from_seed(Seed::new([0x35; 32]));
        let mut storage = MemStorage::new();
        let (mut root, mut state) =
            DaoManager::provision_root(&mut storage, ll(1), 0, dodag_id()).unwrap();
        for value in 0..MAX_PATH_SEQUENCES as u16 {
            root.path_seq_map
                .insert(addr(value), Freshness::new(1, None, 0));
        }
        let before_paths = root.path_seq_map.clone();
        let before_a = storage.raw(DAO_RX_KEYS[0]).map(<[u8]>::to_vec);
        let before_b = storage.raw(DAO_RX_KEYS[1]).map(<[u8]>::to_vec);
        let (wire, origin) = verified_grouped_dao(&identity, 1, 1, 1, &[(ll(1), 0x80, 0)]);

        assert_eq!(
            process_verified_grouped(
                &mut root,
                &mut state,
                &mut storage,
                &identity,
                &wire,
                origin,
                0,
            ),
            Err(DaoProcessError::RouteRejected)
        );
        assert_eq!(root.path_seq_map.len(), before_paths.len());
        for (target, before) in before_paths {
            let after = root.path_seq_map.get(&target).unwrap();
            assert_eq!(after.sequence, before.sequence);
            assert_eq!(after.active_until, before.active_until);
            assert_eq!(after.retain_until, before.retain_until);
            assert_eq!(after.updated_at, before.updated_at);
        }
        assert!(root.parent_map.is_empty());
        assert!(root.candidate_map.is_empty());
        assert!(root.origin_high_water().is_empty());
        assert_eq!(storage.raw(DAO_RX_KEYS[0]), before_a.as_deref());
        assert_eq!(storage.raw(DAO_RX_KEYS[1]), before_b.as_deref());
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
        let len = encode_high_water(ll(1), 0, dodag_id(), &table, &mut payload).unwrap();
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
                verified.origin_iid(),
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
        let mut first = tx_provision(&mut storage, identity.pubkey);
        let mut stale = tx_open(&storage, identity.pubkey).unwrap();

        let sequence = first.reserve_next(&mut storage).unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(stale.reserve_next(&mut storage), Err(DaoTxError::Stale));
        first
            .finalize_signed(&mut storage, sequence, &wire)
            .unwrap();
        let mut rebooted = tx_open(&storage, identity.pubkey).unwrap();
        assert_eq!(rebooted.last_signed_dao(), Some(wire.as_slice()));

        assert_eq!(rebooted.reserve_next(&mut storage), Ok(2));
        let reopened = tx_open(&storage, identity.pubkey).unwrap();
        assert_eq!(reopened.last_reserved, 2);
        assert_eq!(reopened.last_signed_dao(), Some(wire.as_slice()));
    }

    #[test]
    fn authenticated_origin_sequence_does_not_override_stale_path_sequence() {
        let identity = Identity::from_seed(Seed::new([0x47; 32]));
        let (first_wire, origin) = verified_dao_with_path_sequence(&identity, 1, 241, ll(1));
        let (latest_wire, _) = verified_dao_with_path_sequence(&identity, 21, 5, ll(1));
        let first_verified = SignatureVerifiedDao::verify_signature(
            &first_wire,
            origin,
            0,
            dodag_id(),
            Some(identity.pubkey),
        )
        .unwrap();
        let latest_verified = SignatureVerifiedDao::verify_signature(
            &latest_wire,
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
            root.process_signature_verified(
                &first_verified,
                identity.iid,
                &mut state,
                &mut storage,
                timing,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        let latest_dao = latest_verified.envelope.dao.clone();
        let (updates, update_count) = root
            .extract_updates(&latest_dao, latest_verified.envelope.unsigned_bytes)
            .unwrap();
        assert!(DaoManager::sender_is_authorized(
            &updates,
            update_count,
            origin,
            ll(1),
            identity.iid,
        ));
        assert!(root
            .staged()
            .process_dao_inner(
                latest_dao,
                updates,
                update_count,
                origin,
                true,
                DaoTiming {
                    now_seconds: 0,
                    lifetime_unit_seconds: 60,
                    max_deadline_seconds: u64::MAX,
                },
                DaoStateLimits::PRODUCTION,
            )
            .is_err());
        assert_eq!(
            root.process_signature_verified(
                &latest_verified,
                identity.iid,
                &mut state,
                &mut storage,
                timing,
            ),
            Err(DaoProcessError::RouteRejected)
        );
        assert_eq!(
            root.process_signature_verified(
                &latest_verified,
                identity.iid,
                &mut state,
                &mut storage,
                timing,
            ),
            Err(DaoProcessError::RouteRejected)
        );
        assert_eq!(root.origin_high_water()[0].origin_sequence, 1);

        let mut raw = DaoManager::as_root(ll(1), 0, dodag_id());
        let first = SignedDaoEnvelope::from_bytes(&first_wire).unwrap();
        let latest = SignedDaoEnvelope::from_bytes(&latest_wire).unwrap();
        assert!(raw.process_dao_at(first.unsigned_bytes, origin, 0, 60));
        assert!(!raw.process_dao_at(latest.unsigned_bytes, origin, 0, 60));
    }

    #[test]
    fn link_local_origin_requires_direct_authenticated_parent_root() {
        let origin_identity = Identity::from_seed(Seed::new([0x48; 32]));
        let relay_identity = Identity::from_seed(Seed::new([0x49; 32]));
        let (relayed_wire, origin) = verified_dao(&origin_identity, 1, ll(2));
        let relayed = SignatureVerifiedDao::verify_signature(
            &relayed_wire,
            origin,
            0,
            dodag_id(),
            Some(origin_identity.pubkey),
        )
        .unwrap();
        let mut storage = MemStorage::new();
        let (mut root, mut state) =
            DaoManager::provision_root(&mut storage, ll(1), 0, dodag_id()).unwrap();
        let before_a = storage.raw(DAO_RX_KEYS[0]).map(<[u8]>::to_vec);
        let before_b = storage.raw(DAO_RX_KEYS[1]).map(<[u8]>::to_vec);
        let timing = DaoProcessTiming {
            now_seconds: 0,
            lifetime_unit_seconds: 60,
            max_deadline_seconds: u64::MAX,
        };

        assert_eq!(
            root.process_signature_verified(
                &relayed,
                relay_identity.iid,
                &mut state,
                &mut storage,
                timing,
            ),
            Err(DaoProcessError::RouteRejected)
        );
        assert!(root.origin_high_water().is_empty());
        assert!(root.routing_table().lookup(&origin).is_none());
        assert_eq!(storage.raw(DAO_RX_KEYS[0]), before_a.as_deref());
        assert_eq!(storage.raw(DAO_RX_KEYS[1]), before_b.as_deref());

        let (direct_wire, _) = verified_dao(&origin_identity, 1, ll(1));
        let direct = SignatureVerifiedDao::verify_signature(
            &direct_wire,
            origin,
            0,
            dodag_id(),
            Some(origin_identity.pubkey),
        )
        .unwrap();
        assert_eq!(
            root.process_signature_verified(
                &direct,
                origin_identity.iid,
                &mut state,
                &mut storage,
                timing,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
    }

    #[test]
    fn tx_finalize_failure_consumes_sequence_without_returnable_new_dao() {
        let identity = Identity::from_seed(Seed::new([0x42; 32]));
        let (wire, _) = verified_dao(&identity, 1, ll(1));
        let mut storage = MemStorage::new();
        let mut state = tx_provision(&mut storage, identity.pubkey);
        let sequence = state.reserve_next(&mut storage).unwrap();
        storage.fail_next_write();
        assert!(matches!(
            state.finalize_signed(&mut storage, sequence, &wire),
            Err(DaoTxError::Persistence(_))
        ));
        let mut reopened = tx_open(&storage, identity.pubkey).unwrap();
        assert_eq!(reopened.last_reserved, 1);
        assert_eq!(reopened.last_signed_dao(), None);
        assert_eq!(reopened.reserve_next(&mut storage), Ok(2));
        assert_eq!(
            reopened.finalize_signed(&mut storage, 2, &[0u8; MAX_SIGNED_DAO_LEN + 1],),
            Err(DaoTxError::Oversized)
        );
        let mut reopened = tx_open(&storage, identity.pubkey).unwrap();
        assert_eq!(reopened.last_signed_dao(), None);
        assert_eq!(reopened.reserve_next(&mut storage), Ok(3));
    }

    #[test]
    fn tx_state_rejects_key_rotation_and_storage_transplant() {
        let first = Identity::from_seed(Seed::new([0x44; 32]));
        let second = Identity::from_seed(Seed::new([0x45; 32]));
        let (wire, _) = verified_dao(&first, 1, ll(1));
        let mut storage = MemStorage::new();
        let mut state = tx_provision(&mut storage, first.pubkey);
        let sequence = state.reserve_next(&mut storage).unwrap();
        state
            .finalize_signed(&mut storage, sequence, &wire)
            .unwrap();
        assert_eq!(state.last_signed_dao(), Some(wire.as_slice()));
        assert_eq!(
            tx_open(&storage, second.pubkey),
            Err(DaoPersistentOpenError::KeyMismatch)
        );
        assert_eq!(
            DaoTxState::open(&storage, first.pubkey, ll(3), 0, dodag_id()),
            Err(DaoPersistentOpenError::ScopeMismatch)
        );
        assert_eq!(
            DaoTxState::open(&storage, first.pubkey, ll(2), 1, dodag_id()),
            Err(DaoPersistentOpenError::ScopeMismatch)
        );
        assert_eq!(
            DaoTxState::open(&storage, first.pubkey, ll(2), 0, ll(9)),
            Err(DaoPersistentOpenError::ScopeMismatch)
        );

        let mut transplanted = MemStorage::new();
        for key in DAO_TX_KEYS {
            if let Some(record) = storage.raw(key) {
                transplanted.set_raw(key, record);
            }
        }
        assert_eq!(
            tx_open(&transplanted, second.pubkey),
            Err(DaoPersistentOpenError::KeyMismatch)
        );
    }

    #[test]
    fn dao_open_and_provision_propagate_read_failures() {
        let key = PublicKey::new([0x46; 32]);
        let mut tx_storage = MemStorage::new();
        tx_storage.fail_next_read();
        assert_eq!(
            DaoTxState::open(&tx_storage, key, ll(2), 0, dodag_id()),
            Err(DaoPersistentOpenError::Storage(
                lichen_hal::storage::mem::MemStorageError
            ))
        );
        tx_storage.fail_next_read();
        assert_eq!(
            DaoTxState::provision(&mut tx_storage, key, ll(2), 0, dodag_id()),
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
            first.process_signature_verified(
                &verified_one,
                verified_one.origin_iid(),
                &mut first_state,
                &mut storage,
                timing,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        assert_eq!(
            stale.process_signature_verified(
                &verified_two,
                verified_two.origin_iid(),
                &mut stale_state,
                &mut storage,
                timing,
            ),
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
            root.process_signature_verified(
                &verified,
                verified.origin_iid(),
                &mut state,
                &mut storage,
                timing,
            ),
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
            root.process_signature_verified(
                &changed,
                changed.origin_iid(),
                &mut state,
                &mut storage,
                timing,
            ),
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
            root.process_signature_verified(
                &verified,
                verified.origin_iid(),
                &mut state,
                &mut storage,
                timing,
            ),
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
            root.process_signature_verified(
                &non_128,
                non_128.origin_iid(),
                &mut state,
                &mut storage,
                timing,
            ),
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
                verified.origin_iid(),
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
                changed.origin_iid(),
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
                other_verified.origin_iid(),
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

    #[test]
    fn root_replay_storage_is_bound_to_exact_scope() {
        let mut storage = MemStorage::new();
        let node = ll(1);
        let dodag = dodag_id();
        DaoManager::provision_root(&mut storage, node, 0, dodag).unwrap();
        assert!(DaoManager::open_root(&storage, node, 0, dodag).is_ok());

        let mut other_node = node;
        other_node[15] ^= 1;
        let mut other_dodag = dodag;
        other_dodag[15] ^= 1;
        assert!(matches!(
            DaoManager::open_root(&storage, other_node, 0, dodag),
            Err(DaoPersistentOpenError::ScopeMismatch)
        ));
        assert!(matches!(
            DaoManager::open_root(&storage, node, 1, dodag),
            Err(DaoPersistentOpenError::ScopeMismatch)
        ));
        assert!(matches!(
            DaoManager::open_root(&storage, node, 0, other_dodag),
            Err(DaoPersistentOpenError::ScopeMismatch)
        ));
    }

    #[test]
    fn legacy_drx1_record_fails_closed_without_migration() {
        let mut storage = MemStorage::new();
        let node = ll(1);
        let dodag = dodag_id();
        let mut payload = [0u8; HIGH_WATER_HEADER_LEN];
        encode_high_water(node, 0, dodag, &HashMap::new(), &mut payload).unwrap();
        let mut record = vec![0u8; payload.len() + SLOT_OVERHEAD];
        provision_redundant(
            &mut storage,
            DAO_RX_KEYS,
            DAO_RX_LEGACY_MAGIC,
            &payload,
            &mut record,
        )
        .unwrap();

        assert!(matches!(
            DaoManager::open_root(&storage, node, 0, dodag),
            Err(DaoPersistentOpenError::Corrupt)
        ));
        assert!(DaoManager::provision_root(&mut storage, node, 0, dodag).is_err());
    }
}
