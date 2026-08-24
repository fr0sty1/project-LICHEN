//! DAO TX/RX state, admission control persistence.
//!
//! Durable state for DAO sending (TX), receiving (RX), and origin admission.

#[cfg(feature = "std")]
use std::{
    collections::{HashMap, HashSet},
    vec,
    vec::Vec,
};

#[cfg(feature = "std")]
use crate::message::SignedDaoEnvelope;
#[cfg(feature = "std")]
use lichen_hal::{
    storage::{
        open_redundant, provision_redundant, update_redundant, RedundantOpenError,
        RedundantProvisionError, RedundantUpdateError, RedundantValue,
    },
    NonVolatile,
};
#[cfg(feature = "std")]
use lichen_link::keys::PublicKey;

// ── Constants ────────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
pub(crate) const DAO_TX_KEYS: [&str; 2] = ["rpl.tx.a", "rpl.tx.b"];
#[cfg(feature = "std")]
pub(crate) const DAO_RX_KEYS: [&str; 2] = ["rpl.rx.a", "rpl.rx.b"];
#[cfg(feature = "std")]
pub(crate) const DAO_ADMISSION_KEYS: [&str; 2] = ["rpl.admit.a", "rpl.admit.b"];
#[cfg(feature = "std")]
// Provisional, unshipped scope-bound format. No migration from DTX1 is supported.
pub(crate) const DAO_TX_MAGIC: [u8; 4] = *b"DTX2";
#[cfg(feature = "std")]
// Provisional, unshipped scope-bound format. DRX1 records fail closed; scope and
// high-water state must never be fabricated or discarded by automatic migration.
pub(crate) const DAO_RX_MAGIC: [u8; 4] = *b"DRX2";
#[cfg(feature = "std")]
// Provisional, unshipped scope-bound format. There is intentionally no migration
// or admission-removal path: an operator must explicitly reprovision invalid state.
pub(crate) const DAO_ADMISSION_MAGIC: [u8; 4] = *b"DAD1";
#[cfg(feature = "std")]
pub(crate) const HIGH_WATER_ENTRY_LEN: usize = 72;
#[cfg(feature = "std")]
pub(crate) const HIGH_WATER_SCOPE_LEN: usize = 16 + 1 + 16;
#[cfg(feature = "std")]
pub(crate) const HIGH_WATER_HEADER_LEN: usize = HIGH_WATER_SCOPE_LEN + 2;
#[cfg(feature = "std")]
pub(crate) const HIGH_WATER_PAYLOAD_LEN: usize =
    HIGH_WATER_HEADER_LEN + crate::routing::MAX_DAO_ORIGINS * HIGH_WATER_ENTRY_LEN;
#[cfg(feature = "std")]
pub(crate) const SLOT_OVERHEAD: usize = 24;
#[cfg(feature = "std")]
pub(crate) const DAO_TX_HEADER_LEN: usize = 75;
/// Maximum complete signed DAO retained for exact retransmission.
#[cfg(feature = "std")]
pub const MAX_SIGNED_DAO_LEN: usize = 255;
#[cfg(feature = "std")]
pub(crate) const DAO_TX_PAYLOAD_LEN: usize = DAO_TX_HEADER_LEN + MAX_SIGNED_DAO_LEN;
#[cfg(feature = "std")]
pub(crate) const DAO_ADMISSION_HEADER_LEN: usize = HIGH_WATER_SCOPE_LEN + 2;
#[cfg(feature = "std")]
pub(crate) const DAO_ADMISSION_PAYLOAD_LEN: usize =
    DAO_ADMISSION_HEADER_LEN + crate::routing::MAX_DAO_ORIGINS * 32;
#[cfg(feature = "std")]
pub(crate) type HighWaterMap = HashMap<[u8; 32], ([u8; 32], u64)>;

// ── Error types ──────────────────────────────────────────────────────────────

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
pub enum DaoAdmissionUpdateError<E> {
    Persistence(E),
    Stale,
    Exhausted,
    Corrupt,
    Capacity,
}

// ── TX State ─────────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub struct DaoTxState {
    pub(crate) current: RedundantValue,
    pub(crate) public_key: [u8; 32],
    pub(crate) local_origin: [u8; 16],
    pub(crate) rpl_instance_id: u8,
    pub(crate) dodag_id: [u8; 16],
    pub(crate) last_reserved: u64,
    pub(crate) last_signed_dao: Vec<u8>,
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

// ── RX State ─────────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub struct DaoRxState {
    pub(crate) current: RedundantValue,
}

// ── Admission State ──────────────────────────────────────────────────────────

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
        if self.admitted.len() == crate::routing::MAX_DAO_ORIGINS {
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

// ── Helper functions ─────────────────────────────────────────────────────────

#[cfg(feature = "std")]
pub(crate) fn encode_tx_state(
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
pub(crate) fn map_tx_update_error<E>(error: RedundantUpdateError<E>) -> DaoTxError<E> {
    match error {
        RedundantUpdateError::Storage(error) => DaoTxError::Persistence(error),
        RedundantUpdateError::Stale => DaoTxError::Stale,
        RedundantUpdateError::Exhausted => DaoTxError::Exhausted,
        RedundantUpdateError::Corrupt => DaoTxError::Corrupt,
    }
}

#[cfg(feature = "std")]
pub(crate) fn map_rx_update_error<E>(
    error: RedundantUpdateError<E>,
) -> crate::routing::DaoProcessError<E> {
    use crate::routing::DaoProcessError;
    match error {
        RedundantUpdateError::Storage(error) => DaoProcessError::Persistence(error),
        RedundantUpdateError::Stale => DaoProcessError::Stale,
        RedundantUpdateError::Exhausted => DaoProcessError::Exhausted,
        RedundantUpdateError::Corrupt => DaoProcessError::Corrupt,
    }
}

#[cfg(feature = "std")]
pub(crate) fn map_open_error<E>(error: RedundantOpenError<E>) -> DaoPersistentOpenError<E> {
    match error {
        RedundantOpenError::Missing => DaoPersistentOpenError::Missing,
        RedundantOpenError::Corrupt | RedundantOpenError::BufferTooSmall => {
            DaoPersistentOpenError::Corrupt
        }
        RedundantOpenError::Storage(error) => DaoPersistentOpenError::Storage(error),
    }
}

#[cfg(feature = "std")]
pub(crate) fn encode_admissions(
    node_address: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    admitted: &HashSet<[u8; 32]>,
) -> Option<Vec<u8>> {
    if admitted.len() > crate::routing::MAX_DAO_ORIGINS {
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
pub(crate) enum AdmissionDecodeError {
    ScopeMismatch,
    Corrupt,
}

#[cfg(feature = "std")]
pub(crate) fn decode_admissions(
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
    if count > crate::routing::MAX_DAO_ORIGINS
        || payload.len() != DAO_ADMISSION_HEADER_LEN + count * 32
    {
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
pub(crate) fn encode_high_water(
    node_address: [u8; 16],
    rpl_instance_id: u8,
    dodag_id: [u8; 16],
    map: &HighWaterMap,
    out: &mut [u8],
) -> Option<usize> {
    if map.len() > crate::routing::MAX_DAO_ORIGINS {
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
pub(crate) fn decode_high_water(data: &[u8]) -> Option<HighWaterMap> {
    if data.len() < HIGH_WATER_HEADER_LEN {
        return None;
    }
    let count = u16::from_be_bytes(
        data[HIGH_WATER_SCOPE_LEN..HIGH_WATER_HEADER_LEN]
            .try_into()
            .ok()?,
    ) as usize;
    if count > crate::routing::MAX_DAO_ORIGINS
        || data.len() != HIGH_WATER_HEADER_LEN + count * HIGH_WATER_ENTRY_LEN
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
