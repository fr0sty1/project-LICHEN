// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! GCP-6.2 Slot Allocation algorithms for multi-gateway coordination.
//!
//! Per spec section 08-gateway-coordination.md GCP-6.2, two allocation modes
//! are supported (both MUST be implemented):
//!
//! 1. **Interleaved**: Gateway with ordinal N owns slots N, N+G, N+2G...
//!    where G = gateway count. This distributes TX opportunities evenly
//!    across the superframe.
//!
//! 2. **Contiguous blocks**: Each gateway owns a sequential block of slots.
//!    Simpler for handoff since entire blocks can be transferred.
//!
//! # Conflict Resolution (GCP-6.3)
//!
//! If two gateways claim overlapping slots:
//! - Lowest IID (as unsigned big-endian 64-bit integer) MUST win
//! - Claims with invalid or missing signatures MUST be silently discarded
//! - Loser MUST select next available slot and re-claim
//!
//! # Example
//!
//! ```
//! use lichen_gateway::slot::{AllocationMode, SlotAllocator};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let allocator = SlotAllocator::try_new(AllocationMode::Interleaved, 60, 3)?;
//!
//! // Gateway 0 owns slots 0, 3, 6, 9...
//! let slots = allocator.allocate_for_ordinal(0)?;
//! assert!(slots.contains(&0));
//! assert!(slots.contains(&3));
//!
//! // Check if TX is allowed in a given slot
//! assert!(allocator.is_tx_allowed(0, &slots));
//! assert!(!allocator.is_tx_allowed(1, &slots));
//! # Ok(())
//! # }
//! ```

use core::cmp::Ordering;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use lichen_link::keys::Seed;
use schnorr48::{derive_keypair, sign, verify};

use crate::trust::{verify_gateway_message, verify_iid_binding, SIGNATURE_LEN};

/// Absolute number of slots accepted in one superframe.
pub const MAX_SLOTS_PER_SUPERFRAME: u32 = 4_096;

/// Absolute number of gateways accepted in a coordination federation.
pub const MAX_COORDINATING_GATEWAYS: usize = 256;

const SLOT_CLAIM_DOMAIN: &[u8] = b"LICHEN-GCP-SLOT-CLAIM-v1";
const SLOT_REPLAY_MAGIC: &[u8; 8] = b"LCHNSRP1";
const SLOT_REPLAY_VERSION: u16 = 1;
const SLOT_REPLAY_SEAL_DOMAIN: &[u8] = b"LICHEN-GCP-SLOT-REPLAY-v1";

/// Slot coordination validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotError {
    InvalidDimensions,
    TooManyGateways,
    InvalidOrdinal,
    InvalidSlot,
    TooManySlots,
    InsufficientSlots,
    DuplicateSlot,
    NonCanonicalSlots,
    DuplicateGateway,
    InvalidSignature,
    IdentityMismatch,
    StaleSuperframe {
        claim: u64,
        current: u64,
    },
    Replay {
        gateway_iid: Iid,
        superframe_id: u64,
    },
    StateFull {
        capacity: usize,
    },
    ArithmeticOverflow,
    TimestampBeforeEpoch,
    MissingState,
    CorruptState,
    IntegrityFailure,
    RollbackDetected {
        stored: u64,
        minimum: u64,
    },
    GenerationExhausted,
    StorageIo(String),
}

impl std::fmt::Display for SlotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SlotError {}

/// Gateway Interface Identifier (IID) - last 8 bytes of link-local IPv6 address.
///
/// Used for conflict resolution: lowest IID (as unsigned big-endian u64) wins.
pub type Iid = [u8; 8];

/// Slot allocation mode per GCP-6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AllocationMode {
    /// Gateway with ordinal N owns slots N, N+G, N+2G... where G = gateway count.
    /// Distributes TX opportunities evenly across the superframe.
    #[default]
    Interleaved,

    /// Each gateway owns a sequential block of slots.
    /// Simpler for handoff since entire blocks can be transferred.
    Contiguous,
}

/// Slot allocator for multi-gateway coordination.
///
/// Computes which TDMA slots belong to each gateway based on the
/// allocation mode and gateway count.
#[derive(Debug, Clone)]
pub struct SlotAllocator {
    mode: AllocationMode,
    slots_per_superframe: u32,
    gateway_count: u32,
}

impl SlotAllocator {
    /// Create a new slot allocator.
    ///
    /// # Arguments
    ///
    /// * `mode` - Interleaved or Contiguous allocation
    /// * `slots_per_superframe` - Total slots in the superframe (e.g., 60)
    /// * `gateway_count` - Number of coordinating gateways (must be >= 1)
    ///
    /// Invalid or resource-exhausting dimensions are rejected.
    pub fn try_new(
        mode: AllocationMode,
        slots_per_superframe: u32,
        gateway_count: u32,
    ) -> Result<Self, SlotError> {
        validate_dimensions(slots_per_superframe, gateway_count)?;
        Ok(Self {
            mode,
            slots_per_superframe,
            gateway_count,
        })
    }

    /// Get the allocation mode.
    pub fn mode(&self) -> AllocationMode {
        self.mode
    }

    /// Get the total slots per superframe.
    pub fn slots_per_superframe(&self) -> u32 {
        self.slots_per_superframe
    }

    /// Get the gateway count.
    pub fn gateway_count(&self) -> u32 {
        self.gateway_count
    }

    /// Allocate slots for a gateway with the given ordinal.
    ///
    /// # Arguments
    ///
    /// * `ordinal` - Gateway ordinal (0-indexed, must be < gateway_count)
    ///
    /// # Returns
    ///
    /// Vector of slot indices owned by this gateway.
    pub fn allocate_for_ordinal(&self, ordinal: u32) -> Result<Vec<u32>, SlotError> {
        if ordinal >= self.gateway_count {
            return Err(SlotError::InvalidOrdinal);
        }
        Ok(match self.mode {
            AllocationMode::Interleaved => self.allocate_interleaved(ordinal),
            AllocationMode::Contiguous => self.allocate_contiguous(ordinal)?,
        })
    }

    /// Allocate slots using interleaved pattern.
    ///
    /// Gateway with ordinal N owns slots N, N+G, N+2G... where G = gateway_count.
    fn allocate_interleaved(&self, ordinal: u32) -> Vec<u32> {
        (ordinal..self.slots_per_superframe)
            .step_by(self.gateway_count as usize)
            .collect()
    }

    /// Allocate slots using contiguous blocks.
    ///
    /// Each gateway owns floor(slots/G) slots, with remainder distributed
    /// to lower ordinals.
    fn allocate_contiguous(&self, ordinal: u32) -> Result<Vec<u32>, SlotError> {
        let base_count = self.slots_per_superframe / self.gateway_count;
        let remainder = self.slots_per_superframe % self.gateway_count;

        let extra_before = ordinal.min(remainder);
        let start = ordinal
            .checked_mul(base_count)
            .and_then(|value| value.checked_add(extra_before))
            .ok_or(SlotError::ArithmeticOverflow)?;

        // This gateway's count
        let count = base_count + if ordinal < remainder { 1 } else { 0 };

        let end = start
            .checked_add(count)
            .ok_or(SlotError::ArithmeticOverflow)?;
        Ok((start..end).collect())
    }

    /// Check if transmission is allowed in the given slot for the given slot map.
    ///
    /// # Arguments
    ///
    /// * `current_slot` - Current slot index in the superframe
    /// * `owned_slots` - Slots owned by this gateway
    ///
    /// # Returns
    ///
    /// `true` if the current slot is in the owned set, `false` otherwise.
    pub fn is_tx_allowed(&self, current_slot: u32, owned_slots: &[u32]) -> bool {
        owned_slots.contains(&current_slot)
    }

    /// Validate that a slot pattern matches the expected interleaved allocation.
    ///
    /// Per GCP-6.2: slots[i] == ordinal + i * gateway_count
    ///
    /// # Returns
    ///
    /// `true` if the pattern is valid, `false` otherwise.
    pub fn validate_interleaved_pattern(&self, ordinal: u32, slots: &[u32]) -> bool {
        if ordinal >= self.gateway_count
            || slots.len() > self.slots_per_superframe as usize
            || slots.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return false;
        }
        for (i, &slot) in slots.iter().enumerate() {
            let Some(expected) = u32::try_from(i)
                .ok()
                .and_then(|index| index.checked_mul(self.gateway_count))
                .and_then(|offset| ordinal.checked_add(offset))
            else {
                return false;
            };
            if slot != expected {
                return false;
            }
            // Also check that slot is within bounds
            if slot >= self.slots_per_superframe {
                return false;
            }
        }
        true
    }

    /// Get the ordinal that owns a specific slot in interleaved mode.
    ///
    /// # Returns
    ///
    /// Gateway ordinal (0-indexed) that owns this slot.
    pub fn slot_owner_interleaved(&self, slot: u32) -> Result<u32, SlotError> {
        if slot >= self.slots_per_superframe {
            return Err(SlotError::InvalidSlot);
        }
        Ok(slot % self.gateway_count)
    }

    /// Get the ordinal that owns a specific slot in contiguous mode.
    ///
    /// # Returns
    ///
    /// Gateway ordinal (0-indexed) that owns this slot.
    pub fn slot_owner_contiguous(&self, slot: u32) -> Result<u32, SlotError> {
        if slot >= self.slots_per_superframe {
            return Err(SlotError::InvalidSlot);
        }
        let base_count = self.slots_per_superframe / self.gateway_count;
        let remainder = self.slots_per_superframe % self.gateway_count;

        // Find which gateway owns this slot
        let mut boundary = 0u32;
        for ordinal in 0..self.gateway_count {
            let count = base_count + if ordinal < remainder { 1 } else { 0 };
            boundary = boundary
                .checked_add(count)
                .ok_or(SlotError::ArithmeticOverflow)?;
            if slot < boundary {
                return Ok(ordinal);
            }
        }
        Err(SlotError::InvalidSlot)
    }

    /// Get the owner of a specific slot using current allocation mode.
    pub fn slot_owner(&self, slot: u32) -> Result<u32, SlotError> {
        match self.mode {
            AllocationMode::Interleaved => self.slot_owner_interleaved(slot),
            AllocationMode::Contiguous => self.slot_owner_contiguous(slot),
        }
    }
}

fn validate_dimensions(slots_per_superframe: u32, gateway_count: u32) -> Result<(), SlotError> {
    if slots_per_superframe == 0 || gateway_count == 0 {
        return Err(SlotError::InvalidDimensions);
    }
    if slots_per_superframe > MAX_SLOTS_PER_SUPERFRAME {
        return Err(SlotError::TooManySlots);
    }
    if gateway_count as usize > MAX_COORDINATING_GATEWAYS {
        return Err(SlotError::TooManyGateways);
    }
    Ok(())
}

/// Compare two IIDs as unsigned big-endian 64-bit integers.
///
/// Per GCP-6.3: IIDs are compared as unsigned big-endian 64-bit integers.
/// Lowest IID wins conflict resolution.
pub fn compare_iids(a: &Iid, b: &Iid) -> Ordering {
    let a_val = u64::from_be_bytes(*a);
    let b_val = u64::from_be_bytes(*b);
    a_val.cmp(&b_val)
}

/// Convert an IID to its unsigned 64-bit integer value.
pub fn iid_to_u64(iid: &Iid) -> u64 {
    u64::from_be_bytes(*iid)
}

/// Result of a slot conflict resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictResolution {
    /// No conflict exists.
    NoConflict,

    /// Conflict resolved - this claim wins.
    Winner,

    /// Conflict resolved - this claim loses, must reclaim.
    Loser {
        /// Slots that were lost and must be reclaimed.
        lost_slots: Vec<u32>,
    },

    /// Claim rejected because it is not for the current superframe.
    Rejected,
}

/// An untrusted, signed slot claim received from the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSlotClaim {
    gateway_iid: Iid,
    slots: Vec<u32>,
    superframe_id: u64,
    claim_sequence: u32,
    signature: [u8; SIGNATURE_LEN],
}

impl RawSlotClaim {
    /// Validate the structural bounds of an untrusted claim.
    pub fn new(
        gateway_iid: Iid,
        slots: Vec<u32>,
        superframe_id: u64,
        claim_sequence: u32,
        signature: [u8; SIGNATURE_LEN],
        slots_per_superframe: u32,
    ) -> Result<Self, SlotError> {
        validate_claim_slots(&slots, slots_per_superframe)?;
        Ok(Self {
            gateway_iid,
            slots,
            superframe_id,
            claim_sequence,
            signature,
        })
    }

    pub fn gateway_iid(&self) -> &Iid {
        &self.gateway_iid
    }

    pub fn slots(&self) -> &[u32] {
        &self.slots
    }

    pub fn superframe_id(&self) -> u64 {
        self.superframe_id
    }

    pub fn claim_sequence(&self) -> u32 {
        self.claim_sequence
    }
}

/// Opaque capability proving signature, IID binding, freshness, and replay checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSlotClaim {
    gateway_iid: Iid,
    slots: Vec<u32>,
    superframe_id: u64,
    claim_sequence: u32,
}

impl VerifiedSlotClaim {
    pub fn gateway_iid(&self) -> &Iid {
        &self.gateway_iid
    }

    pub fn slots(&self) -> &[u32] {
        &self.slots
    }

    pub fn superframe_id(&self) -> u64 {
        self.superframe_id
    }

    pub fn claim_sequence(&self) -> u32 {
        self.claim_sequence
    }

    pub(crate) fn restore(
        gateway_iid: Iid,
        slots: Vec<u32>,
        superframe_id: u64,
        claim_sequence: u32,
        slots_per_superframe: u32,
    ) -> Result<Self, SlotError> {
        validate_claim_slots(&slots, slots_per_superframe)?;
        Ok(Self {
            gateway_iid,
            slots,
            superframe_id,
            claim_sequence,
        })
    }

    fn overlap_with(&self, other: &Self) -> Vec<u32> {
        let mut overlap = Vec::with_capacity(self.slots.len().min(other.slots.len()));
        let (mut left, mut right) = (0, 0);
        while left < self.slots.len() && right < other.slots.len() {
            match self.slots[left].cmp(&other.slots[right]) {
                Ordering::Less => left += 1,
                Ordering::Greater => right += 1,
                Ordering::Equal => {
                    overlap.push(self.slots[left]);
                    left += 1;
                    right += 1;
                }
            }
        }
        overlap
    }
}

/// Stateful verifier for signed claims and their per-gateway replay high-water.
#[derive(Debug, Clone)]
pub struct SlotClaimVerifier {
    last_seen: HashMap<Iid, (u64, u32)>,
    max_gateways: usize,
    generation: u64,
}

impl SlotClaimVerifier {
    pub fn new_ephemeral(max_gateways: usize) -> Result<Self, SlotError> {
        validate_gateway_capacity(max_gateways)?;
        Ok(Self {
            last_seen: HashMap::with_capacity(max_gateways.min(64)),
            max_gateways,
            generation: 1,
        })
    }

    /// Verify one claim for exactly the current superframe.
    ///
    /// Exact matching rejects both captured old claims and pre-played future
    /// claims. A gateway may re-claim within a superframe only by advancing the
    /// signed `claim_sequence`, preserving the required loser-reclaim flow.
    pub fn verify(
        &mut self,
        claim: RawSlotClaim,
        gateway_pubkey: &[u8; 32],
        current_superframe: u64,
    ) -> Result<VerifiedSlotClaim, SlotError> {
        if claim.superframe_id != current_superframe {
            return Err(SlotError::StaleSuperframe {
                claim: claim.superframe_id,
                current: current_superframe,
            });
        }
        verify_iid_binding(gateway_pubkey, &claim.gateway_iid)
            .map_err(|_| SlotError::IdentityMismatch)?;
        if let Some(previous) = self.last_seen.get(&claim.gateway_iid) {
            if (claim.superframe_id, claim.claim_sequence) <= *previous {
                return Err(SlotError::Replay {
                    gateway_iid: claim.gateway_iid,
                    superframe_id: claim.superframe_id,
                });
            }
        } else if self.last_seen.len() >= self.max_gateways {
            return Err(SlotError::StateFull {
                capacity: self.max_gateways,
            });
        }
        let transcript = slot_claim_transcript(
            &claim.gateway_iid,
            &claim.slots,
            claim.superframe_id,
            claim.claim_sequence,
        )?;
        if !verify_gateway_message(gateway_pubkey, &transcript, &claim.signature) {
            return Err(SlotError::InvalidSignature);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(SlotError::GenerationExhausted)?;
        self.last_seen.insert(
            claim.gateway_iid,
            (claim.superframe_id, claim.claim_sequence),
        );
        Ok(VerifiedSlotClaim {
            gateway_iid: claim.gateway_iid,
            slots: claim.slots,
            superframe_id: claim.superframe_id,
            claim_sequence: claim.claim_sequence,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn snapshot(&self) -> SlotReplaySnapshot {
        let mut entries: Vec<_> = self
            .last_seen
            .iter()
            .map(|(iid, (superframe, sequence))| (*iid, *superframe, *sequence))
            .collect();
        entries.sort_by_key(|(iid, _, _)| *iid);
        SlotReplaySnapshot {
            generation: self.generation,
            max_gateways: self.max_gateways,
            entries,
        }
    }

    pub(crate) fn restore(snapshot: SlotReplaySnapshot) -> Result<Self, SlotError> {
        validate_gateway_capacity(snapshot.max_gateways)?;
        if snapshot.generation == 0 || snapshot.entries.len() > snapshot.max_gateways {
            return Err(SlotError::CorruptState);
        }
        let mut last_seen = HashMap::with_capacity(snapshot.entries.len());
        for (iid, superframe, sequence) in snapshot.entries {
            if last_seen.insert(iid, (superframe, sequence)).is_some() {
                return Err(SlotError::CorruptState);
            }
        }
        Ok(Self {
            last_seen,
            max_gateways: snapshot.max_gateways,
            generation: snapshot.generation,
        })
    }

    pub(crate) fn highwater(&self, iid: &Iid) -> Option<(u64, u32)> {
        self.last_seen.get(iid).copied()
    }

    /// Atomically persist replay high-water state with a Schnorr48 seal.
    pub fn save_atomic(&self, path: &Path, sealing_key: &[u8; 32]) -> Result<(), SlotError> {
        let payload = self.encode_payload()?;
        let seal = slot_replay_seal(&payload, sealing_key);
        let temp_path = slot_replay_temp_path(path, self.generation)?;
        let result = (|| -> Result<(), SlotError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .map_err(|error| SlotError::StorageIo(error.to_string()))?;
            file.write_all(&payload)
                .and_then(|_| file.write_all(&seal))
                .and_then(|_| file.sync_all())
                .map_err(|error| SlotError::StorageIo(error.to_string()))?;
            fs::rename(&temp_path, path)
                .map_err(|error| SlotError::StorageIo(error.to_string()))?;
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| SlotError::StorageIo(error.to_string()))?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    /// Load replay state, rejecting missing, corrupt, forged, or rolled-back data.
    pub fn load(
        path: &Path,
        sealing_key: &[u8; 32],
        minimum_generation: u64,
        configured_capacity: usize,
    ) -> Result<Self, SlotError> {
        validate_gateway_capacity(configured_capacity)?;
        let maximum_len = slot_replay_encoded_len(configured_capacity);
        let mut file = File::open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SlotError::MissingState
            } else {
                SlotError::StorageIo(error.to_string())
            }
        })?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((maximum_len + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| SlotError::StorageIo(error.to_string()))?;
        if bytes.len() > maximum_len || bytes.len() < 8 + 2 + 8 + 4 + 4 + SIGNATURE_LEN {
            return Err(SlotError::CorruptState);
        }
        let payload_len = bytes
            .len()
            .checked_sub(SIGNATURE_LEN)
            .ok_or(SlotError::CorruptState)?;
        let (payload, received_seal) = bytes.split_at(payload_len);
        let received_seal: &[u8; SIGNATURE_LEN] = received_seal
            .try_into()
            .map_err(|_| SlotError::CorruptState)?;
        if !verify_slot_replay_seal(payload, received_seal, sealing_key) {
            return Err(SlotError::IntegrityFailure);
        }
        let mut cursor = SlotCursor::new(payload);
        if cursor.take(8)? != SLOT_REPLAY_MAGIC || cursor.u16()? != SLOT_REPLAY_VERSION {
            return Err(SlotError::CorruptState);
        }
        let generation = cursor.u64()?;
        if generation < minimum_generation {
            return Err(SlotError::RollbackDetected {
                stored: generation,
                minimum: minimum_generation,
            });
        }
        let stored_capacity = cursor.u32()? as usize;
        if stored_capacity != configured_capacity {
            return Err(SlotError::CorruptState);
        }
        let count = cursor.u32()? as usize;
        if count > stored_capacity {
            return Err(SlotError::CorruptState);
        }
        let mut last_seen = HashMap::with_capacity(count);
        for _ in 0..count {
            let iid = cursor.array()?;
            let superframe = cursor.u64()?;
            let sequence = cursor.u32()?;
            if last_seen.insert(iid, (superframe, sequence)).is_some() {
                return Err(SlotError::CorruptState);
            }
        }
        if !cursor.is_empty() {
            return Err(SlotError::CorruptState);
        }
        Ok(Self {
            last_seen,
            max_gateways: configured_capacity,
            generation,
        })
    }

    fn encode_payload(&self) -> Result<Vec<u8>, SlotError> {
        let mut entries: Vec<_> = self.last_seen.iter().collect();
        entries.sort_by_key(|(iid, _)| **iid);
        let mut payload = Vec::with_capacity(slot_replay_encoded_len(entries.len()));
        payload.extend_from_slice(SLOT_REPLAY_MAGIC);
        payload.extend_from_slice(&SLOT_REPLAY_VERSION.to_be_bytes());
        payload.extend_from_slice(&self.generation.to_be_bytes());
        payload.extend_from_slice(&(self.max_gateways as u32).to_be_bytes());
        payload.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (iid, (superframe, sequence)) in entries {
            payload.extend_from_slice(iid);
            payload.extend_from_slice(&superframe.to_be_bytes());
            payload.extend_from_slice(&sequence.to_be_bytes());
        }
        Ok(payload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SlotReplaySnapshot {
    pub generation: u64,
    pub max_gateways: usize,
    pub entries: Vec<(Iid, u64, u32)>,
}

/// Canonical, domain-separated signed transcript for a slot claim.
pub fn slot_claim_transcript(
    gateway_iid: &Iid,
    slots: &[u32],
    superframe_id: u64,
    claim_sequence: u32,
) -> Result<Vec<u8>, SlotError> {
    if slots.len() > MAX_SLOTS_PER_SUPERFRAME as usize {
        return Err(SlotError::TooManySlots);
    }
    if slots.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SlotError::DuplicateSlot);
    }
    if slots.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(SlotError::NonCanonicalSlots);
    }
    let mut transcript =
        Vec::with_capacity(SLOT_CLAIM_DOMAIN.len() + 8 + 8 + 4 + 4 + slots.len() * 4);
    transcript.extend_from_slice(SLOT_CLAIM_DOMAIN);
    transcript.extend_from_slice(gateway_iid);
    transcript.extend_from_slice(&superframe_id.to_be_bytes());
    transcript.extend_from_slice(&claim_sequence.to_be_bytes());
    transcript.extend_from_slice(&(slots.len() as u32).to_be_bytes());
    for slot in slots {
        transcript.extend_from_slice(&slot.to_be_bytes());
    }
    Ok(transcript)
}

fn validate_claim_slots(slots: &[u32], slots_per_superframe: u32) -> Result<(), SlotError> {
    if slots_per_superframe == 0 || slots_per_superframe > MAX_SLOTS_PER_SUPERFRAME {
        return Err(SlotError::InvalidDimensions);
    }
    if slots.len() > slots_per_superframe as usize {
        return Err(SlotError::TooManySlots);
    }
    if slots.iter().any(|slot| *slot >= slots_per_superframe) {
        return Err(SlotError::InvalidSlot);
    }
    if slots.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SlotError::DuplicateSlot);
    }
    if slots.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(SlotError::NonCanonicalSlots);
    }
    Ok(())
}

fn validate_gateway_capacity(capacity: usize) -> Result<(), SlotError> {
    if capacity == 0 || capacity > MAX_COORDINATING_GATEWAYS {
        Err(SlotError::TooManyGateways)
    } else {
        Ok(())
    }
}

fn slot_replay_encoded_len(entries: usize) -> usize {
    8 + 2 + 8 + 4 + 4 + entries.saturating_mul(8 + 8 + 4) + SIGNATURE_LEN
}

fn slot_replay_transcript(payload: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(SLOT_REPLAY_SEAL_DOMAIN.len() + payload.len());
    transcript.extend_from_slice(SLOT_REPLAY_SEAL_DOMAIN);
    transcript.extend_from_slice(payload);
    transcript
}

fn slot_replay_seal(payload: &[u8], sealing_seed: &[u8; 32]) -> [u8; SIGNATURE_LEN] {
    let (private, public) = derive_keypair(&Seed::new(*sealing_seed));
    sign(&private, &public, &slot_replay_transcript(payload))
}

fn verify_slot_replay_seal(
    payload: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    sealing_seed: &[u8; 32],
) -> bool {
    let (_, public) = derive_keypair(&Seed::new(*sealing_seed));
    verify(&public, &slot_replay_transcript(payload), signature)
}

fn slot_replay_temp_path(path: &Path, generation: u64) -> Result<PathBuf, SlotError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| SlotError::StorageIo("replay-state path has no UTF-8 file name".into()))?;
    Ok(path.with_file_name(format!(".{name}.tmp-{}-{generation}", std::process::id())))
}

struct SlotCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SlotCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SlotError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SlotError::CorruptState)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SlotError::CorruptState)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SlotError> {
        self.take(N)?
            .try_into()
            .map_err(|_| SlotError::CorruptState)
    }

    fn u16(&mut self) -> Result<u16, SlotError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, SlotError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, SlotError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Resolve a conflict between two slot claims per GCP-6.3.
///
/// Rules:
/// 1. Claims with invalid or missing signatures MUST be silently discarded.
/// 2. If both signatures verify, lowest IID MUST win.
/// 3. If one signature fails and one succeeds, valid claim wins.
///
/// # Arguments
///
/// * `our_claim` - Our gateway's claim
/// * `their_claim` - Other gateway's claim
///
/// # Returns
///
/// Resolution result from our perspective.
pub fn resolve_conflict(
    our_claim: &VerifiedSlotClaim,
    their_claim: &VerifiedSlotClaim,
    current_superframe: u64,
) -> ConflictResolution {
    if our_claim.superframe_id != current_superframe
        || their_claim.superframe_id != current_superframe
    {
        return ConflictResolution::Rejected;
    }
    // Check for overlapping slots
    let overlap = our_claim.overlap_with(their_claim);
    if overlap.is_empty() {
        return ConflictResolution::NoConflict;
    }

    // Both capabilities have already passed signature, IID, and replay checks.
    match compare_iids(&our_claim.gateway_iid, &their_claim.gateway_iid) {
        Ordering::Less => ConflictResolution::Winner,
        Ordering::Greater => ConflictResolution::Loser {
            lost_slots: overlap,
        },
        Ordering::Equal => {
            // Same IID - should not happen in practice
            // Tie-breaker: first claim wins (we lose if processing their claim)
            ConflictResolution::Loser {
                lost_slots: overlap,
            }
        }
    }
}

/// Find the next available slots after losing a conflict.
///
/// Per GCP-6.3: Loser MUST select next available slot and re-claim.
///
/// # Arguments
///
/// * `lost_slots` - Slots we lost
/// * `occupied_slots` - All currently occupied slots
/// * `slots_per_superframe` - Total slots in superframe
///
/// # Returns
///
/// Vector of replacement slot indices (same count as lost_slots).
pub fn find_next_available(
    lost_count: usize,
    occupied_slots: &[u32],
    slots_per_superframe: u32,
) -> Result<Vec<u32>, SlotError> {
    if slots_per_superframe == 0 || slots_per_superframe > MAX_SLOTS_PER_SUPERFRAME {
        return Err(SlotError::InvalidDimensions);
    }
    if lost_count > slots_per_superframe as usize
        || occupied_slots.len() > slots_per_superframe as usize
    {
        return Err(SlotError::TooManySlots);
    }
    if lost_count == 0 {
        return Ok(Vec::new());
    }
    let mut occupied = vec![false; slots_per_superframe as usize];
    for slot in occupied_slots {
        let Some(value) = occupied.get_mut(*slot as usize) else {
            return Err(SlotError::InvalidSlot);
        };
        if *value {
            return Err(SlotError::DuplicateSlot);
        }
        *value = true;
    }
    let mut available = Vec::new();
    for (slot, is_occupied) in occupied.into_iter().enumerate() {
        if !is_occupied {
            available.push(slot as u32);
            if available.len() >= lost_count {
                break;
            }
        }
    }
    if available.len() != lost_count {
        return Err(SlotError::InsufficientSlots);
    }
    Ok(available)
}

/// Gateway ordinal assignment based on IID.
///
/// Per GCP-6.1: Non-GPS time master election uses lowest IID.
/// Same principle applies to ordinal assignment for slot allocation.
pub fn assign_ordinals(iids: &[Iid]) -> Result<Vec<(Iid, u32)>, SlotError> {
    if iids.len() > MAX_COORDINATING_GATEWAYS {
        return Err(SlotError::TooManyGateways);
    }
    let mut sorted: Vec<Iid> = iids.to_vec();
    sorted.sort_by(compare_iids);
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SlotError::DuplicateGateway);
    }

    Ok(sorted
        .into_iter()
        .enumerate()
        .map(|(ordinal, iid)| (iid, ordinal as u32))
        .collect())
}

/// Calculate current slot within superframe from timestamp.
///
/// Per GCP-6.1, scale elapsed time within the superframe by the configured
/// slot count; slots need not be one second long.
pub fn current_slot_from_timestamp(
    timestamp_unix: u64,
    superframe_duration_s: u32,
    superframe_start_unix: u64,
    slots_per_superframe: u32,
) -> Result<u32, SlotError> {
    validate_dimensions(slots_per_superframe, 1)?;
    if superframe_duration_s == 0 {
        return Err(SlotError::InvalidDimensions);
    }
    let elapsed = timestamp_unix
        .checked_sub(superframe_start_unix)
        .ok_or(SlotError::TimestampBeforeEpoch)?;
    let within = elapsed % u64::from(superframe_duration_s);
    Ok(
        ((u128::from(within) * u128::from(slots_per_superframe))
            / u128::from(superframe_duration_s)) as u32,
    )
}

/// Calculate superframe ID from timestamp.
///
/// Per GCP-6.1: superframe_id = unix_timestamp / superframe_duration_s
pub fn superframe_id_from_timestamp(
    timestamp_unix: u64,
    superframe_duration_s: u32,
) -> Result<u64, SlotError> {
    if superframe_duration_s == 0 {
        return Err(SlotError::InvalidDimensions);
    }
    Ok(timestamp_unix / u64::from(superframe_duration_s))
}

/// Calculate superframe start time from superframe ID.
pub fn superframe_start_from_id(
    superframe_id: u64,
    superframe_duration_s: u32,
) -> Result<u64, SlotError> {
    if superframe_duration_s == 0 {
        return Err(SlotError::InvalidDimensions);
    }
    superframe_id
        .checked_mul(u64::from(superframe_duration_s))
        .ok_or(SlotError::ArithmeticOverflow)
}

/// Calculate slots remaining in current superframe.
pub fn slots_remaining(current_slot: u32, slots_per_superframe: u32) -> Result<u32, SlotError> {
    if slots_per_superframe == 0
        || slots_per_superframe > MAX_SLOTS_PER_SUPERFRAME
        || current_slot >= slots_per_superframe
    {
        return Err(SlotError::InvalidDimensions);
    }
    Ok(slots_per_superframe - current_slot - 1)
}

// ─── GCP-6.1 Superframe Synchronization ─────────────────────────────────────

/// Time source for superframe synchronization (GCP-6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    /// GPS-equipped gateway provides absolute time reference.
    Gps,
    /// Non-GPS: time master elected by lowest IID.
    BackboneElect,
    /// Synced from another gateway via backbone CoAP.
    BackboneSync,
    /// Local clock (unsynchronized).
    Local,
}

impl TimeSource {
    /// Convert to string for CBOR/JSON encoding.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gps => "gps",
            Self::BackboneElect => "backbone_elect",
            Self::BackboneSync => "backbone_sync",
            Self::Local => "local",
        }
    }
}

/// Superframe timing configuration (GCP-6.1).
///
/// Per spec 08-gateway-coordination.md Section 6.1:
/// - GPS-equipped gateways use GPS epoch for absolute time
/// - Non-GPS: elect time master (lowest IID wins)
/// - Superframe duration configurable (default 60 seconds, aligned to UTC)
#[derive(Debug, Clone)]
pub struct SuperframeConfig {
    /// Superframe duration in seconds.
    duration_s: u32,
    /// Number of slots per superframe.
    slots_per_superframe: u32,
    /// Time source for this gateway.
    time_source: TimeSource,
    /// Superframe epoch (Unix timestamp of superframe 0 start).
    epoch: u64,
}

impl Default for SuperframeConfig {
    fn default() -> Self {
        Self::new(TimeSource::Local, 0)
    }
}

impl SuperframeConfig {
    /// Create a new superframe config.
    ///
    /// Default: 60-second superframe with 60 slots (1 second per slot).
    pub fn new(time_source: TimeSource, epoch: u64) -> Self {
        Self {
            duration_s: 60,
            slots_per_superframe: 60,
            time_source,
            epoch,
        }
    }

    /// Create a validated custom superframe configuration.
    pub fn try_new(
        duration_s: u32,
        slots_per_superframe: u32,
        time_source: TimeSource,
        epoch: u64,
    ) -> Result<Self, SlotError> {
        if duration_s == 0 {
            return Err(SlotError::InvalidDimensions);
        }
        validate_dimensions(slots_per_superframe, 1)?;
        Ok(Self {
            duration_s,
            slots_per_superframe,
            time_source,
            epoch,
        })
    }

    pub fn duration_s(&self) -> u32 {
        self.duration_s
    }

    pub fn slots_per_superframe(&self) -> u32 {
        self.slots_per_superframe
    }

    pub fn time_source(&self) -> TimeSource {
        self.time_source
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Compute this configured schedule's epoch-relative superframe index.
    ///
    /// This is `(unix_timestamp - epoch) / duration`, saturating to zero for
    /// pre-epoch timestamps. Use [`superframe_id_from_timestamp`] for the
    /// canonical absolute GCP superframe ID used in signed claim freshness.
    pub fn superframe_id(&self, timestamp: u64) -> u64 {
        timestamp.saturating_sub(self.epoch) / self.duration_s as u64
    }

    /// Compute current slot within superframe from Unix timestamp.
    pub fn current_slot(&self, timestamp: u64) -> u32 {
        let elapsed = timestamp.saturating_sub(self.epoch);
        let within = elapsed % self.duration_s as u64;
        ((u128::from(within) * u128::from(self.slots_per_superframe)) / u128::from(self.duration_s))
            as u32
    }

    /// Compute slots remaining in current superframe.
    pub fn slots_remaining(&self, timestamp: u64) -> u32 {
        let current = self.current_slot(timestamp);
        self.slots_per_superframe - current - 1
    }
}

/// Candidate for time master election (GCP-6.1).
///
/// Per spec: GPS-equipped gateways take precedence, then lowest IID wins.
#[derive(Debug, Clone)]
pub struct TimeMasterCandidate {
    /// Gateway IID.
    pub iid: Iid,
    /// Whether this gateway has GPS.
    pub has_gps: bool,
}

/// Elect time master from candidates (GCP-6.1).
///
/// Rules:
/// 1. GPS-equipped gateways take precedence
/// 2. Among equals, lowest IID wins
pub fn elect_time_master(candidates: &[TimeMasterCandidate]) -> Option<&TimeMasterCandidate> {
    candidates
        .iter()
        .filter(|candidate| candidate.has_gps)
        .min_by_key(|candidate| iid_to_u64(&candidate.iid))
        .or_else(|| {
            candidates
                .iter()
                .min_by_key(|candidate| iid_to_u64(&candidate.iid))
        })
}

// ─── GCP-6.4 CoAP Resource Structures ───────────────────────────────────────

/// Slot allocation map for all gateways in federation.
///
/// This is the response format for GET /.well-known/lichen-gw/slots.
#[derive(Debug, Clone)]
pub struct SlotAllocationMap {
    /// Allocation mode used.
    mode: AllocationMode,
    /// Total gateways in federation.
    gateway_count: u32,
    /// Current superframe ID.
    superframe_id: u64,
    slots_per_superframe: u32,
    /// Map from gateway IID to owned slots.
    allocations: Vec<(Iid, Vec<u32>)>,
}

impl SlotAllocationMap {
    /// Create a new allocation map.
    pub fn new(
        mode: AllocationMode,
        gateway_count: u32,
        superframe_id: u64,
        slots_per_superframe: u32,
    ) -> Result<Self, SlotError> {
        validate_dimensions(slots_per_superframe, gateway_count)?;
        Ok(Self {
            mode,
            gateway_count,
            superframe_id,
            slots_per_superframe,
            allocations: Vec::new(),
        })
    }

    /// Add or update allocation for a gateway.
    pub fn set_allocation(&mut self, iid: Iid, slots: Vec<u32>) -> Result<(), SlotError> {
        validate_claim_slots(&slots, self.slots_per_superframe)?;
        if let Some(entry) = self.allocations.iter_mut().find(|(i, _)| *i == iid) {
            entry.1 = slots;
        } else {
            if self.allocations.len() >= self.gateway_count as usize {
                return Err(SlotError::StateFull {
                    capacity: self.gateway_count as usize,
                });
            }
            self.allocations.push((iid, slots));
        }
        Ok(())
    }

    /// Get allocation for a gateway.
    pub fn get_allocation(&self, iid: &Iid) -> Option<&[u32]> {
        self.allocations
            .iter()
            .find(|(i, _)| i == iid)
            .map(|(_, slots)| slots.as_slice())
    }

    pub fn mode(&self) -> AllocationMode {
        self.mode
    }

    pub fn gateway_count(&self) -> u32 {
        self.gateway_count
    }

    pub fn superframe_id(&self) -> u64 {
        self.superframe_id
    }

    pub fn allocations(&self) -> &[(Iid, Vec<u32>)] {
        &self.allocations
    }
}

/// Channel ownership map.
///
/// This is the response format for GET /.well-known/lichen-gw/channels.
#[derive(Debug, Clone, Default)]
pub struct ChannelMap {
    /// Map from channel ID to owning gateway IID.
    pub channels: Vec<(u8, Iid)>,
}

impl ChannelMap {
    /// Create a new empty channel map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set channel ownership.
    pub fn set_owner(&mut self, channel: u8, iid: Iid) {
        if let Some(entry) = self.channels.iter_mut().find(|(c, _)| *c == channel) {
            entry.1 = iid;
        } else {
            self.channels.push((channel, iid));
        }
    }

    /// Get channel owner.
    pub fn get_owner(&self, channel: u8) -> Option<&Iid> {
        self.channels
            .iter()
            .find(|(c, _)| *c == channel)
            .map(|(_, iid)| iid)
    }
}

/// Gateway info response for GET /.well-known/lichen-gw/info.
#[derive(Debug, Clone)]
pub struct GatewayInfo {
    /// Gateway IID.
    pub gateway_iid: Iid,
    /// Superframe duration in seconds.
    pub superframe_duration_s: u32,
    /// Superframe epoch (Unix timestamp).
    pub superframe_epoch: u64,
    /// Time source.
    pub time_source: TimeSource,
    /// Total slots per superframe.
    pub slots_total: u32,
    /// This gateway's allocated slots.
    pub allocated_slots: Vec<u32>,
}

/// Slot grant response for POST /.well-known/lichen-gw/slots.
#[derive(Debug, Clone)]
pub struct SlotGrantResponse {
    /// Slots that were granted.
    pub granted_slots: Vec<u32>,
    /// Superframe ID when grant was made.
    pub superframe_id: u64,
    /// Unix timestamp when grant expires.
    pub valid_until: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static TEST_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn verified_claim(
        seed_bytes: [u8; 32],
        slots: Vec<u32>,
        superframe: u64,
        slots_per_superframe: u32,
        verifier: &mut SlotClaimVerifier,
    ) -> VerifiedSlotClaim {
        let (raw, pubkey) = signed_raw_claim(seed_bytes, slots, superframe, slots_per_superframe);
        verifier.verify(raw, &pubkey, superframe).unwrap()
    }

    fn signed_raw_claim(
        seed_bytes: [u8; 32],
        slots: Vec<u32>,
        superframe: u64,
        slots_per_superframe: u32,
    ) -> (RawSlotClaim, [u8; 32]) {
        signed_raw_claim_with_sequence(seed_bytes, slots, superframe, 0, slots_per_superframe)
    }

    fn signed_raw_claim_with_sequence(
        seed_bytes: [u8; 32],
        mut slots: Vec<u32>,
        superframe: u64,
        claim_sequence: u32,
        slots_per_superframe: u32,
    ) -> (RawSlotClaim, [u8; 32]) {
        slots.sort_unstable();
        let (private, public) = derive_keypair(&Seed::new(seed_bytes));
        let pubkey = *public.as_bytes();
        let iid = crate::trust::iid_from_pubkey(&pubkey);
        let transcript = slot_claim_transcript(&iid, &slots, superframe, claim_sequence).unwrap();
        let signature = sign(&private, &public, &transcript);
        let raw = RawSlotClaim::new(
            iid,
            slots,
            superframe,
            claim_sequence,
            signature,
            slots_per_superframe,
        )
        .unwrap();
        (raw, pubkey)
    }

    fn test_replay_path(label: &str) -> PathBuf {
        let sequence = TEST_PATH_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
        std::env::temp_dir().join(format!(
            "lichen-slot-replay-{label}-{}-{sequence}.bin",
            std::process::id()
        ))
    }

    // Test vectors from gcp6_slot_coordination.json

    #[test]
    fn interleaved_3gw_15slots() {
        // From vector "slot_allocation_interleaved_3gw"
        let allocator = SlotAllocator::try_new(AllocationMode::Interleaved, 15, 3).unwrap();

        let gw0_slots = allocator.allocate_for_ordinal(0).unwrap();
        let gw1_slots = allocator.allocate_for_ordinal(1).unwrap();
        let gw2_slots = allocator.allocate_for_ordinal(2).unwrap();

        assert_eq!(gw0_slots, vec![0, 3, 6, 9, 12]);
        assert_eq!(gw1_slots, vec![1, 4, 7, 10, 13]);
        assert_eq!(gw2_slots, vec![2, 5, 8, 11, 14]);
    }

    #[test]
    fn contiguous_3gw_60slots() {
        // From vector "slot_allocation_contiguous_blocks"
        let allocator = SlotAllocator::try_new(AllocationMode::Contiguous, 60, 3).unwrap();

        let gw0_slots = allocator.allocate_for_ordinal(0).unwrap();
        let gw1_slots = allocator.allocate_for_ordinal(1).unwrap();
        let gw2_slots = allocator.allocate_for_ordinal(2).unwrap();

        // Each gateway gets 20 slots
        assert_eq!(gw0_slots.len(), 20);
        assert_eq!(gw1_slots.len(), 20);
        assert_eq!(gw2_slots.len(), 20);

        assert_eq!(gw0_slots[0], 0);
        assert_eq!(gw0_slots[19], 19);

        assert_eq!(gw1_slots[0], 20);
        assert_eq!(gw1_slots[19], 39);

        assert_eq!(gw2_slots[0], 40);
        assert_eq!(gw2_slots[19], 59);
    }

    #[test]
    fn tx_allowed_check() {
        // From vector "tx_allowed_check"
        let allocator = SlotAllocator::try_new(AllocationMode::Interleaved, 15, 3).unwrap();
        let slot_map = vec![0, 3, 6, 9, 12];

        assert!(allocator.is_tx_allowed(0, &slot_map));
        assert!(!allocator.is_tx_allowed(1, &slot_map));
        assert!(!allocator.is_tx_allowed(2, &slot_map));
        assert!(allocator.is_tx_allowed(3, &slot_map));
        assert!(allocator.is_tx_allowed(6, &slot_map));
        assert!(!allocator.is_tx_allowed(7, &slot_map));
        assert!(allocator.is_tx_allowed(12, &slot_map));
        assert!(!allocator.is_tx_allowed(14, &slot_map));
    }

    #[test]
    fn interleaved_pattern_validation() {
        // From vector "interleaved_pattern_validation"
        let allocator = SlotAllocator::try_new(AllocationMode::Interleaved, 15, 3).unwrap();

        // Valid patterns
        assert!(allocator.validate_interleaved_pattern(0, &[0, 3, 6, 9, 12]));
        assert!(allocator.validate_interleaved_pattern(1, &[1, 4, 7, 10, 13]));

        // Invalid: wrong start slot
        assert!(!allocator.validate_interleaved_pattern(0, &[1, 4, 7]));

        // Invalid: wrong spacing
        assert!(!allocator.validate_interleaved_pattern(0, &[0, 2, 4]));
    }

    #[test]
    fn iid_comparison() {
        // From vector "iid_comparison_unsigned_bigendian"

        // Case 1: 0x0000000000000001 < 0x0000000000000002
        let iid_a: Iid = [0, 0, 0, 0, 0, 0, 0, 1];
        let iid_b: Iid = [0, 0, 0, 0, 0, 0, 0, 2];
        assert_eq!(compare_iids(&iid_a, &iid_b), Ordering::Less);

        // Case 2: 0x0011223344556677 < 0xaabbccddeeff0011
        let iid_a: Iid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let iid_b: Iid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
        assert_eq!(compare_iids(&iid_a, &iid_b), Ordering::Less);
        assert_eq!(iid_to_u64(&iid_a), 4822678189205111);
        // Note: test vector JSON has incorrect decimal (12302652060662325265)
        // Correct value for 0xaabbccddeeff0011:
        assert_eq!(iid_to_u64(&iid_b), 0xaabbccddeeff0011);

        // Case 3: 0xffffffffffffffff > 0x0000000000000001
        let iid_a: Iid = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let iid_b: Iid = [0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(compare_iids(&iid_a, &iid_b), Ordering::Greater);
    }

    #[test]
    fn conflict_resolution_both_valid_lowest_wins() {
        let mut verifier = SlotClaimVerifier::new_ephemeral(4).unwrap();
        let claim_a = verified_claim([1; 32], vec![5, 6, 7], 1000, 60, &mut verifier);
        let claim_b = verified_claim([2; 32], vec![5, 6, 7], 1000, 60, &mut verifier);
        let (lower, higher) =
            if compare_iids(claim_a.gateway_iid(), claim_b.gateway_iid()) == Ordering::Less {
                (&claim_a, &claim_b)
            } else {
                (&claim_b, &claim_a)
            };

        let result = resolve_conflict(lower, higher, 1000);
        assert_eq!(result, ConflictResolution::Winner);

        let result = resolve_conflict(higher, lower, 1000);
        match result {
            ConflictResolution::Loser { lost_slots } => {
                assert_eq!(lost_slots, vec![5, 6, 7]);
            }
            _ => panic!("Expected Loser"),
        }
    }

    #[test]
    fn invalid_signature_cannot_create_verified_claim() {
        let (_, public) = derive_keypair(&Seed::new([3; 32]));
        let pubkey = *public.as_bytes();
        let iid = crate::trust::iid_from_pubkey(&pubkey);
        let raw = RawSlotClaim::new(iid, vec![5, 6, 7], 1000, 0, [0; 48], 60).unwrap();
        let mut verifier = SlotClaimVerifier::new_ephemeral(4).unwrap();
        assert_eq!(
            verifier.verify(raw, &pubkey, 1000),
            Err(SlotError::InvalidSignature)
        );
    }

    #[test]
    fn find_next_available_slots() {
        // From vector "conflict_resolution_loser_must_reclaim"
        let occupied = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let replacement = find_next_available(3, &occupied, 15).unwrap();
        assert_eq!(replacement, vec![8, 9, 10]);
    }

    #[test]
    fn find_next_available_rejects_partial_replacement() {
        assert_eq!(
            find_next_available(2, &[0, 1, 2], 4),
            Err(SlotError::InsufficientSlots)
        );
    }

    #[test]
    fn superframe_timing() {
        // From vector "superframe_sync_gps_epoch"
        let gps_epoch_unix = 1720008000u64;
        let superframe_duration_s = 60u32;

        let superframe_id =
            superframe_id_from_timestamp(gps_epoch_unix, superframe_duration_s).unwrap();
        assert_eq!(superframe_id, 28666800);

        // From vector "superframe_slot_timing"
        let test_timestamp = 1720008025u64;
        let superframe_start = 1720008000u64;
        let current_slot = current_slot_from_timestamp(
            test_timestamp,
            superframe_duration_s,
            superframe_start,
            60,
        )
        .unwrap();
        assert_eq!(current_slot, 25);

        let remaining = slots_remaining(current_slot, 60).unwrap();
        assert_eq!(remaining, 34); // 60 - 25 - 1 = 34
    }

    #[test]
    fn time_master_election() {
        // From vector "superframe_sync_time_master_election"
        let iids: Vec<Iid> = vec![
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
            [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
        ];

        let ordinals = assign_ordinals(&iids).unwrap();

        // Lowest IID should be ordinal 0 (time master)
        let expected_lowest: Iid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        assert_eq!(ordinals[0].0, expected_lowest);
        assert_eq!(ordinals[0].1, 0);
    }

    #[test]
    fn slot_owner_interleaved() {
        let allocator = SlotAllocator::try_new(AllocationMode::Interleaved, 15, 3).unwrap();

        assert_eq!(allocator.slot_owner(0).unwrap(), 0);
        assert_eq!(allocator.slot_owner(1).unwrap(), 1);
        assert_eq!(allocator.slot_owner(2).unwrap(), 2);
        assert_eq!(allocator.slot_owner(3).unwrap(), 0);
        assert_eq!(allocator.slot_owner(4).unwrap(), 1);
        assert_eq!(allocator.slot_owner(14).unwrap(), 2);
    }

    #[test]
    fn slot_owner_contiguous() {
        let allocator = SlotAllocator::try_new(AllocationMode::Contiguous, 60, 3).unwrap();

        assert_eq!(allocator.slot_owner(0).unwrap(), 0);
        assert_eq!(allocator.slot_owner(19).unwrap(), 0);
        assert_eq!(allocator.slot_owner(20).unwrap(), 1);
        assert_eq!(allocator.slot_owner(39).unwrap(), 1);
        assert_eq!(allocator.slot_owner(40).unwrap(), 2);
        assert_eq!(allocator.slot_owner(59).unwrap(), 2);
    }

    #[test]
    fn contiguous_uneven_distribution() {
        // 10 slots among 3 gateways: 4, 3, 3
        let allocator = SlotAllocator::try_new(AllocationMode::Contiguous, 10, 3).unwrap();

        let gw0_slots = allocator.allocate_for_ordinal(0).unwrap();
        let gw1_slots = allocator.allocate_for_ordinal(1).unwrap();
        let gw2_slots = allocator.allocate_for_ordinal(2).unwrap();

        assert_eq!(gw0_slots, vec![0, 1, 2, 3]); // 4 slots (gets remainder)
        assert_eq!(gw1_slots, vec![4, 5, 6]); // 3 slots
        assert_eq!(gw2_slots, vec![7, 8, 9]); // 3 slots

        // Verify ownership
        assert_eq!(allocator.slot_owner(3).unwrap(), 0);
        assert_eq!(allocator.slot_owner(4).unwrap(), 1);
        assert_eq!(allocator.slot_owner(7).unwrap(), 2);
    }

    #[test]
    fn hostile_dimensions_and_ordinals_are_rejected_without_panics() {
        assert!(matches!(
            SlotAllocator::try_new(AllocationMode::Interleaved, 0, 1),
            Err(SlotError::InvalidDimensions)
        ));
        assert!(matches!(
            SlotAllocator::try_new(AllocationMode::Interleaved, 1, 0),
            Err(SlotError::InvalidDimensions)
        ));
        assert!(matches!(
            SlotAllocator::try_new(AllocationMode::Interleaved, MAX_SLOTS_PER_SUPERFRAME + 1, 1),
            Err(SlotError::TooManySlots)
        ));
        let allocator = SlotAllocator::try_new(AllocationMode::Contiguous, 60, 3).unwrap();
        assert_eq!(
            allocator.allocate_for_ordinal(u32::MAX),
            Err(SlotError::InvalidOrdinal)
        );
        assert_eq!(allocator.slot_owner(60), Err(SlotError::InvalidSlot));
        assert_eq!(
            current_slot_from_timestamp(1, 0, 0, 60),
            Err(SlotError::InvalidDimensions)
        );
        assert_eq!(
            current_slot_from_timestamp(9, 60, 10, 240),
            Err(SlotError::TimestampBeforeEpoch)
        );
        assert_eq!(current_slot_from_timestamp(25, 60, 10, 240), Ok(60));
        assert_eq!(
            superframe_id_from_timestamp(1, 0),
            Err(SlotError::InvalidDimensions)
        );
        assert_eq!(
            superframe_start_from_id(u64::MAX, 2),
            Err(SlotError::ArithmeticOverflow)
        );
        assert!(matches!(
            SuperframeConfig::try_new(0, 60, TimeSource::Local, 0),
            Err(SlotError::InvalidDimensions)
        ));
    }

    #[test]
    fn claims_reject_duplicates_out_of_range_and_max_plus_one() {
        let iid = [1; 8];
        assert_eq!(
            RawSlotClaim::new(iid, vec![1, 1], 7, 0, [0; 48], 60),
            Err(SlotError::DuplicateSlot)
        );
        assert_eq!(
            RawSlotClaim::new(iid, vec![2, 1], 7, 0, [0; 48], 60),
            Err(SlotError::NonCanonicalSlots)
        );
        assert_eq!(
            RawSlotClaim::new(iid, vec![60], 7, 0, [0; 48], 60),
            Err(SlotError::InvalidSlot)
        );
        assert_eq!(
            RawSlotClaim::new(
                iid,
                vec![0; MAX_SLOTS_PER_SUPERFRAME as usize + 1],
                7,
                0,
                [0; 48],
                MAX_SLOTS_PER_SUPERFRAME
            ),
            Err(SlotError::TooManySlots)
        );
    }

    #[test]
    fn old_future_and_duplicate_superframe_claims_are_rejected() {
        let mut verifier = SlotClaimVerifier::new_ephemeral(4).unwrap();
        let (old, pubkey) = signed_raw_claim([31; 32], vec![1], 9, 60);
        assert!(matches!(
            verifier.verify(old, &pubkey, 10),
            Err(SlotError::StaleSuperframe {
                claim: 9,
                current: 10
            })
        ));
        let (future, pubkey) = signed_raw_claim([31; 32], vec![1], 11, 60);
        assert!(matches!(
            verifier.verify(future, &pubkey, 10),
            Err(SlotError::StaleSuperframe {
                claim: 11,
                current: 10
            })
        ));
        let (first, pubkey) = signed_raw_claim([31; 32], vec![1], 10, 60);
        verifier.verify(first, &pubkey, 10).unwrap();
        let (replay, pubkey) = signed_raw_claim([31; 32], vec![1], 10, 60);
        assert!(matches!(
            verifier.verify(replay, &pubkey, 10),
            Err(SlotError::Replay { .. })
        ));
        let (replacement, pubkey) = signed_raw_claim_with_sequence([31; 32], vec![2], 10, 1, 60);
        let replacement = verifier.verify(replacement, &pubkey, 10).unwrap();
        assert_eq!(replacement.claim_sequence(), 1);
        assert_eq!(replacement.slots(), &[2]);
    }

    #[test]
    fn claim_signature_binds_slots_identity_and_superframe() {
        let (raw, pubkey) = signed_raw_claim([32; 32], vec![1, 2], 10, 60);
        let mut verifier = SlotClaimVerifier::new_ephemeral(4).unwrap();
        verifier.verify(raw, &pubkey, 10).unwrap();

        let (signed, pubkey) = signed_raw_claim([32; 32], vec![1, 2], 11, 60);
        let tampered = RawSlotClaim::new(
            *signed.gateway_iid(),
            vec![1, 3],
            11,
            signed.claim_sequence(),
            signed.signature,
            60,
        )
        .unwrap();
        assert_eq!(
            verifier.verify(tampered, &pubkey, 11),
            Err(SlotError::InvalidSignature)
        );
    }

    #[test]
    fn replay_highwater_survives_restart_and_rejects_rollback() {
        let path = test_replay_path("restart");
        let sealing_seed = [0x61; 32];
        let mut verifier = SlotClaimVerifier::new_ephemeral(4).unwrap();
        let (first, pubkey) = signed_raw_claim([33; 32], vec![1], 10, 60);
        verifier.verify(first, &pubkey, 10).unwrap();
        let generation = verifier.generation();
        verifier.save_atomic(&path, &sealing_seed).unwrap();

        let mut loaded = SlotClaimVerifier::load(&path, &sealing_seed, generation, 4).unwrap();
        let (replay, pubkey) = signed_raw_claim([33; 32], vec![1], 10, 60);
        assert!(matches!(
            loaded.verify(replay, &pubkey, 10),
            Err(SlotError::Replay { .. })
        ));
        assert!(matches!(
            SlotClaimVerifier::load(&path, &sealing_seed, generation + 1, 4),
            Err(SlotError::RollbackDetected { .. })
        ));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn replay_state_rejects_corruption_and_capacity_flood() {
        let path = test_replay_path("corrupt");
        let sealing_seed = [0x62; 32];
        let mut verifier = SlotClaimVerifier::new_ephemeral(1).unwrap();
        let (first, first_key) = signed_raw_claim([34; 32], vec![1], 10, 60);
        verifier.verify(first, &first_key, 10).unwrap();
        let (second, second_key) = signed_raw_claim([35; 32], vec![2], 10, 60);
        assert_eq!(
            verifier.verify(second, &second_key, 10),
            Err(SlotError::StateFull { capacity: 1 })
        );
        verifier.save_atomic(&path, &sealing_seed).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert_eq!(
            SlotClaimVerifier::load(&path, &sealing_seed, 0, 1).unwrap_err(),
            SlotError::IntegrityFailure
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn allocation_map_enforces_gateway_and_slot_bounds() {
        let mut map = SlotAllocationMap::new(AllocationMode::Interleaved, 1, 10, 60).unwrap();
        map.set_allocation([1; 8], vec![1, 3]).unwrap();
        assert_eq!(map.get_allocation(&[1; 8]), Some(&[1, 3][..]));
        assert_eq!(
            map.set_allocation([2; 8], vec![2]),
            Err(SlotError::StateFull { capacity: 1 })
        );
        assert_eq!(
            map.set_allocation([1; 8], vec![2, 2]),
            Err(SlotError::DuplicateSlot)
        );
        assert!(matches!(
            SlotAllocationMap::new(
                AllocationMode::Interleaved,
                MAX_COORDINATING_GATEWAYS as u32 + 1,
                10,
                60
            ),
            Err(SlotError::TooManyGateways)
        ));
    }

    #[test]
    fn no_conflict_when_no_overlap() {
        let mut verifier = SlotClaimVerifier::new_ephemeral(4).unwrap();
        let claim_a = verified_claim([7; 32], vec![0, 3, 6], 1000, 60, &mut verifier);
        let claim_b = verified_claim([8; 32], vec![1, 4, 7], 1000, 60, &mut verifier);

        let result = resolve_conflict(&claim_a, &claim_b, 1000);
        assert_eq!(result, ConflictResolution::NoConflict);
    }
}
