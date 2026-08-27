// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Coordinator-managed short addresses carried by RPL DAO / DAO-ACK.
//!
//! The generic RPL codec does not interpret LICHEN extensions. This module
//! places a versioned assignment payload in one project-private RPL option
//! (type 252) and implements the coordinator and node state machines around
//! it. Canonical wires and maintenance values live in
//! `test/vectors/short_addr_assignment.json`.

use crate::message::{Dao, DaoAck, OptionIter, RplError};

/// Project-private RPL option type. This is not an IANA allocation.
pub const SHORT_ADDRESS_OPTION_TYPE: u8 = 252;
/// Current assignment option encoding version.
pub const SHORT_ADDRESS_OPTION_VERSION: u8 = 1;
/// Wire sentinel meaning "no preferred or assigned short address".
pub const SHORT_ADDRESS_NONE: u16 = 0xFFFF;

const REQUEST_KIND: u8 = 0;
const ACK_KIND: u8 = 1;
const REQUEST_LENGTH: usize = 13;
const ACK_LENGTH: usize = 14;
const FIRST_SHORT: u16 = 1;
const LAST_SHORT: u16 = 0xFFFD;
const MAX_ACK_WIRE: usize = 40;

/// Malformed assignment message, option, or persisted snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignmentError {
    /// Option, DAO, DAO-ACK, or snapshot failed closed.
    Protocol(&'static str),
    /// Durable load or commit failed before in-memory publish.
    Persistence(&'static str),
}

impl core::fmt::Display for AssignmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Protocol(msg) | Self::Persistence(msg) => f.write_str(msg),
        }
    }
}

impl core::error::Error for AssignmentError {}

impl From<RplError> for AssignmentError {
    fn from(_err: RplError) -> Self {
        Self::Protocol("invalid RPL assignment message")
    }
}

/// Operation requested in a DAO assignment option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AssignmentOperation {
    /// Allocate or renew a unique short address.
    Allocate = 0,
    /// Release any address currently held by this EUI-64.
    Release = 1,
}

impl TryFrom<u8> for AssignmentOperation {
    type Error = AssignmentError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Allocate),
            1 => Ok(Self::Release),
            _ => Err(AssignmentError::Protocol("unknown assignment operation")),
        }
    }
}

/// Status mirrored in the DAO-ACK base object and assignment option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AssignmentStatus {
    /// Request applied; ALLOCATE success carries an assigned address.
    Success = 0,
    /// No free address remains in the coordinator pool.
    Exhausted = 1,
    /// Request was structurally valid but semantically rejected.
    Invalid = 2,
}

impl TryFrom<u8> for AssignmentStatus {
    type Error = AssignmentError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::Exhausted),
            2 => Ok(Self::Invalid),
            _ => Err(AssignmentError::Protocol("unknown assignment ACK value")),
        }
    }
}

fn check_eui64(eui64: &[u8]) -> Result<[u8; 8], AssignmentError> {
    <[u8; 8]>::try_from(eui64)
        .map_err(|_| AssignmentError::Protocol("EUI-64 must be exactly 8 immutable bytes"))
}

/// Canonical wire EUI-64 for option 252 from an authenticated native identity.
///
/// The preserved DAO origin proves the key-to-native-address binding. The
/// option value is then derived from that authenticated key: its canonical IID
/// with the RFC 4291 U/L bit toggled exactly once for the link-layer wire EUI.
/// It MUST NOT be reconstructed by applying the generic hardware-EUI inverse
/// to arbitrary IPv6 address bytes.
pub fn eui64_from_authenticated_identity(
    origin: [u8; 16],
    pubkey: [u8; 32],
) -> Result<[u8; 8], AssignmentError> {
    if lichen_core::addr::ygg_addr_from_pubkey(&pubkey) != origin {
        return Err(AssignmentError::Protocol(
            "origin address does not match authenticated DAO pubkey",
        ));
    }
    let mut eui64 = lichen_core::addr::iid_from_pubkey_bytes(&pubkey);
    eui64[0] ^= 0x02;
    Ok(eui64)
}

fn check_short(short_addr: u16) -> Result<u16, AssignmentError> {
    if (FIRST_SHORT..=LAST_SHORT).contains(&short_addr) {
        Ok(short_addr)
    } else {
        Err(AssignmentError::Protocol(
            "short address must be in 0x0001..0xfffd",
        ))
    }
}

/// RFC 6550 Section 7.2 lollipop comparison (`SEQUENCE_WINDOW` = 16).
///
/// Equal sequences are not newer. A same-region difference above the window,
/// or the non-newer cross-region direction, is stale or incomparable.
#[cfg(any(test, feature = "std"))]
fn dao_seq_is_newer(new_seq: u8, old_seq: u8) -> bool {
    const CIRCULAR_BIT: u8 = 128;
    const SEQUENCE_WINDOW: u8 = 16;
    match (new_seq < CIRCULAR_BIT, old_seq < CIRCULAR_BIT) {
        (true, true) | (false, false) => {
            let diff = new_seq.wrapping_sub(old_seq) & 0x7F;
            (1..=SEQUENCE_WINDOW).contains(&diff)
        }
        (true, false) => {
            256u16 + u16::from(new_seq) - u16::from(old_seq) <= u16::from(SEQUENCE_WINDOW)
        }
        (false, true) => {
            256u16 + u16::from(old_seq) - u16::from(new_seq) > u16::from(SEQUENCE_WINDOW)
        }
    }
}

fn one_assignment_option(tail: &[u8]) -> Result<&[u8], AssignmentError> {
    let mut found = None;
    for option in OptionIter::new(tail) {
        let option = option?;
        if option.opt_type != SHORT_ADDRESS_OPTION_TYPE {
            continue;
        }
        if found.is_some() {
            return Err(AssignmentError::Protocol(
                "message must contain exactly one short-address option",
            ));
        }
        found = Some(option.data);
    }
    found.ok_or(AssignmentError::Protocol(
        "message must contain exactly one short-address option",
    ))
}

fn write_option(out: &mut [u8], payload: &[u8]) -> Result<usize, AssignmentError> {
    let total = 2 + payload.len();
    if out.len() < total {
        return Err(AssignmentError::Protocol(
            "assignment option buffer too small",
        ));
    }
    out[0] = SHORT_ADDRESS_OPTION_TYPE;
    out[1] = payload.len() as u8;
    out[2..total].copy_from_slice(payload);
    Ok(total)
}

/// A node's allocation or release request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressAssignmentRequest {
    /// Canonical EUI-64 of the requesting node.
    pub eui64: [u8; 8],
    /// ALLOCATE or RELEASE.
    pub operation: AssignmentOperation,
    /// Preferred address, or `None` to let the coordinator derive one.
    pub requested_short: Option<u16>,
}

impl AddressAssignmentRequest {
    /// Construct a validated request.
    pub fn new(
        eui64: [u8; 8],
        operation: AssignmentOperation,
        requested_short: Option<u16>,
    ) -> Result<Self, AssignmentError> {
        if operation == AssignmentOperation::Release && requested_short.is_some() {
            return Err(AssignmentError::Protocol(
                "release request cannot carry a preferred address",
            ));
        }
        if let Some(short_addr) = requested_short {
            check_short(short_addr)?;
        }
        Ok(Self {
            eui64,
            operation,
            requested_short,
        })
    }

    /// ALLOCATE request for `eui64`, optionally naming a preferred address.
    pub fn allocate(eui64: [u8; 8], requested_short: Option<u16>) -> Result<Self, AssignmentError> {
        Self::new(eui64, AssignmentOperation::Allocate, requested_short)
    }

    /// RELEASE request for `eui64`.
    pub fn release(eui64: [u8; 8]) -> Result<Self, AssignmentError> {
        Self::new(eui64, AssignmentOperation::Release, None)
    }

    /// Encode the type-252 request option, including type and length bytes.
    pub fn write_option(&self, out: &mut [u8]) -> Result<usize, AssignmentError> {
        let short_addr = self.requested_short.unwrap_or(SHORT_ADDRESS_NONE);
        let mut payload = [0u8; REQUEST_LENGTH];
        payload[0] = SHORT_ADDRESS_OPTION_VERSION;
        payload[1] = REQUEST_KIND;
        payload[2] = self.operation as u8;
        payload[3..11].copy_from_slice(&self.eui64);
        payload[11..13].copy_from_slice(&short_addr.to_be_bytes());
        write_option(out, &payload)
    }

    /// Parse a type-252 request option (type/length already stripped).
    pub fn from_option_data(data: &[u8]) -> Result<Self, AssignmentError> {
        if data.len() != REQUEST_LENGTH {
            return Err(AssignmentError::Protocol(
                "invalid short-address request option",
            ));
        }
        if data[0] != SHORT_ADDRESS_OPTION_VERSION || data[1] != REQUEST_KIND {
            return Err(AssignmentError::Protocol(
                "unsupported short-address request encoding",
            ));
        }
        let requested = u16::from_be_bytes([data[11], data[12]]);
        Self::new(
            check_eui64(&data[3..11])?,
            AssignmentOperation::try_from(data[2])?,
            if requested == SHORT_ADDRESS_NONE {
                None
            } else {
                Some(requested)
            },
        )
    }

    /// Write an ACK-requesting DAO that carries this request.
    pub fn write_dao(
        &self,
        rpl_instance_id: u8,
        dao_sequence: u8,
        dodag_id: Option<[u8; 16]>,
        out: &mut [u8],
    ) -> Result<usize, AssignmentError> {
        let dao = Dao {
            rpl_instance_id,
            ack_requested: true,
            flags: 0,
            dao_sequence,
            dodag_id,
        };
        let base = dao.write_to(out)?;
        let option = self.write_option(&mut out[base..])?;
        Ok(base + option)
    }

    /// Parse a request from a complete DAO body, including the option.
    pub fn from_dao_bytes(data: &[u8]) -> Result<Self, AssignmentError> {
        let dao = Dao::from_bytes(data)?;
        if !dao.ack_requested {
            return Err(AssignmentError::Protocol(
                "address-assignment DAO must request an ACK",
            ));
        }
        Self::from_option_data(one_assignment_option(Dao::options_tail(data))?)
    }
}

/// Coordinator result carried by an RPL DAO-ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressAssignmentAck {
    /// EUI-64 the ACK is bound to.
    pub eui64: [u8; 8],
    /// Operation the ACK answers.
    pub operation: AssignmentOperation,
    /// Mirrored DAO-ACK status.
    pub status: AssignmentStatus,
    /// Assigned address; present only for successful ALLOCATE.
    pub assigned_short: Option<u16>,
    /// DAO sequence copied from the request.
    pub dao_sequence: u8,
}

impl AddressAssignmentAck {
    /// Construct a validated ACK object.
    pub fn new(
        eui64: [u8; 8],
        operation: AssignmentOperation,
        status: AssignmentStatus,
        assigned_short: Option<u16>,
        dao_sequence: u8,
    ) -> Result<Self, AssignmentError> {
        if let Some(short_addr) = assigned_short {
            check_short(short_addr)?;
        }
        let should_assign =
            operation == AssignmentOperation::Allocate && status == AssignmentStatus::Success;
        if should_assign != assigned_short.is_some() {
            return Err(AssignmentError::Protocol(
                "ACK address is inconsistent with operation/status",
            ));
        }
        Ok(Self {
            eui64,
            operation,
            status,
            assigned_short,
            dao_sequence,
        })
    }

    /// Encode the type-252 ACK option, including type and length bytes.
    pub fn write_option(&self, out: &mut [u8]) -> Result<usize, AssignmentError> {
        let short_addr = self.assigned_short.unwrap_or(SHORT_ADDRESS_NONE);
        let mut payload = [0u8; ACK_LENGTH];
        payload[0] = SHORT_ADDRESS_OPTION_VERSION;
        payload[1] = ACK_KIND;
        payload[2] = self.operation as u8;
        payload[3] = self.status as u8;
        payload[4..12].copy_from_slice(&self.eui64);
        payload[12..14].copy_from_slice(&short_addr.to_be_bytes());
        write_option(out, &payload)
    }

    /// Parse a type-252 ACK option (type/length already stripped).
    pub fn from_option_data(data: &[u8], dao_sequence: u8) -> Result<Self, AssignmentError> {
        if data.len() != ACK_LENGTH {
            return Err(AssignmentError::Protocol(
                "invalid short-address ACK option",
            ));
        }
        if data[0] != SHORT_ADDRESS_OPTION_VERSION || data[1] != ACK_KIND {
            return Err(AssignmentError::Protocol(
                "unsupported short-address ACK encoding",
            ));
        }
        let assigned = u16::from_be_bytes([data[12], data[13]]);
        Self::new(
            check_eui64(&data[4..12])?,
            AssignmentOperation::try_from(data[2])?,
            AssignmentStatus::try_from(data[3])?,
            if assigned == SHORT_ADDRESS_NONE {
                None
            } else {
                Some(assigned)
            },
            dao_sequence,
        )
    }

    /// Write a DAO-ACK body that carries this assignment result.
    pub fn write_dao_ack(
        &self,
        rpl_instance_id: u8,
        dodag_id: Option<[u8; 16]>,
        out: &mut [u8],
    ) -> Result<usize, AssignmentError> {
        let ack = DaoAck {
            rpl_instance_id,
            flags: 0,
            dao_sequence: self.dao_sequence,
            status: self.status as u8,
            dodag_id,
        };
        let base = ack.write_to(out)?;
        let option = self.write_option(&mut out[base..])?;
        Ok(base + option)
    }

    /// Parse an assignment ACK from a complete DAO-ACK body.
    pub fn from_dao_ack_bytes(data: &[u8]) -> Result<Self, AssignmentError> {
        let ack = DaoAck::from_bytes(data)?;
        let result = Self::from_option_data(
            one_assignment_option(DaoAck::options_tail(data))?,
            ack.dao_sequence,
        )?;
        if ack.status != result.status as u8 {
            return Err(AssignmentError::Protocol(
                "DAO-ACK status disagrees with assignment option",
            ));
        }
        Ok(result)
    }
}

/// Node-side DAO-ACK validator and assignment state.
#[derive(Clone, Debug)]
pub struct ShortAddressAssignmentClient {
    eui64: [u8; 8],
    assigned_short: Option<u16>,
    last_ack: Option<([u8; MAX_ACK_WIRE], usize)>,
    last_sequence: Option<u8>,
}

impl ShortAddressAssignmentClient {
    /// Create a client bound to `eui64`.
    pub fn new(eui64: [u8; 8]) -> Self {
        Self {
            eui64,
            assigned_short: None,
            last_ack: None,
            last_sequence: None,
        }
    }

    /// EUI-64 this client will accept ACKs for.
    pub fn eui64(&self) -> [u8; 8] {
        self.eui64
    }

    /// Currently installed short address, if any.
    pub fn assigned_short(&self) -> Option<u16> {
        self.assigned_short
    }

    /// Apply only an ACK for this identity and outstanding DAO sequence.
    ///
    /// Returns `Ok(true)` when the ACK is accepted (including an identical
    /// retransmission), `Ok(false)` when it is ignored, and `Err` when the
    /// ACK is unauthenticated, malformed, or conflicts with a previously
    /// accepted ACK.
    ///
    /// SECURITY: `root_authenticated` MUST be true only after the caller has
    /// verified this DAO-ACK as originating from the DODAG root (link
    /// signature from the root, or an equivalent root-authenticated control
    /// path). An unauthenticated ACK MUST NOT install `assigned_short`.
    pub fn apply_dao_ack(
        &mut self,
        ack: &[u8],
        expected_sequence: u8,
        root_authenticated: bool,
    ) -> Result<bool, AssignmentError> {
        if !root_authenticated {
            return Err(AssignmentError::Protocol(
                "DAO-ACK is not root-authenticated",
            ));
        }
        let result = AddressAssignmentAck::from_dao_ack_bytes(ack)?;
        if result.dao_sequence != expected_sequence {
            return Ok(false);
        }
        if result.eui64 != self.eui64 {
            return Ok(false);
        }
        if ack.len() > MAX_ACK_WIRE {
            return Err(AssignmentError::Protocol(
                "DAO-ACK exceeds stored fingerprint",
            ));
        }
        if let Some((stored, stored_len)) = self.last_ack {
            if self.last_sequence == Some(result.dao_sequence) {
                if stored_len == ack.len() && stored[..stored_len] == *ack {
                    return Ok(true);
                }
                return Err(AssignmentError::Protocol(
                    "conflicting DAO-ACK for one sequence",
                ));
            }
        }
        if result.status != AssignmentStatus::Success {
            return Ok(false);
        }
        let mut stored = [0u8; MAX_ACK_WIRE];
        stored[..ack.len()].copy_from_slice(ack);
        self.assigned_short = result.assigned_short;
        self.last_ack = Some((stored, ack.len()));
        self.last_sequence = Some(result.dao_sequence);
        Ok(true)
    }
}

#[cfg(feature = "std")]
mod std_support {
    use super::{
        check_eui64, check_short, AddressAssignmentAck, AddressAssignmentRequest, AssignmentError,
        AssignmentOperation, AssignmentStatus, FIRST_SHORT, LAST_SHORT,
    };
    use crate::message::Dao;
    use lichen_core::short_addr::{crc32_ieee, derive_short_addr, derive_short_addr_with_seed};
    use std::cell::RefCell;
    use std::collections::{BTreeMap, HashMap};
    use std::rc::Rc;
    use std::vec::Vec;

    const SHORT_POOL_SIZE: u16 = LAST_SHORT;
    const STATE_MAGIC: &[u8; 4] = b"SAA1";
    const STATE_RECORD_LENGTH: usize = 10;
    const TABLE_STATE_MAGIC: &[u8; 4] = b"SAT2";
    const TABLE_STATE_RECORD_LENGTH: usize = 20;
    const NO_EXPIRY: u64 = u64::MAX;
    const NO_SEQUENCE: u16 = 256;

    type TableSnapshot = (
        BTreeMap<u16, [u8; 8]>,
        HashMap<[u8; 8], u64>,
        HashMap<[u8; 8], u8>,
    );

    #[cfg(feature = "std")]
    fn crc32_be(data: &[u8]) -> [u8; 4] {
        crc32_ieee(data, 0).to_be_bytes()
    }

    #[cfg(feature = "std")]
    fn checksum_ok(state: &[u8]) -> bool {
        let n = state.len();
        n >= 4
            && crc32_be(&state[..n - 4]) == [state[n - 4], state[n - 3], state[n - 2], state[n - 1]]
    }

    /// Persistence adapter whose `save` operation is atomic.
    ///
    /// # Trust boundary
    ///
    /// Snapshots persisted through this trait are guarded solely by the
    /// `crc32_ieee` checksum appended by the encoder. That detects accidental
    /// corruption such as torn writes and bit rot; it authenticates nothing.
    /// Anything able to write through the backing storage can forge lease
    /// deadlines or resurrect EUI-64 mappings that
    /// [`ShortAddressCoordinator`] honors across restarts. Implementations
    /// therefore MUST return state only from trusted, verified storage --
    /// files writable exclusively by trusted processes, or snapshots whose
    /// integrity or authenticity is enforced by a layer above this trait --
    /// and callers MUST treat untrusted writers as out of scope here rather
    /// than a reason to add MAC machinery below this interface.
    pub trait AddressAssignmentStore {
        /// Return the last complete state blob, or `None` on first boot.
        fn load(&self) -> Result<Option<Vec<u8>>, AssignmentError>;
        /// Atomically replace the durable state blob.
        fn save(&mut self, state: &[u8]) -> Result<(), AssignmentError>;
    }

    /// In-memory persistence adapter for simulation and restart tests.
    ///
    /// Clones share the same blob so a restarted coordinator observes commits.
    #[derive(Clone, Debug, Default)]
    pub struct MemoryAddressAssignmentStore {
        state: Rc<RefCell<Option<Vec<u8>>>>,
    }

    impl MemoryAddressAssignmentStore {
        /// Wrap an existing snapshot, if any.
        pub fn new(state: Option<Vec<u8>>) -> Self {
            Self {
                state: Rc::new(RefCell::new(state)),
            }
        }
    }

    impl AddressAssignmentStore for MemoryAddressAssignmentStore {
        fn load(&self) -> Result<Option<Vec<u8>>, AssignmentError> {
            Ok(self.state.borrow().clone())
        }

        fn save(&mut self, state: &[u8]) -> Result<(), AssignmentError> {
            *self.state.borrow_mut() = Some(state.to_vec());
            Ok(())
        }
    }

    /// Store that never persists; used when the coordinator is memory-only.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct NoStore;

    impl AddressAssignmentStore for NoStore {
        fn load(&self) -> Result<Option<Vec<u8>>, AssignmentError> {
            Ok(None)
        }

        fn save(&mut self, _state: &[u8]) -> Result<(), AssignmentError> {
            Ok(())
        }
    }

    fn check_capacity(capacity: u16) -> Result<u16, AssignmentError> {
        if (1..=SHORT_POOL_SIZE).contains(&capacity) {
            Ok(capacity)
        } else {
            Err(AssignmentError::Protocol("capacity must be in 1..65533"))
        }
    }

    fn encode_records(
        magic: &[u8; 4],
        record_len: usize,
        assignments: &BTreeMap<u16, [u8; 8]>,
        mut write_record: impl FnMut(u16, [u8; 8], &mut Vec<u8>) -> Result<(), AssignmentError>,
    ) -> Result<Vec<u8>, AssignmentError> {
        if assignments.len() > SHORT_POOL_SIZE as usize {
            return Err(AssignmentError::Protocol(
                "too many short-address assignments",
            ));
        }
        let mut seen = HashMap::with_capacity(assignments.len());
        let mut records = Vec::with_capacity(assignments.len() * record_len);
        for (&short_addr, &eui64) in assignments {
            check_short(short_addr)?;
            check_eui64(&eui64)?;
            if seen.insert(eui64, short_addr).is_some() {
                return Err(AssignmentError::Protocol(
                    "one EUI-64 cannot own multiple short addresses",
                ));
            }
            write_record(short_addr, eui64, &mut records)?;
        }
        let count = u16::try_from(assignments.len())
            .map_err(|_| AssignmentError::Protocol("too many short-address assignments"))?;
        let mut body = Vec::with_capacity(6 + records.len() + 4);
        body.extend_from_slice(magic);
        body.extend_from_slice(&count.to_be_bytes());
        body.extend_from_slice(&records);
        let checksum = crc32_be(&body);
        body.extend_from_slice(&checksum);
        Ok(body)
    }

    /// Encode a deterministic, checksummed coordinator snapshot (SAA1).
    pub fn encode_assignment_state(
        assignments: &BTreeMap<u16, [u8; 8]>,
    ) -> Result<Vec<u8>, AssignmentError> {
        encode_records(
            STATE_MAGIC,
            STATE_RECORD_LENGTH,
            assignments,
            |short_addr, eui64, records| {
                records.extend_from_slice(&short_addr.to_be_bytes());
                records.extend_from_slice(&eui64);
                Ok(())
            },
        )
    }

    /// Decode an SAA1 snapshot, failing closed on truncation or corruption.
    pub fn decode_assignment_state(
        state: &[u8],
    ) -> Result<BTreeMap<u16, [u8; 8]>, AssignmentError> {
        if state.len() < 10 || !state.starts_with(STATE_MAGIC) {
            return Err(AssignmentError::Protocol("invalid assignment state header"));
        }
        let count = u16::from_be_bytes([state[4], state[5]]) as usize;
        let expected = 6 + count * STATE_RECORD_LENGTH + 4;
        if state.len() != expected {
            return Err(AssignmentError::Protocol(
                "assignment state length does not match record count",
            ));
        }
        if !checksum_ok(state) {
            return Err(AssignmentError::Protocol(
                "assignment state checksum mismatch",
            ));
        }
        let mut assignments = BTreeMap::new();
        let mut seen = HashMap::new();
        let mut previous = 0u16;
        let mut offset = 6;
        for _ in 0..count {
            let short_addr = u16::from_be_bytes([state[offset], state[offset + 1]]);
            let eui64 = check_eui64(&state[offset + 2..offset + 10])?;
            offset += STATE_RECORD_LENGTH;
            check_short(short_addr)?;
            if short_addr <= previous {
                return Err(AssignmentError::Protocol(
                    "assignment state records are not strictly sorted",
                ));
            }
            if seen.insert(eui64, short_addr).is_some() {
                return Err(AssignmentError::Protocol(
                    "assignment state contains duplicate EUI-64",
                ));
            }
            previous = short_addr;
            assignments.insert(short_addr, eui64);
        }
        Ok(assignments)
    }

    fn encode_table_state(
        assignments: &BTreeMap<u16, [u8; 8]>,
        expiries: &HashMap<[u8; 8], u64>,
        sequences: &HashMap<[u8; 8], u8>,
    ) -> Result<Vec<u8>, AssignmentError> {
        encode_records(
            TABLE_STATE_MAGIC,
            TABLE_STATE_RECORD_LENGTH,
            assignments,
            |short_addr, eui64, records| {
                let expiry = expiries.get(&eui64).copied().unwrap_or(NO_EXPIRY);
                let sequence = sequences
                    .get(&eui64)
                    .map(|seq| u16::from(*seq))
                    .unwrap_or(NO_SEQUENCE);
                records.extend_from_slice(&short_addr.to_be_bytes());
                records.extend_from_slice(&eui64);
                records.extend_from_slice(&expiry.to_be_bytes());
                records.extend_from_slice(&sequence.to_be_bytes());
                Ok(())
            },
        )
    }

    fn decode_table_state(state: &[u8]) -> Result<TableSnapshot, AssignmentError> {
        if !state.starts_with(TABLE_STATE_MAGIC) {
            return Ok((
                decode_assignment_state(state)?,
                HashMap::new(),
                HashMap::new(),
            ));
        }
        if state.len() < 10 {
            return Err(AssignmentError::Protocol(
                "invalid coordinator table state header",
            ));
        }
        let count = u16::from_be_bytes([state[4], state[5]]) as usize;
        let expected = 6 + count * TABLE_STATE_RECORD_LENGTH + 4;
        if state.len() != expected {
            return Err(AssignmentError::Protocol(
                "coordinator table state length mismatch",
            ));
        }
        if !checksum_ok(state) {
            return Err(AssignmentError::Protocol(
                "coordinator table state checksum mismatch",
            ));
        }
        let mut assignments = BTreeMap::new();
        let mut expiries = HashMap::new();
        let mut sequences = HashMap::new();
        let mut seen = HashMap::new();
        let mut previous = 0u16;
        let mut offset = 6;
        for _ in 0..count {
            let short_addr = u16::from_be_bytes([state[offset], state[offset + 1]]);
            let eui64 = check_eui64(&state[offset + 2..offset + 10])?;
            let expiry = u64::from_be_bytes(
                state[offset + 10..offset + 18]
                    .try_into()
                    .expect("expiry slice is 8 bytes"),
            );
            let sequence = u16::from_be_bytes([state[offset + 18], state[offset + 19]]);
            offset += TABLE_STATE_RECORD_LENGTH;
            check_short(short_addr)?;
            if short_addr <= previous {
                return Err(AssignmentError::Protocol(
                    "coordinator table records are not strictly sorted",
                ));
            }
            if seen.insert(eui64, short_addr).is_some() {
                return Err(AssignmentError::Protocol(
                    "coordinator table contains duplicate EUI-64",
                ));
            }
            if sequence > NO_SEQUENCE {
                return Err(AssignmentError::Protocol(
                    "persisted DAO sequence is invalid",
                ));
            }
            previous = short_addr;
            assignments.insert(short_addr, eui64);
            if expiry != NO_EXPIRY {
                expiries.insert(eui64, expiry);
            }
            if sequence != NO_SEQUENCE {
                let seq8 = u8::try_from(sequence)
                    .map_err(|_| AssignmentError::Protocol("persisted DAO sequence is invalid"))?;
                sequences.insert(eui64, seq8);
            }
        }
        Ok((assignments, expiries, sequences))
    }

    fn write_vec(
        write: impl FnOnce(&mut [u8]) -> Result<usize, AssignmentError>,
    ) -> Result<Vec<u8>, AssignmentError> {
        let mut buf = [0u8; 64];
        let n = write(&mut buf)?;
        Ok(buf[..n].to_vec())
    }

    impl AddressAssignmentRequest {
        /// Encode an ACK-requesting DAO as an owned buffer.
        pub fn to_dao_vec(
            &self,
            rpl_instance_id: u8,
            dao_sequence: u8,
            dodag_id: Option<[u8; 16]>,
        ) -> Result<Vec<u8>, AssignmentError> {
            write_vec(|out| self.write_dao(rpl_instance_id, dao_sequence, dodag_id, out))
        }
    }

    impl AddressAssignmentAck {
        /// Encode a DAO-ACK as an owned buffer.
        pub fn to_dao_ack_vec(
            &self,
            rpl_instance_id: u8,
            dodag_id: Option<[u8; 16]>,
        ) -> Result<Vec<u8>, AssignmentError> {
            write_vec(|out| self.write_dao_ack(rpl_instance_id, dodag_id, out))
        }
    }

    /// Allocates unique addresses and returns wire-ready DAO-ACKs.
    pub struct ShortAddressCoordinator<S, C> {
        store: S,
        clock: C,
        capacity: u16,
        lease_seconds: Option<u64>,
        by_short: BTreeMap<u16, [u8; 8]>,
        by_eui: HashMap<[u8; 8], u16>,
        expires_by_eui: HashMap<[u8; 8], u64>,
        last_sequence_by_eui: HashMap<[u8; 8], u8>,
    }

    impl ShortAddressCoordinator<NoStore, fn() -> u64> {
        /// Empty in-memory coordinator with the full usable pool.
        pub fn new() -> Result<Self, AssignmentError> {
            Self::build(NoStore, None, SHORT_POOL_SIZE, None, unix_zero)
        }

        /// Empty in-memory coordinator with a bounded table.
        pub fn with_capacity(capacity: u16) -> Result<Self, AssignmentError> {
            Self::build(NoStore, None, capacity, None, unix_zero)
        }

        /// Coordinator restored from a caller-supplied assignment map.
        pub fn with_initial_assignments(
            assignments: BTreeMap<u16, [u8; 8]>,
        ) -> Result<Self, AssignmentError> {
            Self::build(NoStore, Some(assignments), SHORT_POOL_SIZE, None, unix_zero)
        }
    }

    impl<S: AddressAssignmentStore> ShortAddressCoordinator<S, fn() -> u64> {
        /// Coordinator that loads and commits through `store`.
        ///
        /// Persisted lease deadlines are pruned against the wall clock on
        /// load, matching the Python constructor default (`clock=time.time`)
        /// rather than freezing time at zero.
        ///
        /// Restored blobs pass only the `crc32_ieee` corruption checksum;
        /// see [`AddressAssignmentStore`] for the trust boundary that keeps
        /// forged state out.
        pub fn with_store(store: S) -> Result<Self, AssignmentError> {
            Self::build(store, None, SHORT_POOL_SIZE, None, unix_now)
        }
    }

    impl<S: AddressAssignmentStore, C: Fn() -> u64> ShortAddressCoordinator<S, C> {
        /// Full constructor used by lease and restart tests.
        ///
        /// `clock` returns whole seconds since the Unix epoch. Blobs loaded
        /// from `store` are honored beyond the `crc32_ieee` corruption
        /// checksum; see [`AddressAssignmentStore`] for the trust boundary.
        pub fn with_lease(
            store: S,
            capacity: u16,
            lease_seconds: Option<u64>,
            clock: C,
        ) -> Result<Self, AssignmentError> {
            Self::build(store, None, capacity, lease_seconds, clock)
        }

        /// Primes from `initial` when no snapshot is stored, then prunes
        /// expired leases; blobs the store returns are trusted subject to
        /// the [`AddressAssignmentStore`] trust boundary.
        fn build(
            store: S,
            initial: Option<BTreeMap<u16, [u8; 8]>>,
            capacity: u16,
            lease_seconds: Option<u64>,
            clock: C,
        ) -> Result<Self, AssignmentError> {
            let capacity = check_capacity(capacity)?;
            if let Some(lease) = lease_seconds {
                if lease < 1 {
                    return Err(AssignmentError::Protocol("lease_seconds must be positive"));
                }
            }
            let stored = store
                .load()
                .map_err(|_| AssignmentError::Persistence("could not load assignment state"))?;
            if stored.is_some() && initial.is_some() {
                return Err(AssignmentError::Protocol(
                    "store and initial_assignments are mutually exclusive",
                ));
            }
            let (assignments, expiries, sequences) = if let Some(blob) = stored {
                decode_table_state(&blob)?
            } else if let Some(initial) = initial {
                let blob = encode_assignment_state(&initial)?;
                (
                    decode_assignment_state(&blob)?,
                    HashMap::new(),
                    HashMap::new(),
                )
            } else {
                (BTreeMap::new(), HashMap::new(), HashMap::new())
            };
            if assignments.len() > capacity as usize {
                return Err(AssignmentError::Protocol(
                    "persisted assignments exceed coordinator capacity",
                ));
            }
            let by_eui = assignments.iter().map(|(&s, &e)| (e, s)).collect();
            let mut coordinator = Self {
                store,
                clock,
                capacity,
                lease_seconds,
                by_short: assignments,
                by_eui,
                expires_by_eui: expiries,
                last_sequence_by_eui: sequences,
            };
            coordinator.prune_expired(None)?;
            Ok(coordinator)
        }

        fn commit(
            &mut self,
            assignments: BTreeMap<u16, [u8; 8]>,
            expiries: HashMap<[u8; 8], u64>,
            sequences: HashMap<[u8; 8], u8>,
        ) -> Result<(), AssignmentError> {
            let blob = encode_table_state(&assignments, &expiries, &sequences)?;
            self.store
                .save(&blob)
                .map_err(|_| AssignmentError::Persistence("could not commit assignment state"))?;
            self.by_eui = assignments.iter().map(|(&s, &e)| (e, s)).collect();
            self.by_short = assignments;
            self.expires_by_eui = expiries;
            self.last_sequence_by_eui = sequences;
            Ok(())
        }

        /// Look up the EUI-64 that currently owns `short_addr`.
        pub fn lookup_by_short(&self, short_addr: u16) -> Option<[u8; 8]> {
            self.by_short.get(&short_addr).copied()
        }

        /// Look up the short address currently assigned to `eui64`.
        pub fn lookup_by_eui(&self, eui64: &[u8]) -> Result<Option<u16>, AssignmentError> {
            let eui64 = check_eui64(eui64)?;
            Ok(self.by_eui.get(&eui64).copied())
        }

        /// Absolute lease deadline for `eui64`, if leases are enabled.
        pub fn expires_at(&self, eui64: &[u8]) -> Result<Option<u64>, AssignmentError> {
            let eui64 = check_eui64(eui64)?;
            Ok(self.expires_by_eui.get(&eui64).copied())
        }

        /// Configured table capacity.
        pub fn capacity(&self) -> u16 {
            self.capacity
        }

        /// Number of currently assigned addresses.
        pub fn len(&self) -> usize {
            self.by_short.len()
        }

        /// Whether the table is empty.
        pub fn is_empty(&self) -> bool {
            self.by_short.is_empty()
        }

        /// Copy of the live short-address map.
        pub fn snapshot(&self) -> BTreeMap<u16, [u8; 8]> {
            self.by_short.clone()
        }

        /// Release all leases whose deadlines are at or before `now`.
        pub fn prune_expired(&mut self, now: Option<u64>) -> Result<usize, AssignmentError> {
            let now = match now {
                Some(now) => now,
                None => (self.clock)(),
            };
            let expired: Vec<[u8; 8]> = self
                .expires_by_eui
                .iter()
                .filter_map(
                    |(&eui64, &deadline)| {
                        if deadline <= now {
                            Some(eui64)
                        } else {
                            None
                        }
                    },
                )
                .collect();
            if expired.is_empty() {
                return Ok(0);
            }
            let count = expired.len();
            let assignments = self
                .by_short
                .iter()
                .filter(|(_, eui64)| !expired.contains(eui64))
                .map(|(&s, &e)| (s, e))
                .collect();
            let expiries = self
                .expires_by_eui
                .iter()
                .filter(|(eui64, _)| !expired.contains(eui64))
                .map(|(&e, &d)| (e, d))
                .collect();
            let sequences = self
                .last_sequence_by_eui
                .iter()
                .filter(|(eui64, _)| !expired.contains(eui64))
                .map(|(&e, &s)| (e, s))
                .collect();
            self.commit(assignments, expiries, sequences)?;
            Ok(count)
        }

        fn fallback(start: u16, occupied: &BTreeMap<u16, [u8; 8]>) -> Option<u16> {
            if occupied.len() >= SHORT_POOL_SIZE as usize {
                return None;
            }
            let start = start.max(FIRST_SHORT);
            for offset in 0..SHORT_POOL_SIZE {
                let candidate = FIRST_SHORT
                    + ((u32::from(start) - u32::from(FIRST_SHORT) + u32::from(offset))
                        % u32::from(SHORT_POOL_SIZE)) as u16;
                if !occupied.contains_key(&candidate) {
                    return Some(candidate);
                }
            }
            None
        }

        fn candidate(&self, eui64: &[u8; 8], preferred: Option<u16>) -> Option<u16> {
            if let Some(preferred) = preferred {
                if !self.by_short.contains_key(&preferred) {
                    return Some(preferred);
                }
            }
            let derived = derive_short_addr(eui64);
            if (FIRST_SHORT..=LAST_SHORT).contains(&derived)
                && !self.by_short.contains_key(&derived)
            {
                return Some(derived);
            }
            for seed in 1u32..=255 {
                let candidate = derive_short_addr_with_seed(eui64, seed);
                if (FIRST_SHORT..=LAST_SHORT).contains(&candidate)
                    && !self.by_short.contains_key(&candidate)
                {
                    return Some(candidate);
                }
            }
            let start = preferred.unwrap_or(derived.max(FIRST_SHORT));
            Self::fallback(start, &self.by_short)
        }

        /// Apply one request using RFC 6550 DAOSequence freshness.
        ///
        /// Same sequence is an idempotent copy of already-applied state. A
        /// newer sequence is a new request. Older or incomparable sequences
        /// are ignored and MUST NOT mutate the table.
        ///
        /// SECURITY: `authenticated_eui64` MUST be the DAO origin/signer EUI-64
        /// established outside this module (DAO Origin Signature plus pinned
        /// Announce per `spec/05-routing.md` 8.6, or the equivalent verified
        /// one-hop signer SIID). It MUST NOT be copied from option 252.
        pub fn process(
            &mut self,
            request: AddressAssignmentRequest,
            dao_sequence: u8,
            authenticated_eui64: [u8; 8],
        ) -> Result<AddressAssignmentAck, AssignmentError> {
            if request.eui64 != authenticated_eui64 {
                return Err(AssignmentError::Protocol(
                    "assignment option EUI-64 does not match authenticated origin",
                ));
            }
            let now = (self.clock)();
            self.prune_expired(Some(now))?;
            let current = self.by_eui.get(&request.eui64).copied();
            if let Some(last) = self.last_sequence_by_eui.get(&request.eui64).copied() {
                if !super::dao_seq_is_newer(dao_sequence, last) {
                    let already_matches = match request.operation {
                        AssignmentOperation::Release => current.is_none(),
                        AssignmentOperation::Allocate => current.is_some(),
                    };
                    return AddressAssignmentAck::new(
                        request.eui64,
                        request.operation,
                        if already_matches {
                            AssignmentStatus::Success
                        } else {
                            AssignmentStatus::Invalid
                        },
                        if already_matches && request.operation == AssignmentOperation::Allocate {
                            current
                        } else {
                            None
                        },
                        dao_sequence,
                    );
                }
            }
            if request.operation == AssignmentOperation::Release {
                if let Some(current) = current {
                    let mut updated = self.by_short.clone();
                    updated.remove(&current);
                    let mut expiries = self.expires_by_eui.clone();
                    expiries.remove(&request.eui64);
                    let mut sequences = self.last_sequence_by_eui.clone();
                    sequences.insert(request.eui64, dao_sequence);
                    self.commit(updated, expiries, sequences)?;
                } else {
                    self.last_sequence_by_eui
                        .insert(request.eui64, dao_sequence);
                }
                return AddressAssignmentAck::new(
                    request.eui64,
                    request.operation,
                    AssignmentStatus::Success,
                    None,
                    dao_sequence,
                );
            }
            let assigned = if let Some(current) = current {
                let mut expiries = self.expires_by_eui.clone();
                if let Some(lease) = self.lease_seconds {
                    let expiry = now
                        .checked_add(lease)
                        .ok_or(AssignmentError::Protocol("lease expiry overflow"))?;
                    expiries.insert(request.eui64, expiry);
                }
                let mut sequences = self.last_sequence_by_eui.clone();
                sequences.insert(request.eui64, dao_sequence);
                self.commit(self.by_short.clone(), expiries, sequences)?;
                current
            } else {
                if self.by_short.len() >= self.capacity as usize {
                    return AddressAssignmentAck::new(
                        request.eui64,
                        request.operation,
                        AssignmentStatus::Exhausted,
                        None,
                        dao_sequence,
                    );
                }
                let Some(current) = self.candidate(&request.eui64, request.requested_short) else {
                    return AddressAssignmentAck::new(
                        request.eui64,
                        request.operation,
                        AssignmentStatus::Exhausted,
                        None,
                        dao_sequence,
                    );
                };
                let mut updated = self.by_short.clone();
                updated.insert(current, request.eui64);
                let mut expiries = self.expires_by_eui.clone();
                if let Some(lease) = self.lease_seconds {
                    let expiry = now
                        .checked_add(lease)
                        .ok_or(AssignmentError::Protocol("lease expiry overflow"))?;
                    expiries.insert(request.eui64, expiry);
                }
                let mut sequences = self.last_sequence_by_eui.clone();
                sequences.insert(request.eui64, dao_sequence);
                self.commit(updated, expiries, sequences)?;
                current
            };
            AddressAssignmentAck::new(
                request.eui64,
                request.operation,
                AssignmentStatus::Success,
                Some(assigned),
                dao_sequence,
            )
        }

        /// Parse a DAO, apply it, and return the DAO-ACK wire image.
        ///
        /// SECURITY: `authenticated_eui64` is the same origin/signer binding
        /// required by [`Self::process`]. Unsigned canonical vectors are
        /// accepted only when the caller supplies that already-verified
        /// identity; option 252 is never treated as provenance.
        pub fn handle_dao(
            &mut self,
            dao_bytes: &[u8],
            authenticated_eui64: [u8; 8],
        ) -> Result<Vec<u8>, AssignmentError> {
            let dao = Dao::from_bytes(dao_bytes)?;
            let request = AddressAssignmentRequest::from_dao_bytes(dao_bytes)?;
            let result = self.process(request, dao.dao_sequence, authenticated_eui64)?;
            result.to_dao_ack_vec(dao.rpl_instance_id, dao.dodag_id)
        }

        /// Apply a DAO after [`crate::dao_origin::DaoOriginValidator`] accepted it.
        ///
        /// Rejects assignment unless the origin result is valid, the preserved
        /// origin matches the authenticated pubkey, and option 252 EUI-64
        /// equals that origin's canonical EUI-64.
        pub fn handle_origin_validated_dao(
            &mut self,
            dao_bytes: &[u8],
            origin: [u8; 16],
            origin_result: &crate::dao_origin::DaoOriginResult,
        ) -> Result<Vec<u8>, AssignmentError> {
            if !origin_result.valid {
                return Err(AssignmentError::Protocol(
                    "assignment DAO origin is not authenticated",
                ));
            }
            let Some(pubkey) = origin_result.pubkey else {
                return Err(AssignmentError::Protocol(
                    "assignment DAO origin is not authenticated",
                ));
            };
            let authenticated_eui64 = super::eui64_from_authenticated_identity(origin, pubkey)?;
            self.handle_dao(dao_bytes, authenticated_eui64)
        }
    }

    fn unix_zero() -> u64 {
        0
    }

    /// Whole seconds elapsed since the Unix epoch.
    ///
    /// Panics when the system clock precedes the epoch. That is the
    /// deliberately conservative failure mode for persistence-backed use:
    /// freezing time at zero leaves every persisted lease below the wall
    /// clock forever, while admitting an unvalidated pre-epoch timestamp
    /// puts `now` on the early side of every stored deadline and evicts the
    /// whole table at once. Both silent outcomes are worse than refusing to
    /// start.
    ///
    /// Intentional divergence from the Python reference twin: its
    /// `ShortAddressCoordinator.prune_expired`
    /// (`python/src/lichen/link/address_assignment.py`) checks
    /// `now >= 0` and raises `ValueError("now must be non-negative")`
    /// instead of panicking. Both implementations fail fast on a pre-epoch
    /// clock and differ only in how loudly they refuse.
    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_secs()
    }
}

#[cfg(feature = "std")]
pub use std_support::{
    decode_assignment_state, encode_assignment_state, AddressAssignmentStore,
    MemoryAddressAssignmentStore, NoStore, ShortAddressCoordinator,
};

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_core::short_addr::{crc32_ieee, derive_short_addr};

    const EUI: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

    fn hex(value: &str) -> std::vec::Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn request_option_roundtrip_without_preferred_address() {
        let request = AddressAssignmentRequest::allocate(EUI, None).unwrap();
        let mut option = [0u8; 16];
        let n = request.write_option(&mut option).unwrap();
        assert_eq!(n, 15);
        assert_eq!(option[0], SHORT_ADDRESS_OPTION_TYPE);
        assert_eq!(option[1], REQUEST_LENGTH as u8);
        let parsed = AddressAssignmentRequest::from_option_data(&option[2..n]).unwrap();
        assert_eq!(parsed, request);
    }

    #[test]
    fn derive_fallback_matches_core_short_addr() {
        assert_eq!(derive_short_addr(&EUI), 0x056E);
        assert_eq!(crc32_ieee(EUI.as_slice(), 0x4348_454e) as u16, 0x056E);
    }

    #[test]
    fn allocate_dao_matches_canonical_hex() {
        let request = AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap();
        let mut out = [0u8; 32];
        let n = request.write_dao(0, 7, None, &mut out).unwrap();
        assert_eq!(&out[..n], hex("00800007fc0d01000000112233445566771234"));
        let parsed = AddressAssignmentRequest::from_dao_bytes(&out[..n]).unwrap();
        assert_eq!(parsed, request);
    }

    #[test]
    fn authenticated_identity_derives_wire_eui_from_key_not_native_origin_bytes() {
        let pubkey = [0x42u8; 32];
        let origin = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
        let raw_iid: [u8; 8] = origin[8..].try_into().unwrap();
        let mut expected_eui = lichen_core::addr::iid_from_pubkey_bytes(&pubkey);
        expected_eui[0] ^= 0x02;

        assert_eq!(
            eui64_from_authenticated_identity(origin, pubkey).unwrap(),
            expected_eui
        );
        assert_ne!(expected_eui, raw_iid);
        assert_eq!(expected_eui[0], raw_iid[0] ^ 0x02);

        let mut non_native = origin;
        non_native[0] = 0x03;
        assert!(eui64_from_authenticated_identity(non_native, pubkey).is_err());

        let low_order = hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
        assert!(eui64_from_authenticated_identity(origin, low_order.try_into().unwrap()).is_err());
    }

    #[test]
    fn apply_dao_ack_requires_root_authentication() {
        let mut client = ShortAddressAssignmentClient::new(EUI);
        let mut ack = [0u8; 32];
        let n = AddressAssignmentAck::new(
            EUI,
            AssignmentOperation::Allocate,
            AssignmentStatus::Success,
            Some(0x1234),
            12,
        )
        .unwrap()
        .write_dao_ack(0, None, &mut ack)
        .unwrap();
        assert!(matches!(
            client.apply_dao_ack(&ack[..n], 12, false),
            Err(AssignmentError::Protocol(
                "DAO-ACK is not root-authenticated"
            ))
        ));
        assert_eq!(client.assigned_short(), None);
        assert!(client.apply_dao_ack(&ack[..n], 12, true).unwrap());
        assert_eq!(client.assigned_short(), Some(0x1234));
    }

    #[cfg(feature = "std")]
    #[test]
    fn process_and_handle_dao_reject_option_eui_not_bound_to_origin() {
        let victim = EUI;
        let attacker = [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut coordinator = ShortAddressCoordinator::new().unwrap();
        coordinator
            .process(
                AddressAssignmentRequest::allocate(victim, Some(0x1234)).unwrap(),
                1,
                victim,
            )
            .unwrap();
        assert_eq!(coordinator.lookup_by_eui(&victim).unwrap(), Some(0x1234));

        let spoofed_allocate = AddressAssignmentRequest::allocate(victim, Some(0x2222)).unwrap();
        assert!(matches!(
            coordinator.process(spoofed_allocate, 2, attacker),
            Err(AssignmentError::Protocol(
                "assignment option EUI-64 does not match authenticated origin"
            ))
        ));
        assert_eq!(coordinator.lookup_by_eui(&victim).unwrap(), Some(0x1234));
        assert_eq!(coordinator.lookup_by_eui(&attacker).unwrap(), None);

        let spoofed_release = AddressAssignmentRequest::release(victim)
            .unwrap()
            .to_dao_vec(0, 3, None)
            .unwrap();
        assert!(matches!(
            coordinator.handle_dao(&spoofed_release, attacker),
            Err(AssignmentError::Protocol(
                "assignment option EUI-64 does not match authenticated origin"
            ))
        ));
        assert_eq!(coordinator.lookup_by_eui(&victim).unwrap(), Some(0x1234));
    }

    #[cfg(feature = "std")]
    #[test]
    fn origin_validated_dao_requires_valid_origin_and_matching_eui() {
        use crate::dao_origin::{DaoOriginRejectReason, DaoOriginResult};

        let pubkey = [0x42u8; 32];
        let origin = lichen_core::addr::ygg_addr_from_pubkey(&pubkey);
        let origin_eui = eui64_from_authenticated_identity(origin, pubkey).unwrap();
        let raw_origin_iid: [u8; 8] = origin[8..].try_into().unwrap();
        let mut coordinator = ShortAddressCoordinator::new().unwrap();
        let dao = AddressAssignmentRequest::allocate(origin_eui, Some(0x1234))
            .unwrap()
            .to_dao_vec(0, 7, None)
            .unwrap();

        assert!(matches!(
            coordinator.handle_origin_validated_dao(
                &dao,
                origin,
                &DaoOriginResult::reject(DaoOriginRejectReason::SignatureMissing),
            ),
            Err(AssignmentError::Protocol(
                "assignment DAO origin is not authenticated"
            ))
        ));
        assert!(coordinator.is_empty());

        let mismatched_key = DaoOriginResult::accept([0x43u8; 32], 1, [0u8; 64], true);
        assert!(matches!(
            coordinator.handle_origin_validated_dao(&dao, origin, &mismatched_key),
            Err(AssignmentError::Protocol(
                "origin address does not match authenticated DAO pubkey"
            ))
        ));

        let foreign_dao = AddressAssignmentRequest::allocate(EUI, Some(0x1234))
            .unwrap()
            .to_dao_vec(0, 7, None)
            .unwrap();
        let accepted = DaoOriginResult::accept(pubkey, 1, [0u8; 64], true);
        assert!(matches!(
            coordinator.handle_origin_validated_dao(&foreign_dao, origin, &accepted),
            Err(AssignmentError::Protocol(
                "assignment option EUI-64 does not match authenticated origin"
            ))
        ));
        assert!(coordinator.is_empty());

        let raw_iid_dao = AddressAssignmentRequest::allocate(raw_origin_iid, Some(0x1234))
            .unwrap()
            .to_dao_vec(0, 7, None)
            .unwrap();
        assert!(matches!(
            coordinator.handle_origin_validated_dao(&raw_iid_dao, origin, &accepted),
            Err(AssignmentError::Protocol(
                "assignment option EUI-64 does not match authenticated origin"
            ))
        ));
        assert!(coordinator.is_empty());

        let ack = coordinator
            .handle_origin_validated_dao(&dao, origin, &accepted)
            .unwrap();
        let parsed = AddressAssignmentAck::from_dao_ack_bytes(&ack).unwrap();
        assert_eq!(parsed.eui64, origin_eui);
        assert_eq!(parsed.assigned_short, Some(0x1234));
        assert_eq!(
            coordinator.lookup_by_eui(&origin_eui).unwrap(),
            Some(0x1234)
        );
    }

    #[cfg(feature = "std")]
    fn sat2_record(
        short_addr: u16,
        eui64: [u8; 8],
        expiry: u64,
        sequence: u16,
    ) -> std::vec::Vec<u8> {
        let mut record = std::vec::Vec::with_capacity(20);
        record.extend_from_slice(&short_addr.to_be_bytes());
        record.extend_from_slice(&eui64);
        record.extend_from_slice(&expiry.to_be_bytes());
        record.extend_from_slice(&sequence.to_be_bytes());
        record
    }

    #[cfg(feature = "std")]
    fn sat2_blob(records: &[std::vec::Vec<u8>]) -> std::vec::Vec<u8> {
        let mut body = b"SAT2".to_vec();
        body.extend_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            body.extend_from_slice(record);
        }
        body.extend_from_slice(&crc32_ieee(&body, 0).to_be_bytes());
        body
    }

    #[cfg(feature = "std")]
    #[test]
    fn with_store_load_prunes_expired_persisted_deadlines() {
        let survivor_eui: [u8; 8] = [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        // Canonical maintenance.initial_expiry (allocated_at 100 + lease 60).
        // Independent oracle: wall clock after 1970-01-01 00:02:40 UTC.
        // A clock frozen at 0 keeps 160 because 160 > 0.
        const PAST_DEADLINE: u64 = 160;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_secs();
        assert!(
            PAST_DEADLINE <= now,
            "wall clock must be after canonical SAT2 lease expiry"
        );

        let expired_row = sat2_record(0x1234, EUI, PAST_DEADLINE, 5);
        let live_row = sat2_record(0x1235, survivor_eui, u64::MAX - 1, 256);
        let blob = sat2_blob(&[expired_row, live_row.clone()]);

        let frozen_store = MemoryAddressAssignmentStore::new(Some(blob.clone()));
        let frozen = ShortAddressCoordinator::with_lease(frozen_store, 2, None, || 0).unwrap();
        assert_eq!(frozen.lookup_by_short(0x1234), Some(EUI));
        assert_eq!(frozen.lookup_by_short(0x1235), Some(survivor_eui));
        assert_eq!(frozen.len(), 2);

        let store = MemoryAddressAssignmentStore::new(Some(blob));
        let coordinator = ShortAddressCoordinator::with_store(store.clone()).unwrap();
        assert_eq!(coordinator.lookup_by_short(0x1234), None);
        assert_eq!(coordinator.lookup_by_short(0x1235), Some(survivor_eui));
        assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), None);
        assert_eq!(
            coordinator.expires_at(&survivor_eui).unwrap(),
            Some(u64::MAX - 1)
        );
        assert_eq!(coordinator.len(), 1);
        drop(coordinator);
        let pruned_state = AddressAssignmentStore::load(&store).unwrap().unwrap();
        assert_eq!(pruned_state, sat2_blob(&[live_row]));
    }

    #[test]
    fn dao_seq_is_newer_matches_rfc6550_section_7_2_vectors() {
        // Independent oracle: RFC 6550 Section 7.2 SEQUENCE_WINDOW=16 cases
        // transcribed from lichen/tests/rpl_dao_sequence/gen_golden_sweep.py.
        // Values are not taken from dao_seq_is_newer.
        let cases: &[(u8, u8, bool)] = &[
            (1, 1, false),
            (2, 1, true),
            (1, 2, false),
            (3, 1, true),
            (0, 255, true),
            (255, 0, false),
            (0, 127, true),
            (16, 0, true),
            (17, 0, false),
            (255, 239, true),
            (255, 238, false),
            (0, 240, true),
            (0, 239, false),
            (250, 10, false),
            (10, 250, true),
        ];
        for &(new_seq, old_seq, expected) in cases {
            assert_eq!(
                dao_seq_is_newer(new_seq, old_seq),
                expected,
                "{new_seq} newer than {old_seq}"
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn stale_release_does_not_drop_a_newer_allocation() {
        let mut coordinator = ShortAddressCoordinator::new().unwrap();
        let allocate = AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap();
        let release = AddressAssignmentRequest::release(EUI).unwrap();

        assert_eq!(
            coordinator
                .process(allocate, 1, EUI)
                .unwrap()
                .assigned_short,
            Some(0x1234)
        );
        assert_eq!(
            coordinator.process(release, 2, EUI).unwrap().status,
            AssignmentStatus::Success
        );
        assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), None);

        assert_eq!(
            coordinator
                .process(allocate, 3, EUI)
                .unwrap()
                .assigned_short,
            Some(0x1234)
        );
        let stale = coordinator.process(release, 2, EUI).unwrap();
        assert_eq!(stale.status, AssignmentStatus::Invalid);
        assert_eq!(stale.assigned_short, None);
        assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), Some(0x1234));
        assert_eq!(coordinator.len(), 1);

        let same_seq_as_allocate = coordinator.process(release, 3, EUI).unwrap();
        assert_eq!(same_seq_as_allocate.status, AssignmentStatus::Invalid);
        assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), Some(0x1234));
    }

    #[cfg(feature = "std")]
    #[test]
    fn duplicate_release_of_current_mapping_is_idempotent() {
        let mut coordinator = ShortAddressCoordinator::new().unwrap();
        coordinator
            .process(
                AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap(),
                10,
                EUI,
            )
            .unwrap();
        let release = AddressAssignmentRequest::release(EUI).unwrap();
        let first = coordinator.process(release, 11, EUI).unwrap();
        let second = coordinator.process(release, 11, EUI).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.status, AssignmentStatus::Success);
        assert_eq!(first.assigned_short, None);
        assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), None);
    }

    #[cfg(feature = "std")]
    #[test]
    fn wrapping_release_applies_and_older_wrap_is_ignored() {
        let mut coordinator = ShortAddressCoordinator::new().unwrap();
        let allocate = AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap();
        let release = AddressAssignmentRequest::release(EUI).unwrap();

        coordinator.process(allocate, 255, EUI).unwrap();
        assert_eq!(
            coordinator.process(release, 0, EUI).unwrap().status,
            AssignmentStatus::Success
        );
        assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), None);

        coordinator.process(allocate, 1, EUI).unwrap();
        let stale_wrap = coordinator.process(release, 255, EUI).unwrap();
        assert_eq!(stale_wrap.status, AssignmentStatus::Invalid);
        assert_eq!(coordinator.lookup_by_eui(&EUI).unwrap(), Some(0x1234));

        const PEER: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        coordinator
            .process(
                AddressAssignmentRequest::allocate(PEER, Some(0x2222)).unwrap(),
                0,
                PEER,
            )
            .unwrap();
        let incomparable = coordinator
            .process(AddressAssignmentRequest::release(PEER).unwrap(), 17, PEER)
            .unwrap();
        assert_eq!(incomparable.status, AssignmentStatus::Invalid);
        assert_eq!(coordinator.lookup_by_eui(&PEER).unwrap(), Some(0x2222));
    }

    #[cfg(feature = "std")]
    #[test]
    fn stale_allocate_does_not_renew_lease() {
        use std::cell::Cell;
        use std::rc::Rc;

        let clock = Rc::new(Cell::new(100u64));
        let clock_now = Rc::clone(&clock);
        let mut coordinator =
            ShortAddressCoordinator::with_lease(NoStore, 1, Some(60), move || clock_now.get())
                .unwrap();
        let request = AddressAssignmentRequest::allocate(EUI, Some(0x1234)).unwrap();
        coordinator.process(request, 5, EUI).unwrap();
        assert_eq!(coordinator.expires_at(&EUI).unwrap(), Some(160));

        clock.set(130);
        let stale = coordinator.process(request, 4, EUI).unwrap();
        assert_eq!(stale.status, AssignmentStatus::Success);
        assert_eq!(stale.assigned_short, Some(0x1234));
        assert_eq!(coordinator.expires_at(&EUI).unwrap(), Some(160));

        let duplicate = coordinator.process(request, 5, EUI).unwrap();
        assert_eq!(duplicate.status, AssignmentStatus::Success);
        assert_eq!(coordinator.expires_at(&EUI).unwrap(), Some(160));

        let renewed = coordinator.process(request, 6, EUI).unwrap();
        assert_eq!(renewed.status, AssignmentStatus::Success);
        assert_eq!(coordinator.expires_at(&EUI).unwrap(), Some(190));
    }
}
