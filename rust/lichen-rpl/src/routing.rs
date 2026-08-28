//! RPL routing table, DAO management, and source-routing header (RFC 6550 §6.7, RFC 6554).
//!
//! Ports `python/src/lichen/rpl/routing.py` and `python/src/lichen/rpl/dao.py`.
//!
//! - `RoutingTable` maps a /128 target to the ordered hop path from root to target.
//! - `DaoManager` builds DAOs (non-root) and assembles routes from incoming DAOs (root).
//! - `SourceRoutingHeader` encodes/decodes the RFC 6554 SRH wire format.

// Re-export from submodules
#[cfg(feature = "std")]
pub use crate::announce::{AnnounceRelayAction, AnnounceState, ANNOUNCE_TYPE, MAX_ANNOUNCE_HOPS};
#[cfg(feature = "std")]
pub use crate::dao_origin::{
    compute_dao_digest, DaoOriginRejectReason, DaoOriginResult, DaoOriginValidator,
    DaoOriginValidatorNoReplay, OriginReplayStore, PinTable, DAO_ORIGIN_SIGNATURE_LENGTH,
    DAO_ORIGIN_SIGNATURE_TYPE,
};
#[cfg(feature = "std")]
pub use crate::persistence::{
    DaoAdmissionState, DaoAdmissionUpdateError, DaoPersistentOpenError, DaoProvisionError,
    DaoRxState, DaoTxError, DaoTxState, MAX_SIGNED_DAO_LEN,
};
#[cfg(feature = "std")]
pub use crate::srh::{SourceRoutingHeader, MAX_ROUTE_HOPS};
pub use crate::table::RouteTarget;
#[cfg(feature = "std")]
pub use crate::table::{
    InvalidRouteEntryTransition, RouteEntry, RouteEntryState, RoutingTable, MAX_ROUTES,
};
#[cfg(feature = "std")]
pub use crate::verify::{
    dao_origin_digest, DaoMalformed, DaoVerifyError, SignatureVerifiedDao, DAO_ORIGIN_DOMAIN,
};

#[cfg(feature = "std")]
use std::{
    collections::{HashMap, HashSet},
    vec,
    vec::Vec,
};

#[cfg(feature = "std")]
use crate::message::{
    Dao, OptionIter, RplTarget, TransitInfo, OPT_RPL_TARGET, OPT_RPL_TARGET_DESCRIPTOR,
    OPT_TRANSIT_INFO,
};
#[cfg(feature = "std")]
use crate::persistence::{
    decode_high_water, encode_high_water, map_open_error, map_rx_update_error, HighWaterMap,
    DAO_RX_KEYS, DAO_RX_MAGIC, HIGH_WATER_HEADER_LEN, HIGH_WATER_PAYLOAD_LEN, HIGH_WATER_SCOPE_LEN,
    SLOT_OVERHEAD,
};
#[cfg(feature = "std")]
use lichen_hal::{
    storage::{open_redundant, provision_redundant, update_redundant, RedundantProvisionError},
    NonVolatile,
};
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
        (true, true) => {
            // Linear region: also has 16-step window per Python reference.
            let diff = (new_seq.wrapping_sub(old_seq)) & 0x7F;
            (1..=LOLLIPOP_SEQUENCE_WINDOW).contains(&diff)
        }
        (false, false) => {
            // Circular region: 16-step window.
            let diff = new_seq.wrapping_sub(old_seq) & 0x7F;
            (1..=LOLLIPOP_SEQUENCE_WINDOW).contains(&diff)
        }
        (true, false) => {
            // New is linear, old is circular: new is newer if within 16 of wrap.
            // Python: 256 + new - old <= 16
            256u16 + u16::from(new_seq) - u16::from(old_seq) <= LOLLIPOP_SEQUENCE_WINDOW.into()
        }
        (false, true) => {
            // New is circular, old is linear: new is newer if >16 steps past wrap.
            // Python: 256 + old - new > 16
            256u16 + u16::from(old_seq) - u16::from(new_seq) > LOLLIPOP_SEQUENCE_WINDOW.into()
        }
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
const MAX_DAO_UPDATES: usize = 64;
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
    NotAdmitted,
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
#[cfg(all(feature = "std", any(test, feature = "test-helpers")))]
const DEFAULT_LIFETIME_UNIT_SECONDS: u64 = 60;
/// Keep expired freshness state long enough to reject delayed replays. Once this
/// finite window passes, the oldest inactive record may be reclaimed at capacity;
/// deployments needing a longer replay horizon must persist freshness externally.
#[cfg(feature = "std")]
const FRESHNESS_TOMBSTONE_RETENTION_SECONDS: u64 = 60 * 60;

#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DaoUpdate {
    target: [u8; 16],
    parent: [u8; 16],
    path_control: u8,
    path_sequence: u8,
    path_lifetime: u8,
    descriptor: Option<u32>,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DaoCandidate {
    parent: [u8; 16],
    path_control: u8,
    path_lifetime: u8,
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Freshness {
    sequence: u8,
    active_until: Option<u64>,
    retain_until: Option<u64>,
    updated_at: u64,
}

#[cfg(feature = "std")]
impl Freshness {
    fn new(sequence: u8, active_until: Option<u64>, updated_at: u64) -> Self {
        let retain_until = active_until
            .map(|deadline| deadline.saturating_add(FRESHNESS_TOMBSTONE_RETENTION_SECONDS));
        Self {
            sequence,
            active_until,
            retain_until,
            updated_at,
        }
    }

    fn is_reclaimable(&self, now_seconds: u64) -> bool {
        self.retain_until
            .is_some_and(|deadline| deadline <= now_seconds)
    }
}

#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DaoTiming {
    now_seconds: u64,
    lifetime_unit_seconds: u64,
    max_deadline_seconds: u64,
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
    last_built_dao: Option<([u8; 16], u8)>,
    parent_map: HashMap<[u8; 16], Vec<[u8; 16]>>,
    edge_expiry: HashMap<([u8; 16], [u8; 16]), Option<u64>>,
    origin_seq_map: HashMap<[u8; 16], Freshness>,
    path_seq_map: HashMap<[u8; 16], Freshness>,
    candidate_map: HashMap<[u8; 16], Vec<DaoCandidate>>,
    descriptor_map: HashMap<[u8; 16], Option<u32>>,
    origin_high_water: HighWaterMap,
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
            edge_expiry: HashMap::new(),
            origin_seq_map: HashMap::new(),
            path_seq_map: HashMap::new(),
            candidate_map: HashMap::new(),
            descriptor_map: HashMap::new(),
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
        dao_admission: &DaoAdmissionState,
    ) -> Result<DaoProcessOutcome, DaoProcessError<S::Error>> {
        self.process_signature_verified_inner(
            verified,
            authenticated_sender_iid,
            rx_state,
            storage,
            timing,
            true,
            dao_admission,
        )
    }

    /// Process a signature-verified DAO while retaining RFC DAOSequence freshness.
    ///
    /// Path Sequence freshness is always enforced independently of the authenticated
    /// 64-bit origin sequence. This stricter compatibility mode additionally checks
    /// the eight-bit DAOSequence.
    pub fn process_signature_verified_with_lollipop<S: NonVolatile>(
        &mut self,
        verified: &SignatureVerifiedDao<'_>,
        authenticated_sender_iid: [u8; 8],
        rx_state: &mut DaoRxState,
        storage: &mut S,
        timing: DaoProcessTiming,
        dao_admission: &DaoAdmissionState,
    ) -> Result<DaoProcessOutcome, DaoProcessError<S::Error>> {
        self.process_signature_verified_inner(
            verified,
            authenticated_sender_iid,
            rx_state,
            storage,
            timing,
            false,
            dao_admission,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn process_signature_verified_inner<S: NonVolatile>(
        &mut self,
        verified: &SignatureVerifiedDao<'_>,
        authenticated_sender_iid: [u8; 8],
        rx_state: &mut DaoRxState,
        storage: &mut S,
        timing: DaoProcessTiming,
        skip_dao_sequence_check: bool,
        dao_admission: &DaoAdmissionState,
    ) -> Result<DaoProcessOutcome, DaoProcessError<S::Error>> {
        if !dao_admission.contains(&verified.public_key) {
            return Err(DaoProcessError::NotAdmitted);
        }
        let sequence = verified.envelope.origin.origin_sequence;

        // Replay check precedes route validation per RFC 6550 security considerations.
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
            return Err(DaoProcessError::NotAdmitted);
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
        if !Self::sender_is_authorized(
            &updates,
            update_count,
            verified.origin,
            self.node_address,
            authenticated_sender_iid,
        ) {
            return Err(DaoProcessError::RouteRejected);
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
        let mut found_origin = false;
        for update in updates[..update_count].iter().flatten() {
            if update.target != origin {
                continue;
            }
            found_origin = true;
            if link_local_origin {
                let canonical_link_local_parent = update.parent[0] == 0xfe
                    && update.parent[1] == 0x80
                    && update.parent[2..8] == [0; 6];
                if !canonical_link_local_parent {
                    return false;
                }
                if update.parent[8..] == root[8..] {
                    if origin[8..] != sender_iid {
                        return false;
                    }
                } else if update.parent[8..] != sender_iid {
                    return false;
                }
            }
        }
        found_origin
    }

    fn has_exact_origin_target(_dao: &Dao, dao_bytes: &[u8], origin: [u8; 16]) -> bool {
        let mut target = None;
        for option in OptionIter::new(Dao::options_tail(dao_bytes)) {
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

    pub fn routing_table_mut(&mut self) -> &mut RoutingTable {
        &mut self.routing_table
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
            external: false,
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
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn process_dao(&mut self, dao_bytes: &[u8]) -> bool {
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
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn process_dao_at(
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
        // D=0 uses Some([0; 16]) sentinel meaning "use receiver's DODAG".
        // Reject if dodag_id is explicitly set to a non-matching, non-sentinel value.
        if dao.rpl_instance_id != self.rpl_instance_id
            || dao
                .dodag_id
                .is_some_and(|dodag_id| dodag_id != [0u8; 16] && dodag_id != self.dodag_id)
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
                    let same_data = proposed_candidates.get(target) == Some(candidates)
                        && proposed_descriptors.get(target).copied().flatten()
                            == incoming_descriptors[target];
                    if same_data {
                        continue;
                    }
                    // Same path_sequence but different data: always reject. Even with 64-bit
                    // origin_sequence authority, mutation at equal path_sequence is invalid.
                    return Err(());
                }
                // Origin replay and Path Sequence protect different state. A fresh signed
                // origin counter cannot authorize an older or incomparable Path Sequence.
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
            let active_until = Self::target_active_until(*target, &proposed_expiry, now_seconds);
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
            .map(|update| Self::target_active_until(update.target, &proposed_expiry, now_seconds))
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
        fallback: u64,
    ) -> Option<u64> {
        // ponytail: fallback is the withdrawal time; without it, withdrawn routes would use epoch 0
        expiry
            .iter()
            .filter_map(|((edge_target, _), deadline)| {
                (*edge_target == target).then_some(*deadline)
            })
            .fold(Some(fallback), Self::max_deadline)
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
        let options = Dao::options_tail(dao_bytes);
        let mut updates = [const { None }; MAX_DAO_UPDATES];
        let mut update_count = 0;
        let mut targets = [const { None }; MAX_DAO_UPDATES];
        let mut descriptors = [const { None }; MAX_DAO_UPDATES];
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
                    let parsed = TransitInfo::from_bytes(opt.data).ok()?;
                    // The current node-owned /128 profile does not admit E=1.
                    if parsed.external {
                        return None;
                    }
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
        Some(())
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
        if node == root || (Self::is_canonical_link_local(&node) && node[8..] == root[8..]) {
            return Ok(true);
        }
        let node = if parent_map.contains_key(&node) {
            node
        } else if Self::is_canonical_link_local(&node) {
            // Transit information names link-local next hops, while RPL targets
            // are primary native addresses. Permit only that protocol-defined
            // canonical alias; never treat an arbitrary prefix with the same
            // lower IID as the same routing identity.
            let mut aliases = parent_map
                .keys()
                .copied()
                .filter(|candidate| candidate[8..] == node[8..]);
            let Some(alias) = aliases.next() else {
                return Ok(false);
            };
            if aliases.next().is_some() {
                return Err(());
            }
            alias
        } else {
            return Ok(false);
        };
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

    fn is_canonical_link_local(address: &[u8; 16]) -> bool {
        address[0] == 0xfe && address[1] == 0x80 && address[2..8].iter().all(|byte| *byte == 0)
    }

    fn path_control_rank(path_control: u8) -> Option<u8> {
        let active_mask = u8::MAX << (7 - PATH_CONTROL_SIZE);
        let masked = path_control & active_mask;
        [6, 4, 2, 0]
            .into_iter()
            .position(|shift| masked & (0x03 << shift) != 0)
            .map(|rank| rank as u8)
    }

    fn contains_cycle(parent_map: &HashMap<[u8; 16], Vec<[u8; 16]>>) -> bool {
        let mut visited = HashSet::new();
        let mut stack = HashSet::new();
        for node in parent_map.keys() {
            if Self::has_cycle_from(*node, parent_map, &mut visited, &mut stack) {
                return true;
            }
        }
        false
    }

    fn has_cycle_from(
        node: [u8; 16],
        parent_map: &HashMap<[u8; 16], Vec<[u8; 16]>>,
        visited: &mut HashSet<[u8; 16]>,
        stack: &mut HashSet<[u8; 16]>,
    ) -> bool {
        if stack.contains(&node) {
            return true;
        }
        if visited.contains(&node) {
            return false;
        }
        visited.insert(node);
        stack.insert(node);
        if let Some(parents) = parent_map.get(&node) {
            for parent in parents {
                if Self::has_cycle_from(*parent, parent_map, visited, stack) {
                    return true;
                }
            }
        }
        stack.remove(&node);
        false
    }

    fn rebuilt_routes(
        root: [u8; 16],
        parent_map: &HashMap<[u8; 16], Vec<[u8; 16]>>,
        candidate_map: &HashMap<[u8; 16], Vec<DaoCandidate>>,
        existing: &RoutingTable,
        _changed_targets: &HashSet<[u8; 16]>,
    ) -> Option<RoutingTable> {
        let mut routes = RoutingTable::new();
        // Copy prefix routes
        for (target, entry) in &existing.routes {
            if target.prefix_len() < 128 {
                routes.routes.insert(*target, entry.clone());
                routes.prefix_route_count += 1;
            }
        }
        routes.rpl_managed_hosts = existing.rpl_managed_hosts.clone();
        routes.rpl_managed_prefixes = existing.rpl_managed_prefixes.clone();
        routes.unavailable_managed_prefixes = existing.unavailable_managed_prefixes.clone();

        // Build host routes
        for target in parent_map.keys() {
            let path = Self::assemble_path_checked(root, parent_map, candidate_map, *target);
            match path {
                Ok(Some(path)) => {
                    if routes.routes.len() >= MAX_ROUTES {
                        return None;
                    }
                    routes
                        .routes
                        .insert(RouteTarget::host(*target), RouteEntry::fresh(&path));
                    routes.rpl_managed_hosts.insert(*target);
                }
                Ok(None) => {}
                Err(()) => return None,
            }
        }

        // Reconcile managed prefixes
        for (prefix, egress) in &existing.rpl_managed_prefixes {
            if !routes.rpl_managed_hosts.contains(egress) {
                routes.unavailable_managed_prefixes.insert(*prefix);
                if let Some(entry) = routes.routes.get_mut(prefix) {
                    let _ = entry.mark_expired();
                }
            } else if let Some(path) = routes.lookup(egress) {
                let egress_path = path.to_vec();
                if !egress_path.is_empty() {
                    routes
                        .routes
                        .insert(*prefix, RouteEntry::fresh(&egress_path));
                    routes.unavailable_managed_prefixes.remove(prefix);
                }
            }
        }

        Some(routes)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn ll(iid: u8) -> [u8; 16] {
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid]
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
    fn srh_encode_decode_roundtrip() {
        use crate::srh::SourceRoutingHeader;
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
    fn announce_state_local_seq_wraps() {
        use crate::announce::AnnounceState;
        let mut state = AnnounceState::new();
        assert_eq!(state.local_seq(), 0);
        assert_eq!(state.bump_local_seq(), 1);
        assert_eq!(state.local_seq(), 1);
        assert_eq!(state.bump_local_seq(), 2);
    }
}
