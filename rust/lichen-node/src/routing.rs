//! Routing integration: wraps lichen-rpl with neighbor tracking and node-level API.
//!
//! RPL Non-Storing Mode (MOP=1) is the primary routing protocol. The `Router`
//! type owns DODAG state, trickle timer, and neighbor table, providing a
//! unified interface for the node's receive/transmit paths.
//!
//! Also provides GPSR geographic forwarding fallback (spec 9.7) when gradient
//! routes are unavailable and LOADng discovery times out.
//!
//! Requires `std` feature for full RPL integration.

#[cfg(feature = "std")]
use lichen_core::constants::RPL_INSTANCE_ID;
#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "std")]
use lichen_hal::NonVolatile;
#[cfg(feature = "std")]
use lichen_link::{identity::iid_from_pubkey, link_layer::LinkLayer};
#[cfg(feature = "std")]
use lichen_rpl::dodag::DioOutcome;
#[cfg(feature = "std")]
pub use lichen_rpl::dodag::{DodagRole, DodagState, ParentCandidate, ROOT_RANK};
#[cfg(feature = "std")]
use lichen_rpl::message::DODAG_CONFIG_DATA_LEN;
#[cfg(feature = "std")]
pub use lichen_rpl::message::{
    Dao, DaoOriginSignature, Dio, DodagConfig, OptionIter, RplError, RplTarget, SignedDaoEnvelope,
    TransitInfo, DAO_ORIGIN_SIGNATURE_LEN, OPT_DODAG_CONFIG, OPT_RPL_TARGET, OPT_TRANSIT_INFO,
};
#[cfg(feature = "std")]
use lichen_rpl::routing::SignatureVerifiedDao;
#[cfg(feature = "std")]
pub(crate) use lichen_rpl::routing::{
    dao_origin_digest, DaoManager, DaoProcessError, DaoProcessOutcome, DaoProcessTiming,
    DaoTxError, DaoTxState, DaoVerifyError,
};
#[cfg(feature = "std")]
pub use lichen_rpl::routing::{
    DaoPersistentOpenError, DaoProvisionError, DaoRxState, RouteTarget, RoutingTable,
    SourceRoutingHeader,
};
#[cfg(feature = "std")]
pub use lichen_rpl::trickle::{TrickleEvent, TrickleTimer};

#[cfg(feature = "std")]
fn trickle_from_config(config: &DodagConfig) -> Option<TrickleTimer> {
    let imin_ms = 1u32
        .checked_shl(u32::from(config.dio_int_min))
        .unwrap_or(0);
    if imin_ms == 0 || config.dio_redundancy_const == 0 {
        return None;
    }
    Some(TrickleTimer::new(
        imin_ms,
        u32::from(config.dio_int_doublings),
        u32::from(config.dio_redundancy_const),
    ))
}

#[cfg(feature = "std")]
fn version_cmp(a: u8, b: u8) -> Option<core::cmp::Ordering> {
    if a == b {
        Some(core::cmp::Ordering::Equal)
    } else if (a, b) == (0, 127) {
        Some(core::cmp::Ordering::Greater)
    } else {
        let a_linear = a < 128;
        let b_linear = b < 128;
        if a_linear == b_linear {
            let diff = a.abs_diff(b);
            if diff <= 16 {
                Some(a.cmp(&b))
            } else {
                None
            }
        } else if a_linear {
            Some(core::cmp::Ordering::Greater)
        } else {
            Some(core::cmp::Ordering::Less)
        }
    }
}

/// Maximum neighbors tracked.
pub const MAX_NEIGHBORS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DioProcessOutcome {
    Rejected,
    Consistent,
    Inconsistent,
}

/// Effects of one cohesive routing maintenance observation.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RplMaintenanceOutcome {
    pub routes_expired: bool,
    pub neighbors_pruned: bool,
    pub topology_changed: bool,
}

#[cfg(feature = "std")]
pub trait TrickleSafeLivenessPolicy {
    fn confirmation(&self, now_ms: u64, last_seen_ms: u64, max_age_ms: u64) -> bool;
}

#[cfg(feature = "std")]
impl TrickleSafeLivenessPolicy for () {
    fn confirmation(&self, _now_ms: u64, _last_seen_ms: u64, _max_age_ms: u64) -> bool {
        true
    }
}

#[cfg(feature = "std")]
impl DioProcessOutcome {
    fn accepted(inconsistent: bool) -> Self {
        if inconsistent {
            Self::Inconsistent
        } else {
            Self::Consistent
        }
    }

    fn is_inconsistent(self) -> bool {
        self == Self::Inconsistent
    }
}

#[cfg(feature = "std")]
const NON_STORING_MOP: u8 = 1;
#[cfg(feature = "std")]
const MRHOF_OCP: u16 = 1;
#[cfg(feature = "std")]
fn sign_dao(
    unsigned_dao: &[u8],
    origin: [u8; 16],
    active_dodag_id: [u8; 16],
    origin_sequence: u64,
    link: &LinkLayer,
) -> Option<Vec<u8>> {
    if origin_sequence == 0 || origin[8..] != iid_from_pubkey(&link.local_public_key()) {
        return None;
    }
    let dao = Dao::from_bytes(unsigned_dao).ok()?;
    for option in OptionIter::new(dao.options_tail(unsigned_dao)) {
        if option.ok()?.opt_type == lichen_rpl::message::OPT_DAO_ORIGIN_SIGNATURE {
            return None;
        }
    }
    let dodag_id = dao.dodag_id.unwrap_or(active_dodag_id);
    if dao.dodag_id.is_some_and(|id| id != active_dodag_id) {
        return None;
    }
    let digest = dao_origin_digest(origin, dodag_id, origin_sequence, unsigned_dao);
    let signature = link.sign_digest(&digest);
    let mut wire = Vec::with_capacity(unsigned_dao.len() + DAO_ORIGIN_SIGNATURE_LEN);
    wire.extend_from_slice(unsigned_dao);
    let old_len = wire.len();
    wire.resize(old_len + DAO_ORIGIN_SIGNATURE_LEN, 0);
    DaoOriginSignature::write_to(origin_sequence, &signature, &mut wire[old_len..]).ok()?;
    Some(wire)
}

/// Link quality estimate (ETX as f32: 1.0 = perfect link).
pub type LinkEtx = f32;

/// Geographic coordinates (latitude, longitude) in decimal degrees.
pub type GeoCoords = (f64, f64);

pub trait TrickleSafeLivenessPolicy {
    fn is_alive(&self, last_seen: u64, now: u64, timeout: u64) -> bool {
        now.saturating_sub(last_seen) <= timeout
    }
}

impl TrickleSafeLivenessPolicy for () {}

/// Neighbor entry with link quality tracking and optional coordinates.
#[derive(Clone, Debug)]
pub struct Neighbor {
    pub addr: [u8; 16],
    pub etx: LinkEtx,
    /// Last observation on the caller's monotonic millisecond timeline.
    pub last_seen_ms: u64,
    pub rssi: i8,
    /// Geographic coordinates from announce app_data (spec 9.7).
    /// None if neighbor hasn't advertised coords.
    pub coords: Option<GeoCoords>,
}

/// Neighbor table for link quality tracking.
#[derive(Clone, Debug)]
pub struct NeighborTable {
    entries: [Option<Neighbor>; MAX_NEIGHBORS],
    last_now_ms: u64,
}

impl NeighborTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_NEIGHBORS],
            last_now_ms: 0,
        }
    }

    /// Update or insert a neighbor. Returns the slot index.
    ///
    /// `now_ms` must use one nondecreasing monotonic `u64` timeline.
    pub fn update(&mut self, addr: &[u8; 16], etx: LinkEtx, rssi: i8, now_ms: u64) -> usize {
        self.update_with_coords(addr, etx, rssi, now_ms, None)
    }

    /// Update or insert a neighbor with optional coordinates.
    pub fn update_with_coords(
        &mut self,
        addr: &[u8; 16],
        etx: LinkEtx,
        rssi: i8,
        now_ms: u64,
        coords: Option<GeoCoords>,
    ) -> usize {
        self.update_with_coords_and_eviction(addr, etx, rssi, now_ms, coords, None)
            .0
    }

    fn update_with_coords_and_eviction(
        &mut self,
        addr: &[u8; 16],
        etx: LinkEtx,
        rssi: i8,
        now_ms: u64,
        coords: Option<GeoCoords>,
        protected: Option<[u8; 16]>,
    ) -> (usize, Option<[u8; 16]>) {
        let now_ms = now_ms.max(self.last_now_ms);
        self.last_now_ms = now_ms;
        // Find existing or empty slot
        let mut empty_slot = None;
        for (i, slot) in self.entries.iter_mut().enumerate() {
            match slot {
                Some(n) if n.addr == *addr => {
                    n.etx = etx;
                    n.rssi = rssi;
                    n.last_seen_ms = now_ms;
                    if coords.is_some() {
                        n.coords = coords;
                    }
                    return (i, None);
                }
                None if empty_slot.is_none() => empty_slot = Some(i),
                _ => {}
            }
        }
        // Insert new
        if let Some(i) = empty_slot {
            self.entries[i] = Some(Neighbor {
                addr: *addr,
                etx,
                rssi,
                last_seen_ms: now_ms,
                coords,
            });
            return (i, None);
        }
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|n| (i, n.last_seen_ms)))
            .max_by_key(|(i, t)| (now_ms.wrapping_sub(*t), MAX_NEIGHBORS - *i))
            .map(|(i, _)| i)
            .unwrap_or(0);
        let evicted = self.entries[oldest].as_ref().map(|neighbor| neighbor.addr);
        self.entries[oldest] = Some(Neighbor {
            addr: *addr,
            etx,
            rssi,
            last_seen_ms: now_ms,
            coords,
        });
        (oldest, evicted)
    }

    /// Get neighbor ETX, or None if unknown.
    pub fn get_etx(&self, addr: &[u8; 16]) -> Option<LinkEtx> {
        self.entries
            .iter()
            .flatten()
            .find(|n| n.addr == *addr)
            .map(|n| n.etx)
    }

    /// Get neighbor coordinates, or None if unknown or not advertised.
    pub fn get_coords(&self, addr: &[u8; 16]) -> Option<GeoCoords> {
        self.entries
            .iter()
            .flatten()
            .find(|n| n.addr == *addr)
            .and_then(|n| n.coords)
    }

    /// Update coordinates for an existing neighbor. Does nothing if neighbor not found.
    pub fn set_coords(&mut self, addr: &[u8; 16], coords: GeoCoords) {
        for n in self.entries.iter_mut().flatten() {
            if n.addr == *addr {
                n.coords = Some(coords);
                return;
            }
        }
    }

    pub fn prune(&mut self, now_ms: u64, max_age_ms: u64) {
        let policy = TrickleAwareNeighborLiveness::default();
        self.prune_with_removed(&policy, now_ms, max_age_ms, 0, |_| {});
    }

    #[cfg(feature = "std")]
    fn prune_with_removed<P: TrickleSafeLivenessPolicy>(
        &mut self,
        policy: &P,
        now_ms: u64,
        max_age_ms: u64,
        heard_consistent: u32,
        mut removed: impl FnMut([u8; 16]),
        policy: &P,
    ) {
        let now_ms = now_ms.max(self.last_now_ms);
        self.last_now_ms = now_ms;
        for slot in self.entries.iter_mut() {
            let is_stale = slot.as_ref().map_or(false, |neighbor| {
                !policy.is_alive(
                    neighbor.last_seen_ms,
                    now_ms,
                    max_age_ms,
                    heard_consistent,
                )
            });
            if is_stale {
                let neighbor = slot.take().expect("stale slot contains a neighbor");
                removed(neighbor.addr);
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Neighbor> {
        self.entries.iter().flatten()
    }

    pub fn count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    pub fn is_likely_alive<P: TrickleSafeLivenessPolicy>(
        &self,
        policy: &P,
        addr: &[u8; 16],
        now_ms: u64,
        max_age_ms: u64,
        heard_consistent: u32,
    ) -> bool {
        self.entries
            .iter()
            .flatten()
            .find(|n| n.addr == *addr)
            .map_or(false, |n| {
                policy.is_alive(n.last_seen_ms, now_ms, max_age_ms, heard_consistent)
            })
    }
}

impl Default for NeighborTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl NeighborTable {
    /// Trickle-aware liveness policy per RFC 6206 and RPL neighbor timeout.
    ///
    /// Factors in TrickleTimer::counter (from heard_consistent) to avoid
    /// premature eviction of suppressed neighbors in dense networks (when
    /// counter >= k, transmissions suppressed). Scales effective timeout
    /// up to 3x under full suppression. Design doc as specified in
    /// project-LICHEN-2auf.44.11.7.1.1.
    pub fn is_trickle_aware_live(
        &self,
        addr: &[u8; 16],
        trickle: &TrickleTimer,
        now_ms: u64,
        max_age_ms: u64,
    ) -> bool {
        let Some(neighbor) = self
            .entries
            .iter()
            .flatten()
            .find(|n| n.addr == *addr)
        else {
            return false;
        };
        let age = now_ms.saturating_sub(neighbor.last_seen_ms);
        if age <= max_age_ms {
            return true;
        }
        let k = u64::from(trickle.k);
        if k == 0 {
            return false;
        }
        let c = u64::from(trickle.counter.min(trickle.k));
        let scale = 1 + (2 * c / k);
        age <= max_age_ms * scale
    }

    pub fn prune_trickle_safe(
        &mut self,
        now_ms: u64,
        max_age_ms: u64,
        trickle: &TrickleTimer,
        mut removed: impl FnMut([u8; 16]),
    ) {
        let now_ms = now_ms.max(self.last_now_ms);
        self.last_now_ms = now_ms;
        for slot in self.entries.iter_mut() {
            let is_stale = slot.as_ref().is_some_and(|neighbor| {
                !self.is_trickle_aware_live(&neighbor.addr, trickle, now_ms, max_age_ms)
            });
            if is_stale {
                let neighbor = slot.take().expect("stale slot contains a neighbor");
                removed(neighbor.addr);
            }
        }
    }
}

/// Unified routing state combining DODAG, trickle, DAO manager, and neighbor table.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct Router {
    dodag: DodagState,
    trickle: TrickleTimer,
    dao_manager: DaoManager,
    neighbors: NeighborTable,
    dodag_id: [u8; 16],
    dodag_config: DodagConfig,
    last_now_ms: u64,
    /// This node's geographic coordinates for GPSR (spec 9.7).
    /// None if GPS unavailable or privacy mode enabled.
    pub node_coords: Option<GeoCoords>,
    #[cfg(test)]
    test_storage: lichen_hal::storage::mem::MemStorage,
    #[cfg(test)]
    test_rx_state: Option<DaoRxState>,
    #[cfg(test)]
    test_origin_sequence: u64,
}

#[cfg(feature = "std")]
impl Router {
    /// Create a new router for a non-root node.
    pub fn new(node_addr: [u8; 16], dodag_id: [u8; 16]) -> Self {
        let dodag_config = DodagConfig::default();
        Self {
            dodag: DodagState::new(RPL_INSTANCE_ID, dodag_id, 0),
            trickle: trickle_from_config(&dodag_config).expect("default Trickle config is valid"),
            dao_manager: DaoManager::new(node_addr, RPL_INSTANCE_ID, dodag_id),
            neighbors: NeighborTable::new(),
            dodag_id,
            dodag_config,
            last_now_ms: 0,
            node_coords: None,
            #[cfg(test)]
            test_storage: lichen_hal::storage::mem::MemStorage::new(),
            #[cfg(test)]
            test_rx_state: None,
            #[cfg(test)]
            test_origin_sequence: 0,
        }
    }

    fn root_with_manager(
        node_addr: [u8; 16],
        dodag_config: DodagConfig,
        dao_manager: DaoManager,
    ) -> Option<Self> {
        if dodag_config.min_hop_rank_increase == 0
            || dodag_config.lifetime_unit == 0
            || dodag_config.ocp != MRHOF_OCP
        {
            return None;
        }
        let trickle = trickle_from_config(&dodag_config)?;
        let dodag_id = node_addr; // Root's address is DODAG ID
        let dodag = DodagState::as_root_with_rank_config(
            RPL_INSTANCE_ID,
            dodag_id,
            0,
            dodag_config.min_hop_rank_increase,
            dodag_config.max_rank_increase,
        )?;
        Some(Self {
            dodag,
            trickle,
            dao_manager,
            neighbors: NeighborTable::new(),
            dodag_id,
            dodag_config,
            last_now_ms: 0,
            node_coords: None,
            #[cfg(test)]
            test_storage: lichen_hal::storage::mem::MemStorage::new(),
            #[cfg(test)]
            test_rx_state: None,
            #[cfg(test)]
            test_origin_sequence: 0,
        })
    }

    pub(crate) fn provision_root<S: NonVolatile>(
        storage: &mut S,
        node_addr: [u8; 16],
    ) -> Result<(Self, DaoRxState), DaoProvisionError<S::Error>> {
        let (manager, state) =
            DaoManager::provision_root(storage, node_addr, RPL_INSTANCE_ID, node_addr)?;
        let router = Self::root_with_manager(node_addr, DodagConfig::default(), manager)
            .expect("default DODAG config is valid");
        Ok((router, state))
    }

    pub(crate) fn open_root<S: NonVolatile>(
        storage: &S,
        node_addr: [u8; 16],
    ) -> Result<(Self, DaoRxState), DaoPersistentOpenError<S::Error>> {
        let (manager, state) =
            DaoManager::open_root(storage, node_addr, RPL_INSTANCE_ID, node_addr)?;
        let router = Self::root_with_manager(node_addr, DodagConfig::default(), manager)
            .expect("default DODAG config is valid");
        Ok((router, state))
    }

    #[cfg(test)]
    pub(crate) fn new_root(node_addr: [u8; 16]) -> Self {
        Self::new_root_with_config(node_addr, DodagConfig::default()).unwrap()
    }

    #[cfg(test)]
    fn new_root_with_config(node_addr: [u8; 16], config: DodagConfig) -> Option<Self> {
        if config.min_hop_rank_increase == 0 || config.lifetime_unit == 0 || config.ocp != MRHOF_OCP
        {
            return None;
        }
        let mut storage = lichen_hal::storage::mem::MemStorage::new();
        let (manager, state) =
            DaoManager::provision_root(&mut storage, node_addr, RPL_INSTANCE_ID, node_addr).ok()?;
        let mut router = Self::root_with_manager(node_addr, config, manager)?;
        router.test_storage = storage;
        router.test_rx_state = Some(state);
        Some(router)
    }

    /// Process a received DIO message from a neighbor.
    ///
    /// Updates neighbor table, feeds DODAG state machine, and returns whether
    /// the trickle timer should be reset (inconsistent DIO heard). `now_ms`
    /// must use one nondecreasing monotonic `u64` timeline.
    pub fn process_dio(
        &mut self,
        dio: &Dio,
        dio_bytes: &[u8],
        sender_addr: [u8; 16],
        rssi: i8,
        now_ms: u64,
    ) -> bool {
        self.process_dio_outcome(dio, dio_bytes, sender_addr, rssi, now_ms)
            .is_inconsistent()
    }

    pub fn process_dio_outcome(
        &mut self,
        dio: &Dio,
        dio_bytes: &[u8],
        sender_addr: [u8; 16],
        rssi: i8,
        now_ms: u64,
    ) -> DioProcessOutcome {
        let etx = self.neighbors.get_etx(&sender_addr).unwrap_or(1.0);
        self.process_dio_with_etx_outcome(dio, dio_bytes, sender_addr, etx, rssi, now_ms)
    }

    /// Process a DIO using a measured link ETX.
    pub fn process_dio_with_etx(
        &mut self,
        dio: &Dio,
        dio_bytes: &[u8],
        sender_addr: [u8; 16],
        etx: LinkEtx,
        rssi: i8,
        now_ms: u64,
    ) -> bool {
        self.process_dio_with_etx_outcome(dio, dio_bytes, sender_addr, etx, rssi, now_ms)
            .is_inconsistent()
    }

    pub fn process_dio_with_etx_outcome(
        &mut self,
        dio: &Dio,
        dio_bytes: &[u8],
        sender_addr: [u8; 16],
        etx: LinkEtx,
        rssi: i8,
        now_ms: u64,
    ) -> DioProcessOutcome {
        let now_ms = self.observe_now(now_ms);
        if !etx.is_finite() || etx < 1.0 {
            return DioProcessOutcome::Rejected;
        }
        if Dio::from_bytes(dio_bytes).as_ref() != Ok(dio) {
            return DioProcessOutcome::Rejected;
        }
        if self.dodag.is_root()
            || dio.rpl_instance_id != self.dodag.rpl_instance_id
            || dio.dodag_id != self.dodag_id
            || dio.mode_of_operation != NON_STORING_MOP
        {
            return DioProcessOutcome::Rejected;
        }

        let Some(version_order) = version_cmp(dio.version, self.dodag.version) else {
            return DioProcessOutcome::Rejected;
        };
        if version_order.is_lt() {
            return DioProcessOutcome::Rejected;
        }

        let mut proposed_config = self.dodag_config.clone();
        for option in OptionIter::new(Dio::options_tail(dio_bytes)) {
            let Ok(option) = option else {
                return DioProcessOutcome::Rejected;
            };
            if option.opt_type == OPT_DODAG_CONFIG {
                if option.data.len() != DODAG_CONFIG_DATA_LEN {
                    return DioProcessOutcome::Rejected;
                }
                let Ok(parsed) = DodagConfig::from_bytes(option.data) else {
                    return DioProcessOutcome::Rejected;
                };
                if parsed.min_hop_rank_increase == 0
                    || parsed.min_hop_rank_increase > u16::MAX / 2
                    || parsed.lifetime_unit == 0
                    || parsed.ocp != MRHOF_OCP
                    || trickle_from_config(&parsed).is_none()
                {
                    return DioProcessOutcome::Rejected;
                }
                proposed_config = parsed;
            }
        }
        let neighbor_known = self.neighbors.get_etx(&sender_addr).is_some();
        if dio.rank == u16::MAX {
            if !version_order.is_eq() || !neighbor_known {
                return DioProcessOutcome::Rejected;
            }
            let was_joined = self.dodag.is_joined();
            let old_parent = self.dodag.preferred_parent;
            let old_rank = self.dodag.rank;
            self.neighbors.update(&sender_addr, etx, rssi, now_ms);
            self.dodag.remove_parent(&sender_addr);
            let inconsistent = old_rank != self.dodag.rank
                || was_joined != self.dodag.is_joined()
                || old_parent != self.dodag.preferred_parent;
            if inconsistent {
                self.trickle.reset(now_ms, 0);
            }
            return DioProcessOutcome::accepted(inconsistent);
        }

        let was_joined = self.dodag.is_joined();
        let old_parent = self.dodag.preferred_parent;
        let old_rank = self.dodag.rank;
        let old_version = self.dodag.version;
        let config_changed = proposed_config != self.dodag_config;

        let mut staged_dodag = self.dodag.clone();
        let applied = staged_dodag.set_rank_config(
            proposed_config.min_hop_rank_increase,
            proposed_config.max_rank_increase,
        );
        if !applied {
            return DioProcessOutcome::Rejected;
        }
        let mut staged_neighbors = self.neighbors.clone();
        let (_, evicted) = staged_neighbors.update_with_coords_and_eviction(
            &sender_addr,
            etx,
            rssi,
            now_ms,
            None,
            staged_dodag.preferred_parent,
        );
        if let Some(evicted) = evicted {
            staged_dodag.remove_parent(&evicted);
        }
        match staged_dodag.process_dio(dio, sender_addr, etx) {
            DioOutcome::Accepted => {}
            DioOutcome::Removed if !config_changed => {
                self.dodag = staged_dodag;
                self.neighbors = staged_neighbors;
                let inconsistent = old_rank != self.dodag.rank
                    || was_joined != self.dodag.is_joined()
                    || old_parent != self.dodag.preferred_parent;
                if inconsistent {
                    self.trickle.reset(now_ms, 0);
                }
                return DioProcessOutcome::accepted(inconsistent);
            }
            DioOutcome::Removed | DioOutcome::Rejected => return DioProcessOutcome::Rejected,
        }

        self.dodag = staged_dodag;
        self.neighbors = staged_neighbors;
        self.dodag_config = proposed_config;

        let now_joined = self.dodag.is_joined();
        let new_parent = self.dodag.preferred_parent;
        let inconsistent = config_changed
            || old_version != self.dodag.version
            || old_rank != self.dodag.rank
            || was_joined != now_joined
            || old_parent != new_parent;
        if inconsistent {
            if config_changed {
                self.trickle = trickle_from_config(&self.dodag_config)
                    .expect("accepted Trickle config was validated");
                self.trickle.start(now_ms, 0);
            } else {
                self.trickle.reset(now_ms, 0);
            }
        }
        DioProcessOutcome::accepted(inconsistent)
    }

    #[cfg(test)]
    fn process_dao_at_times(
        &mut self,
        dao_bytes: &[u8],
        packet_source: [u8; 16],
        authenticated_sender: [u8; 16],
        _expire_seconds: u64,
        lifetime_start_seconds: u64,
    ) -> bool {
        if !self.dodag.is_root() {
            return false;
        }

        let Some(parents) = dao_parents_for_source(dao_bytes, &packet_source) else {
            return false;
        };
        // A direct child signs its own DAO. Beyond one hop, L2 authentication
        // establishes only the forwarding neighbor, not the DAO originator.
        if parents
            .iter()
            .any(|parent| same_interface(parent, &self.dodag_id))
            && !same_interface(&authenticated_sender, &packet_source)
        {
            return false;
        }

        #[cfg(test)]
        {
            use lichen_link::{identity::Identity, keys::Seed};
            let Some(identity) = (0u8..=u8::MAX)
                .map(|seed| Identity::from_seed(Seed::new([seed; 32])))
                .find(|identity| identity.iid == packet_source[8..])
            else {
                return false;
            };
            let mut origin = [0u8; 16];
            origin[..2].copy_from_slice(&[0xfe, 0x80]);
            origin[8..].copy_from_slice(&identity.iid);
            self.test_origin_sequence += 1;
            let Some(wire) = sign_dao(
                dao_bytes,
                origin,
                self.dodag_id,
                self.test_origin_sequence,
                &LinkLayer::new(identity.clone()),
            ) else {
                return false;
            };
            let Ok(verified) = SignatureVerifiedDao::verify_signature(
                &wire,
                origin,
                RPL_INSTANCE_ID,
                self.dodag_id,
                Some(identity.pubkey),
            ) else {
                return false;
            };
            let state = self.test_rx_state.as_mut().expect("test root has RX state");
            self.dao_manager
                .process_signature_verified_with_lollipop(
                    &verified,
                    identity.iid,
                    state,
                    &mut self.test_storage,
                    DaoProcessTiming {
                        now_seconds: lifetime_start_seconds,
                        lifetime_unit_seconds: u64::from(self.dodag_config.lifetime_unit),
                        max_deadline_seconds: u64::MAX / 1_000,
                    },
                )
                .is_ok()
        }
        #[cfg(not(test))]
        {
            let _ = (expire_seconds, lifetime_start_seconds);
            false
        }
    }

    #[cfg(test)]
    pub(crate) fn process_signature_verified_dao_at_ms<S: NonVolatile>(
        &mut self,
        dao: &SignatureVerifiedDao<'_>,
        authenticated_sender_iid: [u8; 8],
        rx_state: &mut DaoRxState,
        storage: &mut S,
        now_ms: u64,
    ) -> Result<DaoProcessOutcome, DaoProcessError<S::Error>> {
        self.process_signature_verified_dao_from_at_ms(
            dao,
            authenticated_sender_iid,
            rx_state,
            storage,
            now_ms,
        )
    }

    pub(crate) fn process_signature_verified_dao_from_at_ms<S: NonVolatile>(
        &mut self,
        dao: &SignatureVerifiedDao<'_>,
        authenticated_sender_iid: [u8; 8],
        rx_state: &mut DaoRxState,
        storage: &mut S,
        now_ms: u64,
    ) -> Result<DaoProcessOutcome, DaoProcessError<S::Error>> {
        if !self.dodag.is_root() {
            return Err(DaoProcessError::RouteRejected);
        }
        let now_ms = now_ms.max(self.last_now_ms);
        let expire_seconds = now_ms / 1_000;
        let lifetime_start_seconds = expire_seconds + u64::from(!now_ms.is_multiple_of(1_000));
        let outcome = self.dao_manager.process_signature_verified(
            dao,
            authenticated_sender_iid,
            rx_state,
            storage,
            DaoProcessTiming {
                now_seconds: lifetime_start_seconds,
                lifetime_unit_seconds: u64::from(self.dodag_config.lifetime_unit),
                max_deadline_seconds: u64::MAX / 1_000,
            },
        )?;
        if outcome == DaoProcessOutcome::Applied {
            self.last_now_ms = now_ms;
        }
        Ok(outcome)
    }

    #[cfg(test)]
    pub(crate) fn process_dao_at_ms(
        &mut self,
        dao_bytes: &[u8],
        packet_source: [u8; 16],
        authenticated_sender: [u8; 16],
        now_ms: u64,
    ) -> bool {
        let now_ms = self.observe_now(now_ms);
        let expire_seconds = now_ms / 1_000;
        let lifetime_start_seconds = expire_seconds + u64::from(!now_ms.is_multiple_of(1_000));
        self.process_dao_at_times(
            dao_bytes,
            packet_source,
            authenticated_sender,
            expire_seconds,
            lifetime_start_seconds,
        )
    }

    /// Build a DAO message to send to parent.
    ///
    /// Returns the DAO bytes, or empty vec if not joined.
    #[cfg(test)]
    pub(crate) fn build_dao(&mut self) -> Vec<u8> {
        if let Some(parent) = self.dodag.preferred_parent {
            self.dao_manager
                .build_dao_with_lifetime(parent, self.dodag_config.def_lifetime)
        } else {
            Vec::new()
        }
    }

    /// Build and sign one logical DAO with a caller-persisted origin sequence.
    /// Retransmissions must resend the returned bytes rather than call this again.
    pub(crate) fn build_signed_dao<S: NonVolatile>(
        &mut self,
        origin_ipv6: [u8; 16],
        tx_state: &mut DaoTxState,
        storage: &mut S,
        link: &LinkLayer,
    ) -> Result<Vec<u8>, DaoTxError<S::Error>> {
        let Some(parent) = self.dodag.preferred_parent else {
            return Err(DaoTxError::NotJoined);
        };
        if origin_ipv6[8..] != iid_from_pubkey(&link.local_public_key()) {
            return Err(DaoTxError::InvalidOrigin);
        }
        if !tx_state.is_for_scope(
            &link.local_public_key(),
            origin_ipv6,
            RPL_INSTANCE_ID,
            self.dodag_id,
        ) {
            return Err(DaoTxError::KeyMismatch);
        }
        let sequence = tx_state.reserve_next(storage)?;
        let unsigned = self
            .dao_manager
            .build_dao_with_lifetime(parent, self.dodag_config.def_lifetime);
        let wire = sign_dao(&unsigned, origin_ipv6, self.dodag_id, sequence, link)
            .ok_or(DaoTxError::Encoding)?;
        tx_state.finalize_signed(storage, sequence, &wire)?;
        Ok(wire)
    }

    /// Build a DIO message to advertise.
    ///
    /// Returns the number of bytes written.
    pub fn build_dio(&self, out: &mut [u8]) -> usize {
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: self.dodag.version,
            rank: self.dodag.rank,
            grounded: true,
            mode_of_operation: 1, // Non-Storing
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: self.dodag_id,
        };
        let Ok(base_len) = dio.write_to(out) else {
            return 0;
        };
        let Ok(config_len) = self.dodag_config.write_to(&mut out[base_len..]) else {
            return 0;
        };
        base_len + config_len
    }

    /// Get the route path for a destination (root only).
    ///
    /// Non-root nodes always return `None` (routing table is root-only in non-storing RPL mode per spec/05-routing.md). Error handling for invalid dst is delegated to routing_table.lookup.
    pub fn lookup_route(&self, dst: &[u8; 16]) -> Option<&[[u8; 16]]> {
        if !self.dodag.is_root() {
            return None;
        }
        self.dao_manager.routing_table.lookup(dst)
    }

    /// Expire finite routes and look up a destination using monotonic time.
    pub fn lookup_route_at(&mut self, dst: &[u8; 16], now_ms: u64) -> Option<&[[u8; 16]]> {
        self.expire_routes_at(now_ms);
        self.lookup_route(dst)
    }

    /// Check trickle timer and return pending event.
    pub fn poll_trickle(&self) -> TrickleEvent {
        self.trickle.next_event()
    }

    /// Handle trickle transmit event. Returns true if DIO should be sent.
    pub fn trickle_transmit(&mut self) -> bool {
        self.trickle.fire_transmit()
    }

    /// Handle trickle expire event. Doubles interval.
    pub fn trickle_expire(&mut self, now_ms: u64, rand_offset: u32) {
        let now_ms = self.expire_routes_at(now_ms);
        self.trickle.expire(now_ms, rand_offset);
    }

    /// Reset trickle on inconsistency.
    pub fn trickle_reset(&mut self, now_ms: u64, rand_offset: u32) {
        let now_ms = self.expire_routes_at(now_ms);
        self.trickle.reset(now_ms, rand_offset);
    }

    /// Start trickle timer.
    pub fn trickle_start(&mut self, now_ms: u64, rand_offset: u32) {
        let now_ms = self.expire_routes_at(now_ms);
        self.trickle.start(now_ms, rand_offset);
    }

    /// Heard consistent DIO - increment counter.
    pub fn trickle_consistent(&mut self) {
        self.trickle.heard_consistent();
    }

    pub fn is_root(&self) -> bool {
        self.dodag.is_root()
    }

    pub fn is_joined(&self) -> bool {
        self.dodag.is_joined()
    }

    pub fn rank(&self) -> u16 {
        self.dodag.rank
    }

    pub fn preferred_parent(&self) -> Option<[u8; 16]> {
        self.dodag.preferred_parent
    }

    pub fn dodag(&self) -> &DodagState {
        &self.dodag
    }

    /// Read-only access to the synchronized neighbor table.
    pub fn neighbors(&self) -> &NeighborTable {
        &self.neighbors
    }

    /// Remove stale neighbors and their corresponding DODAG parent candidates.
    ///
    /// Uses `TrickleAwareNeighborLiveness` policy (see its docs for RFC 6206
    /// suppression-aware logic using `trickle.counter`).
    /// Times use the same monotonic `u64` millisecond timeline as DIO processing.
    pub fn prune_neighbors<P: TrickleSafeLivenessPolicy>(
        &mut self,
        now_ms: u64,
        max_age_ms: u64,
        policy: &P,
    ) -> bool {
        let now_ms = self.observe_now(now_ms);
        self.prune_neighbors_at(now_ms, max_age_ms, policy).1
    }

    pub fn maintain(&mut self, now_ms: u64, neighbor_timeout_ms: u64) -> RplMaintenanceOutcome {
        let now_ms = self.observe_now(now_ms);
        let routes_expired = self.dao_manager.expire_routes(now_ms / 1_000);
        let policy = TrickleAwareNeighborLiveness::default();
        let (neighbors_pruned, topology_changed) =
            self.prune_neighbors_at(now_ms, neighbor_timeout_ms, policy);
        RplMaintenanceOutcome {
            routes_expired,
            neighbors_pruned,
            topology_changed,
        }
    }

    fn prune_neighbors_at<P: TrickleSafeLivenessPolicy>(
        &mut self,
        now_ms: u64,
        max_age_ms: u64,
        policy: &P,
    ) -> (bool, bool) {
        let was_joined = self.dodag.is_joined();
        let old_parent = self.dodag.preferred_parent;
        let old_rank = self.dodag.rank;
        let heard_consistent = self.trickle.counter;
        let mut removed = [[0u8; 16]; MAX_NEIGHBORS];
        let mut removed_len = 0;
        self.neighbors
            .prune_with_removed(policy, now_ms, max_age_ms, heard_consistent, |addr| {
                removed[removed_len] = addr;
                removed_len += 1;
            }, policy);
        if removed_len != 0 {
            self.dodag.remove_parents(&removed[..removed_len]);
        }

        let inconsistent = old_rank != self.dodag.rank
            || was_joined != self.dodag.is_joined()
            || old_parent != self.dodag.preferred_parent;
        if inconsistent {
            self.trickle.reset(now_ms, 0);
        }
        (removed_len != 0, inconsistent)
    }

    pub fn dodag_id(&self) -> [u8; 16] {
        self.dodag_id
    }

    /// Set the active DODAG Configuration Lifetime Unit for DAO paths.
    #[must_use]
    pub fn set_dao_lifetime_unit(&mut self, lifetime_unit_seconds: u16) -> bool {
        if lifetime_unit_seconds == 0 {
            return false;
        }
        self.dodag_config.lifetime_unit = lifetime_unit_seconds;
        true
    }

    fn expire_routes_at(&mut self, now_ms: u64) -> u64 {
        let now_ms = self.observe_now(now_ms);
        self.dao_manager.expire_routes(now_ms / 1_000);
        now_ms
    }

    fn observe_now(&mut self, now_ms: u64) -> u64 {
        self.last_now_ms = self.last_now_ms.max(now_ms);
        self.last_now_ms
    }

    /// Set this node's geographic coordinates (from GPS or config).
    pub fn set_node_coords(&mut self, coords: GeoCoords) {
        self.node_coords = Some(coords);
    }

    /// Clear this node's coordinates (privacy mode or GPS unavailable).
    pub fn clear_node_coords(&mut self) {
        self.node_coords = None;
    }

    /// Update a neighbor's coordinates (from their announce app_data).
    pub fn update_neighbor_coords(&mut self, addr: &[u8; 16], coords: GeoCoords) {
        self.neighbors.set_coords(addr, coords);
    }

    /// GPSR greedy forwarding: find neighbor closest to destination (spec 9.7).
    ///
    /// Returns the address of the neighbor that makes the most progress toward
    /// the destination, or None if:
    /// - This node has no coordinates
    /// - No neighbors have coordinates
    /// - No neighbor is closer to the destination than this node (local minimum)
    /// - Destination coordinates are invalid (NaN, inf, out of range, null island)
    ///
    /// # Arguments
    /// * `dst_coords` - Geographic coordinates of the destination node
    ///
    /// # Returns
    /// Next-hop address if forwarding is possible, None otherwise
    pub fn gpsr_forward(&self, dst_coords: GeoCoords) -> Option<[u8; 16]> {
        // Validate destination coordinates
        if !is_valid_coords(dst_coords) {
            return None;
        }

        // Need our own coordinates to calculate progress
        let my_coords = self.node_coords?;
        if !is_valid_coords(my_coords) {
            return None;
        }

        let my_dist = haversine(my_coords, dst_coords);
        let mut best_neighbor: Option<[u8; 16]> = None;
        let mut best_dist = my_dist; // Must make progress

        for neighbor in self.neighbors.iter() {
            if let Some(n_coords) = neighbor.coords {
                // Skip neighbors with invalid coordinates
                if !is_valid_coords(n_coords) {
                    continue;
                }
                let d = haversine(n_coords, dst_coords);
                if d < best_dist {
                    best_dist = d;
                    best_neighbor = Some(neighbor.addr);
                }
            }
        }

        best_neighbor
    }
}

#[cfg(feature = "std")]
/// Haversine distance in meters between two (lat, lon) points.
#[cfg(feature = "std")]
fn haversine(c1: GeoCoords, c2: GeoCoords) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_000.0;

    let (lat1, lon1) = c1;
    let (lat2, lon2) = c2;

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();

    let a =
        (dlat / 2.0).sin().powi(2) + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
    // Clamp a to [0, 1] before sqrt to handle floating-point errors
    let c = 2.0 * libm::asin(libm::sqrt(a.min(1.0)));

    EARTH_RADIUS_M * c
}

#[cfg(feature = "std")]
/// Validate geographic coordinates.
/// Returns false for NaN, inf, out-of-range, or null island (0,0).
#[cfg(feature = "std")]
fn is_valid_coords(coords: GeoCoords) -> bool {
    let (lat, lon) = coords;

    // Check for NaN/inf
    if !lat.is_finite() || !lon.is_finite() {
        return false;
    }

    // Reject null island sentinel (almost always invalid GPS data)
    if lat == 0.0 && lon == 0.0 {
        return false;
    }

    // Check valid geographic ranges
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

#[cfg(feature = "std")]
use std::collections::VecDeque;

/// Default DTN buffer size: 64KB per spec 9.8
#[cfg(feature = "std")]
pub const DTN_BUFFER_MAX_BYTES: usize = 65536;

/// A message buffered for DTN store-and-forward (spec 9.8).
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct DtnMessage {
    /// Raw IPv6 packet data.
    pub packet: Vec<u8>,
    /// 8-byte IID of destination.
    pub destination_iid: [u8; 8],
    /// Unix timestamp when message expires.
    pub expiry_unix: u32,
    /// When message was buffered (monotonic ms for eviction ordering).
    pub buffered_at_ms: u32,
}

#[cfg(feature = "std")]
impl DtnMessage {
    /// Approximate size in bytes for buffer accounting.
    pub fn size(&self) -> usize {
        self.packet.len() + std::mem::size_of::<Self>()
    }
}

/// DTN store-and-forward buffer (spec 9.8).
///
/// Buffers messages for unreachable destinations until a path appears.
/// Uses oldest-first eviction when the buffer exceeds max_bytes.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct DtnBuffer {
    buffer: VecDeque<DtnMessage>,
    max_bytes: usize,
    current_bytes: usize,
}

#[cfg(feature = "std")]
impl DtnBuffer {
    /// Create a new DTN buffer with default capacity (64KB).
    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new(),
            max_bytes: DTN_BUFFER_MAX_BYTES,
            current_bytes: 0,
        }
    }

    /// Create a new DTN buffer with custom capacity.
    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            buffer: VecDeque::new(),
            max_bytes,
            current_bytes: 0,
        }
    }

    /// Buffer a message for DTN store-and-forward.
    ///
    /// Returns `true` if buffered, `false` if rejected (expired or oversized).
    pub fn buffer_message(
        &mut self,
        packet: Vec<u8>,
        destination_iid: [u8; 8],
        expiry_unix: u32,
        now_unix: u32,
        now_ms: u32,
    ) -> bool {
        // Reject already-expired messages
        if expiry_unix <= now_unix {
            return false;
        }

        let msg = DtnMessage {
            packet,
            destination_iid,
            expiry_unix,
            buffered_at_ms: now_ms,
        };

        // Reject messages that exceed the maximum buffer size
        let msg_size = msg.size();
        if msg_size > self.max_bytes {
            return false;
        }

        // Evict oldest messages until we have space
        self.evict_if_needed(msg_size);

        self.current_bytes += msg_size;
        self.buffer.push_back(msg);
        true
    }

    /// Get list of destination IIDs with buffered messages.
    pub fn get_pending_iids(&self) -> Vec<[u8; 8]> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for msg in &self.buffer {
            if seen.insert(msg.destination_iid) {
                result.push(msg.destination_iid);
            }
        }
        result
    }

    /// Retrieve and remove all messages for a destination IID.
    pub fn retrieve_for(&mut self, destination_iid: &[u8; 8]) -> Vec<DtnMessage> {
        let mut matching = Vec::new();
        let mut remaining = VecDeque::new();

        for msg in self.buffer.drain(..) {
            if msg.destination_iid == *destination_iid {
                self.current_bytes -= msg.size();
                matching.push(msg);
            } else {
                remaining.push_back(msg);
            }
        }
        self.buffer = remaining;
        matching
    }

    /// Remove expired messages from buffer. Returns count removed.
    pub fn expire_old(&mut self, now_unix: u32) -> usize {
        let mut expired = 0;
        let mut remaining = VecDeque::new();

        for msg in self.buffer.drain(..) {
            if msg.expiry_unix > now_unix {
                remaining.push_back(msg);
            } else {
                self.current_bytes -= msg.size();
                expired += 1;
            }
        }
        self.buffer = remaining;
        expired
    }

    /// Current buffer size in bytes.
    pub fn current_size(&self) -> usize {
        self.current_bytes
    }

    /// Number of messages in the buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Evict oldest messages to make room for new_msg_size bytes.
    fn evict_if_needed(&mut self, new_msg_size: usize) -> usize {
        let mut evicted = 0;
        while self.current_bytes + new_msg_size > self.max_bytes {
            if let Some(oldest) = self.buffer.pop_front() {
                self.current_bytes -= oldest.size();
                evicted += 1;
            } else {
                break;
            }
        }
        evicted
    }
}

#[cfg(feature = "std")]
impl Default for DtnBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use lichen_link::{identity::Identity, keys::Seed};
    use std::vec;

    fn link_local(iid: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0xfe;
        addr[1] = 0x80;
        addr[15] = iid;
        addr
    }

    fn ula(iid: u8) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0xfd;
        addr[15] = iid;
        addr
    }

    fn test_origin(seed: u8) -> [u8; 16] {
        let identity = Identity::from_seed(Seed::new([seed; 32]));
        let mut address = [0u8; 16];
        address[..2].copy_from_slice(&[0xfe, 0x80]);
        address[8..].copy_from_slice(&identity.iid);
        address
    }

    fn dio_bytes(dio: &Dio) -> [u8; Dio::BASE_LEN] {
        let mut bytes = [0u8; Dio::BASE_LEN];
        dio.write_to(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn neighbor_table_update_and_lookup() {
        let mut table = NeighborTable::new();
        let addr1 = link_local(1);
        let addr2 = link_local(2);

        table.update(&addr1, 1.0, -50, 1000);
        table.update(&addr2, 2.0, -70, 2000);

        assert_eq!(table.get_etx(&addr1), Some(1.0));
        assert_eq!(table.get_etx(&addr2), Some(2.0));
        assert_eq!(table.count(), 2);
    }

    #[test]
    fn neighbor_table_prune_stale() {
        let mut table = NeighborTable::new();
        let addr = link_local(1);
        table.update(&addr, 1.0, -50, 1000);

        table.prune(5000, 3000); // 4 seconds elapsed, 3 second max age
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn router_non_root_starts_unjoined() {
        let router = Router::new(link_local(1), link_local(0));
        assert!(!router.is_joined());
        assert!(!router.is_root());
        assert_eq!(router.rank(), u16::MAX);
    }

    #[test]
    fn router_root_starts_joined() {
        let router = Router::new_root(link_local(0));
        assert!(router.is_joined());
        assert!(router.is_root());
        assert_eq!(router.rank(), ROOT_RANK);
    }

    #[test]
    fn router_joins_on_dio() {
        let mut router = Router::new(link_local(2), link_local(0));
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: link_local(0),
        };
        let root_addr = link_local(0);
        let inconsistent = router.process_dio(&dio, &dio_bytes(&dio), root_addr, -40, 1000);
        assert!(inconsistent, "should detect inconsistency on join");
        assert!(router.is_joined());
        assert_eq!(router.preferred_parent(), Some(root_addr));
    }

    #[test]
    fn router_uses_measured_etx_for_parent_rank() {
        let dodag_id = link_local(0);
        let parent = link_local(1);
        let mut router = Router::new(link_local(2), dodag_id);
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };

        assert!(router.process_dio_with_etx(&dio, &dio_bytes(&dio), parent, 2.0, -40, 100,));
        assert_eq!(router.rank(), 768);
        assert_eq!(router.neighbors.get_etx(&parent), Some(2.0));

        let mut rejected = Router::new(link_local(3), dodag_id);
        assert!(!rejected.process_dio_with_etx(&dio, &dio_bytes(&dio), parent, f32::NAN, -40, 100,));
        assert_eq!(rejected.neighbors.count(), 0);
        assert!(!rejected.is_joined());

        assert!(!rejected.process_dio_with_etx(&dio, &dio_bytes(&dio), parent, 0.9, -40, 100,));
        assert_eq!(rejected.neighbors.count(), 0);

        assert!(!rejected.process_dio(&dio, &[], parent, -40, 100));
        let mut mismatched = dio.clone();
        mismatched.rank = 300;
        assert!(!rejected.process_dio(&dio, &dio_bytes(&mismatched), parent, -40, 100,));
        assert_eq!(rejected.neighbors.count(), 0);
    }

    #[test]
    fn foreign_dios_do_not_mutate_neighbors() {
        let dodag_id = link_local(0);
        let mut router = Router::new(link_local(2), dodag_id);
        let mut dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID.wrapping_add(1),
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };

        assert!(!router.process_dio(&dio, &dio_bytes(&dio), link_local(3), -40, 1000));
        assert_eq!(router.neighbors.count(), 0);

        dio.rpl_instance_id = RPL_INSTANCE_ID;
        dio.dodag_id = link_local(9);
        assert!(!router.process_dio(&dio, &dio_bytes(&dio), link_local(4), -40, 2000));
        assert_eq!(router.neighbors.count(), 0);
    }

    #[test]
    fn dodag_config_literal_roundtrips_through_router() {
        let dodag_id = link_local(1);
        let sender = link_local(2);
        let bytes = [
            RPL_INSTANCE_ID,
            0,
            1,
            0,
            0x88,
            0,
            0,
            0,
            0xfe,
            0x80,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
            4,
            14,
            0,
            8,
            3,
            10,
            4,
            0,
            0,
            128,
            0,
            1,
            0,
            255,
            0,
            30,
        ];
        let dio = Dio::from_bytes(&bytes).unwrap();
        let mut router = Router::new(sender, dodag_id);

        assert!(router.process_dio(&dio, &bytes, dodag_id, -40, 1000));
        assert_eq!(router.dodag.min_hop_rank_increase, 128);
        assert_eq!(router.dodag.max_rank_increase, 1024);
        assert_eq!(router.dodag_config.lifetime_unit, 30);

        let mut encoded = [0u8; 40];
        assert_eq!(router.build_dio(&mut encoded), encoded.len());
        assert_eq!(&encoded[Dio::BASE_LEN..], &bytes[Dio::BASE_LEN..]);
        assert_eq!(router.build_dio(&mut [0u8; 39]), 0);
    }

    #[test]
    fn malformed_dodag_config_does_not_mutate_router() {
        let dodag_id = link_local(1);
        let sender = link_local(2);
        let mut router = Router::new(link_local(3), dodag_id);
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        let mut bytes = [0u8; 40];
        dio.write_to(&mut bytes).unwrap();
        DodagConfig::default()
            .write_to(&mut bytes[Dio::BASE_LEN..])
            .unwrap();

        for offset in [32, 38] {
            let mut malformed = bytes;
            malformed[offset] = 0;
            malformed[offset + 1] = 0;
            assert!(!router.process_dio(&dio, &malformed, sender, -40, 1000));
            assert_eq!(router.neighbors.count(), 0);
            assert!(!router.is_joined());
            assert_eq!(router.rank(), u16::MAX);
            assert_eq!(router.preferred_parent(), None);
            assert_eq!(router.dodag.min_hop_rank_increase, 256);
            assert_eq!(router.dodag_config, DodagConfig::default());
        }

        assert!(!router.process_dio(&dio, &bytes[..39], sender, -40, 1000));
        assert_eq!(router.neighbors.count(), 0);
        assert!(!router.is_joined());
        assert_eq!(router.dodag_config, DodagConfig::default());

        let mut overlong = bytes.to_vec();
        overlong[Dio::BASE_LEN + 1] = (DODAG_CONFIG_DATA_LEN + 1) as u8;
        overlong.push(0);
        assert!(!router.process_dio(&dio, &overlong, sender, -40, 1000));
        assert_eq!(router.neighbors.count(), 0);
        assert_eq!(router.dodag_config, DodagConfig::default());

        let invalid_rank = DodagConfig {
            min_hop_rank_increase: 32_768,
            ..DodagConfig::default()
        };
        let invalid_rank = dio_with_config(&dio, &invalid_rank);
        assert!(!router.process_dio(&dio, &invalid_rank, sender, -40, 1000));
        assert_eq!(router.neighbors.count(), 0);
        assert_eq!(router.dodag_config, DodagConfig::default());

        assert!(router.process_dio(&dio, &bytes, sender, -40, 50));
        assert_eq!(router.neighbors.iter().next().unwrap().last_seen_ms, 1_000);
    }

    fn dio_with_config(dio: &Dio, config: &DodagConfig) -> Vec<u8> {
        let mut bytes = vec![0u8; Dio::BASE_LEN + 16];
        dio.write_to(&mut bytes).unwrap();
        config.write_to(&mut bytes[Dio::BASE_LEN..]).unwrap();
        bytes
    }

    #[test]
    fn stale_dio_config_does_not_mutate_router() {
        let dodag_id = link_local(1);
        let mut router = Router::new(link_local(3), dodag_id);
        let mut dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 1,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        assert!(router.process_dio(&dio, &dio_bytes(&dio), link_local(2), -40, 1000));
        let original_config = router.dodag_config.clone();
        let original_parent = router.preferred_parent();
        let original_timer = (
            router.trickle.imin,
            router.trickle.max_interval,
            router.trickle.k,
            router.trickle.interval_start,
        );

        dio.version = 0;
        let mut stale_config = original_config.clone();
        stale_config.min_hop_rank_increase = 128;
        let bytes = dio_with_config(&dio, &stale_config);
        assert!(!router.process_dio(&dio, &bytes, link_local(4), -30, 2000));
        assert_eq!(router.dodag_config, original_config);
        assert_eq!(router.preferred_parent(), original_parent);
        assert_eq!(router.neighbors.count(), 1);
        assert_eq!(
            (
                router.trickle.imin,
                router.trickle.max_interval,
                router.trickle.k,
                router.trickle.interval_start,
            ),
            original_timer
        );
    }

    #[test]
    fn poisoned_parent_is_removed_and_resets_trickle() {
        let dodag_id = link_local(1);
        let parent = link_local(2);
        let mut router = Router::new(link_local(3), dodag_id);
        let mut dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        assert!(router.process_dio(&dio, &dio_bytes(&dio), parent, -40, 1_000));
        assert!(router.trickle_transmit());
        router.trickle_expire(1_008, 0);
        assert_eq!(router.trickle.interval, 16);

        dio.rank = u16::MAX;
        let ignored_config = DodagConfig {
            min_hop_rank_increase: 128,
            ..DodagConfig::default()
        };
        let bytes = dio_with_config(&dio, &ignored_config);
        assert!(router.process_dio(&dio, &bytes, parent, -40, 2_000));
        assert!(!router.is_joined());
        assert_eq!(router.preferred_parent(), None);
        assert_eq!(router.dodag_config, DodagConfig::default());
        assert_eq!(router.trickle.interval, router.trickle.imin);
        assert_eq!(router.trickle.interval_start, 2_000);
    }

    #[test]
    fn malformed_poison_does_not_remove_parent() {
        let dodag_id = link_local(1);
        let parent = link_local(2);
        let mut router = Router::new(link_local(3), dodag_id);
        let mut dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        router.process_dio(&dio, &dio_bytes(&dio), parent, -40, 0);

        dio.rank = u16::MAX;
        let mut malformed = dio_bytes(&dio).to_vec();
        malformed.extend_from_slice(&[OPT_DODAG_CONFIG, 14, 0]);
        assert!(!router.process_dio(&dio, &malformed, parent, -20, 1_000));
        assert_eq!(router.preferred_parent(), Some(parent));
        assert_eq!(router.dodag.parent_count(), 1);
        let neighbor = router
            .neighbors
            .iter()
            .find(|neighbor| neighbor.addr == parent)
            .unwrap();
        assert_eq!(neighbor.last_seen_ms, 0);
        assert_eq!(neighbor.rssi, -40);
    }

    #[test]
    fn newer_version_can_adopt_a_higher_rank_and_resets_trickle() {
        const WRAP: u64 = 0x1_0000_0000;
        let dodag_id = link_local(1);
        let parent = link_local(2);
        let mut router = Router::new(link_local(3), dodag_id);
        let mut dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        assert!(router.process_dio(&dio, &dio_bytes(&dio), parent, -40, WRAP + 100));
        assert!(router.trickle_transmit());
        router.trickle_expire(WRAP + 108, 0);
        assert_eq!(router.trickle.interval, 16);

        dio.version = 1;
        dio.rank = 1_400;
        assert!(router.process_dio(&dio, &dio_bytes(&dio), parent, -40, 50));
        assert_eq!(router.dodag.version, 1);
        assert_eq!(router.preferred_parent(), Some(parent));
        assert_eq!(router.rank(), 1_656);
        assert_eq!(router.trickle.interval, router.trickle.imin);
        assert_eq!(router.trickle.interval_start, WRAP + 108);
    }

    #[test]
    fn router_accepts_version_wrap_from_127_to_zero() {
        let dodag_id = link_local(1);
        let parent = link_local(2);
        let mut router = Router::new(link_local(3), dodag_id);
        router.dodag = DodagState::new(RPL_INSTANCE_ID, dodag_id, 127);
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };

        assert!(router.process_dio(&dio, &dio_bytes(&dio), parent, -40, 100));
        assert_eq!(router.dodag.version, 0);
        assert_eq!(router.preferred_parent(), Some(parent));
    }

    #[test]
    fn rejected_newer_version_does_not_commit_config_or_neighbor_refresh() {
        let dodag_id = link_local(1);
        let parent = link_local(2);
        let mut router = Router::new(link_local(3), dodag_id);
        let mut dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        router.process_dio(&dio, &dio_bytes(&dio), parent, -40, 10);
        let original_config = router.dodag_config.clone();

        dio.version = 1;
        dio.rank = 64;
        let mut proposed = original_config.clone();
        proposed.min_hop_rank_increase = 128;
        let bytes = dio_with_config(&dio, &proposed);
        assert!(!router.process_dio(&dio, &bytes, parent, -20, 1_000));

        assert_eq!(router.dodag.version, 0);
        assert_eq!(router.dodag_config, original_config);
        assert_eq!(router.preferred_parent(), Some(parent));
        let neighbor = router
            .neighbors
            .iter()
            .find(|neighbor| neighbor.addr == parent)
            .unwrap();
        assert_eq!(neighbor.last_seen_ms, 10);
        assert_eq!(neighbor.rssi, -40);
    }

    #[test]
    fn finite_inadmissible_update_removes_existing_parent() {
        let dodag_id = link_local(1);
        let parent = link_local(2);
        let mut router = Router::new(link_local(3), dodag_id);
        let mut dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        router.process_dio(&dio, &dio_bytes(&dio), parent, -40, 0);

        dio.rank = u16::MAX - 1;
        assert!(router.process_dio(&dio, &dio_bytes(&dio), parent, -40, 1_000));
        assert!(!router.is_joined());
        assert_eq!(router.preferred_parent(), None);
        assert_eq!(router.dodag.parent_count(), 0);
        assert_eq!(router.neighbors.get_etx(&parent), Some(1.0));
    }

    #[test]
    fn accepted_config_applies_and_resets_trickle() {
        let dodag_id = link_local(1);
        let parent = link_local(2);
        let mut router = Router::new(link_local(3), dodag_id);
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        let mut config = DodagConfig {
            dio_int_min: 5,
            dio_int_doublings: 4,
            dio_redundancy_const: 7,
            ..DodagConfig::default()
        };
        let bytes = dio_with_config(&dio, &config);

        assert!(router.process_dio(&dio, &bytes, parent, -40, 1_000));
        assert_eq!(router.trickle.imin, 32);
        assert_eq!(router.trickle.max_interval, 512);
        assert_eq!(router.trickle.k, 7);
        assert_eq!(router.trickle.interval_start, 1_000);

        config.dio_int_min = 31;
        config.dio_int_doublings = 1;
        let invalid = dio_with_config(&dio, &config);
        assert!(!router.process_dio(&dio, &invalid, parent, -40, 2_000));
        assert_eq!(router.trickle.imin, 32);
        assert_eq!(router.trickle.interval_start, 1_000);
    }

    #[test]
    fn root_advertises_its_actual_trickle_config() {
        let root = Router::new_root(link_local(1));
        let mut bytes = [0u8; Dio::BASE_LEN + 16];
        assert_eq!(root.build_dio(&mut bytes), bytes.len());
        let advertised = DodagConfig::from_bytes(&bytes[Dio::BASE_LEN + 2..]).unwrap();

        assert_eq!(root.trickle.imin, 1 << advertised.dio_int_min);
        assert_eq!(
            root.trickle.max_interval,
            root.trickle.imin << advertised.dio_int_doublings
        );
        assert_eq!(root.trickle.k, u32::from(advertised.dio_redundancy_const));
    }

    #[test]
    fn configured_root_advertises_its_rank_and_lifetime() {
        let config = DodagConfig {
            min_hop_rank_increase: 128,
            max_rank_increase: 1_024,
            lifetime_unit: 30,
            ..DodagConfig::default()
        };
        let root = Router::new_root_with_config(link_local(1), config.clone()).unwrap();

        assert_eq!(root.rank(), 128);
        let mut bytes = [0u8; Dio::BASE_LEN + 16];
        assert_eq!(root.build_dio(&mut bytes), bytes.len());
        let dio = Dio::from_bytes(&bytes).unwrap();
        let advertised = DodagConfig::from_bytes(&bytes[Dio::BASE_LEN + 2..]).unwrap();
        assert_eq!(dio.rank, 128);
        assert_eq!(advertised, config);

        for invalid in [32_768, u16::MAX] {
            let config = DodagConfig {
                min_hop_rank_increase: invalid,
                ..DodagConfig::default()
            };
            assert!(Router::new_root_with_config(link_local(1), config).is_none());
        }
    }

    #[test]
    fn root_ignores_neighbor_dodag_config() {
        let root_addr = link_local(1);
        let mut root = Router::new_root(root_addr);
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 1,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: root_addr,
        };
        let config = DodagConfig {
            min_hop_rank_increase: 128,
            ..DodagConfig::default()
        };
        let bytes = dio_with_config(&dio, &config);

        assert!(!root.process_dio(&dio, &bytes, link_local(2), -40, 1000));
        assert_eq!(root.rank(), ROOT_RANK);
        assert_eq!(root.dodag_config, DodagConfig::default());
        assert_eq!(root.neighbors.count(), 0);
    }

    #[test]
    fn unsupported_mop_and_ocp_are_rejected_without_mutation() {
        let dodag_id = link_local(1);
        let mut router = Router::new(link_local(3), dodag_id);
        let mut dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: 2,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        assert!(!router.process_dio(&dio, &dio_bytes(&dio), link_local(2), -40, 1000));

        dio.mode_of_operation = NON_STORING_MOP;
        let config = DodagConfig {
            ocp: 0,
            ..DodagConfig::default()
        };
        let bytes = dio_with_config(&dio, &config);
        assert!(!router.process_dio(&dio, &bytes, link_local(2), -40, 1000));
        assert!(!router.is_joined());
        assert_eq!(router.dodag_config, DodagConfig::default());
        assert_eq!(router.neighbors.count(), 0);
    }

    #[test]
    fn spoofed_dao_target_is_rejected_before_replay_state_changes() {
        let root_addr = link_local(1);
        let target = test_origin(2);
        let mut sender = DaoManager::new(target, RPL_INSTANCE_ID, root_addr);
        let dao = sender.build_dao(root_addr);
        let mut root = Router::new_root(root_addr);

        assert!(!root.process_dao_at_ms(&dao, target, link_local(3), 0));
        assert!(root.lookup_route(&target).is_none());
        assert!(root.process_dao_at_ms(&dao, target, target, 0));
        assert_eq!(root.lookup_route(&target), Some([target].as_slice()));
    }

    #[test]
    fn aggregated_dao_uses_parent_for_packet_source_group() {
        let root_addr = ula(1);
        let first_target = ula(2);
        let packet_source = ula(3);
        let source_parent = ula(2);
        let mut first = DaoManager::new(first_target, RPL_INSTANCE_ID, root_addr);
        let mut second = DaoManager::new(packet_source, RPL_INSTANCE_ID, root_addr);
        let mut dao = first.build_dao(root_addr);
        let second_dao = second.build_dao(source_parent);
        let parsed = Dao::from_bytes(&second_dao).unwrap();
        dao.extend_from_slice(parsed.options_tail(&second_dao));

        assert_eq!(
            dao_parents_for_source(&dao, &packet_source),
            Some(vec![source_parent])
        );
    }

    #[test]
    fn dao_helper_returns_every_parent_for_source_group() {
        let root_addr = ula(1);
        let packet_source = ula(2);
        let alternate_parent = ula(3);
        let mut sender = DaoManager::new(packet_source, RPL_INSTANCE_ID, root_addr);
        let mut dao = sender.build_dao(root_addr);
        let transit = TransitInfo {
            path_control: 1,
            path_sequence: 241,
            path_lifetime: 255,
            parent_address: alternate_parent,
        };
        let mut option = [0u8; 22];
        let option_len = transit.write_to(&mut option).unwrap();
        dao.extend_from_slice(&option[..option_len]);

        assert_eq!(
            dao_parents_for_source(&dao, &packet_source),
            Some(vec![root_addr, alternate_parent])
        );
    }

    #[test]
    fn processing_dao_expires_routes_with_active_lifetime_unit() {
        let root_addr = link_local(1);
        let first_target = test_origin(2);
        let second_target = test_origin(3);
        let mut first = DaoManager::new(first_target, RPL_INSTANCE_ID, root_addr);
        let mut second = DaoManager::new(second_target, RPL_INSTANCE_ID, root_addr);
        let first_dao = first.build_dao_with_lifetime(root_addr, 1);
        let second_dao = second.build_dao(root_addr);
        let mut root = Router::new_root(root_addr);
        assert!(root.set_dao_lifetime_unit(10));

        assert!(root.process_dao_at_ms(&first_dao, first_target, first_target, 100_000));
        assert!(root.lookup_route(&first_target).is_some());
        assert!(root.process_dao_at_ms(&second_dao, second_target, second_target, 110_000));
        assert!(root.lookup_route(&first_target).is_none());
        assert!(root.lookup_route(&second_target).is_some());
    }

    #[test]
    fn exact_dao_at_expiry_reports_accepted_update() {
        let root_addr = link_local(1);
        let target = test_origin(2);
        let mut sender = DaoManager::new(target, RPL_INSTANCE_ID, root_addr);
        let dao = sender.build_dao_with_lifetime(root_addr, 1);
        let exact = sender.build_dao_copy_with_lifetime(root_addr, 1).unwrap();
        let mut root = Router::new_root(root_addr);
        assert!(root.set_dao_lifetime_unit(1));

        assert!(root.process_dao_at_ms(&dao, target, target, 1_000));
        assert!(!root.process_dao_at_ms(&exact, target, link_local(3), 2_000));
        assert!(root.lookup_route(&target).is_some());
        assert!(root.process_dao_at_ms(&exact, target, target, 2_000));
        assert!(root.lookup_route(&target).is_none());
    }

    #[test]
    fn finite_route_expires_during_idle_lookup_and_timer() {
        let root_addr = link_local(1);
        let target = test_origin(2);
        let mut sender = DaoManager::new(target, RPL_INSTANCE_ID, root_addr);
        let dao = sender.build_dao_with_lifetime(root_addr, 1);
        let mut root = Router::new_root(root_addr);
        assert!(root.set_dao_lifetime_unit(1));

        assert!(root.process_dao_at_ms(&dao, target, target, 1_000));
        assert!(root.lookup_route_at(&target, 1_999).is_some());
        root.trickle_start(2_000, 0);
        assert!(root.lookup_route(&target).is_none());
    }

    #[test]
    fn maintenance_expires_idle_route_at_boundary_without_changing_trickle() {
        let root_addr = link_local(1);
        let target = test_origin(2);
        let mut sender = DaoManager::new(target, RPL_INSTANCE_ID, root_addr);
        let dao = sender.build_dao_with_lifetime(root_addr, 1);
        let mut root = Router::new_root(root_addr);
        assert!(root.set_dao_lifetime_unit(1));
        assert!(root.process_dao_at_ms(&dao, target, target, 1_000));
        root.trickle_start(1_000, 0);
        let trickle = root.poll_trickle();

        assert_eq!(
            root.maintain(1_999, 10_000, &()),
            RplMaintenanceOutcome::default()
        );
        assert!(root.lookup_route(&target).is_some());
        assert_eq!(root.poll_trickle(), trickle);

        assert_eq!(
            root.maintain(2_000, 10_000, &()),
            RplMaintenanceOutcome {
                routes_expired: true,
                neighbors_pruned: false,
                topology_changed: false,
            }
        );
        assert!(root.lookup_route(&target).is_none());
        assert_eq!(root.poll_trickle(), trickle);
    }

    #[test]
    fn dao_clock_expires_across_u32_boundary() {
        const WRAP: u64 = 0x1_0000_0000;
        let root_addr = link_local(1);
        let target = test_origin(2);
        let mut sender = DaoManager::new(target, RPL_INSTANCE_ID, root_addr);
        let dao = sender.build_dao_with_lifetime(root_addr, 1);
        let mut root = Router::new_root(root_addr);
        assert!(root.set_dao_lifetime_unit(1));

        assert!(root.process_dao_at_ms(&dao, target, target, WRAP - 296));
        assert!(root.lookup_route_at(&target, WRAP + 703).is_some());
        assert!(root.lookup_route_at(&target, WRAP + 704).is_none());
    }

    #[test]
    fn dao_clock_expires_after_half_range_gap() {
        const HALF: u64 = 0x8000_0000;
        let root_addr = link_local(1);
        let target = test_origin(2);
        let mut sender = DaoManager::new(target, RPL_INSTANCE_ID, root_addr);
        let dao = sender.build_dao_with_lifetime(root_addr, 1);
        let mut root = Router::new_root(root_addr);
        assert!(root.set_dao_lifetime_unit(1));

        let start = 1_000u64;
        assert!(root.process_dao_at_ms(&dao, target, target, start));
        assert!(root.lookup_route_at(&target, start + HALF).is_none());
    }

    #[test]
    fn dao_is_rejected_when_no_future_deadline_is_representable() {
        let root_addr = link_local(1);
        let target = test_origin(2);
        let infinite_target = test_origin(3);
        let mut sender = DaoManager::new(target, RPL_INSTANCE_ID, root_addr);
        let mut infinite = DaoManager::new(infinite_target, RPL_INSTANCE_ID, root_addr);
        let dao = sender.build_dao_with_lifetime(root_addr, 1);
        let mut root = Router::new_root(root_addr);

        assert!(!root.process_dao_at_ms(&dao, target, target, u64::MAX - 1_000));
        assert!(root.lookup_route(&target).is_none());
        assert!(root.process_dao_at_ms(
            &infinite.build_dao(root_addr),
            infinite_target,
            infinite_target,
            u64::MAX,
        ));
        assert!(root.lookup_route(&infinite_target).is_some());
        assert!(root.process_dao_at_ms(
            &infinite.build_dao_with_lifetime(root_addr, 0),
            infinite_target,
            infinite_target,
            u64::MAX,
        ));
        assert!(root.lookup_route(&infinite_target).is_none());
    }

    #[test]
    fn dao_uses_active_default_lifetime_and_zero_unit_is_rejected() {
        let dodag_id = link_local(1);
        let parent = link_local(2);
        let mut router = Router::new(link_local(3), dodag_id);
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };
        let config = DodagConfig {
            def_lifetime: 9,
            ..DodagConfig::default()
        };
        let bytes = dio_with_config(&dio, &config);
        assert!(router.process_dio(&dio, &bytes, parent, -40, 0));

        let dao = router.build_dao();
        let parsed = Dao::from_bytes(&dao).unwrap();
        let lifetime = OptionIter::new(parsed.options_tail(&dao))
            .filter_map(Result::ok)
            .find(|option| option.opt_type == OPT_TRANSIT_INFO)
            .map(|option| TransitInfo::from_bytes(option.data).unwrap().path_lifetime);
        assert_eq!(lifetime, Some(9));

        assert!(!router.set_dao_lifetime_unit(0));
        assert_eq!(router.dodag_config.lifetime_unit, config.lifetime_unit);
    }

    #[test]
    fn neighbor_table_eviction_distinguishes_complete_wraps() {
        const WRAP: u64 = 0x1_0000_0000;
        let mut table = NeighborTable::new();

        table.update(&link_local(0), 1.0, -50, 100);
        for i in 1..MAX_NEIGHBORS {
            let addr = link_local(i as u8);
            table.update(&addr, 1.0, -50, WRAP + 90 + i as u64);
        }
        assert_eq!(table.count(), MAX_NEIGHBORS);

        let new_addr = link_local(0xFF);
        let evicted_slot = table.update(&new_addr, 1.0, -50, WRAP + 200);

        assert_eq!(evicted_slot, 0);
        assert_eq!(table.get_etx(&new_addr), Some(1.0));
        assert_eq!(table.get_etx(&link_local(0)), None);
    }

    #[test]
    fn neighbor_pruning_handles_half_range_and_complete_wrap() {
        const HALF: u64 = 0x8000_0000;
        const WRAP: u64 = 0x1_0000_0000;
        let mut table = NeighborTable::new();

        table.update(&link_local(1), 1.0, -50, 0);
        table.prune(HALF, HALF);
        assert_eq!(table.count(), 1);
        table.prune(HALF + 1, HALF);
        assert_eq!(table.count(), 0);

        table.update(&link_local(2), 1.0, -50, 100);
        table.prune(WRAP + 100, 1);
        assert_eq!(table.count(), 0);

        table.update(&link_local(3), 1.0, -50, WRAP + 200);
        table.update(&link_local(3), 1.0, -40, 50);
        assert_eq!(table.iter().next().unwrap().last_seen_ms, WRAP + 200);
        table.prune(WRAP + 201, 0);
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn router_neighbor_eviction_removes_dodag_parent() {
        let dodag_id = link_local(0);
        let mut router = Router::new(link_local(200), dodag_id);
        let dio = |rank| Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };

        let parent = link_local(1);
        let message = dio(ROOT_RANK);
        assert!(router.process_dio(&message, &dio_bytes(&message), parent, -40, 0));

        let fallback = link_local(2);
        let message = dio(300);
        router.process_dio(&message, &dio_bytes(&message), fallback, -40, 100);

        for iid in 3..=MAX_NEIGHBORS as u8 {
            let message = dio(400);
            router.process_dio(&message, &dio_bytes(&message), link_local(iid), -40, 990);
        }

        assert_eq!(router.neighbors.count(), MAX_NEIGHBORS);
        assert_eq!(router.dodag.parent_count(), MAX_NEIGHBORS);
        assert_eq!(router.preferred_parent(), Some(parent));

        let replacement = link_local(17);
        let message = dio(400);
        router.process_dio(&message, &dio_bytes(&message), replacement, -40, 1_000);

        assert_eq!(router.neighbors.get_etx(&parent), Some(1.0));
        assert_eq!(router.neighbors.get_etx(&fallback), None);
        assert_eq!(router.neighbors.count(), MAX_NEIGHBORS);
        assert_eq!(router.dodag.parent_count(), MAX_NEIGHBORS);
        assert_eq!(router.preferred_parent(), Some(parent));
        assert_eq!(router.rank(), 512);
        assert!(router.is_joined());

        let poison = dio(u16::MAX);
        router.process_dio(&poison, &dio_bytes(&poison), replacement, -40, 1_001);
        assert_eq!(router.dodag.parent_count(), MAX_NEIGHBORS - 1);
    }

    #[test]
    fn unknown_poison_does_not_evict_a_parent() {
        let dodag_id = link_local(0);
        let mut router = Router::new(link_local(200), dodag_id);
        let dio = |rank| Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };

        for iid in 1..=MAX_NEIGHBORS as u8 {
            let message = dio(ROOT_RANK + u16::from(iid));
            router.process_dio(
                &message,
                &dio_bytes(&message),
                link_local(iid),
                -40,
                u64::from(iid),
            );
        }
        let old_parent = router.preferred_parent();

        let poison = dio(u16::MAX);
        assert!(!router.process_dio(&poison, &dio_bytes(&poison), link_local(17), -40, 1_000,));
        assert_eq!(router.neighbors.count(), MAX_NEIGHBORS);
        assert_eq!(router.dodag.parent_count(), MAX_NEIGHBORS);
        assert_eq!(router.preferred_parent(), old_parent);
    }

    #[test]
    fn inadmissible_rank_config_does_not_mutate_router() {
        let dodag_id = link_local(0);
        let mut router = Router::new(link_local(200), dodag_id);
        let dio = |rank| Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };

        let parent = link_local(1);
        let message = dio(ROOT_RANK);
        router.process_dio(&message, &dio_bytes(&message), parent, -40, 0);
        let original_config = router.dodag_config.clone();

        let sender = link_local(2);
        let message = dio(300);
        let mut restrictive = original_config.clone();
        restrictive.max_rank_increase = 1;
        let bytes = dio_with_config(&message, &restrictive);
        assert!(!router.process_dio(&message, &bytes, sender, -40, 1_000));

        assert_eq!(router.dodag_config, original_config);
        assert_eq!(router.neighbors.get_etx(&sender), None);
        assert_eq!(router.neighbors.count(), 1);
        assert_eq!(router.dodag.parent_count(), 1);
        assert_eq!(router.preferred_parent(), Some(parent));
        assert_eq!(router.rank(), 512);
    }

    #[test]
    fn pruning_neighbors_removes_dodag_parents() {
        const WRAP: u64 = 0x1_0000_0000;
        let dodag_id = link_local(0);
        let mut router = Router::new(link_local(200), dodag_id);
        let dio = |rank| Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id,
        };

        let stale_parent = link_local(1);
        let message = dio(ROOT_RANK);
        router.process_dio(&message, &dio_bytes(&message), stale_parent, -40, 100);
        let fallback = link_local(2);
        let message = dio(300);
        router.process_dio(&message, &dio_bytes(&message), fallback, -40, WRAP + 90);
        assert!(router.trickle_transmit());
        router.trickle_expire(WRAP + 100, 0);

        assert!(router.prune_neighbors(50, 5, &()));
        assert_eq!(router.neighbors.get_etx(&stale_parent), None);
        assert_eq!(router.neighbors.count(), 0);
        assert_eq!(router.dodag.parent_count(), 0);
        assert_eq!(router.preferred_parent(), None);
        assert_eq!(router.rank(), u16::MAX);
        assert_eq!(router.trickle.interval_start, WRAP + 100);
    }

    #[test]
    fn maintenance_clamps_backward_clock_and_prunes_only_after_timeout() {
        let mut router = Router::new(link_local(2), link_local(1));
        let neighbor = link_local(3);
        router.maintain(5_000, 10_000, &());
        router.neighbors.update(&neighbor, 1.0, -40, 5_000);

        assert!(!router.maintain(4_000, 0, &()).neighbors_pruned);
        assert_eq!(router.neighbors.count(), 1);
        assert!(!router.maintain(15_000, 10_000, &()).neighbors_pruned);
        assert_eq!(router.neighbors.count(), 1);
        assert!(router.maintain(15_001, 10_000, &()).neighbors_pruned);
        assert_eq!(router.neighbors.count(), 0);
    }

    // --- DTN Buffer Tests ---

    fn make_iid(v: u8) -> [u8; 8] {
        [0, 0, 0, 0, 0, 0, 0, v]
    }

    #[test]
    fn dtn_buffer_message_and_retrieve() {
        let mut buf = DtnBuffer::new();
        let iid = make_iid(1);
        let packet = vec![0u8; 100];

        // Buffer a message
        let buffered = buf.buffer_message(packet.clone(), iid, 1000, 500, 100);
        assert!(buffered);
        assert_eq!(buf.len(), 1);

        // Retrieve it
        let retrieved = buf.retrieve_for(&iid);
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].packet, packet);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn dtn_buffer_rejects_expired() {
        let mut buf = DtnBuffer::new();
        let iid = make_iid(1);
        let packet = vec![0u8; 100];

        // Try to buffer an expired message (expiry <= now)
        let buffered = buf.buffer_message(packet, iid, 500, 600, 100);
        assert!(!buffered);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn dtn_buffer_rejects_oversized() {
        let mut buf = DtnBuffer::with_max_bytes(1000);
        let iid = make_iid(1);
        let packet = vec![0u8; 2000]; // Larger than buffer

        let buffered = buf.buffer_message(packet, iid, 1000, 500, 100);
        assert!(!buffered);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn dtn_buffer_expire_old() {
        let mut buf = DtnBuffer::new();
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);

        // Buffer two messages with different expiry times
        buf.buffer_message(vec![0u8; 100], iid1, 500, 100, 10);
        buf.buffer_message(vec![0u8; 100], iid2, 1000, 100, 20);
        assert_eq!(buf.len(), 2);

        // Expire at time 600 - first message should be removed
        let expired = buf.expire_old(600);
        assert_eq!(expired, 1);
        assert_eq!(buf.len(), 1);

        // The remaining message should be for iid2
        let pending = buf.get_pending_iids();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], iid2);
    }

    #[test]
    fn dtn_buffer_eviction_on_full() {
        let mut buf = DtnBuffer::with_max_bytes(350);
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);
        let iid3 = make_iid(3);

        buf.buffer_message(vec![0u8; 100], iid1, 1000, 100, 10);
        buf.buffer_message(vec![0u8; 100], iid2, 1000, 100, 20);
        assert_eq!(buf.len(), 2);

        buf.buffer_message(vec![0u8; 100], iid3, 1000, 100, 30);
        assert_eq!(buf.len(), 2);

        let pending = buf.get_pending_iids();
        assert!(!pending.contains(&iid1));
        assert!(pending.contains(&iid2));
        assert!(pending.contains(&iid3));
    }

    #[test]
    fn dtn_buffer_get_pending_iids_deduplicates() {
        let mut buf = DtnBuffer::new();
        let iid = make_iid(1);

        // Buffer multiple messages for the same destination
        buf.buffer_message(vec![0u8; 100], iid, 1000, 100, 10);
        buf.buffer_message(vec![0u8; 100], iid, 1000, 100, 20);
        buf.buffer_message(vec![0u8; 100], iid, 1000, 100, 30);
        assert_eq!(buf.len(), 3);

        // get_pending_iids should return only one IID
        let pending = buf.get_pending_iids();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], iid);
    }

    #[test]
    fn dtn_buffer_retrieve_removes_all_for_iid() {
        let mut buf = DtnBuffer::new();
        let iid1 = make_iid(1);
        let iid2 = make_iid(2);

        // Buffer multiple messages for different destinations
        buf.buffer_message(vec![0u8; 100], iid1, 1000, 100, 10);
        buf.buffer_message(vec![0u8; 100], iid1, 1000, 100, 20);
        buf.buffer_message(vec![0u8; 100], iid2, 1000, 100, 30);
        assert_eq!(buf.len(), 3);

        // Retrieve all for iid1
        let retrieved = buf.retrieve_for(&iid1);
        assert_eq!(retrieved.len(), 2);
        assert_eq!(buf.len(), 1);

        // Only iid2 should remain
        let pending = buf.get_pending_iids();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], iid2);
    }

    // --- GPSR Tests (spec 9.7) ---

    #[test]
    fn neighbor_coords_update_and_lookup() {
        let mut table = NeighborTable::new();
        let addr = link_local(1);

        // Insert neighbor without coords
        table.update(&addr, 1.0, -50, 1000);
        assert_eq!(table.get_coords(&addr), None);

        // Update with coords
        let coords = (47.6062, -122.3321);
        table.set_coords(&addr, coords);
        assert_eq!(table.get_coords(&addr), Some(coords));
    }

    #[test]
    fn neighbor_update_with_coords() {
        let mut table = NeighborTable::new();
        let addr = link_local(1);
        let coords = (45.5152, -122.6784);

        table.update_with_coords(&addr, 1.0, -50, 1000, Some(coords));
        assert_eq!(table.get_coords(&addr), Some(coords));
    }

    #[test]
    fn gpsr_forward_selects_closest_neighbor() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0)); // Avoid null island

        // Add two neighbors with coords
        let neighbor_a = link_local(0xa);
        let neighbor_b = link_local(0xb);
        router
            .neighbors
            .update_with_coords(&neighbor_a, 1.0, -50, 1000, Some((1.0, 1.0)));
        router
            .neighbors
            .update_with_coords(&neighbor_b, 1.0, -50, 1000, Some((0.5, 1.0)));

        // Destination is 2 degrees north - neighbor_a (1.0) is closer than neighbor_b (0.5)
        let dst_coords = (2.0, 1.0);
        let next_hop = router.gpsr_forward(dst_coords);

        assert_eq!(next_hop, Some(neighbor_a));
    }

    #[test]
    fn gpsr_forward_requires_progress() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((1.0, 1.0));

        // Neighbors are further from destination than we are
        let neighbor_a = link_local(0xa);
        let neighbor_b = link_local(0xb);
        router
            .neighbors
            .update_with_coords(&neighbor_a, 1.0, -50, 1000, Some((0.5, 1.0)));
        router
            .neighbors
            .update_with_coords(&neighbor_b, 1.0, -50, 1000, Some((0.0, 1.0)));

        // Destination is 2.0 north - we're at 1.0, neighbors are at 0.5 and 0.0
        let dst_coords = (2.0, 1.0);
        let next_hop = router.gpsr_forward(dst_coords);

        // No progress possible - local minimum
        assert_eq!(next_hop, None);
    }

    #[test]
    fn gpsr_forward_no_node_coords() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = None; // No GPS

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        let next_hop = router.gpsr_forward((2.0, 1.0));
        assert_eq!(next_hop, None);
    }

    #[test]
    fn gpsr_forward_no_neighbor_coords() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        // Neighbor without coords
        let neighbor = link_local(0xa);
        router.neighbors.update(&neighbor, 1.0, -50, 1000);

        let next_hop = router.gpsr_forward((2.0, 1.0));
        assert_eq!(next_hop, None);
    }

    #[test]
    fn gpsr_forward_nan_coords() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        assert_eq!(router.gpsr_forward((f64::NAN, 1.0)), None);
        assert_eq!(router.gpsr_forward((1.0, f64::NAN)), None);
    }

    #[test]
    fn gpsr_forward_inf_coords() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        assert_eq!(router.gpsr_forward((f64::INFINITY, 1.0)), None);
        assert_eq!(router.gpsr_forward((f64::NEG_INFINITY, 1.0)), None);
    }

    #[test]
    fn gpsr_forward_invalid_latitude() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        assert_eq!(router.gpsr_forward((91.0, 0.0)), None);
        assert_eq!(router.gpsr_forward((-91.0, 0.0)), None);
    }

    #[test]
    fn gpsr_forward_invalid_longitude() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        assert_eq!(router.gpsr_forward((0.0, 181.0)), None);
        assert_eq!(router.gpsr_forward((0.0, -181.0)), None);
    }

    #[test]
    fn gpsr_forward_null_island() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((1.0, 1.0));

        let neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&neighbor, 1.0, -50, 1000, Some((0.5, 0.5)));

        // Null island (0, 0) is rejected as invalid sentinel
        assert_eq!(router.gpsr_forward((0.0, 0.0)), None);
    }

    #[test]
    fn gpsr_forward_skips_invalid_neighbor_coords() {
        let mut router = Router::new(link_local(0), link_local(0));
        router.node_coords = Some((0.0, 1.0));

        // Neighbor with NaN coords should be skipped
        let bad_neighbor = link_local(0xa);
        router
            .neighbors
            .update_with_coords(&bad_neighbor, 1.0, -50, 1000, Some((f64::NAN, 1.0)));

        // Good neighbor should still be selected
        let good_neighbor = link_local(0xb);
        router
            .neighbors
            .update_with_coords(&good_neighbor, 1.0, -50, 1000, Some((1.0, 1.0)));

        let next_hop = router.gpsr_forward((2.0, 1.0));
        assert_eq!(next_hop, Some(good_neighbor));
    }

    #[test]
    fn haversine_distance_same_point() {
        let p = (47.6062, -122.3321);
        assert!(super::haversine(p, p) < 0.01);
    }

    #[test]
    fn haversine_distance_known() {
        // Seattle to Portland ~= 233km
        let seattle = (47.6062, -122.3321);
        let portland = (45.5152, -122.6784);
        let d = super::haversine(seattle, portland);
        assert!((d - 233_000.0).abs() < 5000.0);
    }

    #[test]
    fn is_valid_coords_rejects_nan() {
        assert!(!super::is_valid_coords((f64::NAN, 0.0)));
        assert!(!super::is_valid_coords((0.0, f64::NAN)));
    }

    #[test]
    fn is_valid_coords_rejects_inf() {
        assert!(!super::is_valid_coords((f64::INFINITY, 0.0)));
        assert!(!super::is_valid_coords((f64::NEG_INFINITY, 0.0)));
    }

    #[test]
    fn is_valid_coords_rejects_null_island() {
        assert!(!super::is_valid_coords((0.0, 0.0)));
    }

    #[test]
    fn is_valid_coords_accepts_valid() {
        assert!(super::is_valid_coords((47.6062, -122.3321)));
        assert!(super::is_valid_coords((-33.8688, 151.2093))); // Sydney
        assert!(super::is_valid_coords((90.0, 0.0))); // North pole
        assert!(super::is_valid_coords((-90.0, 180.0))); // South pole
    }

    fn signed_dao(
        identity: &Identity,
        parent: [u8; 16],
        dodag: [u8; 16],
        sequence: u64,
    ) -> ([u8; 16], Vec<u8>) {
        let mut origin = [0u8; 16];
        origin[0] = 0xfd;
        origin[8..].copy_from_slice(&identity.iid);
        let mut manager = DaoManager::new(origin, RPL_INSTANCE_ID, dodag);
        let unsigned = manager.build_dao(parent);
        let link = LinkLayer::new(identity.clone());
        let wire = sign_dao(&unsigned, origin, dodag, sequence, &link).unwrap();
        (origin, wire)
    }

    #[test]
    fn tx_sequence_is_persisted_before_bytes_and_write_failure_returns_no_bytes() {
        let identity = Identity::from_seed(Seed::new([1; 32]));
        let root = [0x44; 16];
        let mut router = Router::new(origin_for(&identity), root);
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: 0,
            rank: ROOT_RANK,
            grounded: true,
            mode_of_operation: NON_STORING_MOP,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: root,
        };
        router.process_dio(&dio, &dio_bytes(&dio), root, -40, 0);
        let other = Identity::from_seed(Seed::new([2; 32]));
        let mut wrong_storage = lichen_hal::storage::mem::MemStorage::new();
        let mut wrong_tx = DaoTxState::provision(
            &mut wrong_storage,
            other.pubkey,
            origin_for(&identity),
            RPL_INSTANCE_ID,
            root,
        )
        .unwrap();
        let before_a = wrong_storage.raw("rpl.tx.a").map(<[u8]>::to_vec);
        let before_b = wrong_storage.raw("rpl.tx.b").map(<[u8]>::to_vec);
        assert_eq!(
            router.build_signed_dao(
                origin_for(&identity),
                &mut wrong_tx,
                &mut wrong_storage,
                &LinkLayer::new(identity.clone()),
            ),
            Err(DaoTxError::KeyMismatch)
        );
        assert_eq!(wrong_storage.raw("rpl.tx.a"), before_a.as_deref());
        assert_eq!(wrong_storage.raw("rpl.tx.b"), before_b.as_deref());

        let mut storage = lichen_hal::storage::mem::MemStorage::new();
        let mut tx = DaoTxState::provision(
            &mut storage,
            identity.pubkey,
            origin_for(&identity),
            RPL_INSTANCE_ID,
            root,
        )
        .unwrap();
        storage.fail_next_write();
        assert!(matches!(
            router.build_signed_dao(
                origin_for(&identity),
                &mut tx,
                &mut storage,
                &LinkLayer::new(identity.clone())
            ),
            Err(DaoTxError::Persistence(_))
        ));
        let wire = router
            .build_signed_dao(
                origin_for(&identity),
                &mut tx,
                &mut storage,
                &LinkLayer::new(identity.clone()),
            )
            .unwrap();
        assert_eq!(
            SignedDaoEnvelope::from_bytes(&wire)
                .unwrap()
                .origin
                .origin_sequence,
            1
        );
        assert_eq!(
            DaoTxState::open(
                &storage,
                identity.pubkey,
                origin_for(&identity),
                RPL_INSTANCE_ID,
                root,
            )
            .unwrap()
            .last_signed_dao(),
            Some(wire.as_slice())
        );

        storage.fail_after_writes(1);
        assert!(matches!(
            router.build_signed_dao(
                origin_for(&identity),
                &mut tx,
                &mut storage,
                &LinkLayer::new(identity.clone()),
            ),
            Err(DaoTxError::Persistence(_))
        ));
        assert_eq!(
            DaoTxState::open(
                &storage,
                identity.pubkey,
                origin_for(&identity),
                RPL_INSTANCE_ID,
                root,
            )
            .unwrap()
            .last_signed_dao(),
            Some(wire.as_slice())
        );
        let after_failure = router
            .build_signed_dao(
                origin_for(&identity),
                &mut tx,
                &mut storage,
                &LinkLayer::new(identity),
            )
            .unwrap();
        assert_eq!(
            SignedDaoEnvelope::from_bytes(&after_failure)
                .unwrap()
                .origin
                .origin_sequence,
            3
        );
    }

    fn origin_for(identity: &Identity) -> [u8; 16] {
        let mut origin = [0u8; 16];
        origin[0] = 0xfd;
        origin[8..].copy_from_slice(&identity.iid);
        origin
    }

    #[test]
    fn stable_key_floor_duplicate_changed_equal_prefix_and_reboot() {
        let identity = Identity::from_seed(Seed::new([2; 32]));
        let root_addr = [0x55; 16];
        let (origin, wire) = signed_dao(&identity, root_addr, root_addr, 1);
        let verified = SignatureVerifiedDao::verify_signature(
            &wire,
            origin,
            RPL_INSTANCE_ID,
            root_addr,
            Some(identity.pubkey),
        )
        .unwrap();
        let mut storage = lichen_hal::storage::mem::MemStorage::new();
        let (mut root, mut state) = Router::provision_root(&mut storage, root_addr).unwrap();
        assert_eq!(
            root.process_signature_verified_dao_at_ms(
                &verified,
                verified.origin_iid(),
                &mut state,
                &mut storage,
                0,
            ),
            Ok(DaoProcessOutcome::Applied)
        );
        assert_eq!(
            root.process_signature_verified_dao_at_ms(
                &verified,
                verified.origin_iid(),
                &mut state,
                &mut storage,
                1,
            ),
            Ok(DaoProcessOutcome::Duplicate)
        );
        let mut other_prefix = origin;
        other_prefix[0] ^= 0x20;
        let changed = sign_dao(
            SignedDaoEnvelope::from_bytes(&wire).unwrap().unsigned_bytes,
            other_prefix,
            root_addr,
            1,
            &LinkLayer::new(identity.clone()),
        )
        .unwrap();
        let changed = SignatureVerifiedDao::verify_signature(
            &changed,
            other_prefix,
            RPL_INSTANCE_ID,
            root_addr,
            Some(identity.pubkey),
        )
        .unwrap();
        assert!(matches!(
            root.process_signature_verified_dao_at_ms(
                &changed,
                changed.origin_iid(),
                &mut state,
                &mut storage,
                2,
            ),
            Err(DaoProcessError::Replay)
        ));
        let (mut rebooted, mut rebooted_state) = Router::open_root(&storage, root_addr).unwrap();
        assert_eq!(
            rebooted.process_signature_verified_dao_at_ms(
                &verified,
                verified.origin_iid(),
                &mut rebooted_state,
                &mut storage,
                3
            ),
            Ok(DaoProcessOutcome::Duplicate)
        );
    }

    #[test]
    fn production_handler_requires_announce_pin() {
        let identity = Identity::from_seed(Seed::new([3; 32]));
        let root_id = lichen_core::addr::NodeId([9; 8]);
        let root_addr = root_id.link_local_addr().0;
        let (origin, wire) = signed_dao(&identity, root_addr, root_addr, 1);
        let mut storage = lichen_hal::storage::mem::MemStorage::new();
        let (mut node, mut state) =
            crate::node::RplNode::provision_root(root_id, &mut storage).unwrap();
        let mut announces = crate::announce::AnnounceProcessor::new(
            crate::gradient::GradientTable::new(crate::announce::MAX_TRACKED_ORIGINATORS),
            [0xfd; 8],
        );
        assert_eq!(
            node.handle_dao(
                &wire,
                origin,
                identity.iid,
                &announces,
                &mut state,
                &mut storage,
                0,
            ),
            crate::node::DaoHandlingOutcome::UnknownKey
        );
        announces.pin_for_test(identity.pubkey);
        assert_eq!(
            node.handle_dao(
                &wire,
                origin,
                identity.iid,
                &announces,
                &mut state,
                &mut storage,
                0,
            ),
            crate::node::DaoHandlingOutcome::Applied
        );
    }
}
