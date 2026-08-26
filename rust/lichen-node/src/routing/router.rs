//! RPL Router state machine.

extern crate std;
use std::vec::Vec;

use lichen_core::constants::RPL_INSTANCE_ID;
use lichen_hal::NonVolatile;
use lichen_link::{
    keys::PublicKey,
    link_layer::{AuthenticatedFrame, LinkLayer},
};
use lichen_rpl::dodag::DioOutcome;
use lichen_rpl::message::{
    Dao, Dio, DodagConfig, DodagVersionAuthorization, OptionIter, TransitInfo,
    DODAG_CONFIG_DATA_LEN, OPT_DODAG_VERSION_AUTHORIZATION,
};
use lichen_rpl::trickle::TrickleTimer;

use super::{
    dao_origin_digest, DaoAdmissionState, DaoManager, DaoOriginSignature, DaoPersistentOpenError,
    DaoProcessError, DaoProcessOutcome, DaoProcessTiming, DaoProvisionError, DaoRxState,
    DaoTxError, DaoTxState, SignatureVerifiedDao, DAO_ORIGIN_SIGNATURE_LEN, OPT_DODAG_CONFIG,
};
pub use lichen_rpl::dodag::DodagState;

use super::gpsr::{haversine, is_valid_coords};
use super::neighbor::{
    GeoCoords, LinkEtx, NeighborTable, TrickleSafeLivenessPolicy, MAX_NEIGHBORS,
};

const NON_STORING_MOP: u8 = 1;
const MRHOF_OCP: u16 = 1;
const DODAG_VERSION_AUTHORIZATION_DOMAIN: &[u8] = b"LICHEN-RPL-DODAG-VERSION-v1";

fn dodag_version_authorization_transcript(
    rpl_instance_id: u8,
    dodag_id: &[u8; 16],
    version: u8,
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(DODAG_VERSION_AUTHORIZATION_DOMAIN.len() + 1 + 16 + 1);
    transcript.extend_from_slice(DODAG_VERSION_AUTHORIZATION_DOMAIN);
    transcript.push(rpl_instance_id);
    transcript.extend_from_slice(dodag_id);
    transcript.push(version);
    transcript
}

fn verify_dodag_version_authorization(
    authorization: &DodagVersionAuthorization,
    dio: &Dio,
) -> bool {
    authorization.version == dio.version
        && lichen_core::addr::ygg_addr_from_pubkey(&authorization.root_pubkey) == dio.dodag_id
        && lichen_link::schnorr::verify(
            &PublicKey::new(authorization.root_pubkey),
            &dodag_version_authorization_transcript(
                dio.rpl_instance_id,
                &dio.dodag_id,
                dio.version,
            ),
            &authorization.signature,
        )
}

fn trickle_from_config(config: &DodagConfig) -> Option<TrickleTimer> {
    let imin_ms = 1u32.checked_shl(u32::from(config.dio_int_min)).unwrap_or(0);
    if imin_ms == 0 || config.dio_redundancy_const == 0 {
        return None;
    }
    Some(TrickleTimer::new(
        imin_ms,
        u32::from(config.dio_int_doublings),
        u32::from(config.dio_redundancy_const),
    ))
}

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

pub(crate) fn sign_dao(
    unsigned_dao: &[u8],
    origin: [u8; 16],
    active_dodag_id: [u8; 16],
    origin_sequence: u64,
    link: &LinkLayer,
) -> Option<Vec<u8>> {
    if origin_sequence == 0
        || origin != lichen_link::ygg_addr_from_pubkey(link.local_public_key().as_bytes())
    {
        return None;
    }
    let dao = Dao::from_bytes(unsigned_dao).ok()?;
    for option in OptionIter::new(Dao::options_tail(unsigned_dao)) {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DioProcessOutcome {
    Rejected,
    Consistent,
    Inconsistent,
}

impl DioProcessOutcome {
    fn accepted(inconsistent: bool) -> Self {
        if inconsistent {
            Self::Inconsistent
        } else {
            Self::Consistent
        }
    }

    #[cfg(test)]
    fn is_inconsistent(self) -> bool {
        self == Self::Inconsistent
    }
}

/// Effects of one cohesive routing maintenance observation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RplMaintenanceOutcome {
    pub routes_expired: bool,
    pub neighbors_pruned: bool,
    pub topology_changed: bool,
}

/// Unified routing state combining DODAG, trickle, DAO manager, and neighbor table.
#[derive(Debug)]
pub struct Router {
    pub(crate) dodag: DodagState,
    pub(crate) trickle: TrickleTimer,
    pub(crate) dao_manager: DaoManager,
    pub(crate) neighbors: NeighborTable,
    pub(crate) dodag_id: [u8; 16],
    pub(crate) dodag_config: DodagConfig,
    pub(crate) last_now_ms: u64,
    /// Latest independently verified root-owned version authorization.
    version_authorization: Option<DodagVersionAuthorization>,
    /// DODAG Grounded state: the root has an identity-preserving global path.
    grounded: bool,
    /// This node's geographic coordinates for GPSR (spec 9.7).
    /// None if GPS unavailable or privacy mode enabled.
    pub node_coords: Option<GeoCoords>,
    #[cfg(test)]
    pub(crate) test_storage: lichen_hal::storage::mem::MemStorage,
    #[cfg(test)]
    pub(crate) test_rx_state: Option<DaoRxState>,
    #[cfg(test)]
    pub(crate) test_origin_sequence: u64,
    #[cfg(test)]
    pub(crate) test_dao_admission: Option<DaoAdmissionState>,
}

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
            version_authorization: None,
            grounded: false,
            node_coords: None,
            #[cfg(test)]
            test_storage: lichen_hal::storage::mem::MemStorage::new(),
            #[cfg(test)]
            test_rx_state: None,
            #[cfg(test)]
            test_origin_sequence: 0,
            #[cfg(test)]
            test_dao_admission: None,
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
            version_authorization: None,
            // Existing component-level root constructors represent an active
            // border router. Production Gateway startup updates this from the
            // actual upstream/TUN state before serving packets.
            grounded: true,
            node_coords: None,
            #[cfg(test)]
            test_storage: lichen_hal::storage::mem::MemStorage::new(),
            #[cfg(test)]
            test_rx_state: None,
            #[cfg(test)]
            test_origin_sequence: 0,
            #[cfg(test)]
            test_dao_admission: None,
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
    pub(crate) fn new_root_with_config(node_addr: [u8; 16], config: DodagConfig) -> Option<Self> {
        if config.min_hop_rank_increase == 0 || config.lifetime_unit == 0 || config.ocp != MRHOF_OCP
        {
            return None;
        }
        let mut storage = lichen_hal::storage::mem::MemStorage::new();
        let (manager, state) =
            DaoManager::provision_root(&mut storage, node_addr, RPL_INSTANCE_ID, node_addr).ok()?;
        let dao_admission =
            DaoAdmissionState::provision(&mut storage, node_addr, RPL_INSTANCE_ID, node_addr)
                .ok()?;
        let mut router = Self::root_with_manager(node_addr, config, manager)?;
        router.test_storage = storage;
        router.test_rx_state = Some(state);
        router.test_dao_admission = Some(dao_admission);
        Some(router)
    }

    /// Process a received DIO message from a neighbor.
    ///
    /// Updates neighbor table, feeds DODAG state machine, and returns whether
    /// the trickle timer should be reset (inconsistent DIO heard). `now_ms`
    /// must use one nondecreasing monotonic `u64` timeline.
    #[cfg(test)]
    pub(crate) fn process_dio(
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

    /// Production DIO admission from live link-authenticated evidence.
    pub fn process_authenticated_dio(
        &mut self,
        link: &LinkLayer,
        frame: AuthenticatedFrame,
        etx: LinkEtx,
        rssi: i8,
        now_ms: u64,
    ) -> DioProcessOutcome {
        let signer_iid = frame.sender().iid;
        let expected_role =
            if lichen_core::addr::ygg_addr_from_pubkey(frame.sender().pubkey.as_bytes())
                == self.dodag_id
            {
                lichen_schc::ExpectedDioRole::Root
            } else {
                lichen_schc::ExpectedDioRole::Peer
            };
        let Ok(peer) = lichen_schc::AuthenticatedPeerSchcContext::from_authenticated_dio_frame(
            frame,
            self.dodag.rpl_instance_id,
            &self.dodag_id,
            NON_STORING_MOP,
            expected_role,
        ) else {
            self.revoke_schc_peer(&signer_iid, now_ms);
            return DioProcessOutcome::Rejected;
        };
        let Some(frame) = peer.authenticated_frame() else {
            self.revoke_schc_peer(&signer_iid, now_ms);
            return DioProcessOutcome::Rejected;
        };
        if !peer.allows_dodag_join() || !link.accepts_authenticated_frame(frame) {
            self.revoke_schc_peer(&signer_iid, now_ms);
            return DioProcessOutcome::Rejected;
        }
        let mut ipv6 = [0u8; 512];
        let Ok(ipv6_len) = lichen_schc::decompress(&frame.payload()[1..], &mut ipv6) else {
            self.revoke_schc_peer(&signer_iid, now_ms);
            return DioProcessOutcome::Rejected;
        };
        if ipv6_len < 68 {
            self.revoke_schc_peer(&signer_iid, now_ms);
            return DioProcessOutcome::Rejected;
        }
        let dio_bytes = &ipv6[44..ipv6_len];
        let Ok(dio) = Dio::from_bytes(dio_bytes) else {
            self.revoke_schc_peer(&signer_iid, now_ms);
            return DioProcessOutcome::Rejected;
        };
        let sender_addr = ipv6[8..24]
            .try_into()
            .expect("validated IPv6 header has a complete source address");
        self.process_dio_with_etx_outcome(&dio, dio_bytes, sender_addr, etx, rssi, now_ms)
    }

    fn revoke_schc_peer(&mut self, signer_iid: &[u8; 8], now_ms: u64) {
        let was_joined = self.dodag.is_joined();
        let old_parent = self.dodag.preferred_parent;
        let old_rank = self.dodag.rank;
        let parent_removed = self.dodag.remove_parents_with_iid(signer_iid);
        let neighbor_removed = self.neighbors.remove_with_iid(signer_iid);
        let topology_changed = parent_removed
            || neighbor_removed
            || was_joined != self.dodag.is_joined()
            || old_parent != self.dodag.preferred_parent
            || old_rank != self.dodag.rank;
        if topology_changed {
            let now_ms = self.observe_now(now_ms);
            self.trickle.reset(now_ms, 0);
        }
    }

    pub(crate) fn process_dio_outcome(
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
    #[cfg(test)]
    pub(crate) fn process_dio_with_etx(
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

    pub(crate) fn process_dio_with_etx_outcome(
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
        let mut version_authorization = None;
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
            } else if option.opt_type == OPT_DODAG_VERSION_AUTHORIZATION {
                if version_authorization.is_some() {
                    return DioProcessOutcome::Rejected;
                }
                let Ok(parsed) = DodagVersionAuthorization::from_option_data(option.data) else {
                    return DioProcessOutcome::Rejected;
                };
                version_authorization = Some(parsed);
            }
        }
        let version_authorized = version_authorization
            .as_ref()
            .is_some_and(|authorization| verify_dodag_version_authorization(authorization, dio));
        if version_authorization.is_some() && !version_authorized {
            return DioProcessOutcome::Rejected;
        }
        if !version_order.is_eq() && !version_authorized {
            return DioProcessOutcome::Rejected;
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
        match staged_dodag.process_dio_with_version_authorization(
            dio,
            sender_addr,
            etx,
            version_authorized,
        ) {
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

        // A DIO that proposes a config change is only trustworthy if the sender
        // would be a valid parent under that config. If the sender was pruned as
        // inadmissible, reject the entire DIO including the config update.
        if config_changed && !staged_dodag.has_parent(&sender_addr) {
            return DioProcessOutcome::Rejected;
        }

        self.dodag = staged_dodag;
        self.neighbors = staged_neighbors;
        self.dodag_config = proposed_config;
        let grounded_changed = self.grounded != dio.grounded;
        self.grounded = dio.grounded;
        if let Some(authorization) = version_authorization {
            self.version_authorization = Some(authorization);
        }

        let now_joined = self.dodag.is_joined();
        let new_parent = self.dodag.preferred_parent;
        let inconsistent = config_changed
            || grounded_changed
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
    pub(crate) fn process_dao_at_times(
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
            let origin = lichen_link::ygg_addr_from_pubkey(identity.pubkey.as_bytes());
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
            let admission = self
                .test_dao_admission
                .as_mut()
                .expect("test root has admission state");
            // Auto-admit test identity pubkeys so process_dao_at_times works as expected
            let _ = admission.admit(&mut self.test_storage, *identity.pubkey.as_bytes());
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
                    admission,
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
        dao_admission: &DaoAdmissionState,
    ) -> Result<DaoProcessOutcome, DaoProcessError<S::Error>> {
        self.process_signature_verified_dao_from_at_ms(
            dao,
            authenticated_sender_iid,
            rx_state,
            storage,
            now_ms,
            dao_admission,
        )
    }

    pub(crate) fn process_signature_verified_dao_from_at_ms<S: NonVolatile>(
        &mut self,
        dao: &SignatureVerifiedDao<'_>,
        authenticated_sender_iid: [u8; 8],
        rx_state: &mut DaoRxState,
        storage: &mut S,
        now_ms: u64,
        dao_admission: &DaoAdmissionState,
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
            dao_admission,
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
        if origin_ipv6 != lichen_link::ygg_addr_from_pubkey(link.local_public_key().as_bytes()) {
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
        self.build_dio_with_authorization(out, None)
    }

    /// Update the root's identity-preserving global reachability state.
    ///
    /// The standard RPL Grounded bit carries this advertisement. LICHEN's
    /// single-primary profile intentionally emits no Prefix Information option.
    #[must_use]
    pub fn set_ygg_reachable(&mut self, reachable: bool) -> bool {
        if !self.dodag.is_root() || self.grounded == reachable {
            return false;
        }
        self.grounded = reachable;
        self.trickle.reset(self.last_now_ms, 0);
        true
    }

    /// Build a DIO with the root authorization minted locally by a root or
    /// propagated unchanged by a non-root router.
    pub fn build_authenticated_dio(&self, out: &mut [u8], link: &LinkLayer) -> usize {
        let authorization = if self.dodag.is_root() {
            let root_pubkey = *link.local_public_key().as_bytes();
            if lichen_core::addr::ygg_addr_from_pubkey(&root_pubkey) != self.dodag_id {
                return 0;
            }
            let transcript = dodag_version_authorization_transcript(
                self.dodag.rpl_instance_id,
                &self.dodag_id,
                self.dodag.version,
            );
            Some(DodagVersionAuthorization {
                version: self.dodag.version,
                root_pubkey,
                signature: link.sign_digest(&transcript),
            })
        } else {
            self.version_authorization
                .clone()
                .filter(|authorization| authorization.version == self.dodag.version)
        };
        self.build_dio_with_authorization(out, authorization.as_ref())
    }

    fn build_dio_with_authorization(
        &self,
        out: &mut [u8],
        authorization: Option<&DodagVersionAuthorization>,
    ) -> usize {
        let dio = Dio {
            rpl_instance_id: RPL_INSTANCE_ID,
            version: self.dodag.version,
            rank: self.dodag.rank,
            grounded: self.grounded,
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
        let mut length = base_len + config_len;
        if let Some(authorization) = authorization {
            let Ok(authorization_len) = authorization.write_to(&mut out[length..]) else {
                return 0;
            };
            length += authorization_len;
        }
        length
    }

    /// Get the route path for a destination (root only).
    ///
    /// Non-root nodes always return `None` (routing table is root-only in non-storing RPL mode per spec/05-routing.md). Error handling for invalid dst is delegated to routing_table.lookup.
    pub fn lookup_route(&self, dst: &[u8; 16]) -> Option<&[[u8; 16]]> {
        if !self.dodag.is_root() {
            return None;
        }
        self.dao_manager.routing_table().lookup(dst)
    }

    /// Expire finite routes and look up a destination using monotonic time.
    pub fn lookup_route_at(&mut self, dst: &[u8; 16], now_ms: u64) -> Option<&[[u8; 16]]> {
        self.expire_routes_at(now_ms);
        self.lookup_route(dst)
    }

    /// Inject a route directly into the routing table (for testing).
    pub fn inject_route(&mut self, target: [u8; 16], path: &[[u8; 16]]) {
        self.dao_manager.routing_table_mut().add_route(target, path);
    }

    /// Check trickle timer and return pending event.
    pub fn poll_trickle(&self) -> lichen_rpl::trickle::TrickleEvent {
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

    pub fn maintain<P: TrickleSafeLivenessPolicy>(
        &mut self,
        now_ms: u64,
        neighbor_timeout_ms: u64,
        policy: &P,
    ) -> RplMaintenanceOutcome {
        let now_ms = self.observe_now(now_ms);
        let routes_expired = self.dao_manager.expire_routes(now_ms / 1_000);
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
        let _heard_consistent = self.trickle.counter;
        let mut removed = [[0u8; 16]; MAX_NEIGHBORS];
        let mut removed_len = 0;
        self.neighbors
            .prune_with_removed(policy, now_ms, max_age_ms, 0, |addr| {
                removed[removed_len] = addr;
                removed_len += 1;
            });
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

    /// Get DAO origin high water marks for testing.
    #[cfg(test)]
    pub fn dao_origin_keys(&self) -> Vec<super::DaoOriginHighWater> {
        self.dao_manager.origin_high_water()
    }
}

// Helper functions for DAO processing
pub(crate) fn dao_parents_for_source(
    dao_bytes: &[u8],
    packet_source: &[u8; 16],
) -> Option<Vec<[u8; 16]>> {
    use lichen_rpl::message::{RplTarget, OPT_RPL_TARGET, OPT_TRANSIT_INFO};

    let _dao = Dao::from_bytes(dao_bytes).ok()?;
    let mut parents = Vec::new();
    let mut current_target: Option<[u8; 16]> = None;

    for option in OptionIter::new(Dao::options_tail(dao_bytes)) {
        let option = option.ok()?;
        match option.opt_type {
            OPT_RPL_TARGET => {
                let target = RplTarget::from_bytes(option.data).ok()?;
                current_target = Some(target.prefix);
            }
            OPT_TRANSIT_INFO => {
                if current_target == Some(*packet_source) {
                    let transit = TransitInfo::from_bytes(option.data).ok()?;
                    parents.push(transit.parent_address);
                }
            }
            _ => {}
        }
    }

    if parents.is_empty() {
        None
    } else {
        Some(parents)
    }
}

#[cfg(test)]
fn same_interface(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a[8..] == b[8..]
}
