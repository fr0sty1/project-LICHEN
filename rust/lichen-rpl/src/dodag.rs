//! RPL DODAG state machine with MRHOF parent selection (RFC 6550, spec §8).
//!
//! Port of `python/src/lichen/rpl/dodag.py`. The key behaviours:
//!
//! - A node starts UNJOINED; on hearing a usable DIO it elects a preferred
//!   parent and becomes JOINED.
//! - Rank = preferred_parent.rank + round(link_etx × MinHopRankIncrease).
//! - Hysteresis: switch parent only if the candidate improves path cost by
//!   more than `PARENT_SWITCH_THRESHOLD`.
//! - MaxRankIncrease: reject candidates that would take rank above the lowest
//!   rank we have ever held plus `max_rank_increase`.

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "std")]
use core::cmp::Ordering;

#[cfg(feature = "std")]
use crate::message::Dio;

pub const INFINITE_RANK: u16 = 0xFFFF;
pub const MIN_HOP_RANK_INCREASE: u16 = 256;
pub const ROOT_RANK: u16 = MIN_HOP_RANK_INCREASE;
pub const MAX_RANK_INCREASE: u16 = 1024;
pub const PARENT_SWITCH_THRESHOLD: u16 = 192;
pub const MAX_PARENT_CANDIDATES: usize = 16;

pub const ALL_RPL_NODES: [u8; 16] = [
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a,
];

pub fn is_rpl_multicast(addr: &[u8; 16]) -> bool {
    *addr == ALL_RPL_NODES
}

/// Lollipop sequence-counter comparison (RFC 6550 Section 7.2,
/// SEQUENCE_WINDOW = 16).
///
/// Returns `None` only when both counters sit in the same region and their
/// absolute difference exceeds SEQUENCE_WINDOW (desynchronization); otherwise
/// the ordering of `a` versus `b`. Boundaries are inclusive by RFC MUST:
/// a same-region difference of exactly 16 is comparable (rule 3.2.1), and a
/// cross-region wrap distance `(256 + B - A)` of exactly 16 means the
/// freshly wrapped counter is newer (rule 3.1.1). Cross-region counters are
/// always comparable.
#[cfg(feature = "std")]
fn lollipop_cmp(a: u8, b: u8) -> Option<core::cmp::Ordering> {
    if a == b {
        return Some(core::cmp::Ordering::Equal);
    }
    let a_circular = a < 128;
    let b_circular = b < 128;
    if a_circular == b_circular {
        // RFC 6550 §7.2 rule 3.2 tests the absolute magnitude before
        // applying RFC 1982 ordering. Reducing modulo 128 first would
        // incorrectly make distant pairs such as 0 and 127 comparable.
        if a.abs_diff(b) > 16 {
            None
        } else if a > b {
            Some(core::cmp::Ordering::Greater)
        } else {
            Some(core::cmp::Ordering::Less)
        }
    } else if a_circular {
        // a in circular (0-127), b in linear (128-255)
        // Wrap distance from b to a: 256 - b + a
        let wrap_distance = 256 - b as u16 + a as u16;
        if wrap_distance <= 16 {
            Some(core::cmp::Ordering::Greater)
        } else {
            Some(core::cmp::Ordering::Less)
        }
    } else {
        // a in linear (128-255), b in circular (0-127)
        // Wrap distance from a to b: 256 - a + b
        let wrap_distance = 256 - a as u16 + b as u16;
        if wrap_distance <= 16 {
            Some(core::cmp::Ordering::Less)
        } else {
            Some(core::cmp::Ordering::Greater)
        }
    }
}

#[cfg(feature = "std")]
fn version_is_newer(new_ver: u8, old_ver: u8) -> bool {
    (new_ver, old_ver) == (0, 127)
        || lollipop_cmp(new_ver, old_ver) == Some(core::cmp::Ordering::Greater)
}

#[cfg(feature = "std")]
fn version_is_equal(new_ver: u8, old_ver: u8) -> bool {
    lollipop_cmp(new_ver, old_ver) == Some(Ordering::Equal)
}

#[cfg(feature = "std")]
fn version_is_older_or_incomparable(new_ver: u8, old_ver: u8) -> bool {
    !version_is_newer(new_ver, old_ver) && !version_is_equal(new_ver, old_ver)
}

/// MRHOF candidate admissibility (RFC 6719 Section 3.3, spec B.1).
///
/// Every rank-versus-rank comparison below is made on DAGRank values, not
/// raw Rank: `DAGRank(R) = floor(R / min_hop_rank_increase)` per RFC 6550
/// Section 3.5.1. Integer division implements the floor, so truncation is
/// intentional: e.g. with MinHopRankIncrease 256, a candidate at rank 256
/// (DAGRank 1) offering a path cost of 511 (DAGRank 1) is refused because
/// the DAGRanks compare equal, while a cost of 512 (DAGRank 2) passes.
#[cfg(feature = "std")]
fn candidate_admissible(
    candidate: &ParentCandidate,
    node_rank: u16,
    lowest_rank: u16,
    min_hop_rank_increase: u16,
    max_rank_increase: u16,
) -> bool {
    if min_hop_rank_increase == 0 {
        return false;
    }
    let cost = candidate.path_cost(min_hop_rank_increase);
    // DAGRank comparisons (floor division), per RFC 6550 Section 3.5.1:
    // refuse ranks below the root floor and candidates whose path cost does
    // not strictly exceed their own advertised DAGRank.
    if candidate.rank < min_hop_rank_increase
        || cost == INFINITE_RANK
        || cost / min_hop_rank_increase <= candidate.rank / min_hop_rank_increase
    {
        return false;
    }
    // Candidate must sit strictly below our own DAGRank to avoid loops.
    if node_rank != INFINITE_RANK
        && candidate.rank / min_hop_rank_increase >= node_rank / min_hop_rank_increase
    {
        return false;
    }
    max_rank_increase == 0
        || lowest_rank == INFINITE_RANK
        || cost <= lowest_rank.saturating_add(max_rank_increase)
}

/// Node's role in the DODAG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DodagRole {
    Unjoined,
    Joined,
    Root,
}

impl DodagRole {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Unjoined, Self::Unjoined)
                | (Self::Unjoined, Self::Joined)
                | (Self::Unjoined, Self::Root)
                | (Self::Joined, Self::Unjoined)
                | (Self::Joined, Self::Joined)
                | (Self::Joined, Self::Root)
                | (Self::Root, Self::Root)
                | (Self::Root, Self::Unjoined)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDodagTransition {
    pub from: DodagRole,
    pub to: DodagRole,
}

/// A neighbour that is advertising membership in the DODAG.
#[derive(Clone, Debug)]
pub struct ParentCandidate {
    /// Full 16-byte IPv6 link-local address of the neighbour.
    pub addr: [u8; 16],
    pub rank: u16,
    /// Link ETX estimate (1.0 = perfect link).
    pub link_etx: f32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DioOutcome {
    Accepted,
    Removed,
    Rejected,
}

impl ParentCandidate {
    /// Rank this node would achieve via this parent (MRHOF, spec B.1).
    #[cfg(feature = "std")]
    pub fn path_cost(&self, mhri: u16) -> u16 {
        let link_cost = (self.link_etx * mhri as f32).round();
        // NaN or negative -> saturate to max (treat invalid link as unusable)
        if link_cost.is_nan() || link_cost < 0.0 {
            return u16::MAX;
        }
        self.rank.saturating_add(link_cost as u16)
    }
}

/// RPL DODAG membership state for a single node.
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct DodagState {
    pub rpl_instance_id: u8,
    pub dodag_id: [u8; 16],
    pub version: u8,
    pub role: DodagRole,
    pub rank: u16,
    pub preferred_parent: Option<[u8; 16]>,
    pub min_hop_rank_increase: u16,
    pub max_rank_increase: u16,
    pub parent_switch_threshold: u16,
    pub is_gateway_centric: bool,
    parents: HashMap<[u8; 16], ParentCandidate>,
    lowest_rank: u16,
}

#[cfg(feature = "std")]
impl DodagState {
    /// Create an unjoined node for the given DODAG.
    pub fn new(rpl_instance_id: u8, dodag_id: [u8; 16], version: u8) -> Self {
        Self {
            rpl_instance_id,
            dodag_id,
            version,
            role: DodagRole::Unjoined,
            rank: INFINITE_RANK,
            preferred_parent: None,
            min_hop_rank_increase: MIN_HOP_RANK_INCREASE,
            max_rank_increase: MAX_RANK_INCREASE,
            parent_switch_threshold: PARENT_SWITCH_THRESHOLD,
            is_gateway_centric: false,
            parents: HashMap::new(),
            lowest_rank: INFINITE_RANK,
        }
    }

    /// Create a DODAG root using the default rank configuration.
    pub fn as_root(rpl_instance_id: u8, dodag_id: [u8; 16], version: u8) -> Self {
        Self::as_root_with_rank_config(
            rpl_instance_id,
            dodag_id,
            version,
            MIN_HOP_RANK_INCREASE,
            MAX_RANK_INCREASE,
        )
        .expect("default MinHopRankIncrease is non-zero")
    }

    /// Create a DODAG root whose rank is the configured MinHopRankIncrease.
    pub fn as_root_with_rank_config(
        rpl_instance_id: u8,
        dodag_id: [u8; 16],
        version: u8,
        min_hop_rank_increase: u16,
        max_rank_increase: u16,
    ) -> Option<Self> {
        if min_hop_rank_increase == 0 || min_hop_rank_increase > INFINITE_RANK / 2 {
            return None;
        }
        Some(Self {
            rpl_instance_id,
            dodag_id,
            version,
            role: DodagRole::Root,
            rank: min_hop_rank_increase,
            preferred_parent: None,
            min_hop_rank_increase,
            max_rank_increase,
            parent_switch_threshold: PARENT_SWITCH_THRESHOLD,
            is_gateway_centric: false,
            parents: HashMap::new(),
            lowest_rank: min_hop_rank_increase,
        })
    }

    /// Apply rank values from a DODAG Configuration option.
    ///
    /// Returns `false` without changing state when MinHopRankIncrease is zero.
    #[must_use]
    pub fn set_rank_config(&mut self, min_hop_rank_increase: u16, max_rank_increase: u16) -> bool {
        if min_hop_rank_increase == 0 || min_hop_rank_increase > INFINITE_RANK / 2 {
            return false;
        }
        if (min_hop_rank_increase, max_rank_increase)
            == (self.min_hop_rank_increase, self.max_rank_increase)
        {
            return true;
        }
        self.min_hop_rank_increase = min_hop_rank_increase;
        self.max_rank_increase = max_rank_increase;
        if self.role == DodagRole::Root {
            self.rank = min_hop_rank_increase;
            self.lowest_rank = min_hop_rank_increase;
        } else if self.role == DodagRole::Joined {
            self.rank = INFINITE_RANK;
            self.lowest_rank = INFINITE_RANK;
            self.select_parent();
        }
        true
    }

    pub fn is_root(&self) -> bool {
        self.role == DodagRole::Root
    }

    /// Set the gateway-centric flag for the DODAG this node is part of.
    /// Returns true if the value changed.
    #[must_use]
    pub fn set_gateway_centric(&mut self, gc: bool) -> bool {
        if self.is_gateway_centric == gc {
            return false;
        }
        self.is_gateway_centric = gc;
        true
    }

    pub fn is_joined(&self) -> bool {
        matches!(self.role, DodagRole::Joined | DodagRole::Root)
    }

    pub fn demote(&mut self) {
        if self.role == DodagRole::Root {
            self.role = DodagRole::Unjoined;
            self.preferred_parent = None;
            self.rank = INFINITE_RANK;
            self.parents.clear();
        }
    }

    fn set_role(&mut self, next: DodagRole) -> Result<(), InvalidDodagTransition> {
        if self.role.can_transition_to(next) {
            self.role = next;
            Ok(())
        } else {
            Err(InvalidDodagTransition {
                from: self.role,
                to: next,
            })
        }
    }

    /// Process a received DIO from `neighbor_addr` with `link_etx` quality.
    pub fn process_dio(&mut self, dio: &Dio, neighbor_addr: [u8; 16], link_etx: f32) -> DioOutcome {
        self.process_dio_with_version_authorization(dio, neighbor_addr, link_etx, false)
    }

    /// Process a DIO after the caller has independently authenticated any
    /// root-owned DODAG version transition.
    pub fn process_dio_with_version_authorization(
        &mut self,
        dio: &Dio,
        neighbor_addr: [u8; 16],
        link_etx: f32,
        version_authorized: bool,
    ) -> DioOutcome {
        if !link_etx.is_finite() || link_etx < 1.0 {
            return DioOutcome::Rejected;
        }
        // SECURITY: Root nodes are DODAG authorities; they do not accept DIOs.
        if self.role == DodagRole::Root {
            return DioOutcome::Rejected;
        }
        if dio.rpl_instance_id != self.rpl_instance_id || dio.dodag_id != self.dodag_id {
            return DioOutcome::Rejected;
        }

        let newer_version = version_is_newer(dio.version, self.version);
        if !newer_version && version_is_older_or_incomparable(dio.version, self.version) {
            return DioOutcome::Rejected;
        }
        if newer_version && !version_authorized {
            return DioOutcome::Rejected;
        }

        let candidate = ParentCandidate {
            addr: neighbor_addr,
            rank: dio.rank,
            link_etx,
        };
        if newer_version {
            // Judge the candidate before adopting so an unusable advertiser
            // is rejected without becoming a parent, but do not gate the
            // version itself on it: RFC 6550 Section 8.2.2.4 makes a later
            // DODAGVersionNumber supersede the local one outright, and
            // waiting for an admissible advertiser strands this node on a
            // stale version while the rest of the network moves forward.
            let usable = candidate_admissible(
                &candidate,
                INFINITE_RANK,
                INFINITE_RANK,
                self.min_hop_rank_increase,
                self.max_rank_increase,
            );
            if self.adopt_version(dio.version).is_err() || !usable {
                return DioOutcome::Rejected;
            }
        }

        if dio.rank == INFINITE_RANK {
            // Poisoned route; drop this candidate.
            let removed = self.parents.remove(&neighbor_addr).is_some();
            self.select_parent();
            return if removed {
                DioOutcome::Removed
            } else {
                DioOutcome::Rejected
            };
        }

        // SECURITY: RFC 6550 Section 8.2.2.5 - reject parents with equal or
        // higher rank to prevent routing loops. Only accept neighbors with
        // strictly lower rank (unless we're unjoined with infinite rank).
        if self.rank != INFINITE_RANK && dio.rank >= self.rank {
            let removed = self.parents.remove(&neighbor_addr).is_some();
            self.select_parent();
            return if removed {
                DioOutcome::Removed
            } else {
                DioOutcome::Rejected
            };
        }

        let candidate = ParentCandidate {
            addr: neighbor_addr,
            rank: dio.rank,
            link_etx,
        };
        if !candidate_admissible(
            &candidate,
            self.rank,
            self.lowest_rank,
            self.min_hop_rank_increase,
            self.max_rank_increase,
        ) {
            let removed = self.parents.remove(&neighbor_addr).is_some();
            self.select_parent();
            return if removed {
                DioOutcome::Removed
            } else {
                DioOutcome::Rejected
            };
        }
        if self.parents.contains_key(&neighbor_addr) {
            // Update existing parent
            self.parents.insert(neighbor_addr, candidate);
        } else if self.parents.len() < MAX_PARENT_CANDIDATES {
            // Insert new parent only if under limit
            self.parents.insert(neighbor_addr, candidate);
        }
        // else: at capacity with a new parent -> reject silently
        self.select_parent();
        DioOutcome::Accepted
    }

    /// Admit a DIO only from the capability returned after link signature and
    /// replay validation, and only when its sole SCHC version option is v3.
    pub fn process_authenticated_dio(
        &mut self,
        link: &lichen_link::link_layer::LinkLayer,
        frame: lichen_link::link_layer::AuthenticatedFrame,
        link_etx: f32,
    ) -> DioOutcome {
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
            self.rpl_instance_id,
            &self.dodag_id,
            1,
            expected_role,
        ) else {
            self.remove_parents_with_iid(&signer_iid);
            return DioOutcome::Rejected;
        };
        if !peer.allows_dodag_join() {
            self.remove_parents_with_iid(&signer_iid);
            return DioOutcome::Rejected;
        }
        let Some(frame) = peer.authenticated_frame() else {
            self.remove_parents_with_iid(&signer_iid);
            return DioOutcome::Rejected;
        };
        if !link.accepts_authenticated_frame(frame) {
            self.remove_parents_with_iid(&signer_iid);
            return DioOutcome::Rejected;
        }
        if frame.payload().first().copied() != Some(lichen_core::constants::L2_DISPATCH_SCHC) {
            return DioOutcome::Rejected;
        }
        let mut ipv6 = [0u8; 512];
        let Ok(ipv6_len) = lichen_schc::decompress(&frame.payload()[1..], &mut ipv6) else {
            self.remove_parents_with_iid(&signer_iid);
            return DioOutcome::Rejected;
        };
        if ipv6_len < 68 {
            return DioOutcome::Rejected;
        }
        let Ok(dio) = Dio::from_bytes(&ipv6[44..ipv6_len]) else {
            self.remove_parents_with_iid(&signer_iid);
            return DioOutcome::Rejected;
        };
        if dio.version != self.version
            && !matches!(expected_role, lichen_schc::ExpectedDioRole::Root)
        {
            self.remove_parents_with_iid(&signer_iid);
            return DioOutcome::Rejected;
        }
        let neighbor_addr = ipv6[8..24]
            .try_into()
            .expect("validated IPv6 header has a complete source address");
        self.process_dio(&dio, neighbor_addr, link_etx)
    }

    pub fn remove_parents_with_iid(&mut self, signer_iid: &[u8; 8]) -> bool {
        let addresses: Vec<[u8; 16]> = self
            .parents
            .keys()
            .filter(|address| address[8..] == *signer_iid)
            .copied()
            .collect();
        let removed = !addresses.is_empty();
        self.remove_parents(&addresses);
        removed
    }

    /// Adopt a newer DODAG version: record it and reset all membership
    /// state, leaving the node unjoined pending re-selection.
    ///
    /// Returns an error without mutating anything when called on a root.
    /// Roots are the DODAG authorities: they mint new versions themselves
    /// and never adopt one from a received DIO (`process_dio()` rejects all
    /// DIOs aimed at a root before reaching this point). Unlike a
    /// `debug_assert`, this invariant holds in release builds too.
    fn adopt_version(&mut self, version: u8) -> Result<(), InvalidDodagTransition> {
        if self.role == DodagRole::Root {
            return Err(InvalidDodagTransition {
                from: self.role,
                to: DodagRole::Unjoined,
            });
        }
        self.version = version;
        self.parents.clear();
        self.preferred_parent = None;
        self.rank = INFINITE_RANK;
        self.lowest_rank = INFINITE_RANK;
        // Unjoined->Unjoined and Joined->Unjoined are both legal transitions,
        // so this cannot fail for a non-root node.
        self.set_role(DodagRole::Unjoined)
    }

    fn admissible(&self, candidate: &ParentCandidate) -> bool {
        candidate_admissible(
            candidate,
            self.rank,
            self.lowest_rank,
            self.min_hop_rank_increase,
            self.max_rank_increase,
        )
    }

    fn prune_inadmissible_parents(&mut self) {
        let to_remove: Vec<[u8; 16]> = self
            .parents
            .iter()
            .filter(|(_, candidate)| !self.admissible(candidate))
            .map(|(addr, _)| *addr)
            .collect();
        for addr in to_remove {
            self.parents.remove(&addr);
        }
    }

    /// MRHOF parent selection with hysteresis.
    pub fn select_parent(&mut self) {
        // A root never selects parents: process_dio() rejects every DIO
        // aimed at a root, so a root's candidate set stays empty. Checking
        // here keeps that invariant runtime-enforced in release builds too,
        // guarantees the set_role(DodagRole::Joined) below can never fire
        // for a root, and prevents any partial mutation of root state.
        if self.role == DodagRole::Root {
            return;
        }
        self.prune_inadmissible_parents();
        let mhri = self.min_hop_rank_increase;
        let threshold = self.parent_switch_threshold;

        let best = self
            .parents
            .values()
            .filter(|c| self.admissible(c))
            .min_by_key(|c| c.path_cost(mhri));

        let Some(best) = best else {
            // No admissible candidate remains: leave the DODAG.
            // Unjoined->Unjoined and Joined->Unjoined are legal transitions,
            // so this cannot fail; membership state is only reset once the
            // transition succeeds so a failure cannot strand a half-demoted
            // node (checked at runtime in all build profiles).
            if self.set_role(DodagRole::Unjoined).is_ok() {
                self.preferred_parent = None;
                self.rank = INFINITE_RANK;
            }
            return;
        };

        let best_addr = best.addr;
        let best_cost = best.path_cost(mhri);

        // Hysteresis: only switch if improvement exceeds threshold.
        let (chosen_addr, chosen_cost) = match self.preferred_parent {
            Some(cur_addr) if cur_addr != best_addr => {
                // Check if current parent still exists and improvement is below threshold.
                self.parents
                    .get(&cur_addr)
                    .filter(|cur| self.admissible(cur))
                    .map(|cur| cur.path_cost(mhri))
                    .filter(|&cur_cost| best_cost > cur_cost.saturating_sub(threshold))
                    .map_or((best_addr, best_cost), |cur_cost| (cur_addr, cur_cost))
            }
            _ => (best_addr, best_cost),
        };

        let previous_parent = self.preferred_parent;
        let previous_rank = self.rank;
        self.preferred_parent = Some(chosen_addr);
        self.rank = chosen_cost;
        // Unjoined->Joined and Joined->Joined are legal for a non-root node,
        // so this cannot fail; on an unexpected failure roll the mutation
        // back instead of silently keeping corrupted state (release builds
        // included).
        if self.set_role(DodagRole::Joined).is_err() {
            self.preferred_parent = previous_parent;
            self.rank = previous_rank;
            return;
        }
        if chosen_cost < self.lowest_rank {
            self.lowest_rank = chosen_cost;
        }
        // Re-prune: choosing a better parent may have lowered lowest_rank
        // above, which tightens the MaxRankIncrease bound; parents still
        // admissible under the previous lowest_rank may now exceed
        // cost <= lowest_rank + max_rank_increase and must be dropped.
        self.prune_inadmissible_parents();
    }

    /// Drop a neighbour (e.g. link failure) and re-select.
    pub fn remove_parent(&mut self, addr: &[u8; 16]) {
        self.remove_parents(core::slice::from_ref(addr));
    }

    /// Drop multiple neighbours and re-select once after the batch.
    pub fn remove_parents(&mut self, addrs: &[[u8; 16]]) {
        for addr in addrs {
            self.parents.remove(addr);
        }
        self.select_parent();
    }

    /// Check if an address is a current parent candidate.
    pub fn has_parent(&self, addr: &[u8; 16]) -> bool {
        self.parents.contains_key(addr)
    }

    /// Number of parent candidates.
    pub fn parent_count(&self) -> usize {
        self.parents.len()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// Link-local address with given IID.
    fn ll(iid: u8) -> [u8; 16] {
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid]
    }

    fn dodag_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = 0xfd;
        id[15] = 1;
        id
    }

    fn dio(rank: u16) -> Dio {
        Dio {
            rpl_instance_id: 0,
            version: 0,
            rank,
            grounded: true,
            mode_of_operation: 1,
            preference: 0,
            dtsn: 0,
            flags: 0,
            dodag_id: dodag_id(),
        }
    }

    #[test]
    fn dodag_role_transition_table_allows_root_demotion_rejects_root_join() {
        assert!(DodagRole::Unjoined.can_transition_to(DodagRole::Joined));
        assert!(DodagRole::Joined.can_transition_to(DodagRole::Unjoined));
        assert!(DodagRole::Root.can_transition_to(DodagRole::Root));
        assert!(DodagRole::Root.can_transition_to(DodagRole::Unjoined));
        assert!(DodagRole::Joined.can_transition_to(DodagRole::Root));
        assert!(!DodagRole::Root.can_transition_to(DodagRole::Joined));
    }

    #[test]
    fn root_starts_joined_at_root_rank() {
        let root = DodagState::as_root(0, dodag_id(), 0);
        assert!(root.is_root());
        assert!(root.is_joined());
        assert_eq!(root.rank, ROOT_RANK);
    }

    #[test]
    fn configured_min_hop_rank_increase_is_root_rank() {
        let mut root = DodagState::as_root_with_rank_config(0, dodag_id(), 0, 128, 1024)
            .expect("non-zero MinHopRankIncrease");
        assert_eq!(root.rank, 128);
        assert_eq!(root.min_hop_rank_increase, 128);
        assert_eq!(root.max_rank_increase, 1024);

        assert!(root.set_rank_config(64, 512));
        assert_eq!(root.rank, 64);
        assert_eq!(root.lowest_rank, 64);
        assert!(!root.set_rank_config(0, 512));
        assert_eq!(root.rank, 64);
    }

    #[test]
    fn root_rejects_rank_increment_without_finite_one_hop_rank() {
        for invalid in [32_768, INFINITE_RANK] {
            assert!(DodagState::as_root_with_rank_config(0, dodag_id(), 0, invalid, 0).is_none());
        }

        let mut root = DodagState::as_root(0, dodag_id(), 0);
        assert!(!root.set_rank_config(32_768, 0));
        assert_eq!(root.rank, ROOT_RANK);
        assert_eq!(root.min_hop_rank_increase, ROOT_RANK);
    }

    #[test]
    fn invalid_etx_does_not_remove_existing_parent() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        assert_eq!(
            node.process_dio(&dio(ROOT_RANK), ll(1), 1.0),
            DioOutcome::Accepted
        );

        for invalid in [f32::NAN, f32::INFINITY, 0.0, 0.9] {
            assert_eq!(
                node.process_dio(&dio(ROOT_RANK), ll(1), invalid),
                DioOutcome::Rejected
            );
            assert_eq!(node.preferred_parent, Some(ll(1)));
            assert_eq!(node.parent_count(), 1);
        }
    }

    #[test]
    fn node_joins_on_first_dio() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        assert!(!node.is_joined());

        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);

        assert!(node.is_joined());
        assert_eq!(node.preferred_parent, Some(ll(1)));
        assert_eq!(node.rank, ROOT_RANK + MIN_HOP_RANK_INCREASE); // 256+256=512
    }

    #[test]
    fn saturated_path_cost_cannot_join() {
        let mut node = DodagState::new(0, dodag_id(), 0);

        // The finite parent rank and link ETX produce a saturated path cost.
        node.process_dio(&dio(1), ll(1), 256.0);

        assert!(!node.is_joined());
        assert_eq!(node.rank, INFINITE_RANK);
    }

    #[test]
    fn same_version_foreign_dio_does_not_adopt_dodag() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        let mut foreign_id = dodag_id();
        foreign_id[15] = 2;
        let foreign_dio = Dio {
            dodag_id: foreign_id,
            ..dio(ROOT_RANK)
        };

        node.process_dio(&foreign_dio, ll(1), 1.0);

        assert_eq!(node.dodag_id, dodag_id());
        assert_eq!(node.version, 0);
        assert!(!node.is_joined());
        assert_eq!(node.parent_count(), 0);
    }

    #[test]
    fn two_parents_selects_best() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        // parent 1: root_rank + 1 hop = 512
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
        // parent 2: rank 800 + 1 hop = 1056 — worse
        node.process_dio(&dio(800), ll(2), 1.0);

        assert_eq!(node.preferred_parent, Some(ll(1)));
        assert_eq!(node.rank, 512);
    }

    #[test]
    fn hysteresis_prevents_minor_switch() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        // Establish parent 1 at rank 512
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
        assert_eq!(node.preferred_parent, Some(ll(1)));

        // Candidate 2 with path cost 512-100=412, not enough to overcome
        // hysteresis (need >192 improvement over 512 → need cost < 320).
        // cost = 412 > 512-192=320, so no switch.
        node.process_dio(&dio(156), ll(2), 1.0); // 156+256=412
        assert_eq!(node.preferred_parent, Some(ll(1)));
    }

    #[test]
    fn previously_accepted_parent_becoming_inadmissible_is_removed() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0); // cost 512

        // Establish a valid but worse backup parent through the public API.
        node.process_dio(&dio(450), ll(2), 1.0); // cost 706
        assert_eq!(node.parent_count(), 2);

        // The preferred parent now advertises a rank equal to this node's
        // rank, making the cached candidate inadmissible.
        node.process_dio(&dio(512), ll(1), 1.0);

        assert_eq!(node.preferred_parent, Some(ll(2)));
        assert_eq!(node.rank, 706);
        assert_eq!(node.parent_count(), 1);
    }

    #[test]
    fn significant_improvement_triggers_switch() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        // Parent 1 at rank 1024
        node.process_dio(&dio(768), ll(1), 1.0); // 768+256=1024
        assert_eq!(node.preferred_parent, Some(ll(1)));

        // Candidate 2 with path cost 512 — improvement of 512 > threshold 192.
        node.process_dio(&dio(ROOT_RANK), ll(2), 1.0); // 256+256=512
        assert_eq!(node.preferred_parent, Some(ll(2)));
        assert_eq!(node.rank, 512);
    }

    #[test]
    fn parent_failure_triggers_re_selection() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0); // cost 512

        // Backup parent must have rank < node's rank (512) to be admissible per RFC 6550.
        // rank 450 < 512, cost = 450 + 256 = 706
        node.process_dio(&dio(450), ll(2), 1.0); // cost 706 — worse, but valid backup

        assert_eq!(node.preferred_parent, Some(ll(1)));

        // Remove preferred parent → falls back to ll(2)
        node.remove_parent(&ll(1));
        assert_eq!(node.preferred_parent, Some(ll(2)));
        assert_eq!(node.rank, 706);
    }

    #[test]
    fn all_parents_fail_returns_unjoined() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
        node.remove_parent(&ll(1));
        assert!(!node.is_joined());
        assert_eq!(node.rank, INFINITE_RANK);
    }

    #[test]
    fn root_ignores_dio() {
        let mut root = DodagState::as_root(0, dodag_id(), 0);
        // Same-version DIO rejected
        let outcome = root.process_dio(&dio(ROOT_RANK), ll(99), 1.0);
        assert_eq!(outcome, DioOutcome::Rejected);
        assert_eq!(root.rank, ROOT_RANK); // unchanged
        assert_eq!(root.parent_count(), 0);
    }

    #[test]
    fn root_ignores_newer_version_dio() {
        // Root must reject DIOs even with newer versions - roots are DODAG authorities
        let mut root = DodagState::as_root(0, dodag_id(), 0);
        let newer_dio = Dio {
            version: 1, // newer than root's version 0
            ..dio(ROOT_RANK)
        };
        let outcome = root.process_dio(&newer_dio, ll(99), 1.0);
        assert_eq!(outcome, DioOutcome::Rejected);
        assert!(root.is_root()); // never adopts a version
        assert_eq!(root.version, 0); // version unchanged
        assert_eq!(root.rank, ROOT_RANK);
        assert_eq!(root.parent_count(), 0);
    }

    #[test]
    fn poisoned_dio_removes_parent() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
        assert!(node.is_joined());

        // Sender poisons with infinite rank
        node.process_dio(&dio(INFINITE_RANK), ll(1), 1.0);
        assert!(!node.is_joined());
    }

    #[test]
    fn newer_version_triggers_rejoin() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
        assert_eq!(node.version, 0);

        // Newer version DIO
        let new_dio = Dio {
            version: 1,
            ..dio(ROOT_RANK)
        };
        assert_eq!(node.process_dio(&new_dio, ll(1), 1.0), DioOutcome::Rejected);
        assert_eq!(node.version, 0);
        node.process_dio_with_version_authorization(&new_dio, ll(1), 1.0, true);
        assert_eq!(node.version, 1);
        assert_eq!(node.rank, 512);
    }

    #[test]
    fn inadmissible_newer_version_still_adopts_and_resets_membership() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);

        for (version, rank, link_etx) in [(1u8, ROOT_RANK - 1, 1.0), (2u8, ROOT_RANK, f32::MAX)] {
            let invalid = Dio {
                version,
                rank,
                ..dio(ROOT_RANK)
            };
            node.process_dio_with_version_authorization(&invalid, ll(2), link_etx, true);

            // RFC 6550 Section 8.2.2.4: a later DODAGVersionNumber
            // supersedes the local one even when this particular advertiser
            // cannot become a parent; membership resets and the node waits
            // for an admissible advertiser of the new version.
            assert_eq!(node.version, version);
            assert!(!node.is_joined());
            assert_eq!(node.preferred_parent, None);
            assert_eq!(node.rank, INFINITE_RANK);
            assert_eq!(node.parent_count(), 0);
        }
    }

    #[test]
    fn admissible_newer_version_dio_restores_connectivity_after_bad_ones() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
        assert!(node.is_joined());

        // A saturated-cost advertiser of version 1 cannot become a parent
        // but still moves the node to version 1.
        let bad = Dio {
            version: 1,
            ..dio(ROOT_RANK)
        };
        assert_eq!(
            node.process_dio_with_version_authorization(&bad, ll(2), f32::MAX, true),
            DioOutcome::Rejected
        );
        assert_eq!(node.version, 1);
        assert!(!node.is_joined());

        // An admissible advertiser of the same new version rejoins the node,
        // so a network-wide version bump cannot strand it on the old one.
        let good = Dio {
            version: 1,
            ..dio(ROOT_RANK)
        };
        assert_eq!(node.process_dio(&good, ll(3), 1.0), DioOutcome::Accepted);
        assert!(node.is_joined());
        assert_eq!(node.preferred_parent, Some(ll(3)));
        assert_eq!(node.rank, ROOT_RANK + MIN_HOP_RANK_INCREASE);
    }

    #[test]
    fn configured_rank_is_used_when_adopting_a_version() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        assert!(node.set_rank_config(128, 1024));
        node.process_dio(&dio(128), ll(1), 1.0);
        assert_eq!(node.rank, 256);

        let newer = Dio {
            version: 1,
            ..dio(128)
        };
        node.process_dio_with_version_authorization(&newer, ll(2), 1.0, true);
        assert_eq!(node.version, 1);
        assert_eq!(node.rank, 256);
    }

    #[test]
    fn repeated_unchanged_rank_config_preserves_lowest_rank() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        assert!(node.set_rank_config(MIN_HOP_RANK_INCREASE, 300));
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
        node.process_dio(&dio(450), ll(2), 1.0);
        node.remove_parent(&ll(1));
        assert_eq!(node.rank, 706);
        assert_eq!(node.lowest_rank, 512);

        assert!(node.set_rank_config(MIN_HOP_RANK_INCREASE, 300));

        assert_eq!(node.rank, 706);
        assert_eq!(node.lowest_rank, 512);
        assert_eq!(node.preferred_parent, Some(ll(2)));
    }

    #[test]
    fn unchanged_rank_config_preserves_max_rank_increase_floor() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        assert!(node.set_rank_config(MIN_HOP_RANK_INCREASE, 300));
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
        node.process_dio(&dio(450), ll(2), 1.0);
        node.remove_parent(&ll(1));

        assert!(node.set_rank_config(MIN_HOP_RANK_INCREASE, 300));
        node.process_dio(&dio(450), ll(3), 2.0);

        assert_eq!(node.parent_count(), 1);
        assert_eq!(node.preferred_parent, Some(ll(2)));
        assert_eq!(node.rank, 706);
    }

    #[test]
    fn version_lollipop_wraparound_255_to_0() {
        // Node at version 255 (circular region) should accept version 0 (linear region)
        let mut node = DodagState::new(0, dodag_id(), 255);
        let dio_v255 = Dio {
            version: 255,
            ..dio(ROOT_RANK)
        };
        node.process_dio(&dio_v255, ll(1), 1.0);
        assert!(node.is_joined());
        assert_eq!(node.version, 255);

        // DIO with version 0 (restart in linear region) should be accepted as newer
        let restart_dio = Dio {
            version: 0,
            ..dio(ROOT_RANK)
        };
        node.process_dio_with_version_authorization(&restart_dio, ll(2), 1.0, true);
        assert_eq!(
            node.version, 0,
            "lollipop: version 0 should be accepted as newer than 255"
        );
    }

    #[test]
    fn version_lollipop_semantics() {
        use core::cmp::Ordering::{Equal, Greater, Less};

        // RFC 6550 Section 7.2 applies the absolute-magnitude window before
        // RFC 1982 ordering. Distant same-region pairs are incomparable.
        let cases = [
            (0, 0, Some(Equal)),
            (128, 128, Some(Equal)),
            (16, 0, Some(Greater)),
            (17, 0, None),
            (0, 16, Some(Less)),
            (0, 17, None),
            (0, 127, None),
            (127, 0, None),
            (120, 5, None),
            (5, 100, None),
            (100, 5, None),
            (255, 239, Some(Greater)),
            (255, 238, None),
            (5, 250, Some(Greater)),
            (5, 240, Some(Less)),
            (0, 240, Some(Greater)),
            (0, 239, Some(Less)),
        ];
        for (a, b, expected) in cases {
            assert_eq!(super::lollipop_cmp(a, b), expected, "{a} vs {b}");
        }
    }

    #[test]
    fn dodag_version_preserves_explicit_adjacent_restart_policy() {
        assert_eq!(super::lollipop_cmp(0, 127), None);
        assert!(version_is_newer(0, 127));
        assert!(!version_is_newer(127, 0));
        assert_eq!(super::lollipop_cmp(5, 120), None);
        assert!(!version_is_newer(5, 120));
        assert!(!version_is_newer(120, 5));
    }

    #[test]
    fn lollipop_comparison_exhaustively_matches_rfc_6550_7_2() {
        use core::cmp::Ordering::{Equal, Greater, Less};

        fn oracle(a: u8, b: u8) -> Option<core::cmp::Ordering> {
            if a == b {
                return Some(Equal);
            }
            if (a < 128) == (b < 128) {
                if a.abs_diff(b) > 16 {
                    return None;
                }
                return Some(if a > b { Greater } else { Less });
            }
            if a < 128 {
                return Some(if 256 - u16::from(b) + u16::from(a) <= 16 {
                    Greater
                } else {
                    Less
                });
            }
            Some(if 256 - u16::from(a) + u16::from(b) <= 16 {
                Less
            } else {
                Greater
            })
        }

        for a in u8::MIN..=u8::MAX {
            for b in u8::MIN..=u8::MAX {
                let actual = super::lollipop_cmp(a, b);
                assert_eq!(actual, oracle(a, b), "{a} vs {b}");
                assert_eq!(actual, super::lollipop_cmp(b, a).map(Ordering::reverse));
            }
        }
    }

    #[test]
    fn foreign_and_incomparable_dios_do_not_change_state() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);

        let foreign_instance = Dio {
            rpl_instance_id: 1,
            version: 1,
            ..dio(ROOT_RANK)
        };
        node.process_dio(&foreign_instance, ll(2), 1.0);
        let mut foreign_dodag = dio(ROOT_RANK);
        foreign_dodag.version = 1;
        foreign_dodag.dodag_id[15] = 2;
        node.process_dio(&foreign_dodag, ll(3), 1.0);
        let incomparable = Dio {
            version: 17,
            ..dio(ROOT_RANK)
        };
        node.process_dio(&incomparable, ll(4), 1.0);

        assert_eq!(node.version, 0);
        assert_eq!(node.preferred_parent, Some(ll(1)));
        assert_eq!(node.rank, 512);
        assert_eq!(node.parent_count(), 1);
    }

    #[test]
    fn saturated_and_max_rank_parents_are_removed() {
        let mut saturated = DodagState::new(0, dodag_id(), 0);
        saturated.process_dio(&dio(ROOT_RANK), ll(1), f32::MAX);
        assert!(!saturated.is_joined());
        assert_eq!(saturated.parent_count(), 0);

        let mut bounded = DodagState::new(0, dodag_id(), 0);
        bounded.max_rank_increase = 300;
        bounded.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
        bounded.process_dio(&dio(450), ll(2), 2.0);
        assert_eq!(bounded.parent_count(), 1);
        assert_eq!(bounded.preferred_parent, Some(ll(1)));
    }

    #[test]
    fn admissibility_uses_dag_rank_boundaries() {
        let cost_in_parent_dag_rank = ParentCandidate {
            addr: ll(1),
            rank: 256,
            link_etx: 0.5,
        };
        assert!(!candidate_admissible(
            &cost_in_parent_dag_rank,
            INFINITE_RANK,
            INFINITE_RANK,
            256,
            2048
        ));

        let same_dag_rank = ParentCandidate {
            addr: ll(2),
            rank: 256,
            link_etx: 1.0,
        };
        assert!(!candidate_admissible(&same_dag_rank, 511, 511, 256, 2048));

        let lower_dag_rank = ParentCandidate {
            addr: ll(3),
            rank: 256,
            link_etx: 1.0,
        };
        assert!(candidate_admissible(&lower_dag_rank, 512, 512, 256, 2048));
    }

    #[test]
    fn finite_rank_below_root_is_inadmissible() {
        let candidate = ParentCandidate {
            addr: ll(1),
            rank: 255,
            link_etx: 1.0,
        };
        assert!(!candidate_admissible(&candidate, 65535, 65535, 256, 2048));
    }

    #[test]
    fn fresh_node_rejects_below_root_dio_without_transient_membership() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        assert_eq!(
            node.process_dio(&dio(100), ll(1), 1.0),
            DioOutcome::Rejected
        );
        assert_eq!(node.role, DodagRole::Unjoined);
        assert_eq!(node.rank, INFINITE_RANK);
        assert_eq!(node.parent_count(), 0);
        assert!(node.preferred_parent.is_none());
    }

    #[test]
    fn admissibility_derives_root_rank_from_min_hop_rank_increase() {
        let below_root = ParentCandidate {
            addr: ll(1),
            rank: 127,
            link_etx: 1.0,
        };
        assert!(!candidate_admissible(
            &below_root,
            INFINITE_RANK,
            INFINITE_RANK,
            128,
            2048
        ));

        let root = ParentCandidate {
            addr: ll(2),
            rank: 128,
            link_etx: 1.0,
        };
        assert!(candidate_admissible(
            &root,
            INFINITE_RANK,
            INFINITE_RANK,
            128,
            2048
        ));
    }

    #[test]
    fn zero_max_rank_increase_disables_the_bound() {
        let candidate = ParentCandidate {
            addr: ll(1),
            rank: 512,
            link_etx: 2.0,
        };
        assert!(candidate_admissible(&candidate, 65535, 512, 256, 0));
    }

    #[test]
    fn valid_downward_failover_remains_available() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
        node.process_dio(&dio(450), ll(2), 1.0);

        assert_eq!(node.parent_count(), 2);
        node.remove_parent(&ll(1));
        assert_eq!(node.preferred_parent, Some(ll(2)));
        assert_eq!(node.rank, 706);
    }

    #[test]
    fn parent_candidates_fail_closed_at_neighbor_limit() {
        assert_eq!(MAX_PARENT_CANDIDATES, 16);
        let mut node = DodagState::new(0, dodag_id(), 0);
        for iid in 1..=MAX_PARENT_CANDIDATES as u8 {
            node.process_dio(&dio(ROOT_RANK), ll(iid), 1.0);
        }
        assert_eq!(node.parent_count(), MAX_PARENT_CANDIDATES);

        node.process_dio(&dio(ROOT_RANK), ll(MAX_PARENT_CANDIDATES as u8 + 1), 1.0);
        assert_eq!(node.parent_count(), MAX_PARENT_CANDIDATES);

        node.process_dio(&dio(ROOT_RANK), ll(1), 1.25);
        assert_eq!(node.parent_count(), MAX_PARENT_CANDIDATES);
        assert_eq!(node.parents[&ll(1)].link_etx, 1.25);
    }

    #[test]
    fn lollipop_sequence_window_boundaries_are_inclusive_per_rfc_6550_7_2() {
        use core::cmp::Ordering::{Greater, Less};

        // Same-region rule 3.2: |diff| <= SEQUENCE_WINDOW (16) is comparable
        // via RFC 1982 ordering; > 16 means desynchronization (None).
        assert_eq!(super::lollipop_cmp(16, 0), Some(Greater)); // diff exactly 16
        assert_eq!(super::lollipop_cmp(15, 0), Some(Greater)); // just below
        assert_eq!(super::lollipop_cmp(17, 0), None); // just above
        assert_eq!(super::lollipop_cmp(255, 239), Some(Greater)); // diff exactly 16
        assert_eq!(super::lollipop_cmp(255, 240), Some(Greater)); // just below
        assert_eq!(super::lollipop_cmp(255, 238), None); // just above

        // Cross-region rule 3.1: wrap distance (256 + B - A) <= SEQUENCE_WINDOW
        // makes the wrapped counter newer; a larger distance makes the
        // unwrapped counter newer. Never incomparable.
        assert_eq!(super::lollipop_cmp(0, 240), Some(Greater)); // wrap exactly 16
        assert_eq!(super::lollipop_cmp(0, 241), Some(Greater)); // wrap 15
        assert_eq!(super::lollipop_cmp(0, 239), Some(Less)); // wrap 17
        assert_eq!(super::lollipop_cmp(250, 10), Some(Less)); // wrap exactly 16
        assert_eq!(super::lollipop_cmp(250, 9), Some(Less)); // wrap 15
        assert_eq!(super::lollipop_cmp(250, 11), Some(Greater)); // wrap 17
    }

    #[test]
    fn dagrank_truncation_boundary_is_floor_semantics() {
        // RFC 6550 Section 3.5.1: DAGRank(R) = floor(R / MinHopRankIncrease).
        // Candidate rank 256 with link cost 255 gives path cost 511:
        // DAGRank(cost) == DAGRank(rank) == 1, so it is refused even though
        // the raw ranks differ by 255.
        let truncated = ParentCandidate {
            addr: ll(1),
            rank: 256,
            link_etx: 255.0 / 256.0,
        };
        assert_eq!(truncated.path_cost(256), 511);
        assert!(!candidate_admissible(
            &truncated,
            INFINITE_RANK,
            INFINITE_RANK,
            256,
            2048
        ));

        // One step higher, path cost 512 -> DAGRank 2 > 1 -> admissible.
        let exact = ParentCandidate {
            addr: ll(1),
            rank: 256,
            link_etx: 1.0,
        };
        assert_eq!(exact.path_cost(256), 512);
        assert!(candidate_admissible(
            &exact,
            INFINITE_RANK,
            INFINITE_RANK,
            256,
            2048
        ));
    }

    #[test]
    fn selecting_better_parent_reprunes_against_new_max_rank_bound() {
        let mut node = DodagState::new(0, dodag_id(), 0);
        // lowest_rank starts at 1024; backup parent B at cost 1792 fits the
        // initial bound (1024 + MaxRankIncrease 1024).
        node.process_dio(&dio(768), ll(1), 1.0); // A: cost 1024
        node.process_dio(&dio(768), ll(2), 4.0); // B: cost 1792
        assert_eq!(node.parent_count(), 2);

        // Switching to C drops rank to 512 and lowest_rank with it,
        // tightening the bound to 512 + 1024 = 1536. The re-prune pass also
        // removes A because its advertised DAGRank is no longer below ours.
        node.process_dio(&dio(256), ll(3), 1.0); // C: cost 512

        assert_eq!(node.preferred_parent, Some(ll(3)));
        assert_eq!(node.rank, 512);
        assert!(!node.has_parent(&ll(2)));
        assert!(!node.has_parent(&ll(1)));
        assert_eq!(node.parent_count(), 1); // Only C remains loop-safe.
    }

    #[test]
    fn select_parent_and_remove_parents_leave_root_state_untouched() {
        let mut root = DodagState::as_root(0, dodag_id(), 0);

        root.select_parent();
        root.remove_parent(&ll(1));
        root.remove_parents(&[ll(1), ll(2)]);

        assert!(root.is_root());
        assert_eq!(root.rank, ROOT_RANK);
        assert_eq!(root.preferred_parent, None);
        assert_eq!(root.parent_count(), 0);
    }
}
