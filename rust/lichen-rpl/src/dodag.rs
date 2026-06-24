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

use crate::messages::Dio;

pub const INFINITE_RANK: u16 = 0xFFFF;
pub const ROOT_RANK: u16 = 256; // MinHopRankIncrease
pub const MIN_HOP_RANK_INCREASE: u16 = 256;
pub const MAX_RANK_INCREASE: u16 = 2048;
pub const PARENT_SWITCH_THRESHOLD: u16 = 192;

/// Node's role in the DODAG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DodagRole {
    Unjoined,
    Joined,
    Root,
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

impl ParentCandidate {
    /// Rank this node would achieve via this parent (MRHOF, spec B.1).
    pub fn path_cost(&self, mhri: u16) -> u16 {
        self.rank
            .saturating_add((self.link_etx * mhri as f32).round() as u16)
    }
}

/// RPL DODAG membership state for a single node.
#[cfg(feature = "std")]
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
            parents: HashMap::new(),
            lowest_rank: INFINITE_RANK,
        }
    }

    /// Create a DODAG root with rank = ROOT_RANK.
    pub fn as_root(rpl_instance_id: u8, dodag_id: [u8; 16], version: u8) -> Self {
        Self {
            rpl_instance_id,
            dodag_id,
            version,
            role: DodagRole::Root,
            rank: ROOT_RANK,
            preferred_parent: None,
            min_hop_rank_increase: MIN_HOP_RANK_INCREASE,
            max_rank_increase: MAX_RANK_INCREASE,
            parent_switch_threshold: PARENT_SWITCH_THRESHOLD,
            parents: HashMap::new(),
            lowest_rank: ROOT_RANK,
        }
    }

    pub fn is_root(&self) -> bool {
        self.role == DodagRole::Root
    }

    pub fn is_joined(&self) -> bool {
        matches!(self.role, DodagRole::Joined | DodagRole::Root)
    }

    /// Process a received DIO from `neighbor_addr` with `link_etx` quality.
    pub fn process_dio(&mut self, dio: &Dio, neighbor_addr: [u8; 16], link_etx: f32) {
        if self.role == DodagRole::Root {
            return;
        }
        // Only accept DIOs from the same DODAG once joined.
        if self.is_joined() && dio.dodag_id != self.dodag_id {
            return;
        }

        if dio.version > self.version || !self.is_joined() {
            // Newer (or first) version — rejoin.
            self.adopt_version(dio);
        } else if dio.version < self.version {
            return; // stale
        }

        if dio.rank == INFINITE_RANK {
            // Poisoned route; drop this candidate.
            self.parents.remove(&neighbor_addr);
            self.select_parent();
            return;
        }

        self.parents.insert(
            neighbor_addr,
            ParentCandidate {
                addr: neighbor_addr,
                rank: dio.rank,
                link_etx,
            },
        );
        self.select_parent();
    }

    fn adopt_version(&mut self, dio: &Dio) {
        self.dodag_id = dio.dodag_id;
        self.rpl_instance_id = dio.rpl_instance_id;
        self.version = dio.version;
        self.parents.clear();
        self.preferred_parent = None;
        self.rank = INFINITE_RANK;
        self.lowest_rank = INFINITE_RANK;
        self.role = DodagRole::Unjoined;
    }

    fn admissible(&self, candidate: &ParentCandidate) -> bool {
        let cost = candidate.path_cost(self.min_hop_rank_increase);
        if self.lowest_rank == INFINITE_RANK {
            return true;
        }
        cost <= self.lowest_rank.saturating_add(self.max_rank_increase)
    }

    /// MRHOF parent selection with hysteresis.
    pub fn select_parent(&mut self) {
        let mhri = self.min_hop_rank_increase;
        let threshold = self.parent_switch_threshold;

        let best = self
            .parents
            .values()
            .filter(|c| self.admissible(c))
            .min_by_key(|c| c.path_cost(mhri));

        let Some(best) = best else {
            if self.role != DodagRole::Root {
                self.role = DodagRole::Unjoined;
                self.preferred_parent = None;
                self.rank = INFINITE_RANK;
            }
            return;
        };

        let best_addr = best.addr;
        let best_cost = best.path_cost(mhri);

        // Hysteresis: only switch if improvement exceeds threshold.
        let (chosen_addr, chosen_cost) = if let Some(cur_addr) = self.preferred_parent {
            if cur_addr != best_addr {
                if let Some(cur) = self.parents.get(&cur_addr) {
                    let cur_cost = cur.path_cost(mhri);
                    if best_cost > cur_cost.saturating_sub(threshold) {
                        // Not a big enough improvement — stick with current.
                        (cur_addr, cur_cost)
                    } else {
                        (best_addr, best_cost)
                    }
                } else {
                    (best_addr, best_cost)
                }
            } else {
                (best_addr, best_cost)
            }
        } else {
            (best_addr, best_cost)
        };

        self.preferred_parent = Some(chosen_addr);
        self.rank = chosen_cost;
        self.role = DodagRole::Joined;
        if chosen_cost < self.lowest_rank {
            self.lowest_rank = chosen_cost;
        }
    }

    /// Drop a neighbour (e.g. link failure) and re-select.
    pub fn remove_parent(&mut self, addr: &[u8; 16]) {
        self.parents.remove(addr);
        self.select_parent();
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
        [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid,
        ]
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
    fn root_starts_joined_at_root_rank() {
        let root = DodagState::as_root(0, dodag_id(), 0);
        assert!(root.is_root());
        assert!(root.is_joined());
        assert_eq!(root.rank, ROOT_RANK);
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
        node.process_dio(&dio(512), ll(2), 1.0); // cost 768 — worse

        assert_eq!(node.preferred_parent, Some(ll(1)));

        // Remove preferred parent → falls back to ll(2)
        node.remove_parent(&ll(1));
        assert_eq!(node.preferred_parent, Some(ll(2)));
        assert_eq!(node.rank, 768);
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
        root.process_dio(&dio(ROOT_RANK), ll(99), 1.0);
        assert_eq!(root.rank, ROOT_RANK); // unchanged
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
        node.process_dio(&new_dio, ll(1), 1.0);
        assert_eq!(node.version, 1);
        assert_eq!(node.rank, 512);
    }
}
