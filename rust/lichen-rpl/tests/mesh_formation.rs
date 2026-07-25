//! 5-node RPL mesh formation integration test.
//!
//! Exit criteria for Phase 4 (d5c):
//!   - 5-node mesh forms DODAG
//!   - Upward routing: every node knows its preferred parent
//!   - Downward routing: root assembles source routes from DAOs
//!   - Parent switching on link failure

use lichen_rpl::{
    dodag::{DodagState, MIN_HOP_RANK_INCREASE, ROOT_RANK},
    message::Dio,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

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

fn dio_with_instance(rank: u16, rpl_instance_id: u8) -> Dio {
    Dio {
        rpl_instance_id,
        ..dio(rank)
    }
}

// ── Topology ──────────────────────────────────────────────────────────────────
//
//   root(1) [rank 256]
//   ├── n2(2) [rank 512]   ← hears root
//   │   ├── n3(3) [rank 768]  ← hears n2
//   │   └── n5(5) [rank 768]  ← hears n2
//   └── n4(4)              ← hears both n3 (cost 1024) and n2 (cost 768)
//                            → prefers n2; on n2 failure falls back to n3

// ── Test 1: DODAG formation ───────────────────────────────────────────────────

#[test]
fn five_node_dodag_forms() {
    let root = DodagState::as_root(0, dodag_id(), 0);
    assert!(root.is_root());
    assert_eq!(root.rank, ROOT_RANK);

    let mut n2 = DodagState::new(0, dodag_id(), 0);
    n2.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
    assert!(n2.is_joined());
    assert_eq!(n2.preferred_parent, Some(ll(1)));
    assert_eq!(n2.rank, ROOT_RANK + MIN_HOP_RANK_INCREASE); // 512

    let mut n3 = DodagState::new(0, dodag_id(), 0);
    n3.process_dio(&dio(512), ll(2), 1.0);
    assert!(n3.is_joined());
    assert_eq!(n3.rank, 768);

    let mut n4 = DodagState::new(0, dodag_id(), 0);
    n4.process_dio(&dio(768), ll(3), 1.0); // cost 1024 via n3
    n4.process_dio(&dio(512), ll(2), 1.0); // cost 768 via n2, improvement 256 > threshold 192
    assert!(n4.is_joined());
    assert_eq!(n4.preferred_parent, Some(ll(2)));
    assert_eq!(n4.rank, 768);

    let mut n5 = DodagState::new(0, dodag_id(), 0);
    n5.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
    assert!(n5.is_joined());
    assert_eq!(n5.rank, 512);
}

// ── Test 2: Upward routing — every node has a preferred parent ────────────────

#[test]
fn upward_routing_via_preferred_parents() {
    // All nodes route upward by forwarding to preferred_parent.
    let mut n2 = DodagState::new(0, dodag_id(), 0);
    n2.process_dio(&dio(ROOT_RANK), ll(1), 1.0);

    let mut n3 = DodagState::new(0, dodag_id(), 0);
    n3.process_dio(&dio(512), ll(2), 1.0);

    let mut n5 = DodagState::new(0, dodag_id(), 0);
    n5.process_dio(&dio(ROOT_RANK), ll(1), 1.0);

    let mut n4 = DodagState::new(0, dodag_id(), 0);
    n4.process_dio(&dio(768), ll(3), 1.0);
    n4.process_dio(&dio(512), ll(2), 1.0);

    // Upward next-hop chain: n4 → n2 → root, n3 → n2 → root, n5 → root
    assert_eq!(n4.preferred_parent, Some(ll(2)));
    assert_eq!(n3.preferred_parent, Some(ll(2)));
    assert_eq!(n5.preferred_parent, Some(ll(1)));
    assert_eq!(n2.preferred_parent, Some(ll(1)));
}

// ── Test 3: Parent switching on link failure ──────────────────────────────────

#[test]
fn parent_switch_on_link_failure() {
    // n4 sees both n2 (cost 768) and n3 (cost 1024). Prefers n2.
    let mut n4 = DodagState::new(0, dodag_id(), 0);
    n4.process_dio(&dio(512), ll(2), 1.0); // cost 768
    n4.process_dio(&dio(512), ll(3), 2.0); // cost 1024; rank 512 < n4's rank
    assert_eq!(n4.preferred_parent, Some(ll(2)));
    assert_eq!(n4.rank, 768);

    // n2 fails → n4 falls back to n3
    n4.remove_parent(&ll(2));
    assert!(n4.is_joined());
    assert_eq!(n4.preferred_parent, Some(ll(3)));
    assert_eq!(n4.rank, 1024);

    // n3 also fails → n4 goes unjoined
    n4.remove_parent(&ll(3));
    assert!(!n4.is_joined());
}

#[test]
fn mismatched_rpl_instance_dio_is_ignored() {
    let mut node = DodagState::new(0, dodag_id(), 0);

    node.process_dio(&dio_with_instance(ROOT_RANK, 1), ll(1), 1.0);

    assert!(!node.is_joined());
    assert_eq!(node.parent_count(), 0);
    assert_eq!(node.rpl_instance_id, 0);
}

#[test]
fn saturated_finite_candidate_is_removed() {
    let mut node = DodagState::new(0, dodag_id(), 0);
    node.process_dio(&dio(ROOT_RANK), ll(1), 1.0);
    node.process_dio(&dio(450), ll(2), 1.0);
    assert_eq!(node.parent_count(), 2);

    node.process_dio(&dio(1), ll(1), 256.0);

    assert_eq!(node.parent_count(), 1);
    assert_eq!(node.preferred_parent, Some(ll(2)));
    assert_eq!(node.rank, 706);
}
