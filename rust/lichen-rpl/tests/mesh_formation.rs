//! 5-node RPL mesh formation integration test.
//!
//! Exit criteria for Phase 4 (d5c):
//!   - 5-node mesh forms DODAG
//!   - Upward routing: every node knows its preferred parent
//!   - Downward routing: root assembles source routes from DAOs
//!   - Parent switching on link failure

use lichen_hal::storage::mem::MemStorage;
use lichen_link::{identity::Identity, keys::Seed};
use lichen_rpl::{
    dodag::{DodagState, MIN_HOP_RANK_INCREASE, ROOT_RANK},
    message::Dio,
    routing::DaoManager,
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

fn identity(seed: u8) -> Identity {
    Identity::from_seed(Seed::new([seed; 32]))
}

fn origin(identity: &Identity) -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[..2].copy_from_slice(&[0xfe, 0x80]);
    addr[8..].copy_from_slice(&identity.iid);
    addr
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

// ── Test 3: Downward routing — root assembles source routes from DAOs ─────────

#[test]
fn downward_routes_assembled_from_daos() {
    let root_addr = ll(1);
    let mut storage = MemStorage::new();
    let (mut root, mut state) =
        DaoManager::provision_root(&mut storage, root_addr, 0, dodag_id()).unwrap();
    let id2 = identity(2);
    let id3 = identity(3);
    let id4 = identity(4);
    let id5 = identity(5);
    let n2 = origin(&id2);
    let n3 = origin(&id3);
    let n4 = origin(&id4);
    let n5 = origin(&id5);

    // n2 sends DAO: target=n2, parent=root
    let mut mgr2 = DaoManager::new(ll(2), 0, dodag_id());
    assert!(root.process_dao(&mgr2.build_dao(root_addr)));
    assert_eq!(
        root.routing_table().lookup(&ll(2)),
        Some(&[ll(2)] as &[[u8; 16]])
    );
    assert_eq!(root.routing_table().lookup(&n2), Some(&[n2] as &[[u8; 16]]));

    // n3 sends DAO: target=n3, parent=n2
    let mut mgr3 = DaoManager::new(ll(3), 0, dodag_id());
    assert!(root.process_dao(&mgr3.build_dao(ll(2))));
    assert_eq!(
        root.routing_table().lookup(&n3),
        Some(&[n2, n3] as &[[u8; 16]])
    );

    // n5 sends DAO: target=n5, parent=root (single hop)
    let mut mgr5 = DaoManager::new(ll(5), 0, dodag_id());
    assert!(root.process_dao(&mgr5.build_dao(root_addr)));
    assert_eq!(
        root.routing_table().lookup(&ll(5)),
        Some(&[ll(5)] as &[[u8; 16]])
    );
    assert_eq!(root.routing_table().lookup(&n5), Some(&[n5] as &[[u8; 16]]));

    // n4 sends DAO: target=n4, parent=n2 (two hops: root→n2→n4)
    let mut mgr4 = DaoManager::new(ll(4), 0, dodag_id());
    assert!(root.process_dao(&mgr4.build_dao(ll(2))));
    assert_eq!(
        root.routing_table().lookup(&n4),
        Some(&[n2, n4] as &[[u8; 16]])
    );

    // Root has routes to all 4 non-root nodes
    assert_eq!(root.routing_table().len(), 4);
}

// ── Test 4: Parent switching on link failure ──────────────────────────────────

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

// ── Test 5: Downward route updates after topology change ─────────────────────

#[test]
fn route_updates_when_node_reparents() {
    let root_addr = ll(1);
    let mut storage = MemStorage::new();
    let (mut root, mut state) =
        DaoManager::provision_root(&mut storage, root_addr, 0, dodag_id()).unwrap();
    let id2 = identity(2);
    let id3 = identity(3);
    let id4 = identity(4);
    let n2 = origin(&id2);
    let n3 = origin(&id3);
    let n4 = origin(&id4);

    // Initial topology: n4 is behind n3
    let mut mgr2 = DaoManager::new(n2, 0, dodag_id());
    let mut mgr3 = DaoManager::new(n3, 0, dodag_id());
    let mut mgr4 = DaoManager::new(n4, 0, dodag_id());

    root.process_dao(&mgr2.build_dao(root_addr)); // n2 → root
    root.process_dao(&mgr3.build_dao(ll(2))); // n3 → n2
    root.process_dao(&mgr4.build_dao(ll(3))); // n4 → n3

    assert_eq!(
        root.routing_table().lookup(&n4),
        Some(&[n2, n3, n4] as &[[u8; 16]])
    );

    // n3 fails; n4 reparents to n2 and sends a new DAO
    root.process_dao(&mgr4.build_dao(ll(2))); // n4 → n2 (shorter path)

    assert_eq!(
        root.routing_table().lookup(&n4),
        Some(&[n2, n4] as &[[u8; 16]])
    );
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
