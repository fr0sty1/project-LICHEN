//! Tests for the routing module.

use super::gpsr::{haversine, is_valid_coords};
use super::router::{dao_parents_for_source, sign_dao};
use super::*;
use lichen_core::constants::RPL_INSTANCE_ID;
use lichen_link::{identity::Identity, keys::Seed, link_layer::LinkLayer};
use lichen_rpl::dodag::DodagState;
use lichen_rpl::message::{
    Dao, Dio, DodagConfig, OptionIter, TransitInfo, DODAG_CONFIG_DATA_LEN, OPT_DODAG_CONFIG,
    OPT_TRANSIT_INFO,
};
use std::vec;
use std::vec::Vec;

const NON_STORING_MOP: u8 = 1;

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
    // imin = 2^12 = 4096 (default dio_int_min=12), doubles to 8192
    assert_eq!(router.trickle.interval, 8192);

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
    // imin = 2^12 = 4096 (default dio_int_min=12), doubles to 8192
    assert_eq!(router.trickle.interval, 8192);

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

    // dio_int_min >= 32 causes 1u32 << 32 to overflow, making imin=0 -> rejected
    config.dio_int_min = 32;
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
    dao.extend_from_slice(Dao::options_tail(&second_dao));

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
    let lifetime = OptionIter::new(Dao::options_tail(&dao))
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
    assert!(haversine(p, p) < 0.01);
}

#[test]
fn haversine_distance_known() {
    // Seattle to Portland ~= 233km
    let seattle = (47.6062, -122.3321);
    let portland = (45.5152, -122.6784);
    let d = haversine(seattle, portland);
    assert!((d - 233_000.0).abs() < 5000.0);
}

#[test]
fn is_valid_coords_rejects_nan() {
    assert!(!is_valid_coords((f64::NAN, 0.0)));
    assert!(!is_valid_coords((0.0, f64::NAN)));
}

#[test]
fn is_valid_coords_rejects_inf() {
    assert!(!is_valid_coords((f64::INFINITY, 0.0)));
    assert!(!is_valid_coords((f64::NEG_INFINITY, 0.0)));
}

#[test]
fn is_valid_coords_rejects_null_island() {
    assert!(!is_valid_coords((0.0, 0.0)));
}

#[test]
fn is_valid_coords_accepts_valid() {
    assert!(is_valid_coords((47.6062, -122.3321)));
    assert!(is_valid_coords((-33.8688, 151.2093))); // Sydney
    assert!(is_valid_coords((90.0, 0.0))); // North pole
    assert!(is_valid_coords((-90.0, 180.0))); // South pole
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
    use lichen_rpl::routing::DaoAdmissionState;
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
    let mut admission =
        DaoAdmissionState::provision(&mut storage, root_addr, RPL_INSTANCE_ID, root_addr).unwrap();
    admission
        .admit(&mut storage, *identity.pubkey.as_bytes())
        .unwrap();
    assert_eq!(
        root.process_signature_verified_dao_at_ms(
            &verified,
            verified.origin_iid(),
            &mut state,
            &mut storage,
            0,
            &admission,
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
            &admission,
        ),
        Ok(DaoProcessOutcome::Duplicate)
    );
    // Create a replay DAO: same identity, same origin, same sequence, but different content
    // (different parent creates a different hash, triggering replay detection)
    let mut different_parent = root_addr;
    different_parent[0] ^= 0x01;
    let (replay_origin, replay_wire) = signed_dao(&identity, different_parent, root_addr, 1);
    let replay_verified = SignatureVerifiedDao::verify_signature(
        &replay_wire,
        replay_origin,
        RPL_INSTANCE_ID,
        root_addr,
        Some(identity.pubkey),
    )
    .unwrap();
    let replay_result = root.process_signature_verified_dao_at_ms(
        &replay_verified,
        replay_verified.origin_iid(),
        &mut state,
        &mut storage,
        2,
        &admission,
    );
    assert!(
        matches!(replay_result, Err(DaoProcessError::Replay)),
        "expected Err(Replay) but got {:?}",
        replay_result
    );
    let (mut rebooted, mut rebooted_state) = Router::open_root(&storage, root_addr).unwrap();
    let rebooted_admission =
        DaoAdmissionState::open(&storage, root_addr, RPL_INSTANCE_ID, root_addr).unwrap();
    assert_eq!(
        rebooted.process_signature_verified_dao_at_ms(
            &verified,
            verified.origin_iid(),
            &mut rebooted_state,
            &mut storage,
            3,
            &rebooted_admission,
        ),
        Ok(DaoProcessOutcome::Duplicate)
    );
}

#[test]
fn production_handler_requires_announce_pin() {
    use lichen_rpl::routing::DaoAdmissionState;
    let identity = Identity::from_seed(Seed::new([3; 32]));
    let root_id = lichen_core::addr::NodeId([9; 8]);
    let root_addr = root_id.link_local_addr().0;
    let (origin, wire) = signed_dao(&identity, root_addr, root_addr, 1);
    let mut storage = lichen_hal::storage::mem::MemStorage::new();
    let (mut node, mut state) =
        crate::node::RplNode::provision_root(root_id, &mut storage).unwrap();
    let mut admission = DaoAdmissionState::provision(
        &mut storage,
        root_addr,
        lichen_core::constants::RPL_INSTANCE_ID,
        root_addr,
    )
    .unwrap();
    admission
        .admit(&mut storage, *identity.pubkey.as_bytes())
        .unwrap();
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
            &admission,
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
            &admission,
        ),
        crate::node::DaoHandlingOutcome::Applied
    );
}
