// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_rpl::message::OPT_TRANSIT_INFO;
use lichen_rpl::routing::{
    DaoDiagnosticLimits, DaoManager, DaoProcessTiming, RouteTarget, RoutingTable, MAX_ROUTES,
};

fn address(last: u8) -> [u8; 16] {
    [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, last]
}

fn route_dao(
    dao_sequence: u8,
    path_sequence: u8,
    path_lifetime: u8,
    target: [u8; 16],
    parent: [u8; 16],
) -> Vec<u8> {
    let mut wire = vec![0, 0, 0, dao_sequence, 5, 18, 0, 128];
    wire.extend_from_slice(&target);
    wire.extend_from_slice(&[OPT_TRANSIT_INFO, 20, 0, 0x80, path_sequence, path_lifetime]);
    wire.extend_from_slice(&parent);
    wire
}

fn limits() -> DaoDiagnosticLimits {
    DaoDiagnosticLimits {
        max_targets: MAX_ROUTES,
        max_candidates_per_target: MAX_ROUTES,
        max_candidates: MAX_ROUTES,
    }
}

#[test]
fn route_target_canonicalizes_every_profile_boundary() {
    let all = [0xff; 16];
    assert_eq!(*RouteTarget::new(all, 0).unwrap().prefix(), [0; 16]);

    let mut prefix64 = [0xff; 16];
    prefix64[8..].fill(0);
    assert_eq!(*RouteTarget::new(all, 64).unwrap().prefix(), prefix64);

    let mut prefix127 = [0xff; 16];
    prefix127[15] = 0xfe;
    let target127 = RouteTarget::new(all, 127).unwrap();
    assert_eq!(*target127.prefix(), prefix127);
    assert!(target127.contains(&all));
    assert!(target127.contains(&prefix127));

    assert_eq!(RouteTarget::new(all, 128), Some(RouteTarget::host(all)));
    assert_eq!(RouteTarget::new(all, 129), None);
    assert_eq!(RouteTarget::new(all, u8::MAX), None);

    let mut equivalent = [0xff; 16];
    equivalent[8] = 0x80;
    equivalent[9..].fill(0);
    assert_eq!(RouteTarget::new(all, 65), RouteTarget::new(equivalent, 65));
}

#[test]
fn lookup_is_deterministic_lpm_with_expired_fallback_and_exact_host_mutation() {
    let mut table = RoutingTable::new();
    let default = RouteTarget::new([0xff; 16], 0).unwrap();
    let mut network = [0u8; 16];
    network[..8].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 1]);
    let prefix64 = RouteTarget::new(network, 64).unwrap();
    let mut pair = network;
    pair[15] = 2;
    let prefix127 = RouteTarget::new(pair, 127).unwrap();
    let mut host = pair;
    host[15] = 3;

    assert!(!table.add_prefix_route(prefix64, *prefix64.prefix(), &[*prefix64.prefix()]));
    assert!(!table.add_prefix_route(prefix64, address(11), &[address(99)]));
    assert!(table.add_prefix_route(default, address(10), &[address(10)]));
    assert!(table.add_prefix_route(prefix64, address(11), &[address(11)]));
    assert!(table.add_prefix_route(prefix127, address(12), &[address(12)]));
    assert!(table.add_route(host, &[address(13)]));

    assert_eq!(table.lookup(&host), Some([address(13)].as_slice()));
    assert_eq!(table.lookup(&pair), Some([address(12)].as_slice()));
    let mut network_host = network;
    network_host[15] = 99;
    assert_eq!(table.lookup(&network_host), Some([address(11)].as_slice()));
    assert_eq!(table.lookup(&address(99)), Some([address(10)].as_slice()));

    table.mark_expired(&host).unwrap().unwrap();
    assert_eq!(table.lookup(&host), Some([address(12)].as_slice()));
    table.remove_route(&host);
    assert_eq!(table.lookup(&host), Some([address(12)].as_slice()));
    table.mark_prefix_expired(prefix127).unwrap().unwrap();
    assert_eq!(table.lookup(&host), Some([address(11)].as_slice()));
    table.remove_prefix_route(prefix127);
    assert_eq!(table.lookup(&network_host), Some([address(11)].as_slice()));
}

#[test]
fn dao_rebuild_and_expiry_preserve_static_prefix_while_wire_stays_host_only() {
    let root = address(1);
    let host = address(2);
    let authority = address(3);
    let mut prefix = [0xfd; 16];
    prefix[8..].fill(0);
    let prefix = RouteTarget::new(prefix, 64).unwrap();
    let mut destination = *prefix.prefix();
    destination[15] = 99;
    let mut manager = DaoManager::diagnostic_root(root, 0, root);
    assert!(manager
        .routing_table_mut()
        .add_prefix_route(prefix, root, &[root]));
    let timing = DaoProcessTiming {
        now_seconds: 10,
        lifetime_unit_seconds: 2,
        max_deadline_seconds: u64::MAX,
    };

    manager
        .process_route_state_diagnostic(
            &route_dao(1, 1, 1, host, root),
            authority,
            timing,
            limits(),
        )
        .unwrap();
    assert_eq!(
        manager.routing_table().lookup(&destination),
        Some([root].as_slice())
    );
    assert!(manager.routing_table().lookup(&host).is_some());

    assert!(manager.expire_routes(12));
    assert_eq!(manager.routing_table().lookup(&host), None);
    assert_eq!(
        manager.routing_table().lookup(&destination),
        Some([root].as_slice())
    );

    let before = manager.route_state_diagnostic(authority, 2);
    let mut non_host = route_dao(2, 2, 255, host, root);
    non_host[7] = 127;
    assert!(manager
        .process_route_state_diagnostic(&non_host, authority, timing, limits())
        .is_err());
    assert_eq!(manager.route_state_diagnostic(authority, 2), before);
    assert_eq!(
        manager.routing_table().lookup(&destination),
        Some([root].as_slice())
    );
}

#[test]
fn prefix_and_dao_host_routes_share_one_atomic_capacity_budget() {
    let root = address(1);
    let host = address(2);
    let authority = address(3);
    let mut manager = DaoManager::diagnostic_root(root, 0, root);
    for index in 0..MAX_ROUTES {
        let mut prefix = [0xfd; 16];
        prefix[13..15].copy_from_slice(&(index as u16).to_be_bytes());
        let target = RouteTarget::new(prefix, 120).unwrap();
        assert!(manager
            .routing_table_mut()
            .add_prefix_route(target, address(9), &[address(9)]));
    }
    assert_eq!(manager.routing_table().len(), MAX_ROUTES);

    let result = manager.process_route_state_diagnostic(
        &route_dao(1, 1, 255, host, root),
        authority,
        DaoProcessTiming {
            now_seconds: 0,
            lifetime_unit_seconds: 1,
            max_deadline_seconds: u64::MAX,
        },
        limits(),
    );
    assert!(result.is_err());
    assert_eq!(manager.routing_table().len(), MAX_ROUTES);
    assert_eq!(manager.routing_table().lookup(&host), None);
    assert!(manager.route_state_diagnostic(authority, 1).is_empty());
}
