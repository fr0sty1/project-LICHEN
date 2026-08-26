// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

use lichen_core::addr::Ipv6Addr;
use lichen_core::multicast::{
    ALL_LICHEN_NODES_MULTICAST, ALL_NODES_MULTICAST, ALL_RPL_NODES_MULTICAST,
};

#[test]
fn standard_multicast_groups_are_typed_and_byte_exact() {
    fn require_ipv6_addr(_: Ipv6Addr) {}

    let expected = [
        (
            ALL_NODES_MULTICAST,
            [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        ),
        (
            ALL_RPL_NODES_MULTICAST,
            [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a],
        ),
        (
            ALL_LICHEN_NODES_MULTICAST,
            [0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfc],
        ),
    ];

    for (address, bytes) in expected {
        require_ipv6_addr(address);
        assert_eq!(address.0, bytes);
    }
}

#[test]
fn standard_multicast_group_scopes_match_the_spec() {
    fn scope(address: Ipv6Addr) -> u8 {
        assert!(address.is_multicast());
        assert_eq!(address.0[1] & 0xf0, 0, "standard group must be unflagged");
        address.0[1] & 0x0f
    }

    assert_eq!(scope(ALL_NODES_MULTICAST), 2);
    assert_eq!(scope(ALL_RPL_NODES_MULTICAST), 2);
    assert_eq!(scope(ALL_LICHEN_NODES_MULTICAST), 3);
}
