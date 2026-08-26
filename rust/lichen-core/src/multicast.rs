// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! Standard IPv6 multicast groups used by LICHEN.

use crate::addr::Ipv6Addr;

/// Link-local all-nodes group (`ff02::1`).
pub const ALL_NODES_MULTICAST: Ipv6Addr = Ipv6Addr::ALL_NODES;

/// Link-local all-RPL-nodes group (`ff02::1a`).
pub const ALL_RPL_NODES_MULTICAST: Ipv6Addr =
    Ipv6Addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a]);

/// Mesh-local all-LICHEN-nodes group (`ff03::fc`).
pub const ALL_LICHEN_NODES_MULTICAST: Ipv6Addr =
    Ipv6Addr([0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfc]);
