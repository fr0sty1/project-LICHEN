/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_FORWARDING_H_
#define LICHEN_GATEWAY_FORWARDING_H_

#include <stdint.h>
#include <stddef.h>

#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>

struct lichen_forwarding_stats {
	uint64_t mesh_to_backhaul;
	uint64_t backhaul_to_mesh;
	uint64_t backhaul_to_mesh_dropped_mtu;
};

int lichen_forwarding_init(void);

void lichen_forwarding_handle(struct net_pkt *pkt, struct net_if *in_iface,
			      struct net_if *out_iface);

int lichen_forwarding_stats_get(struct lichen_forwarding_stats *stats);

int lichen_forwarding_stats_clear(void);

#endif
