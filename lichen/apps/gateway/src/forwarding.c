/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "forwarding.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_pkt.h>

LOG_MODULE_REGISTER(lichen_forwarding, LOG_LEVEL_INF);

#define LICHEN_MESH_MTU 200

static struct k_mutex s_stats_mutex;
static struct lichen_forwarding_stats s_stats;

static bool s_initialized;

static void forwarding_stats_init(struct lichen_forwarding_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
}

static void forwarding_mgmt_event_handler(struct net_mgmt_event_callback *cb,
					   uint32_t mgmt_event,
					   struct net_if *iface)
{
	ARG_UNUSED(cb);

	if (mgmt_event == NET_EVENT_IPV6_CMD_ROUTE_ADD) {
		LOG_DBG("Route added on iface %p", (void *)iface);
	} else if (mgmt_event == NET_EVENT_IPV6_CMD_ROUTE_DEL) {
		LOG_DBG("Route removed on iface %p", (void *)iface);
	}
}

int lichen_forwarding_init(void)
{
	if (s_initialized) {
		return -EALREADY;
	}

	static struct net_mgmt_event_callback fwd_mgmt_cb;

	k_mutex_init(&s_stats_mutex);
	forwarding_stats_init(&s_stats);

	net_mgmt_init_event_callback(&fwd_mgmt_cb, forwarding_mgmt_event_handler,
				     NET_EVENT_IPV6_CMD_ROUTE_ADD |
				     NET_EVENT_IPV6_CMD_ROUTE_DEL);
	net_mgmt_add_event_callback(&fwd_mgmt_cb);

	LOG_INF("IPv6 forwarding active: mesh MTU=%u", LICHEN_MESH_MTU);

	s_initialized = true;
	return 0;
}

void lichen_forwarding_handle(struct net_pkt *pkt, struct net_if *in_iface,
			      struct net_if *out_iface)
{
	uint32_t pkt_len;

	if (pkt == NULL || in_iface == NULL || out_iface == NULL) {
		return;
	}

	if (in_iface == out_iface) {
		return;
	}

	pkt_len = net_pkt_get_len(pkt);

	k_mutex_lock(&s_stats_mutex, K_FOREVER);

	if (pkt_len > LICHEN_MESH_MTU) {
		s_stats.backhaul_to_mesh_dropped_mtu++;
		LOG_WRN("Forwarding: packet %u B exceeds mesh MTU %u, dropping",
			pkt_len, LICHEN_MESH_MTU);
	}

	k_mutex_unlock(&s_stats_mutex);
}

int lichen_forwarding_stats_get(struct lichen_forwarding_stats *stats)
{
	if (stats == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_stats_mutex, K_FOREVER);
	*stats = s_stats;
	k_mutex_unlock(&s_stats_mutex);

	return 0;
}

int lichen_forwarding_stats_clear(void)
{
	k_mutex_lock(&s_stats_mutex, K_FOREVER);
	forwarding_stats_init(&s_stats);
	k_mutex_unlock(&s_stats_mutex);

	return 0;
}
