/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "rpl_root.h"

#include <lichen/rpl.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_core.h>
#include <zephyr/sys/byteorder.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

LOG_MODULE_REGISTER(lichen_rpl_root, LOG_LEVEL_INF);

#define IPV6_HDR_LEN      40
#define ICMPV6_HDR_LEN     4
#define IPV6_NH_ICMPV6    58

/* RPL ICMPv6 constants (RFC 6550) */
#define ICMPV6_TYPE_RPL        155
#define ICMPV6_CODE_RPL_DIO      1

/* All-RPL-nodes multicast address (RFC 6550 §5.1) */
#define RPL_MULTICAST_ADDR { 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1A }

/* ── Packet-building helpers (no shared SCHC dependency) ──────────────────── */

static uint16_t read_be16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static void write_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static uint32_t ones_sum_bytes(const uint8_t *data, size_t len)
{
	uint32_t sum = 0;
	for (size_t i = 0; i + 1 < len; i += 2) {
		sum += read_be16(&data[i]);
	}
	if (len & 1) {
		sum += (uint32_t)data[len - 1] << 8;
	}
	return sum;
}

static uint16_t finalize_cksum(uint32_t sum)
{
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return ~((uint16_t)sum);
}

static uint16_t icmpv6_checksum(const uint8_t src[16], const uint8_t dst[16],
				const uint8_t *icmp, uint16_t len)
{
	uint32_t sum = 0;
	for (int i = 0; i < 16; i += 2) {
		sum += read_be16(&src[i]);
	}
	for (int i = 0; i < 16; i += 2) {
		sum += read_be16(&dst[i]);
	}
	sum += len;
	sum += IPV6_NH_ICMPV6;
	sum += ones_sum_bytes(icmp, len);
	return finalize_cksum(sum);
}

static void ipv6_write_base(uint8_t *pkt, uint16_t payload_len,
			    uint8_t next_hdr, uint8_t hop_limit,
			    const uint8_t src[16], const uint8_t dst[16])
{
	pkt[0] = 0x60;
	memset(&pkt[1], 0, 3);
	write_be16(&pkt[4], payload_len);
	pkt[6] = next_hdr;
	pkt[7] = hop_limit;
	memcpy(&pkt[8], src, 16);
	memcpy(&pkt[24], dst, 16);
}

static void icmpv6_write_header(uint8_t *icmp, uint8_t type, uint8_t code,
				uint16_t cksum)
{
	icmp[0] = type;
	icmp[1] = code;
	write_be16(&icmp[2], cksum);
}

static void icmpv6_write_checksum(uint8_t *icmp, uint16_t cksum)
{
	write_be16(&icmp[2], cksum);
}

struct lichen_rpl_root {
	struct lichen_rpl_dodag dodag;
	struct lichen_trickle trickle;
	struct lichen_rpl_dao_manager dao_manager;
	struct lichen_rpl_dao_root_state root_state;
	uint8_t prefix[16];
	uint8_t prefix_len;
	struct net_if *iface;
};

struct lichen_rpl_root *lichen_rpl_root_init(struct lichen_rpl_root *root, struct net_if *iface,
					     const uint8_t *dodag_id, const uint8_t *node_addr)
{
	if (root == NULL || dodag_id == NULL || node_addr == NULL) {
		return NULL;
	}
	memset(root, 0, sizeof(*root));
	lichen_rpl_dodag_init_root(&root->dodag, 0, dodag_id, 0);
	lichen_rpl_dao_manager_init_root(&root->dao_manager, node_addr, 0, dodag_id);
	lichen_rpl_dao_manager_bind_root_state(&root->dao_manager, &root->root_state);
	lichen_trickle_init(&root->trickle, CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS,
			   CONFIG_LICHEN_RPL_TRICKLE_IMAX_DOUBLINGS,
			   CONFIG_LICHEN_RPL_TRICKLE_K);
	lichen_trickle_start(&root->trickle, 0, 0);
	memcpy(root->prefix, dodag_id, 16);
	root->prefix_len = 128;
	root->iface = iface;
	return root;
}

void lichen_rpl_root_tick(struct lichen_rpl_root *root, uint32_t now)
{
	if (root == NULL) {
		return;
	}
	struct lichen_trickle_event ev;
	lichen_trickle_next_event(&root->trickle, &ev);
	if (ev.type == LICHEN_TRICKLE_TRANSMIT) {
		if (lichen_trickle_fire_transmit(&root->trickle)) {
			lichen_rpl_root_send_dio(root);
		}
	} else if (ev.type == LICHEN_TRICKLE_EXPIRE) {
		lichen_trickle_expire(&root->trickle, now, 0);
	}
}

bool lichen_rpl_root_send_dio(struct lichen_rpl_root *root)
{
	if (root == NULL || root->iface == NULL) {
		return false;
	}

	/* Buffer for IPv6 + ICMPv6 + DIO base + DODAG config option */
	uint8_t buf[IPV6_HDR_LEN + ICMPV6_HDR_LEN + LICHEN_RPL_DIO_BASE_LEN + 2 + LICHEN_RPL_DODAG_CONFIG_DATA_LEN];
	uint8_t src[16], dst[16] = RPL_MULTICAST_ADDR;

	/* Build link-local source address from DODAG ID (IID portion) */
	memset(src, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	memcpy(&src[8], &root->dodag.dodag_id[8], 8);

	/* Build DODAG config option */
	struct lichen_rpl_dodag_config dcfg;
	lichen_rpl_dodag_config_init(&dcfg);
	dcfg.dio_int_min = CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS / 1000;
	if (dcfg.dio_int_min < 1) {
		dcfg.dio_int_min = 1;
	}
	dcfg.dio_int_doublings = CONFIG_LICHEN_RPL_TRICKLE_IMAX_DOUBLINGS;
	dcfg.dio_redundancy_const = CONFIG_LICHEN_RPL_TRICKLE_K;

	/* Build DIO base */
	struct lichen_rpl_dio dio;
	memset(&dio, 0, sizeof(dio));
	dio.rpl_instance_id = root->dodag.rpl_instance_id;
	dio.version = root->dodag.version;
	dio.rank = root->dodag.rank;
	dio.grounded = true;
	dio.mode_of_operation = 0;
	dio.preference = 0;
	dio.dtsn = root->dodag.dtsn;
	memcpy(dio.dodag_id, root->dodag.dodag_id, 16);

	/* Serialize DIO base */
	uint8_t *icmp = &buf[IPV6_HDR_LEN];
	uint8_t *rpl = &icmp[ICMPV6_HDR_LEN];
	int dio_len = lichen_rpl_dio_write(&dio, rpl, LICHEN_RPL_DIO_BASE_LEN);
	if (dio_len < 0) {
		LOG_ERR("DIO serialize failed: %d", dio_len);
		return false;
	}

	/* Append DODAG config option after DIO base */
	uint8_t *opt = rpl + dio_len;
	int opt_len = lichen_rpl_dodag_config_write(&dcfg, opt,
		sizeof(buf) - IPV6_HDR_LEN - ICMPV6_HDR_LEN - dio_len);
	if (opt_len < 0) {
		LOG_ERR("DODAG config option serialize failed: %d", opt_len);
		return false;
	}

	size_t rpl_body_len = (size_t)dio_len + (size_t)opt_len;
	size_t icmp_len = ICMPV6_HDR_LEN + rpl_body_len;

	/* Build IPv6 header */
	ipv6_write_base(buf, (uint16_t)icmp_len, IPV6_NH_ICMPV6, 255, src, dst);

	/* Write ICMPv6 header with checksum = 0 */
	icmpv6_write_header(icmp, ICMPV6_TYPE_RPL, ICMPV6_CODE_RPL_DIO, 0);

	/* Compute ICMPv6 checksum */
	uint16_t cksum = icmpv6_checksum(src, dst, icmp, (uint16_t)icmp_len);
	icmpv6_write_checksum(icmp, cksum);

	size_t total = IPV6_HDR_LEN + icmp_len;

	/* Allocate net_pkt and send via net_recv_data */
	struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(root->iface, total,
							   AF_INET6, IPPROTO_RAW,
							   K_NO_WAIT);
	if (pkt == NULL) {
		LOG_ERR("DIO: failed to allocate net_pkt (%zu B)", total);
		return false;
	}

	int ret = net_pkt_write(pkt, buf, total);
	if (ret < 0) {
		LOG_ERR("DIO: net_pkt_write failed: %d", ret);
		net_pkt_unref(pkt);
		return false;
	}

	ret = net_recv_data(root->iface, pkt);
	if (ret < 0) {
		LOG_ERR("DIO: net_recv_data failed: %d", ret);
		net_pkt_unref(pkt);
		return false;
	}

	LOG_DBG("DIO sent (rank=%u, dodag_id=fd00::%02x%02x)",
		dio.rank, dio.dodag_id[14], dio.dodag_id[15]);
	return true;
}

bool lichen_rpl_root_handle_dao(struct lichen_rpl_root *root, const uint8_t *data, size_t len, uint32_t now)
{
	return lichen_rpl_dao_manager_process_dao(&root->dao_manager, data, len, now);
}

const struct lichen_rpl_route *lichen_rpl_root_lookup(struct lichen_rpl_root *root, const uint8_t *target)
{
	if (root == NULL || target == NULL) {
		return NULL;
	}
	return lichen_rpl_routing_table_lookup(&root->root_state.routing_table, target);
}

int lichen_rpl_root_set_prefix(struct lichen_rpl_root *root, const uint8_t *prefix, uint8_t len)
{
	if (root == NULL || prefix == NULL || len > 128) return -EINVAL;
	memcpy(root->prefix, prefix, 16);
	root->prefix_len = len;
	if (len >= 64) {
		memcpy(root->dodag.dodag_id, prefix, 16);
		memcpy(root->dao_manager.dodag_id, prefix, 16);
	}
	return 0;
}
