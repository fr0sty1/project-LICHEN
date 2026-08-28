/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "dad.h"

#include <errno.h>
#include <string.h>

#define IPV6_HEADER_LEN 40U
#define ICMPV6_ND_LEN 24U
#define ICMPV6_NEXT_HEADER 58U
#define ICMPV6_NS 135U
#define ICMPV6_NA 136U
#define ND_HOP_LIMIT 255U
#define NA_OVERRIDE 0x20U
#define NA_SOLICITED 0x40U
#define NA_RESERVED_MASK 0x1fU

static const uint8_t unspecified[16];
static const uint8_t all_nodes[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
				      0, 0, 0, 0, 0, 0, 0, 1 };

static uint32_t checksum_add(uint32_t sum, const uint8_t *data, size_t len)
{
	while (len >= 2U) {
		sum += ((uint32_t)data[0] << 8U) | data[1];
		data += 2;
		len -= 2U;
	}
	if (len != 0U) {
		sum += (uint32_t)data[0] << 8U;
	}
	return sum;
}

static uint16_t icmpv6_checksum(const uint8_t src[16], const uint8_t dst[16],
				const uint8_t *icmp, size_t icmp_len)
{
	uint8_t length_and_next[8] = { 0 };
	uint32_t sum = 0;

	length_and_next[2] = (uint8_t)(icmp_len >> 8U);
	length_and_next[3] = (uint8_t)icmp_len;
	length_and_next[7] = ICMPV6_NEXT_HEADER;
	sum = checksum_add(sum, src, 16U);
	sum = checksum_add(sum, dst, 16U);
	sum = checksum_add(sum, length_and_next, sizeof(length_and_next));
	sum = checksum_add(sum, icmp, icmp_len);
	while ((sum >> 16U) != 0U) {
		sum = (sum & UINT32_C(0xffff)) + (sum >> 16U);
	}
	return (uint16_t)~sum;
}

static bool is_unicast(const uint8_t addr[16])
{
	return memcmp(addr, unspecified, 16U) != 0 && addr[0] != 0xffU;
}

bool lichen_dad_short_addr_is_reserved(uint16_t short_addr)
{
	return short_addr == 0U || short_addr == UINT16_C(0xfffe) ||
	       short_addr == UINT16_C(0xffff);
}

int lichen_dad_target(uint16_t short_addr, uint8_t target[16])
{
	if (target == NULL || lichen_dad_short_addr_is_reserved(short_addr)) {
		return -EINVAL;
	}
	memset(target, 0, 16U);
	target[0] = 0xfeU;
	target[1] = 0x80U;
	target[11] = 0xffU;
	target[12] = 0xfeU;
	target[14] = (uint8_t)(short_addr >> 8U);
	target[15] = (uint8_t)short_addr;
	return 0;
}

static void solicited_node(const uint8_t target[16], uint8_t dst[16])
{
	memset(dst, 0, 16U);
	dst[0] = 0xffU;
	dst[1] = 0x02U;
	dst[11] = 0x01U;
	dst[12] = 0xffU;
	memcpy(&dst[13], &target[13], 3U);
}

static int build_packet(uint16_t short_addr, bool conflict, uint8_t *out,
			 size_t out_size, size_t *out_len)
{
	uint8_t target[16];
	uint8_t *icmp;
	uint16_t checksum;
	int ret;

	if (out == NULL || out_len == NULL) {
		return -EINVAL;
	}
	if (out_size < LICHEN_DAD_PACKET_LEN) {
		return -ENOBUFS;
	}
	ret = lichen_dad_target(short_addr, target);
	if (ret < 0) {
		return ret;
	}
	memset(out, 0, LICHEN_DAD_PACKET_LEN);
	out[0] = 0x60U;
	out[5] = ICMPV6_ND_LEN;
	out[6] = ICMPV6_NEXT_HEADER;
	out[7] = ND_HOP_LIMIT;
	if (conflict) {
		memcpy(&out[8], target, 16U);
		memcpy(&out[24], all_nodes, 16U);
	} else {
		solicited_node(target, &out[24]);
	}
	icmp = &out[IPV6_HEADER_LEN];
	icmp[0] = conflict ? ICMPV6_NA : ICMPV6_NS;
	icmp[4] = conflict ? NA_OVERRIDE : 0U;
	memcpy(&icmp[8], target, 16U);
	checksum = icmpv6_checksum(&out[8], &out[24], icmp, ICMPV6_ND_LEN);
	icmp[2] = (uint8_t)(checksum >> 8U);
	icmp[3] = (uint8_t)checksum;
	*out_len = LICHEN_DAD_PACKET_LEN;
	return 0;
}

int lichen_dad_build_probe(uint16_t short_addr, uint8_t *out, size_t out_size,
			   size_t *out_len)
{
	return build_packet(short_addr, false, out, out_size, out_len);
}

int lichen_dad_build_conflict(uint16_t short_addr, uint8_t *out, size_t out_size,
			      size_t *out_len)
{
	return build_packet(short_addr, true, out, out_size, out_len);
}

static int parse_common(const uint8_t *packet, size_t packet_len, bool conflict,
			uint16_t *short_addr)
{
	const uint8_t *src;
	const uint8_t *dst;
	const uint8_t *icmp;
	uint8_t target[16];
	uint16_t candidate;

	if (packet == NULL || short_addr == NULL) {
		return -EINVAL;
	}
	if (packet_len != LICHEN_DAD_PACKET_LEN || (packet[0] >> 4U) != 6U ||
	    packet[4] != 0U || packet[5] != ICMPV6_ND_LEN ||
	    packet[6] != ICMPV6_NEXT_HEADER || packet[7] != ND_HOP_LIMIT) {
		return -EBADMSG;
	}
	src = &packet[8];
	dst = &packet[24];
	icmp = &packet[IPV6_HEADER_LEN];
	if (icmp[0] != (conflict ? ICMPV6_NA : ICMPV6_NS) || icmp[1] != 0U ||
	    icmpv6_checksum(src, dst, icmp, ICMPV6_ND_LEN) != 0U ||
	    icmp[5] != 0U || icmp[6] != 0U || icmp[7] != 0U) {
		return -EBADMSG;
	}
	if (icmp[8] != 0xfeU || icmp[9] != 0x80U ||
	    memcmp(&icmp[10], &unspecified[2], 9U) != 0 || icmp[19] != 0xffU ||
	    icmp[20] != 0xfeU || icmp[21] != 0U) {
		return -EBADMSG;
	}
	candidate = (uint16_t)(((uint16_t)icmp[22] << 8U) | (uint16_t)icmp[23]);
	if (lichen_dad_short_addr_is_reserved(candidate) ||
	    lichen_dad_target(candidate, target) < 0 || memcmp(target, &icmp[8], 16U) != 0) {
		return -EBADMSG;
	}
	if (conflict) {
		if (!is_unicast(src) || memcmp(dst, all_nodes, 16U) != 0 ||
		    (icmp[4] & (NA_SOLICITED | NA_RESERVED_MASK)) != 0U) {
			return -EBADMSG;
		}
	} else {
		uint8_t expected_dst[16];

		solicited_node(target, expected_dst);
		if (memcmp(src, unspecified, 16U) != 0 || memcmp(dst, expected_dst, 16U) != 0 ||
		    icmp[4] != 0U) {
			return -EBADMSG;
		}
	}
	*short_addr = candidate;
	return 0;
}

int lichen_dad_parse_probe(const uint8_t *packet, size_t packet_len,
			   uint16_t *short_addr)
{
	return parse_common(packet, packet_len, false, short_addr);
}

int lichen_dad_parse_conflict(const uint8_t *packet, size_t packet_len,
			      uint16_t expected_short_addr)
{
	uint16_t short_addr;
	int ret;

	if (lichen_dad_short_addr_is_reserved(expected_short_addr)) {
		return -EINVAL;
	}
	ret = parse_common(packet, packet_len, true, &short_addr);
	if (ret < 0) {
		return ret;
	}
	return short_addr == expected_short_addr ? 1 : 0;
}

int lichen_dad_conflict_for_probe(const uint8_t *probe, size_t probe_len,
				  uint16_t owned_short_addr,
				  const uint8_t owner_eui64[LICHEN_DAD_EUI64_LEN],
				  const uint8_t sender_eui64[LICHEN_DAD_EUI64_LEN],
				  uint8_t *out, size_t out_size, size_t *out_len)
{
	uint16_t probed;
	int ret;

	if (owner_eui64 == NULL || sender_eui64 == NULL || out_len == NULL) {
		return -EINVAL;
	}
	if (memcmp(owner_eui64, sender_eui64, LICHEN_DAD_EUI64_LEN) == 0) {
		return -EACCES;
	}
	ret = lichen_dad_parse_probe(probe, probe_len, &probed);
	if (ret < 0) {
		return ret;
	}
	if (probed != owned_short_addr) {
		return 0;
	}
	ret = lichen_dad_build_conflict(owned_short_addr, out, out_size, out_len);
	return ret < 0 ? ret : 1;
}

int lichen_dad_exchange_init(struct lichen_dad_exchange *exchange,
			     const uint8_t challenger_eui64[LICHEN_DAD_EUI64_LEN],
			     uint16_t short_addr)
{
	if (exchange == NULL || challenger_eui64 == NULL ||
	    lichen_dad_short_addr_is_reserved(short_addr)) {
		return -EINVAL;
	}
	memset(exchange, 0, sizeof(*exchange));
	memcpy(exchange->challenger_eui64, challenger_eui64, LICHEN_DAD_EUI64_LEN);
	exchange->short_addr = short_addr;
	return 0;
}

int lichen_dad_exchange_next_probe(struct lichen_dad_exchange *exchange,
				   uint8_t *out, size_t out_size, size_t *out_len)
{
	int ret;

	if (exchange == NULL) {
		return -EINVAL;
	}
	if (exchange->cancelled) {
		return -ECANCELED;
	}
	if (exchange->conflict_detected) {
		return -EADDRINUSE;
	}
	if (exchange->completed || exchange->probes_sent >= LICHEN_DAD_PROBE_COUNT) {
		return -EALREADY;
	}
	ret = lichen_dad_build_probe(exchange->short_addr, out, out_size, out_len);
	if (ret == 0) {
		exchange->probes_sent++;
	}
	return ret;
}

int lichen_dad_exchange_record_conflict(
	struct lichen_dad_exchange *exchange, const uint8_t *packet, size_t packet_len,
	const uint8_t owner_eui64[LICHEN_DAD_EUI64_LEN])
{
	int ret;

	if (exchange == NULL || owner_eui64 == NULL) {
		return -EINVAL;
	}
	if (exchange->cancelled || exchange->completed) {
		return -EALREADY;
	}
	if (memcmp(owner_eui64, exchange->challenger_eui64, LICHEN_DAD_EUI64_LEN) == 0) {
		return -EACCES;
	}
	ret = lichen_dad_parse_conflict(packet, packet_len, exchange->short_addr);
	if (ret == 1) {
		exchange->conflict_detected = true;
		exchange->completed = true;
	}
	return ret;
}

int lichen_dad_exchange_finish(struct lichen_dad_exchange *exchange)
{
	if (exchange == NULL) {
		return -EINVAL;
	}
	if (exchange->cancelled) {
		return -ECANCELED;
	}
	if (exchange->conflict_detected) {
		return -EADDRINUSE;
	}
	if (exchange->completed || exchange->probes_sent != LICHEN_DAD_PROBE_COUNT) {
		return -EAGAIN;
	}
	exchange->completed = true;
	return 0;
}

int lichen_dad_exchange_cancel(struct lichen_dad_exchange *exchange)
{
	if (exchange == NULL) {
		return -EINVAL;
	}
	if (exchange->completed) {
		return 0;
	}
	exchange->cancelled = true;
	exchange->completed = true;
	return 1;
}
