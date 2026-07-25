/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_checksum.c
 * @brief UDP and ICMPv6 checksum computation for SCHC decompression.
 */

#include "schc_internal.h"
#include <limits.h>

/* ─── one's complement arithmetic ─────────────────────────────────────────── */

static uint32_t oc_add(uint32_t a, uint32_t b)
{
	uint32_t s = a + b;
	if (s >> 16) {
		s = (s & 0xFFFF) + (s >> 16);
	}
	return s;
}

static uint32_t checksum_bytes(const uint8_t *data, size_t len)
{
	uint32_t sum = 0;
	size_t i;

	for (i = 0; i + 1 < len; i += 2) {
		sum = oc_add(sum, ((uint16_t)data[i] << 8) | data[i + 1]);
	}
	if (i < len) {
		sum = oc_add(sum, (uint32_t)data[i] << 8);
	}
	return sum;
}

static uint32_t pseudo_sum(const uint8_t src[16], const uint8_t dst[16],
			   uint8_t next_header, uint16_t length)
{
	uint32_t sum = 0;

	for (int i = 0; i < 16; i += 2) {
		sum = oc_add(sum, ((uint16_t)src[i] << 8) | src[i + 1]);
	}
	for (int i = 0; i < 16; i += 2) {
		sum = oc_add(sum, ((uint16_t)dst[i] << 8) | dst[i + 1]);
	}
	sum = oc_add(sum, length);
	sum = oc_add(sum, next_header);
	return sum;
}

static uint16_t finalize_checksum(uint32_t sum)
{
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return ~((uint16_t)sum);
}

/* ─── protocol checksums ──────────────────────────────────────────────────── */

/**
 * @brief Compute UDP checksum.
 *
 * @param src         Source IPv6 address
 * @param dst         Destination IPv6 address
 * @param src_port    Source port
 * @param dst_port    Destination port
 * @param payload     UDP payload (CoAP data)
 * @param payload_len Payload length
 * @param cksum_out   Output: computed checksum (only valid if return is 0)
 * @return 0 on success, -1 if payload_len would overflow UDP length field
 */
int udp_checksum(const uint8_t src[16], const uint8_t dst[16],
		 uint16_t src_port, uint16_t dst_port,
		 const uint8_t *payload, size_t payload_len,
		 uint16_t *cksum_out)
{
	/* UDP length field is 16 bits; header is 8 bytes, max payload is 65527 */
	if (payload_len > UINT16_MAX - 8) {
		return -1;
	}
	uint16_t udp_length = (uint16_t)(8 + payload_len);
	uint32_t sum = pseudo_sum(src, dst, IPV6_NH_UDP, udp_length);

	sum = oc_add(sum, src_port);
	sum = oc_add(sum, dst_port);
	sum = oc_add(sum, udp_length);
	/* checksum field (0 during computation) */
	sum = oc_add(sum, checksum_bytes(payload, payload_len));
	*cksum_out = finalize_checksum(sum);
	return 0;
}

uint16_t icmpv6_checksum(const uint8_t src[16], const uint8_t dst[16],
			 const uint8_t *icmpv6_payload, uint16_t len)
{
	uint32_t sum = pseudo_sum(src, dst, IPV6_NH_ICMPV6, len);

	sum = oc_add(sum, checksum_bytes(icmpv6_payload, len));
	return finalize_checksum(sum);
}
