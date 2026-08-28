/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_helpers.c
 * @brief Address helpers, byte order helpers, and protocol accessors for SCHC.
 */

#include "schc_internal.h"
#include <string.h>

/* ─── address helpers ─────────────────────────────────────────────────────── */

bool is_link_local(const uint8_t addr[16])
{
	return addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80;
}

bool is_canonical_link_local(const uint8_t addr[16])
{
	static const uint8_t prefix[8] = { 0xFE, 0x80, 0, 0, 0, 0, 0, 0 };

	return memcmp(addr, prefix, sizeof(prefix)) == 0;
}

static bool is_unspecified(const uint8_t addr[16])
{
	static const uint8_t zero[16];

	return memcmp(addr, zero, sizeof(zero)) == 0;
}

static bool is_loopback(const uint8_t addr[16])
{
	static const uint8_t loopback[16] = { [15] = 1 };

	return memcmp(addr, loopback, sizeof(loopback)) == 0;
}

static bool is_ipv4_mapped(const uint8_t addr[16])
{
	static const uint8_t prefix[12] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
	};

	return memcmp(addr, prefix, sizeof(prefix)) == 0;
}

int validate_rule7_addresses(const uint8_t src[16], const uint8_t dst[16])
{
	if (is_unspecified(src) || is_loopback(src) || src[0] == 0xFF ||
	    is_ipv4_mapped(src)) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (is_unspecified(dst) || is_loopback(dst) || is_ipv4_mapped(dst)) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (dst[0] == 0xFF) {
		uint8_t scope = dst[1] & 0x0F;

		if (scope < 2 || scope > 14) {
			return SCHC_ERR_INVALID_ARGUMENT;
		}
	}

	return SCHC_OK;
}

bool is_global(const uint8_t addr[16])
{
	return (addr[0] >> 5) == 0x01 ||             /* 2000::/3 */
	       (addr[0] & 0xFE) == 0x02;              /* 02xx::/7 Yggdrasil */
}

bool is_ula(const uint8_t addr[16])
{
	return addr[0] == 0xFD;
}

uint16_t read_be16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

void write_be16(uint8_t *p, uint16_t value)
{
	p[0] = (uint8_t)(value >> 8);
	p[1] = (uint8_t)value;
}

/* ─── IPv6 accessors ──────────────────────────────────────────────────────── */

uint8_t ipv6_version(const uint8_t *packet)
{
	return packet[SCHC_IPV6_VERSION_OFFSET] >> 4;
}

uint16_t ipv6_payload_len(const uint8_t *packet)
{
	return read_be16(&packet[SCHC_IPV6_PAYLOAD_LEN_OFFSET]);
}

uint8_t ipv6_next_header(const uint8_t *packet)
{
	return packet[SCHC_IPV6_NEXT_HEADER_OFFSET];
}

uint8_t ipv6_hop_limit(const uint8_t *packet)
{
	return packet[SCHC_IPV6_HOP_LIMIT_OFFSET];
}

const uint8_t *ipv6_src(const uint8_t *packet)
{
	return &packet[SCHC_IPV6_SRC_OFFSET];
}

const uint8_t *ipv6_dst(const uint8_t *packet)
{
	return &packet[SCHC_IPV6_DST_OFFSET];
}

const uint8_t *ipv6_payload(const uint8_t *packet)
{
	return &packet[IPV6_HDR_LEN];
}

uint8_t *ipv6_payload_mut(uint8_t *packet)
{
	return &packet[IPV6_HDR_LEN];
}

void ipv6_write_base(uint8_t *packet, uint16_t payload_len,
		     uint8_t next_header, uint8_t hop_limit,
		     const uint8_t src[16], const uint8_t dst[16])
{
	packet[SCHC_IPV6_VERSION_OFFSET] = 0x60;
	memset(&packet[SCHC_IPV6_TC_FLOW_OFFSET], 0, SCHC_IPV6_TC_FLOW_LEN);
	write_be16(&packet[SCHC_IPV6_PAYLOAD_LEN_OFFSET], payload_len);
	packet[SCHC_IPV6_NEXT_HEADER_OFFSET] = next_header;
	packet[SCHC_IPV6_HOP_LIMIT_OFFSET] = hop_limit;
	memcpy(&packet[SCHC_IPV6_SRC_OFFSET], src, SCHC_IPV6_ADDR_LEN);
	memcpy(&packet[SCHC_IPV6_DST_OFFSET], dst, SCHC_IPV6_ADDR_LEN);
}

/* ─── UDP accessors ───────────────────────────────────────────────────────── */

uint16_t udp_src_port(const uint8_t *udp)
{
	return read_be16(&udp[SCHC_UDP_SRC_PORT_OFFSET]);
}

uint16_t udp_dst_port(const uint8_t *udp)
{
	return read_be16(&udp[SCHC_UDP_DST_PORT_OFFSET]);
}

uint16_t udp_len(const uint8_t *udp)
{
	return read_be16(&udp[SCHC_UDP_LEN_OFFSET]);
}

const uint8_t *udp_payload(const uint8_t *udp)
{
	return &udp[SCHC_UDP_PAYLOAD_OFFSET];
}

uint8_t *udp_payload_mut(uint8_t *udp)
{
	return &udp[SCHC_UDP_PAYLOAD_OFFSET];
}

void udp_write_header(uint8_t *udp, uint16_t src_port,
		      uint16_t dst_port, uint16_t len,
		      uint16_t checksum)
{
	write_be16(&udp[SCHC_UDP_SRC_PORT_OFFSET], src_port);
	write_be16(&udp[SCHC_UDP_DST_PORT_OFFSET], dst_port);
	write_be16(&udp[SCHC_UDP_LEN_OFFSET], len);
	write_be16(&udp[SCHC_UDP_CHECKSUM_OFFSET], checksum);
}

void udp_write_checksum(uint8_t *udp, uint16_t checksum)
{
	write_be16(&udp[SCHC_UDP_CHECKSUM_OFFSET], checksum);
}

/* ─── CoAP accessors ──────────────────────────────────────────────────────── */

uint8_t coap_type(const uint8_t *coap)
{
	return (coap[SCHC_COAP_VER_TYPE_TKL_OFFSET] >> 4) & 0x3;
}

uint8_t coap_tkl(const uint8_t *coap)
{
	return coap[SCHC_COAP_VER_TYPE_TKL_OFFSET] & 0x0F;
}

uint8_t coap_version(const uint8_t *coap)
{
	return coap[SCHC_COAP_VER_TYPE_TKL_OFFSET] >> 6;
}

uint8_t coap_code(const uint8_t *coap)
{
	return coap[SCHC_COAP_CODE_OFFSET];
}

uint16_t coap_mid(const uint8_t *coap)
{
	return read_be16(&coap[SCHC_COAP_MID_OFFSET]);
}

const uint8_t *coap_tail(const uint8_t *coap)
{
	return &coap[SCHC_COAP_FIXED_LEN];
}

uint8_t *coap_tail_mut(uint8_t *coap)
{
	return &coap[SCHC_COAP_FIXED_LEN];
}

void coap_write_fixed(uint8_t *coap, uint8_t type, uint8_t tkl,
		      uint8_t code, uint16_t mid)
{
	coap[SCHC_COAP_VER_TYPE_TKL_OFFSET] = (uint8_t)(
		(1u << 6) | ((type & 0x3u) << 4) | (tkl & 0x0Fu));
	coap[SCHC_COAP_CODE_OFFSET] = code;
	write_be16(&coap[SCHC_COAP_MID_OFFSET], mid);
}

/* ─── ICMPv6 accessors ────────────────────────────────────────────────────── */

uint8_t icmpv6_type(const uint8_t *icmpv6)
{
	return icmpv6[SCHC_ICMPV6_TYPE_OFFSET];
}

uint8_t icmpv6_code(const uint8_t *icmpv6)
{
	return icmpv6[SCHC_ICMPV6_CODE_OFFSET];
}

const uint8_t *icmpv6_body(const uint8_t *icmpv6)
{
	return &icmpv6[SCHC_ICMPV6_BODY_OFFSET];
}

uint8_t *icmpv6_body_mut(uint8_t *icmpv6)
{
	return &icmpv6[SCHC_ICMPV6_BODY_OFFSET];
}

void icmpv6_write_header(uint8_t *icmpv6, uint8_t type, uint8_t code,
			 uint16_t checksum)
{
	icmpv6[SCHC_ICMPV6_TYPE_OFFSET] = type;
	icmpv6[SCHC_ICMPV6_CODE_OFFSET] = code;
	write_be16(&icmpv6[SCHC_ICMPV6_CHECKSUM_OFFSET], checksum);
}

void icmpv6_write_checksum(uint8_t *icmpv6, uint16_t checksum)
{
	write_be16(&icmpv6[SCHC_ICMPV6_CHECKSUM_OFFSET], checksum);
}

uint16_t icmpv6_echo_id(const uint8_t *icmpv6)
{
	return read_be16(&icmpv6[SCHC_ICMPV6_ECHO_ID_OFFSET]);
}

uint16_t icmpv6_echo_seq(const uint8_t *icmpv6)
{
	return read_be16(&icmpv6[SCHC_ICMPV6_ECHO_SEQ_OFFSET]);
}

const uint8_t *icmpv6_echo_tail(const uint8_t *icmpv6)
{
	return &icmpv6[SCHC_ICMPV6_ECHO_TAIL_OFFSET];
}

uint8_t *icmpv6_echo_tail_mut(uint8_t *icmpv6)
{
	return &icmpv6[SCHC_ICMPV6_ECHO_TAIL_OFFSET];
}

void icmpv6_echo_write_body(uint8_t *icmpv6, uint16_t id, uint16_t seq)
{
	write_be16(&icmpv6[SCHC_ICMPV6_ECHO_ID_OFFSET], id);
	write_be16(&icmpv6[SCHC_ICMPV6_ECHO_SEQ_OFFSET], seq);
}

/* ─── RPL accessors ───────────────────────────────────────────────────────── */

uint8_t rpl_instance(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_INSTANCE_OFFSET];
}

uint8_t rpl_dio_version(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_DIO_VERSION_OFFSET];
}

uint16_t rpl_dio_rank(const uint8_t *rpl)
{
	return read_be16(&rpl[SCHC_RPL_DIO_RANK_OFFSET]);
}

uint8_t rpl_dio_gmop(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_DIO_GMOP_OFFSET];
}

uint8_t rpl_dio_dtsn(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_DIO_DTSN_OFFSET];
}

const uint8_t *rpl_dio_dodagid(const uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DIO_DODAGID_OFFSET];
}

const uint8_t *rpl_dio_tail(const uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DIO_BASE_LEN];
}

uint8_t *rpl_dio_tail_mut(uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DIO_BASE_LEN];
}

void rpl_dio_write_base(uint8_t *rpl, uint8_t instance,
			uint8_t version, uint16_t rank,
			uint8_t gmop, uint8_t dtsn,
			const uint8_t dodagid[16])
{
	rpl[SCHC_RPL_INSTANCE_OFFSET] = instance;
	rpl[SCHC_RPL_DIO_VERSION_OFFSET] = version;
	write_be16(&rpl[SCHC_RPL_DIO_RANK_OFFSET], rank);
	rpl[SCHC_RPL_DIO_GMOP_OFFSET] = gmop;
	rpl[SCHC_RPL_DIO_DTSN_OFFSET] = dtsn;
	rpl[SCHC_RPL_DIO_FLAGS_OFFSET] = 0;
	rpl[SCHC_RPL_DIO_RESERVED_OFFSET] = 0;
	memcpy(&rpl[SCHC_RPL_DIO_DODAGID_OFFSET], dodagid, SCHC_RPL_DODAGID_LEN);
}

uint8_t rpl_dao_kd_flags(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_DAO_KD_FLAGS_OFFSET];
}

uint8_t rpl_dao_sequence(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_DAO_SEQUENCE_OFFSET];
}

const uint8_t *rpl_dao_dodagid(const uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DAO_DODAGID_OFFSET];
}

const uint8_t *rpl_dao_tail(const uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN];
}

uint8_t *rpl_dao_tail_mut(uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN];
}

void rpl_dao_write_base(uint8_t *rpl, uint8_t instance,
			uint8_t kd_flags, uint8_t seq,
			const uint8_t dodagid[16])
{
	rpl[SCHC_RPL_INSTANCE_OFFSET] = instance;
	rpl[SCHC_RPL_DAO_KD_FLAGS_OFFSET] = kd_flags;
	rpl[SCHC_RPL_DAO_RESERVED_OFFSET] = 0;
	rpl[SCHC_RPL_DAO_SEQUENCE_OFFSET] = seq;
	memcpy(&rpl[SCHC_RPL_DAO_DODAGID_OFFSET], dodagid, SCHC_RPL_DODAGID_LEN);
}

/* ─── validation ──────────────────────────────────────────────────────────── */

int validate_ipv6_transport_lengths(const uint8_t *packet, size_t pkt_len)
{
	uint16_t declared_payload_len = ipv6_payload_len(packet);
	size_t actual_payload_len = pkt_len - IPV6_HDR_LEN;

	if (declared_payload_len != actual_payload_len) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	if (ipv6_next_header(packet) != IPV6_NH_UDP) {
		return SCHC_OK;
	}

	if (actual_payload_len < UDP_HDR_LEN) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint16_t declared_udp_len = udp_len(ipv6_payload(packet));
	if (declared_udp_len < UDP_HDR_LEN || declared_udp_len != actual_payload_len) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	return SCHC_OK;
}
