/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc.c
 * @brief SCHC compress/decompress (RFC 8724) - rules 0-4 + uncompressed fallback
 *
 * Ported from rust/lichen-schc/src/codec.rs.
 * Bit order: MSB-first (network bit order). The residue is zero-padded to
 * a byte boundary.
 *
 * COMPRESSION PROFILE DECISIONS
 * =============================
 *
 * This file currently implements the LICHEN SCHC profile, not a fully generic
 * Zephyr SCHC module. The intended architecture is:
 *
 *   generic RFC 8724 engine + rule machinery
 *       used by
 *   LICHEN-specific packet profiles and rule table
 *
 * Until that split exists, keep the profile decisions explicit in this file:
 *
 * - Rule IDs are interop constants. They must continue to match
 *   rust/lichen-schc, python/src/lichen/schc, constants.toml, and
 *   test/vectors/schc_compression.json.
 *
 * - Rules 0 and 1 cover IPv6 + UDP + CoAP. Rule 0 is link-local source and
 *   destination. Rule 1 is global source and destination. Mixed-scope or
 *   otherwise unsupported address shapes fall through to rule 255.
 *
 * - Rule 2 covers link-local ICMPv6 Echo Request/Reply only.
 *
 * - Rules 3 and 4 cover link-local RPL control messages over ICMPv6 type 155.
 *   Rule 3 covers DIO. Rule 4 covers DAO only when the D flag says DODAGID is
 *   present, matching the non-storing-mode case LICHEN optimizes for.
 *
 * - Rule 255 is the uncompressed fallback. It is deliberately preserved so new
 *   packet shapes remain deliverable before a dedicated compression rule is
 *   designed and tested.
 *
 * - Checksums, lengths, and other derivable fields are reconstructed during
 *   decompression. They are not carried in the residue unless a rule says they
 *   must be sent.
 *
 * - Variable tails are carried verbatim after the fixed rule residue. For CoAP
 *   this means token/options/payload after the 4-byte fixed header. For RPL it
 *   means options after the DIO/DAO base object.
 *
 * - Packet-header positions are fixed by IPv6/UDP/CoAP/ICMPv6/RPL wire
 *   formats, but maintainers must not spread raw stride offsets through rule
 *   code. Use the named layout constants and accessor helpers below.
 *
 * SECURITY CONSIDERATIONS
 * =======================
 * SCHC compression can leak information about packet contents through
 * compressed size variations (compression oracle attack). In contexts where
 * encrypted payloads are compressed, an attacker observing compressed sizes
 * may infer plaintext content by correlating size changes with known inputs.
 *
 * Mitigations applied in LICHEN:
 * - OSCORE encryption happens BEFORE SCHC compression, so encrypted CoAP
 *   payloads appear as opaque bytes that don't compress differentially.
 * - Link-layer encryption (if any) wraps the already-compressed frame.
 *
 * Residual risks:
 * - Header field values (ports, addresses, hop limit) are compressed but
 *   not encrypted; their presence in specific rules may leak metadata.
 * - Tail length variations remain observable.
 *
 * For high-security deployments, consider padding payloads to fixed sizes
 * before OSCORE encryption.
 */

#include <lichen/schc.h>
#include <schc/bitstream.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>

/* IPv6 protocol constants */
#define IPV6_NH_UDP             17   /* UDP next header (RFC 768) */
#define IPV6_NH_ICMPV6          58   /* ICMPv6 next header (RFC 4443) */
#define IPV6_HDR_LEN            40   /* IPv6 base header length */
#define UDP_HDR_LEN             8    /* UDP header length */
#define ICMPV6_TYPE_ECHO_REQUEST 128 /* Echo Request (RFC 4443) */
#define ICMPV6_TYPE_ECHO_REPLY  129  /* Echo Reply (RFC 4443) */
#define ICMPV6_TYPE_RPL         155  /* RPL ICMPv6 type (RFC 6550) */
#define ICMPV6_CODE_RPL_DIO     1    /* RPL DIO code (RFC 6550) */
#define ICMPV6_CODE_RPL_DAO     2    /* RPL DAO code (RFC 6550) */

/*
 * Packet-layout constants.
 *
 * These compile-time constants document the offsets implied by the profile
 * code below. Rule code should use accessors built on these names instead of
 * repeating numbers such as 40, 44, or 45.
 */
enum schc_ipv6_layout {
	SCHC_IPV6_VERSION_OFFSET = 0,
	SCHC_IPV6_TC_FLOW_OFFSET = 1,
	SCHC_IPV6_TC_FLOW_LEN = 3,
	SCHC_IPV6_PAYLOAD_LEN_OFFSET = 4,
	SCHC_IPV6_NEXT_HEADER_OFFSET = 6,
	SCHC_IPV6_HOP_LIMIT_OFFSET = 7,
	SCHC_IPV6_SRC_OFFSET = 8,
	SCHC_IPV6_DST_OFFSET = 24,
	SCHC_IPV6_ADDR_LEN = 16,
};

enum schc_udp_layout {
	SCHC_UDP_SRC_PORT_OFFSET = 0,
	SCHC_UDP_DST_PORT_OFFSET = 2,
	SCHC_UDP_LEN_OFFSET = 4,
	SCHC_UDP_CHECKSUM_OFFSET = 6,
	SCHC_UDP_PAYLOAD_OFFSET = UDP_HDR_LEN,
};

enum schc_coap_layout {
	SCHC_COAP_VER_TYPE_TKL_OFFSET = 0,
	SCHC_COAP_CODE_OFFSET = 1,
	SCHC_COAP_MID_OFFSET = 2,
	SCHC_COAP_FIXED_LEN = 4,
};

/* OSCORE option number (RFC 8613) */
#define COAP_OPTION_OSCORE 9

enum schc_icmpv6_layout {
	SCHC_ICMPV6_TYPE_OFFSET = 0,
	SCHC_ICMPV6_CODE_OFFSET = 1,
	SCHC_ICMPV6_CHECKSUM_OFFSET = 2,
	SCHC_ICMPV6_BODY_OFFSET = 4,
	SCHC_ICMPV6_ECHO_ID_OFFSET = 4,
	SCHC_ICMPV6_ECHO_SEQ_OFFSET = 6,
	SCHC_ICMPV6_ECHO_TAIL_OFFSET = 8,
};

enum schc_rpl_layout {
	SCHC_RPL_AFTER_IPV6_OFFSET = IPV6_HDR_LEN + SCHC_ICMPV6_BODY_OFFSET,
	SCHC_RPL_INSTANCE_OFFSET = 0,
	SCHC_RPL_DIO_VERSION_OFFSET = 1,
	SCHC_RPL_DIO_RANK_OFFSET = 2,
	SCHC_RPL_DIO_GMOP_OFFSET = 4,
	SCHC_RPL_DIO_DTSN_OFFSET = 5,
	SCHC_RPL_DIO_FLAGS_OFFSET = 6,
	SCHC_RPL_DIO_RESERVED_OFFSET = 7,
	SCHC_RPL_DIO_DODAGID_OFFSET = 8,
	SCHC_RPL_DIO_BASE_LEN = 24,
	SCHC_RPL_DAO_KD_FLAGS_OFFSET = 1,
	SCHC_RPL_DAO_RESERVED_OFFSET = 2,
	SCHC_RPL_DAO_SEQUENCE_OFFSET = 3,
	SCHC_RPL_DAO_DODAGID_OFFSET = 4,
	SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN = 20,
	SCHC_RPL_DODAGID_LEN = 16,
};

/* ─── address helpers ─────────────────────────────────────────────────────── */

static bool is_link_local(const uint8_t addr[16])
{
	return addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80;
}

static bool is_global(const uint8_t addr[16])
{
	return (addr[0] >> 5) == 0x01; /* 001x xxxx = 2000::/3 */
}

static bool is_ula(const uint8_t addr[16])
{
	return addr[0] == 0xFD;
}

static uint16_t read_be16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static void write_be16(uint8_t *p, uint16_t value)
{
	p[0] = (uint8_t)(value >> 8);
	p[1] = (uint8_t)value;
}

static uint8_t ipv6_version(const uint8_t *packet)
{
	return packet[SCHC_IPV6_VERSION_OFFSET] >> 4;
}

static uint16_t ipv6_payload_len(const uint8_t *packet)
{
	return read_be16(&packet[SCHC_IPV6_PAYLOAD_LEN_OFFSET]);
}

static uint8_t ipv6_next_header(const uint8_t *packet)
{
	return packet[SCHC_IPV6_NEXT_HEADER_OFFSET];
}

static uint8_t ipv6_hop_limit(const uint8_t *packet)
{
	return packet[SCHC_IPV6_HOP_LIMIT_OFFSET];
}

static const uint8_t *ipv6_src(const uint8_t *packet)
{
	return &packet[SCHC_IPV6_SRC_OFFSET];
}

static const uint8_t *ipv6_dst(const uint8_t *packet)
{
	return &packet[SCHC_IPV6_DST_OFFSET];
}

static const uint8_t *ipv6_payload(const uint8_t *packet)
{
	return &packet[IPV6_HDR_LEN];
}

static uint8_t *ipv6_payload_mut(uint8_t *packet)
{
	return &packet[IPV6_HDR_LEN];
}

static void ipv6_write_base(uint8_t *packet, uint16_t payload_len,
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

static uint16_t udp_src_port(const uint8_t *udp)
{
	return read_be16(&udp[SCHC_UDP_SRC_PORT_OFFSET]);
}

static uint16_t udp_dst_port(const uint8_t *udp)
{
	return read_be16(&udp[SCHC_UDP_DST_PORT_OFFSET]);
}

static uint16_t udp_len(const uint8_t *udp)
{
	return read_be16(&udp[SCHC_UDP_LEN_OFFSET]);
}

static const uint8_t *udp_payload(const uint8_t *udp)
{
	return &udp[SCHC_UDP_PAYLOAD_OFFSET];
}

static uint8_t *udp_payload_mut(uint8_t *udp)
{
	return &udp[SCHC_UDP_PAYLOAD_OFFSET];
}

static void udp_write_header(uint8_t *udp, uint16_t src_port,
			     uint16_t dst_port, uint16_t len,
			     uint16_t checksum)
{
	write_be16(&udp[SCHC_UDP_SRC_PORT_OFFSET], src_port);
	write_be16(&udp[SCHC_UDP_DST_PORT_OFFSET], dst_port);
	write_be16(&udp[SCHC_UDP_LEN_OFFSET], len);
	write_be16(&udp[SCHC_UDP_CHECKSUM_OFFSET], checksum);
}

static void udp_write_checksum(uint8_t *udp, uint16_t checksum)
{
	write_be16(&udp[SCHC_UDP_CHECKSUM_OFFSET], checksum);
}

static uint8_t coap_type(const uint8_t *coap)
{
	return (coap[SCHC_COAP_VER_TYPE_TKL_OFFSET] >> 4) & 0x3;
}

static uint8_t coap_tkl(const uint8_t *coap)
{
	return coap[SCHC_COAP_VER_TYPE_TKL_OFFSET] & 0x0F;
}

static uint8_t coap_version(const uint8_t *coap)
{
	return coap[SCHC_COAP_VER_TYPE_TKL_OFFSET] >> 6;
}

static uint8_t coap_code(const uint8_t *coap)
{
	return coap[SCHC_COAP_CODE_OFFSET];
}

static uint16_t coap_mid(const uint8_t *coap)
{
	return read_be16(&coap[SCHC_COAP_MID_OFFSET]);
}

static const uint8_t *coap_tail(const uint8_t *coap)
{
	return &coap[SCHC_COAP_FIXED_LEN];
}

static uint8_t *coap_tail_mut(uint8_t *coap)
{
	return &coap[SCHC_COAP_FIXED_LEN];
}

static void coap_write_fixed(uint8_t *coap, uint8_t type, uint8_t tkl,
			     uint8_t code, uint16_t mid)
{
	coap[SCHC_COAP_VER_TYPE_TKL_OFFSET] =
		(1u << 6) | ((type & 0x3u) << 4) | (tkl & 0x0Fu);
	coap[SCHC_COAP_CODE_OFFSET] = code;
	write_be16(&coap[SCHC_COAP_MID_OFFSET], mid);
}

/**
 * @brief Check if a CoAP packet contains the OSCORE option (option 9).
 *
 * OSCORE-protected CoAP packets have the Object-Security option present
 * in the option list. This function scans the CoAP options to detect it.
 *
 * @param coap     Pointer to CoAP header (after UDP)
 * @param coap_len Total length of CoAP data (header + options + payload)
 * @return true if OSCORE option is present, false otherwise
 */
static bool coap_has_oscore_option(const uint8_t *coap, size_t coap_len)
{
	if (coap_len < SCHC_COAP_FIXED_LEN) {
		return false;
	}
	if (coap_version(coap) != 1) {
		return false;
	}

	uint8_t tkl = coap_tkl(coap);
	if (tkl > 8) {
		/* Invalid TKL (reserved values 9-15) */
		return false;
	}

	size_t offset = SCHC_COAP_FIXED_LEN + tkl;
	uint16_t option_number = 0;

	while (offset < coap_len) {
		uint8_t byte = coap[offset];

		/* Check for payload marker (0xFF) */
		if (byte == 0xFF) {
			break;
		}

		/* Parse option delta */
		/* SECURITY: Use uint32_t/size_t to avoid truncation when extended
		 * delta/length values exceed 255 (e.g., delta==14 can yield 65804) */
		uint32_t delta = (byte >> 4) & 0x0F;
		size_t length = byte & 0x0F;
		offset++;

		if (delta == 13) {
			if (offset >= coap_len) {
				return false;
			}
			delta = coap[offset] + 13;
			offset++;
		} else if (delta == 14) {
			if (offset + 1 >= coap_len) {
				return false;
			}
			delta = read_be16(&coap[offset]) + 269;
			offset += 2;
		} else if (delta == 15) {
			/* Reserved for payload marker context */
			return false;
		}

		/* Parse option length */
		if (length == 13) {
			if (offset >= coap_len) {
				return false;
			}
			length = coap[offset] + 13;
			offset++;
		} else if (length == 14) {
			if (offset + 1 >= coap_len) {
				return false;
			}
			length = read_be16(&coap[offset]) + 269;
			offset += 2;
		} else if (length == 15) {
			/* Reserved */
			return false;
		}

		option_number += delta;

		/* Check if this is the OSCORE option */
		if (option_number == COAP_OPTION_OSCORE) {
			return true;
		}

		/* If we've passed option 9, no need to continue */
		if (option_number > COAP_OPTION_OSCORE) {
			return false;
		}

		/* Skip option value */
		offset += length;
	}

	return false;
}

static uint8_t icmpv6_type(const uint8_t *icmpv6)
{
	return icmpv6[SCHC_ICMPV6_TYPE_OFFSET];
}

static uint8_t icmpv6_code(const uint8_t *icmpv6)
{
	return icmpv6[SCHC_ICMPV6_CODE_OFFSET];
}

static const uint8_t *icmpv6_body(const uint8_t *icmpv6)
{
	return &icmpv6[SCHC_ICMPV6_BODY_OFFSET];
}

static uint8_t *icmpv6_body_mut(uint8_t *icmpv6)
{
	return &icmpv6[SCHC_ICMPV6_BODY_OFFSET];
}

static void icmpv6_write_header(uint8_t *icmpv6, uint8_t type, uint8_t code,
				uint16_t checksum)
{
	icmpv6[SCHC_ICMPV6_TYPE_OFFSET] = type;
	icmpv6[SCHC_ICMPV6_CODE_OFFSET] = code;
	write_be16(&icmpv6[SCHC_ICMPV6_CHECKSUM_OFFSET], checksum);
}

static void icmpv6_write_checksum(uint8_t *icmpv6, uint16_t checksum)
{
	write_be16(&icmpv6[SCHC_ICMPV6_CHECKSUM_OFFSET], checksum);
}

static uint16_t icmpv6_echo_id(const uint8_t *icmpv6)
{
	return read_be16(&icmpv6[SCHC_ICMPV6_ECHO_ID_OFFSET]);
}

static uint16_t icmpv6_echo_seq(const uint8_t *icmpv6)
{
	return read_be16(&icmpv6[SCHC_ICMPV6_ECHO_SEQ_OFFSET]);
}

static const uint8_t *icmpv6_echo_tail(const uint8_t *icmpv6)
{
	return &icmpv6[SCHC_ICMPV6_ECHO_TAIL_OFFSET];
}

static uint8_t *icmpv6_echo_tail_mut(uint8_t *icmpv6)
{
	return &icmpv6[SCHC_ICMPV6_ECHO_TAIL_OFFSET];
}

static void icmpv6_echo_write_body(uint8_t *icmpv6, uint16_t id, uint16_t seq)
{
	write_be16(&icmpv6[SCHC_ICMPV6_ECHO_ID_OFFSET], id);
	write_be16(&icmpv6[SCHC_ICMPV6_ECHO_SEQ_OFFSET], seq);
}

static uint8_t rpl_instance(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_INSTANCE_OFFSET];
}

static uint8_t rpl_dio_version(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_DIO_VERSION_OFFSET];
}

static uint16_t rpl_dio_rank(const uint8_t *rpl)
{
	return read_be16(&rpl[SCHC_RPL_DIO_RANK_OFFSET]);
}

static uint8_t rpl_dio_gmop(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_DIO_GMOP_OFFSET];
}

static uint8_t rpl_dio_dtsn(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_DIO_DTSN_OFFSET];
}

static const uint8_t *rpl_dio_dodagid(const uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DIO_DODAGID_OFFSET];
}

static const uint8_t *rpl_dio_tail(const uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DIO_BASE_LEN];
}

static uint8_t *rpl_dio_tail_mut(uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DIO_BASE_LEN];
}

static void rpl_dio_write_base(uint8_t *rpl, uint8_t instance,
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

static uint8_t rpl_dao_kd_flags(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_DAO_KD_FLAGS_OFFSET];
}

static uint8_t rpl_dao_sequence(const uint8_t *rpl)
{
	return rpl[SCHC_RPL_DAO_SEQUENCE_OFFSET];
}

static const uint8_t *rpl_dao_dodagid(const uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DAO_DODAGID_OFFSET];
}

static const uint8_t *rpl_dao_tail(const uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN];
}

static uint8_t *rpl_dao_tail_mut(uint8_t *rpl)
{
	return &rpl[SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN];
}

static void rpl_dao_write_base(uint8_t *rpl, uint8_t instance,
			       uint8_t kd_flags, uint8_t seq,
			       const uint8_t dodagid[16])
{
	rpl[SCHC_RPL_INSTANCE_OFFSET] = instance;
	rpl[SCHC_RPL_DAO_KD_FLAGS_OFFSET] = kd_flags;
	rpl[SCHC_RPL_DAO_RESERVED_OFFSET] = 0;
	rpl[SCHC_RPL_DAO_SEQUENCE_OFFSET] = seq;
	memcpy(&rpl[SCHC_RPL_DAO_DODAGID_OFFSET], dodagid, SCHC_RPL_DODAGID_LEN);
}

static int validate_ipv6_transport_lengths(const uint8_t *packet, size_t pkt_len)
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

/* ─── checksum helpers ────────────────────────────────────────────────────── */

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
static int udp_checksum(const uint8_t src[16], const uint8_t dst[16],
			uint16_t src_port, uint16_t dst_port,
			const uint8_t *payload, size_t payload_len,
			uint16_t *cksum_out)
{
	/* UDP length field is 16 bits; header is 8 bytes, max payload is 65527 */
	if (payload_len > UINT16_MAX - 8) {
		return -1;
	}
	uint16_t udp_len = (uint16_t)(8 + payload_len);
	uint32_t sum = pseudo_sum(src, dst, IPV6_NH_UDP, udp_len);

	sum = oc_add(sum, src_port);
	sum = oc_add(sum, dst_port);
	sum = oc_add(sum, udp_len);
	/* checksum field (0 during computation) */
	sum = oc_add(sum, checksum_bytes(payload, payload_len));
	*cksum_out = finalize_checksum(sum);
	return 0;
}

static uint16_t icmpv6_checksum(const uint8_t src[16], const uint8_t dst[16],
				const uint8_t *icmpv6_payload, uint16_t len)
{
	uint32_t sum = pseudo_sum(src, dst, IPV6_NH_ICMPV6, len);

	sum = oc_add(sum, checksum_bytes(icmpv6_payload, len));
	return finalize_checksum(sum);
}

/* ─── per-rule compress ───────────────────────────────────────────────────── */

/*
 * Compression functions follow a common pattern:
 *
 *   1. Validate minimum input length for the rule
 *   2. Write rule ID to out[0]
 *   3. Initialize bit_writer at out[1]
 *   4. For link-local rules: call compress_link_local_header() helper
 *      For global rules: write full addresses inline
 *   5. Write protocol-specific fields
 *   6. Call compress_finish() to copy tail and return total length
 *
 * This pattern ensures consistent bounds checking and avoids code duplication
 * for the common prologue (link-local header) and epilogue (tail copy).
 */

/**
 * Common epilogue for compress_* functions: compute output size, bounds-check,
 * copy the uncompressed tail, and return the total compressed length.
 *
 * @param w         Pointer to bit_writer (already populated with residue)
 * @param out       Output buffer (rule ID already at out[0])
 * @param out_len   Size of output buffer
 * @param tail      Pointer to uncompressed tail data
 * @param tail_len  Length of tail data
 * @return          Total compressed length on success, SCHC_ERR_BUFFER_TOO_SMALL on failure
 */
static int compress_finish(const struct schc_bit_writer *w, uint8_t *out,
			   size_t out_len, const uint8_t *tail, size_t tail_len)
{
	size_t residue_len = schc_bit_writer_byte_len(w);
	size_t tail_start = 1 + residue_len;
	size_t needed = tail_start + tail_len;

	if (needed > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	memcpy(&out[tail_start], tail, tail_len);
	return (int)needed;
}

/**
 * Common prologue for link-local compress_* functions: write hop_limit and
 * src/dst IIDs (64 bits each).
 *
 * @param w          Pointer to initialized bit_writer
 * @param hop_limit  IPv6 hop limit
 * @param src        Source IPv6 address (16 bytes)
 * @param dst        Destination IPv6 address (16 bytes)
 * @return           0 on success, -1 on buffer overflow
 */
static int compress_link_local_header(struct schc_bit_writer *w, uint8_t hop_limit,
				      const uint8_t *src, const uint8_t *dst)
{
	if (schc_bit_writer_write(w, hop_limit, 8) < 0 ||
	    schc_bit_writer_write128(w, &src[8], 64) < 0 ||
	    schc_bit_writer_write128(w, &dst[8], 64) < 0) {
		return -1;
	}
	return 0;
}

/**
 * Rule 0 (link-local) and Rule 1 (global): IPv6 + UDP + CoAP.
 */
static int compress_coap(const uint8_t *packet, size_t pkt_len,
			 uint8_t *out, size_t out_len, uint8_t rule_id)
{
	if (pkt_len < IPV6_HDR_LEN + UDP_HDR_LEN + SCHC_COAP_FIXED_LEN) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = ipv6_hop_limit(packet);
	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);

	/* Validate addresses match rule to prevent silent corruption. */
	if (rule_id == SCHC_RULE_LINK_LOCAL_COAP || rule_id == SCHC_RULE_LINK_LOCAL_OSCORE) {
		if (!is_link_local(src) || !is_link_local(dst)) {
			return SCHC_ERR_NO_MATCHING_RULE;
		}
	} else if (rule_id == SCHC_RULE_GLOBAL_COAP || rule_id == SCHC_RULE_GLOBAL_OSCORE) {
		if (!is_global(src) || !is_global(dst)) {
			return SCHC_ERR_NO_MATCHING_RULE;
		}
	}

	const uint8_t *udp = ipv6_payload(packet);
	uint16_t src_port = udp_src_port(udp);
	uint16_t dst_port = udp_dst_port(udp);
	const uint8_t *coap = udp_payload(udp);
	if (coap_version(coap) != 1) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}
	uint8_t type = coap_type(coap);
	uint8_t tkl = coap_tkl(coap);
	uint8_t code = coap_code(coap);
	uint16_t mid = coap_mid(coap);
	const uint8_t *tail = coap_tail(coap);
	size_t tail_len = pkt_len - IPV6_HDR_LEN - UDP_HDR_LEN -
			  SCHC_COAP_FIXED_LEN;

	if (out_len == 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = rule_id;

	struct schc_bit_writer w;
	schc_bit_writer_init(&w, &out[1], out_len - 1);

	if (schc_bit_writer_write(&w, hop_limit, 8) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	if (rule_id == SCHC_RULE_LINK_LOCAL_COAP || rule_id == SCHC_RULE_LINK_LOCAL_OSCORE) {
		if (schc_bit_writer_write128(&w, &src[8], 64) < 0 ||
		    schc_bit_writer_write128(&w, &dst[8], 64) < 0) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
	} else {
		if (schc_bit_writer_write128(&w, src, 128) < 0 ||
		    schc_bit_writer_write128(&w, dst, 128) < 0) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
	}

	if (schc_bit_writer_write(&w, src_port, 16) < 0 ||
	    schc_bit_writer_write(&w, dst_port, 16) < 0 ||
	    schc_bit_writer_write(&w, type, 2) < 0 ||
	    schc_bit_writer_write(&w, tkl, 4) < 0 ||
	    schc_bit_writer_write(&w, code, 8) < 0 ||
	    schc_bit_writer_write(&w, mid, 16) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/**
 * Rule 2: link-local IPv6 + ICMPv6 Echo.
 */
static int compress_icmpv6_echo(const uint8_t *packet, size_t pkt_len,
				uint8_t *out, size_t out_len)
{
	if (pkt_len < IPV6_HDR_LEN + SCHC_ICMPV6_ECHO_TAIL_OFFSET) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = ipv6_hop_limit(packet);
	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *icmp = ipv6_payload(packet);
	uint8_t type = icmpv6_type(icmp);
	uint16_t id = icmpv6_echo_id(icmp);
	uint16_t seq = icmpv6_echo_seq(icmp);
	const uint8_t *tail = icmpv6_echo_tail(icmp);
	size_t tail_len = pkt_len - IPV6_HDR_LEN - SCHC_ICMPV6_ECHO_TAIL_OFFSET;

	if (out_len < 1) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_ICMPV6_ECHO;

	struct schc_bit_writer w;
	schc_bit_writer_init(&w, &out[1], out_len - 1);

	if (compress_link_local_header(&w, hop_limit, src, dst) < 0 ||
	    schc_bit_writer_write(&w, type, 8) < 0 ||
	    schc_bit_writer_write(&w, id, 16) < 0 ||
	    schc_bit_writer_write(&w, seq, 16) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/**
 * Rule 3: link-local IPv6 + ICMPv6 RPL DIO.
 */
static int compress_rpl_dio(const uint8_t *packet, size_t pkt_len,
			    uint8_t *out, size_t out_len)
{
	if (pkt_len < IPV6_HDR_LEN + SCHC_ICMPV6_BODY_OFFSET +
		      SCHC_RPL_DIO_BASE_LEN) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = ipv6_hop_limit(packet);
	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *rpl = icmpv6_body(ipv6_payload(packet));
	uint8_t instance = rpl_instance(rpl);
	uint8_t version = rpl_dio_version(rpl);
	uint16_t rank = rpl_dio_rank(rpl);
	uint8_t gmop = rpl_dio_gmop(rpl);
	uint8_t dtsn = rpl_dio_dtsn(rpl);
	const uint8_t *dodagid = rpl_dio_dodagid(rpl);
	const uint8_t *tail = rpl_dio_tail(rpl);
	size_t tail_len = pkt_len - IPV6_HDR_LEN - SCHC_ICMPV6_BODY_OFFSET -
			  SCHC_RPL_DIO_BASE_LEN;

	if (out_len < 1) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_RPL_DIO;

	struct schc_bit_writer w;
	schc_bit_writer_init(&w, &out[1], out_len - 1);

	if (compress_link_local_header(&w, hop_limit, src, dst) < 0 ||
	    schc_bit_writer_write(&w, instance, 8) < 0 ||
	    schc_bit_writer_write(&w, version, 8) < 0 ||
	    schc_bit_writer_write(&w, rank, 16) < 0 ||
	    schc_bit_writer_write(&w, gmop, 8) < 0 ||
	    schc_bit_writer_write(&w, dtsn, 8) < 0 ||
	    schc_bit_writer_write128(&w, dodagid, 128) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/**
 * Rule 4: link-local IPv6 + ICMPv6 RPL DAO with DODAGID.
 */
static int compress_rpl_dao(const uint8_t *packet, size_t pkt_len,
			    uint8_t *out, size_t out_len)
{
	if (pkt_len < IPV6_HDR_LEN + SCHC_ICMPV6_BODY_OFFSET +
		      SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = ipv6_hop_limit(packet);
	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *rpl = icmpv6_body(ipv6_payload(packet));
	uint8_t instance = rpl_instance(rpl);
	uint8_t kd_flags = rpl_dao_kd_flags(rpl);
	uint8_t seq = rpl_dao_sequence(rpl);
	const uint8_t *dodagid = rpl_dao_dodagid(rpl);
	const uint8_t *tail = rpl_dao_tail(rpl);
	size_t tail_len = pkt_len - IPV6_HDR_LEN - SCHC_ICMPV6_BODY_OFFSET -
			  SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN;

	if (out_len < 1) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_RPL_DAO;

	struct schc_bit_writer w;
	schc_bit_writer_init(&w, &out[1], out_len - 1);

	if (compress_link_local_header(&w, hop_limit, src, dst) < 0 ||
	    schc_bit_writer_write(&w, instance, 8) < 0 ||
	    schc_bit_writer_write(&w, kd_flags, 8) < 0 ||
	    schc_bit_writer_write(&w, seq, 8) < 0 ||
	    schc_bit_writer_write128(&w, dodagid, 128) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/* ─── per-rule decompress ─────────────────────────────────────────────────── */

static int decompress_coap(const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len, uint8_t rule_id)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * - Rule 0 (link-local): 8 + 64 + 64 + 16 + 16 + 2 + 4 + 8 + 16 = 198 bits = 25 bytes
	 * - Rule 1 (global):     8 + 128 + 128 + 16 + 16 + 2 + 4 + 8 + 16 = 326 bits = 41 bytes
	 */
	size_t min_residue = 25;
	if (data_len < 1 + min_residue) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint8_t src[16], dst[16];

	if (rule_id == SCHC_RULE_LINK_LOCAL_COAP || rule_id == SCHC_RULE_LINK_LOCAL_OSCORE) {
		memset(src, 0, 16);
		memset(dst, 0, 16);
		src[0] = 0xFE;
		src[1] = 0x80;
		dst[0] = 0xFE;
		dst[1] = 0x80;
		if (schc_bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
		    schc_bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
			return SCHC_ERR_TOO_SHORT;
		}
	} else {
		if (schc_bit_reader_read_bytes(&r, 128, src, 16) < 0 ||
		    schc_bit_reader_read_bytes(&r, 128, dst, 16) < 0) {
			return SCHC_ERR_TOO_SHORT;
		}
	}

	uint64_t src_port, dst_port, coap_type, coap_tkl, coap_code, coap_mid;
	if (schc_bit_reader_read(&r, 16, &src_port) < 0 ||
	    schc_bit_reader_read(&r, 16, &dst_port) < 0 ||
	    schc_bit_reader_read(&r, 2, &coap_type) < 0 ||
	    schc_bit_reader_read(&r, 4, &coap_tkl) < 0 ||
	    schc_bit_reader_read(&r, 8, &coap_code) < 0 ||
	    schc_bit_reader_read(&r, 16, &coap_mid) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t coap_len = SCHC_COAP_FIXED_LEN + tail_len;
	if (coap_len > UINT16_MAX - UDP_HDR_LEN) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	uint16_t udp_len = UDP_HDR_LEN + coap_len;
	uint16_t ipv6_len = udp_len;
	size_t total = IPV6_HDR_LEN + UDP_HDR_LEN + coap_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	ipv6_write_base(out, ipv6_len, IPV6_NH_UDP, (uint8_t)hop_limit, src, dst);
	uint8_t *udp = ipv6_payload_mut(out);
	udp_write_header(udp, (uint16_t)src_port, (uint16_t)dst_port, udp_len, 0);
	uint8_t *coap = udp_payload_mut(udp);
	coap_write_fixed(coap, (uint8_t)coap_type, (uint8_t)coap_tkl,
			 (uint8_t)coap_code, (uint16_t)coap_mid);
	if (tail_len > 0) {
		memcpy(coap_tail_mut(coap), tail, tail_len);
	}

	uint16_t udp_cksum;
	if (udp_checksum(src, dst, (uint16_t)src_port, (uint16_t)dst_port,
			 coap, coap_len, &udp_cksum) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;  /* Payload too large for UDP */
	}
	udp_write_checksum(udp, udp_cksum);

	return (int)total;
}

static int decompress_icmpv6_echo(const uint8_t *data, size_t data_len,
				  uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 16 + 16 = 176 bits = 22 bytes
	 */
	if (data_len < 1 + 22) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (schc_bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    schc_bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t icmp_type, icmp_id, icmp_seq;
	if (schc_bit_reader_read(&r, 8, &icmp_type) < 0 ||
	    schc_bit_reader_read(&r, 16, &icmp_id) < 0 ||
	    schc_bit_reader_read(&r, 16, &icmp_seq) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t icmp_len = SCHC_ICMPV6_ECHO_TAIL_OFFSET + tail_len;
	if (icmp_len > UINT16_MAX) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	size_t total = IPV6_HDR_LEN + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	ipv6_write_base(out, (uint16_t)icmp_len, IPV6_NH_ICMPV6,
			(uint8_t)hop_limit, src, dst);
	uint8_t *icmp = ipv6_payload_mut(out);
	icmpv6_write_header(icmp, (uint8_t)icmp_type, 0, 0);
	icmpv6_echo_write_body(icmp, (uint16_t)icmp_id, (uint16_t)icmp_seq);
	if (tail_len > 0) {
		memcpy(icmpv6_echo_tail_mut(icmp), tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp, (uint16_t)icmp_len);
	icmpv6_write_checksum(icmp, cksum);

	return (int)total;
}

static int decompress_rpl_dio(const uint8_t *data, size_t data_len,
			      uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 8 + 16 + 8 + 8 + 128 = 312 bits = 39 bytes
	 */
	if (data_len < 1 + 39) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (schc_bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    schc_bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t instance, version, rank, gmop, dtsn;
	uint8_t dodagid[16];

	if (schc_bit_reader_read(&r, 8, &instance) < 0 ||
	    schc_bit_reader_read(&r, 8, &version) < 0 ||
	    schc_bit_reader_read(&r, 16, &rank) < 0 ||
	    schc_bit_reader_read(&r, 8, &gmop) < 0 ||
	    schc_bit_reader_read(&r, 8, &dtsn) < 0 ||
	    schc_bit_reader_read_bytes(&r, 128, dodagid, 16) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t rpl_body_len = SCHC_RPL_DIO_BASE_LEN + tail_len;
	size_t icmp_len = SCHC_ICMPV6_BODY_OFFSET + rpl_body_len;
	if (icmp_len > UINT16_MAX) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	size_t total = IPV6_HDR_LEN + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	ipv6_write_base(out, (uint16_t)icmp_len, IPV6_NH_ICMPV6,
			(uint8_t)hop_limit, src, dst);
	uint8_t *icmp = ipv6_payload_mut(out);
	icmpv6_write_header(icmp, ICMPV6_TYPE_RPL, ICMPV6_CODE_RPL_DIO, 0);
	uint8_t *rpl = icmpv6_body_mut(icmp);
	rpl_dio_write_base(rpl, (uint8_t)instance, (uint8_t)version,
			   (uint16_t)rank, (uint8_t)gmop, (uint8_t)dtsn,
			   dodagid);
	if (tail_len > 0) {
		memcpy(rpl_dio_tail_mut(rpl), tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp, (uint16_t)icmp_len);
	icmpv6_write_checksum(icmp, cksum);

	return (int)total;
}

static int decompress_rpl_dao(const uint8_t *data, size_t data_len,
			      uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 8 + 8 + 128 = 288 bits = 36 bytes
	 */
	if (data_len < 1 + 36) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (schc_bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    schc_bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t instance, kd_flags, seq;
	uint8_t dodagid[16];

	if (schc_bit_reader_read(&r, 8, &instance) < 0 ||
	    schc_bit_reader_read(&r, 8, &kd_flags) < 0 ||
	    schc_bit_reader_read(&r, 8, &seq) < 0 ||
	    schc_bit_reader_read_bytes(&r, 128, dodagid, 16) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t rpl_body_len = SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN + tail_len;
	size_t icmp_len = SCHC_ICMPV6_BODY_OFFSET + rpl_body_len;
	if (icmp_len > UINT16_MAX) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	size_t total = IPV6_HDR_LEN + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	ipv6_write_base(out, (uint16_t)icmp_len, IPV6_NH_ICMPV6,
			(uint8_t)hop_limit, src, dst);
	uint8_t *icmp = ipv6_payload_mut(out);
	icmpv6_write_header(icmp, ICMPV6_TYPE_RPL, ICMPV6_CODE_RPL_DAO, 0);
	uint8_t *rpl = icmpv6_body_mut(icmp);
	rpl_dao_write_base(rpl, (uint8_t)instance, (uint8_t)kd_flags,
			   (uint8_t)seq, dodagid);
	if (tail_len > 0) {
		memcpy(rpl_dao_tail_mut(rpl), tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp, (uint16_t)icmp_len);
	icmpv6_write_checksum(icmp, cksum);

	return (int)total;
}

static int lichen_rule_compress_coap(const struct schc_rule *rule,
				     const uint8_t *packet, size_t pkt_len,
				     uint8_t *out, size_t out_len)
{
	if (pkt_len < IPV6_HDR_LEN || ipv6_version(packet) != 6 ||
	    ipv6_next_header(packet) != IPV6_NH_UDP) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	return compress_coap(packet, pkt_len, out, out_len, rule->rule_id);
}

static int lichen_rule_compress_icmpv6_echo(const struct schc_rule *rule,
					    const uint8_t *packet, size_t pkt_len,
					    uint8_t *out, size_t out_len)
{
	(void)rule;

	if (pkt_len < IPV6_HDR_LEN + SCHC_ICMPV6_ECHO_TAIL_OFFSET ||
	    ipv6_version(packet) != 6 ||
	    ipv6_next_header(packet) != IPV6_NH_ICMPV6) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *icmp = ipv6_payload(packet);
	uint8_t type = icmpv6_type(icmp);

	if ((type != ICMPV6_TYPE_ECHO_REQUEST &&
	     type != ICMPV6_TYPE_ECHO_REPLY) ||
	    icmpv6_code(icmp) != 0 ||
	    !is_link_local(src) ||
	    (!is_link_local(dst) && !is_ula(dst) && !is_global(dst))) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	return compress_icmpv6_echo(packet, pkt_len, out, out_len);
}

static int lichen_rule_compress_rpl_dio(const struct schc_rule *rule,
					const uint8_t *packet, size_t pkt_len,
					uint8_t *out, size_t out_len)
{
	(void)rule;

	if (pkt_len < IPV6_HDR_LEN + SCHC_ICMPV6_BODY_OFFSET +
		      SCHC_RPL_DIO_BASE_LEN ||
	    ipv6_version(packet) != 6 ||
	    ipv6_next_header(packet) != IPV6_NH_ICMPV6) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *icmp = ipv6_payload(packet);

	if (icmpv6_type(icmp) != ICMPV6_TYPE_RPL ||
	    icmpv6_code(icmp) != ICMPV6_CODE_RPL_DIO ||
	    !is_link_local(src) || !is_link_local(dst)) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	return compress_rpl_dio(packet, pkt_len, out, out_len);
}

static int lichen_rule_compress_rpl_dao(const struct schc_rule *rule,
					const uint8_t *packet, size_t pkt_len,
					uint8_t *out, size_t out_len)
{
	(void)rule;

	if (pkt_len < IPV6_HDR_LEN + SCHC_ICMPV6_BODY_OFFSET +
		      SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN ||
	    ipv6_version(packet) != 6 ||
	    ipv6_next_header(packet) != IPV6_NH_ICMPV6) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *icmp = ipv6_payload(packet);

	if (icmpv6_type(icmp) != ICMPV6_TYPE_RPL ||
	    icmpv6_code(icmp) != ICMPV6_CODE_RPL_DAO ||
	    !is_link_local(src) || !is_link_local(dst)) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t kd_flags = rpl_dao_kd_flags(icmpv6_body(icmp));
	if ((kd_flags & 0x40) == 0) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	return compress_rpl_dao(packet, pkt_len, out, out_len);
}

static int lichen_rule_decompress_coap(const struct schc_rule *rule,
				       const uint8_t *data, size_t data_len,
				       uint8_t *out, size_t out_len)
{
	return decompress_coap(data, data_len, out, out_len, rule->rule_id);
}

static int lichen_rule_decompress_icmpv6_echo(const struct schc_rule *rule,
					      const uint8_t *data, size_t data_len,
					      uint8_t *out, size_t out_len)
{
	(void)rule;

	return decompress_icmpv6_echo(data, data_len, out, out_len);
}

static int lichen_rule_decompress_rpl_dio(const struct schc_rule *rule,
					  const uint8_t *data, size_t data_len,
					  uint8_t *out, size_t out_len)
{
	(void)rule;

	return decompress_rpl_dio(data, data_len, out, out_len);
}

static int lichen_rule_decompress_rpl_dao(const struct schc_rule *rule,
					  const uint8_t *data, size_t data_len,
					  uint8_t *out, size_t out_len)
{
	(void)rule;

	return decompress_rpl_dao(data, data_len, out, out_len);
}

/**
 * Rule 5/6: OSCORE-protected CoAP over link-local/global IPv6 + UDP.
 *
 * OSCORE packets have the same structure as regular CoAP packets, but contain
 * the Object-Security option (option 9). The compression is identical to
 * rules 0/1, but using distinct rule IDs allows:
 * - Explicit identification of OSCORE-protected traffic
 * - Future OSCORE-specific compression optimizations
 * - Interoperability markers for security auditing
 */
static int lichen_rule_compress_oscore(const struct schc_rule *rule,
				       const uint8_t *packet, size_t pkt_len,
				       uint8_t *out, size_t out_len)
{
	if (pkt_len < IPV6_HDR_LEN || ipv6_version(packet) != 6 ||
	    ipv6_next_header(packet) != IPV6_NH_UDP) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	if (pkt_len < IPV6_HDR_LEN + UDP_HDR_LEN + SCHC_COAP_FIXED_LEN) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);

	/* Validate addresses match the rule's scope */
	if (rule->rule_id == SCHC_RULE_LINK_LOCAL_OSCORE) {
		if (!is_link_local(src) || !is_link_local(dst)) {
			return SCHC_ERR_NO_MATCHING_RULE;
		}
	} else if (rule->rule_id == SCHC_RULE_GLOBAL_OSCORE) {
		if (!is_global(src) || !is_global(dst)) {
			return SCHC_ERR_NO_MATCHING_RULE;
		}
	}

	/* Check for OSCORE option presence */
	const uint8_t *udp = ipv6_payload(packet);
	const uint8_t *coap = udp_payload(udp);
	size_t coap_len = pkt_len - IPV6_HDR_LEN - UDP_HDR_LEN;

	if (!coap_has_oscore_option(coap, coap_len)) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	/* Compression is identical to regular CoAP */
	return compress_coap(packet, pkt_len, out, out_len, rule->rule_id);
}

static int lichen_rule_decompress_oscore(const struct schc_rule *rule,
					 const uint8_t *data, size_t data_len,
					 uint8_t *out, size_t out_len)
{
	/*
	 * Decompression is identical to regular CoAP rules. The rule ID
	 * in the compressed data determines which decompress function is
	 * called, and the reconstructed packet will contain the OSCORE
	 * option in the tail (unchanged from compression).
	 */
	return decompress_coap(data, data_len, out, out_len, rule->rule_id);
}

static const struct schc_rule lichen_schc_rules[] = {
	/*
	 * OSCORE rules must come before regular CoAP rules so that
	 * OSCORE-protected packets match on rules 5/6, not 0/1.
	 */
	{
		.rule_id = SCHC_RULE_LINK_LOCAL_OSCORE,
		.compress = lichen_rule_compress_oscore,
		.decompress = lichen_rule_decompress_oscore,
	},
	{
		.rule_id = SCHC_RULE_GLOBAL_OSCORE,
		.compress = lichen_rule_compress_oscore,
		.decompress = lichen_rule_decompress_oscore,
	},
	{
		.rule_id = SCHC_RULE_LINK_LOCAL_COAP,
		.compress = lichen_rule_compress_coap,
		.decompress = lichen_rule_decompress_coap,
	},
	{
		.rule_id = SCHC_RULE_GLOBAL_COAP,
		.compress = lichen_rule_compress_coap,
		.decompress = lichen_rule_decompress_coap,
	},
	{
		.rule_id = SCHC_RULE_ICMPV6_ECHO,
		.compress = lichen_rule_compress_icmpv6_echo,
		.decompress = lichen_rule_decompress_icmpv6_echo,
	},
	{
		.rule_id = SCHC_RULE_RPL_DIO,
		.compress = lichen_rule_compress_rpl_dio,
		.decompress = lichen_rule_decompress_rpl_dio,
	},
	{
		.rule_id = SCHC_RULE_RPL_DAO,
		.compress = lichen_rule_compress_rpl_dao,
		.decompress = lichen_rule_decompress_rpl_dao,
	},
};

static const struct schc_profile lichen_schc_profile = {
	.rules = lichen_schc_rules,
	.rule_count = sizeof(lichen_schc_rules) / sizeof(lichen_schc_rules[0]),
	.uncompressed_rule_id = SCHC_RULE_UNCOMPRESSED,
	.use_uncompressed_fallback = true,
};

/* ─── public API ──────────────────────────────────────────────────────────── */

int lichen_schc_compress(const uint8_t *packet, size_t pkt_len,
			 uint8_t *out, size_t out_len)
{
	int ret;

	if (packet == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	if (out == NULL) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	if (pkt_len < IPV6_HDR_LEN || ipv6_version(packet) != 6) {
		/* Not IPv6 - uncompressed fallback */
		/* SECURITY: Check for overflow before addition */
		if (pkt_len > SIZE_MAX - 1) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
		size_t needed = 1 + pkt_len;
		if (out_len < needed) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
		out[0] = SCHC_RULE_UNCOMPRESSED;
		memcpy(&out[1], packet, pkt_len);
		return (int)needed;
	}

	ret = validate_ipv6_transport_lengths(packet, pkt_len);
	if (ret < 0) {
		return ret;
	}

	return schc_compress(&lichen_schc_profile, packet, pkt_len, out, out_len);
}

int lichen_schc_decompress(const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len)
{
	return schc_decompress(&lichen_schc_profile, data, data_len, out, out_len);
}
