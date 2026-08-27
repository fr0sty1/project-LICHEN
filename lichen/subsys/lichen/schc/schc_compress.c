/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_compress.c
 * @brief SCHC compression functions for CoAP, ICMPv6 Echo, and RPL.
 *
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

#include "schc_internal.h"
#include <string.h>

/* ─── compression helpers ─────────────────────────────────────────────────── */

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

/* ─── per-rule compress ───────────────────────────────────────────────────── */

static int compress_global_coap_v3(const uint8_t *packet, size_t pkt_len,
				   uint8_t *out, size_t out_len,
				   uint8_t rule_id)
{
	if (rule_id != SCHC_RULE_GLOBAL_COAP &&
	    rule_id != SCHC_RULE_GLOBAL_OSCORE) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}
	if (pkt_len < IPV6_HDR_LEN + UDP_HDR_LEN + SCHC_COAP_FIXED_LEN) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}
	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *udp = ipv6_payload(packet);
	const uint8_t *coap = udp_payload(udp);
	uint16_t src_port = udp_src_port(udp);
	uint16_t dst_port = udp_dst_port(udp);

	/* Rules 1/6 use the canonical LICHEN Yggdrasil 0200::/8 prefix and
	 * the CoAP 5680..5695 port block (MSB(12)/LSB(4)). */
	if (src[0] != 0x02 || dst[0] != 0x02 ||
	    (src_port >> 4) != (5683u >> 4) ||
	    (dst_port >> 4) != (5683u >> 4)) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	size_t coap_len = pkt_len - IPV6_HDR_LEN - UDP_HDR_LEN;
	uint16_t expected_checksum;
	if (udp_checksum(src, dst, src_port, dst_port, coap, coap_len,
			 &expected_checksum) < 0 ||
	    read_be16(&udp[SCHC_UDP_CHECKSUM_OFFSET]) == 0 ||
	    read_be16(&udp[SCHC_UDP_CHECKSUM_OFFSET]) != expected_checksum) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	uint8_t tkl = coap_tkl(coap);
	if (packet[0] != 0x60 || packet[1] != 0 || packet[2] != 0 ||
	    packet[3] != 0 || coap_version(coap) != 1 || tkl > 8 ||
	    coap_len < SCHC_COAP_FIXED_LEN + (size_t)tkl) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	const uint8_t *tail = coap_tail(coap);
	size_t tail_len = coap_len - SCHC_COAP_FIXED_LEN;
	if (tail_len > SIZE_MAX - 37u || 37u + tail_len > out_len ||
	    37u + tail_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	/* All validation precedes the first write, so failures are atomic. */
	out[0] = rule_id;
	struct schc_bit_writer w;
	schc_bit_writer_init(&w, &out[1], 36);
	if (schc_bit_writer_write(&w, ipv6_hop_limit(packet), 8) < 0 ||
	    schc_bit_writer_write128(&w, &src[1], 120) < 0 ||
	    schc_bit_writer_write128(&w, &dst[1], 120) < 0 ||
	    schc_bit_writer_write(&w, src_port & 0x0Fu, 4) < 0 ||
	    schc_bit_writer_write(&w, dst_port & 0x0Fu, 4) < 0 ||
	    schc_bit_writer_write(&w, coap_type(coap), 2) < 0 ||
	    schc_bit_writer_write(&w, tkl, 4) < 0 ||
	    schc_bit_writer_write(&w, coap_code(coap), 8) < 0 ||
	    schc_bit_writer_write(&w, coap_mid(coap), 16) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

static int compress_link_local_coap_v3(const uint8_t *packet, size_t pkt_len,
				       uint8_t *out, size_t out_len,
				       uint8_t rule_id)
{
	enum { LINK_LOCAL_FIXED_LEN = 23, LINK_LOCAL_RESIDUE_LEN = 22 };

	if (rule_id != SCHC_RULE_LINK_LOCAL_COAP &&
	    rule_id != SCHC_RULE_LINK_LOCAL_OSCORE) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	if (pkt_len < IPV6_HDR_LEN + UDP_HDR_LEN + SCHC_COAP_FIXED_LEN) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}
	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *udp = ipv6_payload(packet);
	const uint8_t *coap = udp_payload(udp);
	uint16_t src_port = udp_src_port(udp);
	uint16_t dst_port = udp_dst_port(udp);
	size_t coap_len = pkt_len - IPV6_HDR_LEN - UDP_HDR_LEN;
	uint8_t tkl = coap_tkl(coap);

	/* Rule 5 elides zero TC/flow, the exact fe80::/64 prefix, and the
	 * upper twelve bits of the 5680..5695 CoAP port block. */
	if (packet[0] != 0x60 || packet[1] != 0 || packet[2] != 0 ||
	    packet[3] != 0 || !is_canonical_link_local(src) ||
	    !is_canonical_link_local(dst) ||
	    (src_port >> 4) != (5683u >> 4) ||
	    (dst_port >> 4) != (5683u >> 4) ||
	    coap_version(coap) != 1 || tkl > 8 ||
	    coap_len < SCHC_COAP_FIXED_LEN + (size_t)tkl) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint16_t expected_checksum;
	if (udp_checksum(src, dst, src_port, dst_port, coap, coap_len,
			 &expected_checksum) < 0 ||
	    read_be16(&udp[SCHC_UDP_CHECKSUM_OFFSET]) == 0 ||
	    read_be16(&udp[SCHC_UDP_CHECKSUM_OFFSET]) != expected_checksum) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	const uint8_t *tail = coap_tail(coap);
	size_t tail_len = coap_len - SCHC_COAP_FIXED_LEN;
	if (tail_len > SIZE_MAX - LINK_LOCAL_FIXED_LEN ||
	    LINK_LOCAL_FIXED_LEN + tail_len > out_len ||
	    LINK_LOCAL_FIXED_LEN + tail_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	/* All validation precedes the first write, so failures are atomic. */
	out[0] = rule_id;
	struct schc_bit_writer w;
	schc_bit_writer_init(&w, &out[1], LINK_LOCAL_RESIDUE_LEN);
	if (compress_link_local_header(&w, ipv6_hop_limit(packet), src, dst) < 0 ||
	    schc_bit_writer_write(&w, src_port & 0x0Fu, 4) < 0 ||
	    schc_bit_writer_write(&w, dst_port & 0x0Fu, 4) < 0 ||
	    schc_bit_writer_write(&w, coap_type(coap), 2) < 0 ||
	    schc_bit_writer_write(&w, tkl, 4) < 0 ||
	    schc_bit_writer_write(&w, coap_code(coap), 8) < 0 ||
	    schc_bit_writer_write(&w, coap_mid(coap), 16) < 0) {
		/* The residue buffer is the exact capacity for these fixed fields. */
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/** Rule 0/1 and their OSCORE-layout peers: IPv6 + UDP + CoAP. */
int compress_coap(const uint8_t *packet, size_t pkt_len,
		  uint8_t *out, size_t out_len, uint8_t rule_id)
{
	if (rule_id == SCHC_RULE_LINK_LOCAL_COAP ||
	    rule_id == SCHC_RULE_LINK_LOCAL_OSCORE) {
		return compress_link_local_coap_v3(packet, pkt_len, out, out_len,
					   rule_id);
	}
	if (rule_id == SCHC_RULE_GLOBAL_COAP ||
	    rule_id == SCHC_RULE_GLOBAL_OSCORE) {
		return compress_global_coap_v3(packet, pkt_len, out, out_len,
					       rule_id);
	}
	return SCHC_ERR_NO_MATCHING_RULE;
}

/**
 * Rule 2: link-local IPv6 + ICMPv6 Echo.
 */
int compress_icmpv6_echo(const uint8_t *packet, size_t pkt_len,
			 uint8_t *out, size_t out_len)
{
	if (pkt_len < IPV6_HDR_LEN + SCHC_ICMPV6_ECHO_TAIL_OFFSET ||
	    packet[0] != 0x60 || packet[1] != 0 || packet[2] != 0 ||
	    packet[3] != 0) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = ipv6_hop_limit(packet);
	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *icmp = ipv6_payload(packet);
	uint8_t type = icmpv6_type(icmp);
	if (!is_canonical_link_local(src) || !is_canonical_link_local(dst) ||
	    (type != ICMPV6_TYPE_ECHO_REQUEST && type != ICMPV6_TYPE_ECHO_REPLY) ||
	    icmpv6_code(icmp) != 0) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}
	uint16_t id = icmpv6_echo_id(icmp);
	uint16_t seq = icmpv6_echo_seq(icmp);
	const uint8_t *tail = icmpv6_echo_tail(icmp);
	size_t tail_len = pkt_len - IPV6_HDR_LEN - SCHC_ICMPV6_ECHO_TAIL_OFFSET;

	if (tail_len > SIZE_MAX - 23u || 23u + tail_len > out_len ||
	    23u + tail_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_ICMPV6_ECHO;

	struct schc_bit_writer w;
	schc_bit_writer_init(&w, &out[1], 22);

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
int compress_rpl_dio(const uint8_t *packet, size_t pkt_len,
		     uint8_t *out, size_t out_len)
{
	if (pkt_len < IPV6_HDR_LEN + SCHC_ICMPV6_BODY_OFFSET +
		      SCHC_RPL_DIO_BASE_LEN ||
	    packet[0] != 0x60 || packet[1] != 0 || packet[2] != 0 ||
	    packet[3] != 0) {
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
	if (!is_canonical_link_local(src) || !is_canonical_link_local(dst) ||
	    rpl[SCHC_RPL_DIO_FLAGS_OFFSET] != 0 ||
	    rpl[SCHC_RPL_DIO_RESERVED_OFFSET] != 0) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}
	const uint8_t *dodagid = rpl_dio_dodagid(rpl);
	const uint8_t *tail = rpl_dio_tail(rpl);
	size_t tail_len = pkt_len - IPV6_HDR_LEN - SCHC_ICMPV6_BODY_OFFSET -
			  SCHC_RPL_DIO_BASE_LEN;

	if (tail_len > SIZE_MAX - 40u || 40u + tail_len > out_len ||
	    40u + tail_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_RPL_DIO;

	struct schc_bit_writer w;
	schc_bit_writer_init(&w, &out[1], 39);

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
int compress_rpl_dao(const uint8_t *packet, size_t pkt_len,
		     uint8_t *out, size_t out_len)
{
	if (pkt_len < IPV6_HDR_LEN + SCHC_ICMPV6_BODY_OFFSET +
		      SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN ||
	    packet[0] != 0x60 || packet[1] != 0 || packet[2] != 0 ||
	    packet[3] != 0) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = ipv6_hop_limit(packet);
	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *rpl = icmpv6_body(ipv6_payload(packet));
	uint8_t instance = rpl_instance(rpl);
	uint8_t kd_flags = rpl_dao_kd_flags(rpl);
	if (!is_canonical_link_local(src) || !is_canonical_link_local(dst) ||
	    (kd_flags & 0x40u) == 0u || rpl[SCHC_RPL_DAO_RESERVED_OFFSET] != 0) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}
	uint8_t seq = rpl_dao_sequence(rpl);
	const uint8_t *dodagid = rpl_dao_dodagid(rpl);
	const uint8_t *tail = rpl_dao_tail(rpl);
	size_t tail_len = pkt_len - IPV6_HDR_LEN - SCHC_ICMPV6_BODY_OFFSET -
			  SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN;

	if (tail_len > SIZE_MAX - 37u || 37u + tail_len > out_len ||
	    37u + tail_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_RPL_DAO;

	struct schc_bit_writer w;
	schc_bit_writer_init(&w, &out[1], 36);

	if (compress_link_local_header(&w, hop_limit, src, dst) < 0 ||
	    schc_bit_writer_write(&w, instance, 8) < 0 ||
	    schc_bit_writer_write(&w, kd_flags, 8) < 0 ||
	    schc_bit_writer_write(&w, seq, 8) < 0 ||
	    schc_bit_writer_write128(&w, dodagid, 128) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/**
 * Rule 7: IPv6 + UDP + MQTT-SN (port 10883).
 */
int compress_mqtt_sn(const uint8_t *packet, size_t pkt_len,
		     uint8_t *out, size_t out_len)
{
	if (pkt_len < IPV6_HDR_LEN + UDP_HDR_LEN ||
	    packet[0] != 0x60 || packet[1] != 0 || packet[2] != 0 ||
	    packet[3] != 0 || ipv6_next_header(packet) != IPV6_NH_UDP) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	const uint8_t *src = ipv6_src(packet);
	const uint8_t *dst = ipv6_dst(packet);
	const uint8_t *udp = ipv6_payload(packet);
	uint16_t src_port = udp_src_port(udp);
	uint16_t dst_port = udp_dst_port(udp);

	if (src_port != MQTT_SN_PORT && dst_port != MQTT_SN_PORT) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}
	if (validate_rule7_addresses(src, dst) < 0) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	size_t payload_len = pkt_len - IPV6_HDR_LEN - UDP_HDR_LEN;
	uint16_t expected_checksum;
	if (udp_checksum(src, dst, src_port, dst_port, udp_payload(udp),
			 payload_len, &expected_checksum) < 0 ||
	    read_be16(&udp[SCHC_UDP_CHECKSUM_OFFSET]) == 0 ||
	    read_be16(&udp[SCHC_UDP_CHECKSUM_OFFSET]) != expected_checksum) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	bool link_local_mode = is_canonical_link_local(src) &&
			       is_canonical_link_local(dst);
	size_t residue_len = link_local_mode ? 20u : 36u;
	if (payload_len > SIZE_MAX - 1u - residue_len ||
	    1u + residue_len + payload_len > SCHC_FRAGMENT_MAX_PACKET_SIZE ||
	    out_len < 1u + residue_len + payload_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	out[0] = SCHC_RULE_MQTT_SN;
	struct schc_bit_writer w;
	schc_bit_writer_init(&w, &out[1], residue_len);
	if (schc_bit_writer_write(&w, ipv6_hop_limit(packet), 8) < 0 ||
	    schc_bit_writer_write(&w, link_local_mode ? 0 : 1, 1) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	if (link_local_mode) {
		if (schc_bit_writer_write128(&w, &src[8], 64) < 0 ||
		    schc_bit_writer_write128(&w, &dst[8], 64) < 0) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
	} else if (schc_bit_writer_write128(&w, src, 128) < 0 ||
		   schc_bit_writer_write128(&w, dst, 128) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	uint8_t direction = src_port == MQTT_SN_PORT ? 0 : 1;
	uint16_t other_port = direction == 0 ? dst_port : src_port;
	if (schc_bit_writer_write(&w, direction, 1) < 0 ||
	    schc_bit_writer_write(&w, other_port, 16) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, udp_payload(udp), payload_len);
}
