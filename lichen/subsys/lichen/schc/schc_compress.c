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

/**
 * Rule 0 (link-local) and Rule 1 (global): IPv6 + UDP + CoAP.
 */
int compress_coap(const uint8_t *packet, size_t pkt_len,
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
		if (!(is_global(src) || is_ula(src)) || !(is_global(dst) || is_ula(dst))) {
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

	if (schc_bit_writer_write128(&w, &src[8], 64) < 0 ||
	    schc_bit_writer_write128(&w, &dst[8], 64) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
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
int compress_icmpv6_echo(const uint8_t *packet, size_t pkt_len,
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
int compress_rpl_dio(const uint8_t *packet, size_t pkt_len,
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
int compress_rpl_dao(const uint8_t *packet, size_t pkt_len,
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
