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

#include "schc_internal.h"
#include <string.h>

/* ─── OSCORE detection ────────────────────────────────────────────────────── */

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

/* ─── rule wrappers ───────────────────────────────────────────────────────── */

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
	    (!is_link_local(dst) && !is_ula(dst) && dst[0] != 0x02 && !is_global(dst))) {
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

/* ─── rule table ──────────────────────────────────────────────────────────── */

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
