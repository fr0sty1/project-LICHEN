/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/schc.h
 * @brief SCHC header compression (RFC 8724) for LICHEN
 *
 * Compresses IPv6/UDP/CoAP and IPv6/ICMPv6 packets using Static Context
 * Header Compression. Rules match constants.toml [schc.rule_id]:
 *
 *   Rule 0: link-local IPv6 + UDP + CoAP
 *   Rule 1: global IPv6 + UDP + CoAP
 *   Rule 2: ICMPv6 Echo (link-local)
 *   Rule 3: RPL DIO (link-local ICMPv6)
 *   Rule 4: RPL DAO (link-local ICMPv6)
 *   Rule 255: uncompressed passthrough
 *
 * Compression target: 48+ byte IPv6/UDP header to 3-6 bytes.
 *
 * Design decisions captured here are part of the wire contract:
 *
 * - This API is packet-oriented. Callers pass a complete IPv6 packet and get
 *   one complete SCHC datagram. It is not a streaming parser.
 *
 * - Rule IDs are stable interop values, not local enum ordinals. Changing a
 *   rule ID requires updating the Rust, Python, C, and JSON test vectors
 *   together.
 *
 * - Rule selection is deterministic. The compressor tries specific LICHEN
 *   profiles first and uses rule 255 only when no compression profile matches.
 *   Rule 255 is an interop fallback, not a best-effort compression rule.
 *
 * - Unknown IPv6 shapes intentionally fall back to uncompressed passthrough.
 *   That keeps the link usable while making missing compression rules visible
 *   through size and rule ID.
 *
 * - Checksums and lengths are reconstructed on decompression instead of being
 *   carried when the rule can derive them. Any future generic SCHC module must
 *   preserve byte-for-byte output for the current test vectors.
 *
 * - The generic RFC 8724 engine and LICHEN-specific rules should remain
 *   separable. LICHEN profiles decide which IPv6/UDP/CoAP/RPL shapes are in
 *   scope; the SCHC engine should only apply rule mechanics.
 *
 * - Packet-header access in implementations should use named constants and
 *   accessor helpers/macros rather than naked stride offsets such as
 *   packet[45]. Fixed-format headers are positional by design, but duplicated
 *   magic offsets are not acceptable as the code evolves.
 *
 * @warning SCHC compression can leak information through compressed size
 * variations (compression oracle attack). In LICHEN, OSCORE encryption
 * happens BEFORE SCHC compression, so encrypted payloads appear opaque.
 * Header field values (ports, addresses) are compressed but not encrypted
 * and may leak metadata. For high-security deployments, pad payloads to
 * fixed sizes before OSCORE encryption.
 */

#ifndef LICHEN_SCHC_H_
#define LICHEN_SCHC_H_

#include <stdint.h>
#include <stddef.h>

#ifndef LICHEN_WARN_UNUSED_RESULT
#if defined(__GNUC__) || defined(__clang__)
#define LICHEN_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define LICHEN_WARN_UNUSED_RESULT
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** SCHC rule IDs matching constants.toml */
#define SCHC_RULE_LINK_LOCAL_COAP  0
#define SCHC_RULE_GLOBAL_COAP      1
#define SCHC_RULE_ICMPV6_ECHO      2
#define SCHC_RULE_RPL_DIO          3
#define SCHC_RULE_RPL_DAO          4
#define SCHC_RULE_UNCOMPRESSED     255

/** Error codes */
enum schc_error {
	SCHC_OK = 0,
	SCHC_ERR_NO_MATCHING_RULE = -1,
	SCHC_ERR_BUFFER_TOO_SMALL = -2,
	SCHC_ERR_UNKNOWN_RULE_ID = -3,
	SCHC_ERR_TOO_SHORT = -4,
};

/**
 * @brief Compress an IPv6 packet using SCHC.
 *
 * Selects the best matching rule and writes the compressed residue to @p out.
 * Falls back to rule 255 (uncompressed) if no rule matches.
 *
 * @warning CoAP payloads MUST be OSCORE-protected before compression.
 * Compressing plaintext enables compression oracle attacks.
 *
 * @param[in]  packet    Full IPv6 packet
 * @param[in]  pkt_len   Length of packet
 * @param[out] out       Output buffer for compressed data
 * @param[in]  out_len   Size of output buffer
 * @return Number of bytes written to @p out, or negative error code
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_schc_compress(const uint8_t *packet, size_t pkt_len,
			 uint8_t *out, size_t out_len);

/**
 * @brief Decompress a SCHC packet to full IPv6.
 *
 * Reconstructs the original IPv6 packet from compressed SCHC data,
 * including recomputing checksums.
 *
 * @param[in]  data      Compressed SCHC data (rule_id + residue + tail)
 * @param[in]  data_len  Length of compressed data
 * @param[out] out       Output buffer for reconstructed IPv6 packet
 * @param[in]  out_len   Size of output buffer
 * @return Number of bytes written to @p out, or negative error code
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_schc_decompress(const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len);

/**
 * @brief Get the rule ID from compressed SCHC data.
 *
 * @param[in] data  Compressed SCHC data
 * @return Rule ID (first byte), or -1 if data is empty
 */
static inline int lichen_schc_rule_id(const uint8_t *data, size_t len)
{
	return (len > 0) ? data[0] : -1;
}

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SCHC_H_ */
