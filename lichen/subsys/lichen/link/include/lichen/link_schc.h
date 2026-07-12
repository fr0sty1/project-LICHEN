/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/link_schc.h
 * @brief SCHC compression integration for LICHEN link layer
 *
 * This header provides thin wrappers around the SCHC subsystem for use
 * by the link layer TX/RX paths. The frame payload field carries SCHC-
 * compressed IPv6 packets:
 *
 *   TX path: IPv6 packet -> lichen_link_compress() -> frame.payload
 *   RX path: frame.payload -> lichen_link_decompress() -> IPv6 packet
 *
 * The SCHC subsystem implements RFC 8724 Static Context Header Compression
 * with rules optimized for LICHEN's link-local CoAP, global CoAP, ICMPv6
 * Echo, and RPL DIO/DAO traffic patterns.
 *
 * Build wiring:
 *   - CONFIG_LICHEN_LINK selects CONFIG_LICHEN_SCHC automatically
 *   - link/CMakeLists.txt includes schc/include for header access
 */

#ifndef LICHEN_LINK_SCHC_H_
#define LICHEN_LINK_SCHC_H_

#include <stdint.h>
#include <stddef.h>
#include <lichen/schc.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compress an IPv6 packet for link-layer transmission.
 *
 * Applies SCHC compression (RFC 8724) to reduce IPv6/UDP/CoAP or
 * IPv6/ICMPv6 headers from ~48 bytes to 3-6 bytes. Falls back to
 * uncompressed (rule 255) if no rule matches.
 *
 * @param[in]  ipv6      Full IPv6 packet to compress
 * @param[in]  ipv6_len  Length of IPv6 packet
 * @param[out] out       Output buffer for compressed data
 * @param[in]  out_max   Size of output buffer
 * @return Number of bytes written to @p out, or negative error code:
 *         - SCHC_ERR_BUFFER_TOO_SMALL (-2): output buffer too small
 */
static inline int lichen_link_compress(const uint8_t *_Nonnull ipv6, size_t ipv6_len,
				       uint8_t *_Nonnull out, size_t out_max)
{
	return lichen_schc_compress(ipv6, ipv6_len, out, out_max);
}

/**
 * @brief Decompress SCHC data to a full IPv6 packet.
 *
 * Reconstructs the original IPv6 packet from SCHC-compressed data,
 * including recomputing UDP/ICMPv6 checksums.
 *
 * @param[in]  schc      Compressed SCHC data (rule_id + residue + tail)
 * @param[in]  schc_len  Length of compressed data
 * @param[out] out       Output buffer for reconstructed IPv6 packet
 * @param[in]  out_max   Size of output buffer
 * @return Number of bytes written to @p out, or negative error code:
 *         - SCHC_ERR_BUFFER_TOO_SMALL (-2): output buffer too small
 *         - SCHC_ERR_UNKNOWN_RULE_ID (-3): unrecognized rule in data
 *         - SCHC_ERR_TOO_SHORT (-4): truncated compressed data
 */
static inline int lichen_link_decompress(const uint8_t *_Nonnull schc, size_t schc_len,
					 uint8_t *_Nonnull out, size_t out_max)
{
	return lichen_schc_decompress(schc, schc_len, out, out_max);
}

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LINK_SCHC_H_ */
