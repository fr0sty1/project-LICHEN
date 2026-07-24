/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_link_tx.c
 * @brief LICHEN frame TX path
 *
 * Takes an IPv6 packet, compresses with SCHC, builds a LICHEN frame with
 * optional Schnorr-48 signature, and outputs the wire-ready frame.
 */

#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/l2_payload.h>
#include <lichen/schc.h>
#include <lichen/schnorr48.h>
#include <string.h>

/* Error codes */
#include <lichen/errno.h>

int lichen_link_tx(struct lichen_link_ctx *ctx,
		   const uint8_t *ipv6_pkt, size_t ipv6_len,
		   const uint8_t *dst_eui64,
		   uint8_t *out_frame, size_t *out_len)
{
	uint8_t compressed[256];
	uint8_t l2_payload[256];
	uint8_t payload_buf[256];
	uint8_t signature[SCHNORR48_SIG_LEN];
	int compressed_len;
	size_t l2_payload_len;
	size_t payload_len;
	uint8_t addr_mode;
	uint8_t dst_addr[8];
	uint8_t dst_addr_len;
	uint8_t epoch;
	uint16_t seqnum;
	size_t off;
	size_t frame_body_len;
	uint8_t mic_len;
	bool signing_enabled;
	int ret;

	if (ctx == NULL || ipv6_pkt == NULL || out_frame == NULL || out_len == NULL) {
		return -EINVAL;
	}

	if (IS_ENABLED(CONFIG_LICHEN_TDMA)) {
		struct lichen_tdma_ctx tdma = {0};
		if (!tdma_tx_allowed(&tdma, 0)) {
			return -EBUSY;
		}
	}

	if (!ctx->has_key) {
		return -ENOKEY;
	}

	/*
	 * Validate IPv6 packet length (python-ano.11):
	 * - Must be > 0 (empty packets are invalid)
	 * - Must be <= 1280 (IPv6 minimum MTU per RFC 8200)
	 */
	if (ipv6_len == 0 || ipv6_len > 1280) {
		return -EINVAL;
	}

	/*
	 * Minimum output buffer size check (assumes signature):
	 * 1+1+1+2+(0-8)+payload+48
	 */
	if (*out_len < 16) {
		return -ENOMEM;
	}

	/* Step 1: Compress IPv6 packet with SCHC */
	compressed_len = lichen_schc_compress(ipv6_pkt, ipv6_len,
					      compressed, sizeof(compressed));
	if (compressed_len < 0) {
		return compressed_len;
	}
	if ((size_t)compressed_len + 1U > sizeof(l2_payload)) {
		return -EMSGSIZE;
	}
	l2_payload[0] = LICHEN_L2_DISPATCH_SCHC;
	memcpy(&l2_payload[1], compressed, (size_t)compressed_len);
	l2_payload_len = (size_t)compressed_len + 1U;

	/* Determine address mode and destination */
	if (dst_eui64 != NULL) {
		addr_mode = LICHEN_ADDR_EUI64;
		memcpy(dst_addr, dst_eui64, 8);
		dst_addr_len = 8;
	} else {
		addr_mode = LICHEN_ADDR_BROADCAST;
		dst_addr_len = 0;
	}

	/* LLSec byte: S=1 (bit 5), MicLength=0 (bits 2-4 cleared per spec and
	 * Rust). Matches frame.c:162, link_layer.rs:486, 09-packets-timing.md:48
	 * (0x21 example). LLSec included in signed_data; fixes interop. */
	uint8_t llsec = (addr_mode & 0x03U) | 0x20U;

	/* Preflight size checks BEFORE consuming nonce (deterministic TX
	 * requirement; matches Python/Rust frame_length calc). */
	if (l2_payload_len > sizeof(payload_buf)) {
		return -EMSGSIZE;
	}
	mic_len = SCHNORR48_SIG_LEN;
	frame_body_len = (LICHEN_FRAME_PAYLOAD_OFFSET(dst_addr_len) -
			  LICHEN_FRAME_LEN_FIELD_LEN) + l2_payload_len + mic_len;
	if (frame_body_len > 255 || frame_body_len > LICHEN_MAX_FRAME_BODY_LEN) {
		return -EMSGSIZE;
	}
	if (1 + frame_body_len > *out_len) {
		return -ENOMEM;
	}

	/* Allocate nonce only after preflight (fixes duplicate next_tx bug). */
	int seq_err = lichen_link_next_tx(ctx, &epoch, &seqnum);
	if (seq_err != 0) {
		return seq_err;
	}

	/* Sign using parameters that guarantee DST_LEN(1) prefix at signable
	 * offset 5 (fixes cross-impl inconsistency with Python _build_signable_data
	 * at link_layer.py:285-289 and Rust build_signable at schnorr.rs:202-208).
	 * Uses payload_buf copy for safety during crypto. Matches spec exactly. */
	memcpy(payload_buf, l2_payload, l2_payload_len);
	if (schnorr48_sign_frame((uint8_t)frame_body_len, llsec, epoch, seqnum,
				 dst_addr, dst_addr_len, payload_buf, l2_payload_len,
				 ctx->ed25519_sk, ctx->ed25519_pk, signature) != 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	/* Build wire frame (LENGTH || LLSec || EPO || SEQ || DST || PLD || SIG) */
	off = 0;
	out_frame[off++] = (uint8_t)frame_body_len; /* body length after LENGTH byte */
	out_frame[off++] = llsec;
	out_frame[off++] = epoch;
	out_frame[off++] = (uint8_t)(seqnum >> 8);
	out_frame[off++] = (uint8_t)(seqnum & 0xFF);
	if (dst_addr_len > 0) {
		memcpy(&out_frame[off], dst_addr, dst_addr_len);
		off += dst_addr_len;
	}
	memcpy(&out_frame[off], l2_payload, l2_payload_len);
	off += l2_payload_len;
	memcpy(&out_frame[off], signature, SCHNORR48_SIG_LEN);
	off += SCHNORR48_SIG_LEN;

	*out_len = off;
	ret = 0;

cleanup:
	/*
	 * SECURITY: Wipe stack buffers on all paths to avoid leaking keys,
	 * signatures, or packet data.
	 */
	memset(payload_buf, 0, sizeof(payload_buf));
	memset(signature, 0, sizeof(signature));
	memset(l2_payload, 0, sizeof(l2_payload));
	memset(compressed, 0, sizeof(compressed));
	return ret;
}
