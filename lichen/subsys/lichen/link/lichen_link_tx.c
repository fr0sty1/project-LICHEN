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

	/*
	 * Validate IPv6 packet length (python-ano.11):
	 * - Must be > 0 (empty packets are invalid)
	 * - Must be <= 1280 (IPv6 minimum MTU per RFC 8200)
	 */
	if (ipv6_len == 0 || ipv6_len > 1280) {
		return -EINVAL;
	}

	/*
	 * Minimum output buffer size check:
	 * - 1 byte length
	 * - 1 byte LLSec
	 * - 1 byte epoch
	 * - 2 bytes seqnum
	 * - 0-8 bytes dst_addr (variable)
	 * - at least 1 byte payload
	 * - 0 bytes for unsigned or 48-byte signature
	 *
	 * Absolute minimum: 1+1+1+2+1+4 = 10 bytes (broadcast, CRC32, 1-byte payload)
	 * Practical minimum: 16 bytes handles most cases
	 */
	if (*out_len < 16) {
		return -ENOMEM;
	}

	/* Link-layer encryption is reserved until all implementations support it. */
	if (ctx->has_link_key) {
		return -EPROTONOSUPPORT;
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

	/* LLSec byte used for both signing and wire format. Includes full
	 * MIC selector (LICHEN_MIC_64 only when signature present) so that
	 * sign/verify use the exact byte that appears on-wire. This fixes
	 * the no-op commit 7bb6ad2.
	 */
	uint8_t llsec = addr_mode & 0x03U;
	if (ctx->has_key) {
		llsec |= (1U << 2); /* LICHEN_MIC_64 << LLSEC_MIC_LEN_SHIFT */
		llsec |= 0x20U; /* LLSEC_SIG_PRESENT */
	}

	/* Get next nonce tuple using the link context API */
	int seq_err = lichen_link_next_tx(ctx, &epoch, &seqnum);
	if (seq_err != 0) {
		/* Nonce exhausted or invalid context - TX blocked */
		return seq_err;
	}

	/* Step 2: A signature occupies the MIC field, not the payload. */
	if (ctx->has_key) {
		if (l2_payload_len > sizeof(payload_buf)) {
			return -EMSGSIZE;
		}

		memcpy(payload_buf, l2_payload, l2_payload_len);
		payload_len = l2_payload_len;
		mic_len = SCHNORR48_SIG_LEN;
		frame_body_len = (LICHEN_FRAME_PAYLOAD_OFFSET(dst_addr_len) -
				  LICHEN_FRAME_LEN_FIELD_LEN) + payload_len + mic_len;
		if (frame_body_len > 255) {
			return -EMSGSIZE;
		}

		if (schnorr48_sign_frame((uint8_t)frame_body_len,
					 llsec,
					 epoch, seqnum,
					 dst_addr, dst_addr_len,
					 l2_payload, l2_payload_len,
					 ctx->ed25519_sk, ctx->ed25519_pk,
					 signature) != 0) {
			ret = -EINVAL;
			goto cleanup;
		}
	} else {
		goto cleanup;
	}

	/* CCP-15: CCA before every TX (project-LICHEN-bwmc / ccp15.json). Threshold from Kconfig. */
	/* Stubbed pending full impl in lichen_lora_l2_tx and Kconfig (fixed per codereview). */
	(void)ctx;

	/* S=0 frames have no MIC. */
	if (!ctx->has_key) {
		mic_len = 0U;
	}

	/* Calculate frame body length (everything after the length byte). */
	frame_body_len = (LICHEN_FRAME_PAYLOAD_OFFSET(dst_addr_len) -
			  LICHEN_FRAME_LEN_FIELD_LEN) + payload_len + mic_len;

	if (frame_body_len > LICHEN_MAX_FRAME_BODY_LEN) {
		ret = -EMSGSIZE;
		goto cleanup;
	}

	/* Total frame = length byte + body */
	if (1 + frame_body_len > *out_len) {
		ret = -ENOMEM;
		goto cleanup;
	}

	/* Allocate a nonce only after every deterministic preflight check passes. */
	int seq_err = lichen_link_next_tx(ctx, &epoch, &seqnum);
	if (seq_err != 0) {
		ret = seq_err;
		goto cleanup;
	}

	if (signing_enabled &&
	    schnorr48_sign_frame((uint8_t)frame_body_len,
				 (uint8_t)(addr_mode | 0x20),
				 epoch, seqnum,
				 dst_addr, dst_addr_len,
				 l2_payload, l2_payload_len,
				 keypair.sk, keypair.pk,
				 signature) != 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	/* Step 3: Build frame header */
	off = 0;

	/* Length byte (body length, excludes itself) */
	out_frame[off++] = (uint8_t)frame_body_len;

	/* LLSec byte (computed earlier to ensure signable data matches wire) */
	out_frame[off++] = llsec;

	/* Epoch */
	out_frame[off++] = epoch;

	/* Sequence number (big-endian) */
	out_frame[off++] = (uint8_t)(seqnum >> 8);
	out_frame[off++] = (uint8_t)(seqnum & 0xFF);

	/* Destination address */
	if (dst_addr_len > 0) {
		memcpy(&out_frame[off], dst_addr, dst_addr_len);
		off += dst_addr_len;
	}

	/* Append plaintext payload before the signature (if any). */
	memcpy(&out_frame[off], payload_buf, payload_len);
	off += payload_len;
	if (ctx->has_key) {
		memcpy(&out_frame[off], signature, SCHNORR48_SIG_LEN);
		off += SCHNORR48_SIG_LEN;
	}

	*out_len = off;
	ret = 0;

cleanup:
	/*
	 * SECURITY: Wipe stack buffers on cleanup exits to avoid leaking
	 * compressed packet data, signatures, or partial frame data.
	 */
	memset(payload_buf, 0, sizeof(payload_buf));
	memset(signature, 0, sizeof(signature));
	memset(l2_payload, 0, sizeof(l2_payload));
	memset(compressed, 0, sizeof(compressed));
	lichen_link_clear_keypair_snapshot(&keypair);
	return ret;
}
