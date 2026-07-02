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

/* AES-CCM for link-layer MIC */
#include "aes_ccm.h"

/* CRC32 for non-crypto MIC fallback */
#include <zephyr/sys/crc.h>

/* Shared nonce construction */
#include "link_nonce.h"

int lichen_link_tx(struct lichen_link_ctx *ctx,
		   const uint8_t *ipv6_pkt, size_t ipv6_len,
		   const uint8_t *dst_eui64,
		   uint8_t *out_frame, size_t *out_len)
{
	uint8_t compressed[256];
	uint8_t l2_payload[256];
	uint8_t payload_buf[256];
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
	size_t aad_len;
	uint8_t mic_len;
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
	 * - 4-8 bytes MIC
	 *
	 * Absolute minimum: 1+1+1+2+1+4 = 10 bytes (broadcast, CRC32, 1-byte payload)
	 * Practical minimum: 16 bytes handles most cases
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

	/* Get next nonce tuple using the link context API */
	int seq_err = lichen_link_next_tx(ctx, &epoch, &seqnum);
	if (seq_err != 0) {
		/* Nonce exhausted or invalid context - TX blocked */
		return seq_err;
	}

	/* Step 2: If signing enabled (has_key set), compute Schnorr-48 signature */
	if (ctx->has_key) {
		/* Signature is appended to the authenticated L2 payload. */
		if (l2_payload_len + SCHNORR48_SIG_LEN > sizeof(payload_buf)) {
			return -EMSGSIZE;
		}

		memcpy(payload_buf, l2_payload, l2_payload_len);

		if (schnorr48_sign_frame(epoch, seqnum,
					 dst_addr, dst_addr_len,
					 l2_payload, l2_payload_len,
					 ctx->ed25519_sk, ctx->ed25519_pk,
					 &payload_buf[l2_payload_len]) != 0) {
			/*
			 * SECURITY: Wipe buffers to avoid leaking partial data.
			 * payload_buf may have uninitialized signature slot,
			 * compressed[] contains SCHC-compressed packet data.
			 */
			memset(payload_buf, 0, sizeof(payload_buf));
			memset(compressed, 0, sizeof(compressed));
			return -EINVAL;
		}

		payload_len = l2_payload_len + SCHNORR48_SIG_LEN;
	} else {
		/* No signature */
		if (l2_payload_len > sizeof(payload_buf)) {
			return -EMSGSIZE;
		}
		memcpy(payload_buf, l2_payload, l2_payload_len);
		payload_len = l2_payload_len;
	}

	/* MIC length: 8 bytes for AES-CCM-64, 4 bytes for CRC32 fallback */
	mic_len = ctx->has_link_key ? LICHEN_MIC_64_LEN : LICHEN_MIC_32_LEN;

	/* Calculate frame body length (everything after the length byte):
	 * LLSec(1) + Epoch(1) + SeqNum(2) + DstAddr(0/2/8) + Payload + MIC(4/8)
	 */
	frame_body_len = (LICHEN_FRAME_PAYLOAD_OFFSET(dst_addr_len) -
			  LICHEN_FRAME_LEN_FIELD_LEN) + payload_len + mic_len;

	if (frame_body_len > 255) {
		ret = -EMSGSIZE;
		goto cleanup;
	}

	/* Total frame = length byte + body */
	if (1 + frame_body_len > *out_len) {
		ret = -ENOMEM;
		goto cleanup;
	}

	/* Step 3: Build frame header */
	off = 0;

	/* Length byte (body length, excludes itself) */
	out_frame[off++] = (uint8_t)frame_body_len;

	/* LLSec byte:
	 * bits 0-1: AddrMode
	 * bit 2: MicLength (0 = 32-bit, 1 = 64-bit)
	 * bit 5: signature present
	 * bit 6: encrypted when a link key is present
	 * bit 7: reserved (0)
	 */
	out_frame[off] = addr_mode & 0x03;
	if (ctx->has_link_key) {
		out_frame[off] |= 0x04; /* 64-bit MIC */
		out_frame[off] |= 0x40; /* encrypted */
	}
	if (ctx->has_key) {
		out_frame[off] |= 0x20; /* signature present */
	}
	off++;

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

	aad_len = off;

	/* Step 4/5: Protect payload and append MIC */
	if (ctx->has_link_key) {
		/*
		 * AES-CCM-64 encryption and MIC.
		 *
		 * AAD = length || LLSec || epoch || seqnum || dst_addr.
		 * Plaintext = compressed payload plus optional Schnorr-48 signature.
		 * Nonce = eui64 || epoch || seqnum || 0x0000
		 */
		uint8_t nonce[AES_CCM_NONCE_LEN];

		build_link_nonce(nonce, ctx->eui64, epoch, seqnum);

		if (lichen_aes_ccm_encrypt(ctx->link_key, nonce,
					   &out_frame[0], aad_len,
					   payload_buf, payload_len,
					   &out_frame[off]) != 0) {
			ret = -EINVAL;
			goto cleanup;
		}

		off += payload_len + AES_CCM_TAG_LEN;
	} else {
		/* Append plaintext payload before computing the CRC32 fallback. */
		memcpy(&out_frame[off], payload_buf, payload_len);
		off += payload_len;
#ifdef CONFIG_LICHEN_LINK_INSECURE_CRC32_MIC
#warning "CONFIG_LICHEN_LINK_INSECURE_CRC32_MIC is enabled - CRC32 MIC provides NO authentication, frames can be forged!"
		/*
		 * CRC32 fallback (no link key configured).
		 *
		 * SECURITY LIMITATION: CRC32 provides error detection only, NOT
		 * authentication. An attacker can trivially compute valid CRC32
		 * values and forge frames. This mode is suitable only for:
		 *   - Development and testing
		 *   - Environments where link-layer forgery is acceptable
		 *   - Networks with higher-layer authentication (e.g., OSCORE)
		 *
		 * For production deployments requiring link-layer authentication,
		 * configure CONFIG_LICHEN_LINK_KEY to enable AES-CCM-64 MIC.
		 */
		uint32_t mic = crc32_ieee(&out_frame[1], off - 1);

		/* Append 32-bit MIC (little-endian per CRC32 convention) */
		out_frame[off++] = (uint8_t)(mic & 0xFF);
		out_frame[off++] = (uint8_t)((mic >> 8) & 0xFF);
		out_frame[off++] = (uint8_t)((mic >> 16) & 0xFF);
		out_frame[off++] = (uint8_t)((mic >> 24) & 0xFF);
#else
		/*
		 * No link key and CRC32 fallback not enabled.
		 * Require CONFIG_LICHEN_LINK_INSECURE_CRC32_MIC=y to use CRC32 mode.
		 */
		ret = -EINVAL;
		goto cleanup;
#endif
	}

	*out_len = off;
	ret = 0;

cleanup:
	/*
	 * SECURITY: Wipe stack buffers on cleanup exits to avoid leaking
	 * compressed packet data, signatures, or partial frame data.
	 */
	memset(payload_buf, 0, sizeof(payload_buf));
	memset(l2_payload, 0, sizeof(l2_payload));
	memset(compressed, 0, sizeof(compressed));
	return ret;
}
