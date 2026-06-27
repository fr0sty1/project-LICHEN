/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_link_rx.c
 * @brief LICHEN frame receive path
 *
 * Parses LICHEN frames, verifies replay protection and signatures,
 * and decompresses the payload to a full IPv6 packet.
 */

#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/errno.h>
#include <lichen/replay.h>
#include <lichen/schnorr48.h>
#include <lichen/schc.h>
#include <string.h>
#include <stdint.h>

/* AES-CCM for link-layer MIC verification */
#include "oscore/aes_ccm.h"

/* CRC32 for non-crypto MIC fallback */
#include <zephyr/sys/crc.h>

/* Shared nonce construction */
#include "link_nonce.h"

/* Replay table functions are in replay.c */

/* ─── Logging ─────────────────────────────────────────────────────────────── */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lichen_link_rx, CONFIG_LICHEN_LINK_LOG_LEVEL);
#else
/* Minimal logging for non-Zephyr builds */
#include <stdio.h>
#define LOG_WRN(...) fprintf(stderr, "WRN: " __VA_ARGS__)
#endif

/* ─── MIC verification ────────────────────────────────────────────────────── */

/**
 * Verify the frame MIC.
 *
 * MIC verification is ENABLED by default. To disable for testing, set
 * CONFIG_LICHEN_LINK_MIC_SKIP_VERIFY=y — this is a dangerous option that
 * should NEVER be used in production as it allows frame forgery.
 *
 * For AES-CCM-64 MIC (mic_len == 8):
 * - Requires ctx->link_key and ctx->peer_eui64 to be set
 * - AAD = entire frame body up to MIC
 * - Nonce = peer_eui64 || epoch || seqnum || 0x0000
 *
 * For CRC32 MIC (mic_len == 4):
 * - Fallback verification (no cryptographic authentication)
 */
static int verify_mic(const struct lichen_link_rx_ctx *ctx,
		      const struct lichen_frame *frame,
		      const uint8_t *raw_frame, size_t raw_len)
{
/*
 * Compile-time warning if MIC verification is disabled.
 * This makes the insecure configuration visible in build logs.
 */
#ifdef CONFIG_LICHEN_LINK_MIC_SKIP_VERIFY
#warning "CONFIG_LICHEN_LINK_MIC_SKIP_VERIFY is enabled - MIC verification DISABLED, frames can be forged!"
	(void)ctx;
	(void)frame;
	(void)raw_frame;
	(void)raw_len;
	/*
	 * DANGER: MIC verification is disabled — frames can be forged.
	 * This option exists ONLY for testing. Never enable in production.
	 */
	LOG_WRN("MIC verification DISABLED — accepting unverified frame\n");
	return 0;
#else
	if (frame->mic_len == 8) {
		/* AES-CCM-64 MIC verification */
		uint8_t nonce[AES_CCM_NONCE_LEN];
		uint8_t expected_mic[AES_CCM_TAG_LEN];
		size_t aad_len;

		/* Require link key and peer EUI-64 for AES-CCM verification */
		if (ctx->link_key == NULL || ctx->peer_eui64 == NULL) {
			LOG_WRN("AES-CCM MIC verification requires link_key and peer_eui64\n");
			return -EAUTH;
		}

		/* AAD is everything except the MIC itself */
		aad_len = raw_len - frame->mic_len;

		/* Build nonce from peer's EUI-64, epoch, and seqnum */
		build_link_nonce(nonce, ctx->peer_eui64, frame->epoch, frame->seqnum);

		/* Compute expected MIC (encrypt with empty plaintext) */
		if (lichen_aes_ccm_encrypt(ctx->link_key, nonce,
					   raw_frame, aad_len,
					   NULL, 0,
					   expected_mic) != 0) {
			return -EAUTH;
		}

		/* Constant-time comparison of MIC */
		uint8_t diff = 0;
		for (int i = 0; i < AES_CCM_TAG_LEN; i++) {
			diff |= frame->mic[i] ^ expected_mic[i];
		}

		if (diff != 0) {
			return -EAUTH;
		}

		return 0;
	} else {
#ifdef CONFIG_LICHEN_LINK_INSECURE_CRC32_MIC
#warning "CONFIG_LICHEN_LINK_INSECURE_CRC32_MIC is enabled - CRC32 MIC provides NO authentication, frames can be forged!"
		/*
		 * CRC32 fallback - verifies data integrity (transmission errors)
		 * but provides NO cryptographic authentication. An attacker can
		 * forge frames by computing a valid CRC32.
		 *
		 * WARNING: This mode should only be used for testing or when
		 * authentication is provided by a higher layer (e.g., OSCORE).
		 */
		size_t aad_len = raw_len - frame->mic_len;
		uint32_t expected_crc = crc32_ieee(&raw_frame[1], aad_len - 1);

		/* Extract received CRC32 (little-endian per TX convention) */
		uint32_t received_crc = (uint32_t)frame->mic[0] |
					((uint32_t)frame->mic[1] << 8) |
					((uint32_t)frame->mic[2] << 16) |
					((uint32_t)frame->mic[3] << 24);

		uint32_t diff = expected_crc ^ received_crc;
		if (diff != 0) {
			LOG_WRN("CRC32 mismatch: expected 0x%08x, got 0x%08x\n",
				expected_crc, received_crc);
			return -EAUTH;
		}

		return 0;
#else
		/*
		 * No link key and CRC32 fallback not enabled.
		 * Require CONFIG_LICHEN_LINK_INSECURE_CRC32_MIC=y to use CRC32 mode.
		 */
		LOG_WRN("CRC32 MIC received but CONFIG_LICHEN_LINK_INSECURE_CRC32_MIC not enabled\n");
		return -EAUTH;
#endif
	}
#endif
}

/* ─── RX path ─────────────────────────────────────────────────────────────── */

int lichen_link_rx(struct lichen_link_rx_ctx *ctx,
		   struct lichen_replay_table *replay,
		   const uint8_t *frame, size_t frame_len,
		   uint8_t *out_ipv6, size_t *out_len,
		   uint8_t *src_eui64)
{
	struct lichen_frame parsed;
	int ret;

	if (ctx == NULL || frame == NULL || out_ipv6 == NULL ||
	    out_len == NULL || src_eui64 == NULL) {
		return -EINVAL;
	}

	/* Step 1: Parse frame header */
	ret = lichen_frame_parse(&parsed, frame, frame_len);
	if (ret < 0) {
		return -EINVAL;
	}

	/* Step 2: Verify Schnorr-48 signature if present */
	if (parsed.signature_present) {
		if (ctx->peer_pubkey == NULL) {
			/* Cannot verify without sender's public key */
			return -EAUTH;
		}

		/*
		 * schnorr48_verify_frame expects:
		 * - Full payload including signature (payload_len)
		 * - It extracts inner payload and signature internally
		 *
		 * Note: frame_parse() already validated payload_len >= LICHEN_SIG_LEN
		 * Returns: 1=valid, 0=invalid signature, -1=invalid parameters
		 */
		int verify_result = schnorr48_verify_frame(parsed.epoch, parsed.seqnum,
							   parsed.dst_addr,
							   parsed.dst_addr_len,
							   parsed.payload,
							   parsed.payload_len,
							   ctx->peer_pubkey);
		if (verify_result != 1) {
			return -EAUTH;
		}
	}

	/*
	 * Step 3: Extract source EUI-64
	 *
	 * The source address is not in the frame header - it must be
	 * derived from one of:
	 * - Radio layer metadata (LoRa)
	 * - Signature verification (sender's public key)
	 * - Explicit source field in extended frames
	 *
	 * For signed frames, we derive EUI-64 from the sender's public
	 * key after signature verification. For unsigned frames, the
	 * caller must provide the source via ctx->peer_pubkey context.
	 *
	 * SECURITY: This MUST happen AFTER signature verification (Step 2).
	 * Using peer_pubkey before verification would allow an attacker to
	 * poison data structures (like the replay window) with spoofed EUI-64s.
	 *
	 * TEMPORARY: Use first 8 bytes of peer_pubkey as EUI-64.
	 * Real implementation should use SHA-256(pubkey)[0:8].
	 */
	if (ctx->peer_pubkey != NULL) {
		memcpy(src_eui64, ctx->peer_pubkey, LICHEN_EUI64_LEN);
	} else {
		/* No peer context - cannot determine source */
		memset(src_eui64, 0, LICHEN_EUI64_LEN);
	}

	/*
	 * Step 4: Get replay window handle (check deferred to Step 7)
	 *
	 * We look up the replay window here but defer the atomic check-and-
	 * commit to Step 7, after all validation succeeds. This prevents
	 * malformed frames from polluting the replay window.
	 *
	 * Note: We deliberately do NOT peek at replay state here. A peek
	 * without commit creates a TOCTOU race where concurrent frames with
	 * the same sequence could both pass the peek, wasting CPU on
	 * signature/MIC verification for frames that will ultimately be
	 * rejected. The atomic check-and-commit in Step 7 is correct.
	 */
	struct lichen_replay_window *replay_window = NULL;
	if (replay != NULL) {
		replay_window = lichen_replay_get(replay, src_eui64);
		if (replay_window == NULL) {
			/* Table full */
			return -ENOMEM;
		}
	}

	/* Step 5: Verify MIC */
	ret = verify_mic(ctx, &parsed, frame, frame_len);
	if (ret < 0) {
		return -EAUTH;
	}

	/*
	 * Step 6: Decompress SCHC payload to IPv6
	 *
	 * Use inner_payload_len which excludes the signature if present.
	 * Minimum IPv6 header is 40 bytes; require at least that.
	 */
	const uint8_t *schc_data = parsed.payload;
	size_t schc_len = parsed.inner_payload_len;

	/* Validate output buffer can hold minimum IPv6 header */
	if (*out_len < 40) {
		return -ENOMEM;
	}

	ret = lichen_schc_decompress(schc_data, schc_len, out_ipv6, *out_len);
	if (ret < 0) {
		if (ret == SCHC_ERR_BUFFER_TOO_SMALL) {
			return -ENOMEM;
		}
		return -EINVAL;
	}

	/*
	 * Step 7: Atomic replay check-and-commit
	 *
	 * SECURITY: Only check/commit AFTER all validation succeeds.
	 * This prevents malformed frames from polluting the replay window.
	 *
	 * lichen_replay_check() atomically checks whether the sequence is
	 * valid AND marks it as seen in a single operation, eliminating the
	 * TOCTOU race that a separate peek-then-commit pattern would create.
	 */
	if (replay_window != NULL) {
		if (!lichen_replay_check(replay_window, parsed.seqnum)) {
			return -EALREADY;
		}
	}

	*out_len = (size_t)ret;
	return 0;
}
