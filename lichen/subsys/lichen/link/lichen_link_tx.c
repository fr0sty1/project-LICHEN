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
#include <monocypher.h>
#include <monocypher-ed25519.h>
#include <string.h>

/* Error codes */
#include <lichen/errno.h>

/* Keep this dependency-free link-layer derivation in sync with
 * lichen_pubkey_to_iid(): a wire EUI-64 is SHA-512(pubkey)[0:8] with the
 * universal/local bit set exactly once. */
static void derive_signer_eui64(const uint8_t pubkey[SCHNORR48_PUBKEY_LEN],
				uint8_t signer_eui64[LICHEN_EUI64_LEN])
{
	uint8_t hash[64];

	crypto_sha512(hash, pubkey, SCHNORR48_PUBKEY_LEN);
	memcpy(signer_eui64, hash, LICHEN_EUI64_LEN);
	signer_eui64[0] |= 0x02U;
	crypto_wipe(hash, sizeof(hash));
}

int lichen_link_tx(struct lichen_link_ctx *ctx,
		   const uint8_t *ipv6_pkt, size_t ipv6_len,
		   const uint8_t *dst_eui64,
		   uint8_t *out_frame, size_t *out_len)
{
	uint8_t compressed[256];
	uint8_t l2_payload[256];
	uint8_t payload_buf[256];
	uint8_t signature[SCHNORR48_SIG_LEN];
	uint8_t signer_eui64[LICHEN_EUI64_LEN];
	int compressed_len;
	size_t l2_payload_len;
	uint8_t addr_mode;
	uint8_t dst_addr[8];
	uint8_t dst_addr_len;
	uint8_t epoch;
	uint16_t seqnum;
	size_t off;
	size_t frame_body_len;
	uint8_t mic_len;
	int ret;

	if (ctx == NULL || ipv6_pkt == NULL || out_frame == NULL || out_len == NULL) {
		return -EINVAL;
	}

	if (!ctx->has_key) {
		return -ENOKEY;
	}

	/* Link-layer symmetric encryption has no coordinated design yet
	 * (bead 2auf.21): E=1 frames are rejected on every boundary. A
	 * context with a loaded legacy link key must not silently fall
	 * back to unsigned transmission. */
	if (ctx->has_link_key) {
		return -EPROTONOSUPPORT;
	}

#if defined(CONFIG_LICHEN_TDMA)
	{
		/* SECURITY: TDMA schedule state lives inside lichen_link_ctx,
		 * so each context gates its own TX with its own schedule;
		 * alternating contexts can no longer churn a shared latch back
		 * to synced=false, which would silently bypass the collision
		 * gate. Sync installed on this context via
		 * lichen_link_set_slot(ctx, &ctx->tdma, ...) persists across
		 * calls. Ordering: the init graph (AGENTS.md) has
		 * lichen_link_load_key() precede lichen_tdma_init(), so this
		 * lazy init runs only after the has_key check above succeeded,
		 * keeping an unkeyed context fail-fast (-ENOKEY) before any
		 * TDMA latch/schedule state is created on it (tdma_init itself
		 * consumes no RNG and no keys — it hashes ctx->eui64 against
		 * the SFN-0 baseline only; load_key() does not rotate slots).
		 * The latch re-runs init only when ctx->epoch differs from the
		 * value tdma was built from: exactly one init per
		 * (context, epoch). */
		if (!ctx->tdma_init_done || ctx->tdma_epoch_seen != ctx->epoch) {
			(void)lichen_tdma_init(&ctx->tdma, ctx);
			ctx->tdma_epoch_seen = ctx->epoch;
			ctx->tdma_init_done = true;
		}
		/* FIXME: Pass actual time once TDMA time source is wired up.
		 * A real clock source is REQUIRED before enabling synced
		 * operation: the exact data window [slot_start,
		 * slot_start + d - g) makes the synced gate schedule-dependent,
		 * so the constant now_ms=0 is only correct while
		 * ctx->tdma.synced is false (unsynced gate passes
		 * unconditionally). Once synced, now_ms=0 maps every nonzero
		 * schedule position to a huge modular offset and fails the
		 * gate (-EBUSY); the sole exception is the slot_start==0
		 * special case (superframe==0 AND slot==0), whose window
		 * [0, d-g) contains 0 and alone stays open. */
		if (!tdma_tx_allowed(&ctx->tdma, 0)) {
			return -EBUSY;
		}
	}
#endif

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

	/* Current signed frames carry both S (bit 5) and SI (bit 7). */
	uint8_t llsec = (addr_mode & 0x03U) | 0x20U | 0x80U;
	derive_signer_eui64(ctx->ed25519_pk, signer_eui64);

	/* Preflight size checks BEFORE consuming nonce (deterministic TX
	 * requirement; matches Python/Rust frame_length calc). */
	if (l2_payload_len > sizeof(payload_buf)) {
		return -EMSGSIZE;
	}
	mic_len = SCHNORR48_SIG_LEN;
	frame_body_len = (LICHEN_FRAME_PAYLOAD_OFFSET(dst_addr_len) -
			  LICHEN_FRAME_LEN_FIELD_LEN) + LICHEN_EUI64_LEN +
			 l2_payload_len + mic_len;
	if (frame_body_len > LICHEN_MAX_FRAME_BODY_LEN) {
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
	 * The SIID is authenticated as part of the transcript. Uses payload_buf
	 * copy for safety during crypto. */
	memcpy(payload_buf, l2_payload, l2_payload_len);
	if (schnorr48_sign_frame((uint8_t)frame_body_len, llsec, epoch, seqnum,
				 dst_addr, dst_addr_len,
				 signer_eui64, sizeof(signer_eui64),
				 payload_buf, l2_payload_len,
				 ctx->ed25519_sk, ctx->ed25519_pk, signature) != 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	/* Build wire frame (LENGTH || LLSec || EPO || SEQ || DST || SIID || PLD || SIG) */
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
	memcpy(&out_frame[off], signer_eui64, sizeof(signer_eui64));
	off += sizeof(signer_eui64);
	memcpy(&out_frame[off], l2_payload, l2_payload_len);
	off += l2_payload_len;
	memcpy(&out_frame[off], signature, SCHNORR48_SIG_LEN);
	off += SCHNORR48_SIG_LEN;

	*out_len = off;

	/* Frame construction has no transport side effects.  The radio L2 owns
	 * the single bounded TX queue and copies this frame before returning, so
	 * callers can safely reuse their output buffer after transport accepts it. */
	ret = 0;

cleanup:
	/*
	 * SECURITY: Wipe stack buffers on all paths to avoid leaking keys,
	 * signatures, or packet data.
	 */
	memset(payload_buf, 0, sizeof(payload_buf));
	memset(signature, 0, sizeof(signature));
	crypto_wipe(signer_eui64, sizeof(signer_eui64));
	memset(l2_payload, 0, sizeof(l2_payload));
	memset(compressed, 0, sizeof(compressed));
	return ret;
}

int lichen_link_relay_raw(struct lichen_link_ctx *ctx,
			  const uint8_t *payload, size_t payload_len,
			  const uint8_t *dst_eui64,
			  uint8_t *out_frame, size_t *out_len)
{
	uint8_t payload_buf[256];
	uint8_t signature[SCHNORR48_SIG_LEN];
	uint8_t signer_eui64[LICHEN_EUI64_LEN];
	uint8_t addr_mode;
	uint8_t dst_addr[8];
	uint8_t dst_addr_len;
	uint8_t epoch;
	uint16_t seqnum;
	size_t off;
	size_t frame_body_len;
	uint8_t mic_len;
	int ret;

	if (ctx == NULL || payload == NULL || out_frame == NULL || out_len == NULL) {
		return -EINVAL;
	}

	if (!ctx->has_key) {
		return -ENOKEY;
	}

	/* Validate payload length */
	if (payload_len == 0 || payload_len > LICHEN_MAX_PAYLOAD) {
		return -EINVAL;
	}

	/* Minimum output buffer size check (assumes signature) */
	if (*out_len < 16) {
		return -ENOMEM;
	}

	/* Determine address mode and destination */
	if (dst_eui64 != NULL) {
		addr_mode = LICHEN_ADDR_EUI64;
		memcpy(dst_addr, dst_eui64, 8);
		dst_addr_len = 8;
	} else {
		addr_mode = LICHEN_ADDR_BROADCAST;
		dst_addr_len = 0;
	}

	/* LLSec byte: every signed frame sets both S and SI. */
	uint8_t llsec = (addr_mode & 0x03U) | 0x20U | 0x80U;
	derive_signer_eui64(ctx->ed25519_pk, signer_eui64);

	/* Preflight size checks BEFORE consuming nonce */
	if (payload_len > sizeof(payload_buf)) {
		return -EMSGSIZE;
	}
	mic_len = SCHNORR48_SIG_LEN;
	frame_body_len = (LICHEN_FRAME_PAYLOAD_OFFSET(dst_addr_len) -
			  LICHEN_FRAME_LEN_FIELD_LEN) + LICHEN_EUI64_LEN +
			 payload_len + mic_len;
	if (frame_body_len > LICHEN_MAX_FRAME_BODY_LEN) {
		return -EMSGSIZE;
	}
	if (1 + frame_body_len > *out_len) {
		return -ENOMEM;
	}

	/* Allocate nonce only after preflight */
	int seq_err = lichen_link_next_tx(ctx, &epoch, &seqnum);
	if (seq_err != 0) {
		return seq_err;
	}

	/* Sign with local keys (replaces any previous link signature) */
	memcpy(payload_buf, payload, payload_len);
	if (schnorr48_sign_frame((uint8_t)frame_body_len, llsec, epoch, seqnum,
				 dst_addr, dst_addr_len,
				 signer_eui64, sizeof(signer_eui64),
				 payload_buf, payload_len,
				 ctx->ed25519_sk, ctx->ed25519_pk, signature) != 0) {
		ret = -EINVAL;
		goto relay_cleanup;
	}

	/* Build wire frame (LENGTH || LLSec || EPO || SEQ || DST || SIID || PLD || SIG) */
	off = 0;
	out_frame[off++] = (uint8_t)frame_body_len;
	out_frame[off++] = llsec;
	out_frame[off++] = epoch;
	out_frame[off++] = (uint8_t)(seqnum >> 8);
	out_frame[off++] = (uint8_t)(seqnum & 0xFF);
	if (dst_addr_len > 0) {
		memcpy(&out_frame[off], dst_addr, dst_addr_len);
		off += dst_addr_len;
	}
	memcpy(&out_frame[off], signer_eui64, sizeof(signer_eui64));
	off += sizeof(signer_eui64);
	memcpy(&out_frame[off], payload, payload_len);
	off += payload_len;
	memcpy(&out_frame[off], signature, SCHNORR48_SIG_LEN);
	off += SCHNORR48_SIG_LEN;

	*out_len = off;

	/* As with lichen_link_tx(), the caller owns transport submission. */
	ret = 0;

relay_cleanup:
	/* SECURITY: Wipe stack buffers */
	memset(payload_buf, 0, sizeof(payload_buf));
	memset(signature, 0, sizeof(signature));
	crypto_wipe(signer_eui64, sizeof(signer_eui64));
	return ret;
}

int lichen_link_relay_frame(struct lichen_link_rx_ctx *rx_ctx,
			    struct lichen_replay_table *replay,
			    struct lichen_link_ctx *tx_ctx,
			    const uint8_t *incoming_frame, size_t incoming_len,
			    const uint8_t *dst_eui64,
			    uint8_t *out_frame, size_t *out_len)
{
	struct lichen_link_rx_payload_info info;
	struct lichen_frame parsed;
	uint8_t payload[LICHEN_MAX_PAYLOAD];
	uint8_t relayed[LICHEN_MAX_FRAME_LEN];
	size_t payload_len = sizeof(payload);
	size_t relayed_len = sizeof(relayed);
	size_t dst_len;
	size_t required;
	int ret;

	if (rx_ctx == NULL || tx_ctx == NULL || incoming_frame == NULL ||
	    out_frame == NULL || out_len == NULL) {
		return -EINVAL;
	}

	/* Structural parsing is deliberately side-effect free and is used only
	 * to reject impossible output sizes before consuming replay or TX state.
	 * No payload bytes are acted upon until lichen_link_rx_payload authenticates
	 * the complete immutable incoming transcript. */
	ret = lichen_frame_parse(&parsed, incoming_frame, incoming_len);
	if (ret < 0) {
		return ret;
	}
	if (!tx_ctx->has_key) {
		return -ENOKEY;
	}
	if (parsed.payload_len == 0U || parsed.payload_len > sizeof(payload)) {
		return -EINVAL;
	}
	dst_len = dst_eui64 == NULL ? 0U : LICHEN_EUI64_LEN;
	required = LICHEN_FRAME_FIXED_HEADER_LEN + dst_len + LICHEN_EUI64_LEN +
		   parsed.payload_len + SCHNORR48_SIG_LEN;
	if (required > LICHEN_MAX_FRAME_LEN) {
		return -EMSGSIZE;
	}
	if (*out_len < required) {
		return -ENOMEM;
	}

	/* Authentication and replay commit precede every relay mutation. */
	ret = lichen_link_rx_payload(rx_ctx, replay, incoming_frame, incoming_len,
				     payload, &payload_len, &info);
	if (ret < 0) {
		goto cleanup;
	}

	/* relay_raw assigns the relayer's own epoch/sequence, destination, SIID,
	 * and signature. The authenticated inner payload remains byte-identical;
	 * upper-layer mutable fields must be updated before entering this API. */
	ret = lichen_link_relay_raw(tx_ctx, payload, payload_len, dst_eui64,
				    relayed, &relayed_len);
	if (ret < 0) {
		goto cleanup;
	}

	memcpy(out_frame, relayed, relayed_len);
	*out_len = relayed_len;
	ret = 0;

cleanup:
	crypto_wipe(payload, sizeof(payload));
	crypto_wipe(relayed, sizeof(relayed));
	crypto_wipe(&info, sizeof(info));
	crypto_wipe(&parsed, sizeof(parsed));
	return ret;
}
