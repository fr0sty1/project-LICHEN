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
#include <lichen/l2_payload.h>
#include <lichen/replay.h>
#include <lichen/schnorr48.h>
#include <lichen/schc.h>
#include <string.h>
#include <stdint.h>

#include <lichen_util.h>

/* Replay table functions are in replay.c */

#define LICHEN_PROTECTED_PAYLOAD_MAX (LICHEN_MAX_PAYLOAD + LICHEN_SIG_LEN)


/* Maximum decompressed IPv6 packet size: frame payload + base header. */
#define LICHEN_MAX_IPV6_LEN (LICHEN_MAX_PAYLOAD + 40)

struct lichen_link_auth_payload {
	size_t payload_len;
	struct lichen_link_rx_payload_info info;
	bool replay_eligible;
};

/* ─── Logging ─────────────────────────────────────────────────────────────── */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lichen_link_rx, CONFIG_LICHEN_LINK_LOG_LEVEL);
#else
/* Minimal logging for non-Zephyr builds */
#include <stdio.h>
#define LOG_WRN(...) fprintf(stderr, "WRN: " __VA_ARGS__)
#endif

/* ─── Signature verification ──────────────────────────────────────────────── */

/**
 * Verify frame signature (Schnorr-48). Unsigned frames are rejected.
 *
 * Signatures are now MANDATORY on every frame per spec/06-security.md.
 * The former CRC32 MIC fallback and unsigned (mic_len==0) paths have been
 * removed to eliminate forgery/spoofing attacks (project-LICHEN-rg8t).
 *
 * CONFIG_LICHEN_LINK_MIC_SKIP_VERIFY remains for test-only use but is
 * strongly discouraged.
 */
static int verify_mic(const struct lichen_link_rx_ctx *ctx,
		      const struct lichen_frame *frame,
		      const uint8_t *raw_frame, size_t raw_len)
{
	(void)ctx; (void)raw_frame; (void)raw_len;
#ifdef CONFIG_LICHEN_LINK_MIC_SKIP_VERIFY
#warning "CONFIG_LICHEN_LINK_MIC_SKIP_VERIFY is enabled - signatures DISABLED, frames can be forged!"
	LOG_WRN("signature verification DISABLED — accepting unverified frame\n");
	return 0;
#else
	if (!frame->signature_present || frame->mic_len != LICHEN_SIG_LEN) {
		LOG_WRN("unsigned frame or invalid MIC len rejected (signatures mandatory)\n");
		return -LICHEN_EAUTH;
	}
	return 0;
#endif
}

static int commit_replay(struct lichen_replay_table *replay,
			 struct lichen_link_auth_payload *auth,
			 const uint8_t *public_key)
{
	struct lichen_replay_window *replay_window;

	if (replay == NULL || !auth->replay_eligible) {
		return 0;
	}
	if (public_key == NULL) {
		return -LICHEN_EAUTH;
	}
	replay_window = lichen_replay_get(replay, public_key);
	if (replay_window == NULL) {
		return -ENOMEM;
	}
	if (!lichen_replay_check(replay_window, auth->info.epoch,
				 auth->info.seqnum)) {
		return -EALREADY;
	}
	return 0;
}

/*
 * SECURITY: Domain separation prefix for EUI-64 derivation from Ed25519 pubkey.
 * This ensures SHA-256(prefix || pubkey) produces different output than other
 * uses of SHA-256 on the same pubkey (e.g., key derivation).
 * The prefix is a fixed ASCII string with no trailing NUL in the hash input.
 * Must match the prefix used in lora_l2.c:generate_eui64() for consistency.
 */
#define EUI64_DOMAIN_PREFIX "LICHEN-EUI64-v1"
#define EUI64_DOMAIN_PREFIX_LEN (sizeof(EUI64_DOMAIN_PREFIX) - 1)

static int authenticate_inner_payload(struct lichen_link_rx_ctx *ctx,
				      const uint8_t *frame, size_t frame_len,
				      uint8_t *work_payload, size_t work_len,
				      uint8_t *out_payload, size_t *out_len,
				      struct lichen_link_auth_payload *auth)
{
	struct lichen_frame parsed;
	const uint8_t *auth_payload;
	size_t auth_payload_len;
	uint8_t src_eui64[LICHEN_EUI64_LEN];
	int ret;

	if (ctx == NULL || frame == NULL || work_payload == NULL ||
	    out_payload == NULL || out_len == NULL || auth == NULL) {
		return -EINVAL;
	}
	memset(auth, 0, sizeof(*auth));

	ret = lichen_frame_parse(&parsed, frame, frame_len);
	if (ret < 0) {
		return ret;
	}

	(void)work_payload;
	(void)work_len;
	auth_payload = parsed.payload;
	auth_payload_len = parsed.payload_len;
	parsed.inner_payload_len = auth_payload_len;

	if (parsed.signature_present) {
		if (ctx->peer_pubkey == NULL || auth_payload == NULL) {
			ret = -LICHEN_EAUTH;
			goto cleanup;
		}
	if (!schnorr48_pubkey_valid(ctx->peer_pubkey)) {
		ret = -LICHEN_EAUTH;
		goto cleanup;
	}

		int verify_result = schnorr48_verify_frame(frame[0], frame[1],
							   parsed.epoch, parsed.seqnum,
							   parsed.dst_addr,
							   parsed.dst_addr_len,
							   auth_payload,
							   auth_payload_len,
							   parsed.mic,
							   ctx->peer_pubkey);
		if (verify_result == 0) {
			LOG_WRN("Schnorr signature verification failed\n");
			ret = -LICHEN_EAUTH;
			goto cleanup;
		} else if (verify_result < 0) {
			LOG_WRN("Schnorr verify: invalid parameters (check peer_pubkey)\n");
			ret = -LICHEN_EAUTH;
			goto cleanup;
		} else if (verify_result != 1) {
			LOG_WRN("Schnorr verify: unexpected result %d\n", verify_result);
			ret = -LICHEN_EAUTH;
			goto cleanup;
		}
	}

	if (ctx->peer_eui64 != NULL) {
		memcpy(src_eui64, ctx->peer_eui64, LICHEN_EUI64_LEN);
	} else if (ctx->peer_pubkey != NULL) {
		/*
		 * Derive EUI-64 from pubkey using domain-separated SHA-256,
		 * matching the method in lora_l2.c:generate_eui64().
		 * This ensures: SHA-256("LICHEN-EUI64-v1" || pubkey)[0:8],
		 * with IEEE EUI-64 U/L=1, I/G=0 bit manipulation applied.
		 */
		uint8_t hash_input[EUI64_DOMAIN_PREFIX_LEN + SCHNORR48_PUBKEY_LEN];
		uint8_t hash[32];

		memcpy(hash_input, EUI64_DOMAIN_PREFIX, EUI64_DOMAIN_PREFIX_LEN);
		memcpy(hash_input + EUI64_DOMAIN_PREFIX_LEN, ctx->peer_pubkey,
		       SCHNORR48_PUBKEY_LEN);
		ret = lichen_sha256(hash_input, sizeof(hash_input), hash);
		if (ret != 0) {
			goto cleanup;
		}
		memcpy(src_eui64, hash, LICHEN_EUI64_LEN);
		/* IEEE 802 EUI-64: U/L=1 (locally administered), I/G=0 (unicast) */
		src_eui64[0] = (src_eui64[0] | 0x02) & 0xFE;
	} else {
		ret = -LICHEN_EAUTH;
		goto cleanup;
	}

	if (!parsed.encrypted) {
		ret = verify_mic(ctx, &parsed, frame, frame_len);
		if (ret < 0) {
			ret = -LICHEN_EAUTH;
			goto cleanup;
		}
	}

	if (parsed.inner_payload_len > LICHEN_MAX_PAYLOAD) {
		ret = -EMSGSIZE;
		goto cleanup;
	}
	if (*out_len < parsed.inner_payload_len) {
		ret = -ENOMEM;
		goto cleanup;
	}

	if (auth_payload != out_payload) {
		memcpy(out_payload, auth_payload, parsed.inner_payload_len);
	}
	auth->payload_len = parsed.inner_payload_len;
	*out_len = parsed.inner_payload_len;
	memcpy(auth->info.src_eui64, src_eui64, LICHEN_EUI64_LEN);
	memcpy(auth->info.dst_addr, parsed.dst_addr, parsed.dst_addr_len);
	auth->info.dst_addr_len = parsed.dst_addr_len;
	auth->info.epoch = parsed.epoch;
	auth->info.seqnum = parsed.seqnum;
	auth->info.addr_mode = parsed.addr_mode;
	auth->info.signature_present = parsed.signature_present;
	auth->info.encrypted = parsed.encrypted;
	auth->replay_eligible = parsed.signature_present;
	ret = 0;

cleanup:
	return ret;
}

/* ─── RX path ─────────────────────────────────────────────────────────────── */

int lichen_link_rx_payload(struct lichen_link_rx_ctx *ctx,
			   struct lichen_replay_table *replay,
			   const uint8_t *frame, size_t frame_len,
			   uint8_t *out_payload, size_t *out_len,
			   struct lichen_link_rx_payload_info *info)
{
	struct lichen_link_auth_payload auth;
	uint8_t work_payload[LICHEN_PROTECTED_PAYLOAD_MAX];
	uint8_t inner_payload[LICHEN_MAX_PAYLOAD];
	size_t inner_len = sizeof(inner_payload);
	size_t caller_len;
	int ret;

	if (out_payload == NULL || out_len == NULL || info == NULL) {
		return -EINVAL;
	}
	caller_len = *out_len;

	ret = authenticate_inner_payload(ctx, frame, frame_len,
					 work_payload, sizeof(work_payload),
					 inner_payload, &inner_len, &auth);
	if (ret < 0) {
		memset(inner_payload, 0, sizeof(inner_payload));
		memset(work_payload, 0, sizeof(work_payload));
		return ret;
	}
	if (caller_len < inner_len) {
		memset(inner_payload, 0, sizeof(inner_payload));
		memset(work_payload, 0, sizeof(work_payload));
		memset(&auth, 0, sizeof(auth));
		return -ENOMEM;
	}

	ret = commit_replay(replay, &auth, ctx->peer_pubkey);
	if (ret < 0) {
		memset(inner_payload, 0, sizeof(inner_payload));
		memset(work_payload, 0, sizeof(work_payload));
		memset(&auth, 0, sizeof(auth));
		return ret;
	}

	memcpy(out_payload, inner_payload, inner_len);
	*out_len = inner_len;
	*info = auth.info;
	memset(inner_payload, 0, sizeof(inner_payload));
	memset(work_payload, 0, sizeof(work_payload));
	memset(&auth, 0, sizeof(auth));
	return 0;
}

int lichen_link_rx(struct lichen_link_rx_ctx *ctx,
		   struct lichen_replay_table *replay,
		   const uint8_t *frame, size_t frame_len,
		   uint8_t *out_ipv6, size_t *out_len,
		   uint8_t *src_eui64)
{
	struct lichen_link_auth_payload auth;
	uint8_t l2_payload[LICHEN_PROTECTED_PAYLOAD_MAX];
	uint8_t ipv6_buf[LICHEN_MAX_IPV6_LEN];
	const uint8_t *schc_data;
	size_t l2_payload_len = sizeof(l2_payload);
	size_t caller_len;
	size_t ipv6_len;
	size_t schc_len;
	int ret;

	if (ctx == NULL || frame == NULL || out_ipv6 == NULL ||
	    out_len == NULL || src_eui64 == NULL) {
		return -EINVAL;
	}
	caller_len = *out_len;

	ret = authenticate_inner_payload(ctx, frame, frame_len,
					 l2_payload, sizeof(l2_payload),
					 l2_payload, &l2_payload_len, &auth);
	if (ret < 0) {
		return ret;
	}

	if (lichen_l2_payload_classify(l2_payload, l2_payload_len) !=
	    LICHEN_L2_PAYLOAD_SCHC) {
		ret = -EPROTONOSUPPORT;
		goto cleanup;
	}
	schc_data = lichen_l2_payload_body(l2_payload, l2_payload_len,
					   &schc_len);
	if (schc_data == NULL || schc_len == 0U) {
		ret = -EINVAL;
		goto cleanup;
	}

	/* Validate output buffer can hold minimum IPv6 header */
	if (caller_len < 40) {
		ret = -ENOMEM;
		goto cleanup;
	}

	/*
	 * SECURITY: Decompress to local buffer first, then copy to caller's
	 * buffer only after replay check passes. This prevents authenticated-
	 * but-replayed data from being visible to the caller even if they
	 * (incorrectly) ignore the error return code.
	 */
	ret = lichen_schc_decompress(schc_data, schc_len,
				     ipv6_buf, sizeof(ipv6_buf));
	if (ret < 0) {
		if (ret == SCHC_ERR_BUFFER_TOO_SMALL) {
			ret = -ENOMEM;
			goto cleanup;
		}
		ret = -EINVAL;
		goto cleanup;
	}

	ipv6_len = (size_t)ret;

	/* Verify caller's buffer can hold the decompressed packet */
	if (caller_len < ipv6_len) {
		ret = -ENOMEM;
		goto cleanup;
	}

	ret = commit_replay(replay, &auth, ctx->peer_pubkey);
	if (ret < 0) {
		goto cleanup;
	}

	/* Only copy to caller's buffer after replay check passes */
	memcpy(out_ipv6, ipv6_buf, ipv6_len);
	*out_len = ipv6_len;
	memcpy(src_eui64, auth.info.src_eui64, LICHEN_EUI64_LEN);
	ret = 0;

cleanup:
	memset(ipv6_buf, 0, sizeof(ipv6_buf));
	memset(l2_payload, 0, sizeof(l2_payload));
	memset(&auth, 0, sizeof(auth));
	return ret;
}
