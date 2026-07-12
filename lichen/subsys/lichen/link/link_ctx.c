/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file link_ctx.c
 * @brief LICHEN link layer context implementation
 */

#include <lichen/link_ctx.h>
#include <lichen/schnorr48.h>
#include <lichen/errno.h>
#include <string.h>
#include <stdbool.h>

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
#include "monocypher.h"
#include "monocypher-ed25519.h"
#endif

/* ─── Logging ─────────────────────────────────────────────────────────────── */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
LOG_MODULE_REGISTER(link_ctx, CONFIG_LICHEN_LINK_LOG_LEVEL);
#else
/* Minimal logging for non-Zephyr builds */
#include <stdio.h>
#define LOG_WRN(...) fprintf(stderr, "WRN: " __VA_ARGS__)
/* POSIX CSPRNG */
#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <sys/random.h>
#endif
#endif

/* Runtime warning flag for stub crypto */
#ifndef CONFIG_LICHEN_CRYPTO_MONOCYPHER
static bool stub_warned_load_key = false;
#endif

/* Forward declaration */
static void secure_wipe(void *buf, size_t len);
static int seq_lock(struct lichen_link_ctx *ctx);
static int seq_unlock(struct lichen_link_ctx *ctx);

int lichen_link_init(struct lichen_link_ctx *ctx, const uint8_t *eui64)
{
	if (ctx == NULL || eui64 == NULL) {
		return -EINVAL;
	}

#ifdef __ZEPHYR__
	k_mutex_init(&ctx->seq_lock);
#else
	if (pthread_mutex_init(&ctx->seq_lock, NULL) != 0) {
		return -EIO;
	}
#endif

	memcpy(ctx->eui64, eui64, LICHEN_EUI64_LEN);
	memset(ctx->ed25519_sk, 0, LICHEN_SK_LEN);
	memset(ctx->ed25519_pk, 0, LICHEN_PK_LEN);
	memset(ctx->link_key, 0, LICHEN_LINK_KEY_LEN);

	/* ponytail: random epoch in [128,255] for reboot resilience without flash.
	 * Half-space arithmetic treats upper-half counters as "ahead" of lower-half.
	 * Callers with persisted epoch should call lichen_link_set_epoch() after init.
	 *
	 * SECURITY: ESP32 HW RNG produces weak/predictable output before WiFi/BT radio
	 * init. On ESP32 without epoch persistence, an attacker who knows the boot
	 * timing may predict the epoch. Mitigation: persist epoch to flash, or defer
	 * this call until after radio subsystem init. */
	uint8_t rand_byte;
#ifdef __ZEPHYR__
	sys_csrand_get(&rand_byte, 1);
#elif defined(__linux__) || defined(__APPLE__)
	(void)getentropy(&rand_byte, 1);
#else
	rand_byte = 0; /* fallback: no CSPRNG available */
#endif
	ctx->epoch = 128 + (rand_byte & 0x7F); /* [128, 255] */
	ctx->tx_seq = 0;
	ctx->has_key = false;
	ctx->has_link_key = false;
	ctx->nonce_exhausted = false;

	return 0;
}

/**
 * @brief Load Ed25519 signing key from a 32-byte seed.
 *
 * @param ctx   Link context to initialize
 * @param seed  32-byte random seed (MUST come from a CSPRNG)
 *
 * @note Key Generation Requirements:
 *       The seed MUST be generated using a cryptographically secure PRNG.
 *       On Zephyr: use sys_csrand_get() from <zephyr/random/random.h>
 *       On POSIX: use getrandom(2) or /dev/urandom
 *       NEVER use rand(), random(), or other non-cryptographic sources.
 *
 * @return 0 on success, -EINVAL on invalid parameters
 */
int lichen_link_load_key(struct lichen_link_ctx *ctx, const uint8_t seed[32])
{
	uint8_t new_sk[LICHEN_SK_LEN];
	uint8_t new_pk[LICHEN_PK_LEN];

	if (ctx == NULL || seed == NULL) {
		return -EINVAL;
	}

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
	uint8_t hash[64];

	/* h = SHA-512(seed) */
	crypto_sha512(hash, seed, 32);

	/* sk = clamp(h[0:32]) */
	memcpy(new_sk, hash, sizeof(new_sk));
	schnorr48_clamp_scalar(new_sk);

	/* pk = sk * B */
	crypto_eddsa_scalarbase(new_pk, new_sk);

	/* Wipe sensitive intermediate data */
	crypto_wipe(hash, sizeof(hash));
#else
#ifdef CONFIG_LICHEN_LINK_SCHNORR
#error "CONFIG_LICHEN_LINK_SCHNORR requires CONFIG_LICHEN_CRYPTO_MONOCYPHER for secure key derivation"
#endif
	/* Stub for builds without Monocypher - NOT FOR PRODUCTION */
	if (!stub_warned_load_key) {
		LOG_WRN("INSECURE: using stub lichen_link_load_key - NOT FOR PRODUCTION\n");
		stub_warned_load_key = true;
	}
	memcpy(new_sk, seed, sizeof(new_sk));
	schnorr48_clamp_scalar(new_sk);
	memset(new_pk, 0, sizeof(new_pk));
	new_pk[0] = 0x01;
#endif

	if (ctx->has_key) {
		secure_wipe(ctx->ed25519_sk, LICHEN_SK_LEN);
	}

	memcpy(ctx->ed25519_sk, new_sk, LICHEN_SK_LEN);
	memcpy(ctx->ed25519_pk, new_pk, LICHEN_PK_LEN);
	secure_wipe(new_sk, sizeof(new_sk));
	ctx->has_key = true;
	return 0;
}

int lichen_link_generate_key(struct lichen_link_ctx *ctx)
{
	uint8_t seed[LICHEN_SEED_LEN];
	int ret;

	if (ctx == NULL) {
		return -EINVAL;
	}

#ifdef __ZEPHYR__
	if (sys_csrand_get(seed, sizeof(seed)) != 0) {
		return -EIO;
	}
#elif defined(__linux__) || defined(__APPLE__)
	if (getentropy(seed, sizeof(seed)) != 0) {
		return -EIO;
	}
#else
#error "No CSPRNG available for this platform"
#endif

	ret = lichen_link_load_key(ctx, seed);

	/* Wipe seed from stack */
	secure_wipe(seed, sizeof(seed));

	return ret;
}

int lichen_link_next_seq(struct lichen_link_ctx *ctx, uint16_t *seqnum)
{
	uint8_t epoch;

	return lichen_link_next_tx(ctx, &epoch, seqnum);
}

int lichen_link_next_tx(struct lichen_link_ctx *ctx, uint8_t *epoch, uint16_t *seqnum)
{
	if (ctx == NULL || seqnum == NULL) {
		return -EINVAL;
	}
	if (epoch == NULL) {
		return -EINVAL;
	}

	if (seq_lock(ctx) != 0) {
		return -EIO;
	}

	/*
	 * SECURITY: Once nonce space is exhausted, block all TX until key
	 * rotation occurs. Continuing would cause catastrophic nonce reuse
	 * in AES-CCM, completely breaking confidentiality and authenticity.
	 */
	if (ctx->nonce_exhausted) {
		(void)seq_unlock(ctx);
		return -EOVERFLOW;
	}

	*epoch = ctx->epoch;
	*seqnum = ctx->tx_seq;
	ctx->tx_seq++;

	/*
	 * If tx_seq wrapped to 0, increment epoch to avoid nonce reuse.
	 * The AES-CCM nonce includes (eui64, epoch, seqnum), so reusing
	 * the same (epoch, seqnum) pair would break security guarantees.
	 */
	if (ctx->tx_seq == 0) {
		uint8_t old_epoch = ctx->epoch;
		ctx->epoch++;
		if (ctx->epoch == 0) {
			/*
			 * SECURITY: epoch wrapped from 255 to 0 - nonce space
			 * exhausted after 256 * 65536 = 16M frames. Block all
			 * further TX until key rotation clears the flag.
			 */
			ctx->nonce_exhausted = true;
			LOG_WRN("CRITICAL: nonce exhausted after 16M frames, TX blocked until key rotation\n");
		} else {
			LOG_WRN("tx_seq wrapped - epoch incremented to %u (was %u)\n",
				ctx->epoch, old_epoch);
		}
	}

	(void)seq_unlock(ctx);
	return 0;
}

void lichen_link_set_epoch(struct lichen_link_ctx *ctx, uint8_t epoch)
{
	if (ctx == NULL) {
		return;
	}
	if (seq_lock(ctx) != 0) {
		return;
	}
	ctx->epoch = epoch;
	(void)seq_unlock(ctx);
}

int lichen_link_load_link_key(struct lichen_link_ctx *ctx,
			      const uint8_t link_key[LICHEN_LINK_KEY_LEN])
{
	uint8_t new_link_key[LICHEN_LINK_KEY_LEN];

	if (ctx == NULL || link_key == NULL) {
		return -EINVAL;
	}

	memcpy(new_link_key, link_key, sizeof(new_link_key));

	if (ctx->has_link_key) {
		secure_wipe(ctx->link_key, LICHEN_LINK_KEY_LEN);
	}

	memcpy(ctx->link_key, new_link_key, LICHEN_LINK_KEY_LEN);
	secure_wipe(new_link_key, sizeof(new_link_key));
	ctx->has_link_key = true;

	return 0;
}

/**
 * @brief Secure wipe helper.
 *
 * Uses volatile to prevent compiler from optimizing out the wipe.
 * For Monocypher builds, crypto_wipe() is preferred as it uses
 * platform-specific secure-wipe mechanisms.
 */
static void secure_wipe(void *buf, size_t len)
{
#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
	crypto_wipe(buf, len);
#else
	volatile uint8_t *p = (volatile uint8_t *)buf;
	while (len--) {
		*p++ = 0;
	}
#endif
}

static int seq_lock(struct lichen_link_ctx *ctx)
{
#ifdef __ZEPHYR__
	k_mutex_lock(&ctx->seq_lock, K_FOREVER);
	return 0;
#else
	return pthread_mutex_lock(&ctx->seq_lock);
#endif
}

static int seq_unlock(struct lichen_link_ctx *ctx)
{
#ifdef __ZEPHYR__
	k_mutex_unlock(&ctx->seq_lock);
	return 0;
#else
	return pthread_mutex_unlock(&ctx->seq_lock);
#endif
}

void lichen_link_cleanup(struct lichen_link_ctx *ctx)
{
	if (ctx == NULL) {
		return;
	}

	int locked = (seq_lock(ctx) == 0);

	/* SECURITY: Always wipe keys, even if lock fails */
	secure_wipe(ctx->ed25519_sk, LICHEN_SK_LEN);
	secure_wipe(ctx->link_key, LICHEN_LINK_KEY_LEN);

	/* Clear public key and flags (not secret, but clean up completely) */
	memset(ctx->ed25519_pk, 0, LICHEN_PK_LEN);
	ctx->has_key = false;
	ctx->has_link_key = false;

	/* Reset sequence state and nonce exhaustion flag */
	ctx->epoch = 0;
	ctx->tx_seq = 0;
	ctx->nonce_exhausted = false;

	if (locked) {
		(void)seq_unlock(ctx);
#ifndef __ZEPHYR__
		/* Only destroy mutex if we successfully acquired and released it.
		 * If lock failed, mutex may be held by another thread - destroying
		 * would cause undefined behavior per POSIX. */
		pthread_mutex_destroy(&ctx->seq_lock);
#endif
	}
}
