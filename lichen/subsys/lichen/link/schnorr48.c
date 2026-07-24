/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schnorr48.c
 * @brief Schnorr-48 signatures per draft-lichen-schnorr-00
 *
 * 48-byte deterministic Schnorr signatures over Ed25519:
 *   16-byte truncated challenge (e) || 32-byte response (s)
 *
 * Uses Monocypher for Ed25519 primitives and SHA-512.
 * Test vectors: test/vectors/schnorr48.json
 * Reference impl: python/src/lichen/crypto/schnorr48.py
 */

#include <lichen/schnorr48.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

/* ─── Logging ─────────────────────────────────────────────────────────────── */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
#ifndef CONFIG_LICHEN_LINK_LOG_LEVEL
#define CONFIG_LICHEN_LINK_LOG_LEVEL LOG_LEVEL_INF
#endif
LOG_MODULE_REGISTER(schnorr48, CONFIG_LICHEN_LINK_LOG_LEVEL);
#else
/* Minimal logging for non-Zephyr builds */
#include <stdio.h>
#define LOG_WRN(...) fprintf(stderr, "WRN: " __VA_ARGS__)
#endif

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
#include "monocypher.h"
#include "monocypher-ed25519.h"

void schnorr48_derive_keypair(const uint8_t *seed,
			      uint8_t *privkey,
			      uint8_t *pubkey)
{
	uint8_t hash[64];

	/* h = SHA-512(seed) */
	crypto_sha512(hash, seed, 32);

	/* privkey = clamp(h[0:32]) */
	memcpy(privkey, hash, 32);
	schnorr48_clamp_scalar(privkey);

	/* pubkey = privkey * B */
	crypto_eddsa_scalarbase(pubkey, privkey);

	/* Wipe sensitive data */
	crypto_wipe(hash, sizeof(hash));
}

int schnorr48_sign(const uint8_t *privkey,
		   const uint8_t *pubkey,
		   const uint8_t *msg, size_t msg_len,
		   uint8_t *sig)
{
	uint8_t nonce_hash[64];
	uint8_t r_scalar[32];
	uint8_t R[32];
	uint8_t e_hash[64];
	uint8_t e_extended[32];
	crypto_sha512_ctx ctx;

	/*
	 * Validate: if msg_len > 0, msg must not be NULL.
	 * Empty messages (msg_len == 0) are valid regardless of msg pointer.
	 */
	if (msg_len > 0 && msg == NULL) {
		/* Cannot sign: NULL message with nonzero length */
		memset(sig, 0, SCHNORR48_SIG_LEN);
		return -EINVAL;
	}

	/*
	 * 1. Deterministic nonce: r = SHA-512(privkey || msg) mod L
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, privkey, 32);
	if (msg_len > 0) {
		crypto_sha512_update(&ctx, msg, msg_len);
	}
	crypto_sha512_final(&ctx, nonce_hash);

	/* Reduce 64-byte hash to scalar mod L */
	crypto_eddsa_reduce(r_scalar, nonce_hash);

	/*
	 * 2. Commitment: R = r * B
	 */
	crypto_eddsa_scalarbase(R, r_scalar);

	/*
	 * 3. Challenge: e = SHA-512(R || pubkey || msg)[0:16]
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, R, 32);
	crypto_sha512_update(&ctx, pubkey, 32);
	if (msg_len > 0) {
		crypto_sha512_update(&ctx, msg, msg_len);
	}
	crypto_sha512_final(&ctx, e_hash);

	/* Copy truncated challenge to signature */
	memcpy(sig, e_hash, 16);

	/*
	 * 4. e_extended = e || 0x00*16 (32-byte scalar)
	 */
	memcpy(e_extended, e_hash, 16);
	memset(e_extended + 16, 0, 16);

	/*
	 * 5. s = (r + e_extended * privkey) mod L
	 *    Using crypto_eddsa_mul_add: r + a*b = r + e*priv
	 */
	crypto_eddsa_mul_add(sig + 16, e_extended, privkey, r_scalar);

	/* Wipe sensitive data */
	crypto_wipe(nonce_hash, sizeof(nonce_hash));
	crypto_wipe(r_scalar, sizeof(r_scalar));
	crypto_wipe(R, sizeof(R));
	crypto_wipe(e_hash, sizeof(e_hash));
	crypto_wipe(e_extended, sizeof(e_extended));
	crypto_wipe(&ctx, sizeof(ctx));

	return 0;
}

bool schnorr48_verify(const uint8_t *pubkey,
		      const uint8_t *msg, size_t msg_len,
		      const uint8_t *sig)
{
	const uint8_t *e_received = sig;
	const uint8_t *s = sig + 16;
	uint8_t e_extended[32];
	uint8_t R_prime[32];
	uint8_t e_hash[64];
	crypto_sha512_ctx ctx;

	/*
	 * Validate: if msg_len > 0, msg must not be NULL.
	 * Empty messages (msg_len == 0) are valid regardless of msg pointer.
	 */
	if (msg_len > 0 && msg == NULL) {
		return false;
	}
	if (!schnorr48_pubkey_valid(pubkey)) {
		return false;
	}

	/* s MUST be non-zero per spec §5.3. crypto_verify32 is constant-time. */
	static const uint8_t zero[32] = {0};
	if (crypto_verify32(s, zero) == 0) {
		return false;
	}

	/*
	 * 2. e_extended = e_received || 0x00*16
	 */
	memcpy(e_extended, e_received, 16);
	memset(e_extended + 16, 0, 16);

	/*
	 * 3. R' = s*B - e_extended*pubkey
	 *    Returns -1 if pubkey is invalid or s >= L
	 */
	if (crypto_eddsa_recover_r(R_prime, pubkey, s, e_extended) != 0) {
		return false;
	}

	/*
	 * 4. e' = SHA-512(R' || pubkey || msg)[0:16]
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, R_prime, 32);
	crypto_sha512_update(&ctx, pubkey, 32);
	if (msg_len > 0) {
		crypto_sha512_update(&ctx, msg, msg_len);
	}
	crypto_sha512_final(&ctx, e_hash);

	/*
	 * 5. Constant-time comparison of e' and e_received
	 */
	return crypto_verify16(e_hash, e_received) == 0;
}

bool schnorr48_pubkey_valid(const uint8_t *pubkey) {
	if (pubkey == NULL) return false;
	static const uint8_t lows[8][32] = {{0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x80},{0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},{0x26,0xe8,0x95,0x8f,0xc2,0xb2,0x27,0xb0,0x45,0xc3,0xf4,0x89,0xf2,0xef,0x98,0xf0,0xd5,0xdf,0xac,0x05,0xd3,0xc6,0x33,0x39,0xb1,0x38,0x02,0x88,0x6d,0x53,0xfc,0x05},{0xc7,0x17,0x6a,0x70,0x3d,0x4d,0xd8,0x4f,0xba,0x3c,0x0b,0x76,0x0d,0x10,0x67,0x0f,0x2a,0x20,0x53,0xfa,0x2c,0x39,0xcc,0xc6,0x4e,0xc7,0xfd,0x77,0x92,0xac,0x03,0x7a},{0xc7,0x17,0x6a,0x70,0x3d,0x4d,0xd8,0x4f,0xba,0x3c,0x0b,0x76,0x0d,0x10,0x67,0x0f,0x2a,0x20,0x53,0xfa,0x2c,0x39,0xcc,0xc6,0x4e,0xc7,0xfd,0x77,0x92,0xac,0x03,0xfa},{0x26,0xe8,0x95,0x8f,0xc2,0xb2,0x27,0xb0,0x45,0xc3,0xf4,0x89,0xf2,0xef,0x98,0xf0,0xd5,0xdf,0xac,0x05,0xd3,0xc6,0x33,0x39,0xb1,0x38,0x02,0x88,0x6d,0x53,0xfc,0x85}};
	uint8_t is_low = 0;
	for (int i = 0; i < 8; i++) {
		/* CT via crypto_verify32 (per spec §5.3); rejects low-order points. */
		is_low |= (uint8_t)(crypto_verify32(pubkey, lows[i]) == 0);
	}
	return is_low == 0;
}

#else /* !CONFIG_LICHEN_CRYPTO_MONOCYPHER */

/*
 * Stub implementation for builds without Monocypher.
 * These functions abort at runtime to prevent accidental deployment
 * of a system with no cryptographic security.
 */
#ifdef CONFIG_LICHEN_LINK_SCHNORR
#error "CONFIG_LICHEN_LINK_SCHNORR requires CONFIG_LICHEN_CRYPTO_MONOCYPHER"
#endif

#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noreturn))
#endif
static void schnorr48_stub_abort(const char *func)
{
	LOG_WRN("%s called without Monocypher - aborting\n", func);
	abort();
}

void schnorr48_derive_keypair(const uint8_t *seed,
			      uint8_t *privkey,
			      uint8_t *pubkey)
{
	(void)seed;
	(void)privkey;
	(void)pubkey;
	schnorr48_stub_abort("schnorr48_derive_keypair");
}

int schnorr48_sign(const uint8_t *privkey,
		   const uint8_t *pubkey,
		   const uint8_t *msg, size_t msg_len,
		   uint8_t *sig)
{
	(void)privkey;
	(void)pubkey;
	(void)msg;
	(void)msg_len;
	(void)sig;
	schnorr48_stub_abort("schnorr48_sign");
	return -EINVAL; /* unreachable, but satisfies compiler */
}

bool schnorr48_verify(const uint8_t *pubkey,
		      const uint8_t *msg, size_t msg_len,
		      const uint8_t *sig)
{
	(void)pubkey;
	(void)msg;
	(void)msg_len;
	(void)sig;
	schnorr48_stub_abort("schnorr48_verify");
	return false; /* unreachable, but satisfies compiler */
}

#endif /* CONFIG_LICHEN_CRYPTO_MONOCYPHER */

/*
 * Frame helpers - real implementation uses SHA-512 streaming to avoid
 * fixed-size buffers and handle arbitrary payload lengths.
 */
#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER

int schnorr48_sign_frame(uint8_t length, uint8_t llsec,
			 uint8_t epoch, uint16_t seqnum,
			 const uint8_t *dst_addr, size_t dst_addr_len,
			 const uint8_t *payload, size_t payload_len,
			 const uint8_t *privkey,
			 const uint8_t *pubkey,
			 uint8_t *sig)
{
	uint8_t header[14];

	size_t header_len = 0;
	uint8_t nonce_hash[64];
	uint8_t r_scalar[32];
	uint8_t R[32];
	uint8_t e_hash[64];
	uint8_t e_extended[32];
	crypto_sha512_ctx ctx;

	/* Validate dst_addr_len before use */
	if (dst_addr_len > SCHNORR48_MAX_ADDR_LEN) {
		return -EINVAL;
	}

	/* Validate: if dst_addr_len > 0, dst_addr must not be NULL */
	if (dst_addr_len > 0 && dst_addr == NULL) {
		return -EINVAL;
	}

	/* Validate: if payload_len > 0, payload must not be NULL */
	if (payload_len > 0 && payload == NULL) {
		return -EINVAL;
	}
	if (privkey == NULL || pubkey == NULL || sig == NULL) {
		return -EINVAL;
	}

	header[header_len++] = length;
	header[header_len++] = llsec;
	header[header_len++] = epoch;
	header[header_len++] = (uint8_t)(seqnum >> 8);
	header[header_len++] = (uint8_t)(seqnum & 0xFF);
	header[header_len++] = (uint8_t)dst_addr_len;
	if (dst_addr_len > 0) {
		memcpy(&header[header_len], dst_addr, dst_addr_len);
		header_len += dst_addr_len;
	}

	/*
	 * 1. Deterministic nonce: r = SHA-512(privkey || header || payload) mod L
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, privkey, 32);
	crypto_sha512_update(&ctx, header, header_len);
	if (payload_len > 0) {
		crypto_sha512_update(&ctx, payload, payload_len);
	}
	crypto_sha512_final(&ctx, nonce_hash);
	crypto_eddsa_reduce(r_scalar, nonce_hash);

	/*
	 * 2. Commitment: R = r * B
	 */
	crypto_eddsa_scalarbase(R, r_scalar);

	/*
	 * 3. Challenge: e = SHA-512(R || pubkey || header || payload)[0:16]
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, R, 32);
	crypto_sha512_update(&ctx, pubkey, 32);
	crypto_sha512_update(&ctx, header, header_len);
	if (payload_len > 0) {
		crypto_sha512_update(&ctx, payload, payload_len);
	}
	crypto_sha512_final(&ctx, e_hash);

	/* Copy truncated challenge to signature */
	memcpy(sig, e_hash, 16);

	/*
	 * 4. e_extended = e || 0x00*16 (32-byte scalar)
	 */
	memcpy(e_extended, e_hash, 16);
	memset(e_extended + 16, 0, 16);

	/*
	 * 5. s = (r + e_extended * privkey) mod L
	 */
	crypto_eddsa_mul_add(sig + 16, e_extended, privkey, r_scalar);

	/* Wipe sensitive data */
	crypto_wipe(nonce_hash, sizeof(nonce_hash));
	crypto_wipe(r_scalar, sizeof(r_scalar));
	crypto_wipe(R, sizeof(R));
	crypto_wipe(e_hash, sizeof(e_hash));
	crypto_wipe(e_extended, sizeof(e_extended));
	crypto_wipe(&ctx, sizeof(ctx));

	return 0;
}

int schnorr48_verify_frame(uint8_t length, uint8_t llsec,
			   uint8_t epoch, uint16_t seqnum,
			   const uint8_t *dst_addr, size_t dst_addr_len,
			   const uint8_t *payload, size_t payload_len,
			   const uint8_t *sig,
			   const uint8_t *pubkey)
{
	/* Validate dst_addr_len before use */
	if (dst_addr_len > SCHNORR48_MAX_ADDR_LEN) {
		return -EINVAL;
	}

	/* Validate: if dst_addr_len > 0, dst_addr must not be NULL */
	if (dst_addr_len > 0 && dst_addr == NULL) {
		return -EINVAL;
	}

	/* Validate: if payload_len > 0, payload must not be NULL */
	if (payload_len > 0 && payload == NULL) {
		return -EINVAL;
	}

	/* Validate: pubkey must not be NULL (needed for signature verification) */
	if (pubkey == NULL) {
		return -EINVAL;
	}
	if (!schnorr48_pubkey_valid(pubkey)) {
		return 0;
	}

	if (sig == NULL) {
		return -EINVAL;
	}
	const uint8_t *e_received = sig;
	const uint8_t *s = sig + 16;

	uint8_t header[14];
	size_t header_len = 0;
	uint8_t e_extended[32];
	uint8_t R_prime[32];
	uint8_t e_hash[64];
	crypto_sha512_ctx ctx;

	header[header_len++] = length;
	header[header_len++] = llsec;
	header[header_len++] = epoch;
	header[header_len++] = (uint8_t)(seqnum >> 8);
	header[header_len++] = (uint8_t)(seqnum & 0xFF);
	header[header_len++] = (uint8_t)dst_addr_len;
	if (dst_addr_len > 0) {
		memcpy(&header[header_len], dst_addr, dst_addr_len);
		header_len += dst_addr_len;
	}

	static const uint8_t zero[32] = {0};
	if (crypto_verify32(s, zero) == 0) {
		return 0;
	}

	/*
	 * 2. e_extended = e_received || 0x00*16
	 */
	memcpy(e_extended, e_received, 16);
	memset(e_extended + 16, 0, 16);

	/*
	 * 3. R' = s*B - e_extended*pubkey
	 */
	if (crypto_eddsa_recover_r(R_prime, pubkey, s, e_extended) != 0) {
		return 0;
	}

	/*
	 * 4. e' = SHA-512(R' || pubkey || header || inner_payload)[0:16]
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, R_prime, 32);
	crypto_sha512_update(&ctx, pubkey, 32);
	crypto_sha512_update(&ctx, header, header_len);
	if (payload_len > 0) {
		crypto_sha512_update(&ctx, payload, payload_len);
	}
	crypto_sha512_final(&ctx, e_hash);

	/*
	 * 5. Constant-time comparison of e' and e_received
	 */
	return crypto_verify16(e_hash, e_received) == 0 ? 1 : 0;
}

#else /* !CONFIG_LICHEN_CRYPTO_MONOCYPHER */

int schnorr48_sign_frame(uint8_t length, uint8_t llsec,
			 uint8_t epoch, uint16_t seqnum,
			 const uint8_t *dst_addr, size_t dst_addr_len,
			 const uint8_t *payload, size_t payload_len,
			 const uint8_t *privkey,
			 const uint8_t *pubkey,
			 uint8_t *sig)
{
	(void)length;
	(void)llsec;
	(void)epoch;
	(void)seqnum;
	(void)dst_addr;
	(void)dst_addr_len;
	(void)payload;
	(void)payload_len;
	(void)privkey;
	(void)pubkey;
	(void)sig;
	schnorr48_stub_abort("schnorr48_sign_frame");
	return -EINVAL; /* unreachable, but satisfies compiler */
}

int schnorr48_verify_frame(uint8_t length, uint8_t llsec,
			   uint8_t epoch, uint16_t seqnum,
			   const uint8_t *dst_addr, size_t dst_addr_len,
			   const uint8_t *payload, size_t payload_len,
			   const uint8_t *sig,
			   const uint8_t *pubkey)
{
	(void)length;
	(void)llsec;
	(void)epoch;
	(void)seqnum;
	(void)dst_addr;
	(void)dst_addr_len;
	(void)payload;
	(void)payload_len;
	(void)sig;
	(void)pubkey;
	schnorr48_stub_abort("schnorr48_verify_frame");
	return -EINVAL; /* unreachable, but satisfies compiler */
}

#endif /* CONFIG_LICHEN_CRYPTO_MONOCYPHER */
