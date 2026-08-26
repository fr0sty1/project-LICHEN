/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file sos_origin.c
 * @brief SOS origin signature verification (spec 18.4.1)
 *
 * Implementation of origin signature generation and verification for SOS
 * messages. Uses Schnorr48 signatures with SHA-512 transcript.
 *
 * Reference: python/src/lichen/coap/sos_origin.py
 * Test vectors: test/vectors/sos_signature.json
 */

#include <lichen/sos_origin.h>
#include <lichen/schnorr48.h>
#include <string.h>
#include <errno.h>

/* ---- Logging ------------------------------------------------------------ */

#include <lichen/lichen_log.h>

#ifdef __ZEPHYR__
#ifndef CONFIG_LICHEN_LINK_LOG_LEVEL
#define CONFIG_LICHEN_LINK_LOG_LEVEL LOG_LEVEL_INF
#endif
LICHEN_LOG_MODULE(sos_origin, CONFIG_LICHEN_LINK_LOG_LEVEL);
#else
LICHEN_LOG_MODULE(sos_origin, LOG_LEVEL_WRN);
#endif

/* ---- Domain separator --------------------------------------------------- */

static const uint8_t sos_domain[] = "LICHEN-SOS-ORIGIN-v1";
/* Compile-time check that domain length matches */
_Static_assert(sizeof(sos_domain) == SOS_ORIGIN_DOMAIN_LEN + 1,
	       "SOS_ORIGIN_DOMAIN_LEN mismatch");

/* ---- Monocypher SHA-512 ------------------------------------------------- */

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
#include "monocypher.h"
#include "monocypher-ed25519.h"

int sos_origin_signature_parse(struct sos_origin_signature *out,
			       const uint8_t *data, size_t len)
{
	if (out == NULL || data == NULL) {
		return -EINVAL;
	}
	if (len != SOS_ORIGIN_SIGNATURE_LEN) {
		return -EINVAL;
	}

	/* Parse 8-byte big-endian sequence */
	out->origin_sequence = 0;
	for (int i = 0; i < 8; i++) {
		out->origin_sequence = (out->origin_sequence << 8) | data[i];
	}

	/* Copy 48-byte signature */
	memcpy(out->signature, data + 8, 48);

	return 0;
}

int sos_origin_signature_serialize(const struct sos_origin_signature *sig,
				   uint8_t *out, size_t len)
{
	if (sig == NULL || out == NULL) {
		return -EINVAL;
	}
	if (len < SOS_ORIGIN_SIGNATURE_LEN) {
		return -EINVAL;
	}

	/* Serialize 8-byte big-endian sequence */
	for (int i = 7; i >= 0; i--) {
		out[7 - i] = (uint8_t)(sig->origin_sequence >> (8 * i));
	}

	/* Copy 48-byte signature */
	memcpy(out + 8, sig->signature, 48);

	return 0;
}

int sos_origin_compute_transcript(const uint8_t *origin_ipv6,
				  uint64_t origin_seq,
				  const uint8_t *payload_cbor,
				  size_t payload_len,
				  uint8_t *digest)
{
	uint8_t seq_be[8];
	crypto_sha512_ctx ctx;

	if (origin_ipv6 == NULL || digest == NULL) {
		return -EINVAL;
	}
	if (payload_len > 0 && payload_cbor == NULL) {
		return -EINVAL;
	}

	/* Serialize sequence as big-endian */
	for (int i = 7; i >= 0; i--) {
		seq_be[7 - i] = (uint8_t)(origin_seq >> (8 * i));
	}

	/* Compute SHA-512(domain || origin_ipv6 || seq || cbor) */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, sos_domain, SOS_ORIGIN_DOMAIN_LEN);
	crypto_sha512_update(&ctx, origin_ipv6, SOS_ORIGIN_IPV6_LEN);
	crypto_sha512_update(&ctx, seq_be, sizeof(seq_be));
	if (payload_len > 0) {
		crypto_sha512_update(&ctx, payload_cbor, payload_len);
	}
	crypto_sha512_final(&ctx, digest);

	/* Wipe context */
	crypto_wipe(&ctx, sizeof(ctx));

	return 0;
}

bool sos_origin_verify(const uint8_t *pubkey,
		       const uint8_t *origin_ipv6,
		       const uint8_t *payload_cbor,
		       size_t payload_len,
		       const struct sos_origin_signature *sig)
{
	uint8_t digest[64];
	int ret;
	bool valid;

	if (pubkey == NULL || origin_ipv6 == NULL || sig == NULL) {
		return false;
	}
	if (payload_len > 0 && payload_cbor == NULL) {
		return false;
	}

	/* Compute transcript */
	ret = sos_origin_compute_transcript(origin_ipv6, sig->origin_sequence,
					    payload_cbor, payload_len, digest);
	if (ret < 0) {
		return false;
	}

	/* Verify Schnorr48 signature */
	valid = schnorr48_verify(pubkey, digest, sizeof(digest),
				 sig->signature, sizeof(sig->signature));

	/* Wipe digest */
	crypto_wipe(digest, sizeof(digest));

	return valid;
}

int sos_origin_sign(const uint8_t *privkey,
		    const uint8_t *pubkey,
		    const uint8_t *origin_ipv6,
		    uint64_t origin_seq,
		    const uint8_t *payload_cbor,
		    size_t payload_len,
		    struct sos_origin_signature *sig)
{
	uint8_t digest[64];
	int ret;

	if (privkey == NULL || pubkey == NULL || origin_ipv6 == NULL || sig == NULL) {
		return -EINVAL;
	}
	if (payload_len > 0 && payload_cbor == NULL) {
		return -EINVAL;
	}

	/* Compute transcript */
	ret = sos_origin_compute_transcript(origin_ipv6, origin_seq,
					    payload_cbor, payload_len, digest);
	if (ret < 0) {
		return ret;
	}

	/* Sign with Schnorr48 */
	ret = schnorr48_sign(privkey, pubkey, digest, sizeof(digest), sig->signature);
	if (ret < 0) {
		crypto_wipe(digest, sizeof(digest));
		return ret;
	}

	sig->origin_sequence = origin_seq;

	/* Wipe digest */
	crypto_wipe(digest, sizeof(digest));

	return 0;
}

#else /* !CONFIG_LICHEN_CRYPTO_MONOCYPHER */

/*
 * Stub implementations for builds without Monocypher.
 */

int sos_origin_signature_parse(struct sos_origin_signature *out,
			       const uint8_t *data, size_t len)
{
	if (out == NULL || data == NULL || len != SOS_ORIGIN_SIGNATURE_LEN) {
		return -EINVAL;
	}

	out->origin_sequence = 0;
	for (int i = 0; i < 8; i++) {
		out->origin_sequence = (out->origin_sequence << 8) | data[i];
	}
	memcpy(out->signature, data + 8, 48);
	return 0;
}

int sos_origin_signature_serialize(const struct sos_origin_signature *sig,
				   uint8_t *out, size_t len)
{
	if (sig == NULL || out == NULL || len < SOS_ORIGIN_SIGNATURE_LEN) {
		return -EINVAL;
	}

	for (int i = 7; i >= 0; i--) {
		out[7 - i] = (uint8_t)(sig->origin_sequence >> (8 * i));
	}
	memcpy(out + 8, sig->signature, 48);
	return 0;
}

int sos_origin_compute_transcript(const uint8_t *origin_ipv6,
				  uint64_t origin_seq,
				  const uint8_t *payload_cbor,
				  size_t payload_len,
				  uint8_t *digest)
{
	(void)origin_ipv6;
	(void)origin_seq;
	(void)payload_cbor;
	(void)payload_len;
	(void)digest;
	LOG_WRN("sos_origin_compute_transcript: Monocypher not available");
	return -ENOSYS;
}

bool sos_origin_verify(const uint8_t *pubkey,
		       const uint8_t *origin_ipv6,
		       const uint8_t *payload_cbor,
		       size_t payload_len,
		       const struct sos_origin_signature *sig)
{
	(void)pubkey;
	(void)origin_ipv6;
	(void)payload_cbor;
	(void)payload_len;
	(void)sig;
	LOG_WRN("sos_origin_verify: Monocypher not available");
	return false;
}

int sos_origin_sign(const uint8_t *privkey,
		    const uint8_t *pubkey,
		    const uint8_t *origin_ipv6,
		    uint64_t origin_seq,
		    const uint8_t *payload_cbor,
		    size_t payload_len,
		    struct sos_origin_signature *sig)
{
	(void)privkey;
	(void)pubkey;
	(void)origin_ipv6;
	(void)origin_seq;
	(void)payload_cbor;
	(void)payload_len;
	(void)sig;
	LOG_WRN("sos_origin_sign: Monocypher not available");
	return -ENOSYS;
}

#endif /* CONFIG_LICHEN_CRYPTO_MONOCYPHER */
