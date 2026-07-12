/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/link_ctx.h
 * @brief LICHEN link layer context
 *
 * Manages per-node link layer state: identity (EUI-64), Ed25519 keypair
 * for Schnorr-48 signatures, epoch counter, and TX sequence number.
 *
 * Replay window tracking is handled separately per-neighbor in replay.h.
 */

#ifndef LICHEN_LINK_CTX_H_
#define LICHEN_LINK_CTX_H_

#include <stdint.h>
#include <stdbool.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __ZEPHYR__
#include <zephyr/kernel.h>
#else
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** EUI-64 address length */
#define LICHEN_EUI64_LEN 8

/** Ed25519 seed length (input to key derivation) */
#define LICHEN_SEED_LEN 32

/** Ed25519 secret key length (clamped scalar) */
#define LICHEN_SK_LEN 32

/** Ed25519 public key length (compressed point) */
#define LICHEN_PK_LEN 32

/** AES-128 link-layer key length */
#define LICHEN_LINK_KEY_LEN 16

/**
 * @brief LICHEN link layer context
 *
 * Holds the node's identity and cryptographic material for the link layer.
 * Initialize with lichen_link_init(), then load keys with lichen_link_load_key().
 */
struct lichen_link_ctx {
	uint8_t eui64[LICHEN_EUI64_LEN]; /**< Node's EUI-64 address */
	uint8_t ed25519_sk[LICHEN_SK_LEN]; /**< Ed25519 secret key (clamped) */
	uint8_t ed25519_pk[LICHEN_PK_LEN]; /**< Ed25519 public key */
	uint8_t link_key[LICHEN_LINK_KEY_LEN]; /**< AES-128 key for link MIC */
	uint8_t epoch;    /**< Current epoch (key rotation counter) */
	uint16_t tx_seq;  /**< TX sequence counter */
	bool has_key;     /**< Whether keypair is loaded */
	bool has_link_key; /**< Whether link-layer key is loaded */
	bool nonce_exhausted; /**< Nonce space exhausted, TX blocked until key rotation */
#ifdef __ZEPHYR__
	struct k_mutex seq_lock; /**< Protects TX epoch/sequence allocation */
#else
	pthread_mutex_t seq_lock; /**< Protects TX epoch/sequence allocation */
#endif
};

/**
 * @brief Initialize link context with an EUI-64 address.
 *
 * Sets the node's EUI-64 identity and clears all cryptographic state.
 * After calling this, the context has no keypair loaded (has_key = false).
 *
 * @param[out] ctx   Link context to initialize
 * @param[in]  eui64 8-byte EUI-64 address
 * @return 0 on success, -EINVAL if ctx or eui64 is NULL
 */
int lichen_link_init(struct lichen_link_ctx *_Nonnull ctx,
		     const uint8_t *_Nonnull eui64);

/**
 * @brief Load an Ed25519 keypair from a 32-byte seed.
 *
 * Derives the Ed25519 keypair using the Schnorr-48 key derivation
 * (SHA-512 + clamping), which is compatible with standard Ed25519.
 *
 * @warning SECURITY: The seed MUST be from a CSPRNG. Prefer
 *          lichen_link_generate_key() which handles CSPRNG internally.
 *
 * @param[in,out] ctx  Link context
 * @param[in]     seed 32-byte random seed (MUST be from a CSPRNG)
 * @return 0 on success, -EINVAL if ctx or seed is NULL
 */
int lichen_link_load_key(struct lichen_link_ctx *_Nonnull ctx,
			 const uint8_t seed[_Nonnull 32]);

/**
 * @brief Generate and load an Ed25519 keypair from the platform CSPRNG.
 *
 * Recommended way to initialize link-layer keys. Internally calls the
 * platform's CSPRNG (sys_csrand_get on Zephyr, getrandom on POSIX).
 *
 * @param[in,out] ctx Link context
 * @return 0 on success, -EINVAL if ctx is NULL, -EIO if CSPRNG fails
 */
int lichen_link_generate_key(struct lichen_link_ctx *_Nonnull ctx);

/**
 * @brief Increment and return the next TX sequence number.
 *
 * The sequence number wraps from 0xFFFF to 0x0000. When this happens,
 * the epoch is incremented. If the epoch wraps from 255 to 0, the nonce
 * space is exhausted and this function returns an error.
 *
 * SECURITY: After 256 * 65536 = 16M frames, the nonce space is exhausted.
 * The nonce for AES-CCM is (eui64, epoch, seqnum), so continuing to TX
 * after nonce exhaustion would cause catastrophic nonce reuse. This
 * function sets ctx->nonce_exhausted and returns -EOVERFLOW when this
 * occurs. TX is blocked until key rotation clears the flag.
 *
 * @param[in,out] ctx    Link context
 * @param[out]    seqnum Pointer to receive the sequence number (on success)
 *
 * @return 0 on success, -EINVAL if ctx/seqnum is NULL, -EOVERFLOW if nonce exhausted
 */
int lichen_link_next_seq(struct lichen_link_ctx *_Nonnull ctx,
			 uint16_t *_Nonnull seqnum);

/**
 * @brief Allocate the next TX nonce tuple.
 *
 * Atomically allocates a unique (epoch, seqnum) pair for transmission on this
 * context. Callers that build authenticated frames MUST use the returned epoch
 * with the returned sequence number; reading ctx->epoch separately can race
 * with another transmitter crossing a sequence wrap boundary.
 *
 * @param[in,out] ctx    Link context
 * @param[out]    epoch  Pointer to receive the allocated epoch (on success)
 * @param[out]    seqnum Pointer to receive the allocated sequence number (on success)
 *
 * @return 0 on success, -EINVAL if an argument is NULL, -EOVERFLOW if nonce exhausted
 */
int lichen_link_next_tx(struct lichen_link_ctx *_Nonnull ctx,
			uint8_t *_Nonnull epoch,
			uint16_t *_Nonnull seqnum);

/**
 * @brief Set the current epoch.
 *
 * The epoch is typically incremented when the TX sequence wraps or
 * when a new symmetric key is derived for encryption.
 *
 * @param[in,out] ctx   Link context
 * @param[in]     epoch New epoch value
 */
void lichen_link_set_epoch(struct lichen_link_ctx *_Nonnull ctx, uint8_t epoch);

/**
 * @brief Load a 128-bit AES key for link-layer MIC computation.
 *
 * This key is used for AES-CCM-64 MIC computation/verification on
 * link-layer frames. It is typically derived from a shared secret
 * or pre-shared key.
 *
 * @param[in,out] ctx      Link context
 * @param[in]     link_key 16-byte AES-128 key
 * @return 0 on success, -EINVAL if ctx or link_key is NULL
 */
int lichen_link_load_link_key(struct lichen_link_ctx *_Nonnull ctx,
			      const uint8_t link_key[_Nonnull LICHEN_LINK_KEY_LEN]);

/**
 * @brief Securely wipe all key material and reset the context.
 *
 * Clears ed25519_sk, link_key using secure wipe (cannot be optimized
 * away by the compiler), then resets has_key/has_link_key flags and
 * sequence state.
 *
 * Call this before freeing a context or when keys are no longer needed.
 *
 * @note The eui64 field is intentionally NOT cleared. The EUI-64 is the
 *       node's network identity and is not secret material. Preserving it
 *       allows the context to be reused with new keys without re-initialization.
 *       If a full reset including eui64 is needed, call lichen_link_init() again.
 *
 * @param[in,out] ctx Link context to clean up (may be NULL, no-op)
 */
void lichen_link_cleanup(struct lichen_link_ctx *_Nullable ctx);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LINK_CTX_H_ */
