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
#include <lichen/tx_queue.h>

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

/** Retained legacy link-key length; encrypted link frames are unsupported */
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
	uint8_t link_key[LICHEN_LINK_KEY_LEN]; /**< Retained legacy link key */
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
	struct tx_queue tx_queue; /**< TX queue with priority and deadline support */
};

/** Atomic signing identity snapshot. Clear immediately after use. */
struct lichen_link_keypair_snapshot {
	uint8_t eui64[LICHEN_EUI64_LEN];
	uint8_t sk[LICHEN_SK_LEN];
	uint8_t pk[LICHEN_PK_LEN];
};

/**
 * @brief Initialize link context with an EUI-64 address.
 *
 * Obtains CSPRNG entropy for initial epoch BEFORE any context or mutex
 * mutation (fail-closed). On CSPRNG failure returns -EIO with ctx
 * unmodified. Sets EUI-64, clears crypto state; has_key=false.
 * Callers with persisted epoch MUST call lichen_link_set_epoch()
 * after successful init.
 *
 * @param[out] ctx   Link context to initialize
 * @param[in]  eui64 8-byte EUI-64 address
 * @return 0 on success, -EINVAL if ctx or eui64 is NULL, -EIO on CSPRNG failure
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
 * @brief Derive a per-node seed from a base seed and an EUI-64.
 *
 * out_seed = SHA-512(base_seed || eui64)[0:32]. Deterministic: any node
 * that knows base_seed and a peer's EUI-64 can derive that peer's seed
 * (and via lichen_link_derive_pubkey() its public key).
 *
 * SECURITY: This is a domain-separation helper, not a key-strengthening
 * one. If base_seed is public (e.g. the INSECURE dev-provisioning seed),
 * every derived key is public too. Its purpose is to give distinct nodes
 * distinct keypairs so signature verification attributes frames to the
 * correct peer (see project-LICHEN-wp4o for the shared-key replay-window
 * collision this prevents).
 *
 * @param[in]  base_seed 32-byte base seed
 * @param[in]  eui64     Node's EUI-64 address
 * @param[out] out_seed  Derived 32-byte seed
 * @return 0 on success, -EINVAL on NULL parameters
 */
int lichen_link_derive_seed(const uint8_t base_seed[_Nonnull LICHEN_SEED_LEN],
			    const uint8_t eui64[_Nonnull LICHEN_EUI64_LEN],
			    uint8_t out_seed[_Nonnull LICHEN_SEED_LEN]);

/**
 * @brief Compute the public key for a seed without loading it.
 *
 * Uses the same derivation as lichen_link_load_key() (SHA-512 + clamp +
 * scalar-base multiply), so the result equals the ed25519_pk that
 * lichen_link_load_key() would install for the same seed. Does not touch
 * any link context or retain the secret key.
 *
 * @param[in]  seed   32-byte seed
 * @param[out] out_pk Ed25519 public key
 * @return 0 on success, -EINVAL on NULL parameters
 */
int lichen_link_derive_pubkey(const uint8_t seed[_Nonnull LICHEN_SEED_LEN],
			      uint8_t out_pk[_Nonnull LICHEN_PK_LEN]);

/**
 * @brief Increment and return the next TX sequence number.
 *
 * The sequence number wraps from 0xFFFF to 0x0000. When this happens,
 * the epoch is incremented. If the epoch wraps from 255 to 0, the nonce
 * space is exhausted and this function returns an error.
 *
 * SECURITY: After 256 * 65536 = 16M frames, the epoch/sequence space is
 * exhausted. This function sets ctx->nonce_exhausted and returns -EOVERFLOW
 * when this occurs. TX is blocked until key rotation clears the flag.
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
 * The epoch is typically incremented when the TX sequence wraps.
 *
 * @param[in,out] ctx   Link context
 * @param[in]     epoch New epoch value
 * @return 0 on success, -EINVAL if ctx NULL, -EIO on lock failure
 */
int lichen_link_set_epoch(struct lichen_link_ctx *_Nonnull ctx, uint8_t epoch);

#ifdef CONFIG_LICHEN_LINK_EPOCH_PERSIST
/**
 * @brief Compute and persist this boot's TX epoch.
 *
 * Loads the epoch saved by the previous boot from the settings subsystem,
 * advances it by one (with 8-bit wrap), persists the new value, and
 * returns it. Idempotent within a boot: repeated calls return the same
 * value without advancing or re-writing. Install the result with
 * lichen_link_set_epoch() after lichen_link_init().
 *
 * Advancing by one keeps the node's (epoch, seqnum) counter monotonically
 * ahead of what peers remember in their replay windows, so frames after a
 * reboot are not rejected as replays (lora_ipv6_mesh-3uhb).
 *
 * @return the TX epoch to use for this boot
 */
uint8_t lichen_link_epoch_advance_for_boot(void);

/** Persist an epoch before it becomes live after a sequence wrap. */
int lichen_link_epoch_persist(uint8_t epoch);

#ifdef CONFIG_LICHEN_LINK_EPOCH_TEST_HOOKS
/**
 * @brief Test hook: clear the in-RAM boot-epoch cache (simulate a reboot).
 *
 * The persisted value in the settings backend is retained, so a following
 * lichen_link_epoch_advance_for_boot() re-loads it and advances as if the
 * node had rebooted. Testing only.
 */
void lichen_link_epoch_test_reset(void);
#endif
#endif /* CONFIG_LICHEN_LINK_EPOCH_PERSIST */

/**
 * @brief Load a retained legacy link key.
 *
 * Encrypted link frames are unsupported by the current wire profile; signed
 * frames use the Schnorr-48 signature as their MIC.
 *
 * @param[in,out] ctx      Link context
 * @param[in]     link_key 16-byte retained legacy key
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
 * @warning THREAD SAFETY: This function has single-owner semantics. The caller
 *          MUST ensure no concurrent operations (TX, RX, key loading) are in
 *          progress on this context before calling cleanup. Calling cleanup
 *          while another thread holds the context lock will result in
 *          undefined behavior: keys may be wiped mid-operation, corrupting
 *          cryptographic output or causing information leakage.
 *
 *          Typical safe usage patterns:
 *          1. Shutdown: Stop all TX/RX threads before calling cleanup
 *          2. Key rotation: Use atomic key replacement (load_key) instead
 *             of cleanup + load_key sequence
 *          3. Single-threaded: No concern if context is thread-local
 *
 * @note The eui64 field is intentionally NOT cleared. The EUI-64 is the
 *       node's network identity and is not secret material. Preserving it
 *       allows the context to be reused with new keys without re-initialization.
 *       If a full reset including eui64 is needed, call lichen_link_init() again.
 *
 * @param[in,out] ctx Link context to clean up (may be NULL, no-op)
 */
void lichen_link_cleanup(struct lichen_link_ctx *_Nullable ctx);

/**
 * @brief Atomically copy public identity data from a link context.
 *
 * Copies the node's EUI-64 and public key under the context's internal lock,
 * preventing races with lichen_link_cleanup() or lichen_link_load_key().
 * Use this instead of directly reading ctx fields when thread safety is required.
 *
 * @param[in]  ctx      Link context to read from
 * @param[out] eui64    Buffer to receive EUI-64 (LICHEN_EUI64_LEN bytes), or NULL to skip
 * @param[out] pk       Buffer to receive public key (LICHEN_PK_LEN bytes), or NULL to skip
 * @param[out] has_key  Pointer to receive key availability flag, or NULL to skip
 *
 * @return 0 on success, -EINVAL if ctx is NULL, -ENOKEY if no key is loaded
 */
int lichen_link_copy_identity(const struct lichen_link_ctx *_Nonnull ctx,
			      uint8_t eui64[_Nullable LICHEN_EUI64_LEN],
			      uint8_t pk[_Nullable LICHEN_PK_LEN],
			      bool *_Nullable has_key);

/**
 * @brief Derive 16-byte Yggdrasil address from Ed25519 public key
 *
 * Consistent with Rust yggdrasil_addr_from_pubkey and spec/04-network.md:
 * - byte 0 = 0x02 (Yggdrasil 0200::/7 range)
 * - bytes 1-7 = SHA-512(pubkey)[0:7]
 * - bytes 8-15 = IID derived from pubkey (ensures IID matches node's primary address)
 *
 * Matches test vectors in test/vectors/yggdrasil-derivation.json (cross-validated with official Yggdrasil, Rust, Python, C oracles).
 *
 * @param pubkey 32-byte Ed25519 public key
 * @param ygg_addr Output buffer for 16-byte address
 * @return 0 on success, negative errno on error
 */
int lichen_identity_ygg_addr_from_ed25519(const uint8_t *pubkey,
					  uint8_t ygg_addr[16]);

int lichen_coordination_negotiate(struct lichen_link_ctx *_Nonnull ctx);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LINK_CTX_H_ */
