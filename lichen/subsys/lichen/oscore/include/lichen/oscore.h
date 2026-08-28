/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/oscore.h
 * @brief OSCORE (RFC 8613) API for end-to-end CoAP security
 *
 * Implements Object Security for Constrained RESTful Environments using
 * AES-CCM-16-64-128 (Algorithm ID 10 from RFC 8152).
 *
 * Cipher parameters:
 *   - 128-bit key
 *   - 104-bit nonce (13 bytes)
 *   - 64-bit authentication tag (8 bytes)
 *   - 16-byte L field for CCM
 *
 * Key derivation uses HKDF-SHA256 per RFC 8613 Section 3.2.
 *
 * @anchor oscore_key_rotation
 * ## Key Rotation
 *
 * OSCORE contexts have a finite lifetime bounded by the 40-bit sender sequence
 * number. OSCORE_SSN_MAX (2^40 - 1) is the terminal usable value; after it is
 * reserved, oscore_protect_request() returns OSCORE_ERR_SEQ_EXHAUSTED.
 *
 * ### Recommended rotation pattern:
 *
 * 1. **Monitor remaining budget** - Call oscore_ctx_get_seq_remaining()
 *    periodically (e.g., every 1000 messages). Trigger rotation when
 *    remaining < threshold (suggest 1,000,000 for proactive, 10,000 critical).
 *
 * 2. **Establish new keys** - Run EDHOC (see edhoc.h) or your key agreement
 *    protocol with the peer to derive a fresh master secret.
 *
 * 3. **Create new context** - Call oscore_ctx_create() with the new master
 *    secret. The old context remains valid for receiving in-flight messages.
 *
 * 4. **Transition sending** - Switch application code to use the new context
 *    for outgoing messages. Coordinate with the peer (e.g., via a CoAP signal
 *    or by including kid_context in the OSCORE option).
 *
 * 5. **Drain and retire old context** - After a grace period for in-flight
 *    messages, call oscore_ctx_free() on the old context.
 *
 * ### Why no oscore_ctx_rotate() API?
 *
 * Key rotation inherently requires peer coordination (both sides must agree on
 * the new master secret). This coordination is protocol-specific:
 *   - EDHOC for new key establishment
 *   - Application-level signaling for transition timing
 *   - Grace periods for in-flight message handling
 *
 * Rather than impose a specific coordination model, this API provides the
 * building blocks (sequence monitoring, context creation/destruction) and
 * leaves coordination to the integrator. See RFC 8613 Appendix B.2 for
 * security considerations on key update.
 */

#ifndef LICHEN_OSCORE_H_
#define LICHEN_OSCORE_H_

#include <stdint.h>
#include <stddef.h>
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

#ifdef __cplusplus
extern "C" {
#endif

/** AES-CCM-16-64-128 key length */
#define OSCORE_KEY_LEN 16

/** AES-CCM-16-64-128 nonce length (13 bytes) */
#define OSCORE_NONCE_LEN 13

/** AES-CCM-16-64-128 tag length (8 bytes) */
#define OSCORE_TAG_LEN 8

/** Maximum Sender/Recipient ID length */
#define OSCORE_ID_MAX_LEN 8

/** Maximum Partial IV length */
#define OSCORE_PIV_MAX_LEN 5

/** Maximum ID Context length */
#define OSCORE_ID_CONTEXT_MAX_LEN 8

/** EUI-64 address length for peer identification */
#define OSCORE_EUI64_LEN 8

/**
 * Maximum Sender Sequence Number (SSN) per RFC 8613 Section 7.2.1.
 * Uses the full 40-bit range (5-byte PIV) for cross-implementation
 * compatibility with Rust and Python implementations. Matches the
 * OscoreSeqNum::MAX constant (1 << 40) - 1 in the Rust OSCORE crate.
 * Implementations should trigger key rotation well before exhaustion.
 */
#define OSCORE_SSN_MAX ((1ULL << 40) - 1)

/**
 * Recommended SSN threshold for proactive key rotation warning.
 * Trigger rotation when remaining < 1,000,000 messages.
 */
#define OSCORE_SSN_ROTATION_WARNING 1000000

/**
 * Critical SSN threshold for mandatory key rotation.
 * Trigger immediate rotation when remaining < 10,000 messages.
 */
#define OSCORE_SSN_ROTATION_CRITICAL 10000

/**
 * Safety margin skipped past the next unused sender sequence on every
 * successful SSN persist. oscore_ctx_persist_ssn() stores
 * sender_seq + OSCORE_SSN_SAFETY_MARGIN and, only after the write succeeds,
 * advances the in-RAM sender_seq to that same value, so a reboot that
 * reloads from NVM resumes STRICTLY ABOVE every sequence that could have
 * been transmitted before the crash - no (key, nonce) pair is reused
 * (RFC 8613 Section 7.2, Appendix D.4). The skipped sequences are never
 * used as nonces. Without a registered NVM write callback the margin is not
 * applied (nothing is durable; reboot safety then rests on the mandatory
 * oscore_ctx_set_sender_seq() call after every reboot).
 */
#define OSCORE_SSN_SAFETY_MARGIN 1024

/** OSCORE CoAP option number */
#define COAP_OPTION_OSCORE 9

/**
 * @brief OSCORE error codes
 */
enum oscore_err {
	OSCORE_OK = 0,
	OSCORE_ERR_INVALID_PARAM = -1,
	OSCORE_ERR_NO_CONTEXT = -2,
	OSCORE_ERR_REPLAY = -3,
	OSCORE_ERR_DECRYPT_FAILED = -4,
	OSCORE_ERR_BUFFER_TOO_SMALL = -5,
	OSCORE_ERR_KEY_DERIVATION = -6,
	OSCORE_ERR_NO_MEMORY = -7,
	OSCORE_ERR_SEQ_EXHAUSTED = -8,  /**< Sender sequence exhausted, key rotation required */
	OSCORE_ERR_ENCRYPT_FAILED = -9, /**< Encryption failed */
	/**< NVM SSN persistence or restoration failed. In protect_request(), triggers
	 * rollback of sender_seq (retry with same nonce safe). In set_sender_seq(),
	 * the context stays uninitialized; in persist_ssn(), the in-RAM SSN is
	 * left unchanged (no margin advance). Guarantees (key,nonce)
	 * uniqueness per RFC 8613 §7.2.1, Appendix D.4 even on transient NVM errors.
	 * See oscore_protect_request() nvm_failed path and security comment. */
	OSCORE_ERR_NVM_FAILED = -10,
	OSCORE_ERR_CONTEXT_STALE = -11, /**< Context freshness check failed (RFC 8613 7.2.1) */
};

/**
 * @brief Context freshness status per RFC 8613 Section 7.2.1.
 */
enum oscore_freshness {
	OSCORE_FRESHNESS_OK = 0,      /**< Context is fresh, safe to use */
	OSCORE_FRESHNESS_WARNING = 1, /**< Proactive rotation recommended */
	OSCORE_FRESHNESS_CRITICAL = 2, /**< Immediate rotation required */
	OSCORE_FRESHNESS_EXHAUSTED = 3, /**< Context exhausted, cannot send */
};

/**
 * @brief NVM storage callback for SSN persistence (write_cb).
 *
 * Called from oscore_ctx_set_sender_seq() and oscore_ctx_persist_ssn()
 * (which the protect paths invoke before publishing output). Invoked WITHOUT
 * holding OSCORE mutex (non-blocking I/O recommended). On failure,
 * protect_request() rolls back the SSN increment (new retry semantics);
 * set_sender_seq() leaves context uninitialized; persist_ssn() leaves the
 * in-RAM SSN unchanged (no margin advance).
 *
 * @param[in] eui64  Peer EUI-64 for per-peer NVM key (NULL if not set)
 * @param[in] ssn    Sender sequence number to persist
 * @return 0 on success, any negative on failure (maps to OSCORE_ERR_NVM_FAILED)
 */
typedef int (*oscore_nvm_write_cb)(const uint8_t *_Nullable eui64, uint64_t ssn);

/**
 * @brief NVM read callback for SSN restoration (read_cb).
 *
 * Called during oscore_ctx_create_with_eui64(). On failure or NULL callback,
 * SSN starts at 0; caller MUST call oscore_ctx_set_sender_seq() before first
 * oscore_protect_request() to prevent nonce reuse on reboot.
 *
 * @param[in]  eui64  Peer EUI-64 for lookup (NULL if not set)
 * @param[out] ssn    Receives restored SSN on success
 * @return 0 on success (ssn valid), negative on failure
 */
typedef int (*oscore_nvm_read_cb)(const uint8_t *_Nullable eui64, uint64_t *_Nonnull ssn);

/**
 * @brief OSCORE security context (opaque)
 *
 * Full definition is private to oscore.c to protect cryptographic material
 * (keys, sequence numbers, replay window) from external access. This is a
 * P0 security requirement.
 *
 * Callers MUST treat as completely opaque and use ONLY the provided API:
 *   - oscore_ctx_create() / oscore_ctx_create_with_id_context() /
 *     oscore_ctx_create_with_eui64()
 *   - oscore_ctx_free()
 *   - oscore_ctx_get() / oscore_ctx_get_by_eui64()
 *   - oscore_ctx_set_peer_eui64()
 *   - oscore_ctx_get_sender_seq() / oscore_ctx_set_sender_seq()
 *   - oscore_ctx_get_seq_remaining()
 *   - oscore_ctx_check_freshness()
 *   - oscore_ctx_persist_ssn()
 *   - protect/unprotect functions (which take oscore_ctx *)
 *
 * Direct field access is forbidden (will not compile after this change).
 * Layout changes are now possible without breaking callers.
 */
struct oscore_ctx;  /* forward declaration - full definition in oscore.c */

/**
 * @brief OSCORE option value structure
 *
 * Parsed representation of the OSCORE CoAP option.
 *
 * @note piv_len == 0 indicates no Partial IV regardless of has_piv value.
 *       When building, set has_piv = true AND piv_len > 0 to include PIV.
 */
struct oscore_option {
	uint8_t piv[OSCORE_PIV_MAX_LEN];        /**< Partial IV */
	uint8_t piv_len;                         /**< PIV length */
	uint8_t kid[OSCORE_ID_MAX_LEN];         /**< Key Identifier */
	uint8_t kid_len;                         /**< KID length */
	uint8_t kid_context[OSCORE_ID_CONTEXT_MAX_LEN]; /**< Key ID Context */
	uint8_t kid_context_len;                 /**< KID Context length */
	bool has_piv;                            /**< PIV present */
	bool has_kid;                            /**< KID present */
	bool has_kid_context;                    /**< KID Context present */
};

/**
 * @brief Initialize the OSCORE subsystem.
 *
 * Must be called once at startup before using other OSCORE functions.
 *
 * @return 0 on success, negative error code on failure
 */
int oscore_init(void);

/**
 * @brief Register NVM callbacks for SSN persistence.
 *
 * Critical for preventing nonce reuse across reboots (RFC 8613 §7.2.1,
 * Appendix D.4). Thread-safe; may be called at any time (even after
 * contexts exist). Updates are atomic. Callbacks invoked outside mutex.
 *
 * When registered:
 * - read_cb used in oscore_ctx_create_with_eui64() to restore SSN (failure
 *   starts at 0; caller must call set_sender_seq before protect).
 * - write_cb used by set_sender_seq() and by persist_ssn() (which the
 *   protect paths invoke before publishing output). persist_ssn() writes a
 *   margin-skipped value (see OSCORE_SSN_SAFETY_MARGIN) and advances the
 *   in-RAM SSN to it only on success. On NVM failure in protect_request(),
 *   SSN rolled back (enables safe retry with identical nonce/SSN).
 *
 * @param[in] write_cb Callback for writing SSN to NVM (NULL disables)
 * @param[in] read_cb  Callback for reading SSN from NVM (NULL disables)
 */
void oscore_nvm_register_callbacks(oscore_nvm_write_cb _Nullable write_cb,
				   oscore_nvm_read_cb _Nullable read_cb);

/**
 * @brief Create a new OSCORE security context.
 *
 * Derives sender and recipient keys from the master secret using HKDF.
 *
 * @param[in] master_secret  16-byte master secret
 * @param[in] master_salt    Master salt (may be NULL)
 * @param[in] master_salt_len Salt length (0 if salt is NULL)
 * @param[in] sender_id      Sender ID
 * @param[in] sender_id_len  Sender ID length
 * @param[in] recipient_id   Recipient ID
 * @param[in] recipient_id_len Recipient ID length
 * @param[out] ctx           Output context pointer
 * @return 0 on success, OSCORE_ERR_INVALID_PARAM if oscore_init() has not
 *         been called or a parameter is invalid, negative error code on other
 *         failures
 */
int oscore_ctx_create(const uint8_t *_Nonnull master_secret,
		      const uint8_t *_Nullable master_salt, size_t master_salt_len,
		      const uint8_t *_Nonnull sender_id, size_t sender_id_len,
		      const uint8_t *_Nonnull recipient_id, size_t recipient_id_len,
		      struct oscore_ctx *_Nullable *_Nonnull ctx);

/**
 * @brief Create an OSCORE context with an RFC 8613 ID Context.
 *
 * The ID Context participates in sender-key, recipient-key, and Common IV
 * derivation and is emitted as the request OSCORE option's KID Context.
 * A NULL pointer with length zero means the ID Context is absent. A non-NULL
 * pointer with length zero means a present, empty ID Context; these cases have
 * different CBOR encodings and derive different cryptographic material.
 *
 * @param[in] master_secret   16-byte master secret
 * @param[in] master_salt     Master salt (may be NULL only when length is zero)
 * @param[in] master_salt_len Master salt length (maximum 8 bytes)
 * @param[in] sender_id       Sender ID (may be NULL only when length is zero)
 * @param[in] sender_id_len   Sender ID length (maximum 7 bytes)
 * @param[in] recipient_id    Recipient ID (may be NULL only when length is zero)
 * @param[in] recipient_id_len Recipient ID length (maximum 7 bytes)
 * @param[in] id_context      ID Context; NULL selects the absent form
 * @param[in] id_context_len  ID Context length (maximum
 *                            OSCORE_ID_CONTEXT_MAX_LEN)
 * @param[out] ctx            Output context pointer; set to NULL on failure
 * @return OSCORE_OK on success, OSCORE_ERR_INVALID_PARAM for inconsistent
 *         pointers/lengths or missing initialization, or another OSCORE error
 */
int oscore_ctx_create_with_id_context(
	const uint8_t *_Nonnull master_secret,
	const uint8_t *_Nullable master_salt, size_t master_salt_len,
	const uint8_t *_Nullable sender_id, size_t sender_id_len,
	const uint8_t *_Nullable recipient_id, size_t recipient_id_len,
	const uint8_t *_Nullable id_context, size_t id_context_len,
	struct oscore_ctx *_Nullable *_Nonnull ctx);

/**
 * @brief Create a new OSCORE security context with peer EUI-64.
 *
 * Same as oscore_ctx_create(), but also associates the peer's EUI-64 address
 * for per-peer lookup via oscore_ctx_get_by_eui64().
 *
 * If NVM read callback registered, restores SSN from NVM using read_cb.
 * On failure or no callback, SSN=0; caller MUST call oscore_ctx_set_sender_seq()
 * before oscore_protect_request() (see OSCORE_ERR_NVM_FAILED and NVM docs).
 *
 * @param[in]  master_secret   16-byte master secret
 * @param[in]  master_salt     Master salt (may be NULL)
 * @param[in]  master_salt_len Salt length (0 if salt is NULL)
 * @param[in]  sender_id       Sender ID
 * @param[in]  sender_id_len   Sender ID length
 * @param[in]  recipient_id    Recipient ID
 * @param[in]  recipient_id_len Recipient ID length
 * @param[in]  peer_eui64      8-byte peer EUI-64 address
 * @param[out] ctx             Output context pointer
 * @return 0 on success, negative error code on failure
 */
int oscore_ctx_create_with_eui64(const uint8_t *_Nonnull master_secret,
				 const uint8_t *_Nullable master_salt, size_t master_salt_len,
				 const uint8_t *_Nonnull sender_id, size_t sender_id_len,
				 const uint8_t *_Nonnull recipient_id, size_t recipient_id_len,
				 const uint8_t peer_eui64[_Nonnull OSCORE_EUI64_LEN],
				 struct oscore_ctx *_Nullable *_Nonnull ctx);

/**
 * @brief Associate a peer EUI-64 with an existing context.
 *
 * Links an EUI-64 address to an existing OSCORE context, enabling lookup
 * via oscore_ctx_get_by_eui64(). If the context already has an EUI-64, it
 * is replaced.
 *
 * @param[in] ctx        Security context
 * @param[in] peer_eui64 8-byte peer EUI-64 address
 * @return 0 on success, OSCORE_ERR_INVALID_PARAM if ctx or peer_eui64 is NULL
 */
int oscore_ctx_set_peer_eui64(struct oscore_ctx *_Nonnull ctx,
			      const uint8_t peer_eui64[_Nonnull OSCORE_EUI64_LEN]);

/**
 * @brief Get a security context pointer by peer EUI-64.
 *
 * Returns a pointer to the internal context associated with the given
 * peer EUI-64 address. This requires that the context was created with
 * oscore_ctx_create_with_eui64() or had oscore_ctx_set_peer_eui64() called.
 *
 * @param[in]  peer_eui64 8-byte peer EUI-64 address to search for
 * @param[out] ctx_out    Pointer to receive context pointer
 * @return 0 on success, OSCORE_ERR_NO_CONTEXT if not found,
 *         OSCORE_ERR_INVALID_PARAM if peer_eui64 or ctx_out is NULL
 */
int oscore_ctx_get_by_eui64(const uint8_t peer_eui64[_Nonnull OSCORE_EUI64_LEN],
			    struct oscore_ctx *_Nullable *_Nonnull ctx_out);

/**
 * @brief Free an OSCORE security context.
 *
 * Securely wipes key material before release.
 *
 * @param[in] ctx Context to free
 */
void oscore_ctx_free(struct oscore_ctx *_Nullable ctx);

/**
 * @brief Set the sender sequence number for nonce persistence.
 *
 * MUST be called after oscore_ctx_create*() (before first protect_request())
 * to prevent nonce reuse on reboot (see python-ano.41). Persists exactly the
 * given value (no OSCORE_SSN_SAFETY_MARGIN skip is applied); if NVM write_cb
 * registered and the write fails, returns OSCORE_ERR_NVM_FAILED and the
 * context remains uninitialized (protect_request will fail). Use after NVM
 * failure in protect_request() to bump SSN if retry not desired.
 *
 * @param[in] ctx       Security context
 * @param[in] sender_seq New sender sequence number (MUST be > previously used)
 * @return OSCORE_OK on success, OSCORE_ERR_INVALID_PARAM if ctx NULL,
 *         OSCORE_ERR_NVM_FAILED on NVM write error, OSCORE_ERR_NO_CONTEXT
 *         if the context was freed or its slot recycled before commit
 */
int oscore_ctx_set_sender_seq(struct oscore_ctx *_Nonnull ctx, uint64_t sender_seq);

/**
 * @brief Get the current sender sequence number for persistence.
 *
 * @param[in]  ctx        Security context
 * @param[out] sender_seq Current sender sequence number
 * @return 0 on success, OSCORE_ERR_INVALID_PARAM if ctx or sender_seq is NULL
 */
int oscore_ctx_get_sender_seq(const struct oscore_ctx *_Nonnull ctx,
			      uint64_t *_Nonnull sender_seq);

/**
 * @brief Get remaining sender sequence budget before exhaustion.
 *
 * Returns OSCORE_SSN_MAX - sender_seq + 1 while the terminal PIV remains
 * usable, then zero after it is reserved. Integrators should monitor this
 * value and trigger key rotation before it reaches zero.
 *
 * Example rotation thresholds:
 *   - Warning at 1,000,000 remaining (proactive rotation)
 *   - Critical at 10,000 remaining (mandatory rotation)
 *
 * @param[in]  ctx       Security context
 * @param[out] remaining Messages remaining before exhaustion
 * @return 0 on success, OSCORE_ERR_INVALID_PARAM if ctx or remaining is NULL
 *
 * @see @ref oscore_key_rotation "Key Rotation" for the complete rotation pattern
 */
int oscore_ctx_get_seq_remaining(const struct oscore_ctx *_Nonnull ctx,
				 uint64_t *_Nonnull remaining);

/**
 * @brief Check security context freshness per RFC 8613 Section 7.2.1.
 *
 * Checks if the context's sender sequence number is approaching exhaustion.
 * Returns a status indicating whether key rotation is needed.
 *
 * The thresholds are:
 *   - OSCORE_FRESHNESS_OK: remaining > OSCORE_SSN_ROTATION_WARNING
 *   - OSCORE_FRESHNESS_WARNING: remaining <= OSCORE_SSN_ROTATION_WARNING
 *   - OSCORE_FRESHNESS_CRITICAL: remaining <= OSCORE_SSN_ROTATION_CRITICAL
 *   - OSCORE_FRESHNESS_EXHAUSTED: remaining == 0
 *
 * @param[in]  ctx     Security context
 * @param[out] status  Freshness status (may be NULL to just check for error)
 * @return 0 on success, OSCORE_ERR_INVALID_PARAM if ctx is NULL,
 *         OSCORE_ERR_CONTEXT_STALE if context is exhausted
 */
int oscore_ctx_check_freshness(const struct oscore_ctx *_Nonnull ctx,
			       enum oscore_freshness *_Nullable status);

/**
 * @brief Persist a margin-skipped sender sequence number to NVM.
 *
 * Critical for preventing nonce reuse after reboot (RFC 8613 Section 7.2.1,
 * 7.5, Appendix D.4). Stores sender_seq + OSCORE_SSN_SAFETY_MARGIN (capped
 * at the exhaustion sentinel OSCORE_SSN_MAX + 1) using up to 3 retries with
 * linear backoff, and - only after a successful write - advances the in-RAM
 * sender_seq to that same durable value. A later reload therefore resumes
 * strictly above every sequence that could have been transmitted before a
 * crash; the skipped range is permanently unused (see
 * OSCORE_SSN_SAFETY_MARGIN).
 *
 * On NVM failure the in-RAM sender_seq is left unchanged and
 * OSCORE_ERR_NVM_FAILED is returned (the protect paths roll back their own
 * reservation). On a recycled context slot OSCORE_ERR_NO_CONTEXT is
 * returned after the durable write; the stored value remains valid for the
 * recorded peer.
 *
 * If no write callback is registered via oscore_nvm_register_callbacks(),
 * returns OSCORE_OK immediately (no-op; no margin is skipped).
 *
 * @param[in] ctx Security context
 * @return OSCORE_OK on success, OSCORE_ERR_INVALID_PARAM if ctx is NULL,
 *         OSCORE_ERR_NO_CONTEXT if the slot was freed or recycled,
 *         OSCORE_ERR_NVM_FAILED if all retries fail
 */
int oscore_ctx_persist_ssn(struct oscore_ctx *_Nonnull ctx);

/**
 * @brief Get a security context pointer by recipient ID.
 *
 * Returns a pointer to the internal context. This pointer is required for
 * oscore_protect_request() and oscore_unprotect_request() which perform
 * atomic updates to sender_seq and replay_window.
 *
 * @param[in]  recipient_id     Recipient ID to search for
 * @param[in]  recipient_id_len Length of recipient ID
 * @param[out] ctx_out          Pointer to receive context pointer
 * @return 0 on success, OSCORE_ERR_NO_CONTEXT if not found,
 *         OSCORE_ERR_INVALID_PARAM if ctx_out is NULL
 */
int oscore_ctx_get(const uint8_t *_Nonnull recipient_id,
		   size_t recipient_id_len,
		   struct oscore_ctx *_Nullable *_Nonnull ctx_out);

/**
 * @brief Parse an OSCORE CoAP option.
 *
 * @param[in]  data     Option value bytes
 * @param[in]  len      Option value length
 * @param[out] option   Parsed option structure
 * @return 0 on success, negative error code on failure
 */
int oscore_option_parse(const uint8_t *_Nonnull data, size_t len,
			struct oscore_option *_Nonnull option);

/**
 * @brief Build an OSCORE CoAP option value.
 *
 * @param[in]  option   Option structure to encode
 * @param[out] buf      Output buffer
 * @param[in]  buflen   Buffer size
 * @return Bytes written, or negative error code
 */
int oscore_option_build(const struct oscore_option *_Nonnull option,
			uint8_t *_Nonnull buf, size_t buflen);

/**
 * @brief Protect a CoAP request with OSCORE.
 *
 * Atomically reserves the sender sequence and snapshots the context under
 * mutex. Input, plaintext, AAD, option, and output bounds are validated before
 * publishing output. A margin-skipped durable sequence
 * (oscore_ctx_persist_ssn(), see OSCORE_SSN_SAFETY_MARGIN) is persisted
 * before encryption and the in-RAM sender_seq advances to it on success.
 * A failure before persistence conditionally rolls back this call's reservation;
 * a successfully persisted sequence remains consumed even if encryption later
 * fails, preventing nonce reuse after reboot. The context identity is rechecked
 * after the unlocked persistence callback before any output is published.
 *
 * @param[in]     ctx          Security context (sender_seq must be initialized)
 * @param[in]     code         CoAP request code
 * @param[in]     options      CoAP options to protect (Class E)
 * @param[in]     options_len  Options length
 * @param[in]     payload      Request payload
 * @param[in]     payload_len  Payload length
 * @param[out]    ciphertext   Output ciphertext buffer
 * @param[in,out] ciphertext_len Input: buffer size, output: ciphertext length
 * @param[out]    oscore_opt   Output OSCORE option value
 * @param[in,out] oscore_opt_len Input: buffer size, output: option length
 * @return OSCORE_OK on success, OSCORE_ERR_NVM_FAILED on persistence failure
 *         (with conditional pre-publication rollback), or another negative code
 */
[[nodiscard]] int oscore_protect_request(struct oscore_ctx *_Nonnull ctx,
					 uint8_t code,
					 const uint8_t *_Nullable options, size_t options_len,
					 const uint8_t *_Nullable payload, size_t payload_len,
					 uint8_t *_Nonnull ciphertext, size_t *_Nonnull ciphertext_len,
					 uint8_t *_Nonnull oscore_opt, size_t *_Nonnull oscore_opt_len);

/**
 * @brief Unprotect an OSCORE-protected CoAP request.
 *
 * Decrypts and authenticates the request, binding it to exactly this
 * context. Failure semantics:
 * - The OSCORE option MUST carry a canonical Partial IV (present, 1..
 *   OSCORE_PIV_MAX_LEN bytes, no leading zero byte); violations are
 *   OSCORE_ERR_INVALID_PARAM. A decoded PIV above OSCORE_SSN_MAX is
 *   OSCORE_ERR_SEQ_EXHAUSTED.
 * - The option KID MUST equal the context recipient_id and, when present,
 *   the KID Context MUST equal the context id_context; otherwise
 *   OSCORE_ERR_NO_CONTEXT.
 * - Replay: the sequence is reserved before authentication and committed
 *   only after it succeeds; duplicates and sequences older than
 *   CONFIG_LICHEN_OSCORE_REPLAY_WINDOW return OSCORE_ERR_REPLAY.
 * - The former NULL size-query mode was removed: *options_len and
 *   *payload_len are strict in/out parameters (input capacity, output
 *   length). options/payload == NULL while corresponding content exists is
 *   OSCORE_ERR_INVALID_PARAM (caller contract); insufficient capacity is
 *   OSCORE_ERR_BUFFER_TOO_SMALL.
 * - No caller-visible byte (including *code) is written on any failure.
 *
 * @param[in]     ctx           Security context
 * @param[in]     oscore_opt    OSCORE option value
 * @param[in]     oscore_opt_len OSCORE option length
 * @param[in]     ciphertext    Encrypted payload
 * @param[in]     ciphertext_len Ciphertext length
 * @param[out]    code          Original CoAP request code
 * @param[out]    options       Decrypted Class E options
 * @param[in,out] options_len   Input: buffer size, output: options length
 * @param[out]    payload       Decrypted payload
 * @param[in,out] payload_len   Input: buffer size, output: payload length
 * @return OSCORE_OK on success, or a negative OSCORE_ERR_* code
 */
[[nodiscard]] int oscore_unprotect_request(struct oscore_ctx *_Nonnull ctx,
					   const uint8_t *_Nonnull oscore_opt, size_t oscore_opt_len,
					   const uint8_t *_Nonnull ciphertext, size_t ciphertext_len,
					   uint8_t *_Nonnull code,
					   uint8_t *_Nonnull options, size_t *_Nonnull options_len,
					   uint8_t *_Nonnull payload, size_t *_Nonnull payload_len);

/**
 * @brief Protect a CoAP response with OSCORE (RFC 8613 Section 8.3, no fresh
 *        Partial IV).
 *
 * The request correlation is answered with an EMPTY OSCORE option value and
 * the response nonce reuses the request nonce, so no sender sequence is
 * consumed and no NVM write occurs in this mode. Use
 * oscore_protect_response_with_piv() for the Section 8.4 fresh-PIV mode.
 *
 * Requirements and failure semantics:
 * - request_piv MUST be the canonical Partial IV of the request being
 *   answered: 1..OSCORE_PIV_MAX_LEN bytes with a non-NULL buffer;
 *   request_piv_len == 0 (the pre-rework acceptance of an empty correlation)
 *   or a NULL buffer is OSCORE_ERR_INVALID_PARAM.
 * - code MUST be a response class (top three bits 2..5); anything else is
 *   OSCORE_ERR_INVALID_PARAM.
 * - Duplicate correlation: each request PIV can be answered in this mode
 *   once. Once an answer was built successfully, another call with the same
 *   correlation is refused with OSCORE_ERR_REPLAY; the window tracks the
 *   CONFIG_LICHEN_OSCORE_REPLAY_WINDOW most recent correlations.
 * - Zero-caller-bytes guarantee: encryption is the final fallible step and
 *   the only writer of the caller's buffers, so every policy and validation
 *   failure leaves ciphertext and oscore_opt untouched. (Residual: if the
 *   AEAD primitive itself faults, partial bytes may land in ciphertext.)
 *
 * Caller surfacing: on any error the in-tree callers
 * (coap_oscore_respond_resource(), lichen_coap_oscore_respond()) fall back
 * to an UNPROTECTED, empty 5.00 INTERNAL_ERROR reply. That fallback is the
 * documented, acceptable behavior: the unprotected error carries no
 * application payload, so nothing protected is degraded, and a caller
 * contract violation such as piv_len == 0 surfaces only as this empty
 * error reply. Callers that prefer stricter handling may surface the error
 * instead of replying.
 *
 * @param[in]     ctx          Security context
 * @param[in]     request_piv  Partial IV from request (canonical, non-empty)
 * @param[in]     request_piv_len Request PIV length (1..OSCORE_PIV_MAX_LEN)
 * @param[in]     code         CoAP response code (class 2..5)
 * @param[in]     options      CoAP options to protect (Class E)
 * @param[in]     options_len  Options length
 * @param[in]     payload      Response payload
 * @param[in]     payload_len  Payload length
 * @param[out]    ciphertext   Output ciphertext buffer
 * @param[in,out] ciphertext_len Input: buffer size, output: ciphertext length
 * @param[out]    oscore_opt   Output OSCORE option value (empty on success)
 * @param[in,out] oscore_opt_len Input: buffer size, output: option length
 * @return OSCORE_OK on success, OSCORE_ERR_INVALID_PARAM on contract
 *         violations, OSCORE_ERR_REPLAY for an already-answered
 *         correlation, OSCORE_ERR_NO_CONTEXT for a freed/recycled context,
 *         OSCORE_ERR_BUFFER_TOO_SMALL on insufficient capacity, or another
 *         negative code
 */
[[nodiscard]] int oscore_protect_response(struct oscore_ctx *_Nonnull ctx,
					  const uint8_t *_Nonnull request_piv, size_t request_piv_len,
					  uint8_t code,
					  const uint8_t *_Nullable options, size_t options_len,
					  const uint8_t *_Nullable payload, size_t payload_len,
					  uint8_t *_Nonnull ciphertext, size_t *_Nonnull ciphertext_len,
					  uint8_t *_Nonnull oscore_opt, size_t *_Nonnull oscore_opt_len);

/**
 * @brief Protect a CoAP response with a fresh Partial IV.
 *
 * This is the RFC 8613 Section 8.4 response mode. It consumes and persists
 * the context sender sequence, uses the responder Sender ID plus the fresh
 * PIV for the nonce, and still binds the AAD to the original request PIV/KID.
 * The ordinary oscore_protect_response() API uses the Section 8.3 mode and
 * reuses the request nonce with an empty OSCORE option value.
 *
 * Parameters and output contracts match oscore_protect_response(). The
 * caller MUST initialize sender sequence state before using this mode.
 */
[[nodiscard]] int oscore_protect_response_with_piv(
					  struct oscore_ctx *_Nonnull ctx,
					  const uint8_t *_Nonnull request_piv,
					  size_t request_piv_len,
					  uint8_t code,
					  const uint8_t *_Nullable options,
					  size_t options_len,
					  const uint8_t *_Nullable payload,
					  size_t payload_len,
					  uint8_t *_Nonnull ciphertext,
					  size_t *_Nonnull ciphertext_len,
					  uint8_t *_Nonnull oscore_opt,
					  size_t *_Nonnull oscore_opt_len);

/**
 * @brief Unprotect an OSCORE-protected CoAP response.
 *
 * Correlates the response with the original request and decrypts it per
 * RFC 8613 Sections 8.3/8.4:
 * - request_piv MUST be the canonical Partial IV of the original request
 *   (1..OSCORE_PIV_MAX_LEN bytes, non-NULL); violations are
 *   OSCORE_ERR_INVALID_PARAM.
 * - With a fresh response PIV in oscore_opt (Section 8.4) the nonce uses
 *   the responder KID plus that PIV, and the PIV is checked against the
 *   fresh-response replay window. Without one (Section 8.3) the request
 *   nonce is reused and the request correlation itself is replay-checked.
 *   Both refuse repeats with OSCORE_ERR_REPLAY.
 * - KID and KID Context, when present in the response option, MUST match
 *   this context (recipient_id / id_context); otherwise
 *   OSCORE_ERR_NO_CONTEXT.
 * - The decrypted inner code MUST be a response class (top three bits
 *   2..5).
 * - The former NULL size-query mode was removed: *options_len and
 *   *payload_len are strict in/out parameters (input capacity, output
 *   length), and oscore_opt may be NULL only when oscore_opt_len == 0.
 *   options/payload == NULL while corresponding content exists is
 *   OSCORE_ERR_INVALID_PARAM; insufficient capacity is
 *   OSCORE_ERR_BUFFER_TOO_SMALL.
 * - Replay state is committed and caller bytes are written only after
 *   authentication and all validation succeed; no caller-visible byte is
 *   written on any failure.
 *
 * @param[in]     ctx            Security context
 * @param[in]     request_piv    Partial IV from original request
 * @param[in]     request_piv_len Request PIV length
 * @param[in]     oscore_opt     OSCORE option value (NULL only if len == 0)
 * @param[in]     oscore_opt_len OSCORE option length
 * @param[in]     ciphertext     Encrypted payload
 * @param[in]     ciphertext_len Ciphertext length
 * @param[out]    code           Original CoAP response code
 * @param[out]    options        Decrypted Class E options
 * @param[in,out] options_len    Input: buffer size, output: options length
 * @param[out]    payload        Decrypted payload
 * @param[in,out] payload_len    Input: buffer size, output: payload length
 * @return OSCORE_OK on success, or a negative OSCORE_ERR_* code
 */
[[nodiscard]] int oscore_unprotect_response(struct oscore_ctx *_Nonnull ctx,
					    const uint8_t *_Nonnull request_piv, size_t request_piv_len,
					    const uint8_t *_Nonnull oscore_opt, size_t oscore_opt_len,
					    const uint8_t *_Nonnull ciphertext, size_t ciphertext_len,
					    uint8_t *_Nonnull code,
					    uint8_t *_Nonnull options, size_t *_Nonnull options_len,
					    uint8_t *_Nonnull payload, size_t *_Nonnull payload_len);

#ifdef __cplusplus
}
#endif

/**
 * @defgroup oscore_group OSCORE Group Communication (RFC 9203)
 *
 * Group OSCORE extends per-peer OSCORE to enable encrypted group
 * communication. All group members share the same master secret and
 * common IV. Each member has their own sender/recipient ID pair,
 * derived from their position (index) in the group.
 *
 * Group contexts have a trust level that indicates how the group
 * key was established (direct provisioning, key agreement, etc.).
 *
 * SECURITY: Group keys provide confidentiality within the group but
 * do NOT provide sender authentication (any group member can encrypt
 * as any other). For authenticated group communication, pair with
 * link-layer Ed25519 signatures or per-message signing.
 */

/**
 * @brief Maximum group name length
 */
#define OSCORE_GROUP_NAME_MAX_LEN 16

/**
 * @brief Maximum group members
 */
#define OSCORE_GROUP_MAX_MEMBERS 32

/**
 * @brief Group key trust levels
 */
enum oscore_group_trust {
	OSCORE_GROUP_TRUST_UNKNOWN = 0,
	OSCORE_GROUP_TRUST_PROVISIONED, /**< Directly provisioned (out-of-band) */
	OSCORE_GROUP_TRUST_ESTABLISHED, /**< Established via key agreement */
	OSCORE_GROUP_TRUST_VERIFIED,    /**< Verified group membership */
};

/**
 * @brief OSCORE group context (opaque)
 *
 * Full definition is private to oscore.c. Follows the same opaque
 * pattern as struct oscore_ctx for security (key isolation).
 */
struct oscore_group_ctx;

/**
 * @brief Create a new OSCORE group context.
 *
 * All group members share the same master_secret. Each member's
 * sender and recipient IDs are derived from group_member_index
 * (member 0 uses IDs [0]/[1], member 1 uses [2]/[3], etc.).
 *
 * This simplifies key management: distribute the master_secret,
 * and each member computes their own per-member context from
 * their index.
 *
 * @param[in]  group_name        Group name string (for lookup, NULL for anonymous)
 * @param[in]  master_secret     16-byte group master secret
 * @param[in]  group_member_index Index of this member (0..OSCORE_GROUP_MAX_MEMBERS-1)
 * @param[in]  trust             Group key trust level
 * @param[out] ctx_out           Output group context pointer
 * @return 0 on success, negative error code on failure
 */
int oscore_group_ctx_create(const char *_Nullable group_name,
			    const uint8_t *_Nonnull master_secret,
			    uint8_t group_member_index,
			    enum oscore_group_trust trust,
			    struct oscore_group_ctx *_Nullable *_Nonnull ctx_out);

/**
 * @brief Get an individual OSCORE security context from a group context.
 *
 * Each group member needs a per-peer OSCORE context for send/receive
 * within the group. This extracts the member's derived context from
 * the group context.
 *
 * @param[in]  group_ctx Group context
 * @param[out] out_ctx   Output individual context pointer
 * @return 0 on success, negative error code on failure
 */
int oscore_group_ctx_get_member_ctx(struct oscore_group_ctx *_Nonnull group_ctx,
				    struct oscore_ctx *_Nullable *_Nonnull out_ctx);

/**
 * @brief Get a group context by name.
 *
 * @param[in]  group_name Group name string
 * @param[out] ctx_out    Output group context pointer
 * @return 0 on success, OSCORE_ERR_NO_CONTEXT if not found
 */
int oscore_group_ctx_get_by_name(const char *_Nonnull group_name,
				 struct oscore_group_ctx *_Nullable *_Nonnull ctx_out);

/**
 * @brief Get group trust level.
 *
 * @param[in]  group_ctx Group context
 * @param[out] trust     Output trust level
 * @return 0 on success, negative error code on failure
 */
int oscore_group_ctx_get_trust(const struct oscore_group_ctx *_Nonnull group_ctx,
			       enum oscore_group_trust *_Nonnull trust);

/**
 * @brief Set group trust level.
 *
 * SECURITY: Trust can only be escalated (UNKNOWN < PROVISIONED <
 * ESTABLISHED < VERIFIED). Downgrading returns an error.
 *
 * @param[in] group_ctx Group context
 * @param[in] trust     New trust level
 * @return 0 on success, -EPERM if downgrade attempted
 */
int oscore_group_ctx_set_trust(struct oscore_group_ctx *_Nonnull group_ctx,
			       enum oscore_group_trust trust);

/**
 * @brief Free an OSCORE group context.
 *
 * Also frees the associated per-member OSCORE contexts.
 *
 * @param[in] ctx Group context to free
 */
void oscore_group_ctx_free(struct oscore_group_ctx *_Nullable ctx);

/**
 * @brief Get number of group contexts.
 *
 * @return Number of active group contexts
 */
size_t oscore_group_ctx_count(void);

/**
 * @brief Derive an OSCORE master secret from a peer public key.
 *
 * Uses HKDF-SHA256 with domain separation:
 *   info = "LICHEN-OSCORE-peer-key" || iid
 *   master_secret = HKDF-Expand(HKDF-Extract(salt=0, IKM=pubkey), info, 16)
 *
 * This enables E2E encryption for resources like dead drops and
 * confessions where the communicating parties share public keys
 * via TOFU but have not run EDHOC.
 *
 * @param[in]  peer_pubkey    32-byte Ed25519 public key
 * @param[in]  peer_iid       8-byte peer IID
 * @param[out] master_secret  16-byte output master secret
 * @return 0 on success, negative error code on failure
 */
int oscore_derive_master_secret_from_peer_key(
	const uint8_t peer_pubkey[_Nonnull 32],
	const uint8_t peer_iid[_Nonnull 8],
	uint8_t master_secret[_Nonnull OSCORE_KEY_LEN]);

/**
 * @brief Create an OSCORE context derived from a peer's public key.
 *
 * Combines oscore_derive_master_secret_from_peer_key() and
 * oscore_ctx_create_with_eui64() for convenience. The derived
 * master_secret is wiped after key derivation.
 *
 * @param[in]  peer_pubkey    32-byte Ed25519 public key
 * @param[in]  peer_eui64     8-byte peer EUI-64
 * @param[in]  sender_id      Sender ID
 * @param[in]  sender_id_len  Sender ID length
 * @param[in]  recipient_id   Recipient ID
 * @param[in]  recipient_id_len Recipient ID length
 * @param[out] ctx            Output context pointer
 * @return 0 on success, negative error code on failure
 */
int oscore_ctx_create_from_peer_key(
	const uint8_t peer_pubkey[_Nonnull 32],
	const uint8_t peer_eui64[_Nonnull 8],
	const uint8_t *_Nonnull sender_id, size_t sender_id_len,
	const uint8_t *_Nonnull recipient_id, size_t recipient_id_len,
	struct oscore_ctx *_Nullable *_Nonnull ctx);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_OSCORE_H_ */
