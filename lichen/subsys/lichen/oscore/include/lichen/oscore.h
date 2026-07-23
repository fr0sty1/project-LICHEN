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
 * OSCORE contexts have a finite lifetime bounded by the 32-bit sender sequence
 * number. When sender_seq reaches UINT32_MAX, oscore_protect_request() returns
 * OSCORE_ERR_SEQ_EXHAUSTED and the context can no longer send messages.
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

/** Position of sender_id_len in nonce (NONCE_LEN - 7 per RFC 8613 Section 5.2) */
#define OSCORE_NONCE_S_POS 6

/**
 * Maximum Sender Sequence Number (SSN) per RFC 8613 Section 7.2.1.
 * AES-CCM-16-64-128 limits the SSN to 2^23 - 1 per RFC 9053 Section 4.2.1.
 * We use the full 32-bit range since the PIV can be up to 5 bytes, but
 * implementations should trigger key rotation well before exhaustion.
 */
#define OSCORE_SSN_MAX UINT32_MAX

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
	OSCORE_ERR_NVM_FAILED = -10,    /**< NVM read/write operation failed */
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
 * @brief NVM storage callback for SSN persistence.
 *
 * Called periodically when SSN needs to be persisted to NVM.
 *
 * @param[in] eui64  8-byte peer EUI-64 (or NULL if not set)
 * @param[in] ssn    Sender sequence number to store
 * @return 0 on success, negative error code on failure
 */
typedef int (*oscore_nvm_write_cb)(const uint8_t *_Nullable eui64, uint32_t ssn);

/**
 * @brief NVM read callback for SSN restoration.
 *
 * Called at context initialization to restore SSN from NVM.
 *
 * @param[in]  eui64  8-byte peer EUI-64 (or NULL if not set)
 * @param[out] ssn    Pointer to receive restored SSN
 * @return 0 on success (ssn is valid), negative error code on failure
 */
typedef int (*oscore_nvm_read_cb)(const uint8_t *_Nullable eui64, uint32_t *_Nonnull ssn);

/**
 * @brief OSCORE security context (opaque)
 *
 * Full definition is private to oscore.c to protect cryptographic material
 * (keys, sequence numbers, replay window) from external access. This is a
 * P0 security requirement.
 *
 * Callers MUST treat as completely opaque and use ONLY the provided API:
 *   - oscore_ctx_create() / oscore_ctx_create_with_eui64()
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
 * When NVM callbacks are registered, the OSCORE subsystem will:
 * - Call the read callback during context creation to restore SSN
 * - Call the write callback periodically to persist SSN changes
 *
 * @param[in] write_cb Callback for writing SSN to NVM (may be NULL to disable)
 * @param[in] read_cb  Callback for reading SSN from NVM (may be NULL)
 */
void oscore_nvm_register_callbacks(oscore_nvm_write_cb write_cb,
				   oscore_nvm_read_cb read_cb);

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
 * @brief Create a new OSCORE security context with peer EUI-64.
 *
 * Same as oscore_ctx_create(), but also associates the peer's EUI-64 address
 * for per-peer lookup via oscore_ctx_get_by_eui64().
 *
 * If NVM callbacks registered, restores SSN from NVM; on OSCORE_ERR_NVM_FAILED
 * SSN starts at 0. Caller MUST ensure nonce uniqueness via set_sender_seq.
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
 * If NVM write callback registered, persists SSN before marking context
 * initialized. On NVM failure returns OSCORE_ERR_NVM_FAILED without setting
 * initialized flag (ensures protect_request fails). MUST call before
 * oscore_protect_request() to avoid nonce reuse on reboot.
 *
 * @param[in] ctx       Security context
 * @param[in] sender_seq New sender sequence number (must be > any previously used)
 * @return OSCORE_OK on success, OSCORE_ERR_INVALID_PARAM if ctx NULL,
 *         OSCORE_ERR_NVM_FAILED on NVM write error
 */
int oscore_ctx_set_sender_seq(struct oscore_ctx *_Nonnull ctx, uint32_t sender_seq);

/**
 * @brief Get the current sender sequence number for persistence.
 *
 * @param[in]  ctx        Security context
 * @param[out] sender_seq Current sender sequence number
 * @return 0 on success, OSCORE_ERR_INVALID_PARAM if ctx or sender_seq is NULL
 */
int oscore_ctx_get_sender_seq(const struct oscore_ctx *_Nonnull ctx,
			      uint32_t *_Nonnull sender_seq);

/**
 * @brief Get remaining sender sequence budget before exhaustion.
 *
 * Returns UINT32_MAX - sender_seq, the number of messages that can be sent
 * before OSCORE_ERR_SEQ_EXHAUSTED is returned. Integrators should monitor
 * this value and trigger key rotation before it reaches zero.
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
				 uint32_t *_Nonnull remaining);

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
 * @brief Persist the current sender sequence number to NVM.
 *
 * Manually triggers NVM write for SSN (critical for nonce uniqueness on
 * restart). Handle OSCORE_ERR_NVM_FAILED by retry or safe SSN bump.
 *
 * Requires that NVM callbacks have been registered via
 * oscore_nvm_register_callbacks(). If no write callback is registered,
 * this function returns 0 (success, no-op).
 *
 * @param[in] ctx Security context
 * @return 0 on success, OSCORE_ERR_INVALID_PARAM if ctx is NULL,
 *         OSCORE_ERR_NVM_FAILED if NVM write fails
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
 * Performs atomic SSN increment under mutex (to prevent races and nonce
 * reuse per python-ano.41), builds plaintext/AAD, encrypts with AES-CCM,
 * builds OSCORE option, then calls oscore_ctx_persist_ssn() on success path.
 * All paths ensure crypto_wipe(). On OSCORE_ERR_NVM_FAILED, rolls back
 * sender_seq under mutex (see nvm_failed: in oscore.c:1604 and full
 * security analysis in project-LICHEN-ow3c.1.3.2.1). Rollback chosen over
 * safe-advance for NVM/memory consistency and to avoid SSN reuse on reboot
 * (RFC 8613 §7.2, §7.5, App. D.4).
 *
 * @param[in]     ctx          Security context
 * @param[in]     code         CoAP request code
 * @param[in]     options      CoAP options to protect (Class E)
 * @param[in]     options_len  Options length
 * @param[in]     payload      Request payload
 * @param[in]     payload_len  Payload length
 * @param[out]    ciphertext   Output ciphertext buffer
 * @param[in,out] ciphertext_len Input: buffer size, output: ciphertext length
 * @param[out]    oscore_opt   Output OSCORE option value
 * @param[in,out] oscore_opt_len Input: buffer size, output: option length
 * @return OSCORE_OK on success, OSCORE_ERR_NVM_FAILED if SSN persistence
 *         fails (with rollback), or other negative error codes
 */
int oscore_protect_request(struct oscore_ctx *_Nonnull ctx,
			   uint8_t code,
			   const uint8_t *_Nullable options, size_t options_len,
			   const uint8_t *_Nullable payload, size_t payload_len,
			   uint8_t *_Nonnull ciphertext, size_t *_Nonnull ciphertext_len,
			   uint8_t *_Nonnull oscore_opt, size_t *_Nonnull oscore_opt_len);

/**
 * @brief Unprotect an OSCORE-protected CoAP request.
 *
 * Decrypts and verifies the request.
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
 * @return 0 on success, negative error code on failure
 */
int oscore_unprotect_request(struct oscore_ctx *_Nonnull ctx,
			     const uint8_t *_Nonnull oscore_opt, size_t oscore_opt_len,
			     const uint8_t *_Nonnull ciphertext, size_t ciphertext_len,
			     uint8_t *_Nonnull code,
			     uint8_t *_Nonnull options, size_t *_Nonnull options_len,
			     uint8_t *_Nonnull payload, size_t *_Nonnull payload_len);

/**
 * @brief Protect a CoAP response with OSCORE.
 *
 * @param[in]     ctx          Security context
 * @param[in]     request_piv  Partial IV from request
 * @param[in]     request_piv_len Request PIV length
 * @param[in]     code         CoAP response code
 * @param[in]     options      CoAP options to protect (Class E)
 * @param[in]     options_len  Options length
 * @param[in]     payload      Response payload
 * @param[in]     payload_len  Payload length
 * @param[out]    ciphertext   Output ciphertext buffer
 * @param[in,out] ciphertext_len Input: buffer size, output: ciphertext length
 * @param[out]    oscore_opt   Output OSCORE option value
 * @param[in,out] oscore_opt_len Input: buffer size, output: option length
 * @return 0 on success, negative error code on failure
 */
int oscore_protect_response(struct oscore_ctx *_Nonnull ctx,
			    const uint8_t *_Nonnull request_piv, size_t request_piv_len,
			    uint8_t code,
			    const uint8_t *_Nullable options, size_t options_len,
			    const uint8_t *_Nullable payload, size_t payload_len,
			    uint8_t *_Nonnull ciphertext, size_t *_Nonnull ciphertext_len,
			    uint8_t *_Nonnull oscore_opt, size_t *_Nonnull oscore_opt_len);

/**
 * @brief Unprotect an OSCORE-protected CoAP response.
 *
 * @param[in]     ctx            Security context
 * @param[in]     request_piv    Partial IV from original request
 * @param[in]     request_piv_len Request PIV length
 * @param[in]     oscore_opt     OSCORE option value
 * @param[in]     oscore_opt_len OSCORE option length
 * @param[in]     ciphertext     Encrypted payload
 * @param[in]     ciphertext_len Ciphertext length
 * @param[out]    code           Original CoAP response code
 * @param[out]    options        Decrypted Class E options
 * @param[in,out] options_len    Input: buffer size, output: options length
 * @param[out]    payload        Decrypted payload
 * @param[in,out] payload_len    Input: buffer size, output: payload length
 * @return 0 on success, negative error code on failure
 */
int oscore_unprotect_response(struct oscore_ctx *_Nonnull ctx,
			      const uint8_t *_Nonnull request_piv, size_t request_piv_len,
			      const uint8_t *_Nonnull oscore_opt, size_t oscore_opt_len,
			      const uint8_t *_Nonnull ciphertext, size_t ciphertext_len,
			      uint8_t *_Nonnull code,
			      uint8_t *_Nonnull options, size_t *_Nonnull options_len,
			      uint8_t *_Nonnull payload, size_t *_Nonnull payload_len);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_OSCORE_H_ */
