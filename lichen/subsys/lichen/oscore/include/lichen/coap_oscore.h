/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_oscore.h
 * @brief CoAP-OSCORE integration helpers
 *
 * Provides middleware functions to add OSCORE protection to CoAP resources.
 */

#ifndef LICHEN_COAP_OSCORE_H_
#define LICHEN_COAP_OSCORE_H_

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <lichen/oscore.h>

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

/**
 * @brief Check if a CoAP request is OSCORE-protected
 *
 * @param[in] request CoAP request packet
 * @return true if OSCORE option present, false otherwise
 */
bool coap_oscore_is_protected(const struct coap_packet *_Nonnull request);

/**
 * @brief Extract OSCORE option from CoAP request
 *
 * @param[in]  request     CoAP request packet
 * @param[out] opt_data    Buffer for option value
 * @param[out] opt_len     Option length
 * @return 0 on success, negative error code if not found
 */
int coap_oscore_get_option(const struct coap_packet *_Nonnull request,
			   uint8_t *_Nonnull opt_data, size_t *_Nonnull opt_len);

/**
 * @brief Unprotect an OSCORE-protected CoAP request
 *
 * Decrypts the request and provides the original CoAP code and payload.
 * The caller must look up the security context based on the KID in the
 * OSCORE option.
 *
 * @param[in]     ctx            OSCORE security context
 * @param[in]     request        Protected CoAP request
 * @param[out]    original_code  Original CoAP request code
 * @param[out]    options        Decrypted Class E options (may be NULL)
 * @param[in,out] options_len    Input: buffer size, output: options length (may be NULL)
 * @param[out]    payload        Decrypted payload buffer
 * @param[in,out] payload_len    Input: buffer size, output: payload length
 * @param[out]    request_piv    Request PIV (for response)
 * @param[out]    request_piv_len PIV length
 * @return 0 on success, negative error code on failure
 */
int coap_oscore_unprotect_request(struct oscore_ctx *_Nonnull ctx,
				  const struct coap_packet *_Nonnull request,
				  uint8_t *_Nonnull original_code,
				  uint8_t *_Nonnull options, size_t *_Nonnull options_len,
				  uint8_t *_Nonnull payload, size_t *_Nonnull payload_len,
				  uint8_t *_Nonnull request_piv, size_t *_Nonnull request_piv_len);

/**
 * @brief Build an OSCORE-protected CoAP response
 *
 * Encrypts the response payload and adds the OSCORE option.
 *
 * @param[in]     ctx            OSCORE security context
 * @param[in]     request_piv    PIV from the original request
 * @param[in]     request_piv_len PIV length
 * @param[in]     original_request Original CoAP request (for token, etc)
 * @param[in]     response_code  CoAP response code
 * @param[in]     payload        Response payload to encrypt
 * @param[in]     payload_len    Payload length
 * @param[out]    response       Output protected response packet
 * @param[in]     resp_buf       Buffer for response packet
 * @param[in]     resp_buf_len   Response buffer size
 * @return 0 on success, negative error code on failure
 */
int coap_oscore_protect_response(struct oscore_ctx *_Nonnull ctx,
				 const uint8_t *_Nonnull request_piv, size_t request_piv_len,
				 const struct coap_packet *_Nonnull original_request,
				 uint8_t response_code,
				 const uint8_t *_Nonnull payload, size_t payload_len,
				 struct coap_packet *_Nonnull response,
				 uint8_t *_Nonnull resp_buf, size_t resp_buf_len);

/**
 * @brief Send a 4.01 Unauthorized response for missing/invalid OSCORE
 *
 * @param[in] resource CoAP resource
 * @param[in] request  Original request
 * @param[in] addr     Client address
 * @param[in] addr_len Address length
 * @return 0 on success, negative error code on failure
 */
int coap_oscore_send_unauthorized(struct coap_resource *_Nonnull resource,
				  struct coap_packet *_Nonnull request,
				  struct sockaddr *_Nonnull addr, socklen_t addr_len);

/**
 * @brief LCI mutating operation authorization result
 *
 * Returned by lichen_coap_oscore_authorize_mutating() to provide
 * the caller with all data needed to proceed or send an error.
 *
 * The caller provides the plaintext buffer; after a successful call,
 * payload points into plaintext_buf and payload_len is set.
 */
struct lichen_coap_oscore_auth_result {
	struct oscore_ctx *_Nullable ctx;      /**< OSCORE context, NULL if not OSCORE */
	uint8_t piv[OSCORE_PIV_MAX_LEN];       /**< Request PIV for response */
	size_t piv_len;                         /**< PIV length */
	const uint8_t *_Nullable payload;      /**< Decrypted payload (points into caller's plaintext_buf) */
	uint16_t payload_len;                  /**< Payload length */
	bool is_protected;                     /**< True if OSCORE-protected */
};

/**
 * @brief Authorize a mutating LCI CoAP operation.
 *
 * Combines the common OSCORE ctx-lookup + unprotect pattern shared by
 * /keys PUT/DELETE, /msg/inbox POST, /deaddrop POST, and /confessions POST.
 *
 * The caller MUST provide a plaintext buffer (plaintext_buf / plaintext_buf_len)
 * that the function writes decrypted (or passes-through) payload into.
 * After a successful return, result->payload points into plaintext_buf.
 *
 * When OSCORE is enabled (CONFIG_LICHEN_COAP_SERVER_OSCORE):
 *   1. Checks if request is OSCORE-protected
 *   2. Extracts peer EUI-64 from sockaddr
 *   3. Looks up OSCORE context via oscore_ctx_get_by_eui64()
 *   4. Calls coap_oscore_unprotect_request() into plaintext_buf
 *   5. Validates original method code matches expected_method
 *   6. On any failure, sends 4.01 Unauthorized
 *
 * When OSCORE is disabled or request is unprotected:
 *   - Copies payload data from the raw CoAP packet into plaintext_buf
 *
 * @param[in]     resource        CoAP resource
 * @param[in]     request         CoAP request packet
 * @param[in]     addr            Client address
 * @param[in]     addr_len        Address length
 * @param[in]     expected_method Expected CoAP method code (e.g. COAP_METHOD_PUT)
 * @param[out]    result          Authorization result (payload points into plaintext_buf)
 * @param[out]    plaintext_buf   Caller-provided buffer for decrypted/raw payload
 * @param[in]     plaintext_buf_len Size of plaintext_buf
 * @return 0 on success (caller may proceed with result->payload/ctx/piv),
 *         negative on failure (caller MUST return immediately)
 */
int lichen_coap_oscore_authorize_mutating(struct coap_resource *_Nonnull resource,
					  struct coap_packet *_Nonnull request,
					  struct sockaddr *_Nonnull addr, socklen_t addr_len,
					  uint8_t expected_method,
					  struct lichen_coap_oscore_auth_result *_Nonnull result,
					  uint8_t *_Nonnull plaintext_buf,
					  size_t plaintext_buf_len);

/**
 * @brief Send an OSCORE-protected or plain CoAP response for a mutating operation.
 *
 * If result->is_protected and result->ctx is non-NULL, sends an OSCORE-protected
 * response using coap_oscore_protect_response(). Otherwise falls back to
 * lichen_coap_respond().
 *
 * @param[in] resource      CoAP resource
 * @param[in] request       CoAP request packet
 * @param[in] addr          Client address
 * @param[in] addr_len      Address length
 * @param[in] result        Authorization result from authorize_mutating()
 * @param[in] resp_code     CoAP response code
 * @return 0 on success, negative error code on failure
 */
int lichen_coap_oscore_respond(struct coap_resource *_Nonnull resource,
			       struct coap_packet *_Nonnull request,
			       struct sockaddr *_Nonnull addr, socklen_t addr_len,
			       const struct lichen_coap_oscore_auth_result *_Nonnull result,
			       uint8_t resp_code);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_OSCORE_H_ */
