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
 * @brief Result of unprotecting an OSCORE CoAP resource request.
 *
 * Holds the OSCORE context, PIV, protected flag, and decrypted payload
 * from the common unprotect path used by deaddrop_post, confessions_post,
 * msg_inbox_post, and keys_put.
 *
 * The plaintext buffer is embedded in the struct to avoid dangling pointers
 * when the caller uses oscore.payload after the helper returns.
 */
struct coap_oscore_unprotect_result {
	struct oscore_ctx *ctx;           /**< OSCORE context (NULL if not protected) */
	uint8_t piv[OSCORE_PIV_MAX_LEN]; /**< Partial IV for response protection */
	size_t piv_len;                   /**< PIV length (0 if not protected) */
	bool is_protected;                /**< true if request was OSCORE-protected */
	uint8_t *payload;                 /**< Pointer to decrypted payload or raw CoAP payload */
	uint16_t payload_len;             /**< Decrypted payload length or 0 */
	uint8_t plainbuf[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX]; /**< Buffer for decrypted payload */
};

/**
 * @brief Unprotect an OSCORE CoAP resource request and extract payload.
 *
 * Handles the common OSCORE unprotect pattern used across multiple CoAP
 * resource handlers (deaddrop_post, confessions_post, msg_inbox_post).
 * When CONFIG_LICHEN_COAP_SERVER_OSCORE is disabled or the request is not
 * protected, this function returns the raw payload from the CoAP packet.
 *
 * Caller must check result->payload and result->payload_len after return;
 * if the request is OSCORE-protected but unprotect fails, the function
 * returns a CoAP error response code.
 *
 * @param[in]  resource    CoAP resource
 * @param[in]  request     CoAP request packet
 * @param[in]  addr        Client address (for EUI64 extraction + ctx lookup)
 * @param[in]  addr_len    Address length
 * @param[in]  expected_method Expected CoAP method code (checked after unprotect)
 * @param[out] result      Unprotect result (ctx, piv, payload)
 * @return 0 on success, CoAP response code on error (caller should return it)
 */
int coap_oscore_unprotect_resource_request(struct coap_resource *resource,
					   struct coap_packet *request,
					   struct sockaddr *addr, socklen_t addr_len,
					   uint8_t expected_method,
					   struct coap_oscore_unprotect_result *result);

/**
 * @brief Send an OSCORE-protected response for a resource request.
 *
 * Handles the common OSCORE response protection pattern. When the request
 * was not OSCORE-protected, calls lichen_coap_respond() instead.
 *
 * @param[in] resource    CoAP resource
 * @param[in] request     Original CoAP request
 * @param[in] addr        Client address
 * @param[in] addr_len    Address length
 * @param[in] result      Unprotect result from coap_oscore_unprotect_resource_request()
 * @param[in] resp_code   CoAP response code
 * @param[in] content_format Content-format (0 for none)
 * @param[in] payload     Response payload (may be NULL)
 * @param[in] payload_len Payload length
 * @return 0 on success, negative error code on failure
 */
int coap_oscore_respond_resource(struct coap_resource *resource,
				 struct coap_packet *request,
				 struct sockaddr *addr, socklen_t addr_len,
				 const struct coap_oscore_unprotect_result *result,
				 uint8_t resp_code, uint16_t content_format,
				 const uint8_t *payload, size_t payload_len);

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
 * @brief Build and send an OSCORE-protected CoAP response
 *
 * Convenience wrapper around coap_oscore_protect_response + coap_resource_send.
 * Falls back to an unprotected 5.00 response on protect failure.
 *
 * @param[in] resource    CoAP resource
 * @param[in] request     Original CoAP request
 * @param[in] addr        Client address
 * @param[in] addr_len    Address length
 * @param[in] ctx         OSCORE security context (may be NULL)
 * @param[in] piv         Request PIV
 * @param[in] piv_len     PIV length
 * @param[in] code        CoAP response code
 * @return 0 on success, negative error code on failure
 */
int lichen_coap_oscore_respond(struct coap_resource *_Nonnull resource,
			       struct coap_packet *_Nonnull request,
			       struct sockaddr *_Nonnull addr, socklen_t addr_len,
			       struct oscore_ctx *_Nonnull ctx,
			       const uint8_t *_Nonnull piv, size_t piv_len,
			       uint8_t code);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_OSCORE_H_ */
