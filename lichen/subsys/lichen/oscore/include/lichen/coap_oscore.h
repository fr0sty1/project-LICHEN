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
 * @brief Build and send an OSCORE-protected CoAP response.
 *
 * Centralizes the duplicated pattern across LCI mutating handlers where
 * an OSCORE response must be built from a ctx + PIV, with fallback to
 * plain CoAP on protect failure.
 *
 * @param[in] resource     CoAP resource
 * @param[in] request      Original request (for token, ID, type)
 * @param[in] addr         Client address
 * @param[in] addr_len     Address length
 * @param[in] ctx          OSCORE context (may be NULL, in which case plain
 *                          lichen_coap_respond is used as fallback)
 * @param[in] piv          Request PIV (may be NULL if ctx is NULL)
 * @param[in] piv_len      PIV length
 * @param[in] code         CoAP response code
 * @return 0 on success, negative error code on failure
 */
int coap_oscore_send_protected(struct coap_resource *_Nonnull resource,
			       struct coap_packet *_Nonnull request,
			       struct sockaddr *_Nonnull addr, socklen_t addr_len,
			       struct oscore_ctx *_Nullable ctx,
			       const uint8_t *_Nullable piv, size_t piv_len,
			       uint8_t code);

/**
 * @brief Authorize an LCI mutating CoAP operation.
 *
 * Handles the complete authorization flow for LCI mutating operations:
 *   - For OSCORE-protected requests: extracts peer EUI64 from sockaddr,
 *     looks up OSCORE context via oscore_ctx_get_by_eui64(), unprotects
 *     the request, and validates the expected method.
 *   - For unprotected requests: checks local admin access via
 *     lichen_coap_is_local_admin().
 *
 * On success, sets the output parameters for payload and OSCORE context.
 * The caller uses these to process the request body and to protect the
 * response via coap_oscore_send_protected().
 *
 * @param[in]     resource        CoAP resource
 * @param[in]     request         CoAP request packet
 * @param[in]     addr            Client address
 * @param[in]     addr_len        Address length
 * @param[in]     expected_method Expected CoAP method (POST/PUT/DELETE)
 * @param[in]     plain_buf       Buffer for decrypted payload (may be NULL
 *                                 if no payload expected, e.g. DELETE)
 * @param[in]     plain_buf_len   Size of plain_buf
 * @param[out]    payload_out     Pointer to payload data (set to plain_buf
 *                                 on OSCORE, or raw payload on plain CoAP)
 * @param[out]    payload_len_out Payload length
 * @param[out]    ctx_out         OSCORE context (NULL if plain CoAP)
 * @param[out]    piv_out         Request PIV buffer (must be at least
 *                                 OSCORE_PIV_MAX_LEN bytes)
 * @param[out]    piv_len_out     PIV length
 * @param[out]    is_protected    True if request was OSCORE-protected
 * @return 0 on success, or a CoAP response code to return directly on
 *         authorization failure (UNAUTHORIZED, BAD_REQUEST, NOT_ALLOWED).
 *         The caller should propagate this return value.
 */
int coap_oscore_authorize_mutating(struct coap_resource *_Nonnull resource,
				   struct coap_packet *_Nonnull request,
				   struct sockaddr *_Nonnull addr, socklen_t addr_len,
				   uint8_t expected_method,
				   uint8_t *_Nullable plain_buf, size_t plain_buf_len,
				   const uint8_t *_Nonnull *payload_out,
				   uint16_t *_Nonnull payload_len_out,
				   struct oscore_ctx *_Nullable *ctx_out,
				   uint8_t *_Nonnull piv_out, size_t *_Nonnull piv_len_out,
				   bool *_Nonnull is_protected);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_OSCORE_H_ */
