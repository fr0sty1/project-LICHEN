/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_client.h
 * @brief CoAP client helpers for mesh requests
 *
 * Provides a simple API for making CoAP requests to other mesh nodes.
 * Wraps Zephyr's coap_client APIs with LICHEN-specific defaults.
 *
 * SECURITY: When CONFIG_LICHEN_COAP_CLIENT_OSCORE is enabled, requests
 * with a non-NULL oscore_ctx are protected using RFC 8613. Responses are
 * automatically decrypted before delivery to the callback.
 */

#ifndef LICHEN_COAP_CLIENT_H_
#define LICHEN_COAP_CLIENT_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <zephyr/net/coap.h>

#if defined(CONFIG_LICHEN_COAP_CLIENT_OSCORE) || defined(__DOXYGEN__)
#include <lichen/oscore.h>
#endif

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
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

/** Default CoAP timeout in milliseconds */
#define LICHEN_COAP_TIMEOUT_MS 5000

/** Maximum response payload size */
#define LICHEN_COAP_MAX_PAYLOAD 256

/** Maximum URI path array entries, including the terminating NULL */
#define LICHEN_COAP_MAX_PATH_COMPONENTS 8

/** Sentinel value indicating content_format was not set (use in initializers) */
#define LICHEN_COAP_FMT_UNSET UINT16_MAX

/**
 * @brief CoAP request result codes
 */
enum lichen_coap_result {
	LICHEN_COAP_OK = 0,
	LICHEN_COAP_ERR_TIMEOUT = -1,
	LICHEN_COAP_ERR_NO_MEMORY = -2,
	LICHEN_COAP_ERR_SEND_FAILED = -3,
	LICHEN_COAP_ERR_INVALID_RESPONSE = -4,
	LICHEN_COAP_ERR_NOT_FOUND = -5,
	LICHEN_COAP_ERR_UNAUTHORIZED = -6,
	LICHEN_COAP_ERR_INVALID_PARAM = -7,
	LICHEN_COAP_ERR_TRANSPORT = -8,
	LICHEN_COAP_ERR_OSCORE_PROTECT = -9,   /**< OSCORE protect failed */
	LICHEN_COAP_ERR_OSCORE_UNPROTECT = -10, /**< OSCORE unprotect failed */
};

/**
 * @brief CoAP response callback
 *
 * @param[in] user_data   User-provided context
 * @param[in] status      Request status (LICHEN_COAP_OK, LICHEN_COAP_ERR_TIMEOUT,
 *                        LICHEN_COAP_ERR_TRANSPORT, or
 *                        LICHEN_COAP_ERR_INVALID_RESPONSE)
 * @param[in] code        CoAP response code (only valid when status == LICHEN_COAP_OK)
 * @param[in] payload     Response payload (may be NULL)
 * @param[in] payload_len Payload length
 */
typedef void (*lichen_coap_response_cb)(void *_Nullable user_data,
					int status,
					uint8_t code,
					const uint8_t *_Nullable payload,
					size_t payload_len);

/**
 * @brief CoAP request context
 *
 * The path field must point to a NULL-terminated array of URI path component
 * strings. The terminating NULL must appear within
 * LICHEN_COAP_MAX_PATH_COMPONENTS entries; component strings must be valid
 * NUL-terminated strings for the lifetime of lichen_coap_request().
 */
struct lichen_coap_request {
	struct sockaddr_in6 addr;           /**< Destination address */
	const char * const *path;           /**< URI path components */
	uint8_t method;                     /**< CoAP method (GET, POST, etc) */
	const uint8_t *payload;             /**< Request payload (optional) */
	size_t payload_len;                 /**< Payload length */
	uint16_t content_format;            /**< Content format (LICHEN_COAP_FMT_UNSET = not set) */
	bool confirmable;                   /**< Use CON message type */
	lichen_coap_response_cb callback;   /**< Response callback */
	void *user_data;                    /**< User context for callback */
	uint32_t timeout_ms;                /**< Timeout in ms (0 = default, max UINT32_MAX / 2) */
#if defined(CONFIG_LICHEN_COAP_CLIENT_OSCORE) || defined(__DOXYGEN__)
	struct oscore_ctx *oscore_ctx;      /**< OSCORE context (NULL = unprotected) */
#endif
};

/**
 * @brief Initialize the CoAP client subsystem.
 *
 * Called automatically on first request if not already initialized.
 * Call explicitly at startup to fail-fast on socket/init errors and
 * avoid first-request latency from socket creation.
 *
 * Thread-safe; idempotent (multiple calls return 0 after first success).
 *
 * @return 0 on success, negative error code on failure
 */
int lichen_coap_client_init(void);

/**
 * @brief Send a CoAP request.
 *
 * This is an asynchronous operation. The callback will be invoked
 * when a response is received or the request times out.
 *
 * @param[in] req Request parameters. req->path must be a NULL-terminated
 *                URI component array as described by struct
 *                lichen_coap_request.
 * @return 0 on success (request sent), negative error code on failure
 */
int lichen_coap_request(const struct lichen_coap_request *_Nonnull req);

/**
 * @brief Send a simple GET request.
 *
 * Convenience wrapper for GET requests with no payload.
 *
 * @param[in] addr     Destination IPv6 address
 * @param[in] path     URI path (null-terminated array)
 * @param[in] callback Response callback
 * @param[in] user_data User context
 * @return 0 on success, negative error code on failure
 */
int lichen_coap_get(const struct sockaddr_in6 *_Nonnull addr,
		    const char * const *_Nonnull path,
		    lichen_coap_response_cb _Nonnull callback,
		    void *_Nullable user_data);

/**
 * @brief Send a POST request with CBOR payload.
 *
 * @param[in] addr        Destination IPv6 address
 * @param[in] path        URI path (null-terminated array)
 * @param[in] payload     CBOR payload
 * @param[in] payload_len Payload length
 * @param[in] callback    Response callback
 * @param[in] user_data   User context
 * @return 0 on success, negative error code on failure
 */
int lichen_coap_post_cbor(const struct sockaddr_in6 *_Nonnull addr,
			  const char * const *_Nonnull path,
			  const uint8_t *_Nonnull payload, size_t payload_len,
			  lichen_coap_response_cb _Nonnull callback,
			  void *_Nullable user_data);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_CLIENT_H_ */
