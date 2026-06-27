/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_client.h
 * @brief CoAP client helpers for mesh requests
 *
 * Provides a simple API for making CoAP requests to other mesh nodes.
 * Wraps Zephyr's coap_client APIs with LICHEN-specific defaults.
 */

#ifndef LICHEN_COAP_CLIENT_H_
#define LICHEN_COAP_CLIENT_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <zephyr/net/coap.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default CoAP timeout in milliseconds */
#define LICHEN_COAP_TIMEOUT_MS 5000

/** Maximum response payload size */
#define LICHEN_COAP_MAX_PAYLOAD 256

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
};

/**
 * @brief CoAP response callback
 *
 * @param[in] user_data   User-provided context
 * @param[in] status      Request status (LICHEN_COAP_OK, LICHEN_COAP_ERR_TIMEOUT,
 *                        or LICHEN_COAP_ERR_TRANSPORT)
 * @param[in] code        CoAP response code (only valid when status == LICHEN_COAP_OK)
 * @param[in] payload     Response payload (may be NULL)
 * @param[in] payload_len Payload length
 */
typedef void (*lichen_coap_response_cb)(void *user_data,
					int status,
					uint8_t code,
					const uint8_t *payload,
					size_t payload_len);

/**
 * @brief CoAP request context
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
	uint32_t timeout_ms;                /**< Timeout in ms (0 = default) */
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
 * @param[in] req Request parameters
 * @return 0 on success (request sent), negative error code on failure
 */
int lichen_coap_request(const struct lichen_coap_request *req);

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
int lichen_coap_get(const struct sockaddr_in6 *addr,
		    const char * const *path,
		    lichen_coap_response_cb callback,
		    void *user_data);

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
int lichen_coap_post_cbor(const struct sockaddr_in6 *addr,
			  const char * const *path,
			  const uint8_t *payload, size_t payload_len,
			  lichen_coap_response_cb callback,
			  void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_CLIENT_H_ */
