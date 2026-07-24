/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_server.h
 * @brief CoAP server for LICHEN nodes
 *
 * Provides a CoAP server exposing the LCI resources:
 * - /status - Node status (GET)
 * - /config - Node configuration (GET/PUT)
 * - /neighbors - Neighbor table (GET)
 * - /keys - Peer key store (GET/PUT/DELETE via coap_keys module)
 * - /msg/inbox - Messages (GET/POST)
 * - /deaddrop - Dead drop DTN (POST/GET with ?recipient query)
 * - /.well-known/core - Resource discovery (GET)
 *
 * Uses Zephyr's CoAP service APIs with static resource definitions.
 * CBOR (content-format 60) for most LCI resources; SenML+CBOR (112) for
 * location and deaddrop per RFC 8428.
 *
 * SECURITY: When CONFIG_LICHEN_COAP_SERVER_OSCORE is enabled, the server
 * can be configured to require OSCORE protection for sensitive resources.
 */

#ifndef LICHEN_COAP_SERVER_H_
#define LICHEN_COAP_SERVER_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>

/* Nullability annotations for pointer safety */
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

/** Maximum message inbox depth */
#define LICHEN_COAP_MSG_INBOX_MAX 16

/** Maximum number of neighbors in the neighbor table */
#define LICHEN_COAP_NEIGHBORS_MAX 8

/** Maximum CBOR payload size for responses */
#define LICHEN_COAP_SERVER_MAX_PAYLOAD 512

/** SenML+CBOR content-format (IANA 112, RFC 8428) for /sensors/location
 * and /deaddrop resources.
 */
#define SENML_CBOR_CONTENT_FORMAT 112

/**
 * @brief Node status provider callback
 *
 * Called when /status is accessed. Implementation should populate
 * the CBOR map with status fields (uptime, rank, parent, battery, etc).
 *
 * @param[out] buf Buffer to write CBOR payload
 * @param[in] buf_len Buffer size
 * @return Number of bytes written, or negative error code
 */
typedef int (*lichen_coap_status_cb)(uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Node config provider callback
 *
 * Called when /config GET is accessed. Implementation should populate
 * the CBOR map with config fields (region, tx_power_dbm, etc).
 *
 * @param[out] buf Buffer to write CBOR payload
 * @param[in] buf_len Buffer size
 * @return Number of bytes written, or negative error code
 */
typedef int (*lichen_coap_config_get_cb)(uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Node config update callback
 *
 * Called when /config PUT is received. Implementation should parse
 * the CBOR map and apply configuration updates.
 *
 * @param[in] payload CBOR payload containing config updates
 * @param[in] payload_len Payload length
 * @return 0 on success, negative error code on failure
 */
typedef int (*lichen_coap_config_put_cb)(const uint8_t *_Nonnull payload,
					 size_t payload_len);

/**
 * @brief Neighbor table provider callback
 *
 * Called when /neighbors GET is accessed. Implementation should populate
 * the CBOR array with neighbor entries.
 *
 * @param[out] buf Buffer to write CBOR payload
 * @param[in] buf_len Buffer size
 * @return Number of bytes written, or negative error code
 */
typedef int (*lichen_coap_neighbors_cb)(uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Message inbox provider callback
 *
 * Called when /msg/inbox GET is accessed.
 *
 * @param[out] buf Buffer to write CBOR payload
 * @param[in] buf_len Buffer size
 * @return Number of bytes written, or negative error code
 */
typedef int (*lichen_coap_msg_get_cb)(uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Message post callback
 *
 * Called when /msg/inbox POST is received. Implementation should parse
 * the CBOR message and queue it for delivery.
 *
 * @param[in] payload CBOR payload containing message
 * @param[in] payload_len Payload length
 * @param[out] msg_id Assigned message ID (written on success)
 * @return 0 on success, negative error code on failure
 */
typedef int (*lichen_coap_msg_post_cb)(const uint8_t *_Nonnull payload,
				       size_t payload_len,
				       uint32_t *_Nonnull msg_id);
typedef int (*lichen_coap_deaddrop_cb)(const uint8_t *_Nonnull payload, size_t payload_len);

/**
 * @brief Common helper for sending CoAP responses (avoids duplication in resource handlers).
 *
 * Constructs ACK/NON response matching the request's token and ID, appends content-format
 * if payload present, and sends. Used by deaddrop_post and other resources.
 */
int lichen_coap_respond(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len,
			uint8_t resp_code, uint16_t content_format,
			const uint8_t *payload, size_t payload_len);

/**
 * @brief CoAP server callback configuration
 *
 * Register callbacks to provide data for CoAP resources.
 * NULL callbacks result in 4.04 Not Found responses for those resources.
 */
struct lichen_coap_server_handlers {
	lichen_coap_status_cb status;         /**< /status GET */
	lichen_coap_config_get_cb config_get; /**< /config GET */
	lichen_coap_config_put_cb config_put; /**< /config PUT */
	lichen_coap_neighbors_cb neighbors;   /**< /neighbors GET */
	lichen_coap_msg_get_cb msg_get;       /**< /msg/inbox GET */
	lichen_coap_msg_post_cb msg_post;     /**< /msg/inbox POST */
	lichen_coap_deaddrop_cb deaddrop;
};

/**
 * @brief Initialize the CoAP server subsystem.
 *
 * Registers callbacks and starts the CoAP service. The service binds
 * to port 5683 (CoAP default) on all interfaces.
 *
 * @param[in] handlers Callback handlers (may be NULL for default stubs)
 * @return 0 on success, negative error code on failure
 */
int lichen_coap_server_init(const struct lichen_coap_server_handlers *_Nullable handlers);

/**
 * @brief Start the CoAP server.
 *
 * Starts the CoAP service if not already running.
 * Called automatically by lichen_coap_server_init() if autostart is enabled.
 *
 * @return 0 on success, negative error code on failure
 */
int lichen_coap_server_start(void);

/**
 * @brief Stop the CoAP server.
 *
 * @return 0 on success, negative error code on failure
 */
int lichen_coap_server_stop(void);

/**
 * @brief Check if the CoAP server is running.
 *
 * @return 1 if running, 0 if stopped, negative on error
 */
int lichen_coap_server_is_running(void);

bool lichen_coap_is_local_admin(const struct sockaddr *addr, socklen_t addr_len);

struct lichen_deaddrop_provider {
	int (*store)(const uint8_t *payload, size_t len);
	int (*retrieve)(uint8_t *buf, size_t buf_len, const char *node);
	struct lichen_dtn_buffer *dtn_buf;  /* non-static DTN storage per P4 review */
};

int lichen_coap_deaddrop_register(struct lichen_deaddrop_provider *provider);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_SERVER_H_ */
