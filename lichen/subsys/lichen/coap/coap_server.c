/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_server.c
 * @brief CoAP server for LICHEN nodes
 *
 * Implements CoAP server using Zephyr's CoAP service APIs.
 *
 * Resources exposed:
 * - /.well-known/core - Resource discovery (RFC 6690)
 * - /status - Node status (GET)
 * - /config - Node configuration (GET/PUT)
 * - /neighbors - Neighbor table (GET)
 * - /keys - Peer key store (GET/PUT/DELETE, per LCI spec; see coap_keys.c)
 * - /msg/inbox - Messages (GET/POST)
 * - /deaddrop - DTN dead drop (POST, GET?recipient=...) when enabled
 * - /confessions - Anonymous board (POST/GET, rate-limited RAM-only, per project-LICHEN-2nnd.4.2)
 *
 * All payloads use CBOR (content-format 60) for compact encoding.
 */

#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/coap_link_format.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <lichen/coap_server.h>
#include <lichen/senml.h>
#include <lichen/oscore.h>
#include <lichen/coap_oscore.h>
#include <lichen/l2/ipv6_addr.h>
#include <lichen/transport/slip_transport.h>

LOG_MODULE_REGISTER(lichen_coap_server, CONFIG_LICHEN_COAP_SERVER_LOG_LEVEL);

/* CBOR content-format code */
#define CBOR_CONTENT_FORMAT 60

/* CoAP server port */
static uint16_t s_coap_port = 5683;

static struct lichen_coap_server_handlers s_handlers;

/*
 * Common response helper for all CoAP resources (including deaddrop_post).
 * Centralizes duplicated logic from coap_*.c files. Matches Python/Rust reference
 * behavior and spec/18-applications for DTN. Type=ACK for CON requests.
 * Uses per-call static buffer to avoid both shared race and stack use-after-return.
 * Zephyr coap_resource_send + pending slab performs synchronous memcpy of packet data.
 */
int lichen_coap_respond(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len,
			uint8_t resp_code, uint16_t content_format,
			const uint8_t *payload, size_t payload_len)
{
	static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet response;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint16_t id;
	uint8_t tkl;
	int ret;

	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
		       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;

	ret = coap_packet_init(&response, buf, sizeof(buf),
			       COAP_VERSION_1, type, tkl, token, resp_code, id);
	if (ret < 0) {
		LOG_ERR("Failed to init response packet: %d", ret);
		return ret;
	}

	if (payload != NULL && payload_len > 0) {
		ret = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT,
					     content_format);
		if (ret < 0) {
			LOG_ERR("Failed to add content-format: %d", ret);
			return ret;
		}

		ret = coap_packet_append_payload_marker(&response);
		if (ret < 0) {
			LOG_ERR("Failed to add payload marker: %d", ret);
			return ret;
		}

		ret = coap_packet_append_payload(&response, payload, (uint16_t)payload_len);
		if (ret < 0) {
			LOG_ERR("Failed to add payload: %d", ret);
			return ret;
		}
	}

	ret = coap_resource_send(resource, &response, addr, addr_len, NULL);
	return ret;
}

/*
 * Helper to send a simple ACK with a response code.
 * Uses the common respond path (payload=NULL for empty ACK).
 */
static int send_ack(struct coap_resource *resource,
		    struct coap_packet *request,
		    struct sockaddr *addr, socklen_t addr_len,
		    uint8_t code)
{
	return lichen_coap_respond(resource, request, addr, addr_len, code, 0, NULL, 0);
}

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
static int msg_inbox_oscore_respond(struct coap_resource *resource,
				    struct coap_packet *request,
				    struct sockaddr *addr, socklen_t addr_len,
				    struct oscore_ctx *ctx,
				    const uint8_t *piv, size_t piv_len,
				    uint8_t code)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	int ret = coap_oscore_protect_response(ctx, piv, piv_len, request, code,
					       NULL, 0, &resp, buf, sizeof(buf));
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}
	ret = coap_resource_send(resource, &resp, addr, addr_len, NULL);
	return ret;
}
#endif


/*
 * /status resource - GET returns node status as CBOR
 */
static int status_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t payload[LICHEN_COAP_SERVER_MAX_PAYLOAD];
	int len;

	if (s_handlers.status == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	len = s_handlers.status(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Status callback failed: %d", len);
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	int ret = lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, payload, len);
	return ret < 0 ? ret : 0;
}

static const char * const status_path[] = { "status", NULL };
static const char * const status_attrs[] = {
	"rt=\"lichen.status\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_status, lichen_coap_server, {
	.get = status_get,
	.path = status_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = status_attrs,
	}),
});

/*
 * /config resource - GET returns config, PUT updates config
 */
static int config_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t payload[LICHEN_COAP_SERVER_MAX_PAYLOAD];
	int len;

	if (s_handlers.config_get == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	len = s_handlers.config_get(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Config GET callback failed: %d", len);
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	int ret = lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, payload, len);
	return ret < 0 ? ret : 0;
}

static int config_put(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	const uint8_t *payload;
	uint16_t payload_len;
	int ret;

	if (s_handlers.config_put == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
	}

	payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}

	ret = s_handlers.config_put(payload, payload_len);
	if (ret < 0) {
		LOG_ERR("Config PUT callback failed: %d", ret);
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}

	return send_ack(resource, request, addr, addr_len,
			COAP_RESPONSE_CODE_CHANGED);
}

static const char * const config_path[] = { "config", NULL };
static const char * const config_attrs[] = {
	"rt=\"lichen.config\"",
	"ct=\"60\"",
	NULL,
};

/* coap_config.c already owns the global symbol lichen_config. */
COAP_RESOURCE_DEFINE(lichen_server_config, lichen_coap_server, {
	.get = config_get,
	.put = config_put,
	.path = config_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = config_attrs,
	}),
});

/*
 * /neighbors resource - GET returns neighbor table as CBOR
 */
static int neighbors_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t payload[LICHEN_COAP_SERVER_MAX_PAYLOAD];
	int len;

	if (s_handlers.neighbors == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	len = s_handlers.neighbors(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Neighbors callback failed: %d", len);
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	int ret = lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, payload, len);
	return ret < 0 ? ret : 0;
}

static const char * const neighbors_path[] = { "neighbors", NULL };
static const char * const neighbors_attrs[] = {
	"rt=\"lichen.neighbors\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_neighbors, lichen_coap_server, {
	.get = neighbors_get,
	.path = neighbors_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = neighbors_attrs,
	}),
});

/*
 * /msg/inbox resource - GET returns inbox, POST delivers message
 */
static int msg_inbox_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t payload[LICHEN_COAP_SERVER_MAX_PAYLOAD];
	int len;

	if (s_handlers.msg_get == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	len = s_handlers.msg_get(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Message GET callback failed: %d", len);
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}

	int ret = lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, payload, len);
	return ret < 0 ? ret : 0;
}

static int msg_inbox_post(struct coap_resource *resource,
			  struct coap_packet *request,
			  struct sockaddr *addr, socklen_t addr_len)
{
	const uint8_t *payload;
	uint16_t payload_len;
	uint32_t msg_id = 0;
	int ret;
	uint8_t peer_eui64[8] = {0};
	uint8_t plain[LICHEN_COAP_SERVER_MAX_PAYLOAD];
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	struct oscore_ctx *ctx = NULL;
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = 0;
	bool is_protected = false;
#endif

	/* Extract peer EUI64/IID from sockaddr for oscore_ctx_get_by_eui64()
	 * (similar to deaddrop_post/confessions_post). Allows OSCORE mesh peers
	 * in addition to local_admin for /msg/inbox POST per LCI spec. */
	if (addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
		memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
		lichen_eui64_to_iid(peer_eui64, peer_eui64);
	}

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	is_protected = coap_oscore_is_protected(request);
	if (is_protected) {
		if (oscore_ctx_get_by_eui64(peer_eui64, &ctx) != OSCORE_OK || ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		size_t plain_len = sizeof(plain);
		piv_len = sizeof(piv);
		int r = coap_oscore_unprotect_request(ctx, request, &orig_code, opts, &opt_len,
						      plain, &plain_len, piv, &piv_len);
		if (r != OSCORE_OK) return COAP_RESPONSE_CODE_UNAUTHORIZED;
		if (orig_code != COAP_METHOD_POST) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
		payload = plain;
		payload_len = (uint16_t)plain_len;
	} else {
#endif
		if (!lichen_coap_is_local_admin(addr, addr_len)) {
			return lichen_coap_respond(resource, request, addr, addr_len,
						   COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
		}
		payload = coap_packet_get_payload(request, &payload_len);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	}
#endif

	if (s_handlers.msg_post == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}

	if (payload == NULL || payload_len == 0) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}

	ret = s_handlers.msg_post(payload, payload_len, &msg_id);
	if (ret < 0) {
		LOG_ERR("Message POST callback failed: %d", ret);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return msg_inbox_oscore_respond(resource, request, addr, addr_len, ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && ctx != NULL && piv_len > 0) {
		return msg_inbox_oscore_respond(resource, request, addr, addr_len, ctx, piv, piv_len, COAP_RESPONSE_CODE_CREATED);
	}
#endif

	static uint8_t response_buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet response;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint16_t id;
	uint8_t tkl;

	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	ret = coap_packet_init(&response, response_buf, sizeof(response_buf),
			       COAP_VERSION_1, COAP_TYPE_ACK, tkl, token,
			       COAP_RESPONSE_CODE_CREATED, id);
	if (ret < 0) {
		return ret;
	}

	ret = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH,
					"msg", 3);
	if (ret < 0) {
		return ret;
	}

	ret = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH,
					"sent", 4);
	if (ret < 0) {
		return ret;
	}

	char id_str[12];
	int id_len = snprintf(id_str, sizeof(id_str), "%u", msg_id);
	if (id_len < 0 || (size_t)id_len >= sizeof(id_str)) {
		return -EINVAL;
	}

	ret = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH,
					id_str, id_len);
	if (ret < 0) {
		return ret;
	}

	ret = coap_resource_send(resource, &response, addr, addr_len, NULL);
	return ret < 0 ? ret : 0;
}

static const char * const msg_inbox_path[] = { "msg", "inbox", NULL };
static const char * const msg_inbox_attrs[] = {
	"rt=\"msg.inbox\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_msg_inbox, lichen_coap_server, {
	.get = msg_inbox_get,
	.post = msg_inbox_post,
	.path = msg_inbox_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = msg_inbox_attrs,
	}),
});

/*
 * Define the CoAP service
 *
 * Note: When CONFIG_COAP_SERVER_WELL_KNOWN_CORE is enabled, Zephyr's
 * CoAP server automatically handles /.well-known/core requests using
 * the resources registered with this service.
 */
COAP_SERVICE_DEFINE(lichen_coap_server, NULL, &s_coap_port, 0);

int lichen_coap_server_init(const struct lichen_coap_server_handlers *handlers)
{
	if (handlers != NULL) {
		memcpy(&s_handlers, handlers, sizeof(s_handlers));
	} else {
		memset(&s_handlers, 0, sizeof(s_handlers));
	}

	BUILD_ASSERT(LICHEN_COAP_SERVER_MAX_PAYLOAD + 128 <= CONFIG_COAP_SERVER_MESSAGE_SIZE,
		     "server payload exceeds CoAP capacity");

	LOG_INF("CoAP server initialized on port %u", s_coap_port);
	return lichen_coap_server_start();
}

int lichen_coap_server_start(void)
{
	int ret;

	ret = coap_service_start(&lichen_coap_server);
	if (ret < 0 && ret != -EALREADY) {
		LOG_ERR("Failed to start CoAP server: %d", ret);
		return ret;
	}

	LOG_INF("CoAP server started");
	return 0;
}

int lichen_coap_server_stop(void)
{
	int ret;

	ret = coap_service_stop(&lichen_coap_server);
	if (ret < 0 && ret != -EALREADY) {
		LOG_ERR("Failed to stop CoAP server: %d", ret);
		return ret;
	}

	LOG_INF("CoAP server stopped");
	return 0;
}

int lichen_coap_server_is_running(void)
{
	return coap_service_is_running(&lichen_coap_server);
}
