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
 * - /key - Public key (GET)
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
#include <lichen/coap_server.h>
#include <lichen/senml.h>
#include <lichen/oscore.h>
#include <lichen/coap_oscore.h>

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
			uint8_t resp_code,
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
					     CBOR_CONTENT_FORMAT);
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
	return lichen_coap_respond(resource, request, addr, addr_len, code, NULL, 0);
}


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
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	len = s_handlers.status(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Status callback failed: %d", len);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, payload, len);
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
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	len = s_handlers.config_get(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Config GET callback failed: %d", len);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, payload, len);
}

static int config_put(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	const uint8_t *payload;
	uint16_t payload_len;
	int ret;

	if (s_handlers.config_put == NULL) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	ret = s_handlers.config_put(payload, payload_len);
	if (ret < 0) {
		LOG_ERR("Config PUT callback failed: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
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
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	len = s_handlers.neighbors(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Neighbors callback failed: %d", len);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, payload, len);
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
 * /key resource - GET returns public key as CBOR
 */
static int key_get(struct coap_resource *resource,
		   struct coap_packet *request,
		   struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t pubkey[32];
	/* CBOR map with fingerprint and pubkey: 1 (map) + 12 + 17 (fingerprint)
	 * + 7 + 34 (pubkey) = 71 bytes encoded below.
	 */
	uint8_t payload[72];
	int ret;
	size_t idx = 0;

	if (s_handlers.key == NULL) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	ret = s_handlers.key(pubkey);
	if (ret < 0) {
		LOG_ERR("Key callback failed: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	/*
	 * Encode minimal CBOR response:
	 * { "fingerprint": "<hex>", "pubkey": h'<32 bytes>' }
	 *
	 * For simplicity, encode manually:
	 * A2 (map of 2)
	 *   6B "fingerprint" (text, 11 chars)
	 *   70 <16 hex chars> (text, 16 chars)
	 *   66 "pubkey" (text, 6 chars)
	 *   58 20 <32 bytes> (bytes, length 32)
	 */
	payload[idx++] = 0xA2; /* Map of 2 items */

	/* Key: "fingerprint" */
	payload[idx++] = 0x6B; /* Text, 11 chars */
	memcpy(&payload[idx], "fingerprint", 11);
	idx += 11;

	/* Value: hex string of first 8 bytes */
	payload[idx++] = 0x70; /* Text, 16 chars */
	static const char hex[] = "0123456789abcdef";
	for (int i = 0; i < 8; i++) {
		payload[idx++] = hex[(pubkey[i] >> 4) & 0xF];
		payload[idx++] = hex[pubkey[i] & 0xF];
	}

	/* Key: "pubkey" */
	payload[idx++] = 0x66; /* Text, 6 chars */
	memcpy(&payload[idx], "pubkey", 6);
	idx += 6;

	/* Value: 32-byte public key */
	payload[idx++] = 0x58; /* Bytes, 1-byte length follows */
	payload[idx++] = 0x20; /* 32 bytes */
	memcpy(&payload[idx], pubkey, 32);
	idx += 32;

	return lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, payload, idx);
}

static const char * const key_path[] = { "key", NULL };
static const char * const key_attrs[] = {
	"rt=\"lichen.key\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_key, lichen_coap_server, {
	.get = key_get,
	.path = key_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = key_attrs,
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
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	len = s_handlers.msg_get(payload, sizeof(payload));
	if (len < 0) {
		LOG_ERR("Message GET callback failed: %d", len);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			      COAP_RESPONSE_CODE_CONTENT, payload, len);
}

static int msg_inbox_post(struct coap_resource *resource,
			  struct coap_packet *request,
			  struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_packet response;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint16_t id;
	uint8_t tkl;
	const uint8_t *payload;
	uint16_t payload_len;
	uint32_t msg_id = 0;
	int ret;

	if (s_handlers.msg_post == NULL) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	ret = s_handlers.msg_post(payload, payload_len, &msg_id);
	if (ret < 0) {
		LOG_ERR("Message POST callback failed: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	static uint8_t response_buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet response;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint16_t id;
	uint8_t tkl;
	int ret2;

	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	ret2 = coap_packet_init(&response, response_buf, sizeof(response_buf),
			       COAP_VERSION_1, COAP_TYPE_ACK, tkl, token,
			       COAP_RESPONSE_CODE_CREATED, id);
	if (ret2 < 0) {
		return ret2;
	}

	ret2 = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH,
					"msg", 3);
	if (ret2 < 0) {
		return ret2;
	}

	ret2 = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH,
					"sent", 4);
	if (ret2 < 0) {
		return ret2;
	}

	char id_str[12];
	int id_len = snprintf(id_str, sizeof(id_str), "%u", msg_id);

	ret2 = coap_packet_append_option(&response, COAP_OPTION_LOCATION_PATH,
					id_str, id_len);
	if (ret2 < 0) {
		return ret2;
	}

	return coap_resource_send(resource, &response, addr, addr_len, NULL);
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

int lichen_coap_respond(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len, uint8_t resp_code, uint16_t content_format, const uint8_t *payload, size_t payload_len) {
	static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON) ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int r = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1, type, tkl, token, resp_code, coap_header_get_id(request));
	if (r < 0) return r;
	if (payload != NULL && payload_len > 0) {
		if (content_format != 0) {
			r = coap_append_option_int(&resp, COAP_OPTION_CONTENT_FORMAT, content_format);
			if (r < 0) return r;
		}
		r = coap_packet_append_payload_marker(&resp);
		if (r < 0) return r;
		r = coap_packet_append_payload(&resp, payload, (uint16_t)payload_len);
		if (r < 0) return r;
	}
	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}
