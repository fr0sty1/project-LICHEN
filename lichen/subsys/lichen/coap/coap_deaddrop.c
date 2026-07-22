/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <errno.h>
#include <lichen/coap_server.h>
#include <lichen/oscore.h>
#include <lichen/senml.h>

LOG_MODULE_REGISTER(lichen_coap_deaddrop, CONFIG_LICHEN_COAP_DTN_LOG_LEVEL);

#define SENML_CBOR_CONTENT_FORMAT 112
#define DEADDROP_SENML_MAX 128

static const struct lichen_coap_deaddrop_provider *s_provider;

int coap_respond(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len, uint8_t resp_code, const uint8_t *payload, size_t payload_len) {
	static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON) ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int r;
	r = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1, type, tkl, token, resp_code, coap_header_get_id(request));
	if (r < 0) {
		return r;
	}
	if (payload != NULL && payload_len > 0) {
		r = coap_append_option_int(&resp, COAP_OPTION_CONTENT_FORMAT, SENML_CBOR_CONTENT_FORMAT);
		if (r < 0) {
			return r;
		}
		r = coap_packet_append_payload_marker(&resp);
		if (r < 0) {
			return r;
		}
		r = coap_packet_append_payload(&resp, payload, (uint16_t)payload_len);
		if (r < 0) {
			return r;
		}
	}
	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}

static int deaddrop_get(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	uint8_t payload[DEADDROP_SENML_MAX];
	int len;
	if (s_provider && s_provider->retrieve) {
		len = s_provider->retrieve(NULL, payload, sizeof(payload));
	} else {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}
	if (len < 0) {
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}
	return coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CONTENT, payload, (size_t)len);
}

static int deaddrop_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}
	if (s_provider && s_provider->store) {
		int r = s_provider->store(payload, payload_len, NULL, 86400);
		if (r < 0) {
			return COAP_RESPONSE_CODE_INTERNAL_ERROR;
		}
	}
	return coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CREATED, NULL, 0);
}

int lichen_coap_deaddrop_register(const struct lichen_coap_deaddrop_provider *provider) {
	if (provider == NULL) {
		return -EINVAL;
	}
	int r = oscore_init();
	if (r < 0) {
		return r;
	}
	s_provider = provider;
	return 0;
}

static const char *const deaddrop_path[] = { "deaddrop", NULL };

COAP_RESOURCE_DEFINE(lichen_deaddrop, lichen_coap, {
	.get = deaddrop_get,
	.post = deaddrop_post,
	.path = deaddrop_path,
});
