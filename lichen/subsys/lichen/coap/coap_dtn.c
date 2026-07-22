/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <lichen/coap_server.h>
#include <lichen/oscore.h>
#include <lichen/routing/dtn.h>
#include <lichen/senml.h>

LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DEADDROP_LOG_LEVEL);

static const struct lichen_deaddrop_provider *s_provider;
static struct lichen_dtn_buffer s_dtn_buf;
static struct senml_pack s_senml_pack;

static int coap_respond(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len, uint8_t code, const uint8_t *payload, size_t payload_len) {
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON) ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int r = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1, type, tkl, token, code, coap_header_get_id(request));
	if (r < 0) return r;
	if (payload && payload_len) {
		coap_append_option_int(&resp, COAP_OPTION_CONTENT_FORMAT, 112);
		coap_packet_append_payload_marker(&resp);
		coap_packet_append_payload(&resp, payload, payload_len);
	}
	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}

int lichen_coap_deaddrop_register(const struct lichen_deaddrop_provider *provider) {
	if (provider == NULL) return -EINVAL;
	s_provider = provider;
	int r = oscore_init();
	if (r < 0) return r;
	r = lichen_coap_client_init();
	if (r < 0) return r;
	r = lichen_dtn_init(&s_dtn_buf);
	if (r < 0) return r;
	r = senml_pack_init(&s_senml_pack, "", 0);
	if (r < 0) return r;
	return 0;
}

static int deaddrop_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	if (s_provider == NULL || s_provider->store == NULL) return 0x84;
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) return 0x80;
	int r = s_provider->store(payload, payload_len);
	if (r < 0) return 0xA0;
	return 0x41;
}

static int deaddrop_get(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	if (s_provider == NULL || s_provider->retrieve == NULL) return 0x84;
	uint8_t buf[128];
	int len = s_provider->retrieve(buf, sizeof(buf), NULL);
	if (len < 0) return 0xA0;
	return coap_respond(resource, request, addr, addr_len, 0x45, buf, len);
}

static const char * const deaddrop_path[] = { "deaddrop", NULL };
COAP_RESOURCE_DEFINE(lichen_deaddrop, lichen_coap, {
	.get = deaddrop_get,
	.post = deaddrop_post,
	.path = deaddrop_path,
});
