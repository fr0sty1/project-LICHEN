/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>
#include <string.h>
#include <lichen/oscore.h>
#include <lichen/senml.h>
#include <lichen/routing/dtn.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>

LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DTN_LOG_LEVEL);

#define DTN_SENML_MAX 128

static struct lichen_dtn_buffer s_dtn_buf;
static struct senml_pack s_senml_pack;
static const struct lichen_coap_deaddrop_provider *s_provider;
static uint32_t s_last_confession[16];
static K_MUTEX_DEFINE(s_dtn_mutex);

static int deaddrop_get(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	static bool inited = false;
	if (!inited) {
		lichen_dtn_init(&s_dtn_buf);
		inited = true;
	}
	uint32_t now_unix = (uint32_t)(k_uptime_get() / 1000);
	lichen_dtn_expire_old(&s_dtn_buf, now_unix);
	struct oscore_ctx *ctx = NULL;
	uint8_t payload[DTN_SENML_MAX];
	int len = 0;
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	if (coap_oscore_is_protected(request) && coap_oscore_get_option(request, oscore_opt, &opt_len) == 0) {
		oscore_ctx_get((const uint8_t *)"\x01", 1, &ctx);
	}
	uint8_t iid[8] = {0};
	uint16_t n = lichen_dtn_retrieve_for(&s_dtn_buf, iid, NULL, NULL);
	senml_pack_init(&s_senml_pack, NULL, (uint64_t)now_unix);
	senml_add_float(&s_senml_pack, "pending", NULL, (float)n);
	len = senml_encode_cbor(&s_senml_pack, payload, sizeof(payload));
	if (len < 0) {
		k_mutex_unlock(&s_dtn_mutex);
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}
	k_mutex_unlock(&s_dtn_mutex);
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, payload, (size_t)len);
}

static int deaddrop_post(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	uint32_t now_ms = k_uptime_get_32();
	uint8_t slot = 0;
	uint8_t iid[8] = {0};
	if (addr && addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
		memcpy(iid, &in6->sin6_addr.s6_addr[8], 8);
		slot = in6->sin6_addr.s6_addr[15] % 16;
	}
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	if (now_ms - s_last_confession[slot] < 30000) {
		k_mutex_unlock(&s_dtn_mutex);
		return COAP_RESPONSE_CODE_TOO_MANY_REQUESTS;
	}
	s_last_confession[slot] = now_ms;
	uint16_t payload_len = 0;
	const uint8_t *payload_data = coap_packet_get_payload(request, &payload_len);
	if (payload_data == NULL || payload_len == 0) {
		k_mutex_unlock(&s_dtn_mutex);
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}
	struct oscore_ctx *ctx = NULL;
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	if (coap_oscore_is_protected(request) && coap_oscore_get_option(request, oscore_opt, &opt_len) == 0) {
		oscore_ctx_get_by_eui64(iid, &ctx);
		if (ctx) {
			uint8_t code;
			uint8_t plain[128];
			size_t plain_len = sizeof(plain);
			uint8_t piv[8];
			size_t piv_len = sizeof(piv);
			coap_oscore_unprotect_request(ctx, request, &code, NULL, NULL, plain, &plain_len, piv, &piv_len);
			payload_data = plain;
			payload_len = (uint16_t)plain_len;
		}
	}
	uint32_t now_unix = (uint32_t)(k_uptime_get() / 1000);
	uint8_t dummy_iid[8] = {0};
	bool ok = lichen_dtn_buffer_message(&s_dtn_buf, payload_data, payload_len, dummy_iid, now_unix + 86400, now_unix, now_ms);
	(void)ok;
	k_mutex_unlock(&s_dtn_mutex);
	return coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CREATED, NULL, 0);
}

static int confessions_get(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	static bool inited = false;
	if (!inited) {
		lichen_dtn_init(&s_dtn_buf);
		inited = true;
	}
	uint32_t now_unix = (uint32_t)(k_uptime_get() / 1000);
	lichen_dtn_expire_old(&s_dtn_buf, now_unix);
	struct oscore_ctx *ctx = NULL;
	uint8_t payload[DTN_SENML_MAX];
	int len = 0;
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	if (coap_oscore_is_protected(request) && coap_oscore_get_option(request, oscore_opt, &opt_len) == 0) {
		oscore_ctx_get((const uint8_t *)"\x01", 1, &ctx);
	}
	uint8_t iids[8][8];
	uint16_t n = lichen_dtn_get_pending_iids(&s_dtn_buf, iids, 1);
	senml_pack_init(&s_senml_pack, NULL, (uint64_t)now_unix);
	senml_add_float(&s_senml_pack, "pending", NULL, (float)n);
	len = senml_encode_cbor(&s_senml_pack, payload, sizeof(payload));
	if (len < 0) {
		k_mutex_unlock(&s_dtn_mutex);
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}
	k_mutex_unlock(&s_dtn_mutex);
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, payload, (size_t)len);
}

static int confessions_post(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	uint32_t now_ms = k_uptime_get_32();
	uint8_t slot = 0;
	uint8_t iid[8] = {0};
	if (addr && addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
		memcpy(iid, &in6->sin6_addr.s6_addr[8], 8);
		slot = in6->sin6_addr.s6_addr[15] % 16;
	}
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	if (now_ms - s_last_confession[slot] < 30000) {
		k_mutex_unlock(&s_dtn_mutex);
		return COAP_RESPONSE_CODE_TOO_MANY_REQUESTS;
	}
	s_last_confession[slot] = now_ms;
	struct oscore_ctx *ctx = NULL;
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	if (coap_oscore_is_protected(request) && coap_oscore_get_option(request, oscore_opt, &opt_len) == 0) {
		oscore_ctx_get_by_eui64(iid, &ctx);
		if (ctx) {
			uint8_t code;
			uint8_t plain[64];
			size_t plain_len = sizeof(plain);
			uint16_t ct_len = 0;
			const uint8_t *ct = coap_packet_get_payload(request, &ct_len);
			oscore_unprotect_request(ctx, oscore_opt, opt_len, ct, ct_len, &code, NULL, NULL, plain, &plain_len);
		}
	}
	k_mutex_unlock(&s_dtn_mutex);
	return coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CREATED, NULL, 0);
}

static const char *const confessions_path[] = { "confessions", NULL };

COAP_RESOURCE_DEFINE(lichen_confessions, lichen_coap, {
	.get = confessions_get,
	.post = confessions_post,
	.path = confessions_path,
});
