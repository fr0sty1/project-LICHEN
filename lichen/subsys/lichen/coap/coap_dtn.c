/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_dtn.c
 * @brief LICHEN CoAP DTN/deaddrop resources using SenML CBOR (spec 17, 18, Appendix F).
 *
 * GET /deaddrop returns SenML pack with pending message count.
 * Uses senml_encode pattern from location.c for consistency.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>
#include <stdio.h>
#include <string.h>
#include <lichen/senml.h>
#include <lichen/oscore.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>
#include <lichen/routing/dtn.h>
#include <lichen/l2/ipv6_addr.h>
#include <lichen/l2/lora_l2.h>
#include <zcbor_decode.h>

LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DEADDROP_LOG_LEVEL);

/* Bounded: base record (~40 B urn) + count record. 128 B is ample. */
#define DEADDROP_SENML_MAX 128

/* "urn:dev:mac:" + 16 hex + ":" + NUL */
#define BASE_NAME_MAX 32
static uint64_t s_last_confessions[256];
static struct lichen_dtn_buffer s_dtn_buf;
static K_MUTEX_DEFINE(s_dtn_mutex);

/* Fill `out` with the node's SenML base name, or empty if EUI not available. */
static void build_base_name(char *out, size_t out_len)
{
	uint8_t eui[8];

	if (lichen_lora_l2_copy_eui64(eui) != 0) {
		out[0] = '\0';
		return;
	}
	snprintf(out, out_len,
		 "urn:dev:mac:%02x%02x%02x%02x%02x%02x%02x%02x:", eui[0], eui[1],
		 eui[2], eui[3], eui[4], eui[5], eui[6], eui[7]);
}

static int senml_encode_dtn_count(const char *base_name, uint16_t count,
				  uint8_t *buf, size_t buflen)
{
	struct senml_pack pack;
	int r = senml_pack_init(&pack, base_name, 0);
	if (r < 0) {
		return r;
	}
	r = senml_add_float(&pack, "count", NULL, (float)count);
	if (r < 0) {
		return r;
	}
	return senml_encode_cbor(&pack, buf, buflen);
}

static int deaddrop_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	if (!coap_oscore_is_protected(request)) {
		return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
	}
	struct oscore_ctx *ctx = NULL;
	uint8_t peer_eui64[8];
	if (addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
		if (net_ipv6_is_ll_addr(&in6->sin6_addr)) {
			uint8_t extracted_iid[8];
			memcpy(extracted_iid, &in6->sin6_addr.s6_addr[8], 8);
			lichen_eui64_to_iid(extracted_iid, peer_eui64);
		} else {
			return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
		}
	} else {
		return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
	}
	int ret = oscore_ctx_get_by_eui64(peer_eui64, &ctx);
	if (ret != OSCORE_OK || !ctx) {
		return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
	}
	uint8_t original_code;
	uint8_t options[64];
	size_t options_len = sizeof(options);
	uint8_t plain[128];
	size_t plain_len = sizeof(plain);
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = OSCORE_PIV_MAX_LEN;
	ret = coap_oscore_unprotect_request(ctx, request, &original_code, options, &options_len, plain, &plain_len, piv, &piv_len);
	if (ret != OSCORE_OK) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0, ctx, piv, piv_len);
	}
	if (original_code != COAP_METHOD_POST) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0, NULL, NULL, 0);
	}
	uint8_t dest[8] = {0};
	ZCBOR_STATE_D(zsd, 4, plain, plain_len, 1, 0);
	if (!zcbor_map_start_decode(zsd)) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0, NULL, NULL, 0);
	}
	bool found = false;
	while (!zcbor_array_at_end(zsd)) {
		struct zcbor_string key;
		if (!zcbor_tstr_decode(zsd, &key)) {
			break;
		}
		if (key.len == 9 && memcmp(key.value, "recipient", 9) == 0) {
			struct zcbor_string val;
			if (zcbor_bstr_decode(zsd, &val) && val.len == 8) {
				memcpy(dest, val.value, 8);
				found = true;
				break;
			}
		}
		if (!zcbor_any_skip(zsd, NULL)) {
			break;
		}
	}
	(void)zcbor_map_end_decode(zsd);
	if (!found) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0, NULL, NULL, 0);
	}
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	uint32_t now_unix = k_uptime_get_32() / 1000;
	uint32_t now_ms = k_uptime_get_32();
	uint32_t expiry_unix = now_unix + LICHEN_DTN_DEFAULT_TTL_SEC;
	lichen_dtn_expire_old(&s_dtn_buf, now_unix);
	if (!lichen_dtn_buffer_message(&s_dtn_buf, plain, plain_len, dest, expiry_unix, now_unix, now_ms)) {
		k_mutex_unlock(&s_dtn_mutex);
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, NULL, 0, NULL, NULL, 0);
	}
	k_mutex_unlock(&s_dtn_mutex);
	return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CREATED, NULL, 0, ctx, piv, piv_len);
}
static bool confession_rate_limit_pass_locked(uint8_t iid7, uint64_t now)
{
	if (s_last_confessions[iid7] &&
	    now - s_last_confessions[iid7] < (uint64_t)CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS) {
		return false;
	}
	s_last_confessions[iid7] = now;
	return true;
}

static int confessions_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len)
{
	uint64_t now = k_uptime_get();
	uint8_t iid7 = 0;
	if (addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
		if (net_ipv6_is_ll_addr(&in6->sin6_addr)) {
			iid7 = in6->sin6_addr.s6_addr[15];
		}
	}
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	bool passed = confession_rate_limit_pass_locked(iid7, now);
	k_mutex_unlock(&s_dtn_mutex);
	if (!passed) {
		LOG_WRN("confessions rate limited");
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_TOO_MANY_REQUESTS, NULL, 0, NULL, NULL, 0);
	}
	return deaddrop_post(resource, request, addr, addr_len);
}
static int deaddrop_get(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len)
{
	char base_name[BASE_NAME_MAX];
	uint8_t senml[DEADDROP_SENML_MAX];
	build_base_name(base_name, sizeof(base_name));
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	int r = senml_encode_dtn_count(base_name[0] != '\0' ? base_name : NULL,
				       lichen_dtn_len(&s_dtn_buf), senml,
				       sizeof(senml));
	k_mutex_unlock(&s_dtn_mutex);
	if (r < 0) {
		LOG_ERR("senml_encode_dtn_count failed: %d", r);
		return lichen_coap_senml_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}
	return lichen_coap_senml_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, senml, (size_t)r);
}
static const char *const deaddrop_path[] = { "deaddrop", NULL };
COAP_RESOURCE_DEFINE(lichen_deaddrop, lichen_coap, {
	.get = deaddrop_get,
	.post = deaddrop_post,
	.path = deaddrop_path,
});
static const char *const confessions_path[] = { "confessions", NULL };
COAP_RESOURCE_DEFINE(lichen_confessions, lichen_coap, {
	.post = confessions_post,
	.path = confessions_path,
});

int lichen_coap_deaddrop_register(void)
{
	lichen_dtn_init(&s_dtn_buf);
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	memset(s_last_confessions, 0, sizeof(s_last_confessions));
	k_mutex_unlock(&s_dtn_mutex);
	return oscore_init();
}

