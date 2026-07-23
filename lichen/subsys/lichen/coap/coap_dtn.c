/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zcbor_decode.h>
#include <zephyr/net/net_ip.h>
#include <lichen/coap_server.h>
#include <lichen/coap_client.h>
#include <lichen/coap_dtn.h>
#include <lichen/oscore.h>
#include <lichen/coap_oscore.h>
#include <lichen/routing/dtn.h>
#include <lichen/senml.h>

LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DEADDROP_LOG_LEVEL);

static const struct lichen_deaddrop_provider *s_provider;
static struct lichen_dtn_buffer s_dtn_buf;
static K_MUTEX_DEFINE(s_dtn_buf_mutex);
static struct k_work_delayable s_dtn_expire_work;
static uint32_t s_last_deaddrop[256] = {0};
static uint32_t s_last_confession[256] = {0};
static K_MUTEX_DEFINE(s_rate_mutex);

static bool parse_recipient(const uint8_t *payload, size_t len, uint8_t dest_iid[8]) {
	if (!payload || len == 0) return false;
	ZCBOR_STATE_D(zsd, 8, payload, len, 1, 0);
	if (!zcbor_map_start_decode(zsd)) return false;
	while (!zcbor_map_end_decode(zsd)) {
		struct zcbor_string key;
		if (zcbor_tstr_decode(zsd, &key, 1) && key.len == 1 && key.value[0] == 'r') {
			struct zcbor_string val;
			if (zcbor_bstr_decode(zsd, &val) && val.len >= 8) {
				memcpy(dest_iid, val.value, 8);
				return true;
			}
		} else if (!zcbor_any_skip(zsd, NULL)) break;
	}
	zcbor_map_end_force_decode(zsd);
	return false;
}

static uint32_t dtn_get_unix_time(void) { return (uint32_t)(k_uptime_get() / 1000); }

static void dtn_expire_work_handler(struct k_work *work) { ARG_UNUSED(work); k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER); lichen_dtn_expire_old(&s_dtn_buf, dtn_get_unix_time()); k_mutex_unlock(&s_dtn_buf_mutex); k_work_reschedule(&s_dtn_expire_work, K_SECONDS(30)); }

int lichen_coap_deaddrop_register(const struct lichen_deaddrop_provider *provider) {
	if (provider == NULL) return -EINVAL;
	int r = lichen_coap_dtn_init();
	if (r < 0) return r;
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	s_provider = provider;
	r = lichen_dtn_init(&s_dtn_buf);
	if (r < 0) {
		k_mutex_unlock(&s_dtn_buf_mutex);
		return r;
	}
	k_work_init_delayable(&s_dtn_expire_work, dtn_expire_work_handler);
	lichen_dtn_expire_old(&s_dtn_buf, dtn_get_unix_time());
	k_work_schedule(&s_dtn_expire_work, K_SECONDS(30));
	k_mutex_unlock(&s_dtn_buf_mutex);
	return 0;
}

static int deaddrop_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	if (s_provider == NULL || s_provider->store == NULL) return COAP_RESPONSE_CODE_NOT_FOUND;
	if (addr == NULL || addr_len < sizeof(struct sockaddr_in6)) return COAP_RESPONSE_CODE_BAD_REQUEST;
	const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
	uint8_t peer_eui64[OSCORE_EUI64_LEN];
	memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], OSCORE_EUI64_LEN);
	struct oscore_ctx *ctx = NULL;
	int r = oscore_ctx_get_by_eui64(peer_eui64, &ctx);
	if (r != OSCORE_OK || ctx == NULL) return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
	uint8_t rate_idx = peer_eui64[7];
	uint32_t now_ms = k_uptime_get_32();
	k_mutex_lock(&s_rate_mutex, K_FOREVER);
	if (s_last_deaddrop[rate_idx] && (now_ms - s_last_deaddrop[rate_idx] < CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS)) {
		k_mutex_unlock(&s_rate_mutex);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_TOO_MANY_REQUESTS, 0, NULL, 0);
	}
	s_last_deaddrop[rate_idx] = now_ms;
	k_mutex_unlock(&s_rate_mutex);
	uint8_t original_code;
	uint8_t options[64];
	size_t options_len = sizeof(options);
	uint8_t plaintext[256];
	size_t plaintext_len = sizeof(plaintext);
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = sizeof(piv);
	const uint8_t *payload = NULL;
	uint16_t payload_len = 0;
	if (coap_oscore_is_protected(request)) {
		r = coap_oscore_unprotect_request(ctx, request, &original_code, options, &options_len, plaintext, &plaintext_len, piv, &piv_len);
		if (r != OSCORE_OK) return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
		payload = plaintext;
		payload_len = (uint16_t)plaintext_len;
	} else {
		payload = coap_packet_get_payload(request, &payload_len);
		if (!payload || payload_len == 0) return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	uint8_t dest_iid[8] = {0};
	if (!parse_recipient(payload, payload_len, dest_iid)) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	if (s_provider && s_provider->store) {
		r = s_provider->store(payload, payload_len);
		if (r < 0) {
			k_mutex_unlock(&s_dtn_buf_mutex);
			return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
		}
	}
	uint32_t now = dtn_get_unix_time();
	uint32_t expiry = now + LICHEN_DTN_DEFAULT_TTL_SEC;
	bool ok = lichen_dtn_buffer_message(&s_dtn_buf, payload, payload_len, dest_iid, expiry, now, now_ms);
	k_mutex_unlock(&s_dtn_buf_mutex);
	uint8_t resp_code = ok ? COAP_RESPONSE_CODE_CHANGED : COAP_RESPONSE_CODE_BAD_REQUEST;
	if (coap_oscore_is_protected(request)) {
		uint8_t resp_buf[64];
		struct coap_packet resp;
		int pr = coap_oscore_protect_response(ctx, piv, piv_len, request,
						      resp_code, NULL, 0,
						      &resp, resp_buf, sizeof(resp_buf));
		if (pr != 0) {
			LOG_ERR("OSCORE protect_response failed: %d", pr);
			return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
		}
		return coap_resource_send(resource, &resp, addr, addr_len, NULL);
	}
	return lichen_coap_respond(resource, request, addr, addr_len, resp_code, 0, NULL, 0);
}

static int deaddrop_get(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	if (s_provider == NULL || s_provider->retrieve == NULL) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	uint8_t buf[256];
	uint16_t pending = lichen_dtn_pending_count(&s_dtn_buf);
	int len = senml_encode_deaddrop(NULL, dtn_get_unix_time(), pending, buf, sizeof(buf));
	k_mutex_unlock(&s_dtn_buf_mutex);
	if (len < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}
	return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CONTENT, 112, buf, (size_t)len);
}

static int confessions_get(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	uint8_t buf[64];
	struct senml_pack pack;
	senml_pack_init(&pack, NULL, dtn_get_unix_time());
	senml_add_float(&pack, SENML_KEY_CONFESSIONS, NULL, 0.0f);
	int len = senml_encode_cbor(&pack, buf, sizeof(buf));
	if (len < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}
	return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CONTENT, 112, buf, (size_t)len);
}

static int confessions_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	if (addr == NULL || addr_len < sizeof(struct sockaddr_in6)) return COAP_RESPONSE_CODE_BAD_REQUEST;
	const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
	uint8_t peer_eui64[OSCORE_EUI64_LEN];
	memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], OSCORE_EUI64_LEN);
	struct oscore_ctx *ctx = NULL;
	int r = oscore_ctx_get_by_eui64(peer_eui64, &ctx);
	if (r != OSCORE_OK || ctx == NULL) return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
	uint8_t rate_idx = peer_eui64[7];
	uint32_t now_ms = k_uptime_get_32();
	k_mutex_lock(&s_rate_mutex, K_FOREVER);
	if (s_last_confession[rate_idx] && (now_ms - s_last_confession[rate_idx] < CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS)) {
		k_mutex_unlock(&s_rate_mutex);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_TOO_MANY_REQUESTS, 0, NULL, 0);
	}
	s_last_confession[rate_idx] = now_ms;
	k_mutex_unlock(&s_rate_mutex);
	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CHANGED, 0, NULL, 0);
}

int lichen_coap_dtn_init(void) {
	int r = oscore_init();
	if (r < 0) return r;
	r = lichen_coap_client_init();
	if (r < 0) return r;
	return 0;
}

uint16_t lichen_dtn_expire_periodic(void) {
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	uint16_t expired = lichen_dtn_expire_old(&s_dtn_buf, dtn_get_unix_time());
	k_mutex_unlock(&s_dtn_buf_mutex);
	return expired;
}

static const char * const deaddrop_path[] = { "deaddrop", NULL };
COAP_RESOURCE_DEFINE(lichen_deaddrop, lichen_coap_server, {
	.get = deaddrop_get,
	.post = deaddrop_post,
	.path = deaddrop_path,
});

static const char * const confessions_path[] = { "confessions", NULL };
COAP_RESOURCE_DEFINE(lichen_confessions, lichen_coap_server, {
	.get = confessions_get,
	.post = confessions_post,
	.path = confessions_path,
});
