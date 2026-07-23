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
<<<<<<< HEAD
=======
#include <zcbor_decode.h>
>>>>>>> origin/integration/worker2-20260722
#include <zephyr/net/net_ip.h>

LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DEADDROP_LOG_LEVEL);

<<<<<<< HEAD
static const struct lichen_deaddrop_provider *s_provider;
static struct lichen_dtn_buffer s_dtn_buf;
static K_MUTEX_DEFINE(s_dtn_buf_mutex);
static struct k_work_delayable s_dtn_expire_work;
static uint32_t s_last_deaddrop[16] = {0};

static uint32_t dtn_get_unix_time(void) { return (uint32_t)(k_uptime_get() / 1000); }

static void dtn_expire_work_handler(struct k_work *work) { ARG_UNUSED(work); k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER); lichen_dtn_expire_old(&s_dtn_buf, dtn_get_unix_time()); k_mutex_unlock(&s_dtn_buf_mutex); k_work_reschedule(&s_dtn_expire_work, K_SECONDS(30)); }

int lichen_coap_deaddrop_register(const struct lichen_deaddrop_provider *provider) {
	if (provider == NULL) return -EINVAL;
=======
static struct lichen_dtn_buffer s_dtn_buf;
static struct senml_pack s_senml_pack;
static K_MUTEX_DEFINE(s_dtn_mutex);
static struct k_work_delayable s_dtn_expire_work;
static uint32_t s_last_deaddrop[256];
static uint32_t s_last_confession[256];

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

static void dtn_expire_work_handler(struct k_work *work) {
	ARG_UNUSED(work);
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	lichen_dtn_expire_old(&s_dtn_buf, dtn_get_unix_time());
	k_mutex_unlock(&s_dtn_mutex);
	k_work_reschedule(&s_dtn_expire_work, K_SECONDS(30));
}

int lichen_coap_deaddrop_register(void) {
>>>>>>> origin/integration/worker2-20260722
	int r = oscore_init();
	if (r < 0) return r;
	r = lichen_coap_client_init();
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

<<<<<<< HEAD
static int deaddrop_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	if (s_provider == NULL || s_provider->store == NULL) return COAP_RESPONSE_CODE_NOT_FOUND;
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	uint32_t now = k_uptime_get();
	uint8_t idx = 0;
	if (addr_len >= sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
		idx = in6->sin6_addr.s6_addr[15];
	}
	if (now - s_last_deaddrop[idx] < CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS) {
		k_mutex_unlock(&s_dtn_buf_mutex);
		return COAP_RESPONSE_CODE_TOO_MANY_REQUESTS;
	}
	s_last_deaddrop[idx] = now;
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) { k_mutex_unlock(&s_dtn_buf_mutex); return COAP_RESPONSE_CODE_BAD_REQUEST; }
	int r = s_provider->store(payload, payload_len);
	k_mutex_unlock(&s_dtn_buf_mutex);
	if (r < 0) return COAP_RESPONSE_CODE_INTERNAL_ERROR;
=======
int lichen_coap_dtn_init(void) {
	return lichen_coap_deaddrop_register();
}

static int get_rate_idx(struct sockaddr *addr, socklen_t addr_len) {
	if (addr_len >= sizeof(struct sockaddr_in6) && addr && addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
		return in6->sin6_addr.s6_addr[15];
	}
	return 0;
}

static int deaddrop_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	uint8_t dest_iid[8] = {0};
	if (payload && payload_len > 0) {
		parse_recipient(payload, payload_len, dest_iid);
	}
	uint32_t now = dtn_get_unix_time();
	int idx = get_rate_idx(addr, addr_len);
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	if (now - s_last_deaddrop[idx] < 5) {
		k_mutex_unlock(&s_dtn_mutex);
		return COAP_RESPONSE_CODE_TOO_MANY_REQUESTS;
	}
	s_last_deaddrop[idx] = now;
	uint32_t expiry = now + LICHEN_DTN_DEFAULT_TTL_SEC;
	bool ok = lichen_dtn_buffer_message(&s_dtn_buf, payload, payload_len, dest_iid, expiry, now, k_uptime_get_32());
	k_mutex_unlock(&s_dtn_mutex);
	if (!ok) return COAP_RESPONSE_CODE_BAD_REQUEST;
>>>>>>> origin/integration/worker2-20260722
	return COAP_RESPONSE_CODE_CHANGED;
}

static int deaddrop_get(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	uint8_t buf[256];
	uint16_t pending = lichen_dtn_pending_count(&s_dtn_buf);
<<<<<<< HEAD
	int len = senml_encode_deaddrop(NULL, dtn_get_unix_time(), pending, buf, sizeof(buf));
	k_mutex_unlock(&s_dtn_buf_mutex);
	if (len < 0) return COAP_RESPONSE_CODE_INTERNAL_ERROR;
<<<<<<< HEAD
	return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CONTENT, 112, buf, (size_t)len);
=======
	senml_pack_init(&s_senml_pack, NULL, 0);
	senml_add_float(&s_senml_pack, SENML_KEY_CONFESSIONS, NULL, (float)pending);
	int len = senml_encode_cbor(&s_senml_pack, buf, sizeof(buf));
	k_mutex_unlock(&s_dtn_mutex);
	if (len < 0) return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CONTENT, buf, len);
}

static int confessions_get(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	uint8_t buf[64];
	senml_pack_init(&s_senml_pack, NULL, 0);
	senml_add_float(&s_senml_pack, SENML_KEY_CONFESSIONS, NULL, 0.0f);
	int len = senml_encode_cbor(&s_senml_pack, buf, sizeof(buf));
	k_mutex_unlock(&s_dtn_mutex);
	if (len < 0) return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CONTENT, buf, len);
}

static int confessions_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	uint32_t now = dtn_get_unix_time();
	int idx = get_rate_idx(addr, addr_len);
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	if (s_last_confession[idx] && now - s_last_confession[idx] < 30) {
		k_mutex_unlock(&s_dtn_mutex);
		return COAP_RESPONSE_CODE_TOO_MANY_REQUESTS;
	}
	s_last_confession[idx] = now;
	k_mutex_unlock(&s_dtn_mutex);
	return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CHANGED, NULL, 0);
>>>>>>> origin/integration/worker2-20260722
=======
	return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CONTENT, SENML_CBOR_CONTENT_FORMAT, buf, (size_t)len);
>>>>>>> origin/integration/worker14-20260722
}

static const char * const deaddrop_path[] = { "deaddrop", NULL };
COAP_RESOURCE_DEFINE(lichen_deaddrop, lichen_coap_server, {
	.get = deaddrop_get,
	.post = deaddrop_post,
	.path = deaddrop_path,
});

int lichen_coap_dtn_init(void) { return 0; }

uint16_t lichen_dtn_expire_periodic(void) {
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	uint16_t expired = lichen_dtn_expire_old(&s_dtn_buf, dtn_get_unix_time());
	k_mutex_unlock(&s_dtn_buf_mutex);
	return expired;
}
