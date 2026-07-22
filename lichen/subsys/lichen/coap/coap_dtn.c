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
#include <zcbor_decode.h>
#include <zephyr/net/net_ip.h>

LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DEADDROP_LOG_LEVEL);

static const struct lichen_deaddrop_provider *s_provider;
static struct lichen_dtn_buffer s_dtn_buf;
static struct senml_pack s_senml_pack;
static K_MUTEX_DEFINE(s_dtn_buf_mutex);
static K_MUTEX_DEFINE(s_senml_pack_mutex);
static struct k_work_delayable s_dtn_expire_work;
static uint32_t s_last_deaddrop[16] = {0};



static uint32_t dtn_get_unix_time(void) { return (uint32_t)(k_uptime_get() / 1000); }
static void dtn_expire_work_handler(struct k_work *work) { ARG_UNUSED(work); k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER); lichen_dtn_expire_old(&s_dtn_buf, dtn_get_unix_time()); k_mutex_unlock(&s_dtn_buf_mutex); k_work_reschedule(&s_dtn_expire_work, K_SECONDS(30)); }
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
	k_work_init_delayable(&s_dtn_expire_work, dtn_expire_work_handler);
	lichen_dtn_expire_old(&s_dtn_buf, dtn_get_unix_time());
	k_work_schedule(&s_dtn_expire_work, K_SECONDS(30));
	return 0;
}

static int deaddrop_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	if (s_provider == NULL || s_provider->store == NULL) return 0x84;
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	uint32_t now = k_uptime_get();
	uint8_t idx = 0;
	if (addr_len >= sizeof(struct sockaddr_in6)) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
		idx = in6->sin6_addr.s6_addr[15];
	}
	if (now - s_last_deaddrop[idx] < CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS) {
		k_mutex_unlock(&s_dtn_buf_mutex);
		return 0xA3;
	}
	s_last_deaddrop[idx] = now;
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) { k_mutex_unlock(&s_dtn_buf_mutex); return 0x80; }
	uint8_t recipient[16]; size_t rlen = 0; zcbor_state_t zs[2] = {0}; if (zcbor_new_decode_state(zs, 2, payload, payload_len, 1) && zcbor_map_start_decode(zs) && zcbor_tstr_expect(zs, "recipient") && zcbor_bstr_decode(zs, recipient, &rlen)) {} 
	int r = s_provider->store(payload, payload_len);
	k_mutex_unlock(&s_dtn_buf_mutex);
	if (r < 0) return 0xA0;
	return 0x41;
}

static int deaddrop_get(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len) {
	if (s_provider == NULL || s_provider->retrieve == NULL) return 0x84;
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	int len = s_provider->retrieve(buf, sizeof(buf), NULL);
	k_mutex_unlock(&s_dtn_buf_mutex);
	if (len < 0) return 0xA0;
	return lichen_coap_respond(resource, request, addr, addr_len, 0x45, buf, len);
}

static const char * const deaddrop_path[] = { "deaddrop", NULL };
COAP_RESOURCE_DEFINE(lichen_deaddrop, lichen_coap_server, {
	.get = deaddrop_get,
	.post = deaddrop_post,
	.path = deaddrop_path,
});
