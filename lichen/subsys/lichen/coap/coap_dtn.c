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
#include <lichen/coap_oscore.h>
#include <lichen/oscore.h>
#include <lichen/senml.h>
#include <lichen/l2/ipv6_addr.h>

LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DTN_LOG_LEVEL);

/* Max payload to store in the deaddrop ring buffer. Matches plain[512]
 * in deaddrop_post — OSCORE-decrypted CoAP payloads fit comfortably. */
#define DEADDROP_MAX_PAYLOAD 512

/* Default TTL for deaddrop entries (24 hours) */
#define DEADDROP_DEFAULT_TTL_SEC (24u * 60u * 60u)

struct deaddrop_entry {
	uint8_t payload[DEADDROP_MAX_PAYLOAD];
	uint16_t payload_len;
	uint8_t dest_iid[8];
	uint32_t expiry_unix;
	uint32_t buffered_at_ms;
	bool valid;
};

static struct deaddrop_entry
	s_entries[CONFIG_LICHEN_COAP_DEADDROP_MAX_STORAGE];
static const struct lichen_deaddrop_provider *s_provider;
static K_MUTEX_DEFINE(s_provider_mutex);
static struct k_mutex s_buf_mutex;
static struct k_work_delayable s_expire_work;
#define IID_RATE_SLOTS 8

struct iid_rate_slot {
	uint8_t iid[8];
	uint32_t last_ms;
	bool valid;
};

static struct iid_rate_slot s_last_deaddrop[IID_RATE_SLOTS] = {{{0}}};
static struct iid_rate_slot s_last_confession[IID_RATE_SLOTS] = {{{0}}};
static struct k_mutex s_rate_mutex;

static struct iid_rate_slot *iid_rate_lookup(struct iid_rate_slot *slots,
					     const uint8_t iid[8])
{
	int oldest = -1;
	uint32_t oldest_ms = UINT32_MAX;

	for (int i = 0; i < IID_RATE_SLOTS; i++) {
		if (slots[i].valid &&
		    memcmp(slots[i].iid, iid, 8) == 0) {
			return &slots[i];
		}
		if (!slots[i].valid) {
			oldest = i;
			break;
		}
		if (slots[i].last_ms < oldest_ms) {
			oldest_ms = slots[i].last_ms;
			oldest = i;
		}
	}
	memcpy(slots[oldest].iid, iid, 8);
	slots[oldest].valid = true;
	return &slots[oldest];
}

static const struct lichen_deaddrop_provider *
deaddrop_provider_get(void)
{
	k_mutex_lock(&s_provider_mutex, K_FOREVER);
	const struct lichen_deaddrop_provider *p = s_provider;
	k_mutex_unlock(&s_provider_mutex);
	return p;
}

static bool parse_recipient(const uint8_t *payload, size_t len,
			    uint8_t dest_iid[8])
{
	if (!payload || len == 0) return false;
	ZCBOR_STATE_D(zsd, 8, payload, len, 1, 0);
	if (!zcbor_map_start_decode(zsd)) return false;
	while (!zcbor_map_end_decode(zsd)) {
		struct zcbor_string key;
		if (zcbor_tstr_decode(zsd, &key, 1) && key.len == 1 &&
		    key.value[0] == 'r') {
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

static uint32_t deaddrop_unix_time(void)
{
	return (uint32_t)(k_uptime_get() / 1000);
}

/* -- internal ring buffer helpers (default backend) -- */

static int find_free_slot(void)
{
	for (int i = 0; i < CONFIG_LICHEN_COAP_DEADDROP_MAX_STORAGE; i++) {
		if (!s_entries[i].valid) {
			return i;
		}
	}
	return -1;
}

static int find_oldest(void)
{
	int oldest = -1;
	for (int i = 0; i < CONFIG_LICHEN_COAP_DEADDROP_MAX_STORAGE; i++) {
		if (!s_entries[i].valid) {
			continue;
		}
		if (oldest < 0) {
			oldest = i;
			continue;
		}
		int32_t diff = (int32_t)(s_entries[i].buffered_at_ms -
					 s_entries[oldest].buffered_at_ms);
		if (diff < 0) {
			oldest = i;
		}
	}
	return oldest;
}

static int internal_store(const uint8_t *payload, size_t len)
{
	if (payload == NULL || len == 0 || len > DEADDROP_MAX_PAYLOAD) {
		return -EINVAL;
	}
	/* Evict oldest if full */
	int slot = find_free_slot();
	if (slot < 0) {
		slot = find_oldest();
		if (slot < 0) {
			return -ENOBUFS;
		}
		s_entries[slot].valid = false;
		slot = find_free_slot();
		if (slot < 0) return -ENOBUFS;
	}
	s_entries[slot].payload_len = (uint16_t)len;
	memcpy(s_entries[slot].payload, payload, len);
	memset(s_entries[slot].dest_iid, 0, 8);
	s_entries[slot].expiry_unix = deaddrop_unix_time() + DEADDROP_DEFAULT_TTL_SEC;
	s_entries[slot].buffered_at_ms = k_uptime_get_32();
	s_entries[slot].valid = true;
	return 0;
}

static int internal_retrieve(uint8_t *buf, size_t buf_len, const char *node)
{
	if (buf == NULL || buf_len == 0) {
		return -EINVAL;
	}
	uint32_t now = deaddrop_unix_time();
	/* Find newest valid, non-expired entry — first-come-first-serve
	 * per recipient.  If node is non-NULL, match against stored
	 * dest_iid; otherwise return any entry (admin dump). */
	int best = -1;
	uint32_t best_time = 0;
	for (int i = 0; i < CONFIG_LICHEN_COAP_DEADDROP_MAX_STORAGE; i++) {
		if (!s_entries[i].valid ||
		    s_entries[i].expiry_unix <= now) {
			continue;
		}
		/* If node specifies an IID, only match that */
		if (node != NULL) {
			/* parse hex IID from query string ... for now
			 * return the first match. Full IID matching is
			 * provided by external providers if needed. */
		}
		if (s_entries[i].buffered_at_ms > best_time) {
			best_time = s_entries[i].buffered_at_ms;
			best = i;
		}
	}
	if (best < 0) {
		return -ENOENT;
	}
	size_t copy_len = s_entries[best].payload_len;
	if (copy_len > buf_len) copy_len = buf_len;
	memcpy(buf, s_entries[best].payload, copy_len);
	s_entries[best].valid = false;
	return (int)copy_len;
}

static void expire_old(void)
{
	uint32_t now = deaddrop_unix_time();
	for (int i = 0; i < CONFIG_LICHEN_COAP_DEADDROP_MAX_STORAGE; i++) {
		if (s_entries[i].valid &&
		    s_entries[i].expiry_unix <= now) {
			s_entries[i].valid = false;
		}
	}
}

static void expire_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	k_mutex_lock(&s_buf_mutex, K_FOREVER);
	expire_old();
	k_mutex_unlock(&s_buf_mutex);
	k_work_reschedule(&s_expire_work, K_SECONDS(30));
}

int lichen_coap_deaddrop_register(
	const struct lichen_deaddrop_provider *provider)
{
	if (provider == NULL) return -EINVAL;
	int r = lichen_coap_dtn_init();
	if (r < 0) return r;
	k_mutex_lock(&s_provider_mutex, K_FOREVER);
	s_provider = provider;
	k_mutex_unlock(&s_provider_mutex);
	k_work_init_delayable(&s_expire_work, expire_work_handler);
	expire_old();
	k_work_schedule(&s_expire_work, K_SECONDS(30));
	return 0;
}

static int deaddrop_oscore_respond(struct coap_resource *resource,
				   struct coap_packet *request,
				   struct sockaddr *addr, socklen_t addr_len,
				   struct oscore_ctx *ctx, const uint8_t *piv,
				   size_t piv_len, uint8_t code)
{
	uint8_t buf[256];
	struct coap_packet resp;
	int ret = coap_oscore_protect_response(ctx, piv, piv_len, request,
					       code, NULL, 0, &resp, buf,
					       sizeof(buf));
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL,
				    0);
	}
	ret = coap_resource_send(resource, &resp, addr, addr_len, NULL);
	return ret;
}

static int deaddrop_post(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t peer_eui64[8] = {0};
	if (addr_len >= sizeof(struct sockaddr_in6) &&
	    addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)addr;
		memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
		lichen_eui64_to_iid(peer_eui64, peer_eui64);
	}
	const uint8_t *payload;
	uint16_t payload_len = 0;
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	struct oscore_ctx *ctx = NULL;
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = 0;
	bool is_protected = coap_oscore_is_protected(request);
	uint8_t plain[512];
	size_t plain_len = 0;
	if (is_protected) {
		if (oscore_ctx_get_by_eui64(peer_eui64, &ctx) != OSCORE_OK ||
		    ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request,
							     addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		plain_len = sizeof(plain);
		int r = coap_oscore_unprotect_request(ctx, request, &orig_code,
						      opts, &opt_len, plain,
						      &plain_len, piv,
						      &piv_len);
		if (r != OSCORE_OK) return COAP_RESPONSE_CODE_UNAUTHORIZED;
		if (orig_code != COAP_METHOD_POST) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
		payload = plain;
		payload_len = (uint16_t)plain_len;
	} else {
#endif
		if (!lichen_coap_is_local_admin(addr, addr_len)) {
			return lichen_coap_respond(resource, request, addr,
						   addr_len,
						   COAP_RESPONSE_CODE_UNAUTHORIZED,
						   0, NULL, 0);
		}
		payload = coap_packet_get_payload(request, &payload_len);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	}
#endif
	if (!payload || payload_len == 0) return COAP_RESPONSE_CODE_BAD_REQUEST;
	uint32_t now_ms = k_uptime_get_32();
	k_mutex_lock(&s_rate_mutex, K_FOREVER);
	struct iid_rate_slot *slot = iid_rate_lookup(s_last_deaddrop,
						     peer_eui64);
	if (slot->valid && slot->last_ms &&
	    (now_ms - slot->last_ms <
	     CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS)) {
		k_mutex_unlock(&s_rate_mutex);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL) {
			return deaddrop_oscore_respond(resource, request, addr,
						       addr_len, ctx, piv,
						       piv_len,
						       COAP_RESPONSE_CODE_TOO_MANY_REQUESTS);
		}
#endif
		return COAP_RESPONSE_CODE_TOO_MANY_REQUESTS;
	}
	slot->last_ms = now_ms;
	k_mutex_unlock(&s_rate_mutex);
	k_mutex_lock(&s_buf_mutex, K_FOREVER);
	const struct lichen_deaddrop_provider *p = deaddrop_provider_get();
	int r;
	if (p != NULL && p->store != NULL) {
		r = p->store(payload, payload_len);
	} else {
		r = internal_store(payload, payload_len);
	}
	k_mutex_unlock(&s_buf_mutex);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (r < 0 && is_protected && ctx != NULL) {
		return deaddrop_oscore_respond(resource, request, addr,
					       addr_len, ctx, piv,
					       piv_len,
					       COAP_RESPONSE_CODE_INTERNAL_ERROR);
	}
#endif
	if (r < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0);
	}
	uint8_t resp_code = COAP_RESPONSE_CODE_CHANGED;
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && ctx != NULL) {
		return deaddrop_oscore_respond(resource, request, addr,
					       addr_len, ctx, piv, piv_len,
					       resp_code);
	}
#endif
	return lichen_coap_respond(resource, request, addr, addr_len,
				   resp_code, 0, NULL, 0);
}

static int deaddrop_get(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	const char *node = NULL;
	struct coap_option qopts[4];
	int qcnt = coap_find_options(request, COAP_OPTION_URI_QUERY, qopts, 4);
	for (int i = 0; i < qcnt; i++) {
		if (qopts[i].len > 5 &&
		    memcmp(qopts[i].value, "node=", 5) == 0) {
			node = (const char *)qopts[i].value + 5;
			break;
		}
	}
	k_mutex_lock(&s_buf_mutex, K_FOREVER);
	const struct lichen_deaddrop_provider *p = deaddrop_provider_get();
	uint8_t buf[256];
	int len;
	if (p != NULL && p->retrieve != NULL) {
		len = p->retrieve(buf, sizeof(buf), node);
	} else {
		len = internal_retrieve(buf, sizeof(buf), node);
	}
	k_mutex_unlock(&s_buf_mutex);
	if (len < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL,
				    0);
	}
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT,
			    SENML_CBOR_CONTENT_FORMAT, buf, (size_t)len);
}

static int confessions_get(struct coap_resource *resource,
			   struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t buf[64];
	struct senml_pack pack;
	senml_pack_init(&pack, NULL, deaddrop_unix_time());
	senml_add_float(&pack, SENML_KEY_CONFESSIONS, NULL, 0.0f);
	int len = senml_encode_cbor(&pack, buf, sizeof(buf));
	if (len < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL,
				    0);
	}
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT,
			    SENML_CBOR_CONTENT_FORMAT, buf, (size_t)len);
}

static int confessions_post(struct coap_resource *resource,
			    struct coap_packet *request,
			    struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t peer_eui64[8] = {0};
	if (addr_len >= sizeof(struct sockaddr_in6) &&
	    addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)addr;
		memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
		lichen_eui64_to_iid(peer_eui64, peer_eui64);
	}
	const uint8_t *payload;
	uint16_t payload_len = 0;
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	struct oscore_ctx *ctx = NULL;
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = 0;
	bool is_protected = coap_oscore_is_protected(request);
	uint8_t plain[64];
	size_t plain_len = 0;
	if (is_protected) {
		if (oscore_ctx_get_by_eui64(peer_eui64, &ctx) != OSCORE_OK ||
		    ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request,
							     addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		plain_len = sizeof(plain);
		int r = coap_oscore_unprotect_request(ctx, request, &orig_code,
						      opts, &opt_len, plain,
						      &plain_len, piv,
						      &piv_len);
		if (r != OSCORE_OK) return COAP_RESPONSE_CODE_UNAUTHORIZED;
		if (orig_code != COAP_METHOD_POST) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
		payload = plain;
		payload_len = (uint16_t)plain_len;
	} else {
		if (!lichen_coap_is_local_admin(addr, addr_len)) {
			return lichen_coap_respond(resource, request, addr,
						   addr_len,
						   COAP_RESPONSE_CODE_UNAUTHORIZED,
						   0, NULL, 0);
		}
		payload = coap_packet_get_payload(request, &payload_len);
	}
#else
	payload = coap_packet_get_payload(request, &payload_len);
#endif
	if (!payload || payload_len == 0) return COAP_RESPONSE_CODE_BAD_REQUEST;
	uint32_t now_ms = k_uptime_get_32();
	k_mutex_lock(&s_rate_mutex, K_FOREVER);
	struct iid_rate_slot *slot = iid_rate_lookup(s_last_confession,
						     peer_eui64);
	if (slot->valid && slot->last_ms &&
	    (now_ms - slot->last_ms <
	     CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS)) {
		k_mutex_unlock(&s_rate_mutex);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL) {
			return deaddrop_oscore_respond(resource, request, addr,
						       addr_len, ctx, piv,
						       piv_len,
						       COAP_RESPONSE_CODE_TOO_MANY_REQUESTS);
		}
#endif
		return COAP_RESPONSE_CODE_TOO_MANY_REQUESTS;
	}
	slot->last_ms = now_ms;
	k_mutex_unlock(&s_rate_mutex);
	uint8_t resp_code = COAP_RESPONSE_CODE_CHANGED;
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && ctx != NULL) {
		return deaddrop_oscore_respond(resource, request, addr,
					       addr_len, ctx, piv, piv_len,
					       resp_code);
	}
#endif
	return lichen_coap_respond(resource, request, addr, addr_len,
				   resp_code, 0, NULL, 0);
}

int lichen_coap_dtn_init(void)
{
	int r = oscore_init();
	if (r < 0) return r;
	r = lichen_coap_client_init();
	if (r < 0) return r;
	memset(s_entries, 0, sizeof(s_entries));
	k_mutex_init(&s_buf_mutex);
	k_mutex_init(&s_rate_mutex);
	return 0;
}

uint16_t lichen_dtn_expire_periodic(void)
{
	k_mutex_lock(&s_buf_mutex, K_FOREVER);
	uint16_t before = 0;
	for (int i = 0; i < CONFIG_LICHEN_COAP_DEADDROP_MAX_STORAGE; i++) {
		if (s_entries[i].valid) before++;
	}
	expire_old();
	uint16_t after = 0;
	for (int i = 0; i < CONFIG_LICHEN_COAP_DEADDROP_MAX_STORAGE; i++) {
		if (s_entries[i].valid) after++;
	}
	k_mutex_unlock(&s_buf_mutex);
	return before - after;
}

static const char *const deaddrop_path[] = { "deaddrop", NULL };
COAP_RESOURCE_DEFINE(lichen_deaddrop, lichen_coap_server, {
	.get = deaddrop_get,
	.post = deaddrop_post,
	.path = deaddrop_path,
});

static const char *const confessions_path[] = { "confessions", NULL };
COAP_RESOURCE_DEFINE(lichen_confessions, lichen_coap_server, {
	.get = confessions_get,
	.post = confessions_post,
	.path = confessions_path,
});
