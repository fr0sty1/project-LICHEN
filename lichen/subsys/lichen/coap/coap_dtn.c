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
#include <lichen/routing/dtn.h>
#include <lichen/senml.h>
#include <lichen/l2/ipv6_addr.h>

LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DTN_LOG_LEVEL);

#define DEADDROP_QUERY_OPTS_MAX 8

static const struct lichen_deaddrop_provider *s_provider;
static K_MUTEX_DEFINE(s_provider_mutex);
static struct lichen_dtn_buffer s_dtn_buf;
static K_MUTEX_DEFINE(s_dtn_buf_mutex);
static struct k_work_delayable s_dtn_expire_work;
static uint32_t s_last_deaddrop[256] = {0};
static uint32_t s_last_confession[256] = {0};
static struct k_mutex s_rate_mutex;

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

static uint32_t dtn_get_unix_time(void)
{
	return (uint32_t)(k_uptime_get() / 1000);
}

static void dtn_expire_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	lichen_dtn_expire_old(&s_dtn_buf, dtn_get_unix_time());
	k_mutex_unlock(&s_dtn_buf_mutex);
	k_work_reschedule(&s_dtn_expire_work, K_SECONDS(30));
}

int lichen_coap_deaddrop_register(
	const struct lichen_deaddrop_provider *provider)
{
	if (provider == NULL) return -EINVAL;
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	int r = lichen_coap_dtn_init();
	if (r < 0) {
		k_mutex_unlock(&s_dtn_buf_mutex);
		return r;
	}
	k_mutex_lock(&s_provider_mutex, K_FOREVER);
	s_provider = provider;
	k_mutex_unlock(&s_provider_mutex);
	r = lichen_dtn_init(&s_dtn_buf);
	if (r < 0) {
		k_mutex_unlock(&s_dtn_buf_mutex);
		return r;
	}
	k_mutex_lock(&s_provider_mutex, K_FOREVER);
	s_provider->dtn_buf = &s_dtn_buf;
	k_mutex_unlock(&s_provider_mutex);
	k_work_init_delayable(&s_dtn_expire_work, dtn_expire_work_handler);
	lichen_dtn_expire_old(&s_dtn_buf, dtn_get_unix_time());
	k_work_schedule(&s_dtn_expire_work, K_SECONDS(30));
	k_mutex_unlock(&s_dtn_buf_mutex);
	return 0;
}

const struct lichen_deaddrop_provider *lichen_coap_deaddrop_provider_get(void)
{
	k_mutex_lock(&s_provider_mutex, K_FOREVER);
	const struct lichen_deaddrop_provider *p = s_provider;
	k_mutex_unlock(&s_provider_mutex);
	return p;
}

static int deaddrop_oscore_respond(struct coap_resource *resource,
				   struct coap_packet *request,
				   struct sockaddr *addr, socklen_t addr_len,
				   struct oscore_ctx *ctx, const uint8_t *piv,
				   size_t piv_len, uint8_t code,
				   uint16_t content_format,
				   const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[256];
	struct coap_packet resp;
	int ret = coap_oscore_protect_response(ctx, piv, piv_len, request,
					       code, payload, payload_len,
					       &resp, buf, sizeof(buf));
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   code, content_format, payload,
					   payload_len);
	}
	ret = coap_resource_send(resource, &resp, addr, addr_len, NULL);
	return ret;
}

static int deaddrop_post(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	const struct lichen_deaddrop_provider *provider = lichen_coap_deaddrop_provider_get();
	if (provider == NULL || provider->store == NULL) {
		return COAP_RESPONSE_CODE_NOT_FOUND;
	}
	uint8_t dest_iid[8] = {0};
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
	if (is_protected) {
		if (oscore_ctx_get_by_eui64(peer_eui64, &ctx) != OSCORE_OK ||
		    ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request,
							     addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		uint8_t plain[512];
		size_t plain_len = sizeof(plain);
		int r = coap_oscore_unprotect_request(ctx, request, &orig_code,
						      opts, &opt_len, plain,
						      &plain_len, piv,
						      &piv_len);
		if (r != OSCORE_OK) return COAP_RESPONSE_CODE_UNAUTHORIZED;
		if (orig_code != COAP_METHOD_POST) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
		if (plain_len > sizeof(plain)) {
			LOG_ERR("OSCORE decrypted payload %zu exceeds plain buffer %zu",
				plain_len, sizeof(plain));
			return COAP_RESPONSE_CODE_INTERNAL_ERROR;
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
	parse_recipient(payload, payload_len, dest_iid);
	uint32_t now_ms = k_uptime_get_32();
	uint8_t iid7 = peer_eui64[7];
	k_mutex_lock(&s_rate_mutex, K_FOREVER);
	if (s_last_deaddrop[iid7] &&
	    (now_ms - s_last_deaddrop[iid7] <
	     CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS)) {
		k_mutex_unlock(&s_rate_mutex);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL) {
			return deaddrop_oscore_respond(resource, request, addr,
						       addr_len, ctx, piv,
						       piv_len,
						       COAP_RESPONSE_CODE_TOO_MANY_REQUESTS,
						       0, NULL, 0);
		}
#endif
		return COAP_RESPONSE_CODE_TOO_MANY_REQUESTS;
	}
	s_last_deaddrop[iid7] = now_ms;
	k_mutex_unlock(&s_rate_mutex);
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	if (provider->store) {
		int r = provider->store(payload, payload_len);
		if (r < 0) {
			k_mutex_unlock(&s_dtn_buf_mutex);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
			if (is_protected && ctx != NULL) {
				return deaddrop_oscore_respond(resource,
							       request, addr,
							       addr_len, ctx,
							       piv, piv_len,
							       COAP_RESPONSE_CODE_INTERNAL_ERROR,
							       0, NULL, 0);
			}
#endif
			return lichen_coap_respond(resource, request, addr,
						   addr_len,
						   COAP_RESPONSE_CODE_INTERNAL_ERROR,
						   0, NULL, 0);
		}
	}
	uint32_t now = dtn_get_unix_time();
	uint32_t expiry = now + LICHEN_DTN_DEFAULT_TTL_SEC;
	bool ok = lichen_dtn_buffer_message(&s_dtn_buf, payload, payload_len,
					    dest_iid, expiry, now, now_ms);
	k_mutex_unlock(&s_dtn_buf_mutex);
	uint8_t resp_code = ok ? COAP_RESPONSE_CODE_CHANGED
			       : COAP_RESPONSE_CODE_BAD_REQUEST;
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && ctx != NULL) {
		return deaddrop_oscore_respond(resource, request, addr,
					       addr_len, ctx, piv, piv_len,
					       resp_code, 0, NULL, 0);
	}
#endif
	return lichen_coap_respond(resource, request, addr, addr_len,
				   resp_code, 0, NULL, 0);
}

static int parse_deaddrop_query(struct coap_packet *request,
				char *node, size_t node_max,
				char *type, size_t type_max,
				uint32_t *after_unix)
{
	struct coap_option qopts[DEADDROP_QUERY_OPTS_MAX];
	int qcnt = coap_find_options(request, COAP_OPTION_URI_QUERY, qopts,
				     DEADDROP_QUERY_OPTS_MAX);
	for (int i = 0; i < qcnt; i++) {
		if (qopts[i].len > 5 &&
		    memcmp(qopts[i].value, "node=", 5) == 0) {
			size_t vlen = qopts[i].len - 5;
			if (vlen < node_max) {
				memcpy(node, qopts[i].value + 5, vlen);
				node[vlen] = '\0';
			}
		} else if (qopts[i].len > 5 &&
			   memcmp(qopts[i].value, "type=", 5) == 0) {
			size_t vlen = qopts[i].len - 5;
			if (vlen < type_max) {
				memcpy(type, qopts[i].value + 5, vlen);
				type[vlen] = '\0';
			}
		} else if (qopts[i].len > 6 &&
			   memcmp(qopts[i].value, "after=", 6) == 0) {
			char buf[16];
			size_t vlen = qopts[i].len - 6;
			if (vlen < sizeof(buf)) {
				memcpy(buf, qopts[i].value + 6, vlen);
				buf[vlen] = '\0';
				char *end = NULL;
				unsigned long val = strtoul(buf, &end, 10);
				if (end != buf && val <= UINT32_MAX) {
					*after_unix = (uint32_t)val;
				}
			}
		}
	}
	return qcnt;
}

static int deaddrop_get(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	const struct lichen_deaddrop_provider *provider = lichen_coap_deaddrop_provider_get();
	if (provider == NULL || provider->retrieve == NULL) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}
	uint8_t peer_eui64[8] = {0};
	if (addr_len >= sizeof(struct sockaddr_in6) &&
	    addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)addr;
		memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
		lichen_eui64_to_iid(peer_eui64, peer_eui64);
	}
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	struct oscore_ctx *ctx = NULL;
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = 0;
	bool is_protected = coap_oscore_is_protected(request);
	if (is_protected) {
		if (oscore_ctx_get_by_eui64(peer_eui64, &ctx) != OSCORE_OK ||
		    ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request,
							     addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		uint8_t plain[64];
		size_t plain_len = sizeof(plain);
		int r = coap_oscore_unprotect_request(ctx, request, &orig_code,
						      opts, &opt_len, plain,
						      &plain_len, piv,
						      &piv_len);
		if (r != OSCORE_OK) return COAP_RESPONSE_CODE_UNAUTHORIZED;
		if (orig_code != COAP_METHOD_GET) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
	}
#endif
	char node[64] = {0};
	char type[32] = {0};
	uint32_t after_unix = 0;
	parse_deaddrop_query(request, node, sizeof(node),
			     type, sizeof(type), &after_unix);
	uint8_t raw_buf[CONFIG_LICHEN_DTN_MAX_PACKET_SIZE];
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	int raw_len = provider->retrieve(raw_buf, sizeof(raw_buf),
					   node[0] ? node : NULL);
	uint16_t pending = lichen_dtn_len(&s_dtn_buf);
	k_mutex_unlock(&s_dtn_buf_mutex);
	if (raw_len < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL) {
			return deaddrop_oscore_respond(resource, request, addr,
						       addr_len, ctx, piv,
						       piv_len,
						       COAP_RESPONSE_CODE_INTERNAL_ERROR,
						       0, NULL, 0);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL,
				    0);
	}
	if ((size_t)raw_len > sizeof(raw_buf)) {
		LOG_ERR("deaddrop retrieve returned %d > %zu bytes",
			raw_len, sizeof(raw_buf));
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL) {
			return deaddrop_oscore_respond(resource, request, addr,
						       addr_len, ctx, piv,
						       piv_len,
						       COAP_RESPONSE_CODE_INTERNAL_ERROR,
						       0, NULL, 0);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL,
				    0);
	}
	uint8_t resp_buf[LICHEN_COAP_SERVER_MAX_PAYLOAD];
	int resp_len = senml_encode_deaddrop(NULL, dtn_get_unix_time(),
					     pending, resp_buf,
					     sizeof(resp_buf));
	if (resp_len < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL) {
			return deaddrop_oscore_respond(resource, request, addr,
						       addr_len, ctx, piv,
						       piv_len,
						       COAP_RESPONSE_CODE_INTERNAL_ERROR,
						       0, NULL, 0);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL,
				    0);
	}
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && ctx != NULL) {
		return deaddrop_oscore_respond(resource, request, addr,
					       addr_len, ctx, piv, piv_len,
					       COAP_RESPONSE_CODE_CONTENT,
					       SENML_CBOR_CONTENT_FORMAT,
					       resp_buf, (size_t)resp_len);
	}
#endif
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT,
			    SENML_CBOR_CONTENT_FORMAT, resp_buf,
			    (size_t)resp_len);
}

static int confessions_get(struct coap_resource *resource,
			   struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t buf[64];
	struct senml_pack pack;
	senml_pack_init(&pack, NULL, dtn_get_unix_time());
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
	size_t piv_len = sizeof(piv);
	bool is_protected = coap_oscore_is_protected(request);
	if (is_protected) {
		if (oscore_ctx_get_by_eui64(peer_eui64, &ctx) != OSCORE_OK ||
		    ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request,
							     addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		uint8_t plain[64];
		size_t plain_len = sizeof(plain);
		int r = coap_oscore_unprotect_request(ctx, request, &orig_code,
						      opts, &opt_len, plain,
						      &plain_len, piv,
						      &piv_len);
		if (r != OSCORE_OK) return COAP_RESPONSE_CODE_BAD_REQUEST;
		if (orig_code != COAP_METHOD_POST) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
		payload = plain;
		payload_len = (uint16_t)plain_len;
	} else {
		payload = coap_packet_get_payload(request, &payload_len);
	}
#else
	payload = coap_packet_get_payload(request, &payload_len);
#endif
	if (!payload || payload_len == 0) return COAP_RESPONSE_CODE_BAD_REQUEST;
	uint32_t now_ms = k_uptime_get_32();
	uint8_t iid7 = peer_eui64[7];
	k_mutex_lock(&s_rate_mutex, K_FOREVER);
	if (s_last_confession[iid7] &&
	    (now_ms - s_last_confession[iid7] <
	     CONFIG_LICHEN_COAP_DEADDROP_RATE_LIMIT_MS)) {
		k_mutex_unlock(&s_rate_mutex);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL) {
			return deaddrop_oscore_respond(resource, request, addr,
						       addr_len, ctx, piv,
						       piv_len,
						       COAP_RESPONSE_CODE_TOO_MANY_REQUESTS,
						       0, NULL, 0);
		}
#endif
		return COAP_RESPONSE_CODE_TOO_MANY_REQUESTS;
	}
	s_last_confession[iid7] = now_ms;
	k_mutex_unlock(&s_rate_mutex);
	uint8_t resp_code = COAP_RESPONSE_CODE_CHANGED;
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && ctx != NULL) {
		return deaddrop_oscore_respond(resource, request, addr,
					       addr_len, ctx, piv, piv_len,
					       resp_code, 0, NULL, 0);
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
	k_mutex_init(&s_rate_mutex);
	return 0;
}

uint16_t lichen_dtn_expire_periodic(void)
{
	k_mutex_lock(&s_dtn_buf_mutex, K_FOREVER);
	uint16_t expired = lichen_dtn_expire_old(&s_dtn_buf,
						 dtn_get_unix_time());
	k_mutex_unlock(&s_dtn_buf_mutex);
	return expired;
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
