#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>
#include <string.h>
#include <lichen/coap_server.h>
#include <lichen/coap_oscore.h>
#include <lichen/oscore.h>
#include <lichen/routing/dtn.h>
#include <lichen/senml.h>
LOG_MODULE_REGISTER(lichen_coap_dtn, CONFIG_LICHEN_COAP_DEADDROP_LOG_LEVEL);
static struct lichen_dtn_buffer s_dtn_buffer;
static K_MUTEX_DEFINE(s_dtn_mutex);
static struct senml_pack s_senml_pack;
static K_MUTEX_DEFINE(s_senml_pack_mutex);


static int deaddrop_get(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len)
{
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	if (lichen_dtn_is_empty(&s_dtn_buffer)) {
		k_mutex_unlock(&s_dtn_mutex);
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_NOT_FOUND, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
	}
	uint16_t pending = lichen_dtn_pending_count(&s_dtn_buffer);
	k_mutex_unlock(&s_dtn_mutex);
	k_mutex_lock(&s_senml_pack_mutex, K_FOREVER);
	int r = senml_pack_init(&s_senml_pack, NULL, 0);
	if (r < 0) {
		k_mutex_unlock(&s_senml_pack_mutex);
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_INTERNAL_ERROR, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
	}
	r = senml_add_float(&s_senml_pack, "pending", NULL, (float)pending);
	if (r < 0) {
		k_mutex_unlock(&s_senml_pack_mutex);
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_INTERNAL_ERROR, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
	}
	uint8_t buf[64];
	size_t len = senml_encode_cbor(&s_senml_pack, buf, sizeof(buf));
	k_mutex_unlock(&s_senml_pack_mutex);
	if (len < 0 || len > sizeof(buf)) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_INTERNAL_ERROR, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
	}
	return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CONTENT, SENML_CBOR_CONTENT_FORMAT, buf, len);
}

static int deaddrop_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len)
{
	const uint8_t *payload;
	uint16_t payload_len;
	int r;
	struct oscore_ctx *ctx = NULL;
	uint8_t iid[8] = {0};
	uint8_t decrypted[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX];
	size_t decrypted_len = sizeof(decrypted);
	uint8_t original_code;
	uint8_t opt_buf[64];
	size_t opt_len = sizeof(opt_buf);
	uint8_t piv[8];
	size_t piv_len = sizeof(piv);
	uint32_t now_ms = k_uptime_get_32();
	payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_BAD_REQUEST, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
	}
	if (addr != NULL && addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
		memcpy(iid, &in6->sin6_addr.s6_addr[8], 8);
	}
	r = oscore_ctx_get_by_eui64(iid, &ctx);
	if (r != OSCORE_OK || ctx == NULL) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_UNAUTHORIZED, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
	}
	if (coap_oscore_is_protected(request)) {
		uint8_t oscore_opt[32];
		size_t oscore_opt_len = sizeof(oscore_opt);
		r = coap_oscore_get_option(request, oscore_opt, &oscore_opt_len);
		if (r != 0) {
			return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_BAD_REQUEST, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
		}
		const uint8_t *ciphertext = coap_packet_get_payload(request, &payload_len);
		if (ciphertext == NULL || payload_len == 0) {
			return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_BAD_REQUEST, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
		}
		r = oscore_unprotect_request(ctx, oscore_opt, oscore_opt_len, ciphertext, payload_len, &original_code, NULL, NULL, decrypted, &decrypted_len);
		if (r != OSCORE_OK) {
			return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_BAD_REQUEST, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
		}
		payload = decrypted;
		payload_len = (uint16_t)decrypted_len;
	}
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	if (lichen_dtn_len(&s_dtn_buffer) >= CONFIG_LICHEN_DTN_MAX_MESSAGES || lichen_dtn_has_messages_for(&s_dtn_buffer, iid)) {
		k_mutex_unlock(&s_dtn_mutex);
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_TOO_MANY_REQUESTS, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
	}
	r = lichen_dtn_buffer_message(&s_dtn_buffer, payload, payload_len, iid, LICHEN_DTN_DEFAULT_TTL_SEC, 0, now_ms);
	k_mutex_unlock(&s_dtn_mutex);
	if (r) {
		return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_CREATED, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
	}
	return lichen_coap_respond(resource, request, addr, addr_len, COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, SENML_CBOR_CONTENT_FORMAT, NULL, 0);
}

static int confessions_post(struct coap_resource *resource, struct coap_packet *request, struct sockaddr *addr, socklen_t addr_len)
{
	return deaddrop_post(resource, request, addr, addr_len);
}

static const char *const deaddrop_path[] = {"deaddrop", NULL};
COAP_RESOURCE_DEFINE(lichen_deaddrop, lichen_coap_server, {.get = deaddrop_get, .post = deaddrop_post, .path = deaddrop_path,});

static const char *const confessions_path[] = {"confessions", NULL};
COAP_RESOURCE_DEFINE(lichen_confessions, lichen_coap_server, {.post = confessions_post, .path = confessions_path,});

int lichen_coap_dtn_init(void)
{
	k_mutex_lock(&s_dtn_mutex, K_FOREVER);
	k_mutex_lock(&s_senml_pack_mutex, K_FOREVER);
	BUILD_ASSERT(CONFIG_LICHEN_DTN_MAX_MESSAGES > 0,
		     "DTN max messages must be positive");
	int ret = lichen_dtn_init_with_size(&s_dtn_buffer, CONFIG_LICHEN_DTN_MAX_BYTES);
	if (ret < 0) {
		k_mutex_unlock(&s_senml_pack_mutex);
		k_mutex_unlock(&s_dtn_mutex);
		return ret;
	}
	ret = senml_pack_init(&s_senml_pack, NULL, 0);
	if (ret < 0) {
		k_mutex_unlock(&s_senml_pack_mutex);
		k_mutex_unlock(&s_dtn_mutex);
		return ret;
	}
	lichen_dtn_expire_old(&s_dtn_buffer, 0);
	k_mutex_unlock(&s_senml_pack_mutex);
	k_mutex_unlock(&s_dtn_mutex);
	return 0;
}
