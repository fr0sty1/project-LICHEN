/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file checkin_resource.c
 * @brief CoAP resource handlers for Check-In / Roll Call (spec 18.6)
 *
 * Zephyr glue over lichen/checkin.h. See checkin_resource.h for the
 * endpoint contract. Write endpoints (POST/PUT) unprotect the request
 * with coap_oscore_unprotect_resource_request() and require it to be
 * OSCORE-protected or to originate from the local admin (4.01
 * otherwise); all handler responses go through
 * coap_oscore_respond_resource(). Handler return values follow the
 * coap_server contract: 0 after responding, or a CoAP response code
 * that the framework must deliver (unprotect failures).
 */

#include <lichen/checkin_resource.h>

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>

#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>

LOG_MODULE_REGISTER(lichen_checkin_resource, CONFIG_LICHEN_CHECKIN_LOG_LEVEL);

/* CBOR content-format code (RFC 7252) */
#define CHECKIN_CBOR_CONTENT_FORMAT 60

static struct lichen_checkin_entry
	s_checkins[CONFIG_LICHEN_CHECKIN_MAX_CHECKINS];
static struct lichen_rollcall
	s_rollcalls[CONFIG_LICHEN_CHECKIN_MAX_ROLLCALLS];
static struct lichen_checkin_service s_service;
static K_MUTEX_DEFINE(s_lock);

static uint8_t s_payload[CONFIG_LICHEN_CHECKIN_PAYLOAD_MAX];

/* The Kconfig help promises the buffer bounds the worst-case
 * {"checkins":[...]} document; enforce it at build time (wrapper ~16
 * bytes + one worst-case entry per stored check-in). */
BUILD_ASSERT(CONFIG_LICHEN_CHECKIN_MAX_CHECKINS *
		     LICHEN_CHECKIN_ENTRY_CBOR_MAX + 16 <=
	     CONFIG_LICHEN_CHECKIN_PAYLOAD_MAX,
	     "CONFIG_LICHEN_CHECKIN_PAYLOAD_MAX cannot hold the worst-case "
	     "check-in list document; raise it or lower "
	     "CONFIG_LICHEN_CHECKIN_MAX_CHECKINS");

static bool s_time_overridden;
static uint64_t s_time_override;

struct lichen_checkin_service *lichen_checkin_resource_service(void)
{
	return &s_service;
}

void lichen_checkin_resource_set_time(uint64_t now, bool use_override)
{
	k_mutex_lock(&s_lock, K_FOREVER);
	s_time_overridden = use_override;
	s_time_override = now;
	k_mutex_unlock(&s_lock);
}

static uint64_t resource_now(void)
{
	if (s_time_overridden) {
		return s_time_override;
	}
	return (uint64_t)(k_uptime_get() / 1000);
}

static void service_tick_locked(void)
{
	if (s_service.checkins == NULL) {
		lichen_checkin_service_init(&s_service, s_checkins,
					    CONFIG_LICHEN_CHECKIN_MAX_CHECKINS,
					    s_rollcalls,
					    CONFIG_LICHEN_CHECKIN_MAX_ROLLCALLS);
	}
	lichen_checkin_service_set_time(&s_service, resource_now());
}

/**
 * @brief Whether a self-asserted node address text matches the request
 *        source address (used for OSCORE-authenticated check-ins).
 */
static bool node_matches_peer(const char *node, const struct sockaddr *addr,
			      socklen_t addr_len)
{
	struct in6_addr claimed;

	if (addr == NULL || addr_len < sizeof(struct sockaddr_in6) ||
	    addr->sa_family != AF_INET6) {
		return false;
	}
	return net_addr_pton(AF_INET6, node, &claimed) == 0 &&
	       memcmp(&claimed,
		      &((const struct sockaddr_in6 *)addr)->sin6_addr,
		      sizeof(claimed)) == 0;
}

int lichen_checkin_post_handler(struct coap_resource *resource,
				struct coap_packet *request,
				struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct lichen_checkin c;
	enum lichen_checkin_error detail = LICHEN_CHECKIN_OK;
	uint8_t code;
	int ret;

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len,
						     COAP_METHOD_POST, &oscore);
	if (ret != 0) {
		return ret;
	}
	if (!oscore.is_protected &&
	    !lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0U);
	}
	if (oscore.payload == NULL || oscore.payload_len == 0U) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0U);
	}
	ret = lichen_checkin_from_cbor(oscore.payload, oscore.payload_len, &c);
	if (ret != LICHEN_CHECKIN_OK) {
		LOG_WRN("check-in rejected: %d", ret);
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0U);
	}
	/* An OSCORE-protected request is bound to its source address
	 * (the context lookup keys on the address IID), so the
	 * self-asserted node must be that address. */
	if (oscore.is_protected &&
	    !node_matches_peer(c.node, addr, addr_len)) {
		LOG_WRN("check-in node does not match source");
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_FORBIDDEN,
						    0, NULL, 0U);
	}

	k_mutex_lock(&s_lock, K_FOREVER);
	service_tick_locked();
	code = lichen_checkin_post(&s_service, oscore.payload,
				   oscore.payload_len, &detail);
	k_mutex_unlock(&s_lock);

	if (code != LICHEN_CHECKIN_CODE_CHANGED) {
		LOG_WRN("check-in rejected: %d", detail);
	}
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, code, 0, NULL, 0U);
}

int lichen_checkin_get_handler(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len)
{
	size_t len = 0U;
	int ret;

	k_mutex_lock(&s_lock, K_FOREVER);
	service_tick_locked();
	ret = lichen_checkin_list_encode(&s_service, s_payload,
					 sizeof(s_payload), &len);
	k_mutex_unlock(&s_lock);

	if (ret != LICHEN_CHECKIN_OK) {
		LOG_ERR("check-in list encode failed: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0U);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT,
				   CHECKIN_CBOR_CONTENT_FORMAT, s_payload,
				   len);
}

int lichen_rollcall_post_handler(struct coap_resource *resource,
				 struct coap_packet *request,
				 struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct lichen_rollcall_req req;
	struct lichen_rollcall *rc;
	enum lichen_checkin_error detail = LICHEN_CHECKIN_OK;
	size_t responded_count = 0U;
	size_t missing_count = 0U;
	bool existing = false;
	uint8_t code;
	int ret;

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len,
						     COAP_METHOD_POST, &oscore);
	if (ret != 0) {
		return ret;
	}
	if (!oscore.is_protected &&
	    !lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0U);
	}
	if (oscore.payload == NULL || oscore.payload_len == 0U) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0U);
	}
	ret = lichen_rollcall_req_from_cbor(oscore.payload,
					    oscore.payload_len, &req);
	if (ret != LICHEN_CHECKIN_OK) {
		LOG_WRN("roll-call rejected: %d", ret);
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0U);
	}

	k_mutex_lock(&s_lock, K_FOREVER);
	service_tick_locked();
	rc = lichen_rollcall_find(&s_service, req.id);
	if (rc != NULL) {
		existing = true;
		responded_count = rc->responded_count;
		missing_count = rc->missing_count;
	}
	code = lichen_rollcall_post(&s_service, oscore.payload,
				    oscore.payload_len, &detail);
	if (existing && code == LICHEN_CHECKIN_CODE_CREATED) {
		/* Re-post of a known id: the service layer resets its
		 * tracking lists unconditionally. Creator identity is not
		 * recorded in this layer, so the reset cannot be
		 * conditioned on it; keep the responded/missing lists
		 * (the update stays a capacity/timing operation only). */
		rc = lichen_rollcall_find(&s_service, req.id);
		if (rc != NULL) {
			rc->responded_count = responded_count;
			rc->missing_count = missing_count;
		}
	}
	k_mutex_unlock(&s_lock);

	if (code == LICHEN_CHECKIN_CODE_UNAVAILABLE) {
		LOG_WRN("roll-call table full");
	} else if (code != LICHEN_CHECKIN_CODE_CREATED) {
		LOG_WRN("roll-call rejected: %d", detail);
	}
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, code, 0, NULL, 0U);
}

int lichen_rollcall_get_handler(struct coap_resource *resource,
				struct coap_packet *request,
				struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_option paths[4];
	char id[LICHEN_ROLLCALL_ID_MAX];
	struct lichen_rollcall *rc;
	size_t len = 0U;
	int count;
	int ret;

	count = coap_find_options(request, COAP_OPTION_URI_PATH, paths,
				  ARRAY_SIZE(paths));

	k_mutex_lock(&s_lock, K_FOREVER);
	service_tick_locked();

	rc = NULL;
	if (count >= 2 && paths[1].len > 0U &&
	    paths[1].len < sizeof(id)) {
		memcpy(id, paths[1].value, paths[1].len);
		id[paths[1].len] = '\0';
		rc = lichen_rollcall_find(&s_service, id);
	}

	if (rc != NULL) {
		ret = lichen_rollcall_render(rc, s_payload, sizeof(s_payload),
					     &len);
	} else {
		/* No id, or unknown id: full list document, per spec
		 * 18.6.3 (discovery by polling, not strict lookup). */
		ret = lichen_rollcall_list_encode(&s_service, s_payload,
						  sizeof(s_payload), &len);
	}
	k_mutex_unlock(&s_lock);

	if (ret != LICHEN_CHECKIN_OK) {
		LOG_ERR("roll-call render failed: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0U);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT,
				   CHECKIN_CBOR_CONTENT_FORMAT, s_payload,
				   len);
}

int lichen_checkin_config_put_handler(struct coap_resource *resource,
				      struct coap_packet *request,
				      struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct lichen_checkin_config cfg;
	int ret;

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len,
						     COAP_METHOD_PUT, &oscore);
	if (ret != 0) {
		return ret;
	}
	if (!oscore.is_protected &&
	    !lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0U);
	}
	if (oscore.payload == NULL || oscore.payload_len == 0U) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0U);
	}

	ret = lichen_checkin_config_from_cbor(oscore.payload,
					      oscore.payload_len, &cfg);
	if (ret != LICHEN_CHECKIN_OK) {
		LOG_WRN("check-in config rejected: %d", ret);
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0U);
	}

	k_mutex_lock(&s_lock, K_FOREVER);
	service_tick_locked();
	lichen_checkin_config_apply(&s_service, &cfg);
	k_mutex_unlock(&s_lock);

	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CHANGED,
					    0, NULL, 0U);
}

#if IS_ENABLED(CONFIG_LICHEN_CHECKIN_RESOURCE)

static const char *const checkin_path[] = { "checkin", NULL };
static const char *const rollcall_path[] = { "rollcall", NULL };
static const char *const checkin_config_path[] = { "config", "checkin",
						   NULL };

COAP_RESOURCE_DEFINE(lichen_checkin, lichen_coap_server, {
	.get = lichen_checkin_get_handler,
	.post = lichen_checkin_post_handler,
	.path = checkin_path,
});

COAP_RESOURCE_DEFINE(lichen_rollcall, lichen_coap_server, {
	.get = lichen_rollcall_get_handler,
	.post = lichen_rollcall_post_handler,
	.path = rollcall_path,
});

COAP_RESOURCE_DEFINE(lichen_checkin_config, lichen_coap_server, {
	.put = lichen_checkin_config_put_handler,
	.path = checkin_config_path,
});

#endif /* CONFIG_LICHEN_CHECKIN_RESOURCE */
