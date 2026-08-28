/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file checkin_resource.c
 * @brief CoAP resource handlers for Check-In / Roll Call (spec 18.6)
 *
 * Zephyr glue over lichen/checkin.h. See checkin_resource.h for the
 * endpoint contract. All paths respond through lichen_coap_respond();
 * handler return values propagate its result (0 on success).
 */

#include <lichen/checkin_resource.h>

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap_service.h>

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

static bool s_time_overridden;
static uint64_t s_time_override;

struct lichen_checkin_service *lichen_checkin_resource_service(void)
{
	return &s_service;
}

void lichen_checkin_resource_set_time(uint64_t now, bool use_override)
{
	s_time_overridden = use_override;
	s_time_override = now;
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
 * @brief Read the request payload into s_payload.
 *
 * @return Payload length (0 when absent) or -1 on error.
 */
static int read_payload(struct coap_packet *request)
{
	uint16_t len = 0U;
	const uint8_t *payload = coap_packet_get_payload(request, &len);

	if (payload == NULL) {
		return len == 0U ? 0 : -1;
	}
	if (len == 0U || len > sizeof(s_payload)) {
		return -1;
	}
	memcpy(s_payload, payload, len);
	return (int)len;
}

int lichen_checkin_post_handler(struct coap_resource *resource,
				struct coap_packet *request,
				struct sockaddr *addr, socklen_t addr_len)
{
	enum lichen_checkin_error detail = LICHEN_CHECKIN_OK;
	uint8_t code;
	int len = read_payload(request);
	int ret;

	if (len <= 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST,
					   0, NULL, 0U);
	}

	k_mutex_lock(&s_lock, K_FOREVER);
	service_tick_locked();
	code = lichen_checkin_post(&s_service, s_payload, (size_t)len,
				   &detail);
	k_mutex_unlock(&s_lock);

	if (code != LICHEN_CHECKIN_CODE_CHANGED) {
		LOG_WRN("check-in rejected: %d", detail);
	}
	ret = lichen_coap_respond(resource, request, addr, addr_len, code,
				  0, NULL, 0U);
	return ret;
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
	enum lichen_checkin_error detail = LICHEN_CHECKIN_OK;
	uint8_t code;
	int len = read_payload(request);
	int ret;

	if (len <= 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST,
					   0, NULL, 0U);
	}

	k_mutex_lock(&s_lock, K_FOREVER);
	service_tick_locked();
	code = lichen_rollcall_post(&s_service, s_payload, (size_t)len,
				    &detail);
	k_mutex_unlock(&s_lock);

	if (code == LICHEN_CHECKIN_CODE_UNAVAILABLE) {
		LOG_WRN("roll-call table full");
	} else if (code != LICHEN_CHECKIN_CODE_CREATED) {
		LOG_WRN("roll-call rejected: %d", detail);
	}
	ret = lichen_coap_respond(resource, request, addr, addr_len, code,
				  0, NULL, 0U);
	return ret;
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
		/* No id, or unknown id: full list (Python reference). */
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
	struct lichen_checkin_config cfg;
	int len = read_payload(request);
	int ret;

	if (len <= 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST,
					   0, NULL, 0U);
	}

	ret = lichen_checkin_config_from_cbor(s_payload, (size_t)len, &cfg);
	if (ret != LICHEN_CHECKIN_OK) {
		LOG_WRN("check-in config rejected: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST,
					   0, NULL, 0U);
	}

	k_mutex_lock(&s_lock, K_FOREVER);
	service_tick_locked();
	lichen_checkin_config_apply(&s_service, &cfg);
	k_mutex_unlock(&s_lock);

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CHANGED,
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
