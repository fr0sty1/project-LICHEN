/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Zephyr resource-layer tests for Check-In / Roll Call (spec 18.6)
 *
 * Exercises the CoAP handlers in checkin_resource.c directly, with
 * lichen_coap_respond and the OSCORE/local-admin helpers stubbed to
 * capture responses and control the simulated authentication state
 * (registration is compiled out via CONFIG_LICHEN_CHECKIN_RESOURCE=0,
 * mirroring tests/coap_msg_inbox).
 */

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/ztest.h>

#include <lichen/checkin_resource.h>
#include <lichen/coap_oscore.h>

#define PACKET_SIZE 512U

static uint8_t response_code;
static uint16_t response_format;
static uint8_t response_payload[512];
static size_t response_payload_len;

/* Authentication simulation knobs for the resource gate. */
static bool local_admin = true;
static bool oscore_protect;
static uint8_t last_unprotect_method;

static const uint8_t peer[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

/* --- stubs for coap_server.c and coap_oscore.c (not compiled here) --- */

bool lichen_coap_is_local_admin(const struct sockaddr *addr,
				socklen_t addr_len)
{
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	return local_admin;
}

int lichen_coap_respond(struct coap_resource *resource,
			struct coap_packet *request, struct sockaddr *addr,
			socklen_t addr_len, uint8_t code,
			uint16_t content_format, const uint8_t *payload,
			size_t payload_len)
{
	ARG_UNUSED(resource);
	ARG_UNUSED(request);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	response_code = code;
	response_format = content_format;
	response_payload_len = MIN(payload_len, sizeof(response_payload));
	if (response_payload_len > 0U) {
		memcpy(response_payload, payload, response_payload_len);
	}
	return 0;
}

int coap_oscore_unprotect_resource_request(
	struct coap_resource *resource, struct coap_packet *request,
	struct sockaddr *addr, socklen_t addr_len, uint8_t expected_method,
	struct coap_oscore_unprotect_result *result)
{
	uint16_t len = 0U;
	const uint8_t *payload;

	ARG_UNUSED(resource);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	last_unprotect_method = expected_method;
	memset(result, 0, sizeof(*result));
	result->is_protected = oscore_protect;
	payload = coap_packet_get_payload(request, &len);
	if (payload != NULL && len > 0U) {
		result->payload = (uint8_t *)payload;
		result->payload_len = len;
	}
	return 0;
}

int coap_oscore_respond_resource(
	struct coap_resource *resource, struct coap_packet *request,
	struct sockaddr *addr, socklen_t addr_len,
	const struct coap_oscore_unprotect_result *result, uint8_t code,
	uint16_t content_format, const uint8_t *payload, size_t payload_len)
{
	ARG_UNUSED(result);
	return lichen_coap_respond(resource, request, addr, addr_len, code,
				   content_format, payload, payload_len);
}

/* --- helpers --- */

static void init_resource(struct coap_resource *resource)
{
	memset(resource, 0, sizeof(*resource));
}

static void build_request(struct coap_packet *request, uint8_t *buf,
			  uint8_t method, const char *const *path,
			  const uint8_t *payload, size_t payload_len)
{
	uint8_t token = 0x2aU;

	zassert_ok(coap_packet_init(request, buf, PACKET_SIZE, COAP_VERSION_1,
				    COAP_TYPE_CON, 1U, &token, method, 9U));
	if (path != NULL) {
		for (size_t i = 0U; path[i] != NULL; i++) {
			zassert_ok(coap_packet_append_option(
				request, COAP_OPTION_URI_PATH, path[i],
				strlen(path[i])));
		}
	}
	if (payload != NULL) {
		zassert_ok(coap_packet_append_payload_marker(request));
		zassert_ok(coap_packet_append_payload(request, payload,
						      (uint16_t)payload_len));
	}
	request->max_len = request->offset;
}

static int call_handler(
	int (*handler)(struct coap_resource *, struct coap_packet *,
		       struct sockaddr *, socklen_t),
	struct coap_resource *resource, uint8_t method,
	const char *const *path, const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[PACKET_SIZE];
	struct coap_packet request;
	struct sockaddr_in6 addr = {.sin6_family = AF_INET6};

	memcpy(addr.sin6_addr.s6_addr, peer, sizeof(peer));
	build_request(&request, buf, method, path, payload, payload_len);
	response_code = 0U;
	response_payload_len = 0U;
	int ret = handler(resource, &request, (struct sockaddr *)&addr,
			  sizeof(addr));
	return ret == 0 ? response_code : ret;
}

static size_t encode_checkin(uint8_t *buf, size_t cap, const char *node,
			     uint64_t ts, enum lichen_checkin_status status)
{
	struct lichen_checkin c;
	size_t len = 0U;

	memset(&c, 0, sizeof(c));
	strcpy(c.node, node);
	c.ts = ts;
	c.status = status;
	zassert_ok(lichen_checkin_to_cbor(&c, buf, cap, &len));
	return len;
}

static size_t encode_rollcall(uint8_t *buf, size_t cap, const char *id)
{
	struct lichen_rollcall_req r;
	size_t len = 0U;

	memset(&r, 0, sizeof(r));
	strcpy(r.id, id);
	zassert_ok(lichen_rollcall_req_to_cbor(&r, buf, cap, &len));
	return len;
}

static bool contains_bytes(const uint8_t *buf, size_t len,
			   const char *needle)
{
	size_t needle_len = strlen(needle);

	if (needle_len > len) {
		return false;
	}
	for (size_t i = 0U; i <= len - needle_len; i++) {
		if (memcmp(&buf[i], needle, needle_len) == 0) {
			return true;
		}
	}
	return false;
}

static const char *const CHECKIN_PATH[] = { "checkin", NULL };
static const char *const ROLLCALL_PATH[] = { "rollcall", NULL };
static const char *const ROLLCALL_ID_PATH[] = { "rollcall", "roll-001",
						NULL };
static const char *const CONFIG_PATH[] = { "config", "checkin", NULL };

/* --- tests --- */

ZTEST(checkin_resource, test_checkin_post_valid_and_invalid) {
	struct coap_resource resource;
	uint8_t payload[128];
	size_t payload_len;
	struct lichen_checkin_service *svc =
		lichen_checkin_resource_service();

	init_resource(&resource);
	lichen_checkin_resource_set_time(1716742800U, true);
	zassert_equal(svc->checkin_count, 0U);

	payload_len = encode_checkin(payload, sizeof(payload),
				     "0200:0000:0000:0000:0011:2233:4455:6677",
				     1716742800U, LICHEN_CHECKIN_STATUS_OK);
	zassert_equal(call_handler(lichen_checkin_post_handler, &resource,
				   COAP_METHOD_POST, CHECKIN_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_CHANGED);
	zassert_equal(svc->checkin_count, 1U);

	/* {"node":..., "ts":...} without status: 4.00
	 * (vector checkin_missing_status shape). */
	static const uint8_t bad[] = {
		0xa2,
		0x78, 0x27, '0', '2', '0', '0', ':', '0', '0', '0', '0',
		':', '0', '0', '0', '0', ':', '0', '0', '0', '0', ':',
		'0', '0', '1', '1', ':', '2', '2', '3', '3', ':', '4',
		'4', '5', '5', ':', '6', '6', '7', '7',
		0x62, 't', 's', 0x1a, 0x66, 0x53, 0x6a, 0x90,
	};
	zassert_equal(call_handler(lichen_checkin_post_handler, &resource,
				   COAP_METHOD_POST, CHECKIN_PATH, bad,
				   sizeof(bad)),
		      COAP_RESPONSE_CODE_BAD_REQUEST);
	/* Empty payload: 4.00. */
	zassert_equal(call_handler(lichen_checkin_post_handler, &resource,
				   COAP_METHOD_POST, CHECKIN_PATH, NULL, 0U),
		      COAP_RESPONSE_CODE_BAD_REQUEST);
}

ZTEST(checkin_resource, test_checkin_get_lists_entries) {
	struct coap_resource resource;
	uint8_t payload[128];
	size_t payload_len;

	init_resource(&resource);
	lichen_checkin_resource_set_time(1716742800U, true);

	payload_len = encode_checkin(payload, sizeof(payload),
				     "0200:0000:0000:0000:0011:2233:4455:6677",
				     1716742800U, LICHEN_CHECKIN_STATUS_HELP);
	zassert_equal(call_handler(lichen_checkin_post_handler, &resource,
				   COAP_METHOD_POST, CHECKIN_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_CHANGED);

	zassert_equal(call_handler(lichen_checkin_get_handler, &resource,
				   COAP_METHOD_GET, CHECKIN_PATH, NULL, 0U),
		      COAP_RESPONSE_CODE_CONTENT);
	zassert_equal(response_format, 60U);
	zassert_true(response_payload_len > 3U);
	zassert_true(contains_bytes(response_payload, response_payload_len,
				    "checkins"));
	zassert_true(contains_bytes(response_payload, response_payload_len,
				    "0200:0000:0000:0000:0011:2233:4455:6677"));
}

ZTEST(checkin_resource, test_rollcall_lifecycle_and_capacity) {
	struct coap_resource resource;
	uint8_t payload[64];
	size_t payload_len;
	struct lichen_checkin_service *svc =
		lichen_checkin_resource_service();

	init_resource(&resource);
	lichen_checkin_resource_set_time(1716742800U, true);

	/* Open two roll calls (capacity 2 in this build). */
	payload_len = encode_rollcall(payload, sizeof(payload), "roll-001");
	zassert_equal(call_handler(lichen_rollcall_post_handler, &resource,
				   COAP_METHOD_POST, ROLLCALL_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_CREATED);
	payload_len = encode_rollcall(payload, sizeof(payload), "roll-002");
	zassert_equal(call_handler(lichen_rollcall_post_handler, &resource,
				   COAP_METHOD_POST, ROLLCALL_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_CREATED);

	/* Third distinct id at capacity: 5.03 (vector rollcall_constants). */
	payload_len = encode_rollcall(payload, sizeof(payload), "roll-003");
	zassert_equal(call_handler(lichen_rollcall_post_handler, &resource,
				   COAP_METHOD_POST, ROLLCALL_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE);

	/* Existing id still updates: 2.01. */
	payload_len = encode_rollcall(payload, sizeof(payload), "roll-001");
	zassert_equal(call_handler(lichen_rollcall_post_handler, &resource,
				   COAP_METHOD_POST, ROLLCALL_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_CREATED);

	/* List document contains ids. */
	zassert_equal(call_handler(lichen_rollcall_get_handler, &resource,
				   COAP_METHOD_GET, ROLLCALL_PATH, NULL, 0U),
		      COAP_RESPONSE_CODE_CONTENT);
	zassert_true(contains_bytes(response_payload, response_payload_len,
				    "roll-001"));
	zassert_true(contains_bytes(response_payload, response_payload_len,
				    "roll-002"));

	/* Per-id status document. */
	zassert_equal(call_handler(lichen_rollcall_get_handler, &resource,
				   COAP_METHOD_GET, ROLLCALL_ID_PATH, NULL,
				   0U),
		      COAP_RESPONSE_CODE_CONTENT);
	zassert_true(contains_bytes(response_payload, response_payload_len,
				    "started"));
	zassert_false(contains_bytes(response_payload, response_payload_len,
				     "roll-002"));

	/* Unknown id falls back to the list document (Python reference). */
	zassert_equal(call_handler(lichen_rollcall_get_handler, &resource,
				   COAP_METHOD_GET, ROLLCALL_PATH, NULL, 0U),
		      COAP_RESPONSE_CODE_CONTENT);

	/* Expiry: advance past timeout, table frees. The service clock
	 * follows the override on the next handler tick; set it directly
	 * since find() is called outside a handler here. */
	lichen_checkin_resource_set_time(1716742800U + 61U, true);
	lichen_checkin_service_set_time(svc, 1716742800U + 61U);
	zassert_is_null(lichen_rollcall_find(svc, "roll-001"));
	zassert_equal(svc->rollcall_count, 0U);
	payload_len = encode_rollcall(payload, sizeof(payload), "roll-003");
	zassert_equal(call_handler(lichen_rollcall_post_handler, &resource,
				   COAP_METHOD_POST, ROLLCALL_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_CREATED);
}

ZTEST(checkin_resource, test_rollcall_far_future_rejected) {
	struct coap_resource resource;
	uint8_t payload[64];
	size_t payload_len;
	struct lichen_rollcall_req r;

	init_resource(&resource);
	lichen_checkin_resource_set_time(1716742800U, true);

	memset(&r, 0, sizeof(r));
	strcpy(r.id, "far");
	r.has_ts = true;
	r.ts = 1716742800U + LICHEN_ROLLCALL_FUTURE_SLACK_S + 5U;
	zassert_ok(lichen_rollcall_req_to_cbor(&r, payload, sizeof(payload),
					       &payload_len));
	zassert_equal(call_handler(lichen_rollcall_post_handler, &resource,
				   COAP_METHOD_POST, ROLLCALL_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_BAD_REQUEST);
}

ZTEST(checkin_resource, test_config_put_applies) {
	struct coap_resource resource;
	uint8_t payload[LICHEN_CHECKIN_CONFIG_CBOR_MAX];
	size_t payload_len;
	struct lichen_checkin_config cfg;
	struct lichen_checkin_service *svc =
		lichen_checkin_resource_service();

	init_resource(&resource);
	lichen_checkin_resource_set_time(1000U, true);

	memset(&cfg, 0, sizeof(cfg));
	cfg.enabled = true;
	cfg.has_target = true;
	strcpy(cfg.target, "0200:0000:0000:0000:0000:0000:0000:0001");
	cfg.interval_s = 900U;
	zassert_ok(lichen_checkin_config_to_cbor(&cfg, payload,
						 sizeof(payload),
						 &payload_len));
	zassert_equal(call_handler(lichen_checkin_config_put_handler,
				   &resource, COAP_METHOD_PUT, CONFIG_PATH,
				   payload, payload_len),
		      COAP_RESPONSE_CODE_CHANGED);
	zassert_equal(last_unprotect_method, COAP_METHOD_PUT);
	zassert_equal(svc->config.enabled, true);
	zassert_equal(svc->config.interval_s, 900U);

	/* due() anchors at last_checkin_at = 0, so it becomes due once the
	 * service clock reaches interval_s regardless of apply time. */
	lichen_checkin_service_set_time(svc, 899U);
	zassert_false(lichen_checkin_due(svc));
	lichen_checkin_service_set_time(svc, 900U);
	zassert_true(lichen_checkin_due(svc));
	lichen_checkin_mark_sent(svc);
	zassert_false(lichen_checkin_due(svc));

	/* Invalid payload: 4.00. */
	uint8_t bad[4] = {0xa1, 0x01, 0x02, 0x00};
	zassert_equal(call_handler(lichen_checkin_config_put_handler,
				   &resource, COAP_METHOD_PUT, CONFIG_PATH,
				   bad, sizeof(bad)),
		      COAP_RESPONSE_CODE_BAD_REQUEST);
}

ZTEST(checkin_resource, test_unauthenticated_writes_rejected) {
	struct coap_resource resource;
	struct lichen_checkin_service *svc = lichen_checkin_resource_service();
	uint8_t payload[LICHEN_CHECKIN_CONFIG_CBOR_MAX];
	size_t payload_len;
	struct lichen_checkin_config cfg;

	init_resource(&resource);
	lichen_checkin_resource_set_time(1716742800U, true);
	local_admin = false;
	oscore_protect = false;

	/* POST /checkin from an unauthenticated mesh source: 4.01. */
	payload_len = encode_checkin(payload, sizeof(payload),
				     "0200:0000:0000:0000:0011:2233:4455:6677",
				     1716742800U, LICHEN_CHECKIN_STATUS_OK);
	zassert_equal(last_unprotect_method, 0U);
	zassert_equal(call_handler(lichen_checkin_post_handler, &resource,
				   COAP_METHOD_POST, CHECKIN_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_UNAUTHORIZED);
	zassert_equal(last_unprotect_method, COAP_METHOD_POST);
	zassert_equal(svc->checkin_count, 0U);

	/* POST /rollcall from an unauthenticated mesh source: 4.01. */
	payload_len = encode_rollcall(payload, sizeof(payload), "roll-401");
	zassert_equal(call_handler(lichen_rollcall_post_handler, &resource,
				   COAP_METHOD_POST, ROLLCALL_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_UNAUTHORIZED);
	zassert_equal(svc->rollcall_count, 0U);

	/* PUT /config/checkin from an unauthenticated mesh source: 4.01. */
	memset(&cfg, 0, sizeof(cfg));
	cfg.enabled = true;
	cfg.has_target = true;
	strcpy(cfg.target, "0200:0000:0000:0000:0000:0000:0000:0001");
	cfg.interval_s = 900U;
	zassert_ok(lichen_checkin_config_to_cbor(&cfg, payload,
						 sizeof(payload),
						 &payload_len));
	zassert_equal(call_handler(lichen_checkin_config_put_handler,
				   &resource, COAP_METHOD_PUT, CONFIG_PATH,
				   payload, payload_len),
		      COAP_RESPONSE_CODE_UNAUTHORIZED);
	zassert_equal(last_unprotect_method, COAP_METHOD_PUT);
	zassert_equal(svc->config.enabled, false);
}

ZTEST(checkin_resource, test_oscore_checkin_node_binding) {
	struct coap_resource resource;
	struct lichen_checkin_service *svc = lichen_checkin_resource_service();
	uint8_t payload[128];
	size_t payload_len;

	init_resource(&resource);
	lichen_checkin_resource_set_time(1716742800U, true);
	local_admin = false;
	oscore_protect = true;

	/* Protected request claiming another node's address: 4.03. */
	payload_len = encode_checkin(payload, sizeof(payload),
				     "0200:0000:0000:0000:0011:2233:4455:6677",
				     1716742800U, LICHEN_CHECKIN_STATUS_HELP);
	zassert_equal(call_handler(lichen_checkin_post_handler, &resource,
				   COAP_METHOD_POST, CHECKIN_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_FORBIDDEN);
	zassert_equal(svc->checkin_count, 0U);

	/* Protected request whose node matches the source address
	 * (2001:db8::1): 2.04 and stored. */
	payload_len = encode_checkin(payload, sizeof(payload),
				     "2001:0db8:0000:0000:0000:0000:0000:0001",
				     1716742800U, LICHEN_CHECKIN_STATUS_HELP);
	zassert_equal(call_handler(lichen_checkin_post_handler, &resource,
				   COAP_METHOD_POST, CHECKIN_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_CHANGED);
	zassert_equal(svc->checkin_count, 1U);
}

ZTEST(checkin_resource, test_rollcall_repost_preserves_lists) {
	struct coap_resource resource;
	struct lichen_checkin_service *svc = lichen_checkin_resource_service();
	struct lichen_rollcall *rc;
	struct lichen_rollcall_track track;
	struct lichen_rollcall_req r;
	uint8_t payload[64];
	size_t payload_len;

	init_resource(&resource);
	lichen_checkin_resource_set_time(1716742800U, true);

	/* Open roll-001 as local admin and track one responded and one
	 * missing node. */
	payload_len = encode_rollcall(payload, sizeof(payload), "roll-001");
	zassert_equal(call_handler(lichen_rollcall_post_handler, &resource,
				   COAP_METHOD_POST, ROLLCALL_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_CREATED);
	rc = lichen_rollcall_find(svc, "roll-001");
	zassert_not_null(rc);
	memset(&track, 0, sizeof(track));
	strcpy(track.node, "0200:0000:0000:0000:0011:2233:4455:6677");
	track.ts = 1716742800U;
	track.status = LICHEN_CHECKIN_STATUS_OK;
	zassert_ok(lichen_rollcall_record_responded(rc, &track));
	memset(&track, 0, sizeof(track));
	strcpy(track.node, "0200:0000:0000:0000:0011:2233:4455:6688");
	track.ts = 1716742800U;
	zassert_ok(lichen_rollcall_record_missing(rc, &track));

	/* Unauthenticated re-post of the known id: 4.01 and no reset. */
	local_admin = false;
	payload_len = encode_rollcall(payload, sizeof(payload), "roll-001");
	zassert_equal(call_handler(lichen_rollcall_post_handler, &resource,
				   COAP_METHOD_POST, ROLLCALL_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_UNAUTHORIZED);
	rc = lichen_rollcall_find(svc, "roll-001");
	zassert_not_null(rc);
	zassert_equal(rc->responded_count, 1U);
	zassert_equal(rc->missing_count, 1U);
	local_admin = true;

	/* Authenticated re-post updates the entry (2.01) but must keep
	 * the tracking lists: id-reset may not wipe them. */
	memset(&r, 0, sizeof(r));
	strcpy(r.id, "roll-001");
	r.has_timeout = true;
	r.timeout_s = 120U;
	zassert_ok(lichen_rollcall_req_to_cbor(&r, payload, sizeof(payload),
					       &payload_len));
	zassert_equal(call_handler(lichen_rollcall_post_handler, &resource,
				   COAP_METHOD_POST, ROLLCALL_PATH, payload,
				   payload_len),
		      COAP_RESPONSE_CODE_CREATED);
	rc = lichen_rollcall_find(svc, "roll-001");
	zassert_not_null(rc);
	zassert_equal(rc->responded_count, 1U);
	zassert_equal(rc->missing_count, 1U);
	zassert_equal(rc->timeout_s, 120U);
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);
	response_code = 0U;
	response_format = 0U;
	response_payload_len = 0U;
	local_admin = true;
	oscore_protect = false;
	last_unprotect_method = 0U;
	lichen_checkin_resource_set_time(0U, true);
	memset(lichen_checkin_resource_service(), 0,
	       sizeof(*lichen_checkin_resource_service()));
}

ZTEST_SUITE(checkin_resource, NULL, NULL, before, NULL, NULL);
