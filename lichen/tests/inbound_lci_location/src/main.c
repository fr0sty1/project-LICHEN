/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdint.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_if.h>
#include <zephyr/ztest.h>

#include <lichen/hal.h>

#include "ble_lci_netif.h"
#include "inbound_coap.h"

#define COAP_TEST_BUF_SIZE 64
#define COAP_TEST_OPT_COUNT 4
#define INBOUND_LOCATION_PAYLOAD_LEN 12U

extern struct coap_resource _coap_resource_lichen_coap_list_start[];
extern struct coap_resource _coap_resource_lichen_coap_list_end[];

static void put_be32(uint8_t *buf, uint32_t value)
{
	buf[0] = (uint8_t)(value >> 24);
	buf[1] = (uint8_t)(value >> 16);
	buf[2] = (uint8_t)(value >> 8);
	buf[3] = (uint8_t)value;
}

static void make_location_payload(uint8_t payload[INBOUND_LOCATION_PAYLOAD_LEN])
{
	payload[0] = 1U;
	payload[1] = 0U;
	payload[2] = 2U;
	payload[3] = 0U;
	put_be32(&payload[4], (uint32_t)476206130);
	put_be32(&payload[8], (uint32_t)(int32_t)-1223493000);
}

static void make_post_request(struct coap_packet *request, uint8_t *buf,
			      size_t buf_len, const char * const *path,
			      size_t path_len, const uint8_t *payload,
			      size_t payload_len)
{
	static const uint8_t token[] = { 0x01 };

	zassert_ok(coap_packet_init(request, buf, buf_len, COAP_VERSION_1,
				    COAP_TYPE_CON, sizeof(token), token,
				    COAP_METHOD_POST, 0x1234));
	for (size_t i = 0U; i < path_len; i++) {
		zassert_ok(coap_packet_append_option(request, COAP_OPTION_URI_PATH,
						     path[i], strlen(path[i])));
	}
	zassert_ok(coap_packet_append_payload_marker(request));
	zassert_ok(coap_packet_append_payload(request, payload, payload_len));
}

static int dispatch_location_from(const struct sockaddr_in6 *source,
				  const uint8_t *payload, size_t payload_len)
{
	static const char * const path[] = { "inbound", "location" };
	uint8_t req_buf[COAP_TEST_BUF_SIZE];
	struct coap_packet request;
	struct coap_packet parsed;
	struct coap_option options[COAP_TEST_OPT_COUNT] = { 0 };
	struct coap_resource *resources =
		_coap_resource_lichen_coap_list_start;
	size_t resource_count = _coap_resource_lichen_coap_list_end -
				_coap_resource_lichen_coap_list_start;

	make_post_request(&request, req_buf, sizeof(req_buf), path,
			  ARRAY_SIZE(path), payload, payload_len);
	zassert_ok(coap_packet_parse(&parsed, req_buf, request.offset, options,
				     ARRAY_SIZE(options)));
	return coap_handle_request_len(&parsed, resources, resource_count,
				       options, ARRAY_SIZE(options),
				       (struct sockaddr *)source,
				       sizeof(*source));
}

static struct coap_resource *find_lichen_coap_resource(const char *first,
						      const char *second)
{
	struct coap_resource *resources =
		_coap_resource_lichen_coap_list_start;
	size_t resource_count = _coap_resource_lichen_coap_list_end -
				_coap_resource_lichen_coap_list_start;

	for (size_t i = 0U; i < resource_count; i++) {
		const char * const *path = resources[i].path;

		if (path != NULL && path[0] != NULL && path[1] != NULL &&
		    path[2] == NULL && strcmp(path[0], first) == 0 &&
		    strcmp(path[1], second) == 0) {
			return &resources[i];
		}
	}

	return NULL;
}

static void make_link_local_sockaddr(struct sockaddr_in6 *addr,
				     uint32_t scope_id)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr.s6_addr[0] = 0xfe;
	addr->sin6_addr.s6_addr[1] = 0x80;
	addr->sin6_addr.s6_addr[15] = 1U;
	addr->sin6_scope_id = scope_id;
}

static void make_global_sockaddr(struct sockaddr_in6 *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr.s6_addr[0] = 0x20;
	addr->sin6_addr.s6_addr[1] = 0x01;
	addr->sin6_addr.s6_addr[2] = 0x0d;
	addr->sin6_addr.s6_addr[3] = 0xb8;
	addr->sin6_addr.s6_addr[15] = 1U;
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(10 * 1000);
}

static void after(void *fixture)
{
	ARG_UNUSED(fixture);

	lichen_hal_location_clear();
	lichen_hal_location_test_use_real_uptime();
}

ZTEST(inbound_lci_location, test_native_lci_location_resource_registered)
{
	struct coap_resource *location =
		find_lichen_coap_resource("inbound", "location");
	struct coap_resource *text =
		find_lichen_coap_resource("inbound", "text");
	struct coap_resource *status =
		find_lichen_coap_resource("inbound", "status");

	zassert_not_null(location);
	zassert_not_null(location->post);
	zassert_equal_ptr(location->post, gateway_inbound_location_post);
	zassert_is_null(text);
	zassert_is_null(status);
}

ZTEST(inbound_lci_location, test_scoped_lci_link_local_location_updates_hal)
{
	uint8_t payload[INBOUND_LOCATION_PAYLOAD_LEN];
	struct sockaddr_in6 source;
	struct lichen_hal_location_time_snapshot snapshot;
	struct net_if *iface = ble_lci_netif_get();

	zassert_not_null(iface);
	make_location_payload(payload);
	make_link_local_sockaddr(&source, net_if_get_by_iface(iface));

	zassert_equal(dispatch_location_from(&source, payload, sizeof(payload)),
		      COAP_RESPONSE_CODE_CHANGED);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_true(snapshot.location_provider_available);
	zassert_equal(snapshot.source_class,
		      LICHEN_HAL_LOCATION_SOURCE_LOCAL_CLIENT);
	zassert_equal(snapshot.fix_state, LICHEN_HAL_LOCATION_FIX_2D);
	zassert_true(snapshot.latitude_e7_valid);
	zassert_equal(snapshot.latitude_e7, 476206130);
	zassert_true(snapshot.longitude_e7_valid);
	zassert_equal(snapshot.longitude_e7, -1223493000);
}

ZTEST(inbound_lci_location, test_unscoped_link_local_location_is_forbidden)
{
	uint8_t payload[INBOUND_LOCATION_PAYLOAD_LEN];
	struct sockaddr_in6 source;
	struct lichen_hal_location_time_snapshot snapshot;

	make_location_payload(payload);
	make_link_local_sockaddr(&source, 0U);

	zassert_equal(dispatch_location_from(&source, payload, sizeof(payload)),
		      COAP_RESPONSE_CODE_FORBIDDEN);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_false(snapshot.location_provider_available);
}

ZTEST(inbound_lci_location, test_global_location_source_is_forbidden)
{
	uint8_t payload[INBOUND_LOCATION_PAYLOAD_LEN];
	struct sockaddr_in6 source;
	struct lichen_hal_location_time_snapshot snapshot;

	make_location_payload(payload);
	make_global_sockaddr(&source);

	zassert_equal(dispatch_location_from(&source, payload, sizeof(payload)),
		      COAP_RESPONSE_CODE_FORBIDDEN);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_false(snapshot.location_provider_available);
}

ZTEST_SUITE(inbound_lci_location, NULL, NULL, before, after, NULL);
