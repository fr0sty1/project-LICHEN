/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/ztest.h>
#include <zephyr/sys/util.h>
#include <zephyr/net/coap.h>

#include <lichen/app_interface/app_interface.h>

#include "fake_ble_meshtastic.h"
#include "inbound_coap.h"
#include "inbound_events.h"
#include "meshtastic_adapter.h"

#define COAP_TEST_BUF_SIZE 64

static void reset_gateway(size_t from_radio_cap)
{
	gateway_inbound_events_test_reset();
	lichen_app_interface_test_reset();
	fake_ble_meshtastic_reset(from_radio_cap);
	gateway_meshtastic_adapter_test_reset();
}

static void expect_from_radio(size_t index, const uint8_t *expected,
			      size_t expected_len)
{
	const uint8_t *actual;
	size_t actual_len;

	actual = fake_ble_meshtastic_from_radio(index, &actual_len);
	zassert_not_null(actual);
	zassert_equal(actual_len, expected_len);
	zassert_mem_equal(actual, expected, expected_len);
}

static void make_post_request(struct coap_packet *request, uint8_t *buf,
			      size_t buf_len, const uint8_t *payload,
			      size_t payload_len)
{
	static const uint8_t token[] = { 0x01 };

	zassert_ok(coap_packet_init(request, buf, buf_len, COAP_VERSION_1,
				    COAP_TYPE_CON, sizeof(token), token,
				    COAP_METHOD_POST, 0x1234));
	if (payload_len > 0U) {
		zassert_ok(coap_packet_append_payload_marker(request));
		zassert_ok(coap_packet_append_payload(request, payload,
						      payload_len));
	}
}

ZTEST(meshtastic_gateway_adapter, test_emit_text_uses_current_ble_session)
{
	const uint8_t payload[] = { 'h', 'i' };
	const uint8_t expected[] = {
		0x08, 0x01, 0x12, 0x17, 0x0d, 0x44, 0x33, 0x22,
		0x11, 0x15, 0x04, 0x03, 0x02, 0x01, 0x22, 0x06,
		0x08, 0x01, 0x12, 0x02, 0x68, 0x69, 0x35, 0x88,
		0x77, 0x66, 0x55
	};
	struct gateway_inbound_text_event event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667788U,
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_id = true,
	};

	reset_gateway(2U);
	zassert_equal(gateway_inbound_emit_text(&event), 0);

	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	expect_from_radio(0U, expected, sizeof(expected));
}

ZTEST(meshtastic_gateway_adapter, test_emit_status_uses_current_ble_session)
{
	const uint8_t expected[] = {
		0x08, 0x01, 0x12, 0x18, 0x0d, 0x44, 0x33, 0x22,
		0x11, 0x15, 0x04, 0x03, 0x02, 0x01, 0x22, 0x07,
		0x08, 0x05, 0x35, 0x78, 0x56, 0x34, 0x12, 0x35,
		0x89, 0x77, 0x66, 0x55
	};
	struct gateway_inbound_status_event event = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.id = 0x55667789U,
		.request_id = 0x12345678U,
		.has_id = true,
	};

	reset_gateway(2U);
	zassert_equal(gateway_inbound_emit_status(&event), 0);

	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	expect_from_radio(0U, expected, sizeof(expected));
}

ZTEST(meshtastic_gateway_adapter, test_emit_status_backpressure_propagates)
{
	const uint8_t payload[] = { 'h', 'i' };
	struct gateway_inbound_text_event text = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	struct gateway_inbound_status_event status = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.request_id = 0x12345678U,
	};

	reset_gateway(1U);
	zassert_equal(gateway_inbound_emit_text(&text), 0);
	zassert_equal(gateway_inbound_emit_status(&status), -ENOMEM);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
}

ZTEST(meshtastic_gateway_adapter, test_emit_text_backpressure_propagates)
{
	const uint8_t payload[] = { 'h', 'i' };
	struct gateway_inbound_text_event first = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	struct gateway_inbound_text_event second = first;

	reset_gateway(1U);
	zassert_equal(gateway_inbound_emit_text(&first), 0);
	zassert_equal(gateway_inbound_emit_text(&second), -ENOMEM);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
}

ZTEST(meshtastic_gateway_adapter, test_emit_rejects_inactive_ble_session)
{
	const uint8_t payload[] = { 'h', 'i' };
	struct gateway_inbound_text_event text = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};
	struct gateway_inbound_status_event status = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.request_id = 0x12345678U,
	};

	reset_gateway(2U);
	fake_ble_meshtastic_set_connected(false);

	zassert_equal(gateway_inbound_emit_text(&text), -ENOTCONN);
	zassert_equal(gateway_inbound_emit_status(&status), -ENOTCONN);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST(meshtastic_gateway_adapter, test_emit_rejects_disconnect_during_enqueue)
{
	const uint8_t payload[] = { 'h', 'i' };
	struct gateway_inbound_text_event text = {
		.from = 0x11223344U,
		.to = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	reset_gateway(2U);
	fake_ble_meshtastic_disconnect_on_next_enqueue();

	zassert_equal(gateway_inbound_emit_text(&text), -ENOTCONN);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST(meshtastic_gateway_adapter, test_inbound_rejects_null_events)
{
	reset_gateway(2U);

	zassert_equal(gateway_inbound_emit_text(NULL), -EINVAL);
	zassert_equal(gateway_inbound_emit_status(NULL), -EINVAL);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST(meshtastic_gateway_adapter, test_adapter_wrappers_reject_null_events)
{
	reset_gateway(2U);

	zassert_equal(gateway_meshtastic_adapter_emit_text(NULL), -EINVAL);
	zassert_equal(gateway_meshtastic_adapter_emit_status(NULL), -EINVAL);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST(meshtastic_gateway_adapter, test_coap_text_post_reaches_from_radio)
{
	uint8_t req_buf[COAP_TEST_BUF_SIZE];
	struct coap_packet request;
	const uint8_t payload[] = { 'h', 'i' };
	const uint8_t expected[] = {
		0x08, 0x01, 0x12, 0x17, 0x0d, 0x00, 0x00, 0x00,
		0x00, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22, 0x06,
		0x08, 0x01, 0x12, 0x02, 0x68, 0x69, 0x35, 0x01,
		0x00, 0x00, 0x00
	};

	reset_gateway(2U);
	make_post_request(&request, req_buf, sizeof(req_buf), payload,
			  sizeof(payload));

	zassert_equal(gateway_inbound_text_post(NULL, &request, NULL, 0),
		      COAP_RESPONSE_CODE_CHANGED);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	expect_from_radio(0U, expected, sizeof(expected));
}

ZTEST(meshtastic_gateway_adapter, test_coap_status_post_reaches_from_radio)
{
	uint8_t req_buf[COAP_TEST_BUF_SIZE];
	struct coap_packet request;
	const uint8_t payload[] = { 0x12, 0x34, 0x56, 0x78 };
	const uint8_t expected[] = {
		0x08, 0x01, 0x12, 0x18, 0x0d, 0x00, 0x00, 0x00,
		0x00, 0x15, 0xff, 0xff, 0xff, 0xff, 0x22, 0x07,
		0x08, 0x05, 0x35, 0x78, 0x56, 0x34, 0x12, 0x35,
		0x01, 0x00, 0x00, 0x00
	};

	reset_gateway(2U);
	make_post_request(&request, req_buf, sizeof(req_buf), payload,
			  sizeof(payload));

	zassert_equal(gateway_inbound_status_post(NULL, &request, NULL, 0),
		      COAP_RESPONSE_CODE_CHANGED);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 1U);
	expect_from_radio(0U, expected, sizeof(expected));
}

ZTEST(meshtastic_gateway_adapter, test_coap_invalid_payloads_are_bad_request)
{
	uint8_t req_buf[COAP_TEST_BUF_SIZE];
	struct coap_packet request;
	const uint8_t bad_status[] = { 0x12, 0x34, 0x56 };

	reset_gateway(2U);
	make_post_request(&request, req_buf, sizeof(req_buf), NULL, 0U);
	zassert_equal(gateway_inbound_text_post(NULL, &request, NULL, 0),
		      COAP_RESPONSE_CODE_BAD_REQUEST);

	make_post_request(&request, req_buf, sizeof(req_buf), bad_status,
			  sizeof(bad_status));
	zassert_equal(gateway_inbound_status_post(NULL, &request, NULL, 0),
		      COAP_RESPONSE_CODE_BAD_REQUEST);
	zassert_equal(fake_ble_meshtastic_from_radio_count(), 0U);
}

ZTEST_SUITE(meshtastic_gateway_adapter, NULL, NULL, NULL, NULL, NULL);
