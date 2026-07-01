/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include <lichen/app_interface/app_interface.h>
#include <lichen/meshcore/codec.h>

#include "ble_meshcore.h"
#include "fake_ble_meshcore.h"
#include "meshcore_adapter.h"

static void expect_tx(size_t index, uint8_t type, size_t expected_len)
{
	const uint8_t *frame;
	size_t len;

	frame = fake_ble_meshcore_tx(index, &len);
	zassert_not_null(frame);
	zassert_equal(len, expected_len);
	zassert_equal(frame[0], type);
}

static void reset_gateway(uint32_t tx_cap)
{
	lichen_app_interface_test_reset();
	fake_ble_meshcore_reset(tx_cap);
	gateway_meshcore_adapter_test_reset();
}

ZTEST(meshcore_gateway_adapter, test_process_once_dispatches_current_session)
{
	const uint8_t query[] = { LICHEN_MESHCORE_CMD_DEVICE_QUERY, 0x03 };

	reset_gateway(2U);
	zassert_ok(fake_ble_meshcore_push_rx(query, sizeof(query), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	zassert_equal(fake_ble_meshcore_tx_count(), 1U);
	expect_tx(0U, LICHEN_MESHCORE_RESP_DEVICE_INFO, 82U);
}

ZTEST(meshcore_gateway_adapter, test_process_once_rejects_stale_session)
{
	const uint8_t query[] = { LICHEN_MESHCORE_CMD_DEVICE_QUERY, 0x03 };

	reset_gateway(2U);
	zassert_ok(fake_ble_meshcore_push_rx(query, sizeof(query), 1U));
	fake_ble_meshcore_set_epoch(2U);

	zassert_equal(gateway_meshcore_adapter_test_process_once(), -ESTALE);
	zassert_equal(fake_ble_meshcore_tx_count(), 0U);
}

ZTEST(meshcore_gateway_adapter, test_contacts_preflight_avoids_partial_tx)
{
	const uint8_t contacts[] = { LICHEN_MESHCORE_CMD_GET_CONTACTS };

	reset_gateway(1U);
	zassert_ok(fake_ble_meshcore_push_rx(contacts, sizeof(contacts), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), -ENOMEM);
	zassert_equal(fake_ble_meshcore_tx_count(), 0U);
}

ZTEST(meshcore_gateway_adapter, test_app_interface_text_waiting_and_sync)
{
	const uint8_t payload[] = { 'h', 'i' };
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const struct lichen_app_text_event event = {
		.id = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_id = true,
	};
	const uint8_t *frame;
	size_t len;

	reset_gateway(4U);
	zassert_ok(lichen_app_interface_emit_text(&event));
	expect_tx(0U, LICHEN_MESHCORE_PUSH_MSG_WAITING, 1U);

	zassert_ok(fake_ble_meshcore_push_rx(sync_next, sizeof(sync_next), 1U));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	frame = fake_ble_meshcore_tx(1U, &len);
	zassert_not_null(frame);
	zassert_equal(frame[0], LICHEN_MESHCORE_RESP_CHANNEL_MSG_RECV_V3);
	zassert_equal(len, 13U);
	zassert_mem_equal(&frame[11], payload, sizeof(payload));
}

ZTEST(meshcore_gateway_adapter, test_app_interface_status_waiting_and_sync)
{
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const struct lichen_app_status_event event = {
		.request_id = 0x12345678U,
		.error_reason = 2U,
		.has_error_reason = true,
	};
	const uint8_t *frame;
	size_t len;

	reset_gateway(4U);
	zassert_ok(lichen_app_interface_emit_status(&event));
	expect_tx(0U, LICHEN_MESHCORE_PUSH_MSG_WAITING, 1U);

	zassert_ok(fake_ble_meshcore_push_rx(sync_next, sizeof(sync_next), 1U));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	frame = fake_ble_meshcore_tx(1U, &len);
	zassert_not_null(frame);
	zassert_equal(frame[0], LICHEN_MESHCORE_PUSH_SEND_CONFIRMED);
	zassert_equal(sys_get_le32(&frame[1]), event.request_id);
	zassert_equal(len, 7U);
}

ZTEST(meshcore_gateway_adapter, test_app_interface_rejects_disconnected_session)
{
	const uint8_t payload[] = { 'h' };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	reset_gateway(4U);
	fake_ble_meshcore_set_connected(false);
	zassert_equal(lichen_app_interface_emit_text(&event), -ENOTCONN);
	zassert_equal(fake_ble_meshcore_tx_count(), 0U);
}

ZTEST(meshcore_gateway_adapter, test_app_interface_disconnect_race_drops_pending)
{
	const uint8_t payload[] = { 'h' };
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	reset_gateway(4U);
	fake_ble_meshcore_disconnect_on_next_enqueue();
	zassert_equal(lichen_app_interface_emit_text(&event), -ENOTCONN);

	fake_ble_meshcore_set_connected(true);
	zassert_ok(fake_ble_meshcore_push_rx(sync_next, sizeof(sync_next),
					     ble_meshcore_session_epoch()));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	expect_tx(0U, LICHEN_MESHCORE_RESP_NO_MORE_MESSAGES, 1U);
}

ZTEST(meshcore_gateway_adapter,
      test_app_interface_reconnect_before_sync_drops_pending)
{
	const uint8_t payload[] = { 'h' };
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	reset_gateway(4U);
	zassert_ok(lichen_app_interface_emit_text(&event));
	expect_tx(0U, LICHEN_MESHCORE_PUSH_MSG_WAITING, 1U);

	fake_ble_meshcore_set_connected(false);
	fake_ble_meshcore_set_connected(true);
	zassert_ok(fake_ble_meshcore_push_rx(sync_next, sizeof(sync_next),
					     ble_meshcore_session_epoch()));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	expect_tx(0U, LICHEN_MESHCORE_RESP_NO_MORE_MESSAGES, 1U);
}

ZTEST(meshcore_gateway_adapter, test_app_interface_pending_queue_full)
{
	const uint8_t payload[] = { 'h' };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	reset_gateway(16U);
	for (uint32_t i = 0U; i < CONFIG_LICHEN_MESHCORE_PENDING_EVENTS; i++) {
		zassert_ok(lichen_app_interface_emit_text(&event));
	}
	zassert_equal(lichen_app_interface_emit_text(&event), -ENOMEM);
}

ZTEST_SUITE(meshcore_gateway_adapter, NULL, NULL, NULL, NULL, NULL);
