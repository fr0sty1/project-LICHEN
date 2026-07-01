/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/bluetooth/uuid.h>
#include <zephyr/ztest.h>

#include "ble_app_owner.h"
#include "ble_meshcore.h"

#define NUS_SVC_UUID_VAL \
	BT_UUID_128_ENCODE(0x6e400001, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)

static const uint8_t s_nus_svc_uuid[] = { NUS_SVC_UUID_VAL };

static void assert_flags_data(const struct bt_data *data)
{
	zassert_not_null(data);
	zassert_equal(data->type, BT_DATA_FLAGS);
	zassert_equal(data->data_len, 1U);
	zassert_equal(data->data[0], BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR);
}

static void assert_uuid128_data(const struct bt_data *data,
				const uint8_t *uuid_value)
{
	zassert_not_null(data);
	zassert_equal(data->type, BT_DATA_UUID128_ALL);
	zassert_equal(data->data_len, 16U);
	zassert_mem_equal(data->data, uuid_value, 16U);
}

static void assert_short_name_data(const struct bt_data *data,
				   const char *name)
{
	zassert_not_null(data);
	zassert_equal(data->type, BT_DATA_NAME_SHORTENED);
	zassert_equal(data->data_len, strlen(name));
	zassert_mem_equal(data->data, name, strlen(name));
}

static void meshcore_ble_before(void *fixture)
{
	ARG_UNUSED(fixture);
	ble_app_owner_test_reset();
	ble_meshcore_test_disconnect();
}

ZTEST(meshcore_ble, test_rx_write_dequeues_raw_frame_with_epoch)
{
	const uint8_t frame[] = { 0x01, 0x02, 0x03 };
	uint8_t out[sizeof(frame)];
	size_t out_len;
	uint32_t epoch;

	ble_meshcore_test_disconnect();
	ble_meshcore_reset_session();
	ble_meshcore_test_connect();
	epoch = ble_meshcore_session_epoch();

	zassert_equal(ble_meshcore_test_write_rx(frame, sizeof(frame)),
		      sizeof(frame));
	zassert_equal(ble_meshcore_dequeue_rx(out, sizeof(out), &out_len,
					      &epoch),
		      1);
	zassert_equal(out_len, sizeof(frame));
	zassert_mem_equal(out, frame, sizeof(frame));
	zassert_true(ble_meshcore_session_epoch_current(epoch));
}

ZTEST(meshcore_ble, test_rx_rejects_serial_prefixes_and_oversize)
{
	uint8_t oversize[CONFIG_LICHEN_MESHCORE_MAX_FRAME + 1U] = { 0x01 };
	const uint8_t raw_command_a[] = { 0x3c, 0x01, 0xff, 0x01 };
	const uint8_t raw_command_b[] = { 0x3e, 0x01, 0xff, 0x01 };
	const uint8_t serial_a[] = { 0x3c, 0x01, 0x00, 0x01 };
	const uint8_t serial_b[] = { 0x3e, 0x01, 0x00, 0x01 };
	uint8_t out[1];
	size_t out_len;
	uint32_t epoch;

	ble_meshcore_test_disconnect();
	ble_meshcore_reset_session();
	ble_meshcore_test_connect();

	zassert_true(ble_meshcore_test_write_rx(serial_a, sizeof(serial_a)) < 0);
	zassert_true(ble_meshcore_test_write_rx(serial_b, sizeof(serial_b)) < 0);
	zassert_true(ble_meshcore_test_write_rx(oversize, sizeof(oversize)) < 0);
	zassert_equal(ble_meshcore_test_write_rx(raw_command_a,
						 sizeof(raw_command_a)),
		      sizeof(raw_command_a));
	zassert_equal(ble_meshcore_test_write_rx(raw_command_b,
						 sizeof(raw_command_b)),
		      sizeof(raw_command_b));
	zassert_equal(ble_meshcore_dequeue_rx(out, sizeof(out), &out_len,
					      &epoch),
		      -ENOMEM);
}

ZTEST(meshcore_ble, test_rx_queue_backpressure)
{
	const uint8_t frame[] = { 0x02 };
	uint8_t out[sizeof(frame)];
	size_t out_len;
	uint32_t epoch;

	ble_meshcore_test_disconnect();
	ble_meshcore_reset_session();
	ble_meshcore_test_connect();

	for (uint32_t i = 0U; i < CONFIG_LORA_LICHEN_MESHCORE_BLE_QUEUE_DEPTH; i++) {
		zassert_equal(ble_meshcore_test_write_rx(frame, sizeof(frame)),
			      sizeof(frame));
	}
	zassert_true(ble_meshcore_test_write_rx(frame, sizeof(frame)) < 0);

	zassert_equal(ble_meshcore_dequeue_rx(out, sizeof(out), &out_len,
					      &epoch),
		      1);
	zassert_equal(out_len, sizeof(frame));
	zassert_mem_equal(out, frame, sizeof(frame));
}

ZTEST(meshcore_ble, test_stale_connection_write_is_rejected)
{
	const uint8_t frame[] = { 0x02 };
	uint8_t fake_conn;
	uint8_t out[sizeof(frame)];
	size_t out_len;
	uint32_t epoch;

	ble_meshcore_test_disconnect();
	ble_meshcore_reset_session();
	zassert_true(ble_meshcore_test_write_rx_conn(frame, sizeof(frame),
						     &fake_conn) < 0);
	zassert_equal(ble_meshcore_dequeue_rx(out, sizeof(out), &out_len,
					      &epoch),
		      0);
}

ZTEST(meshcore_ble, test_tx_requires_active_session_and_preserves_epoch)
{
	const uint8_t frame[] = { 0x03, 0x04 };
	uint32_t epoch;

	ble_meshcore_test_disconnect();
	ble_meshcore_reset_session();
	zassert_equal(ble_meshcore_enqueue_tx(frame, sizeof(frame)), -ENOTCONN);

	ble_meshcore_test_connect();
	epoch = ble_meshcore_session_epoch();
	zassert_equal(ble_meshcore_enqueue_tx_if_session(epoch, frame,
							 sizeof(frame)),
		      0);
	zassert_equal(ble_meshcore_tx_free(),
		      ble_meshcore_tx_capacity() - 1U);

	ble_meshcore_reset_session();
	zassert_equal(ble_meshcore_enqueue_tx_if_session(epoch, frame,
							 sizeof(frame)),
		      -ESTALE);
	zassert_equal(ble_meshcore_tx_free(), ble_meshcore_tx_capacity());
}

ZTEST(meshcore_ble, test_tx_rejects_serial_prefix_and_backpressure)
{
	const uint8_t frame[] = { 0x04 };
	const uint8_t raw_command[] = { 0x3c, 0x01, 0xff, 0x04 };
	const uint8_t serial[] = { 0x3c, 0x01, 0x00, 0x04 };

	ble_meshcore_test_disconnect();
	ble_meshcore_reset_session();
	ble_meshcore_test_connect();

	zassert_equal(ble_meshcore_enqueue_tx(serial, sizeof(serial)), -EMSGSIZE);
	zassert_equal(ble_meshcore_enqueue_tx(raw_command, sizeof(raw_command)),
		      0);
	for (uint32_t i = 0U; i < ble_meshcore_tx_capacity(); i++) {
		if (i + 1U < ble_meshcore_tx_capacity()) {
			zassert_equal(ble_meshcore_enqueue_tx(frame,
							      sizeof(frame)),
				      0);
		}
	}
	zassert_equal(ble_meshcore_tx_free(), 0U);
	zassert_equal(ble_meshcore_enqueue_tx(frame, sizeof(frame)), -ENOMEM);
}

ZTEST(meshcore_ble, test_reset_session_if_epoch_preserves_new_session)
{
	const uint8_t frame[] = { 0x05 };
	uint32_t old_epoch;
	uint32_t new_epoch;

	ble_meshcore_test_disconnect();
	ble_meshcore_reset_session();
	old_epoch = ble_meshcore_session_epoch();
	ble_meshcore_reset_session();
	ble_meshcore_test_connect();
	new_epoch = ble_meshcore_session_epoch();

	zassert_not_equal(old_epoch, new_epoch);
	zassert_equal(ble_meshcore_enqueue_tx_if_session(new_epoch, frame,
							 sizeof(frame)),
		      0);
	zassert_equal(ble_meshcore_reset_session_if_epoch(old_epoch), -ESTALE);
	zassert_equal(ble_meshcore_tx_free(),
		      ble_meshcore_tx_capacity() - 1U);

	zassert_equal(ble_meshcore_reset_session_if_epoch(new_epoch), 0);
	zassert_equal(ble_meshcore_tx_free(), ble_meshcore_tx_capacity());
}

ZTEST(meshcore_ble, test_init_uses_meshcore_owner_advertising)
{
	struct ble_app_owner_test_state state;

	zassert_ok(ble_meshcore_init());
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
	zassert_equal(state.surface, BLE_APP_OWNER_SURFACE_MESHCORE);
	zassert_equal(state.ad_len, 2U);
	zassert_equal(state.sd_len, 1U);
	assert_flags_data(&state.ad[0]);
	assert_uuid128_data(&state.ad[1], s_nus_svc_uuid);
	assert_short_name_data(&state.sd[0], "MeshCore-LICHEN");
	zassert_true((state.adv_options & BT_LE_ADV_OPT_CONNECTABLE) != 0U);
	zassert_false((state.adv_options & BT_LE_ADV_OPT_USE_NAME) != 0U);
}

ZTEST_SUITE(meshcore_ble, NULL, NULL, meshcore_ble_before, NULL, NULL);
