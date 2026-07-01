/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/bluetooth/uuid.h>
#include <zephyr/ztest.h>

#include "ble_app_owner.h"
#include "ble_meshtastic.h"

#define MESHTASTIC_SVC_UUID_VAL \
	BT_UUID_128_ENCODE(0x6ba1b218, 0x15a8, 0x461f, 0x9fa8, 0x5dcae273eafd)

static const uint8_t s_meshtastic_svc_uuid[] = { MESHTASTIC_SVC_UUID_VAL };

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

static void meshtastic_ble_before(void *fixture)
{
	ARG_UNUSED(fixture);
	ble_app_owner_test_reset();
	ble_meshtastic_reset_session();
}

ZTEST(meshtastic_ble, test_exact_final_read_releases_from_radio_slot)
{
	const uint8_t msg[] = { 0x38, 0xac, 0x9e, 0x04 };
	uint8_t out[sizeof(msg)];
	uint32_t capacity;
	int ret;

	ble_meshtastic_reset_session();
	capacity = ble_meshtastic_from_radio_capacity();

	zassert_equal(ble_meshtastic_enqueue_from_radio(msg, sizeof(msg)), 0);
	zassert_equal(ble_meshtastic_from_radio_free(), capacity - 1U);

	ret = ble_meshtastic_test_read_from_radio(out, 2U, 0U);
	zassert_equal(ret, 2);
	zassert_mem_equal(out, msg, 2U);
	zassert_equal(ble_meshtastic_from_radio_free(), capacity - 1U);

	ret = ble_meshtastic_test_read_from_radio(out, 2U, 2U);
	zassert_equal(ret, 2);
	zassert_mem_equal(out, &msg[2], 2U);
	zassert_equal(ble_meshtastic_from_radio_free(), capacity);
}

ZTEST(meshtastic_ble, test_noncontiguous_read_offset_does_not_release_slot)
{
	const uint8_t msg[] = { 0x38, 0xac, 0x9e, 0x04 };
	uint8_t out[sizeof(msg)];
	uint32_t capacity;
	int ret;

	ble_meshtastic_reset_session();
	capacity = ble_meshtastic_from_radio_capacity();

	zassert_equal(ble_meshtastic_enqueue_from_radio(msg, sizeof(msg)), 0);
	ret = ble_meshtastic_test_read_from_radio(out, 2U, 0U);
	zassert_equal(ret, 2);

	ret = ble_meshtastic_test_read_from_radio(out, 1U, 3U);
	zassert_true(ret < 0, "non-contiguous read unexpectedly succeeded");
	zassert_equal(ble_meshtastic_from_radio_free(), capacity - 1U);

	ret = ble_meshtastic_test_read_from_radio(out, 2U, 2U);
	zassert_equal(ret, 2);
	zassert_mem_equal(out, &msg[2], 2U);
	zassert_equal(ble_meshtastic_from_radio_free(), capacity);
}

ZTEST(meshtastic_ble, test_single_exact_read_releases_from_radio_slot)
{
	const uint8_t msg[] = { 0x38, 0xac, 0x9e, 0x04 };
	uint8_t out[sizeof(msg)];
	uint32_t capacity;
	int ret;

	ble_meshtastic_reset_session();
	capacity = ble_meshtastic_from_radio_capacity();

	zassert_equal(ble_meshtastic_enqueue_from_radio(msg, sizeof(msg)), 0);
	ret = ble_meshtastic_test_read_from_radio(out, sizeof(out), 0U);

	zassert_equal(ret, sizeof(msg));
	zassert_mem_equal(out, msg, sizeof(msg));
	zassert_equal(ble_meshtastic_from_radio_free(), capacity);
}

ZTEST(meshtastic_ble, test_full_from_radio_queue_rejects_new_packet)
{
	const uint8_t first[] = { 0x38, 0x01 };
	const uint8_t filler[] = { 0x38, 0x02 };
	const uint8_t overflow[] = { 0x38, 0x03 };
	uint8_t out[sizeof(first)];
	uint32_t capacity;
	int ret;

	ble_meshtastic_reset_session();
	capacity = ble_meshtastic_from_radio_capacity();
	zassert_true(capacity > 0U);

	zassert_equal(ble_meshtastic_enqueue_from_radio(first, sizeof(first)), 0);
	for (uint32_t i = 1U; i < capacity; i++) {
		zassert_equal(ble_meshtastic_enqueue_from_radio(filler,
								sizeof(filler)),
			      0);
	}
	zassert_equal(ble_meshtastic_from_radio_free(), 0U);
	zassert_equal(ble_meshtastic_enqueue_from_radio(overflow,
							sizeof(overflow)),
		      -ENOMEM);
	zassert_equal(ble_meshtastic_from_radio_free(), 0U);

	ret = ble_meshtastic_test_read_from_radio(out, sizeof(out), 0U);
	zassert_equal(ret, sizeof(first));
	zassert_mem_equal(out, first, sizeof(first));
	zassert_equal(ble_meshtastic_from_radio_free(), 1U);
}

ZTEST(meshtastic_ble, test_session_epoch_guard_drops_stale_response)
{
	const uint8_t msg[] = { 0x38, 0xac, 0x9e, 0x04 };
	uint32_t epoch;

	ble_meshtastic_reset_session();
	ble_meshtastic_test_connect();
	epoch = ble_meshtastic_session_epoch();
	zassert_true(ble_meshtastic_session_epoch_current(epoch));

	zassert_equal(ble_meshtastic_enqueue_from_radio_if_session(epoch, msg,
								   sizeof(msg)),
		      0);
	zassert_equal(ble_meshtastic_from_radio_free(),
		      ble_meshtastic_from_radio_capacity() - 1U);

	ble_meshtastic_reset_session();
	zassert_false(ble_meshtastic_session_epoch_current(epoch));
	zassert_equal(ble_meshtastic_enqueue_from_radio_if_session(epoch, msg,
								   sizeof(msg)),
		      -ESTALE);
	zassert_equal(ble_meshtastic_from_radio_free(),
		      ble_meshtastic_from_radio_capacity());
}

ZTEST(meshtastic_ble, test_dequeue_returns_write_time_epoch)
{
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	const uint8_t response[] = { 0x38, 0xac, 0x9e, 0x04 };
	uint8_t out[sizeof(heartbeat)];
	size_t out_len;
	uint32_t write_epoch;
	uint32_t dequeue_epoch;

	ble_meshtastic_reset_session();
	write_epoch = ble_meshtastic_session_epoch();
	zassert_equal(ble_meshtastic_test_write_to_radio(heartbeat,
							 sizeof(heartbeat)),
		      sizeof(heartbeat));
	zassert_equal(ble_meshtastic_dequeue_to_radio(out, sizeof(out), &out_len,
						      &dequeue_epoch),
		      1);
	zassert_equal(dequeue_epoch, write_epoch);
	zassert_equal(out_len, sizeof(heartbeat));
	zassert_mem_equal(out, heartbeat, sizeof(heartbeat));

	ble_meshtastic_reset_session();
	zassert_equal(ble_meshtastic_enqueue_from_radio_if_session(dequeue_epoch,
								   response,
								   sizeof(response)),
		      -ESTALE);
	zassert_equal(ble_meshtastic_from_radio_free(),
		      ble_meshtastic_from_radio_capacity());
}

ZTEST(meshtastic_ble, test_stale_connection_write_is_rejected)
{
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	uint8_t fake_conn;
	uint8_t out[sizeof(heartbeat)];
	size_t out_len;
	uint32_t epoch;

	ble_meshtastic_reset_session();
	zassert_true(ble_meshtastic_test_write_to_radio_conn(
			     heartbeat, sizeof(heartbeat), &fake_conn) < 0);
	zassert_equal(ble_meshtastic_dequeue_to_radio(out, sizeof(out), &out_len,
						      &epoch),
		      0);
}

ZTEST(meshtastic_ble, test_owner_connection_write_and_disconnect_cleanup)
{
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	const uint8_t response[] = { 0x38, 0xac, 0x9e, 0x04 };
	struct bt_conn *conn = (struct bt_conn *)0x1;
	struct bt_conn *other_conn = (struct bt_conn *)0x2;
	struct ble_app_owner_test_state owner_state;
	uint8_t out[sizeof(heartbeat)];
	size_t out_len;
	uint32_t epoch;
	uint32_t stale_epoch;

	zassert_ok(ble_meshtastic_init());
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_true(owner_state.has_connected);
	zassert_true(owner_state.has_disconnected);

	stale_epoch = ble_meshtastic_session_epoch();
	ble_app_owner_test_connected(conn, 0U);
	epoch = ble_meshtastic_session_epoch();
	zassert_not_equal(epoch, stale_epoch);
	zassert_true(ble_meshtastic_session_active());
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_true(owner_state.has_connection);
	zassert_equal(owner_state.conn_ref_count, 1U);

	zassert_equal(ble_meshtastic_test_write_to_radio_conn(
			      heartbeat, sizeof(heartbeat), conn),
		      sizeof(heartbeat));
	zassert_equal(ble_meshtastic_dequeue_to_radio(out, sizeof(out),
						      &out_len, &stale_epoch),
		      1);
	zassert_equal(stale_epoch, epoch);
	zassert_equal(out_len, sizeof(heartbeat));
	zassert_mem_equal(out, heartbeat, sizeof(heartbeat));

	zassert_true(ble_meshtastic_test_write_to_radio_conn(
			     heartbeat, sizeof(heartbeat), other_conn) < 0);
	zassert_equal(ble_meshtastic_dequeue_to_radio(out, sizeof(out),
						      &out_len, &stale_epoch),
		      0);

	zassert_equal(ble_meshtastic_enqueue_from_radio_if_session(
			      epoch, response, sizeof(response)),
		      0);
	zassert_equal(ble_meshtastic_from_radio_free(),
		      ble_meshtastic_from_radio_capacity() - 1U);

	ble_app_owner_test_disconnected(other_conn, 19U);
	zassert_true(ble_meshtastic_session_active());
	zassert_equal(ble_meshtastic_from_radio_free(),
		      ble_meshtastic_from_radio_capacity() - 1U);
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_equal(owner_state.adv_start_count, 1U);

	ble_app_owner_test_disconnected(conn, 19U);
	zassert_false(ble_meshtastic_session_active());
	zassert_false(ble_meshtastic_session_epoch_current(epoch));
	zassert_equal(ble_meshtastic_enqueue_from_radio_if_session(
			      epoch, response, sizeof(response)),
		      -ESTALE);
	zassert_equal(ble_meshtastic_from_radio_free(),
		      ble_meshtastic_from_radio_capacity());
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_false(owner_state.has_connection);
	zassert_equal(owner_state.adv_start_count, 2U);
	zassert_equal(owner_state.conn_ref_count, owner_state.conn_unref_count);
}

ZTEST(meshtastic_ble, test_reconnect_rejects_old_connection_write)
{
	const uint8_t heartbeat[] = { 0x3a, 0x00 };
	struct bt_conn *old_conn = (struct bt_conn *)0x1;
	struct bt_conn *new_conn = (struct bt_conn *)0x2;
	uint8_t out[sizeof(heartbeat)];
	size_t out_len;
	uint32_t old_epoch;
	uint32_t new_epoch;

	zassert_ok(ble_meshtastic_init());
	ble_app_owner_test_connected(old_conn, 0U);
	old_epoch = ble_meshtastic_session_epoch();
	ble_app_owner_test_disconnected(old_conn, 19U);
	ble_app_owner_test_connected(new_conn, 0U);
	new_epoch = ble_meshtastic_session_epoch();

	zassert_not_equal(old_epoch, new_epoch);
	zassert_true(ble_meshtastic_test_write_to_radio_conn(
			     heartbeat, sizeof(heartbeat), old_conn) < 0);
	zassert_equal(ble_meshtastic_dequeue_to_radio(out, sizeof(out),
						      &out_len, &new_epoch),
		      0);
	zassert_equal(ble_meshtastic_test_write_to_radio_conn(
			      heartbeat, sizeof(heartbeat), new_conn),
		      sizeof(heartbeat));
}

ZTEST(meshtastic_ble, test_reset_session_if_epoch_preserves_new_session)
{
	const uint8_t msg[] = { 0x38, 0xac, 0x9e, 0x04 };
	uint32_t old_epoch;
	uint32_t new_epoch;

	ble_meshtastic_reset_session();
	old_epoch = ble_meshtastic_session_epoch();
	ble_meshtastic_reset_session();
	ble_meshtastic_test_connect();
	new_epoch = ble_meshtastic_session_epoch();

	zassert_not_equal(old_epoch, new_epoch);
	zassert_equal(ble_meshtastic_enqueue_from_radio_if_session(new_epoch, msg,
								   sizeof(msg)),
		      0);
	zassert_equal(ble_meshtastic_reset_session_if_epoch(old_epoch), -ESTALE);
	zassert_equal(ble_meshtastic_from_radio_free(),
		      ble_meshtastic_from_radio_capacity() - 1U);

	zassert_equal(ble_meshtastic_reset_session_if_epoch(new_epoch), 0);
	zassert_equal(ble_meshtastic_from_radio_free(),
		      ble_meshtastic_from_radio_capacity());
}

ZTEST(meshtastic_ble, test_init_uses_meshtastic_owner_advertising)
{
	struct ble_app_owner_test_state state;

	zassert_ok(ble_meshtastic_init());
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
	zassert_equal(state.surface, BLE_APP_OWNER_SURFACE_MESHTASTIC);
	zassert_equal(state.ad_len, 2U);
	zassert_equal(state.sd_len, 1U);
	assert_flags_data(&state.ad[0]);
	assert_uuid128_data(&state.ad[1], s_meshtastic_svc_uuid);
	assert_short_name_data(&state.sd[0], "LICHEN");
	zassert_true((state.adv_options & BT_LE_ADV_OPT_CONNECTABLE) != 0U);
	zassert_false((state.adv_options & BT_LE_ADV_OPT_USE_NAME) != 0U);
	zassert_true(state.has_connected);
	zassert_true(state.has_disconnected);
}

ZTEST_SUITE(meshtastic_ble, NULL, NULL, meshtastic_ble_before, NULL, NULL);
