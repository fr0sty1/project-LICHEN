/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ble_meshtastic.h"

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

ZTEST_SUITE(meshtastic_ble, NULL, NULL, NULL, NULL, NULL);
