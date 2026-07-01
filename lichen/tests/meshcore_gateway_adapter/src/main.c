/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/ztest.h>

#include <lichen/meshcore/codec.h>

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

ZTEST(meshcore_gateway_adapter, test_process_once_dispatches_current_session)
{
	const uint8_t query[] = { LICHEN_MESHCORE_CMD_DEVICE_QUERY, 0x03 };

	fake_ble_meshcore_reset(2U);
	gateway_meshcore_adapter_test_reset();
	zassert_ok(fake_ble_meshcore_push_rx(query, sizeof(query), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	zassert_equal(fake_ble_meshcore_tx_count(), 1U);
	expect_tx(0U, LICHEN_MESHCORE_RESP_DEVICE_INFO, 82U);
}

ZTEST(meshcore_gateway_adapter, test_process_once_rejects_stale_session)
{
	const uint8_t query[] = { LICHEN_MESHCORE_CMD_DEVICE_QUERY, 0x03 };

	fake_ble_meshcore_reset(2U);
	gateway_meshcore_adapter_test_reset();
	zassert_ok(fake_ble_meshcore_push_rx(query, sizeof(query), 1U));
	fake_ble_meshcore_set_epoch(2U);

	zassert_equal(gateway_meshcore_adapter_test_process_once(), -ESTALE);
	zassert_equal(fake_ble_meshcore_tx_count(), 0U);
}

ZTEST(meshcore_gateway_adapter, test_contacts_preflight_avoids_partial_tx)
{
	const uint8_t contacts[] = { LICHEN_MESHCORE_CMD_GET_CONTACTS };

	fake_ble_meshcore_reset(1U);
	gateway_meshcore_adapter_test_reset();
	zassert_ok(fake_ble_meshcore_push_rx(contacts, sizeof(contacts), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), -ENOMEM);
	zassert_equal(fake_ble_meshcore_tx_count(), 0U);
}

ZTEST_SUITE(meshcore_gateway_adapter, NULL, NULL, NULL, NULL, NULL);
