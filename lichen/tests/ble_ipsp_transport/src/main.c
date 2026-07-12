/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief BLE IPSP transport test suite
 *
 * Tests the BLE IPSP transport binding for LCI per spec/11-lci.md section 17.3.2.
 */

#include <zephyr/ztest.h>
#include <zephyr/bluetooth/bluetooth.h>

#include <string.h>

#include <lichen/transport/ble_ipsp_transport.h>

/* Test callback state */
static struct {
	int rx_count;
	size_t last_rx_len;
	enum lichen_ble_conn_state last_conn_state;
	uint8_t rx_buf[256];
} test_state;

static void test_rx_cb(const uint8_t *data, size_t len, void *ctx)
{
	ARG_UNUSED(ctx);
	test_state.rx_count++;
	test_state.last_rx_len = len;
	if (len <= sizeof(test_state.rx_buf)) {
		memcpy(test_state.rx_buf, data, len);
	}
}

static void test_conn_cb(enum lichen_ble_conn_state state, void *ctx)
{
	ARG_UNUSED(ctx);
	test_state.last_conn_state = state;
}

static void reset_test_state(void)
{
	memset(&test_state, 0, sizeof(test_state));
}

ZTEST_SUITE(ble_ipsp_transport, NULL, NULL, reset_test_state, NULL, NULL);

/**
 * Test SLIP constants are correctly defined per RFC 1055.
 */
ZTEST(ble_ipsp_transport, test_slip_constants)
{
	zassert_equal(SLIP_END, 0xC0, "SLIP_END must be 0xC0");
	zassert_equal(SLIP_ESC, 0xDB, "SLIP_ESC must be 0xDB");
	zassert_equal(SLIP_ESC_END, 0xDC, "SLIP_ESC_END must be 0xDC");
	zassert_equal(SLIP_ESC_ESC, 0xDD, "SLIP_ESC_ESC must be 0xDD");
}

/**
 * Test MTU constants are properly defined.
 */
ZTEST(ble_ipsp_transport, test_mtu_constants)
{
	/* BLE SLIP MTU should match typical BLE DLE max */
	zassert_equal(LICHEN_BLE_SLIP_MTU, 247,
		      "BLE SLIP MTU should be 247 for DLE");

	/* IPv6 MTU should match LICHEN L2 MTU */
	zassert_equal(LICHEN_BLE_IPV6_MTU, 200,
		      "IPv6 MTU should be 200 to match LICHEN L2");
}

/**
 * Test that init fails with NULL config.
 */
ZTEST(ble_ipsp_transport, test_init_null_config)
{
	int ret = lichen_ble_slip_init(NULL);
	zassert_equal(ret, -EINVAL, "Init with NULL config should fail");
}

/**
 * Test that init fails with NULL callback.
 */
ZTEST(ble_ipsp_transport, test_init_null_callback)
{
	struct lichen_ble_transport_config config = {
		.rx_cb = NULL,
		.conn_cb = test_conn_cb,
		.user_ctx = NULL,
		.require_secure = false,
	};

	int ret = lichen_ble_slip_init(&config);
	zassert_equal(ret, -EINVAL, "Init with NULL rx_cb should fail");
}

/**
 * Test connection state enumeration values.
 */
ZTEST(ble_ipsp_transport, test_conn_state_enum)
{
	/* Verify enum values are distinct */
	zassert_true(LICHEN_BLE_DISCONNECTED != LICHEN_BLE_CONNECTED,
		     "States must be distinct");
	zassert_true(LICHEN_BLE_CONNECTED != LICHEN_BLE_PAIRED,
		     "States must be distinct");
	zassert_true(LICHEN_BLE_PAIRED != LICHEN_BLE_SECURE,
		     "States must be distinct");
}

/**
 * Test that IPSP init returns ENOTSUP when not enabled.
 */
ZTEST(ble_ipsp_transport, test_ipsp_not_enabled)
{
	struct lichen_ble_transport_config config = {
		.rx_cb = test_rx_cb,
		.conn_cb = test_conn_cb,
		.user_ctx = NULL,
		.require_secure = false,
	};

	/* IPSP (Option B) is optional and not enabled in this test config */
#if !IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
	int ret = lichen_ble_ipsp_init(&config);
	zassert_equal(ret, -ENOTSUP, "IPSP init should return ENOTSUP");
#endif
}

/**
 * Test get_stats with NULL returns error.
 */
ZTEST(ble_ipsp_transport, test_get_stats_null)
{
	int ret = lichen_ble_transport_get_stats(NULL);
	zassert_equal(ret, -EINVAL, "get_stats with NULL should fail");
}

/**
 * Test send fails when not connected.
 */
ZTEST(ble_ipsp_transport, test_send_not_connected)
{
	uint8_t test_packet[64] = {0};

	/* Without initialization, send should fail */
	int ret = lichen_ble_slip_send(test_packet, sizeof(test_packet));
	zassert_true(ret < 0, "Send without connection should fail");
}

/**
 * Test send fails with NULL data.
 */
ZTEST(ble_ipsp_transport, test_send_null_data)
{
	int ret = lichen_ble_slip_send(NULL, 64);
	zassert_equal(ret, -EINVAL, "Send with NULL data should fail");
}

/**
 * Test send fails with oversized packet.
 */
ZTEST(ble_ipsp_transport, test_send_oversized)
{
	uint8_t oversized[LICHEN_BLE_IPV6_MTU + 100];

	int ret = lichen_ble_slip_send(oversized, sizeof(oversized));
	zassert_equal(ret, -EMSGSIZE, "Oversized packet should be rejected");
}
