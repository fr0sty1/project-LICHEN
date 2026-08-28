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
	enum lichen_ble_conn_state last_conn_state;
} test_state;

static void test_conn_cb(enum lichen_ble_conn_state state, void *ctx)
{
	ARG_UNUSED(ctx);
	test_state.last_conn_state = state;
}

static void reset_test_state(void *fixture)
{
	ARG_UNUSED(fixture);
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
	zassert_equal(LICHEN_BLE_IPSS_UUID, 0x1820, "IPSS UUID mismatch");
	zassert_equal(LICHEN_BLE_IPSP_PSM, 0x0023, "IPSP PSM mismatch");
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
 * Test controller-independent RFC 6282 baseline encoding and decoding.
 */
ZTEST(ble_ipsp_transport, test_ipsp_codec_roundtrip)
{
	const uint8_t ipv6[] = {
		0x6a, 0xb1, 0x23, 0x45, 0x00, 0x08, 0x11, 0x40,
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01,
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x02,
		0x16, 0x33, 0x16, 0x33, 0x00, 0x08, 0x00, 0x00,
	};
	uint8_t encoded[sizeof(ipv6)];
	uint8_t decoded[sizeof(ipv6)];
	size_t encoded_len = 0;
	size_t decoded_len = 0;

	zassert_ok(lichen_ble_ipsp_test_encode(ipv6, sizeof(ipv6), encoded,
					      sizeof(encoded), &encoded_len));
	zassert_equal(encoded_len, sizeof(ipv6));
	zassert_equal(encoded[0], 0x60, "Expected baseline IPHC dispatch");
	zassert_equal(encoded[1], 0x00, "Expected stateless full addresses");
	zassert_ok(lichen_ble_ipsp_test_decode(encoded, encoded_len, decoded,
					      sizeof(decoded), &decoded_len));
	zassert_equal(decoded_len, sizeof(ipv6));
	zassert_mem_equal(decoded, ipv6, sizeof(ipv6));
}

ZTEST(ble_ipsp_transport, test_ipsp_codec_rejects_bad_input)
{
	uint8_t short_packet[39] = {0};
	uint8_t bad_ipv6[40] = {0};
	uint8_t output[LICHEN_BLE_IPV6_MTU];
	size_t output_len = 99;

	zassert_equal(lichen_ble_ipsp_test_encode(NULL, 40, output,
						 sizeof(output), &output_len), -EINVAL);
	zassert_equal(lichen_ble_ipsp_test_encode(short_packet, sizeof(short_packet),
						 output, sizeof(output), &output_len),
		      -EINVAL);
	bad_ipv6[0] = 0x60;
	bad_ipv6[5] = 1;
	zassert_equal(lichen_ble_ipsp_test_encode(bad_ipv6, sizeof(bad_ipv6), output,
						 sizeof(output), &output_len),
		      -EBADMSG);
	short_packet[0] = 0x41;
	zassert_equal(lichen_ble_ipsp_test_decode(short_packet, sizeof(short_packet),
						 output, sizeof(output), &output_len),
		      -EINVAL);
}

ZTEST(ble_ipsp_transport, test_ipsp_init_lifecycle)
{
	zassert_equal(lichen_ble_ipsp_init(NULL), -EINVAL);
	lichen_ble_ipsp_test_set_channel_ready(true);
	zassert_true(lichen_ble_ipsp_test_channel_ready());
	lichen_ble_ipsp_test_set_channel_ready(false);
	zassert_false(lichen_ble_ipsp_test_channel_ready());
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
	uint8_t oversized[LICHEN_BLE_IPV6_MTU + 100] = {0};

	int ret = lichen_ble_slip_send(oversized, sizeof(oversized));
	zassert_equal(ret, -EMSGSIZE, "Oversized packet should be rejected");
}
