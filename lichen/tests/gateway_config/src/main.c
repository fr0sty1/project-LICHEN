/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>

#include "config_cbor.h"

ZTEST(gateway_config, test_decode_valid_map_any_order)
{
	const uint8_t payload[] = {
		0xa2,
		0x65, 'o', 't', 'h', 'e', 'r', 0x82, 0x01, 0x02,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x05,
	};
	int8_t tx_power = 0;

	zassert_ok(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
						     &tx_power));
	zassert_equal(tx_power, 5);
}

ZTEST(gateway_config, test_decode_valid_negative_tx_power)
{
	const uint8_t payload[] = {
		0xa1,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x28, /* -9 */
	};
	int8_t tx_power = 0;

	zassert_ok(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
						     &tx_power));
	zassert_equal(tx_power, -9);
}

ZTEST(gateway_config, test_decode_rejects_malformed_cbor)
{
	const uint8_t payload[] = {
		0xa1,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x18,
	};
	int8_t tx_power = 14;

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&tx_power),
		      -EINVAL);
	zassert_equal(tx_power, 14);
}

ZTEST(gateway_config, test_decode_rejects_malformed_unknown_extension)
{
	const uint8_t payload[] = {
		0xa2,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x05,
		0x65, 'o', 't', 'h', 'e', 'r',
		0x18,
	};
	int8_t tx_power = 14;

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&tx_power),
		      -EINVAL);
	zassert_equal(tx_power, 14);
}

ZTEST(gateway_config, test_decode_rejects_list_payload)
{
	const uint8_t payload[] = {
		0x81, 0x05,
	};
	int8_t tx_power = 14;

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&tx_power),
		      -EINVAL);
	zassert_equal(tx_power, 14);
}

ZTEST(gateway_config, test_decode_rejects_unknown_only_map)
{
	const uint8_t payload[] = {
		0xa1, 0x65, 'o', 't', 'h', 'e', 'r', 0x05,
	};
	int8_t tx_power = 14;

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&tx_power),
		      -EINVAL);
	zassert_equal(tx_power, 14);
}

ZTEST(gateway_config, test_decode_rejects_out_of_range_tx_power)
{
	const uint8_t payload[] = {
		0xa1,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x18, 0x17,
	};
	int8_t tx_power = 14;

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&tx_power),
		      -EINVAL);
	zassert_equal(tx_power, 14);
}

ZTEST(gateway_config, test_encode_config_cbor)
{
	uint8_t buf[16];
	const uint8_t expected[] = {
		0xa1,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x0e,
	};
	size_t len = lichen_gateway_encode_config_cbor(buf, sizeof(buf), 14);

	zassert_equal(len, sizeof(expected));
	zassert_mem_equal(buf, expected, sizeof(expected));
}

ZTEST_SUITE(gateway_config, NULL, NULL, NULL, NULL, NULL);
