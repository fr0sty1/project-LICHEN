/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>
#include <errno.h>

#include <lichen/hal.h>

#include "config_apply.h"
#include "config_cbor.h"

ZTEST(gateway_config, test_decode_valid_map_any_order)
{
	const uint8_t payload[] = {
		0xa2,
		0x65, 'o', 't', 'h', 'e', 'r', 0x82, 0x01, 0x02,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x05,
	};
	struct lichen_gateway_config_update update;

	zassert_ok(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
						     &update));
	zassert_true(update.has_tx_power_dbm);
	zassert_equal(update.tx_power_dbm, 5);
	zassert_false(update.has_manual_location);
}

ZTEST(gateway_config, test_decode_valid_negative_tx_power)
{
	const uint8_t payload[] = {
		0xa1,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x28, /* -9 */
	};
	struct lichen_gateway_config_update update;

	zassert_ok(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
						     &update));
	zassert_true(update.has_tx_power_dbm);
	zassert_equal(update.tx_power_dbm, -9);
}

ZTEST(gateway_config, test_decode_manual_static_location)
{
	const uint8_t payload[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa5,
		0x65, 'l', 'a', 't', '_', 'i',
		0x1a, 0x1c, 0x62, 0x54, 0x32, /* 476206130 */
		0x65, 'l', 'o', 'n', '_', 'i',
		0x3a, 0x48, 0xed, 0x05, 0x87, /* -1223493000 */
		0x67, 'h', 'a', 'c', 'c', '_', 'm', 'm',
		0x19, 0x09, 0xc4, /* 2500 */
		0x6b, 's', 'o', 'u', 'r', 'c', 'e', '_', 'n', 'a', 'm', 'e',
		0x6d, 'c', 'o', 'n', 'f', 'i', 'g', '-', 's', 't', 'a', 't', 'i', 'c',
		0x65, 'a', 'g', 'e', '_', 's',
		0x18, 0x02,
	};
	struct lichen_gateway_config_update update;

	zassert_ok(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
						     &update));
	zassert_false(update.has_tx_power_dbm);
	zassert_true(update.has_manual_location);
	zassert_true(update.manual_location.latitude_e7_valid);
	zassert_equal(update.manual_location.latitude_e7, 476206130);
	zassert_true(update.manual_location.longitude_e7_valid);
	zassert_equal(update.manual_location.longitude_e7, -1223493000);
	zassert_true(update.manual_location.horizontal_accuracy_mm_valid);
	zassert_equal(update.manual_location.horizontal_accuracy_mm, 2500U);
	zassert_true(update.manual_location.age_seconds_valid);
	zassert_equal(update.manual_location.age_seconds, 2U);
	zassert_str_equal(update.manual_location.source_name, "config-static");
}

ZTEST(gateway_config, test_decode_rejects_malformed_cbor)
{
	const uint8_t payload[] = {
		0xa1,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x18,
	};
	struct lichen_gateway_config_update update = {
		.has_tx_power_dbm = true,
		.tx_power_dbm = 14,
	};

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&update),
		      -EINVAL);
	zassert_false(update.has_tx_power_dbm);
}

ZTEST(gateway_config, test_decode_rejects_trailing_bytes)
{
	const uint8_t payload[] = {
		0xa1,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x05,
		0x00,
	};
	struct lichen_gateway_config_update update = { 0 };

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&update),
		      -EINVAL);
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
	struct lichen_gateway_config_update update = { 0 };

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&update),
		      -EINVAL);
}

ZTEST(gateway_config, test_decode_rejects_list_payload)
{
	const uint8_t payload[] = {
		0x81, 0x05,
	};
	struct lichen_gateway_config_update update = { 0 };

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&update),
		      -EINVAL);
}

ZTEST(gateway_config, test_decode_rejects_unknown_only_map)
{
	const uint8_t payload[] = {
		0xa1, 0x65, 'o', 't', 'h', 'e', 'r', 0x05,
	};
	struct lichen_gateway_config_update update = { 0 };

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&update),
		      -EINVAL);
}

ZTEST(gateway_config, test_decode_rejects_out_of_range_tx_power)
{
	const uint8_t payload[] = {
		0xa1,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x18, 0x17,
	};
	struct lichen_gateway_config_update update = { 0 };

	zassert_equal(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
							&update),
		      -EINVAL);
}

ZTEST(gateway_config, test_decode_rejects_duplicate_config_keys)
{
	const uint8_t duplicate_tx[] = {
		0xa2,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x05,
		0x6c, 't', 'x', '_', 'p', 'o', 'w', 'e', 'r', '_', 'd', 'b', 'm',
		0x06,
	};
	const uint8_t duplicate_manual[] = {
		0xa2,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa2,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x02,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa1,
		0x65, 'l', 'a', 't', '_', 'i', 0x03,
	};
	struct lichen_gateway_config_update update = { 0 };

	zassert_equal(lichen_gateway_decode_config_cbor(duplicate_tx,
							sizeof(duplicate_tx),
							&update),
		      -EINVAL);
	zassert_equal(lichen_gateway_decode_config_cbor(duplicate_manual,
							sizeof(duplicate_manual),
							&update),
		      -EINVAL);
}

ZTEST(gateway_config, test_decode_rejects_duplicate_manual_location_fields)
{
	const uint8_t duplicate_lat[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa3,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'a', 't', '_', 'i', 0x02,
		0x65, 'l', 'o', 'n', '_', 'i', 0x03,
	};
	const uint8_t duplicate_empty_source_name[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa4,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x02,
		0x6b, 's', 'o', 'u', 'r', 'c', 'e', '_', 'n', 'a', 'm', 'e', 0x60,
		0x6b, 's', 'o', 'u', 'r', 'c', 'e', '_', 'n', 'a', 'm', 'e',
		0x66, 'm', 'a', 'n', 'u', 'a', 'l',
	};
	const uint8_t duplicate_lon[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa3,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x02,
		0x65, 'l', 'o', 'n', '_', 'i', 0x03,
	};
	const uint8_t duplicate_hacc[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa4,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x02,
		0x67, 'h', 'a', 'c', 'c', '_', 'm', 'm', 0x03,
		0x67, 'h', 'a', 'c', 'c', '_', 'm', 'm', 0x04,
	};
	const uint8_t duplicate_age[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa4,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x02,
		0x65, 'a', 'g', 'e', '_', 's', 0x03,
		0x65, 'a', 'g', 'e', '_', 's', 0x04,
	};
	struct lichen_gateway_config_update update = { 0 };

	zassert_equal(lichen_gateway_decode_config_cbor(duplicate_lat,
							sizeof(duplicate_lat),
							&update),
		      -EINVAL);
	zassert_equal(lichen_gateway_decode_config_cbor(duplicate_lon,
							sizeof(duplicate_lon),
							&update),
		      -EINVAL);
	zassert_equal(lichen_gateway_decode_config_cbor(duplicate_hacc,
							sizeof(duplicate_hacc),
							&update),
		      -EINVAL);
	zassert_equal(lichen_gateway_decode_config_cbor(duplicate_age,
							sizeof(duplicate_age),
							&update),
		      -EINVAL);
	zassert_equal(lichen_gateway_decode_config_cbor(
			      duplicate_empty_source_name,
			      sizeof(duplicate_empty_source_name), &update),
		      -EINVAL);
}

ZTEST(gateway_config, test_decode_manual_location_skips_nested_extensions)
{
	const uint8_t payload[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa4,
		0x65, 'l', 'a', 't', '_', 'i',
		0x1a, 0x1c, 0x62, 0x54, 0x32,
		0x63, 'e', 'x', 't',
		0xa2,
		0x66, 'n', 'e', 's', 't', 'e', 'd',
		0x82, 0x01, 0xa1, 0x61, 'x', 0x02,
		0x63, 'a', 'r', 'r',
		0x82, 0x03, 0x04,
		0x65, 'l', 'o', 'n', '_', 'i',
		0x3a, 0x48, 0xed, 0x05, 0x87,
		0x65, 'a', 'g', 'e', '_', 's',
		0x18, 0x02,
	};
	struct lichen_gateway_config_update update = { 0 };

	zassert_ok(lichen_gateway_decode_config_cbor(payload, sizeof(payload),
						     &update));
	zassert_true(update.has_manual_location);
	zassert_equal(update.manual_location.latitude_e7, 476206130);
	zassert_equal(update.manual_location.longitude_e7, -1223493000);
	zassert_true(update.manual_location.age_seconds_valid);
	zassert_equal(update.manual_location.age_seconds, 2U);
}

ZTEST(gateway_config, test_decode_rejects_invalid_manual_source_name_bytes)
{
	const uint8_t embedded_nul[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa3,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x02,
		0x6b, 's', 'o', 'u', 'r', 'c', 'e', '_', 'n', 'a', 'm', 'e',
		0x63, 'a', 0x00, 'b',
	};
	const uint8_t newline[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa3,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x02,
		0x6b, 's', 'o', 'u', 'r', 'c', 'e', '_', 'n', 'a', 'm', 'e',
		0x63, 'a', '\n', 'b',
	};
	const uint8_t del[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa3,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x02,
		0x6b, 's', 'o', 'u', 'r', 'c', 'e', '_', 'n', 'a', 'm', 'e',
		0x63, 'a', 0x7f, 'b',
	};
	const uint8_t utf8[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa3,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x02,
		0x6b, 's', 'o', 'u', 'r', 'c', 'e', '_', 'n', 'a', 'm', 'e',
		0x63, 'c', 0xc3, 0xa9,
	};
	const uint8_t too_long[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa3,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x02,
		0x6b, 's', 'o', 'u', 'r', 'c', 'e', '_', 'n', 'a', 'm', 'e',
		0x78, 0x18, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
		'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
	};
	struct lichen_gateway_config_update update = { 0 };

	zassert_equal(lichen_gateway_decode_config_cbor(embedded_nul,
							sizeof(embedded_nul),
							&update),
		      -EINVAL);
	zassert_equal(lichen_gateway_decode_config_cbor(newline,
							sizeof(newline),
							&update),
		      -EINVAL);
	zassert_equal(lichen_gateway_decode_config_cbor(del, sizeof(del),
							&update),
		      -EINVAL);
	zassert_equal(lichen_gateway_decode_config_cbor(utf8, sizeof(utf8),
							&update),
		      -EINVAL);
	zassert_equal(lichen_gateway_decode_config_cbor(too_long,
							sizeof(too_long),
							&update),
		      -ENAMETOOLONG);
}

ZTEST(gateway_config, test_decode_rejects_invalid_manual_location)
{
	const uint8_t missing_lon[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa1,
		0x65, 'l', 'a', 't', '_', 'i', 0x01,
	};
	const uint8_t bad_lat[] = {
		0xa1,
		0x6f, 'm', 'a', 'n', 'u', 'a', 'l', '_', 'l', 'o', 'c', 'a', 't', 'i', 'o', 'n',
		0xa2,
		0x65, 'l', 'a', 't', '_', 'i', 0x1a, 0x35, 0xa4, 0xe9, 0x01,
		0x65, 'l', 'o', 'n', '_', 'i', 0x01,
	};
	struct lichen_gateway_config_update update = { 0 };

	zassert_equal(lichen_gateway_decode_config_cbor(missing_lon,
							sizeof(missing_lon),
							&update),
		      -EINVAL);
	zassert_equal(lichen_gateway_decode_config_cbor(bad_lat, sizeof(bad_lat),
							&update),
		      -EINVAL);
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

ZTEST(gateway_config, test_encode_config_cbor_with_manual_location)
{
	const struct lichen_gateway_manual_location_config manual = {
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
		.horizontal_accuracy_mm_valid = true,
		.horizontal_accuracy_mm = 2500U,
		.age_seconds_valid = true,
		.age_seconds = 2U,
		.source_name = "config-static",
	};
	uint8_t buf[160];
	struct lichen_gateway_config_update update;
	size_t len = lichen_gateway_encode_config_update_cbor(
		buf, sizeof(buf), 14, &manual);

	zassert_true(len > 0U);
	zassert_ok(lichen_gateway_decode_config_cbor(buf, len, &update));
	zassert_true(update.has_tx_power_dbm);
	zassert_equal(update.tx_power_dbm, 14);
	zassert_true(update.has_manual_location);
	zassert_equal(update.manual_location.latitude_e7, 476206130);
	zassert_equal(update.manual_location.longitude_e7, -1223493000);
	zassert_equal(update.manual_location.horizontal_accuracy_mm, 2500U);
	zassert_equal(update.manual_location.age_seconds, 2U);
	zassert_str_equal(update.manual_location.source_name, "config-static");
}

ZTEST(gateway_config, test_encode_rejects_invalid_manual_location)
{
	struct lichen_gateway_manual_location_config manual = {
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
	};
	uint8_t buf[160];

	manual.latitude_e7_valid = false;
	zassert_equal(lichen_gateway_encode_config_update_cbor(
			      buf, sizeof(buf), 14, &manual),
		      0U);

	manual.latitude_e7_valid = true;
	manual.longitude_e7_valid = false;
	zassert_equal(lichen_gateway_encode_config_update_cbor(
			      buf, sizeof(buf), 14, &manual),
		      0U);

	manual.longitude_e7_valid = true;
	manual.latitude_e7 = 900000001;
	zassert_equal(lichen_gateway_encode_config_update_cbor(
			      buf, sizeof(buf), 14, &manual),
		      0U);

	manual.latitude_e7 = 476206130;
	manual.longitude_e7 = 1800000001;
	zassert_equal(lichen_gateway_encode_config_update_cbor(
			      buf, sizeof(buf), 14, &manual),
		      0U);

	manual.longitude_e7 = -1223493000;
	manual.source_name[0] = 'a';
	manual.source_name[1] = '\n';
	manual.source_name[2] = '\0';
	zassert_equal(lichen_gateway_encode_config_update_cbor(
			      buf, sizeof(buf), 14, &manual),
		      0U);

	memset(manual.source_name, 'a', sizeof(manual.source_name));
	zassert_equal(lichen_gateway_encode_config_update_cbor(
			      buf, sizeof(buf), 14, &manual),
		      0U);
}

ZTEST(gateway_config, test_encode_config_update_small_buffer_returns_zero)
{
	const struct lichen_gateway_manual_location_config manual = {
		.latitude_e7_valid = true,
		.latitude_e7 = 476206130,
		.longitude_e7_valid = true,
		.longitude_e7 = -1223493000,
		.horizontal_accuracy_mm_valid = true,
		.horizontal_accuracy_mm = 2500U,
		.age_seconds_valid = true,
		.age_seconds = 2U,
		.source_name = "config-static",
	};
	uint8_t buf[8];

	zassert_equal(lichen_gateway_encode_config_update_cbor(
			      buf, sizeof(buf), 14, NULL),
		      0U);
	zassert_equal(lichen_gateway_encode_config_update_cbor(
			      buf, sizeof(buf), 14, &manual),
		      0U);
}

ZTEST(gateway_config, test_apply_manual_static_location_update)
{
	const struct lichen_hal_location_sample network = {
		.source_class = LICHEN_HAL_LOCATION_SOURCE_NETWORK,
		.fix_state = LICHEN_HAL_LOCATION_FIX_2D,
		.source_name = "mesh",
		.latitude_e7_valid = true,
		.latitude_e7 = 1,
		.longitude_e7_valid = true,
		.longitude_e7 = 2,
	};
	const struct lichen_gateway_config_update update = {
		.has_tx_power_dbm = true,
		.tx_power_dbm = 10,
		.has_manual_location = true,
		.manual_location = {
			.latitude_e7_valid = true,
			.latitude_e7 = 476206130,
			.longitude_e7_valid = true,
			.longitude_e7 = -1223493000,
			.horizontal_accuracy_mm_valid = true,
			.horizontal_accuracy_mm = 2500U,
			.source_name = "config-static",
		},
	};
	struct lichen_hal_location_time_snapshot snapshot;
	int8_t tx_power = 14;
	struct lichen_gateway_manual_location_config manual = { 0 };
	bool has_manual = false;

	lichen_hal_location_clear();
	zassert_ok(lichen_hal_location_submit(&network));
	zassert_ok(lichen_gateway_apply_config_update(&update, &tx_power,
						      &manual, &has_manual));
	zassert_equal(tx_power, 10);
	zassert_true(has_manual);
	zassert_equal(manual.latitude_e7, 476206130);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_true(snapshot.source_class_valid);
	zassert_equal(snapshot.source_class,
		      LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC);
	zassert_str_equal(snapshot.source_name, "config-static");
	zassert_true(snapshot.latitude_e7_valid);
	zassert_equal(snapshot.latitude_e7, 476206130);
	zassert_true(snapshot.horizontal_accuracy_mm_valid);
	zassert_equal(snapshot.horizontal_accuracy_mm, 2500U);
}

ZTEST(gateway_config, test_apply_config_update_is_atomic_on_manual_failure)
{
	const struct lichen_gateway_config_update update = {
		.has_tx_power_dbm = true,
		.tx_power_dbm = 10,
		.has_manual_location = true,
		.manual_location = {
			.latitude_e7_valid = true,
			.latitude_e7 = 476206130,
		},
	};
	int8_t tx_power = 14;
	struct lichen_gateway_manual_location_config manual = { 0 };
	bool has_manual = false;

	lichen_hal_location_clear();
	zassert_equal(lichen_gateway_apply_config_update(&update, &tx_power,
							&manual, &has_manual),
		      -EINVAL);
	zassert_equal(tx_power, 14);
	zassert_false(has_manual);
}

ZTEST(gateway_config, test_apply_stale_manual_static_location_suppresses_position)
{
	const struct lichen_gateway_config_update update = {
		.has_manual_location = true,
		.manual_location = {
			.latitude_e7_valid = true,
			.latitude_e7 = 476206130,
			.longitude_e7_valid = true,
			.longitude_e7 = -1223493000,
			.horizontal_accuracy_mm_valid = true,
			.horizontal_accuracy_mm = 2500U,
			.age_seconds_valid = true,
			.age_seconds = CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S + 1U,
			.source_name = "config-static",
		},
	};
	struct lichen_hal_location_time_snapshot snapshot;
	int8_t tx_power = 14;
	struct lichen_gateway_manual_location_config manual = { 0 };
	bool has_manual = false;

	lichen_hal_location_clear();
	lichen_hal_location_test_set_uptime_ms(
		(CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S + 10) * 1000LL);
	zassert_ok(lichen_gateway_apply_config_update(&update, &tx_power,
						      &manual, &has_manual));
	zassert_true(has_manual);
	zassert_ok(lichen_hal_location_time_snapshot_get(&snapshot));
	zassert_equal(snapshot.source_class,
		      LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC);
	zassert_str_equal(snapshot.source_name, "config-static");
	zassert_equal(snapshot.fix_state, LICHEN_HAL_LOCATION_FIX_STALE);
	zassert_false(snapshot.latitude_e7_valid);
	zassert_false(snapshot.longitude_e7_valid);
	zassert_false(snapshot.horizontal_accuracy_mm_valid);
}

ZTEST_SUITE(gateway_config, NULL, NULL, NULL, NULL, NULL);
