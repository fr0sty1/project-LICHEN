/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include "ble_app_owner.h"
#include "ble_uart.h"

void ble_ingress_stub_reset(int return_value);
uint32_t ble_ingress_stub_call_count(void);
size_t ble_ingress_stub_last_len(void);
int ble_ingress_stub_copy_last(uint8_t *buf, size_t cap);

#define TEST_NUS_UUID_VAL \
	BT_UUID_128_ENCODE(0x6e400001, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)
#define TEST_NUS_RX_UUID_VAL \
	BT_UUID_128_ENCODE(0x6e400002, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)
#define TEST_NUS_TX_UUID_VAL \
	BT_UUID_128_ENCODE(0x6e400003, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)
#define TEST_LCI_UUID_VAL \
	BT_UUID_128_ENCODE(0xe665960c, 0x7c84, 0x5606, 0xa8d3, 0x884507d0b7a8)
#define TEST_LCI_RX_UUID_VAL \
	BT_UUID_128_ENCODE(0x5e6e304a, 0x29af, 0x52d9, 0xa813, 0x306f0f888586)
#define TEST_LCI_TX_UUID_VAL \
	BT_UUID_128_ENCODE(0xbe4d4a23, 0x876b, 0x592b, 0xb252, 0x440367e18e43)
#define TEST_LCI_VERSION_UUID_VAL \
	BT_UUID_128_ENCODE(0x9158dca0, 0x14ea, 0x5e1c, 0x8580, 0xb97e7c6381b8)
#define TEST_LCI_CAPABILITIES_UUID_VAL \
	BT_UUID_128_ENCODE(0x3d3c63f3, 0xce23, 0x5451, 0xb357, 0x738a12c20df7)

static const uint8_t s_nus_uuid_value[] = { TEST_NUS_UUID_VAL };
static const uint8_t s_nus_rx_uuid_value[] = { TEST_NUS_RX_UUID_VAL };
static const uint8_t s_nus_tx_uuid_value[] = { TEST_NUS_TX_UUID_VAL };
static const uint8_t s_lci_uuid_value[] = { TEST_LCI_UUID_VAL };
static const uint8_t s_lci_rx_uuid_value[] = { TEST_LCI_RX_UUID_VAL };
static const uint8_t s_lci_tx_uuid_value[] = { TEST_LCI_TX_UUID_VAL };
static const uint8_t s_lci_version_uuid_value[] = {
	TEST_LCI_VERSION_UUID_VAL
};
static const uint8_t s_lci_capabilities_uuid_value[] = {
	TEST_LCI_CAPABILITIES_UUID_VAL
};

static const struct bt_data s_native_ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, TEST_NUS_UUID_VAL),
};

static const struct bt_data s_named_sd[] = {
	BT_DATA(BT_DATA_NAME_SHORTENED, "LICHEN", sizeof("LICHEN") - 1U),
};

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

static bool compiled_surface_enabled(enum ble_app_owner_surface surface)
{
	switch (surface) {
	case BLE_APP_OWNER_SURFACE_NATIVE:
		return IS_ENABLED(CONFIG_LORA_LICHEN_BLE);
	case BLE_APP_OWNER_SURFACE_MESHTASTIC:
		return IS_ENABLED(CONFIG_LORA_LICHEN_MESHTASTIC_BLE);
	case BLE_APP_OWNER_SURFACE_MESHCORE:
		return IS_ENABLED(CONFIG_LORA_LICHEN_MESHCORE_BLE);
	default:
		return false;
	}
}

static bool any_compiled_surface_enabled(void)
{
	return IS_ENABLED(CONFIG_LORA_LICHEN_BLE) ||
	       IS_ENABLED(CONFIG_LORA_LICHEN_MESHTASTIC_BLE) ||
	       IS_ENABLED(CONFIG_LORA_LICHEN_MESHCORE_BLE);
}

static bool surface_can_start(enum ble_app_owner_surface surface)
{
	if (!any_compiled_surface_enabled()) {
		return true;
	}

	return compiled_surface_enabled(surface);
}

static int expect_start_for_surface(const struct ble_app_owner_advertising *adv)
{
	const int ret = ble_app_owner_start(adv);

	if (surface_can_start(adv->surface)) {
		zassert_ok(ret);
	} else {
		zassert_equal(ret, -ENOTSUP);
	}

	return ret;
}

static void owner_before(void *fixture)
{
	ARG_UNUSED(fixture);
	ble_app_owner_test_reset();
}

ZTEST(ble_app_owner, test_current_product_modes_are_mutually_exclusive)
{
	zassert_ok(ble_app_owner_test_validate_modes(false, false, false));
	zassert_ok(ble_app_owner_test_validate_modes(true, false, false));
	zassert_ok(ble_app_owner_test_validate_modes(false, true, false));
	zassert_ok(ble_app_owner_test_validate_modes(false, false, true));
	zassert_equal(ble_app_owner_test_validate_modes(true, true, false),
		      -ENOTSUP);
	zassert_equal(ble_app_owner_test_validate_modes(true, false, true),
		      -ENOTSUP);
	zassert_equal(ble_app_owner_test_validate_modes(false, true, true),
		      -ENOTSUP);
	zassert_equal(ble_app_owner_test_validate_modes(true, true, true),
		      -ENOTSUP);
}

ZTEST(ble_app_owner, test_native_advertising_shape_validates)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.name = "LICHEN",
	};

	zassert_ok(ble_app_owner_test_validate_advertising(&adv));
}

ZTEST(ble_app_owner, test_meshtastic_scan_response_shape_validates)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "LICHEN",
	};

	zassert_ok(ble_app_owner_test_validate_advertising(&adv));
}

ZTEST(ble_app_owner, test_invalid_advertising_is_deterministic)
{
	const struct ble_app_owner_advertising no_ad = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.name = "LICHEN",
	};
	const struct ble_app_owner_advertising sd_without_data = {
		.surface = BLE_APP_OWNER_SURFACE_MESHCORE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd_len = 1U,
		.name = "MeshCore-LICHEN",
	};
	const struct ble_app_owner_advertising no_name = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
	};
	const struct ble_app_owner_advertising bad_surface = {
		.surface = (enum ble_app_owner_surface)99,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.name = "LICHEN",
	};

	zassert_equal(ble_app_owner_test_validate_advertising(NULL), -EINVAL);
	zassert_equal(ble_app_owner_test_validate_advertising(&no_ad), -EINVAL);
	zassert_equal(ble_app_owner_test_validate_advertising(&sd_without_data),
		      -EINVAL);
	zassert_equal(ble_app_owner_test_validate_advertising(&no_name), -EINVAL);
	zassert_equal(ble_app_owner_test_validate_advertising(&bad_surface),
		      -EINVAL);
}

ZTEST(ble_app_owner, test_start_is_single_enable_and_advertising_owner)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "LICHEN",
	};
	struct ble_app_owner_test_state state;

	if (expect_start_for_surface(&adv) < 0) {
		return;
	}
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
	zassert_true(state.has_surface);
	zassert_equal(state.surface, BLE_APP_OWNER_SURFACE_MESHTASTIC);
	zassert_equal_ptr(state.ad, s_native_ad);
	zassert_equal(state.ad_len, ARRAY_SIZE(s_native_ad));
	zassert_equal_ptr(state.sd, s_named_sd);
	zassert_equal(state.sd_len, ARRAY_SIZE(s_named_sd));

	zassert_ok(ble_app_owner_start(&adv));
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
}

ZTEST(ble_app_owner, test_conflicting_surface_does_not_prepare_or_advertise)
{
	const struct ble_app_owner_advertising first = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.name = "LICHEN",
	};
	const struct ble_app_owner_advertising second = {
		.surface = BLE_APP_OWNER_SURFACE_MESHCORE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "MeshCore-LICHEN",
	};
	struct ble_app_owner_test_state state;

	if (expect_start_for_surface(&first) < 0) {
		return;
	}
	zassert_equal(ble_app_owner_start(&second),
		      surface_can_start(second.surface) ? -EALREADY : -ENOTSUP);
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
	zassert_equal(state.surface, BLE_APP_OWNER_SURFACE_NATIVE);
}

ZTEST(ble_app_owner, test_restart_reuses_stored_advertising)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_MESHCORE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "MeshCore-LICHEN",
	};
	struct ble_app_owner_test_state state;

	zassert_equal(ble_app_owner_restart(BLE_APP_OWNER_SURFACE_MESHCORE),
		      -EINVAL);
	if (expect_start_for_surface(&adv) < 0) {
		return;
	}
	zassert_ok(ble_app_owner_restart(BLE_APP_OWNER_SURFACE_MESHCORE));
	zassert_equal(ble_app_owner_restart(BLE_APP_OWNER_SURFACE_MESHTASTIC),
		      -EINVAL);

	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 2U);
	zassert_equal(state.surface, BLE_APP_OWNER_SURFACE_MESHCORE);
	zassert_equal_ptr(state.ad, s_native_ad);
	zassert_equal_ptr(state.sd, s_named_sd);
}

ZTEST(ble_app_owner, test_stop_clears_active_advertising_owner)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "LICHEN",
	};
	struct ble_app_owner_test_state state;

	zassert_equal(ble_app_owner_stop(BLE_APP_OWNER_SURFACE_MESHTASTIC),
		      -EINVAL);
	if (expect_start_for_surface(&adv) < 0) {
		return;
	}
	zassert_equal(ble_app_owner_stop(BLE_APP_OWNER_SURFACE_NATIVE),
		      -EINVAL);
	zassert_ok(ble_app_owner_stop(BLE_APP_OWNER_SURFACE_MESHTASTIC));
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
	zassert_equal(state.adv_stop_count, 1U);
	zassert_false(state.has_surface);

	zassert_ok(ble_app_owner_restart(BLE_APP_OWNER_SURFACE_MESHTASTIC));
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.adv_start_count, 2U);
	zassert_true(state.has_surface);
}

ZTEST(ble_app_owner, test_backend_failures_are_reported)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.name = "LICHEN",
	};

	ble_app_owner_test_set_backend(-EIO, 0, 0);
	if (surface_can_start(adv.surface)) {
		zassert_equal(ble_app_owner_start(&adv), -EIO);
	} else {
		zassert_equal(ble_app_owner_start(&adv), -ENOTSUP);
	}

	ble_app_owner_test_reset();
	ble_app_owner_test_set_backend(0, -EIO, 0);
	if (surface_can_start(adv.surface)) {
		zassert_equal(ble_app_owner_start(&adv), -EIO);
	} else {
		zassert_equal(ble_app_owner_start(&adv), -ENOTSUP);
	}

	ble_app_owner_test_reset();
	if (expect_start_for_surface(&adv) < 0) {
		return;
	}
	ble_app_owner_test_set_backend(0, 0, -EIO);
	zassert_equal(ble_app_owner_stop(BLE_APP_OWNER_SURFACE_NATIVE), -EIO);
}

ZTEST(ble_app_owner, test_compiled_product_mode_accepts_only_matching_surface)
{
	const struct ble_app_owner_advertising native = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.name = "LICHEN",
	};
	const struct ble_app_owner_advertising meshtastic = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "LICHEN",
	};
	const struct ble_app_owner_advertising meshcore = {
		.surface = BLE_APP_OWNER_SURFACE_MESHCORE,
		.ad = s_native_ad,
		.ad_len = ARRAY_SIZE(s_native_ad),
		.sd = s_named_sd,
		.sd_len = ARRAY_SIZE(s_named_sd),
		.name = "MeshCore-LICHEN",
	};

	(void)expect_start_for_surface(&native);
	ble_app_owner_test_reset();
	(void)expect_start_for_surface(&meshtastic);
	ble_app_owner_test_reset();
	(void)expect_start_for_surface(&meshcore);
}

ZTEST(ble_app_owner, test_native_init_uses_owner_advertising)
{
	struct ble_app_owner_test_state state;
	const uint8_t *expected_service_uuid =
		IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS) ?
		s_nus_uuid_value : s_lci_uuid_value;

	if (!IS_ENABLED(CONFIG_LORA_LICHEN_BLE)) {
		ztest_test_skip();
	}

	zassert_ok(ble_uart_init());
	zassert_ok(ble_app_owner_test_copy_state(&state));
	zassert_equal(state.enable_count, 1U);
	zassert_equal(state.adv_start_count, 1U);
	zassert_equal(state.surface, BLE_APP_OWNER_SURFACE_NATIVE);
	zassert_equal(state.ad_len, 2U);
	zassert_equal(state.sd_len, 0U);
	assert_flags_data(&state.ad[0]);
	assert_uuid128_data(&state.ad[1], expected_service_uuid);
	zassert_true((state.adv_options & BT_LE_ADV_OPT_CONNECTABLE) != 0U);
	zassert_true((state.adv_options & BT_LE_ADV_OPT_USE_NAME) != 0U);
	zassert_true(state.has_connected);
	zassert_true(state.has_disconnected);
}

ZTEST(ble_app_owner, test_native_profile_uuid_contract)
{
	struct ble_uart_test_profile profile;
	struct ble_uart_test_gatt_shape shape;
	const bool legacy = IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS);
	uint8_t read_buf[4] = { 0 };

	if (!IS_ENABLED(CONFIG_LORA_LICHEN_BLE)) {
		ztest_test_skip();
	}

	zassert_ok(ble_uart_test_copy_profile(&profile));
	zassert_ok(ble_uart_test_copy_gatt_shape(&shape));
	zassert_equal(profile.legacy_nus, legacy);
	zassert_equal(profile.has_version_capabilities, !legacy);
	zassert_equal(shape.attr_count, legacy ? 6U : 10U);
	zassert_equal(shape.rx_chrc_props, BT_GATT_CHRC_WRITE_WITHOUT_RESP);
	zassert_equal(shape.tx_chrc_props, BT_GATT_CHRC_NOTIFY);
	zassert_equal(shape.rx_value_perm, BT_GATT_PERM_WRITE);
	zassert_equal(shape.tx_value_perm, BT_GATT_PERM_NONE);
	zassert_equal(shape.tx_ccc_perm, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE);
	zassert_true(shape.rx_has_write);
	zassert_true(shape.tx_has_read_write);

	if (legacy) {
		zassert_mem_equal(profile.service_uuid, s_nus_uuid_value, 16U);
		zassert_mem_equal(profile.rx_uuid, s_nus_rx_uuid_value, 16U);
		zassert_mem_equal(profile.tx_uuid, s_nus_tx_uuid_value, 16U);
		zassert_mem_equal(shape.service_uuid, s_nus_uuid_value, 16U);
		zassert_mem_equal(shape.rx_chrc_uuid, s_nus_rx_uuid_value,
				  16U);
		zassert_mem_equal(shape.rx_value_uuid, s_nus_rx_uuid_value,
				  16U);
		zassert_mem_equal(shape.tx_chrc_uuid, s_nus_tx_uuid_value,
				  16U);
		zassert_mem_equal(shape.tx_value_uuid, s_nus_tx_uuid_value,
				  16U);
		zassert_mem_equal(profile.version_uuid, ((uint8_t[16]){ 0 }),
				  16U);
		zassert_mem_equal(profile.capabilities_uuid,
				  ((uint8_t[16]){ 0 }), 16U);
		zassert_mem_equal(profile.version, ((uint8_t[2]){ 0 }), 2U);
		zassert_mem_equal(profile.capabilities, ((uint8_t[4]){ 0 }),
				  4U);
		zassert_equal(ble_uart_test_read_version(read_buf,
							 sizeof(read_buf), 0U),
			      -ENOTSUP);
		zassert_equal(ble_uart_test_read_capabilities(read_buf,
							      sizeof(read_buf),
							      0U),
			      -ENOTSUP);
	} else {
		zassert_mem_equal(profile.service_uuid, s_lci_uuid_value, 16U);
		zassert_mem_equal(profile.rx_uuid, s_lci_rx_uuid_value, 16U);
		zassert_mem_equal(profile.tx_uuid, s_lci_tx_uuid_value, 16U);
		zassert_mem_equal(shape.service_uuid, s_lci_uuid_value, 16U);
		zassert_mem_equal(shape.rx_chrc_uuid, s_lci_rx_uuid_value,
				  16U);
		zassert_mem_equal(shape.rx_value_uuid, s_lci_rx_uuid_value,
				  16U);
		zassert_mem_equal(shape.tx_chrc_uuid, s_lci_tx_uuid_value,
				  16U);
		zassert_mem_equal(shape.tx_value_uuid, s_lci_tx_uuid_value,
				  16U);
		zassert_equal(shape.version_chrc_props, BT_GATT_CHRC_READ);
		zassert_equal(shape.capabilities_chrc_props, BT_GATT_CHRC_READ);
		zassert_equal(shape.version_value_perm, BT_GATT_PERM_READ);
		zassert_equal(shape.capabilities_value_perm, BT_GATT_PERM_READ);
		zassert_true(shape.version_has_read);
		zassert_true(shape.capabilities_has_read);
		zassert_mem_equal(profile.version_uuid,
				  s_lci_version_uuid_value, 16U);
		zassert_mem_equal(profile.capabilities_uuid,
				  s_lci_capabilities_uuid_value, 16U);
		zassert_mem_equal(shape.version_chrc_uuid,
				  s_lci_version_uuid_value, 16U);
		zassert_mem_equal(shape.version_value_uuid,
				  s_lci_version_uuid_value, 16U);
		zassert_mem_equal(shape.capabilities_chrc_uuid,
				  s_lci_capabilities_uuid_value, 16U);
		zassert_mem_equal(shape.capabilities_value_uuid,
				  s_lci_capabilities_uuid_value, 16U);
		zassert_mem_equal(profile.version, ((uint8_t[2]){ 1, 0 }),
				  2U);
		zassert_mem_equal(profile.capabilities,
				  ((uint8_t[4]){ BIT(0), 0, 0, 0 }), 4U);
		zassert_equal(ble_uart_test_read_version(read_buf,
							 sizeof(read_buf), 0U),
			      2);
		zassert_mem_equal(read_buf, ((uint8_t[2]){ 1, 0 }), 2U);
		memset(read_buf, 0, sizeof(read_buf));
		zassert_equal(ble_uart_test_read_capabilities(read_buf,
							      sizeof(read_buf),
							      0U),
			      4);
		zassert_mem_equal(read_buf, ((uint8_t[4]){ BIT(0), 0, 0, 0 }),
				  4U);
		memset(read_buf, 0, sizeof(read_buf));
		zassert_equal(ble_uart_test_read_capabilities(read_buf, 2U,
							      2U),
			      2);
		zassert_mem_equal(read_buf, ((uint8_t[2]){ 0, 0 }), 2U);
	}
}

ZTEST(ble_app_owner, test_native_rx_slip_fragmentation_and_overflow)
{
	const uint8_t frame_part1[] = { 0xc0, 0x60, 0xdb };
	const uint8_t frame_part2[] = { 0xdc, 0xdb, 0xdd, 0x01, 0xc0 };
	const uint8_t expected[] = { 0x60, 0xc0, 0xdb, 0x01 };
	uint8_t copied[sizeof(expected)];
	struct ble_uart_test_state uart_state;
	static uint8_t max_frame[1282];
	static uint8_t max_payload[1280];
	static uint8_t max_copied[1280];
	static uint8_t oversize[1283];

	if (!IS_ENABLED(CONFIG_LORA_LICHEN_BLE)) {
		ztest_test_skip();
	}

	ble_ingress_stub_reset(0);
	zassert_equal(ble_uart_test_write_rx(NULL, frame_part1,
					     sizeof(frame_part1)),
		      sizeof(frame_part1));
	zassert_equal(ble_ingress_stub_call_count(), 0U);
	zassert_ok(ble_uart_test_copy_state(&uart_state));
	zassert_equal(uart_state.rx_len, 1U);
	zassert_true(uart_state.rx_esc);

	zassert_equal(ble_uart_test_write_rx(NULL, frame_part2,
					     sizeof(frame_part2)),
		      sizeof(frame_part2));
	zassert_equal(ble_ingress_stub_call_count(), 1U);
	zassert_equal(ble_ingress_stub_last_len(), sizeof(expected));
	zassert_ok(ble_ingress_stub_copy_last(copied, sizeof(copied)));
	zassert_mem_equal(copied, expected, sizeof(expected));
	zassert_ok(ble_uart_test_copy_state(&uart_state));
	zassert_equal(uart_state.rx_len, 0U);
	zassert_false(uart_state.rx_esc);
	zassert_false(uart_state.rx_overflow);

	max_frame[0] = 0xc0;
	memset(max_payload, 0x60, sizeof(max_payload));
	memcpy(&max_frame[1], max_payload, sizeof(max_payload));
	max_frame[sizeof(max_frame) - 1U] = 0xc0;
	ble_ingress_stub_reset(0);
	zassert_equal(ble_uart_test_write_rx(NULL, max_frame, sizeof(max_frame)),
		      sizeof(max_frame));
	zassert_equal(ble_ingress_stub_call_count(), 1U);
	zassert_equal(ble_ingress_stub_last_len(), sizeof(max_payload));
	zassert_ok(ble_ingress_stub_copy_last(max_copied, sizeof(max_copied)));
	zassert_mem_equal(max_copied, max_payload, sizeof(max_payload));
	zassert_ok(ble_uart_test_copy_state(&uart_state));
	zassert_equal(uart_state.rx_len, 0U);
	zassert_false(uart_state.rx_overflow);

	oversize[0] = 0xc0;
	memset(&oversize[1], 0x42, sizeof(oversize) - 2U);
	oversize[sizeof(oversize) - 1U] = 0xc0;
	ble_ingress_stub_reset(0);
	zassert_equal(ble_uart_test_write_rx(NULL, oversize, sizeof(oversize)),
		      sizeof(oversize));
	zassert_equal(ble_ingress_stub_call_count(), 0U);
	zassert_ok(ble_uart_test_copy_state(&uart_state));
	zassert_equal(uart_state.rx_len, 0U);
	zassert_false(uart_state.rx_overflow);
}

ZTEST(ble_app_owner, test_native_connection_callbacks_are_owner_managed)
{
	struct ble_app_owner_test_state owner_state;
	struct ble_uart_test_state uart_state;
	struct ble_uart_test_tx_state tx_state;
	struct bt_conn *fake_conn = (struct bt_conn *)0x1;
	struct bt_conn *other_conn = (struct bt_conn *)0x2;
	struct bt_conn *owner_conn;
	const uint8_t sample_ipv6[] = { 0x60, 0x00, 0x00, 0x00 };
	const uint8_t escaped_ipv6[] = { 0x01, 0xc0, 0xdb, 0x02 };
	const uint8_t chunked_escaped_ipv6[] = {
		0x60, 0xc0, 0xdb, 0x01, 0x02, 0xc0, 0xdb, 0x03, 0x04
	};
	const uint8_t expected_slip[] = {
		0xc0, 0x01, 0xdb, 0xdc, 0xdb, 0xdd, 0x02, 0xc0
	};
	const uint8_t expected_chunked_slip[] = {
		0xc0, 0x60, 0xdb, 0xdc, 0xdb, 0xdd, 0x01, 0x02,
		0xdb, 0xdc, 0xdb, 0xdd, 0x03, 0x04, 0xc0
	};
	uint8_t expected_fragmented_slip[40];
	uint8_t fragmenting_ipv6[38];

	if (!IS_ENABLED(CONFIG_LORA_LICHEN_BLE)) {
		ztest_test_skip();
	}

	zassert_ok(ble_uart_init());
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_true(owner_state.has_connected);
	zassert_true(owner_state.has_disconnected);

	ble_uart_test_seed_rx_state(17U, true, true);
	ble_app_owner_test_connected(fake_conn, 0U);
	zassert_ok(ble_uart_test_copy_state(&uart_state));
	zassert_equal(uart_state.rx_len, 0U);
	zassert_false(uart_state.rx_esc);
	zassert_false(uart_state.rx_overflow);
	zassert_true(uart_state.has_connection);
	zassert_ok(ble_app_owner_conn_ref(BLE_APP_OWNER_SURFACE_NATIVE,
					  &owner_conn));
	zassert_equal_ptr(owner_conn, fake_conn);
	ble_app_owner_conn_unref(owner_conn);
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_equal(owner_state.conn_ref_count, 2U);
	zassert_equal(owner_state.conn_unref_count, 1U);

	ble_uart_test_set_tx_backend(64U, 0);
	zassert_ok(ble_uart_send_slip(escaped_ipv6, sizeof(escaped_ipv6)));
	zassert_ok(ble_uart_test_copy_tx_state(&tx_state));
	zassert_equal_ptr(tx_state.conn, fake_conn);
	zassert_equal(tx_state.notify_count, 1U);
	zassert_equal(tx_state.len, sizeof(expected_slip));
	zassert_equal(tx_state.total_len, sizeof(expected_slip));
	zassert_mem_equal(tx_state.data, expected_slip, sizeof(expected_slip));
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_equal(owner_state.conn_ref_count, 3U);
	zassert_equal(owner_state.conn_unref_count, 2U);

	memset(fragmenting_ipv6, 0x22, sizeof(fragmenting_ipv6));
	ble_uart_test_set_tx_backend(23U, 0);
	zassert_ok(ble_uart_send_slip(fragmenting_ipv6,
				      sizeof(fragmenting_ipv6)));
	zassert_ok(ble_uart_test_copy_tx_state(&tx_state));
	zassert_equal(tx_state.notify_count, 2U);
	zassert_equal(tx_state.len, 20U);
	zassert_equal(tx_state.total_len, sizeof(expected_fragmented_slip));
	expected_fragmented_slip[0] = 0xc0;
	memcpy(&expected_fragmented_slip[1], fragmenting_ipv6,
	       sizeof(fragmenting_ipv6));
	expected_fragmented_slip[sizeof(expected_fragmented_slip) - 1U] = 0xc0;
	zassert_mem_equal(tx_state.data, expected_fragmented_slip,
			  sizeof(expected_fragmented_slip));
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_equal(owner_state.conn_ref_count, 4U);
	zassert_equal(owner_state.conn_unref_count, 3U);

	ble_uart_test_set_tx_backend(8U, 0);
	zassert_ok(ble_uart_send_slip(chunked_escaped_ipv6,
				      sizeof(chunked_escaped_ipv6)));
	zassert_ok(ble_uart_test_copy_tx_state(&tx_state));
	zassert_equal_ptr(tx_state.conn, fake_conn);
	zassert_equal(tx_state.notify_count, 3U);
	zassert_equal(tx_state.chunk_len[0], 5U);
	zassert_equal(tx_state.chunk_len[1], 5U);
	zassert_equal(tx_state.chunk_len[2], 5U);
	zassert_equal(tx_state.len, 5U);
	zassert_equal(tx_state.total_len, sizeof(expected_chunked_slip));
	zassert_mem_equal(tx_state.data, expected_chunked_slip,
			  sizeof(expected_chunked_slip));
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_equal(owner_state.conn_ref_count, 5U);
	zassert_equal(owner_state.conn_unref_count, 4U);

	ble_uart_test_set_tx_backend(8U, -EIO);
	zassert_equal(ble_uart_send_slip(chunked_escaped_ipv6,
					 sizeof(chunked_escaped_ipv6)),
		      -EIO);
	zassert_ok(ble_uart_test_copy_tx_state(&tx_state));
	zassert_equal_ptr(tx_state.conn, fake_conn);
	zassert_equal(tx_state.notify_count, 1U);
	zassert_equal(tx_state.chunk_len[0], 5U);
	zassert_equal(tx_state.total_len, 5U);
	zassert_mem_equal(tx_state.data, expected_chunked_slip, 5U);
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_equal(owner_state.conn_ref_count, 6U);
	zassert_equal(owner_state.conn_unref_count, 5U);

	ble_uart_test_seed_rx_state(23U, true, true);
	ble_app_owner_test_disconnected(other_conn, 19U);
	zassert_ok(ble_uart_test_copy_state(&uart_state));
	zassert_equal(uart_state.rx_len, 23U);
	zassert_true(uart_state.rx_esc);
	zassert_true(uart_state.rx_overflow);
	zassert_true(uart_state.has_connection);
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_equal(owner_state.adv_start_count, 1U);

	ble_app_owner_test_disconnected(fake_conn, 19U);
	zassert_ok(ble_uart_test_copy_state(&uart_state));
	zassert_equal(uart_state.rx_len, 0U);
	zassert_false(uart_state.rx_esc);
	zassert_false(uart_state.rx_overflow);
	zassert_false(uart_state.has_connection);
	zassert_ok(ble_app_owner_test_copy_state(&owner_state));
	zassert_equal(owner_state.adv_start_count, 2U);
	zassert_equal(owner_state.conn_ref_count, 6U);
	zassert_equal(owner_state.conn_unref_count, 6U);

	zassert_equal(ble_uart_send_slip(sample_ipv6, sizeof(sample_ipv6)),
		      -ENOTCONN);
}

ZTEST_SUITE(ble_app_owner, NULL, NULL, owner_before, NULL, NULL);
