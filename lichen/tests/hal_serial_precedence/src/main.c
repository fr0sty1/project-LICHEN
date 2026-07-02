/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/ztest.h>

#include <lichen/hal.h>

#if DT_NODE_HAS_STATUS(DT_CHOSEN(lichen_native_uart), okay)
#define TEST_EXPECTED_SERIAL_NODE DT_CHOSEN(lichen_native_uart)
#define TEST_EXPECTED_SERIAL_CHOSEN "lichen,native-uart"
#elif DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_uart_pipe), okay)
#define TEST_EXPECTED_SERIAL_NODE DT_CHOSEN(zephyr_uart_pipe)
#define TEST_EXPECTED_SERIAL_CHOSEN "zephyr,uart-pipe"
#elif DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_slip_uart), okay)
#define TEST_EXPECTED_SERIAL_NODE DT_CHOSEN(zephyr_slip_uart)
#define TEST_EXPECTED_SERIAL_CHOSEN "zephyr,slip-uart"
#elif DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_shell_uart), okay)
#define TEST_EXPECTED_SERIAL_NODE DT_CHOSEN(zephyr_shell_uart)
#define TEST_EXPECTED_SERIAL_CHOSEN "zephyr,shell-uart"
#elif DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_console), okay)
#define TEST_EXPECTED_SERIAL_NODE DT_CHOSEN(zephyr_console)
#define TEST_EXPECTED_SERIAL_CHOSEN "zephyr,console"
#else
#error "hal_serial_precedence requires an okay chosen serial-local device"
#endif

ZTEST(hal_serial_precedence, test_serial_local_chosen_precedence)
{
	const struct lichen_hal_capabilities *caps = lichen_hal_capabilities_get();
	const struct device *expected = DEVICE_DT_GET(TEST_EXPECTED_SERIAL_NODE);
	const struct device *actual = NULL;

	zassert_true(IS_ENABLED(CONFIG_LICHEN_HAS_SERIAL_LOCAL));
	zassert_true((caps->flags & LICHEN_HAL_CAP_SERIAL_LOCAL) != 0U);
	zassert_true(device_is_ready(expected),
		     "%s expected device must be ready",
		     TEST_EXPECTED_SERIAL_CHOSEN);

	zassert_equal(lichen_hal_serial_local_status(), 0);
	zassert_equal(lichen_hal_capability_status(LICHEN_HAL_CAP_SERIAL_LOCAL), 0);
	zassert_equal(lichen_hal_serial_device_get(&actual), 0);
	zassert_not_null(actual);
	zassert_true(actual == expected,
		     "HAL selected %s instead of %s",
		     actual->name, expected->name);

	actual = (const struct device *)0x1;
	zassert_equal(lichen_hal_serial_device_get(NULL), -EINVAL);
	zassert_equal(lichen_hal_serial_device_get(&actual), 0);
	zassert_true(actual == expected);
}

ZTEST_SUITE(hal_serial_precedence, NULL, NULL, NULL, NULL, NULL);
