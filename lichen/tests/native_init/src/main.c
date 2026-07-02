/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>

#include <zephyr/ztest.h>

#include <lichen/native.h>

#if IS_ENABLED(CONFIG_LICHEN_HAS_SERIAL_LOCAL)
#define EXPECTED_NATIVE_INIT_RET 0
#else
#define EXPECTED_NATIVE_INIT_RET -ENOTSUP
#endif

static void native_init_rx(uint8_t msg_type, const uint8_t *buf, size_t len)
{
	ARG_UNUSED(msg_type);
	ARG_UNUSED(buf);
	ARG_UNUSED(len);
}

ZTEST(native_init, test_native_init_uses_hal_serial_local_status)
{
	zassert_equal(lichen_native_init(native_init_rx), EXPECTED_NATIVE_INIT_RET);
	zassert_equal(lichen_native_init(native_init_rx), EXPECTED_NATIVE_INIT_RET);
}

ZTEST_SUITE(native_init, NULL, NULL, NULL, NULL, NULL);
