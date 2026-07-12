/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/*
 * GNSS emulator test for native_sim.
 *
 * Verifies that the GNSS emulator driver:
 * 1. Initializes and is ready
 * 2. Provides GNSS data callbacks
 * 3. Reports valid position data after fix acquisition
 */

#include <zephyr/drivers/gnss.h>
#include <zephyr/kernel.h>
#include <zephyr/pm/device.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/ztest.h>

/* The gnss_emul driver has a 5-second fix acquire time */
#define GNSS_FIX_ACQUIRE_WAIT_MS 6000
#define GNSS_CALLBACK_WAIT_MS    2000

static const struct device *gnss_dev = DEVICE_DT_GET(DT_ALIAS(gnss));

static atomic_t callback_count = ATOMIC_INIT(0);
static struct gnss_data last_data;
static K_SEM_DEFINE(data_sem, 0, 1);

static void gnss_data_cb(const struct device *dev, const struct gnss_data *data)
{
	if (dev == gnss_dev) {
		last_data = *data;
		atomic_inc(&callback_count);
		k_sem_give(&data_sem);
	}
}

GNSS_DATA_CALLBACK_DEFINE(DEVICE_DT_GET(DT_ALIAS(gnss)), gnss_data_cb);

static void *gnss_emul_setup(void)
{
	/* Ensure device is resumed for PM-enabled builds */
	if (pm_device_runtime_is_enabled(gnss_dev)) {
		int ret = pm_device_action_run(gnss_dev, PM_DEVICE_ACTION_RESUME);
		zassert_true(ret == 0 || ret == -EALREADY,
			     "Failed to resume GNSS device: %d", ret);
	}
	return NULL;
}

ZTEST(gnss_emul, test_device_ready)
{
	zassert_true(device_is_ready(gnss_dev),
		     "GNSS device not ready");
}

ZTEST(gnss_emul, test_data_callback)
{
	int ret;

	/* Reset callback count */
	atomic_set(&callback_count, 0);
	k_sem_reset(&data_sem);

	/* Wait for at least one callback */
	ret = k_sem_take(&data_sem, K_MSEC(GNSS_CALLBACK_WAIT_MS));
	zassert_ok(ret, "No GNSS data callback received within timeout");

	zassert_true(atomic_get(&callback_count) >= 1,
		     "Expected at least 1 callback, got %d",
		     atomic_get(&callback_count));
}

ZTEST(gnss_emul, test_fix_acquired)
{
	int ret;

	/* Reset state */
	atomic_set(&callback_count, 0);
	k_sem_reset(&data_sem);
	memset(&last_data, 0, sizeof(last_data));

	/* Wait for fix acquisition (gnss_emul has 5s acquire time) */
	k_sleep(K_MSEC(GNSS_FIX_ACQUIRE_WAIT_MS));

	/* Wait for a callback after fix should be acquired */
	ret = k_sem_take(&data_sem, K_MSEC(GNSS_CALLBACK_WAIT_MS));
	zassert_ok(ret, "No GNSS data after fix acquire wait");

	/* Verify we have a valid fix */
	zassert_equal(last_data.info.fix_status, GNSS_FIX_STATUS_GNSS_FIX,
		      "Expected GNSS fix, got status %d",
		      last_data.info.fix_status);

	zassert_equal(last_data.info.fix_quality, GNSS_FIX_QUALITY_GNSS_SPS,
		      "Expected SPS fix quality, got %d",
		      last_data.info.fix_quality);
}

ZTEST(gnss_emul, test_nav_data_valid)
{
	/* The gnss_emul driver returns hardcoded values:
	 * lat = 10000000000 (100 degrees in nano-degrees)
	 * lon = -10000000000 (-100 degrees)
	 * alt = 20000 (200m in cm? or mm?)
	 */

	/* Ensure we have data from a previous test or wait for it */
	if (atomic_get(&callback_count) == 0) {
		k_sleep(K_MSEC(GNSS_FIX_ACQUIRE_WAIT_MS + GNSS_CALLBACK_WAIT_MS));
	}

	/* Verify nav data is populated (non-zero for emulator) */
	zassert_not_equal(last_data.nav_data.latitude, 0,
			  "Latitude should be non-zero");
	zassert_not_equal(last_data.nav_data.longitude, 0,
			  "Longitude should be non-zero");
}

ZTEST(gnss_emul, test_get_fix_rate)
{
	uint32_t fix_interval;
	int ret;

	ret = gnss_get_fix_rate(gnss_dev, &fix_interval);
	zassert_ok(ret, "Failed to get fix rate: %d", ret);

	/* Default fix rate is 1000ms */
	zassert_equal(fix_interval, 1000,
		      "Expected 1000ms fix interval, got %u", fix_interval);
}

ZTEST(gnss_emul, test_set_fix_rate)
{
	uint32_t fix_interval;
	int ret;

	/* Set a different fix rate */
	ret = gnss_set_fix_rate(gnss_dev, 500);
	zassert_ok(ret, "Failed to set fix rate: %d", ret);

	/* Verify it was set */
	ret = gnss_get_fix_rate(gnss_dev, &fix_interval);
	zassert_ok(ret, "Failed to get fix rate: %d", ret);
	zassert_equal(fix_interval, 500,
		      "Expected 500ms fix interval, got %u", fix_interval);

	/* Restore default */
	ret = gnss_set_fix_rate(gnss_dev, 1000);
	zassert_ok(ret, "Failed to restore fix rate: %d", ret);
}

ZTEST_SUITE(gnss_emul, NULL, gnss_emul_setup, NULL, NULL, NULL);
