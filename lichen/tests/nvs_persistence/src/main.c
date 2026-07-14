/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: The contributors to the LICHEN project
 *
 * NVS persistence test for native_sim.
 *
 * Tests that NVS and settings data persists across mount/unmount cycles.
 * On native_sim, real persistence requires the --flash option at runtime.
 */

#include <zephyr/ztest.h>
#include <zephyr/settings/settings.h>
#include <zephyr/fs/nvs.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(nvs_persist_test, LOG_LEVEL_DBG);

#define NVS_PARTITION storage_partition
#define NVS_PARTITION_DEVICE FIXED_PARTITION_DEVICE(NVS_PARTITION)
#define NVS_PARTITION_OFFSET FIXED_PARTITION_OFFSET(NVS_PARTITION)
#define NVS_PARTITION_SIZE FIXED_PARTITION_SIZE(NVS_PARTITION)

/* Test data */
#define TEST_ID_COUNTER 1
#define TEST_ID_STRING 2
#define TEST_ID_BLOB 3

static struct nvs_fs test_fs;

/* Settings test data */
static uint32_t test_counter;
static char test_name[32];
static bool settings_loaded;

static int test_settings_set(const char *name, size_t len,
                             settings_read_cb read_cb, void *cb_arg)
{
	const char *next;
	int rc;

	if (settings_name_steq(name, "counter", &next) && !next) {
		rc = read_cb(cb_arg, &test_counter, sizeof(test_counter));
		if (rc < 0) {
			return rc;
		}
		LOG_INF("Loaded counter: %u", test_counter);
		return 0;
	}

	if (settings_name_steq(name, "name", &next) && !next) {
		rc = read_cb(cb_arg, test_name, sizeof(test_name) - 1);
		if (rc < 0) {
			return rc;
		}
		test_name[rc] = '\0';
		LOG_INF("Loaded name: %s", test_name);
		return 0;
	}

	return -ENOENT;
}

static int test_settings_export(int (*cb)(const char *name, const void *value,
                                          size_t val_len))
{
	cb("persist/counter", &test_counter, sizeof(test_counter));
	cb("persist/name", test_name, strlen(test_name));
	return 0;
}

static int test_settings_commit(void)
{
	settings_loaded = true;
	return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(persist, "persist", NULL, test_settings_set,
                               test_settings_commit, test_settings_export);

static void *nvs_persistence_setup(void)
{
	/* Get flash device info */
	const struct device *flash_dev = NVS_PARTITION_DEVICE;

	zassert_true(device_is_ready(flash_dev), "Flash device not ready");

	/* Initialize NVS filesystem */
	test_fs.flash_device = flash_dev;
	test_fs.offset = NVS_PARTITION_OFFSET;
	test_fs.sector_size = 4096;
	test_fs.sector_count = NVS_PARTITION_SIZE / test_fs.sector_size;

	LOG_INF("NVS partition: offset=0x%x, size=%u, sectors=%u",
	        test_fs.offset, NVS_PARTITION_SIZE, test_fs.sector_count);

	return NULL;
}

ZTEST_SUITE(nvs_persistence, NULL, nvs_persistence_setup, NULL, NULL, NULL);

/**
 * Test basic NVS write and read within a single mount.
 */
ZTEST(nvs_persistence, test_nvs_write_read)
{
	int rc;
	uint32_t counter = 42;
	uint32_t read_counter;
	char test_str[] = "hello_nvs";
	char read_str[16] = {0};

	/* Mount NVS */
	rc = nvs_mount(&test_fs);
	zassert_equal(rc, 0, "NVS mount failed: %d", rc);

	/* Write counter */
	rc = nvs_write(&test_fs, TEST_ID_COUNTER, &counter, sizeof(counter));
	zassert_equal(rc, sizeof(counter), "NVS write counter failed: %d", rc);

	/* Write string */
	rc = nvs_write(&test_fs, TEST_ID_STRING, test_str, strlen(test_str) + 1);
	zassert_equal(rc, strlen(test_str) + 1, "NVS write string failed: %d", rc);

	/* Read back counter */
	rc = nvs_read(&test_fs, TEST_ID_COUNTER, &read_counter, sizeof(read_counter));
	zassert_equal(rc, sizeof(read_counter), "NVS read counter failed: %d", rc);
	zassert_equal(read_counter, counter, "Counter mismatch: got %u, expected %u",
	              read_counter, counter);

	/* Read back string */
	rc = nvs_read(&test_fs, TEST_ID_STRING, read_str, sizeof(read_str));
	zassert_true(rc > 0, "NVS read string failed: %d", rc);
	zassert_str_equal(read_str, test_str, "String mismatch");

	LOG_INF("NVS write/read test passed");
}

/**
 * Test NVS persistence across mount/unmount cycles.
 * This simulates a restart without actually restarting the process.
 */
ZTEST(nvs_persistence, test_nvs_persist_across_mount)
{
	int rc;
	uint32_t counter = 12345;
	uint32_t read_counter;
	uint8_t blob[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	uint8_t read_blob[16] = {0};

	/* First mount: write data */
	rc = nvs_mount(&test_fs);
	zassert_equal(rc, 0, "First NVS mount failed: %d", rc);

	rc = nvs_write(&test_fs, TEST_ID_COUNTER, &counter, sizeof(counter));
	zassert_equal(rc, sizeof(counter), "NVS write counter failed: %d", rc);

	rc = nvs_write(&test_fs, TEST_ID_BLOB, blob, sizeof(blob));
	zassert_equal(rc, sizeof(blob), "NVS write blob failed: %d", rc);

	LOG_INF("First mount: wrote counter=%u and blob", counter);

	/* Clear the filesystem struct to simulate unmount */
	memset(&test_fs, 0, sizeof(test_fs));

	/* Reinitialize and remount to simulate restart */
	test_fs.flash_device = NVS_PARTITION_DEVICE;
	test_fs.offset = NVS_PARTITION_OFFSET;
	test_fs.sector_size = 4096;
	test_fs.sector_count = NVS_PARTITION_SIZE / test_fs.sector_size;

	rc = nvs_mount(&test_fs);
	zassert_equal(rc, 0, "Second NVS mount failed: %d", rc);

	/* Read data back - should persist */
	rc = nvs_read(&test_fs, TEST_ID_COUNTER, &read_counter, sizeof(read_counter));
	zassert_equal(rc, sizeof(read_counter), "NVS read counter failed: %d", rc);
	zassert_equal(read_counter, counter,
	              "Counter not persisted: got %u, expected %u", read_counter, counter);

	rc = nvs_read(&test_fs, TEST_ID_BLOB, read_blob, sizeof(read_blob));
	zassert_equal(rc, sizeof(read_blob), "NVS read blob failed: %d", rc);
	zassert_mem_equal(read_blob, blob, sizeof(blob), "Blob not persisted correctly");

	LOG_INF("Second mount: read persisted counter=%u and blob", read_counter);
	LOG_INF("NVS persistence across mount cycles passed");
}

/**
 * Test settings subsystem with NVS backend.
 */
ZTEST(nvs_persistence, test_settings_nvs)
{
	int rc;

	/* Initialize settings */
	rc = settings_subsys_init();
	zassert_equal(rc, 0, "Settings init failed: %d", rc);

	/* Set test values */
	test_counter = 9999;
	strncpy(test_name, "test_device", sizeof(test_name) - 1);

	/* Save settings */
	rc = settings_save();
	zassert_equal(rc, 0, "Settings save failed: %d", rc);

	LOG_INF("Settings saved: counter=%u, name=%s", test_counter, test_name);

	/* Clear values */
	test_counter = 0;
	memset(test_name, 0, sizeof(test_name));
	settings_loaded = false;

	/* Reload settings */
	rc = settings_load();
	zassert_equal(rc, 0, "Settings load failed: %d", rc);
	zassert_true(settings_loaded, "Settings commit not called");

	/* Verify values */
	zassert_equal(test_counter, 9999, "Counter not restored: got %u", test_counter);
	zassert_str_equal(test_name, "test_device", "Name not restored");

	LOG_INF("Settings reload: counter=%u, name=%s", test_counter, test_name);
	LOG_INF("Settings NVS test passed");
}

/**
 * Test that settings persist across settings_subsys_init() cycles.
 */
ZTEST(nvs_persistence, test_settings_persist_cycle)
{
	int rc;

	/* First cycle: init and save */
	rc = settings_subsys_init();
	zassert_equal(rc, 0, "Settings init failed: %d", rc);

	test_counter = 77777;
	strncpy(test_name, "persist_test", sizeof(test_name) - 1);

	rc = settings_save();
	zassert_equal(rc, 0, "Settings save failed: %d", rc);

	LOG_INF("Saved settings: counter=%u, name=%s", test_counter, test_name);

	/* Clear local values */
	test_counter = 0;
	memset(test_name, 0, sizeof(test_name));
	settings_loaded = false;

	/* Second cycle: just load (simulating restart) */
	rc = settings_load();
	zassert_equal(rc, 0, "Settings load failed: %d", rc);

	/* Verify persistence */
	zassert_equal(test_counter, 77777, "Counter not persisted: got %u", test_counter);
	zassert_str_equal(test_name, "persist_test", "Name not persisted");

	LOG_INF("Loaded persisted settings: counter=%u, name=%s", test_counter, test_name);
	LOG_INF("Settings persistence cycle test passed");
}
