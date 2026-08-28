/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/link_ctx.h>
#include <zephyr/settings/settings.h>

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#define STORAGE_CAPACITY 32U

static uint8_t stored[STORAGE_CAPACITY];
static size_t stored_len;
static bool stored_present;
static int init_error;
static int load_error;
static int save_error;
static int read_error;
static size_t forced_read_len;
static unsigned int load_calls;
static unsigned int save_calls;

bool settings_name_steq(const char *name, const char *key, const char **next)
{
	size_t key_len = strlen(key);

	if (strncmp(name, key, key_len) != 0) {
		return false;
	}
	*next = name[key_len] == '/' ? &name[key_len + 1U] :
		name[key_len] == '\0' ? NULL : &name[key_len];
	return true;
}

int settings_subsys_init(void)
{
	return init_error;
}

static ssize_t read_stored(void *cb_arg, void *data, size_t len)
{
	(void)cb_arg;
	if (read_error != 0) {
		return read_error;
	}
	size_t count = stored_len < len ? stored_len : len;
	if (forced_read_len != 0U && forced_read_len < count) {
		count = forced_read_len;
	}
	memcpy(data, stored, count);
	return (ssize_t)count;
}

int settings_load_subtree(const char *subtree)
{
	assert(strcmp(subtree, "lichen/epoch") == 0);
	load_calls++;
	if (load_error != 0) {
		return load_error;
	}
	if (!stored_present) {
		return 0;
	}
	return test_settings_set_handler("e", stored_len, read_stored, NULL);
}

int settings_save_one(const char *name, const void *value, size_t len)
{
	assert(strcmp(name, "lichen/epoch/e") == 0);
	assert(len <= sizeof(stored));
	save_calls++;
	if (save_error != 0) {
		return save_error;
	}
	memcpy(stored, value, len);
	stored_len = len;
	stored_present = true;
	return 0;
}

static void reset_backend(void)
{
	memset(stored, 0, sizeof(stored));
	stored_len = 0U;
	stored_present = false;
	init_error = 0;
	load_error = 0;
	save_error = 0;
	read_error = 0;
	forced_read_len = 0U;
	load_calls = 0U;
	save_calls = 0U;
	lichen_link_epoch_test_reset();
}

static void seed(uint8_t epoch)
{
	reset_backend();
	assert(lichen_link_epoch_persist(epoch) == 0);
	lichen_link_epoch_test_reset();
	load_calls = 0U;
	save_calls = 0U;
}

static void test_missing_uses_fallback_and_is_idempotent(void)
{
	uint8_t epoch = 0U;

	reset_backend();
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == 0);
	assert(epoch == 200U && stored_present);
	assert(load_calls == 1U && save_calls == 1U);
	assert(lichen_link_epoch_advance_for_boot(201U, &epoch) == 0);
	assert(epoch == 200U);
	assert(load_calls == 1U && save_calls == 1U);
}

static void test_valid_advance_and_exhaustion(void)
{
	uint8_t epoch = 0U;

	seed(42U);
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == 0);
	assert(epoch == 43U);
	seed(UINT8_MAX);
	epoch = 0xa5U;
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == -EOVERFLOW);
	assert(epoch == 0xa5U && save_calls == 0U);
}

static void test_corrupt_torn_and_read_failures(void)
{
	uint8_t epoch = 0xa5U;

	seed(42U);
	stored[0] ^= 1U;
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == -EBADMSG);
	assert(epoch == 0xa5U && save_calls == 0U);

	seed(42U);
	stored_len--;
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == -EBADMSG);

	seed(42U);
	forced_read_len = 1U;
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == -EBADMSG);

	seed(42U);
	read_error = -EIO;
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == -EIO);
}

static void test_init_load_and_save_failures_do_not_publish(void)
{
	uint8_t epoch = 0xa5U;

	reset_backend();
	init_error = -EIO;
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == -EIO);
	assert(epoch == 0xa5U && save_calls == 0U);

	seed(42U);
	load_error = -EIO;
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == -EIO);
	assert(epoch == 0xa5U && save_calls == 0U);

	seed(42U);
	uint8_t before[STORAGE_CAPACITY];
	memcpy(before, stored, stored_len);
	size_t before_len = stored_len;
	save_error = -EIO;
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == -EIO);
	assert(epoch == 0xa5U && stored_len == before_len);
	assert(memcmp(stored, before, before_len) == 0);
	save_error = 0;
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == 0);
	assert(epoch == 43U);
}

static void test_persist_rejects_wrap_rollback_and_failed_publish(void)
{
	uint8_t epoch;

	seed(40U);
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == 0);
	assert(epoch == 41U);
	assert(lichen_link_epoch_persist(0U) == -EOVERFLOW);
	assert(lichen_link_epoch_persist(41U) == -ERANGE);
	assert(lichen_link_epoch_persist(40U) == -ERANGE);
	save_error = -EIO;
	assert(lichen_link_epoch_persist(42U) == -EIO);
	save_error = 0;
	assert(lichen_link_epoch_advance_for_boot(200U, &epoch) == 0);
	assert(epoch == 41U);
	assert(lichen_link_epoch_persist(42U) == 0);
}

int main(void)
{
	test_missing_uses_fallback_and_is_idempotent();
	test_valid_advance_and_exhaustion();
	test_corrupt_torn_and_read_failures();
	test_init_load_and_save_failures_do_not_publish();
	test_persist_rejects_wrap_rollback_and_failed_publish();
	return 0;
}
