/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/replay_persist.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

#define SETTINGS_ROOT "lichen/replay"
#define SETTINGS_SLOT_A SETTINGS_ROOT "/a"
#define SETTINGS_SLOT_B SETTINGS_ROOT "/b"

struct staged_slot {
	uint8_t value[LICHEN_REPLAY_PERSIST_BLOB_MAX];
	size_t length;
	bool present;
};

static struct staged_slot s_slots[2];
static struct lichen_replay_persist s_persistence;
static const struct lichen_replay_protection_ops *s_protection_ops;
static void *s_protection_user;
static K_MUTEX_DEFINE(s_settings_lock);

static int replay_settings_set(const char *name, size_t len,
			       settings_read_cb read_cb, void *cb_arg)
{
	const char *next;
	enum lichen_replay_blob_slot slot;
	ssize_t ret;

	if (settings_name_steq(name, "a", &next) && next == NULL) {
		slot = LICHEN_REPLAY_BLOB_A;
	} else if (settings_name_steq(name, "b", &next) && next == NULL) {
		slot = LICHEN_REPLAY_BLOB_B;
	} else {
		return -ENOENT;
	}
	if (len == 0U || len > sizeof(s_slots[slot].value)) {
		return -EOVERFLOW;
	}
	ret = read_cb(cb_arg, s_slots[slot].value, len);
	if (ret < 0) {
		return (int)ret;
	}
	if ((size_t)ret != len) {
		return -EBADMSG;
	}
	s_slots[slot].length = len;
	s_slots[slot].present = true;
	return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(lichen_replay, SETTINGS_ROOT, NULL,
			      replay_settings_set, NULL, NULL);

static int store_load(void *user, enum lichen_replay_blob_slot slot,
		      uint8_t *out, size_t capacity, size_t *length)
{
	ARG_UNUSED(user);
	if (slot > LICHEN_REPLAY_BLOB_B || !s_slots[slot].present) {
		return -ENOENT;
	}
	if (capacity < s_slots[slot].length) {
		return -ENOSPC;
	}
	memcpy(out, s_slots[slot].value, s_slots[slot].length);
	*length = s_slots[slot].length;
	return 0;
}

static int store_save(void *user, enum lichen_replay_blob_slot slot,
		      const uint8_t *value, size_t length)
{
	const char *key;
	int ret;

	ARG_UNUSED(user);
	if (slot > LICHEN_REPLAY_BLOB_B || value == NULL || length == 0U ||
	    length > sizeof(s_slots[slot].value)) {
		return -EINVAL;
	}
	key = slot == LICHEN_REPLAY_BLOB_A ? SETTINGS_SLOT_A : SETTINGS_SLOT_B;
	ret = settings_save_one(key, value, length);
	if (ret == 0) {
		memcpy(s_slots[slot].value, value, length);
		s_slots[slot].length = length;
		s_slots[slot].present = true;
	}
	return ret;
}

static const struct lichen_replay_store_ops settings_store_ops = {
	.load = store_load,
	.save = store_save,
};

int lichen_replay_settings_register_protection(
	const struct lichen_replay_protection_ops *ops, void *user)
{
	int ret = 0;

	if (ops == NULL || ops->derive_key == NULL || ops->load == NULL ||
	    ops->commit == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&s_settings_lock, K_FOREVER);
	if (s_protection_ops == NULL) {
		s_protection_ops = ops;
		s_protection_user = user;
	} else if (s_protection_ops != ops || s_protection_user != user) {
		ret = -EALREADY;
	}
	k_mutex_unlock(&s_settings_lock);
	return ret;
}

int lichen_replay_settings_open(
	struct lichen_replay_table *table,
	const uint8_t local_public_key[LICHEN_PK_LEN], uint8_t fallback_epoch,
	uint8_t *boot_epoch)
{
	int ret;

	if (table == NULL || local_public_key == NULL || boot_epoch == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&s_settings_lock, K_FOREVER);
	if (s_protection_ops == NULL) {
		ret = -EACCES;
		goto unlock;
	}
	if (s_persistence.ready) {
		ret = -EALREADY;
		goto unlock;
	}
	memset(s_slots, 0, sizeof(s_slots));
	ret = settings_subsys_init();
	if (ret == 0) {
		ret = settings_load_subtree(SETTINGS_ROOT);
	}
	if (ret == 0) {
		ret = lichen_replay_persist_open(
			&s_persistence, table, local_public_key, fallback_epoch,
			&settings_store_ops, NULL, s_protection_ops,
			s_protection_user, boot_epoch);
	}

unlock:
	k_mutex_unlock(&s_settings_lock);
	return ret;
}

int lichen_replay_settings_reserve_tx_epoch(uint8_t current_epoch,
					    uint8_t *next_epoch)
{
	int ret;

	k_mutex_lock(&s_settings_lock, K_FOREVER);
	ret = lichen_replay_persist_reserve_tx_epoch(&s_persistence,
						     current_epoch, next_epoch);
	k_mutex_unlock(&s_settings_lock);
	return ret;
}

void lichen_replay_settings_close(void)
{
	k_mutex_lock(&s_settings_lock, K_FOREVER);
	lichen_replay_persist_close(&s_persistence);
	k_mutex_unlock(&s_settings_lock);
}
