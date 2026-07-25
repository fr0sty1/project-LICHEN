/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_keys_store.c
 * @brief Key store implementation with TOFU semantics
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <lichen/coap_keys.h>
#include "coap_keys_internal.h"

LOG_MODULE_DECLARE(lichen_coap_keys, CONFIG_LICHEN_COAP_KEYS_LOG_LEVEL);

BUILD_ASSERT(CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES <= 16,
	     "CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES >16 risks stack overflow in encode_keys_list_cbor [p0wq]");

/* --------------------------------------------------------------------------
 * Key store state
 * -------------------------------------------------------------------------- */

struct lichen_key_entry s_keys[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES];
K_MUTEX_DEFINE(s_mutex);

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

int key_ct_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
	volatile uint8_t diff = 0U;
	for (size_t i = 0; i < len; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff;
}

int find_key_locked(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN])
{
	for (int i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; i++) {
		if (s_keys[i].valid &&
		    key_ct_compare(s_keys[i].iid, iid, LICHEN_KEY_IID_LEN) == 0) {
			return i;
		}
	}
	return -ENOENT;
}

int find_free_slot_locked(void)
{
	for (int i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; i++) {
		if (!s_keys[i].valid) {
			return i;
		}
	}
	return -ENOSPC;
}

uint32_t get_unix_time(void)
{
	/* Return uptime as a fallback if no wall clock is available */
	return (uint32_t)(k_uptime_get() / 1000);
}

/* --------------------------------------------------------------------------
 * Key store API implementation
 * -------------------------------------------------------------------------- */

int lichen_key_store_put(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
			 const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
			 enum lichen_key_trust trust)
{
	int slot;
	uint32_t now = get_unix_time();

	if (iid == NULL || pubkey == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);

	slot = find_key_locked(iid);
	if (slot >= 0) {
		/*
		 * SECURITY: TOFU key pinning - existing keys cannot have their
		 * pubkey changed. Reject if pubkey differs.
		 */
		if (key_ct_compare(s_keys[slot].pubkey, pubkey, LICHEN_KEY_PUBKEY_LEN) != 0) {
			k_mutex_unlock(&s_mutex);
			LOG_WRN("Key update rejected: pubkey mismatch (TOFU violation)");
			return -EEXIST;
		}
		/* Update trust level and last_seen */
		s_keys[slot].trust = trust;
		s_keys[slot].last_seen = now;
		k_mutex_unlock(&s_mutex);
		return 0;
	}

	/* New key */
	slot = find_free_slot_locked();
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOSPC;
	}

	memcpy(s_keys[slot].iid, iid, LICHEN_KEY_IID_LEN);
	memcpy(s_keys[slot].pubkey, pubkey, LICHEN_KEY_PUBKEY_LEN);
	s_keys[slot].trust = trust;
	s_keys[slot].first_seen = now;
	s_keys[slot].last_seen = now;
	s_keys[slot].valid = true;

	k_mutex_unlock(&s_mutex);
	return 0;
}

int lichen_key_store_get(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
			 struct lichen_key_entry *_Nonnull entry)
{
	int slot;

	if (iid == NULL || entry == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);

	slot = find_key_locked(iid);
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}

	*entry = s_keys[slot];
	k_mutex_unlock(&s_mutex);
	return 0;
}

int lichen_key_store_delete(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN])
{
	int slot;

	if (iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);

	slot = find_key_locked(iid);
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}

	memset(&s_keys[slot], 0, sizeof(s_keys[slot]));
	k_mutex_unlock(&s_mutex);
	return 0;
}

size_t lichen_key_store_count(void)
{
	size_t count = 0;

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (int i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; i++) {
		if (s_keys[i].valid) {
			count++;
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

size_t lichen_key_store_list(struct lichen_key_entry *_Nonnull entries,
			     size_t max_entries)
{
	size_t count = 0;

	if (entries == NULL || max_entries == 0) {
		return 0;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (int i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES && count < max_entries; i++) {
		if (s_keys[i].valid) {
			entries[count++] = s_keys[i];
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

int lichen_key_store_touch(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN], uint32_t unix_time)
{
	int slot;

	if (iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);

	slot = find_key_locked(iid);
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}

	s_keys[slot].last_seen = unix_time;
	k_mutex_unlock(&s_mutex);
	return 0;
}

#ifdef CONFIG_LICHEN_COAP_KEYS_TEST_HOOKS
void lichen_key_store_test_reset(void)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	memset(s_keys, 0, sizeof(s_keys));
	k_mutex_unlock(&s_mutex);
}
#endif
