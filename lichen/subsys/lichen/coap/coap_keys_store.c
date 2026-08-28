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

#include <monocypher.h>
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

/* File-scoped staging avoids large per-thread stack allocations. Access is
 * serialized by s_mutex, including persistence callbacks. */
static struct lichen_key_entry s_candidate[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES];
static struct lichen_key_entry s_snapshot[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES];
static struct lichen_key_entry s_loaded[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES];
static struct lichen_key_mismatch_audit
	s_mismatch_audits[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES];
static lichen_key_store_save_cb s_save_cb;
static lichen_key_mismatch_alert_cb s_alert_cb;
static void *s_persist_user;
static void *s_alert_user;
static uint64_t s_revision;
static uint64_t s_alert_sequence;
static bool s_persistence_ready;

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

int find_key_locked(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN])
{
	for (int i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; i++) {
		if (s_keys[i].valid &&
		    memcmp(s_keys[i].iid, iid, LICHEN_KEY_IID_LEN) == 0) {
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

static bool trust_valid(enum lichen_key_trust trust)
{
	return trust == LICHEN_KEY_TRUST_TOFU ||
	       trust == LICHEN_KEY_TRUST_VERIFIED ||
	       trust == LICHEN_KEY_TRUST_DANE;
}

static bool entry_binding_valid(const struct lichen_key_entry *entry)
{
	uint8_t derived[LICHEN_KEY_IID_LEN];

	if (!entry->valid || !trust_valid(entry->trust) ||
	    entry->last_seen < entry->first_seen ||
	    lichen_key_pubkey_to_iid(entry->pubkey, derived) != 0) {
		return false;
	}
	return memcmp(entry->iid, derived, sizeof(derived)) == 0;
}

static int persist_candidate_locked(const struct lichen_key_entry *candidate)
{
	size_t count = 0;
	int ret;

	if (!s_persistence_ready) {
		return 0;
	}
	if (s_revision == UINT64_MAX) {
		return -EOVERFLOW;
	}

	memset(s_snapshot, 0, sizeof(s_snapshot));
	for (size_t i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; i++) {
		if (candidate[i].valid) {
			s_snapshot[count++] = candidate[i];
		}
	}

	ret = s_save_cb(s_persist_user, s_snapshot, count, s_revision + 1U);
	crypto_wipe(s_snapshot, sizeof(s_snapshot));
	if (ret == 0) {
		s_revision++;
	}
	return ret;
}

static int deliver_alert_locked(struct lichen_key_mismatch_audit *audit)
{
	int ret;

	if (s_alert_cb == NULL) {
		audit->last_delivery_error = -ENOTCONN;
		return -ENOTCONN;
	}

	ret = s_alert_cb(s_alert_user, audit);
	if (ret > 0) {
		ret = -EPROTO;
	}
	audit->last_delivery_error = ret;
	return ret;
}

static void record_mismatch_locked(
	int slot, const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN])
{
	struct lichen_key_mismatch_audit *audit = &s_mismatch_audits[slot];
	uint32_t now = get_unix_time();
	bool replay = audit->valid &&
		crypto_verify32(audit->presented_pubkey, pubkey) == 0;

	if (!replay) {
		crypto_wipe(audit, sizeof(*audit));
		if (s_alert_sequence != UINT64_MAX) {
			s_alert_sequence++;
		}
		memcpy(audit->iid, s_keys[slot].iid, sizeof(audit->iid));
		memcpy(audit->pinned_pubkey, s_keys[slot].pubkey,
		       sizeof(audit->pinned_pubkey));
		memcpy(audit->presented_pubkey, pubkey,
		       sizeof(audit->presented_pubkey));
		audit->sequence = s_alert_sequence;
		audit->first_seen = now;
		audit->attempts = 1U;
		audit->valid = true;
	} else if (audit->attempts != UINT32_MAX) {
		audit->attempts++;
	}
	if (now < audit->first_seen) {
		now = audit->first_seen;
	}
	audit->last_seen = now;

	/* A successfully delivered identical event is a replay: preserve the
	 * counter for audit without allowing alert-flood amplification. */
	if (!replay || audit->last_delivery_error != 0) {
		(void)deliver_alert_locked(audit);
	}
}

int lichen_key_store_init(lichen_key_store_load_cb load_cb,
			  lichen_key_store_save_cb save_cb, void *user)
{
	size_t count = 0;
	uint64_t revision = 0;
	int ret;

	if (load_cb == NULL || save_cb == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	memset(s_loaded, 0, sizeof(s_loaded));
	ret = load_cb(user, s_loaded, ARRAY_SIZE(s_loaded), &count, &revision);
	if (ret == -ENOENT) {
		ret = 0;
		count = 0;
		revision = 0;
	} else if (ret != 0) {
		goto out;
	}
	if (count > ARRAY_SIZE(s_loaded) || (count > 0 && revision == 0)) {
		ret = -EBADMSG;
		goto out;
	}

	for (size_t i = 0; i < count; i++) {
		if (!entry_binding_valid(&s_loaded[i])) {
			ret = -EBADMSG;
			goto out;
		}
		for (size_t j = 0; j < i; j++) {
			if (memcmp(s_loaded[i].iid, s_loaded[j].iid,
				   LICHEN_KEY_IID_LEN) == 0) {
				ret = -EBADMSG;
				goto out;
			}
		}
	}

	/* Publish only after the complete durable snapshot validates. */
	crypto_wipe(s_keys, sizeof(s_keys));
	memcpy(s_keys, s_loaded, count * sizeof(s_loaded[0]));
	crypto_wipe(s_mismatch_audits, sizeof(s_mismatch_audits));
	s_save_cb = save_cb;
	s_persist_user = user;
	s_revision = revision;
	s_persistence_ready = true;

out:
	crypto_wipe(s_loaded, sizeof(s_loaded));
	k_mutex_unlock(&s_mutex);
	return ret;
}

int lichen_key_store_verify_or_pin(
	const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
	const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
	enum lichen_key_pin_result *result)
{
	uint8_t derived[LICHEN_KEY_IID_LEN];
	bool binding_matches;
	int slot;
	int ret;

	if (iid == NULL || pubkey == NULL) {
		return -EINVAL;
	}
	ret = lichen_key_pubkey_to_iid(pubkey, derived);
	if (ret != 0) {
		return ret;
	}
	binding_matches = memcmp(iid, derived, sizeof(derived)) == 0;

	k_mutex_lock(&s_mutex, K_FOREVER);
	if (!s_persistence_ready) {
		k_mutex_unlock(&s_mutex);
		return -EACCES;
	}

	slot = find_key_locked(iid);
	if (slot >= 0) {
		if (crypto_verify32(s_keys[slot].pubkey, pubkey) != 0) {
			record_mismatch_locked(slot, pubkey);
			k_mutex_unlock(&s_mutex);
			return -EEXIST;
		}
		if (!binding_matches) {
			k_mutex_unlock(&s_mutex);
			return -EKEYREJECTED;
		}
		if (result != NULL) {
			*result = LICHEN_KEY_PIN_MATCH;
		}
		k_mutex_unlock(&s_mutex);
		return 0;
	}
	if (!binding_matches) {
		k_mutex_unlock(&s_mutex);
		return -EKEYREJECTED;
	}

	slot = find_free_slot_locked();
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return slot;
	}

	memcpy(s_candidate, s_keys, sizeof(s_candidate));
	memcpy(s_candidate[slot].iid, iid, LICHEN_KEY_IID_LEN);
	memcpy(s_candidate[slot].pubkey, pubkey, LICHEN_KEY_PUBKEY_LEN);
	s_candidate[slot].trust = LICHEN_KEY_TRUST_TOFU;
	s_candidate[slot].first_seen = get_unix_time();
	s_candidate[slot].last_seen = s_candidate[slot].first_seen;
	s_candidate[slot].valid = true;

	ret = persist_candidate_locked(s_candidate);
	if (ret == 0) {
		memcpy(s_keys, s_candidate, sizeof(s_keys));
		crypto_wipe(&s_mismatch_audits[slot],
			    sizeof(s_mismatch_audits[slot]));
		if (result != NULL) {
			*result = LICHEN_KEY_PIN_NEW;
		}
	}
	crypto_wipe(s_candidate, sizeof(s_candidate));
	k_mutex_unlock(&s_mutex);
	return ret;
}

int lichen_key_store_set_mismatch_alert_cb(
	lichen_key_mismatch_alert_cb alert_cb, void *user)
{
	int first_error = 0;

	k_mutex_lock(&s_mutex, K_FOREVER);
	s_alert_cb = alert_cb;
	s_alert_user = user;
	if (alert_cb != NULL) {
		for (size_t i = 0; i < ARRAY_SIZE(s_mismatch_audits); i++) {
			if (s_mismatch_audits[i].valid &&
			    s_mismatch_audits[i].last_delivery_error != 0) {
				int ret = deliver_alert_locked(&s_mismatch_audits[i]);

				if (first_error == 0 && ret != 0) {
					first_error = ret;
				}
			}
		}
	}
	k_mutex_unlock(&s_mutex);
	return first_error;
}

int lichen_key_store_get_mismatch_audit(
	const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
	struct lichen_key_mismatch_audit *audit)
{
	int slot;

	if (iid == NULL || audit == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&s_mutex, K_FOREVER);
	slot = find_key_locked(iid);
	if (slot < 0 || !s_mismatch_audits[slot].valid) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}
	*audit = s_mismatch_audits[slot];
	k_mutex_unlock(&s_mutex);
	return 0;
}

/* --------------------------------------------------------------------------
 * Key store API implementation
 * -------------------------------------------------------------------------- */

int lichen_key_store_put(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
			 const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
			 enum lichen_key_trust trust)
{
	uint8_t derived[LICHEN_KEY_IID_LEN];
	bool new_key = false;
	int slot;
	int ret;
	uint32_t now = get_unix_time();

	if (iid == NULL || pubkey == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	memcpy(s_candidate, s_keys, sizeof(s_candidate));

	slot = find_key_locked(iid);
	if (slot >= 0) {
		/*
		 * SECURITY: TOFU key pinning - existing keys cannot have their
		 * pubkey changed. Reject if pubkey differs. Checked before
		 * binding validation so a key-change attempt keeps reporting
		 * -EEXIST.
		 */
		if (crypto_verify32(s_candidate[slot].pubkey, pubkey) != 0) {
			crypto_wipe(s_candidate, sizeof(s_candidate));
			k_mutex_unlock(&s_mutex);
			LOG_WRN("Key update rejected: pubkey mismatch (TOFU violation)");
			return -EEXIST;
		}
	}

	/*
	 * SECURITY: Trust and IID/pubkey binding validation is unconditional.
	 * It must never depend on persistence readiness; only the persistence
	 * step is degraded when the store was never initialized.
	 */
	if (!trust_valid(trust) ||
	    lichen_key_pubkey_to_iid(pubkey, derived) != 0 ||
	    memcmp(iid, derived, sizeof(derived)) != 0) {
		crypto_wipe(s_candidate, sizeof(s_candidate));
		k_mutex_unlock(&s_mutex);
		LOG_WRN("Key put rejected: invalid trust or IID/pubkey binding");
		return -EKEYREJECTED;
	}

	if (slot >= 0) {
		/* Update trust level and last_seen */
		s_candidate[slot].trust = trust;
		if (now < s_candidate[slot].first_seen) {
			now = s_candidate[slot].first_seen;
		}
		s_candidate[slot].last_seen = now;
		ret = persist_candidate_locked(s_candidate);
		goto publish;
	}

	/* New key */
	slot = find_free_slot_locked();
	if (slot < 0) {
		crypto_wipe(s_candidate, sizeof(s_candidate));
		k_mutex_unlock(&s_mutex);
		return -ENOSPC;
	}
	new_key = true;

	memcpy(s_candidate[slot].iid, iid, LICHEN_KEY_IID_LEN);
	memcpy(s_candidate[slot].pubkey, pubkey, LICHEN_KEY_PUBKEY_LEN);
	s_candidate[slot].trust = trust;
	s_candidate[slot].first_seen = now;
	s_candidate[slot].last_seen = now;
	s_candidate[slot].valid = true;
	ret = persist_candidate_locked(s_candidate);

publish:
	if (ret == 0) {
		memcpy(s_keys, s_candidate, sizeof(s_keys));
		if (new_key) {
			crypto_wipe(&s_mismatch_audits[slot],
				    sizeof(s_mismatch_audits[slot]));
		}
	}
	crypto_wipe(s_candidate, sizeof(s_candidate));
	k_mutex_unlock(&s_mutex);
	return ret;
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
	int ret;

	if (iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);

	slot = find_key_locked(iid);
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}
	memcpy(s_candidate, s_keys, sizeof(s_candidate));
	crypto_wipe(&s_candidate[slot], sizeof(s_candidate[slot]));
	ret = persist_candidate_locked(s_candidate);
	if (ret == 0) {
		memcpy(s_keys, s_candidate, sizeof(s_keys));
		crypto_wipe(&s_mismatch_audits[slot],
			    sizeof(s_mismatch_audits[slot]));
	}
	crypto_wipe(s_candidate, sizeof(s_candidate));
	k_mutex_unlock(&s_mutex);
	return ret;
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
	int ret;

	if (iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);

	slot = find_key_locked(iid);
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}
	if (unix_time < s_keys[slot].first_seen) {
		k_mutex_unlock(&s_mutex);
		return -ERANGE;
	}

	memcpy(s_candidate, s_keys, sizeof(s_candidate));
	s_candidate[slot].last_seen = unix_time;
	ret = persist_candidate_locked(s_candidate);
	if (ret == 0) {
		memcpy(s_keys, s_candidate, sizeof(s_keys));
	}
	crypto_wipe(s_candidate, sizeof(s_candidate));
	k_mutex_unlock(&s_mutex);
	return ret;
}

#ifdef CONFIG_LICHEN_COAP_KEYS_TEST_HOOKS
void lichen_key_store_test_reset(void)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	crypto_wipe(s_keys, sizeof(s_keys));
	crypto_wipe(s_candidate, sizeof(s_candidate));
	crypto_wipe(s_snapshot, sizeof(s_snapshot));
	crypto_wipe(s_loaded, sizeof(s_loaded));
	crypto_wipe(s_mismatch_audits, sizeof(s_mismatch_audits));
	s_save_cb = NULL;
	s_alert_cb = NULL;
	s_persist_user = NULL;
	s_alert_user = NULL;
	s_revision = 0;
	s_alert_sequence = 0;
	s_persistence_ready = false;
	k_mutex_unlock(&s_mutex);
}
#endif
