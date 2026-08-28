/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief LICHEN CoAP /keys store tests
 *
 * Primary purpose (bd a2a2): give CONFIG_LICHEN_COAP_KEYS a build that
 * actually compiles and links coap_keys.c, which no app/test config did
 * before. Also validates the peer key store's CRUD + TOFU semantics.
 *
 * Extended (bd 6mij.2.2.4): enable CONFIG_LICHEN_COAP_SERVER_OSCORE so the
 * OSCORE-protected PUT/DELETE #ifdef blocks in coap_keys.c are compiled and
 * linked. The OSCORE handler functions (keys_single_put, keys_single_delete)
 * are static and require a full CoAP stack + real OSCORE contexts for wire
 * testing; the build-verification here ensures no compilation or link errors
 * in those code paths, and the existing store-API tests continue to validate
 * the CRUD semantics that the OSCORE wrappers delegate to.
 */

#include <zephyr/ztest.h>

#include <lichen/coap_keys.h>
#include <lichen/coap_keys_alert.h>
#include <lichen/coap_keys_settings.h>
#include <lichen/coap_server.h>
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
#include <lichen/coap_oscore.h>
#include <lichen/oscore.h>
/* Build-time verification that the OSCORE header chain compiles */
BUILD_ASSERT(IS_ENABLED(CONFIG_LICHEN_COAP_SERVER_OSCORE),
	     "OSCORE must be enabled for this test build");
#endif

#include "tofu_edge_vectors.h"

#include <string.h>

static const uint8_t iid_a[LICHEN_KEY_IID_LEN] = {
	0x02, 0x00, 0x5e, 0x10, 0x20, 0x30, 0x40, 0x50
};
static const uint8_t pubkey_a[LICHEN_KEY_PUBKEY_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t pubkey_b[LICHEN_KEY_PUBKEY_LEN] = {
	0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
	0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
	0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
	0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0
};

/* Generated from test/vectors/tofu_edge_cases.json. */
static const uint8_t tofu_pubkey[LICHEN_KEY_PUBKEY_LEN] = {
	TOFU_EDGE_ALICE_PUBKEY_BYTES,
};
static const uint8_t tofu_iid[LICHEN_KEY_IID_LEN] = {
	TOFU_EDGE_ALICE_IID_BYTES,
};
static const uint8_t tofu_bob_pubkey[LICHEN_KEY_PUBKEY_LEN] = {
	TOFU_EDGE_BOB_PUBKEY_BYTES,
};
static const uint8_t tofu_bob_iid[LICHEN_KEY_IID_LEN] = {
	TOFU_EDGE_BOB_IID_BYTES,
};

struct mock_persistence {
	struct lichen_key_entry entries[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES];
	size_t count;
	uint64_t revision;
	unsigned int save_calls;
	int load_error;
	int save_error;
	bool present;
};

static struct mock_persistence mock_persist;

struct mock_alert_sink {
	struct lichen_key_mismatch_audit last;
	unsigned int calls;
	int error;
};

static struct mock_alert_sink mock_alert;

struct mock_operator_transport {
	uint8_t payload[LICHEN_KEY_ALERT_WIRE_LEN];
	size_t len;
	unsigned int calls;
	int error;
};

static struct mock_operator_transport mock_operator;

static int mock_operator_deliver(void *user, const uint8_t *payload, size_t len)
{
	struct mock_operator_transport *transport = user;

	transport->calls++;
	if (transport->error != 0) {
		return transport->error;
	}
	if (payload == NULL || len != sizeof(transport->payload)) {
		return -EMSGSIZE;
	}
	memcpy(transport->payload, payload, len);
	transport->len = len;
	return 0;
}

#define FAKE_SETTINGS_RECORDS (2U * (CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES + 1U))
#define FAKE_SETTINGS_VALUE_MAX 49U
#define FAKE_SETTINGS_PREFIX "lichen/tofu/"

struct fake_settings_record {
	char key[24];
	uint8_t value[FAKE_SETTINGS_VALUE_MAX];
	size_t value_len;
	bool present;
};

struct fake_settings_store {
	struct fake_settings_record records[FAKE_SETTINGS_RECORDS];
	unsigned int mutate_calls;
	unsigned int fail_at_call;
	int load_error;
};

static struct fake_settings_store fake_settings;
static const uint8_t settings_auth_key[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN] = {
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
};

static struct fake_settings_record *fake_settings_find(const char *key)
{
	for (size_t i = 0; i < ARRAY_SIZE(fake_settings.records); i++) {
		if (fake_settings.records[i].present &&
		    strcmp(fake_settings.records[i].key, key) == 0) {
			return &fake_settings.records[i];
		}
	}
	return NULL;
}

static int fake_settings_load(void *ctx, lichen_key_settings_visit_cb visit,
			      void *user)
{
	struct fake_settings_store *store = ctx;

	if (store->load_error != 0) {
		return store->load_error;
	}
	for (size_t i = 0; i < ARRAY_SIZE(store->records); i++) {
		const char *relative;
		int ret;

		if (!store->records[i].present) {
			continue;
		}
		zassert_true(strncmp(store->records[i].key, FAKE_SETTINGS_PREFIX,
				     sizeof(FAKE_SETTINGS_PREFIX) - 1U) == 0);
		relative = &store->records[i].key[sizeof(FAKE_SETTINGS_PREFIX) - 1U];
		ret = visit(relative, store->records[i].value,
			    store->records[i].value_len, user);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

static int fake_settings_should_fail(struct fake_settings_store *store)
{
	store->mutate_calls++;
	return store->fail_at_call != 0 &&
	       store->mutate_calls == store->fail_at_call;
}

static int fake_settings_save(void *ctx, const char *key, const uint8_t *value,
			      size_t value_len)
{
	struct fake_settings_store *store = ctx;
	struct fake_settings_record *record;

	if (value == NULL || value_len > FAKE_SETTINGS_VALUE_MAX) {
		return -EINVAL;
	}
	if (fake_settings_should_fail(store)) {
		return -EIO;
	}
	record = fake_settings_find(key);
	if (record == NULL) {
		for (size_t i = 0; i < ARRAY_SIZE(store->records); i++) {
			if (!store->records[i].present) {
				record = &store->records[i];
				break;
			}
		}
	}
	if (record == NULL || strlen(key) >= sizeof(record->key)) {
		return -ENOSPC;
	}
	memset(record, 0, sizeof(*record));
	strcpy(record->key, key);
	memcpy(record->value, value, value_len);
	record->value_len = value_len;
	record->present = true;
	return 0;
}

static int fake_settings_delete(void *ctx, const char *key)
{
	struct fake_settings_store *store = ctx;
	struct fake_settings_record *record;

	if (fake_settings_should_fail(store)) {
		return -EIO;
	}
	record = fake_settings_find(key);
	if (record == NULL) {
		return -ENOENT;
	}
	memset(record, 0, sizeof(*record));
	return 0;
}

static const struct lichen_key_settings_ops fake_settings_ops = {
	.load = fake_settings_load,
	.save = fake_settings_save,
	.delete = fake_settings_delete,
};

static int init_fake_settings_store(const uint8_t *auth_key, uint64_t min_revision)
{
	return lichen_key_store_settings_test_init(auth_key, min_revision,
						   &fake_settings_ops, &fake_settings);
}

static void fake_settings_reboot(void)
{
	lichen_key_store_test_reset();
	lichen_key_store_settings_test_reset();
}

static int mock_alert_deliver(void *user,
			      const struct lichen_key_mismatch_audit *event)
{
	struct mock_alert_sink *sink = user;

	sink->calls++;
	sink->last = *event;
	return sink->error;
}

static int mock_load(void *user, struct lichen_key_entry *entries,
		     size_t capacity, size_t *count, uint64_t *revision)
{
	struct mock_persistence *mock = user;

	if (mock->load_error != 0) {
		return mock->load_error;
	}
	if (!mock->present) {
		return -ENOENT;
	}
	if (mock->count > capacity) {
		return -ENOSPC;
	}
	memcpy(entries, mock->entries, mock->count * sizeof(entries[0]));
	*count = mock->count;
	*revision = mock->revision;
	return 0;
}

static int mock_save(void *user, const struct lichen_key_entry *entries,
		     size_t count, uint64_t revision)
{
	struct mock_persistence *mock = user;

	mock->save_calls++;
	if (mock->save_error != 0) {
		return mock->save_error;
	}
	memset(mock->entries, 0, sizeof(mock->entries));
	memcpy(mock->entries, entries, count * sizeof(entries[0]));
	mock->count = count;
	mock->revision = revision;
	mock->present = true;
	return 0;
}

static int init_mock_store(void)
{
	return lichen_key_store_init(mock_load, mock_save, &mock_persist);
}

static void reset_store(void *fixture)
{
	ARG_UNUSED(fixture);
	lichen_key_alert_sink_deinit();
	lichen_key_store_test_reset();
	lichen_key_store_settings_test_reset();
	memset(&mock_persist, 0, sizeof(mock_persist));
	memset(&mock_alert, 0, sizeof(mock_alert));
	memset(&mock_operator, 0, sizeof(mock_operator));
	memset(&fake_settings, 0, sizeof(fake_settings));
}

ZTEST_SUITE(coap_keys, NULL, NULL, reset_store, NULL, NULL);

ZTEST(coap_keys, test_put_get_roundtrip)
{
	struct lichen_key_entry entry;
	uint8_t iid[LICHEN_KEY_IID_LEN];
	int ret;

	zassert_equal(lichen_key_store_count(), 0, "store should start empty");

	/* Persistence is not initialized here: the put must still validate
	 * the binding and publish the entry to RAM, without persisting. */
	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid));
	ret = lichen_key_store_put(iid, pubkey_a, LICHEN_KEY_TRUST_TOFU);
	zassert_equal(ret, 0, "put failed: %d", ret);
	zassert_equal(lichen_key_store_count(), 1, "count should be 1");
	zassert_equal(mock_persist.save_calls, 0U,
		      "persistence-less put must not write a snapshot");
	zassert_false(mock_persist.present,
		      "persistence-less put must not persist");

	ret = lichen_key_store_get(iid, &entry);
	zassert_equal(ret, 0, "get failed: %d", ret);
	zassert_mem_equal(entry.iid, iid, LICHEN_KEY_IID_LEN, "iid mismatch");
	zassert_mem_equal(entry.pubkey, pubkey_a, LICHEN_KEY_PUBKEY_LEN,
			  "pubkey mismatch");
	zassert_equal(entry.trust, LICHEN_KEY_TRUST_TOFU, "trust mismatch");
	zassert_true(entry.valid, "entry should be valid");
}

ZTEST(coap_keys, test_put_rejects_garbage_trust_without_persistence)
{
	uint8_t iid[LICHEN_KEY_IID_LEN];

	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid));
	zassert_equal(lichen_key_store_put(iid, pubkey_a,
					   LICHEN_KEY_TRUST_UNKNOWN),
		      -EKEYREJECTED,
		      "UNKNOWN trust must be rejected with persistence down");
	zassert_equal(lichen_key_store_put(iid, pubkey_a,
					   (enum lichen_key_trust)0x7f),
		      -EKEYREJECTED,
		      "out-of-range trust must be rejected with persistence down");
	zassert_equal(lichen_key_store_count(), 0U, "store must stay empty");
}

ZTEST(coap_keys, test_put_rejects_binding_mismatch_without_persistence)
{
	uint8_t wrong_iid[LICHEN_KEY_IID_LEN];

	memcpy(wrong_iid, tofu_iid, sizeof(wrong_iid));
	wrong_iid[7] ^= 1U;
	zassert_equal(lichen_key_store_put(wrong_iid, tofu_pubkey,
					   LICHEN_KEY_TRUST_TOFU),
		      -EKEYREJECTED,
		      "mismatched IID/pubkey must be rejected with persistence down");
	zassert_equal(lichen_key_store_count(), 0U, "store must stay empty");
	zassert_false(mock_persist.present, "nothing may be persisted");
}

ZTEST(coap_keys, test_put_ready_path_validates_and_persists)
{
	struct lichen_key_entry entry;
	uint8_t iid[LICHEN_KEY_IID_LEN];
	uint8_t wrong_iid[LICHEN_KEY_IID_LEN];

	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid));
	zassert_ok(lichen_key_store_put(iid, pubkey_a,
					LICHEN_KEY_TRUST_VERIFIED));
	zassert_equal(mock_persist.save_calls, 1U,
		      "valid admin put must persist when ready");
	zassert_ok(lichen_key_store_get(iid, &entry));
	zassert_equal(entry.trust, LICHEN_KEY_TRUST_VERIFIED);

	/* Validation gates the persistence-ready path too. */
	zassert_equal(lichen_key_store_put(iid, pubkey_a,
					   LICHEN_KEY_TRUST_UNKNOWN),
		      -EKEYREJECTED,
		      "garbage trust must be rejected when ready");
	memcpy(wrong_iid, tofu_iid, sizeof(wrong_iid));
	wrong_iid[7] ^= 1U;
	zassert_equal(lichen_key_store_put(wrong_iid, tofu_pubkey,
					   LICHEN_KEY_TRUST_TOFU),
		      -EKEYREJECTED,
		      "binding mismatch must be rejected when ready");
	zassert_equal(mock_persist.save_calls, 1U,
		      "rejected puts must not write the store");
	zassert_ok(lichen_key_store_put(tofu_iid, tofu_pubkey,
					LICHEN_KEY_TRUST_TOFU));
	zassert_equal(mock_persist.save_calls, 2U);
}

ZTEST(coap_keys, test_get_missing_returns_enoent)
{
	struct lichen_key_entry entry;

	zassert_equal(lichen_key_store_get(iid_a, &entry), -ENOENT,
		      "get of absent iid should be -ENOENT");
}

ZTEST(coap_keys, test_tofu_pinning_rejects_key_change)
{
	struct lichen_key_entry entry;
	uint8_t iid[LICHEN_KEY_IID_LEN];
	int ret;

	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid));
	zassert_equal(lichen_key_store_put(iid, pubkey_a,
					   LICHEN_KEY_TRUST_TOFU), 0,
		      "initial put failed");

	/* Same IID, DIFFERENT pubkey: TOFU pinning must reject it. */
	ret = lichen_key_store_put(iid, pubkey_b, LICHEN_KEY_TRUST_TOFU);
	zassert_equal(ret, -EEXIST, "key change should be rejected (-EEXIST)");

	/* Pinned key must be unchanged. */
	zassert_equal(lichen_key_store_get(iid, &entry), 0, "get failed");
	zassert_mem_equal(entry.pubkey, pubkey_a, LICHEN_KEY_PUBKEY_LEN,
			  "pinned pubkey must not change");
}

ZTEST(coap_keys, test_put_same_key_updates_trust)
{
	struct lichen_key_entry entry;
	uint8_t iid[LICHEN_KEY_IID_LEN];

	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid));
	zassert_equal(lichen_key_store_put(iid, pubkey_a,
					   LICHEN_KEY_TRUST_TOFU), 0,
		      "initial put failed");
	/* Same IID and SAME pubkey with a higher trust level: allowed. */
	zassert_equal(lichen_key_store_put(iid, pubkey_a,
					   LICHEN_KEY_TRUST_VERIFIED), 0,
		      "trust upgrade should be accepted");
	zassert_equal(lichen_key_store_count(), 1, "count should stay 1");
	zassert_equal(lichen_key_store_get(iid, &entry), 0, "get failed");
	zassert_equal(entry.trust, LICHEN_KEY_TRUST_VERIFIED,
		      "trust should be upgraded");
}

ZTEST(coap_keys, test_delete)
{
	struct lichen_key_entry entry;
	uint8_t iid[LICHEN_KEY_IID_LEN];

	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid));
	zassert_equal(lichen_key_store_put(iid, pubkey_a,
					   LICHEN_KEY_TRUST_TOFU), 0, "put failed");
	zassert_equal(lichen_key_store_delete(iid), 0, "delete failed");
	zassert_equal(lichen_key_store_count(), 0, "count should be 0");
	zassert_equal(lichen_key_store_get(iid, &entry), -ENOENT,
		      "get after delete should be -ENOENT");
	zassert_equal(lichen_key_store_delete(iid), -ENOENT,
		      "delete of absent iid should be -ENOENT");
}

ZTEST(coap_keys, test_list)
{
	struct lichen_key_entry entries[4];
	uint8_t iid_a_derived[LICHEN_KEY_IID_LEN];
	uint8_t iid_b_derived[LICHEN_KEY_IID_LEN];
	size_t n;

	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid_a_derived));
	zassert_ok(lichen_key_pubkey_to_iid(pubkey_b, iid_b_derived));
	zassert_equal(lichen_key_store_put(iid_a_derived, pubkey_a,
					   LICHEN_KEY_TRUST_TOFU), 0, "put a failed");
	zassert_equal(lichen_key_store_put(iid_b_derived, pubkey_b,
					   LICHEN_KEY_TRUST_VERIFIED), 0,
		      "put b failed");

	n = lichen_key_store_list(entries, ARRAY_SIZE(entries));
	zassert_equal(n, 2, "list should return 2 entries, got %zu", n);
}

ZTEST(coap_keys, test_iid_str_roundtrip)
{
	char buf[LICHEN_KEY_FINGERPRINT_STR_LEN];
	uint8_t parsed[LICHEN_KEY_IID_LEN];
	int ret;

	ret = lichen_key_iid_to_str(iid_a, buf, sizeof(buf));
	zassert_true(ret >= 0, "iid_to_str failed: %d", ret);

	ret = lichen_key_str_to_iid(buf, parsed);
	zassert_equal(ret, 0, "str_to_iid failed: %d", ret);
	zassert_mem_equal(parsed, iid_a, LICHEN_KEY_IID_LEN,
			  "iid string roundtrip mismatch");
}

ZTEST(coap_keys, test_fingerprint_format_and_stability)
{
	char fp_a1[LICHEN_KEY_FINGERPRINT_STR_LEN];
	char fp_a2[LICHEN_KEY_FINGERPRINT_STR_LEN];
	char fp_b[LICHEN_KEY_FINGERPRINT_STR_LEN];

	zassert_true(lichen_key_pubkey_fingerprint(pubkey_a, fp_a1,
						   sizeof(fp_a1)) > 0,
		     "fingerprint a1 failed");
	zassert_true(lichen_key_pubkey_fingerprint(pubkey_a, fp_a2,
						   sizeof(fp_a2)) > 0,
		     "fingerprint a2 failed");
	zassert_true(lichen_key_pubkey_fingerprint(pubkey_b, fp_b,
						   sizeof(fp_b)) > 0,
		     "fingerprint b failed");

	zassert_equal(strncmp(fp_a1, "SHA256:", 7), 0, "prefix should be SHA256:");
	/* Deterministic for the same key, distinct for different keys. */
	zassert_str_equal(fp_a1, fp_a2, "fingerprint must be stable");
	zassert_true(strcmp(fp_a1, fp_b) != 0,
		     "distinct keys must have distinct fingerprints");
}

ZTEST(coap_keys, test_pubkey_to_iid_derivation)
{
	uint8_t iid[LICHEN_KEY_IID_LEN];
	uint8_t iid2[LICHEN_KEY_IID_LEN];

	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid));
	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid2));
	zassert_mem_equal(iid, iid2, LICHEN_KEY_IID_LEN, "must be deterministic");

	zassert_ok(lichen_key_pubkey_to_iid(pubkey_b, iid2));
	/* Different pubkeys produce different IIDs (with high probability) */
	zassert_true(memcmp(iid, iid2, LICHEN_KEY_IID_LEN) != 0,
		     "distinct keys must produce distinct IIDs");
}

ZTEST(coap_keys, test_pubkey_to_iid_matches_shared_tofu_vector)
{
	uint8_t derived[LICHEN_KEY_IID_LEN];

	zassert_ok(lichen_key_pubkey_to_iid(tofu_pubkey, derived));
	zassert_mem_equal(derived, tofu_iid, sizeof(derived),
			  "SHA-512/U-L-bit IID differs from shared vector");
}

ZTEST(coap_keys, test_canonical_tofu_edge_vector_contract)
{
	uint8_t derived[LICHEN_KEY_IID_LEN];
	enum lichen_key_pin_result result;

	BUILD_ASSERT(TOFU_EDGE_VECTOR_COUNT == 14U,
		     "canonical TOFU edge-case corpus changed");
	BUILD_ASSERT(TOFU_EDGE_CONCURRENT_OBSERVERS == 2U,
		     "concurrency vector must exercise two observers");
	zassert_ok(lichen_key_pubkey_to_iid(tofu_bob_pubkey, derived));
	zassert_mem_equal(derived, tofu_bob_iid, sizeof(derived));
	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, &result));
	zassert_equal(result, LICHEN_KEY_PIN_NEW);
	zassert_equal(lichen_key_store_count(), TOFU_EDGE_FIRST_CONTACT_ENTRIES);

	for (size_t i = 0; i < TOFU_EDGE_REPLAY_REPETITIONS; i++) {
		zassert_equal(lichen_key_store_verify_or_pin(
			tofu_iid, tofu_bob_pubkey, NULL), -EEXIST);
	}
	zassert_equal(lichen_key_store_count(), TOFU_EDGE_FIRST_CONTACT_ENTRIES);
	zassert_ok(lichen_key_store_verify_or_pin(
		tofu_bob_iid, tofu_bob_pubkey, &result));
	zassert_equal(result, LICHEN_KEY_PIN_NEW);
	zassert_equal(lichen_key_store_count(), TOFU_EDGE_INDEPENDENT_ENTRIES);
}

ZTEST(coap_keys, test_tofu_first_contact_commits_before_publish)
{
	struct lichen_key_entry entry;
	enum lichen_key_pin_result result = LICHEN_KEY_PIN_MATCH;

	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, &result));
	zassert_equal(result, LICHEN_KEY_PIN_NEW);
	zassert_equal(mock_persist.save_calls, 1U);
	zassert_true(mock_persist.present);
	zassert_equal(mock_persist.revision, 1U);
	zassert_ok(lichen_key_store_get(tofu_iid, &entry));
	zassert_mem_equal(entry.pubkey, tofu_pubkey, sizeof(entry.pubkey));
	zassert_equal(entry.trust, LICHEN_KEY_TRUST_TOFU);

	/* A subsequent matching contact is idempotent and avoids flash wear. */
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, &result));
	zassert_equal(result, LICHEN_KEY_PIN_MATCH);
	zassert_equal(mock_persist.save_calls, 1U);
}

ZTEST(coap_keys, test_tofu_rejects_unbound_iid_before_persisting)
{
	uint8_t wrong_iid[LICHEN_KEY_IID_LEN];

	memcpy(wrong_iid, tofu_iid, sizeof(wrong_iid));
	wrong_iid[7] ^= 1U;
	zassert_ok(init_mock_store());
	zassert_equal(lichen_key_store_verify_or_pin(wrong_iid, tofu_pubkey, NULL),
		      -EKEYREJECTED);
	zassert_equal(mock_persist.save_calls, 0U);
	zassert_equal(lichen_key_store_count(), 0U);
}

ZTEST(coap_keys, test_tofu_mismatch_rejects_without_mutation_and_alerts)
{
	struct lichen_key_mismatch_audit audit;
	struct lichen_key_entry entry;
	uint64_t revision;

	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_set_mismatch_alert_cb(mock_alert_deliver,
							 &mock_alert));
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	revision = mock_persist.revision;
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	zassert_equal(mock_persist.save_calls, 1U,
		      "mismatch must not write the key store");
	zassert_equal(mock_persist.revision, revision);
	zassert_equal(mock_alert.calls, 1U);
	zassert_mem_equal(mock_alert.last.iid, tofu_iid, sizeof(tofu_iid));
	zassert_mem_equal(mock_alert.last.pinned_pubkey, tofu_pubkey,
			  sizeof(tofu_pubkey));
	zassert_mem_equal(mock_alert.last.presented_pubkey, pubkey_b,
			  sizeof(pubkey_b));
	zassert_ok(lichen_key_store_get_mismatch_audit(tofu_iid, &audit));
	zassert_equal(audit.sequence, 1U);
	zassert_equal(audit.attempts, 1U);
	zassert_equal(audit.last_delivery_error, 0);
	zassert_ok(lichen_key_store_get(tofu_iid, &entry));
	zassert_mem_equal(entry.pubkey, tofu_pubkey, sizeof(entry.pubkey));
}

ZTEST(coap_keys, test_tofu_mismatch_replay_is_counted_not_redelivered)
{
	struct lichen_key_mismatch_audit audit;

	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_set_mismatch_alert_cb(mock_alert_deliver,
							 &mock_alert));
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	for (int i = 0; i < 3; i++) {
		zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
			      -EEXIST);
	}
	zassert_ok(lichen_key_store_get_mismatch_audit(tofu_iid, &audit));
	zassert_equal(audit.attempts, 3U);
	zassert_equal(mock_alert.calls, 1U,
		      "identical replay must not amplify alerts");
	zassert_equal(mock_persist.save_calls, 1U);
}

ZTEST(coap_keys, test_tofu_mismatch_alert_error_is_audited_and_retried)
{
	struct lichen_key_mismatch_audit audit;

	mock_alert.error = -EIO;
	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_set_mismatch_alert_cb(mock_alert_deliver,
							 &mock_alert));
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	zassert_ok(lichen_key_store_get_mismatch_audit(tofu_iid, &audit));
	zassert_equal(audit.last_delivery_error, -EIO);

	mock_alert.error = 0;
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	zassert_ok(lichen_key_store_get_mismatch_audit(tofu_iid, &audit));
	zassert_equal(audit.attempts, 2U);
	zassert_equal(audit.last_delivery_error, 0);
	zassert_equal(mock_alert.calls, 2U);

	/* Once accepted, another replay remains audit-only. */
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	zassert_equal(mock_alert.calls, 2U);
}

ZTEST(coap_keys, test_tofu_pending_alert_delivers_on_sink_registration)
{
	struct lichen_key_mismatch_audit audit;

	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	zassert_ok(lichen_key_store_get_mismatch_audit(tofu_iid, &audit));
	zassert_equal(audit.last_delivery_error, -ENOTCONN);
	zassert_ok(lichen_key_store_set_mismatch_alert_cb(mock_alert_deliver,
							 &mock_alert));
	zassert_equal(mock_alert.calls, 1U);
	zassert_ok(lichen_key_store_get_mismatch_audit(tofu_iid, &audit));
	zassert_equal(audit.last_delivery_error, 0);
}

ZTEST(coap_keys, test_operator_sink_authenticates_bounded_mismatch_event)
{
	struct lichen_key_mismatch_audit decoded;
	uint64_t revision;

	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	revision = mock_persist.revision;
	zassert_ok(lichen_key_alert_sink_init(settings_auth_key,
					    mock_operator_deliver, &mock_operator));
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	zassert_equal(mock_persist.revision, revision,
		      "alert path must not mutate the durable key store");
	zassert_equal(mock_operator.calls, 1U);
	zassert_equal(mock_operator.len, LICHEN_KEY_ALERT_WIRE_LEN);
	zassert_ok(lichen_key_alert_decode(settings_auth_key, mock_operator.payload,
					 mock_operator.len, &decoded));
	zassert_equal(decoded.sequence, 1U);
	zassert_equal(decoded.attempts, 1U);
	zassert_equal(decoded.last_delivery_error, 0);
	zassert_mem_equal(decoded.iid, tofu_iid, sizeof(tofu_iid));
	zassert_mem_equal(decoded.pinned_pubkey, tofu_pubkey, sizeof(tofu_pubkey));
	zassert_mem_equal(decoded.presented_pubkey, pubkey_b, sizeof(pubkey_b));
}

ZTEST(coap_keys, test_operator_sink_rejects_tamper_wrong_key_and_bad_lengths)
{
	struct lichen_key_mismatch_audit decoded;
	uint8_t tampered[LICHEN_KEY_ALERT_WIRE_LEN];
	uint8_t wrong_key[LICHEN_KEY_ALERT_AUTH_KEY_LEN];

	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	zassert_ok(lichen_key_alert_sink_init(settings_auth_key,
					    mock_operator_deliver, &mock_operator));
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	memcpy(tampered, mock_operator.payload, sizeof(tampered));
	tampered[72] ^= 1U;
	zassert_equal(lichen_key_alert_decode(settings_auth_key, tampered,
					      sizeof(tampered), &decoded),
		      -EKEYREJECTED);
	memcpy(wrong_key, settings_auth_key, sizeof(wrong_key));
	wrong_key[0] ^= 1U;
	zassert_equal(lichen_key_alert_decode(wrong_key, mock_operator.payload,
					      mock_operator.len, &decoded),
		      -EKEYREJECTED);
	zassert_equal(lichen_key_alert_decode(settings_auth_key, mock_operator.payload,
					      mock_operator.len - 1U, &decoded),
		      -EMSGSIZE);
	zassert_equal(lichen_key_alert_decode(settings_auth_key, mock_operator.payload,
					      mock_operator.len + 1U, &decoded),
		      -EMSGSIZE);
}

ZTEST(coap_keys, test_operator_sink_backpressure_retries_then_suppresses_replay)
{
	struct lichen_key_mismatch_audit audit;

	mock_operator.error = -EAGAIN;
	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	zassert_ok(lichen_key_alert_sink_init(settings_auth_key,
					    mock_operator_deliver, &mock_operator));
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	zassert_equal(mock_operator.calls, 1U);
	zassert_ok(lichen_key_store_get_mismatch_audit(tofu_iid, &audit));
	zassert_equal(audit.last_delivery_error, -EAGAIN);

	mock_operator.error = 0;
	zassert_ok(lichen_key_alert_sink_retry());
	zassert_equal(mock_operator.calls, 2U);
	zassert_ok(lichen_key_store_get_mismatch_audit(tofu_iid, &audit));
	zassert_equal(audit.last_delivery_error, 0);
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	zassert_equal(mock_operator.calls, 2U,
		      "accepted sequence replay must not amplify operator traffic");
}

ZTEST(coap_keys, test_operator_sink_validates_registration_and_rebinds_after_reboot)
{
	uint8_t zero_key[LICHEN_KEY_ALERT_AUTH_KEY_LEN] = { 0 };

	zassert_equal(lichen_key_alert_sink_init(NULL, mock_operator_deliver,
						 &mock_operator), -EINVAL);
	zassert_equal(lichen_key_alert_sink_init(settings_auth_key, NULL,
						 &mock_operator), -EINVAL);
	zassert_equal(lichen_key_alert_sink_init(zero_key, mock_operator_deliver,
						 &mock_operator), -EKEYREJECTED);
	zassert_equal(lichen_key_alert_sink_retry(), -EACCES);

	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	zassert_ok(lichen_key_alert_sink_init(settings_auth_key,
					    mock_operator_deliver, &mock_operator));
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	zassert_equal(mock_operator.calls, 1U);

	/* Runtime callback state is lost at reboot; application init rebinds it
	 * after the authenticated key snapshot is restored. */
	lichen_key_store_test_reset();
	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_alert_sink_init(settings_auth_key,
					    mock_operator_deliver, &mock_operator));
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, pubkey_b, NULL),
		      -EEXIST);
	zassert_equal(mock_operator.calls, 2U);
}

ZTEST(coap_keys, test_tofu_save_failure_rolls_back_memory)
{
	mock_persist.save_error = -EIO;
	zassert_ok(init_mock_store());
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL),
		      -EIO);
	zassert_equal(mock_persist.save_calls, 1U);
	zassert_false(mock_persist.present);
	zassert_equal(lichen_key_store_count(), 0U);
}

ZTEST(coap_keys, test_tofu_pin_restores_after_runtime_reset)
{
	struct lichen_key_entry entry;

	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	zassert_equal(mock_persist.revision, 1U);

	/* Simulate reboot: clear only runtime state, preserving backend bytes. */
	lichen_key_store_test_reset();
	zassert_equal(lichen_key_store_count(), 0U);
	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_get(tofu_iid, &entry));
	zassert_mem_equal(entry.pubkey, tofu_pubkey, sizeof(entry.pubkey));
}

ZTEST(coap_keys, test_tofu_corrupt_snapshot_fails_closed)
{
	memcpy(mock_persist.entries[0].iid, tofu_iid, sizeof(tofu_iid));
	memcpy(mock_persist.entries[0].pubkey, pubkey_b, sizeof(pubkey_b));
	mock_persist.entries[0].trust = LICHEN_KEY_TRUST_TOFU;
	mock_persist.entries[0].valid = true;
	mock_persist.count = 1;
	mock_persist.revision = 1;
	mock_persist.present = true;

	zassert_equal(init_mock_store(), -EBADMSG);
	zassert_equal(lichen_key_store_count(), 0U);
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL),
		      -EACCES);
}

struct pin_thread_result {
	int rc;
	enum lichen_key_pin_result result;
};

K_THREAD_STACK_DEFINE(pin_stack_a, 1024);
K_THREAD_STACK_DEFINE(pin_stack_b, 1024);
static struct k_thread pin_thread_a;
static struct k_thread pin_thread_b;

static void pin_worker(void *arg, void *unused1, void *unused2)
{
	struct pin_thread_result *thread_result = arg;

	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	thread_result->rc = lichen_key_store_verify_or_pin(
		tofu_iid, tofu_pubkey, &thread_result->result);
}

static void mismatch_worker(void *arg, void *unused1, void *unused2)
{
	struct pin_thread_result *thread_result = arg;

	ARG_UNUSED(unused1);
	ARG_UNUSED(unused2);
	thread_result->rc = lichen_key_store_verify_or_pin(
		tofu_iid, pubkey_b, NULL);
}

ZTEST(coap_keys, test_tofu_concurrent_first_contact_is_single_commit)
{
	struct pin_thread_result a = { .rc = -1 };
	struct pin_thread_result b = { .rc = -1 };

	zassert_ok(init_mock_store());
	k_thread_create(&pin_thread_a, pin_stack_a,
			K_THREAD_STACK_SIZEOF(pin_stack_a), pin_worker, &a, NULL, NULL,
			5, 0, K_NO_WAIT);
	k_thread_create(&pin_thread_b, pin_stack_b,
			K_THREAD_STACK_SIZEOF(pin_stack_b), pin_worker, &b, NULL, NULL,
			5, 0, K_NO_WAIT);
	zassert_ok(k_thread_join(&pin_thread_a, K_SECONDS(2)));
	zassert_ok(k_thread_join(&pin_thread_b, K_SECONDS(2)));
	zassert_ok(a.rc);
	zassert_ok(b.rc);
	zassert_true((a.result == LICHEN_KEY_PIN_NEW &&
		      b.result == LICHEN_KEY_PIN_MATCH) ||
		     (b.result == LICHEN_KEY_PIN_NEW &&
		      a.result == LICHEN_KEY_PIN_MATCH));
	zassert_equal(mock_persist.save_calls, 1U);
	zassert_equal(lichen_key_store_count(), 1U);
}

ZTEST(coap_keys, test_tofu_concurrent_mismatch_is_one_bounded_alert)
{
	struct lichen_key_mismatch_audit audit;
	struct pin_thread_result a = { .rc = -1 };
	struct pin_thread_result b = { .rc = -1 };

	zassert_ok(init_mock_store());
	zassert_ok(lichen_key_store_set_mismatch_alert_cb(mock_alert_deliver,
							 &mock_alert));
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	k_thread_create(&pin_thread_a, pin_stack_a,
			K_THREAD_STACK_SIZEOF(pin_stack_a), mismatch_worker, &a, NULL, NULL,
			5, 0, K_NO_WAIT);
	k_thread_create(&pin_thread_b, pin_stack_b,
			K_THREAD_STACK_SIZEOF(pin_stack_b), mismatch_worker, &b, NULL, NULL,
			5, 0, K_NO_WAIT);
	zassert_ok(k_thread_join(&pin_thread_a, K_SECONDS(2)));
	zassert_ok(k_thread_join(&pin_thread_b, K_SECONDS(2)));
	zassert_equal(a.rc, -EEXIST);
	zassert_equal(b.rc, -EEXIST);
	zassert_equal(mock_alert.calls, 1U);
	zassert_ok(lichen_key_store_get_mismatch_audit(tofu_iid, &audit));
	zassert_equal(audit.attempts, 2U);
	zassert_equal(mock_persist.save_calls, 1U);
}

ZTEST(coap_keys, test_settings_backend_reboot_restores_authenticated_snapshot)
{
	struct lichen_key_entry entry;

	zassert_ok(init_fake_settings_store(settings_auth_key, 0));
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	zassert_not_null(fake_settings_find("lichen/tofu/1/meta"));

	fake_settings_reboot();
	zassert_ok(init_fake_settings_store(settings_auth_key, 1));
	zassert_ok(lichen_key_store_get(tofu_iid, &entry));
	zassert_mem_equal(entry.pubkey, tofu_pubkey, sizeof(entry.pubkey));
}

ZTEST(coap_keys, test_settings_backend_torn_save_keeps_previous_generation)
{
	uint8_t iid_b_derived[LICHEN_KEY_IID_LEN];
	struct lichen_key_entry entry;

	zassert_ok(init_fake_settings_store(settings_auth_key, 0));
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	zassert_ok(lichen_key_pubkey_to_iid(pubkey_b, iid_b_derived));
	/* Fail after invalidating slot 0 and writing its first entry. */
	fake_settings.fail_at_call = fake_settings.mutate_calls + 3U;
	zassert_equal(lichen_key_store_verify_or_pin(iid_b_derived, pubkey_b, NULL),
		      -EIO);
	zassert_equal(lichen_key_store_count(), 1U);

	fake_settings.fail_at_call = 0;
	fake_settings_reboot();
	zassert_ok(init_fake_settings_store(settings_auth_key, 1));
	zassert_ok(lichen_key_store_get(tofu_iid, &entry));
	zassert_equal(lichen_key_store_get(iid_b_derived, &entry), -ENOENT);
}

ZTEST(coap_keys, test_settings_backend_rejects_corruption_and_wrong_key)
{
	struct fake_settings_record *entry;
	uint8_t wrong_key[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN];

	zassert_ok(init_fake_settings_store(settings_auth_key, 0));
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	entry = fake_settings_find("lichen/tofu/1/e00");
	zassert_not_null(entry);
	entry->value[0] ^= 1U;
	fake_settings_reboot();
	zassert_equal(init_fake_settings_store(settings_auth_key, 1), -EKEYREJECTED);

	/* Restore the byte, but authenticate with a different device secret. */
	entry->value[0] ^= 1U;
	memcpy(wrong_key, settings_auth_key, sizeof(wrong_key));
	wrong_key[0] ^= 1U;
	fake_settings_reboot();
	zassert_equal(init_fake_settings_store(wrong_key, 1), -EKEYREJECTED);
}

ZTEST(coap_keys, test_settings_backend_rejects_revision_rollback)
{
	zassert_ok(init_fake_settings_store(settings_auth_key, 0));
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	fake_settings_reboot();
	zassert_equal(init_fake_settings_store(settings_auth_key, 2), -ESTALE);
}

ZTEST(coap_keys, test_settings_backend_delete_commits_empty_generation)
{
	zassert_ok(init_fake_settings_store(settings_auth_key, 0));
	zassert_ok(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL));
	zassert_ok(lichen_key_store_delete(tofu_iid));
	zassert_not_null(fake_settings_find("lichen/tofu/0/meta"));

	fake_settings_reboot();
	zassert_ok(init_fake_settings_store(settings_auth_key, 2));
	zassert_equal(lichen_key_store_count(), 0U);
}

ZTEST(coap_keys, test_settings_backend_propagates_load_error)
{
	fake_settings.load_error = -EIO;
	zassert_equal(init_fake_settings_store(settings_auth_key, 0), -EIO);
	zassert_equal(lichen_key_store_verify_or_pin(tofu_iid, tofu_pubkey, NULL),
		      -EACCES);
}

ZTEST(coap_keys, test_list_endpoint_truncates_with_valid_array_count)
{
	uint8_t cbor[512];
	size_t len;

	for (uint8_t i = 0; i < 8; i++) {
		uint8_t iid[LICHEN_KEY_IID_LEN] = { 0 };
		uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN] = { 0 };

		pubkey[0] = i;
		zassert_ok(lichen_key_pubkey_to_iid(pubkey, iid));
		zassert_equal(lichen_key_store_put(iid, pubkey,
					   LICHEN_KEY_TRUST_TOFU), 0);
	}

	len = lichen_key_store_test_encode_list(cbor, sizeof(cbor));
	zassert_true(len > 8U && len <= sizeof(cbor), "invalid endpoint length");
	zassert_equal(cbor[0], 0xa1, "outer value must be a map");
	zassert_equal(cbor[1], 0x64, "outer key must be text(4)");
	zassert_mem_equal(&cbor[2], "keys", 4, "outer key mismatch");
	zassert_equal(cbor[6], 0x98, "keys must use a definite array");
	zassert_equal(cbor[7], 3U,
		      "eight-key endpoint must deterministically truncate to three");

	/* Every encoded entry starts with a five-pair map. Walk the known
	 * fixed schema to prove the declared count consumes the full payload. */
	size_t off = 8U;
	for (uint8_t i = 0; i < cbor[7]; i++) {
		zassert_equal(cbor[off++], 0xa5, "entry %u is not map(5)", i);
		for (int field = 0; field < 10; field++) {
			uint8_t head = cbor[off++];
			size_t str_len = head & 0x1fU;

			zassert_equal(head >> 5, 3U, "entry %u field is not text", i);
			if (str_len == 24U) {
				str_len = cbor[off++];
			}
			off += str_len;
			zassert_true(off <= len, "entry %u exceeds payload", i);
		}
	}
	zassert_equal(off, len, "array count does not match encoded entries");
}

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
ZTEST(coap_keys, test_local_admin_in_test_context)
{
	/* In ZTEST context with NULL addr, lichen_coap_is_local_admin
	 * returns true, overriding the usual SLIP-interface check.
	 * This ensures PUT/DELETE handlers can execute in test builds. */
	zassert_true(lichen_coap_is_local_admin(NULL, 0),
		     "local admin check must pass in test context");
}
#endif /* CONFIG_LICHEN_COAP_SERVER_OSCORE */
