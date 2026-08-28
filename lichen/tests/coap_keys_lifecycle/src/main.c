/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/ztest.h>

#include <lichen/coap_keys.h>
#include <lichen/coap_keys_settings.h>
#include <monocypher.h>

LOG_MODULE_REGISTER(lichen_coap_keys, LOG_LEVEL_NONE);

#define RECORD_CAPACITY 12U
#define KEY_CAPACITY 32U
#define VALUE_CAPACITY 64U

struct fake_record {
  char key[KEY_CAPACITY];
  uint8_t value[VALUE_CAPACITY];
  size_t length;
  bool present;
};

struct fake_settings {
  struct fake_record records[RECORD_CAPACITY];
  int save_error;
  int delete_error;
};

struct fake_protection {
  uint8_t root_key[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN];
  uint64_t floor;
  bool floor_present;
  int derive_error;
  int load_error;
  int advance_error;
  size_t advances;
};

struct alert_sink {
  size_t calls;
  struct lichen_key_mismatch_audit last;
};

static struct fake_settings settings_store;
static struct fake_protection protection;

static struct fake_record *find_record(struct fake_settings *settings,
                                       const char *key) {
  struct fake_record *free_record = NULL;

  for (size_t i = 0U; i < ARRAY_SIZE(settings->records); ++i) {
    if (settings->records[i].present &&
        strcmp(settings->records[i].key, key) == 0) {
      return &settings->records[i];
    }
    if (!settings->records[i].present && free_record == NULL) {
      free_record = &settings->records[i];
    }
  }
  return free_record;
}

static int fake_settings_load(void *ctx, lichen_key_settings_visit_cb visit,
                              void *user) {
  struct fake_settings *settings = ctx;
  static const char prefix[] = "lichen/tofu/";

  for (size_t i = 0U; i < ARRAY_SIZE(settings->records); ++i) {
    if (!settings->records[i].present) {
      continue;
    }
    if (strncmp(settings->records[i].key, prefix, sizeof(prefix) - 1U) != 0) {
      return -EBADMSG;
    }
    int ret =
        visit(&settings->records[i].key[sizeof(prefix) - 1U],
              settings->records[i].value, settings->records[i].length, user);

    if (ret != 0) {
      return ret;
    }
  }
  return 0;
}

static int fake_settings_save(void *ctx, const char *key, const uint8_t *value,
                              size_t length) {
  struct fake_settings *settings = ctx;
  struct fake_record *record;

  if (settings->save_error != 0) {
    return settings->save_error;
  }
  if (key == NULL || value == NULL || length > VALUE_CAPACITY ||
      strlen(key) >= KEY_CAPACITY) {
    return -EINVAL;
  }
  record = find_record(settings, key);
  if (record == NULL) {
    return -ENOSPC;
  }
  memset(record, 0, sizeof(*record));
  strcpy(record->key, key);
  memcpy(record->value, value, length);
  record->length = length;
  record->present = true;
  return 0;
}

static int fake_settings_delete(void *ctx, const char *key) {
  struct fake_settings *settings = ctx;
  struct fake_record *record;

  if (settings->delete_error != 0) {
    return settings->delete_error;
  }
  record = find_record(settings, key);
  if (record == NULL || !record->present) {
    return -ENOENT;
  }
  memset(record, 0, sizeof(*record));
  return 0;
}

static int fake_derive_key(void *user, const uint8_t *context,
                           size_t context_len,
                           uint8_t out[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN]) {
  struct fake_protection *state = user;
  static const uint8_t expected[] = LICHEN_KEY_SETTINGS_DERIVATION_CONTEXT;

  if (state->derive_error != 0) {
    return state->derive_error;
  }
  if (context_len != sizeof(expected) - 1U ||
      memcmp(context, expected, context_len) != 0) {
    return -EKEYREJECTED;
  }
  crypto_blake2b_keyed(out, LICHEN_KEY_SETTINGS_AUTH_KEY_LEN, state->root_key,
                       sizeof(state->root_key), context, context_len);
  return 0;
}

static int fake_load_floor(void *user, uint64_t *revision) {
  struct fake_protection *state = user;

  if (state->load_error != 0) {
    return state->load_error;
  }
  if (!state->floor_present) {
    return -ENOENT;
  }
  *revision = state->floor;
  return 0;
}

static int fake_advance_floor(void *user, const uint64_t *expected,
                              uint64_t next_revision) {
  struct fake_protection *state = user;

  state->advances++;
  if (state->advance_error != 0) {
    return state->advance_error;
  }
  if (next_revision == 0U ||
      (expected == NULL && (state->floor_present || next_revision != 1U)) ||
      (expected != NULL &&
       (!state->floor_present || *expected != state->floor ||
        state->floor == UINT64_MAX || next_revision != state->floor + 1U))) {
    return -ESTALE;
  }
  state->floor = next_revision;
  state->floor_present = true;
  return 0;
}

static const struct lichen_key_settings_ops settings_ops = {
    .load = fake_settings_load,
    .save = fake_settings_save,
    .delete = fake_settings_delete,
};

static const struct lichen_key_store_protection_ops protection_ops = {
    .derive_key = fake_derive_key,
    .load_floor = fake_load_floor,
    .advance_floor = fake_advance_floor,
};

int lichen_key_pubkey_to_iid(const uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN],
                             uint8_t iid[LICHEN_KEY_IID_LEN]) {
  if (pubkey == NULL || iid == NULL) {
    return -EINVAL;
  }
  crypto_blake2b(iid, LICHEN_KEY_IID_LEN, pubkey, LICHEN_KEY_PUBKEY_LEN);
  return 0;
}

static void make_peer(uint8_t discriminator, uint8_t iid[LICHEN_KEY_IID_LEN],
                      uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN]) {
  memset(pubkey, discriminator, LICHEN_KEY_PUBKEY_LEN);
  zassert_ok(lichen_key_pubkey_to_iid(pubkey, iid));
}

static int start_store(void) {
  return lichen_key_store_settings_test_init_protected(
      &protection_ops, &protection, &settings_ops, &settings_store);
}

static int capture_alert(void *user,
                         const struct lichen_key_mismatch_audit *event) {
  struct alert_sink *sink = user;

  sink->calls++;
  sink->last = *event;
  return 0;
}

static void *suite_setup(void) { return NULL; }

static void before_test(void *fixture) {
  ARG_UNUSED(fixture);
  lichen_key_store_test_reset();
  lichen_key_store_settings_test_reset();
  memset(&settings_store, 0, sizeof(settings_store));
  memset(&protection, 0, sizeof(protection));
  for (size_t i = 0U; i < sizeof(protection.root_key); ++i) {
    protection.root_key[i] = (uint8_t)(0xa0U + i);
  }
}

ZTEST(coap_keys_lifecycle, test_first_pin_idempotence_and_reboot) {
  uint8_t iid[LICHEN_KEY_IID_LEN];
  uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];
  enum lichen_key_pin_result result;
  struct lichen_key_entry entry;

  make_peer(1U, iid, pubkey);
  zassert_ok(start_store());
  zassert_ok(lichen_key_store_verify_or_pin(iid, pubkey, &result));
  zassert_equal(result, LICHEN_KEY_PIN_NEW);
  zassert_equal(protection.floor, 1U);
  zassert_equal(protection.advances, 1U);
  zassert_ok(lichen_key_store_verify_or_pin(iid, pubkey, &result));
  zassert_equal(result, LICHEN_KEY_PIN_MATCH);
  zassert_equal(protection.advances, 1U);

  lichen_key_store_test_reset();
  lichen_key_store_settings_test_reset();
  zassert_ok(start_store());
  zassert_ok(lichen_key_store_get(iid, &entry));
  zassert_mem_equal(entry.pubkey, pubkey, sizeof(pubkey));
}

ZTEST(coap_keys_lifecycle, test_mismatch_alerts_without_mutation) {
  uint8_t iid[LICHEN_KEY_IID_LEN];
  uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];
  uint8_t mismatch[LICHEN_KEY_PUBKEY_LEN];
  struct alert_sink sink = {0};

  make_peer(2U, iid, pubkey);
  memset(mismatch, 3, sizeof(mismatch));
  zassert_ok(start_store());
  zassert_ok(lichen_key_store_verify_or_pin(iid, pubkey, NULL));
  zassert_ok(lichen_key_store_set_mismatch_alert_cb(capture_alert, &sink));
  zassert_equal(lichen_key_store_verify_or_pin(iid, mismatch, NULL), -EEXIST);
  zassert_equal(sink.calls, 1U);
  zassert_mem_equal(sink.last.pinned_pubkey, pubkey, sizeof(pubkey));
  zassert_equal(protection.floor, 1U);
}

ZTEST(coap_keys_lifecycle, test_capacity_never_evicts) {
  uint8_t iid[LICHEN_KEY_IID_LEN];
  uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];

  zassert_ok(start_store());
  for (uint8_t i = 0U; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; ++i) {
    make_peer((uint8_t)(10U + i), iid, pubkey);
    zassert_ok(lichen_key_store_verify_or_pin(iid, pubkey, NULL));
  }
  make_peer(99U, iid, pubkey);
  zassert_equal(lichen_key_store_verify_or_pin(iid, pubkey, NULL), -ENOSPC);
  zassert_equal(lichen_key_store_count(), CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES);
  zassert_equal(protection.floor, CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES);
}

ZTEST(coap_keys_lifecycle, test_floor_failure_is_atomic) {
  uint8_t iid[LICHEN_KEY_IID_LEN];
  uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];

  make_peer(4U, iid, pubkey);
  zassert_ok(start_store());
  protection.advance_error = -EIO;
  zassert_equal(lichen_key_store_verify_or_pin(iid, pubkey, NULL), -EIO);
  zassert_equal(lichen_key_store_count(), 0U);
  zassert_false(protection.floor_present);

  protection.advance_error = 0;
  zassert_ok(lichen_key_store_verify_or_pin(iid, pubkey, NULL));
  zassert_equal(protection.floor, 1U);
}

ZTEST(coap_keys_lifecycle,
      test_established_floor_failure_restores_last_authorized_snapshot) {
  uint8_t first_iid[LICHEN_KEY_IID_LEN];
  uint8_t first_pubkey[LICHEN_KEY_PUBKEY_LEN];
  uint8_t second_iid[LICHEN_KEY_IID_LEN];
  uint8_t second_pubkey[LICHEN_KEY_PUBKEY_LEN];

  make_peer(40U, first_iid, first_pubkey);
  make_peer(41U, second_iid, second_pubkey);
  zassert_ok(start_store());
  zassert_ok(lichen_key_store_verify_or_pin(first_iid, first_pubkey, NULL));
  protection.advance_error = -EIO;
  zassert_equal(lichen_key_store_verify_or_pin(second_iid, second_pubkey, NULL),
                -EIO);
  zassert_equal(lichen_key_store_count(), 1U);
  zassert_equal(protection.floor, 1U);

  protection.advance_error = 0;
  lichen_key_store_test_reset();
  lichen_key_store_settings_test_reset();
  zassert_ok(start_store());
  zassert_equal(lichen_key_store_count(), 1U);
  zassert_ok(lichen_key_store_get(first_iid, &(struct lichen_key_entry){0}));
  zassert_equal(lichen_key_store_get(second_iid, &(struct lichen_key_entry){0}),
                -ENOENT);
}

ZTEST(coap_keys_lifecycle, test_unanchored_torn_snapshot_fails_closed) {
  uint8_t iid[LICHEN_KEY_IID_LEN];
  uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];

  make_peer(5U, iid, pubkey);
  zassert_ok(start_store());
  protection.advance_error = -EIO;
  zassert_equal(lichen_key_store_verify_or_pin(iid, pubkey, NULL), -EIO);
  lichen_key_store_test_reset();
  lichen_key_store_settings_test_reset();
  protection.advance_error = 0;
  zassert_equal(start_store(), -EBADMSG);
  zassert_equal(lichen_key_store_verify_or_pin(iid, pubkey, NULL), -EACCES);
}

ZTEST(coap_keys_lifecycle, test_rollback_and_one_sided_deletion_fail_closed) {
  struct fake_settings revision_one;
  uint8_t iid[LICHEN_KEY_IID_LEN];
  uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];

  zassert_ok(start_store());
  make_peer(6U, iid, pubkey);
  zassert_ok(lichen_key_store_verify_or_pin(iid, pubkey, NULL));
  revision_one = settings_store;
  make_peer(7U, iid, pubkey);
  zassert_ok(lichen_key_store_verify_or_pin(iid, pubkey, NULL));
  zassert_equal(protection.floor, 2U);

  settings_store = revision_one;
  lichen_key_store_test_reset();
  lichen_key_store_settings_test_reset();
  zassert_equal(start_store(), -ESTALE);

  settings_store = revision_one;
  protection.floor = 1U;
  struct fake_record *meta = find_record(&settings_store, "lichen/tofu/1/meta");
  zassert_not_null(meta);
  memset(meta, 0, sizeof(*meta));
  lichen_key_store_test_reset();
  lichen_key_store_settings_test_reset();
  zassert_equal(start_store(), -ESTALE);
}

ZTEST(coap_keys_lifecycle,
      test_corrupt_and_unavailable_protection_fail_closed) {
  struct fake_settings valid_settings;
  uint8_t iid[LICHEN_KEY_IID_LEN];
  uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];
  struct fake_record *meta;

  zassert_ok(start_store());
  make_peer(8U, iid, pubkey);
  zassert_ok(lichen_key_store_verify_or_pin(iid, pubkey, NULL));
  valid_settings = settings_store;
  meta = find_record(&settings_store, "lichen/tofu/1/meta");
  zassert_not_null(meta);
  meta->value[20] ^= 1U;
  lichen_key_store_test_reset();
  lichen_key_store_settings_test_reset();
  zassert_equal(start_store(), -EKEYREJECTED);

  settings_store = valid_settings;
  protection.root_key[0] ^= 1U;
  zassert_equal(start_store(), -EKEYREJECTED);
  protection.root_key[0] ^= 1U;

  protection.load_error = -EACCES;
  zassert_equal(start_store(), -EACCES);
  protection.load_error = 0;
  protection.derive_error = -EIO;
  zassert_equal(start_store(), -EIO);
}

ZTEST(coap_keys_lifecycle, test_existing_fake_settings_adapter_remains_usable) {
  static const uint8_t context[] = LICHEN_KEY_SETTINGS_DERIVATION_CONTEXT;
  uint8_t auth_key[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN];
  uint8_t iid[LICHEN_KEY_IID_LEN];
  uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];

  zassert_ok(
      fake_derive_key(&protection, context, sizeof(context) - 1U, auth_key));
  zassert_ok(lichen_key_store_settings_test_init(auth_key, 0U, &settings_ops,
                                                 &settings_store));
  make_peer(60U, iid, pubkey);
  zassert_ok(lichen_key_store_verify_or_pin(iid, pubkey, NULL));
  lichen_key_store_test_reset();
  lichen_key_store_settings_test_reset();
  zassert_ok(lichen_key_store_settings_test_init(auth_key, 1U, &settings_ops,
                                                 &settings_store));
  zassert_equal(lichen_key_store_count(), 1U);
  crypto_wipe(auth_key, sizeof(auth_key));
}

ZTEST_SUITE(coap_keys_lifecycle, NULL, suite_setup, before_test, NULL, NULL);
