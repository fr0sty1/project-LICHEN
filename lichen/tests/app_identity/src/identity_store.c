/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/crc.h>
#include <zephyr/ztest.h>

#include <lichen/app_identity/identity_store.h>
#include <lichen/link_ctx.h>

#define RECORD_VERSION_OFFSET 4U
#define RECORD_REVISION_OFFSET 8U
#define RECORD_EUI_OFFSET 16U
#define RECORD_SEED_OFFSET 24U
#define RECORD_PUBKEY_OFFSET 56U
#define RECORD_CRC_OFFSET 88U

struct fake_blob {
  uint8_t value[LICHEN_APP_IDENTITY_STORE_BLOB_MAX];
  size_t length;
  bool present;
  int load_error;
  int save_error;
};

struct fake_store {
  struct fake_blob blobs[2];
  enum lichen_app_identity_store_blob save_order[4];
  size_t save_count;
  struct lichen_app_identity_authority_state authority;
  bool authority_present;
  int authority_load_error;
  int authority_commit_error;
  size_t authority_load_count;
  size_t authority_commit_count;
};

struct fake_rng {
  uint8_t value[LICHEN_SEED_LEN];
  int result;
  size_t calls;
};

static const uint8_t store_eui64[LICHEN_EUI64_LEN] = {
    0x02, 0x10, 0x20, 0xff, 0xfe, 0x30, 0x40, 0x50,
};

static const uint8_t provisioned_seed[LICHEN_SEED_LEN] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
    0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
    0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
};

static int fake_load(void *user, enum lichen_app_identity_store_blob blob,
                     uint8_t *out, size_t capacity, size_t *length) {
  struct fake_store *store = user;
  struct fake_blob *item;

  if ((unsigned int)blob >= ARRAY_SIZE(store->blobs)) {
    return -EINVAL;
  }
  item = &store->blobs[blob];
  if (item->load_error != 0) {
    return item->load_error;
  }
  if (!item->present) {
    return -ENOENT;
  }
  if (item->length > capacity) {
    *length = item->length;
    return -EOVERFLOW;
  }
  memcpy(out, item->value, item->length);
  *length = item->length;
  return 0;
}

static int fake_save(void *user, enum lichen_app_identity_store_blob blob,
                     const uint8_t *value, size_t length) {
  struct fake_store *store = user;
  struct fake_blob *item;

  if ((unsigned int)blob >= ARRAY_SIZE(store->blobs) ||
      length > LICHEN_APP_IDENTITY_STORE_BLOB_MAX) {
    return -EINVAL;
  }
  item = &store->blobs[blob];
  if (item->save_error != 0) {
    return item->save_error;
  }
  memcpy(item->value, value, length);
  item->length = length;
  item->present = true;
  if (store->save_count < ARRAY_SIZE(store->save_order)) {
    store->save_order[store->save_count] = blob;
  }
  store->save_count++;
  return 0;
}

static int fake_random(void *user, uint8_t *out, size_t length) {
  struct fake_rng *rng = user;

  rng->calls++;
  if (rng->result != 0) {
    return rng->result;
  }
  if (length != sizeof(rng->value)) {
    return -EINVAL;
  }
  memcpy(out, rng->value, length);
  return 0;
}

static int
fake_authority_load(void *user,
                    struct lichen_app_identity_authority_state *state) {
  struct fake_store *store = user;

  store->authority_load_count++;
  if (store->authority_load_error != 0) {
    return store->authority_load_error;
  }
  if (!store->authority_present) {
    return -ENOENT;
  }
  *state = store->authority;
  return 0;
}

static int fake_authority_commit(
    void *user, const struct lichen_app_identity_authority_state *expected,
    const struct lichen_app_identity_authority_state *next) {
  struct fake_store *store = user;

  store->authority_commit_count++;
  if (store->authority_commit_error != 0) {
    return store->authority_commit_error;
  }
  if (next == NULL || next->revision == 0U ||
      (expected == NULL && next->revision != 1U) ||
      (expected != NULL && (expected->revision == UINT64_MAX ||
                            next->revision != expected->revision + 1U))) {
    return -ERANGE;
  }
  if ((expected == NULL && store->authority_present) ||
      (expected != NULL &&
       (!store->authority_present ||
        memcmp(expected, &store->authority, sizeof(*expected)) != 0))) {
    return -ESTALE;
  }
  store->authority = *next;
  store->authority_present = true;
  return 0;
}

static const struct lichen_app_identity_store_ops fake_ops = {
    .load = fake_load,
    .save = fake_save,
};

static const struct lichen_app_identity_authority_ops fake_authority_ops = {
    .load = fake_authority_load,
    .commit = fake_authority_commit,
};

static int load_or_create(struct lichen_link_ctx *ctx, struct fake_store *store,
                          struct fake_rng *rng) {
  return lichen_app_identity_load_or_create_key(ctx, store_eui64, &fake_ops,
                                                store, &fake_authority_ops,
                                                store, fake_random, rng);
}

static int provision(struct lichen_link_ctx *ctx, struct fake_store *store,
                     const uint8_t seed[LICHEN_SEED_LEN]) {
  return lichen_app_identity_provision_key(ctx, store_eui64, seed, &fake_ops,
                                           store, &fake_authority_ops, store);
}

static void put_le32(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t)value;
  out[1] = (uint8_t)(value >> 8);
  out[2] = (uint8_t)(value >> 16);
  out[3] = (uint8_t)(value >> 24);
}

static void init_rng(struct fake_rng *rng) {
  memset(rng, 0, sizeof(*rng));
  memcpy(rng->value, provisioned_seed, sizeof(rng->value));
}

static void init_ctx(struct lichen_link_ctx *ctx) {
  zassert_ok(lichen_link_init(ctx, store_eui64));
  zassert_false(ctx->has_key);
}

static void create_identity(struct fake_store *store, struct fake_rng *rng,
                            struct lichen_link_ctx *ctx) {
  init_ctx(ctx);
  zassert_ok(load_or_create(ctx, store, rng));
}

ZTEST(app_identity_store, test_first_boot_commits_before_publish_and_reboots) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx first;
  struct lichen_link_ctx rebooted;
  uint8_t public_key[LICHEN_PK_LEN];

  init_rng(&rng);
  create_identity(&store, &rng, &first);
  zassert_true(first.has_key);
  zassert_equal(rng.calls, 1U);
  zassert_equal(store.save_count, 2U);
  zassert_equal(store.save_order[0], LICHEN_APP_IDENTITY_STORE_RECORD);
  zassert_equal(store.save_order[1], LICHEN_APP_IDENTITY_STORE_ESTABLISHED);
  zassert_true(store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].present);
  zassert_true(store.blobs[LICHEN_APP_IDENTITY_STORE_ESTABLISHED].present);
  zassert_true(store.authority_present);
  zassert_equal(store.authority.revision, 1U);
  zassert_equal(store.authority_commit_count, 1U);
  memcpy(public_key, first.ed25519_pk, sizeof(public_key));

  init_ctx(&rebooted);
  zassert_ok(load_or_create(&rebooted, &store, &rng));
  zassert_equal(rng.calls, 1U, "reboot must not generate a new identity");
  zassert_equal(store.authority_commit_count, 1U);
  zassert_mem_equal(rebooted.ed25519_pk, public_key, sizeof(public_key));
}

ZTEST(app_identity_store, test_established_corruption_fails_closed) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx first;
  struct lichen_link_ctx rebooted;

  init_rng(&rng);
  create_identity(&store, &rng, &first);
  store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].value[RECORD_SEED_OFFSET] ^=
      0x01U;
  init_ctx(&rebooted);
  zassert_equal(load_or_create(&rebooted, &store, &rng), -EBADMSG);
  zassert_false(rebooted.has_key);
  zassert_equal(rng.calls, 1U);
}

ZTEST(app_identity_store, test_version_eui_and_missing_record_fail_closed) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx first;
  struct lichen_link_ctx rebooted;

  init_rng(&rng);
  create_identity(&store, &rng, &first);
  store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].value[RECORD_VERSION_OFFSET]++;
  init_ctx(&rebooted);
  zassert_equal(load_or_create(&rebooted, &store, &rng), -EBADMSG);

  store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].value[RECORD_VERSION_OFFSET]--;
  store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].value[RECORD_EUI_OFFSET] ^=
      0x01U;
  init_ctx(&rebooted);
  zassert_equal(load_or_create(&rebooted, &store, &rng), -EBADMSG,
                "CRC detects an altered EUI binding first");

  store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].present = false;
  init_ctx(&rebooted);
  zassert_equal(load_or_create(&rebooted, &store, &rng), -EBADMSG);
  zassert_false(rebooted.has_key);
  zassert_equal(rng.calls, 1U);
}

ZTEST(app_identity_store, test_backend_and_rng_errors_never_publish) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx ctx;

  init_rng(&rng);
  store.blobs[LICHEN_APP_IDENTITY_STORE_ESTABLISHED].load_error = -EIO;
  init_ctx(&ctx);
  zassert_equal(load_or_create(&ctx, &store, &rng), -EIO);
  zassert_false(ctx.has_key);
  zassert_equal(rng.calls, 0U);

  memset(&store, 0, sizeof(store));
  rng.result = -EAGAIN;
  init_ctx(&ctx);
  zassert_equal(load_or_create(&ctx, &store, &rng), -EAGAIN);
  zassert_false(ctx.has_key);
  zassert_false(store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].present);
}

ZTEST(app_identity_store, test_torn_commit_fails_closed) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx interrupted;
  struct lichen_link_ctx recovered;

  init_rng(&rng);
  store.blobs[LICHEN_APP_IDENTITY_STORE_ESTABLISHED].save_error = -EIO;
  init_ctx(&interrupted);
  zassert_equal(load_or_create(&interrupted, &store, &rng), -EIO);
  zassert_false(interrupted.has_key);
  zassert_true(store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].present);
  zassert_false(store.blobs[LICHEN_APP_IDENTITY_STORE_ESTABLISHED].present);
  zassert_false(store.authority_present);

  store.blobs[LICHEN_APP_IDENTITY_STORE_ESTABLISHED].save_error = 0;
  init_ctx(&recovered);
  zassert_equal(load_or_create(&recovered, &store, &rng), -EBADMSG);
  zassert_equal(rng.calls, 1U);
  zassert_false(recovered.has_key);
}

ZTEST(app_identity_store, test_record_save_error_leaves_store_virgin) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx ctx;

  init_rng(&rng);
  store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].save_error = -ENOSPC;
  init_ctx(&ctx);
  zassert_equal(load_or_create(&ctx, &store, &rng), -ENOSPC);
  zassert_false(ctx.has_key);
  zassert_false(store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].present);
  zassert_false(store.blobs[LICHEN_APP_IDENTITY_STORE_ESTABLISHED].present);
}

ZTEST(app_identity_store, test_authority_error_and_torn_anchor_never_publish) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx ctx;

  init_rng(&rng);
  store.authority_load_error = -EACCES;
  init_ctx(&ctx);
  zassert_equal(load_or_create(&ctx, &store, &rng), -EACCES);
  zassert_false(ctx.has_key);
  zassert_equal(rng.calls, 0U);

  memset(&store, 0, sizeof(store));
  store.authority_commit_error = -EIO;
  init_ctx(&ctx);
  zassert_equal(load_or_create(&ctx, &store, &rng), -EIO);
  zassert_false(ctx.has_key);
  zassert_false(store.authority_present);
  zassert_true(store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].present);
  zassert_true(store.blobs[LICHEN_APP_IDENTITY_STORE_ESTABLISHED].present);

  store.authority_commit_error = 0;
  init_ctx(&ctx);
  zassert_equal(load_or_create(&ctx, &store, &rng), -EBADMSG,
                "ordinary storage cannot establish its own authority");
  zassert_false(ctx.has_key);
  zassert_equal(rng.calls, 1U);
}

ZTEST(app_identity_store, test_authority_rejects_rollback_and_forgery) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx first;
  struct lichen_link_ctx rebooted;
  struct fake_blob *record;

  init_rng(&rng);
  create_identity(&store, &rng, &first);
  record = &store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD];

  /* Make an internally valid but stale revision. */
  record->value[RECORD_REVISION_OFFSET] = 2U;
  put_le32(&record->value[RECORD_CRC_OFFSET],
           crc32_ieee(record->value, RECORD_CRC_OFFSET));
  init_ctx(&rebooted);
  zassert_equal(load_or_create(&rebooted, &store, &rng), -ESTALE);
  zassert_false(rebooted.has_key);

  /* Restore the anchored record, then forge the protected digest. */
  record->value[RECORD_REVISION_OFFSET] = 1U;
  put_le32(&record->value[RECORD_CRC_OFFSET],
           crc32_ieee(record->value, RECORD_CRC_OFFSET));
  store.authority.digest[0] ^= 1U;
  init_ctx(&rebooted);
  zassert_equal(load_or_create(&rebooted, &store, &rng), -EKEYREJECTED);
  zassert_false(rebooted.has_key);
}

ZTEST(app_identity_store, test_authority_requires_both_settings_blobs) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx first;
  struct lichen_link_ctx rebooted;
  struct fake_blob saved_marker;

  init_rng(&rng);
  create_identity(&store, &rng, &first);
  saved_marker = store.blobs[LICHEN_APP_IDENTITY_STORE_ESTABLISHED];
  store.blobs[LICHEN_APP_IDENTITY_STORE_ESTABLISHED].present = false;
  init_ctx(&rebooted);
  zassert_equal(load_or_create(&rebooted, &store, &rng), -EBADMSG);

  store.blobs[LICHEN_APP_IDENTITY_STORE_ESTABLISHED] = saved_marker;
  store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].present = false;
  init_ctx(&rebooted);
  zassert_equal(load_or_create(&rebooted, &store, &rng), -EBADMSG);
  zassert_false(rebooted.has_key);
}

ZTEST(app_identity_store, test_settings_api_requires_registered_authority) {
  struct lichen_link_ctx ctx;

  init_ctx(&ctx);
  zassert_equal(
      lichen_app_identity_settings_load_or_create_key(&ctx, store_eui64),
      -EACCES);
  zassert_false(ctx.has_key);
}

ZTEST(app_identity_store, test_provisioning_is_one_time) {
  struct fake_store store = {0};
  struct lichen_link_ctx first;
  struct lichen_link_ctx second;
  uint8_t replacement[LICHEN_SEED_LEN];
  uint8_t public_key[LICHEN_PK_LEN];

  memset(replacement, 0x55, sizeof(replacement));
  init_ctx(&first);
  zassert_ok(provision(&first, &store, provisioned_seed));
  memcpy(public_key, first.ed25519_pk, sizeof(public_key));

  init_ctx(&second);
  zassert_equal(provision(&second, &store, replacement), -EEXIST);
  zassert_false(second.has_key);
  zassert_mem_equal(
      &store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD].value[RECORD_SEED_OFFSET],
      provisioned_seed, sizeof(provisioned_seed));
  zassert_mem_equal(&store.blobs[LICHEN_APP_IDENTITY_STORE_RECORD]
                         .value[RECORD_PUBKEY_OFFSET],
                    public_key, sizeof(public_key));
}

ZTEST(app_identity_store, test_rejects_already_initialized_context) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx ctx;

  init_rng(&rng);
  init_ctx(&ctx);
  zassert_ok(lichen_link_load_key(&ctx, provisioned_seed));
  zassert_equal(load_or_create(&ctx, &store, &rng), -EALREADY);
  zassert_equal(rng.calls, 0U);
  zassert_equal(store.save_count, 0U);
}

ZTEST(app_identity_store, test_rejects_context_eui_mismatch) {
  struct fake_store store = {0};
  struct fake_rng rng;
  struct lichen_link_ctx ctx;
  uint8_t other_eui[LICHEN_EUI64_LEN];

  init_rng(&rng);
  init_ctx(&ctx);
  memcpy(other_eui, store_eui64, sizeof(other_eui));
  other_eui[7] ^= 0x01U;
  zassert_equal(lichen_app_identity_load_or_create_key(
                    &ctx, other_eui, &fake_ops, &store, &fake_authority_ops,
                    &store, fake_random, &rng),
                -EKEYREJECTED);
  zassert_equal(rng.calls, 0U);
  zassert_equal(store.save_count, 0U);
}

ZTEST_SUITE(app_identity_store, NULL, NULL, NULL, NULL, NULL);
