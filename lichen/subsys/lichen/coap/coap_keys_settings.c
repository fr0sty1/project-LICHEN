/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_keys_settings.c
 * @brief Authenticated two-generation Settings/NVS persistence
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/settings/settings.h>

#include <lichen/coap_keys.h>
#include <lichen/coap_keys_settings.h>
#include <monocypher.h>

#define SETTINGS_SUBTREE "lichen/tofu"
#define SETTINGS_MAGIC 0x4c544b53U /* "LTKS" */
#define SETTINGS_FORMAT_VERSION 1U
#define SETTINGS_SLOT_COUNT 2U
#define ENTRY_WIRE_LEN                                                         \
  (LICHEN_KEY_IID_LEN + LICHEN_KEY_PUBKEY_LEN + 1U + 4U + 4U)
#define META_PREFIX_LEN 16U
#define META_TAG_LEN 32U
#define META_WIRE_LEN (META_PREFIX_LEN + META_TAG_LEN)
#define RECORD_WIRE_MAX ENTRY_WIRE_LEN
#define SETTINGS_KEY_MAX_LEN 24U

struct settings_slot {
  uint8_t meta[META_WIRE_LEN];
  uint8_t entries[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES][ENTRY_WIRE_LEN];
  bool meta_present;
  bool entry_present[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES];
};

struct settings_backend_ctx {
  struct settings_slot slots[SETTINGS_SLOT_COUNT];
  uint8_t auth_key[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN];
  const struct lichen_key_settings_ops *ops;
  void *ops_ctx;
  uint64_t min_revision;
  const struct lichen_key_store_protection_ops *protection_ops;
  void *protection_ctx;
  bool floor_present;
};

struct zephyr_load_ctx {
  lichen_key_settings_visit_cb visit;
  void *user;
  int error;
};

static struct settings_backend_ctx s_backend;
static uint8_t s_encoded_entries[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES]
                                [ENTRY_WIRE_LEN];

static void put_le32(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t)value;
  out[1] = (uint8_t)(value >> 8);
  out[2] = (uint8_t)(value >> 16);
  out[3] = (uint8_t)(value >> 24);
}

static uint32_t get_le32(const uint8_t in[4]) {
  return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) |
         ((uint32_t)in[3] << 24);
}

static void put_le64(uint8_t out[8], uint64_t value) {
  for (size_t i = 0; i < 8; i++) {
    out[i] = (uint8_t)(value >> (i * 8U));
  }
}

static uint64_t get_le64(const uint8_t in[8]) {
  uint64_t value = 0;

  for (size_t i = 0; i < 8; i++) {
    value |= (uint64_t)in[i] << (i * 8U);
  }
  return value;
}

static void encode_entry(const struct lichen_key_entry *entry,
                         uint8_t out[ENTRY_WIRE_LEN]) {
  size_t off = 0;

  memcpy(&out[off], entry->iid, LICHEN_KEY_IID_LEN);
  off += LICHEN_KEY_IID_LEN;
  memcpy(&out[off], entry->pubkey, LICHEN_KEY_PUBKEY_LEN);
  off += LICHEN_KEY_PUBKEY_LEN;
  out[off++] = (uint8_t)entry->trust;
  put_le32(&out[off], entry->first_seen);
  off += 4U;
  put_le32(&out[off], entry->last_seen);
}

static void decode_entry(const uint8_t in[ENTRY_WIRE_LEN],
                         struct lichen_key_entry *entry) {
  size_t off = 0;

  memset(entry, 0, sizeof(*entry));
  memcpy(entry->iid, &in[off], LICHEN_KEY_IID_LEN);
  off += LICHEN_KEY_IID_LEN;
  memcpy(entry->pubkey, &in[off], LICHEN_KEY_PUBKEY_LEN);
  off += LICHEN_KEY_PUBKEY_LEN;
  entry->trust = (enum lichen_key_trust)in[off++];
  entry->first_seen = get_le32(&in[off]);
  off += 4U;
  entry->last_seen = get_le32(&in[off]);
  entry->valid = true;
}

static void make_tag(const uint8_t meta_prefix[META_PREFIX_LEN],
                     const uint8_t entries[][ENTRY_WIRE_LEN], size_t count,
                     uint8_t tag[META_TAG_LEN]) {
  static const uint8_t domain[] = "LICHEN-TOFU-SETTINGS-v1";
  crypto_blake2b_ctx hash;

  crypto_blake2b_keyed_init(&hash, META_TAG_LEN, s_backend.auth_key,
                            sizeof(s_backend.auth_key));
  crypto_blake2b_update(&hash, domain, sizeof(domain) - 1U);
  crypto_blake2b_update(&hash, meta_prefix, META_PREFIX_LEN);
  for (size_t i = 0; i < count; i++) {
    crypto_blake2b_update(&hash, entries[i], ENTRY_WIRE_LEN);
  }
  crypto_blake2b_final(&hash, tag);
}

static int parse_record_key(const char *key, size_t *slot, int *entry) {
  if (key == NULL || key[0] < '0' || key[0] > '1' || key[1] != '/') {
    return -EINVAL;
  }
  *slot = (size_t)(key[0] - '0');
  if (strcmp(&key[2], "meta") == 0) {
    *entry = -1;
    return 0;
  }
  if (key[2] != 'e' || key[3] < '0' || key[3] > '9' || key[4] < '0' ||
      key[4] > '9' || key[5] != '\0') {
    return -EINVAL;
  }
  *entry = (key[3] - '0') * 10 + (key[4] - '0');
  if (*entry >= CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES) {
    return -EINVAL;
  }
  return 0;
}

static int collect_record(const char *key, const uint8_t *value,
                          size_t value_len, void *user) {
  struct settings_backend_ctx *backend = user;
  size_t slot;
  int entry;
  int ret = parse_record_key(key, &slot, &entry);

  if (ret != 0 || value == NULL) {
    return -EBADMSG;
  }
  if (entry < 0) {
    if (value_len != META_WIRE_LEN || backend->slots[slot].meta_present) {
      return -EBADMSG;
    }
    memcpy(backend->slots[slot].meta, value, value_len);
    backend->slots[slot].meta_present = true;
  } else {
    if (value_len != ENTRY_WIRE_LEN ||
        backend->slots[slot].entry_present[entry]) {
      return -EBADMSG;
    }
    memcpy(backend->slots[slot].entries[entry], value, value_len);
    backend->slots[slot].entry_present[entry] = true;
  }
  return 0;
}

static int validate_slot(const struct settings_slot *slot, size_t slot_index,
                         uint64_t *revision, size_t *count) {
  uint8_t expected_tag[META_TAG_LEN];
  uint32_t magic;

  if (!slot->meta_present) {
    return -ENOENT;
  }
  magic = get_le32(slot->meta);
  *count = slot->meta[5];
  *revision = get_le64(&slot->meta[8]);
  if (magic != SETTINGS_MAGIC || slot->meta[4] != SETTINGS_FORMAT_VERSION ||
      slot->meta[6] != 0 || slot->meta[7] != 0 ||
      *count > CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES || *revision == 0 ||
      (*revision & 1U) != slot_index) {
    return -EBADMSG;
  }
  for (size_t i = 0; i < *count; i++) {
    if (!slot->entry_present[i]) {
      return -EBADMSG;
    }
  }
  make_tag(slot->meta, slot->entries, *count, expected_tag);
  if (crypto_verify32(expected_tag, &slot->meta[META_PREFIX_LEN]) != 0) {
    crypto_wipe(expected_tag, sizeof(expected_tag));
    return -EKEYREJECTED;
  }
  crypto_wipe(expected_tag, sizeof(expected_tag));
  return 0;
}

static int settings_backend_load(void *user, struct lichen_key_entry *entries,
                                 size_t capacity, size_t *count,
                                 uint64_t *revision) {
  struct settings_backend_ctx *backend = user;
  uint64_t revisions[SETTINGS_SLOT_COUNT] = {0};
  size_t counts[SETTINGS_SLOT_COUNT] = {0};
  int states[SETTINGS_SLOT_COUNT];
  int chosen = -1;
  int ret;

  memset(backend->slots, 0, sizeof(backend->slots));
  ret = backend->ops->load(backend->ops_ctx, collect_record, backend);
  if (ret != 0) {
    return ret;
  }
  if (backend->protection_ops != NULL) {
    if (!backend->floor_present) {
      for (size_t i = 0; i < SETTINGS_SLOT_COUNT; i++) {
        bool material = backend->slots[i].meta_present;

        for (size_t j = 0; j < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; j++) {
          material = material || backend->slots[i].entry_present[j];
        }
        if (material) {
          return -EBADMSG;
        }
      }
      return -ENOENT;
    }
    chosen = (int)(backend->min_revision & 1U);
    ret = validate_slot(&backend->slots[chosen], (size_t)chosen,
                        &revisions[chosen], &counts[chosen]);
    if (ret == -ENOENT) {
      return -ESTALE;
    }
    if (ret != 0) {
      return ret;
    }
    if (revisions[chosen] != backend->min_revision) {
      return -ESTALE;
    }
    goto copy_chosen;
  }
  for (size_t i = 0; i < SETTINGS_SLOT_COUNT; i++) {
    states[i] = validate_slot(&backend->slots[i], i, &revisions[i], &counts[i]);
    if (states[i] != 0 && states[i] != -ENOENT) {
      return states[i];
    }
    if (states[i] == 0 && (chosen < 0 || revisions[i] > revisions[chosen])) {
      chosen = (int)i;
    }
  }
  if (chosen < 0) {
    return backend->min_revision == 0 ? -ENOENT : -ESTALE;
  }
  if (revisions[chosen] < backend->min_revision) {
    return -ESTALE;
  }

copy_chosen:
  if (counts[chosen] > capacity) {
    return -ENOSPC;
  }
  for (size_t i = 0; i < counts[chosen]; i++) {
    decode_entry(backend->slots[chosen].entries[i], &entries[i]);
  }
  *count = counts[chosen];
  *revision = revisions[chosen];
  backend->min_revision = revisions[chosen];
  return 0;
}

static int make_key(char key[SETTINGS_KEY_MAX_LEN], size_t slot, int entry) {
  int len;

  if (entry < 0) {
    len = snprintf(key, SETTINGS_KEY_MAX_LEN, SETTINGS_SUBTREE "/%u/meta",
                   (unsigned int)slot);
  } else {
    len = snprintf(key, SETTINGS_KEY_MAX_LEN, SETTINGS_SUBTREE "/%u/e%02d",
                   (unsigned int)slot, entry);
  }
  return len > 0 && (size_t)len < SETTINGS_KEY_MAX_LEN ? 0 : -ENAMETOOLONG;
}

static int settings_backend_save(void *user,
                                 const struct lichen_key_entry *entries,
                                 size_t count, uint64_t revision) {
  struct settings_backend_ctx *backend = user;
  uint8_t meta[META_WIRE_LEN] = {0};
  char key[SETTINGS_KEY_MAX_LEN];
  size_t slot = (size_t)(revision & 1U);
  int ret;

  if (count > CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES || revision == 0 ||
      backend->min_revision == UINT64_MAX ||
      revision != backend->min_revision + 1U) {
    return -ERANGE;
  }
  put_le32(meta, SETTINGS_MAGIC);
  meta[4] = SETTINGS_FORMAT_VERSION;
  meta[5] = (uint8_t)count;
  put_le64(&meta[8], revision);
  for (size_t i = 0; i < count; i++) {
    encode_entry(&entries[i], s_encoded_entries[i]);
  }
  make_tag(meta, s_encoded_entries, count, &meta[META_PREFIX_LEN]);

  /* Invalidate the inactive slot first. The metadata record is the commit
   * marker, so any failure before the final save leaves the prior slot live. */
  ret = make_key(key, slot, -1);
  if (ret == 0) {
    ret = backend->ops->delete(backend->ops_ctx, key);
  }
  if (ret != 0 && ret != -ENOENT) {
    goto out;
  }
  for (size_t i = 0; i < count; i++) {
    ret = make_key(key, slot, (int)i);
    if (ret == 0) {
      ret = backend->ops->save(backend->ops_ctx, key, s_encoded_entries[i],
                               ENTRY_WIRE_LEN);
    }
    if (ret != 0) {
      goto out;
    }
  }
  for (size_t i = count; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; i++) {
    ret = make_key(key, slot, (int)i);
    if (ret == 0) {
      ret = backend->ops->delete(backend->ops_ctx, key);
    }
    if (ret != 0 && ret != -ENOENT) {
      goto out;
    }
  }
  ret = make_key(key, slot, -1);
  if (ret == 0) {
    ret = backend->ops->save(backend->ops_ctx, key, meta, sizeof(meta));
  }
  if (ret == 0) {
    if (backend->protection_ops != NULL) {
      const uint64_t *expected =
          backend->floor_present ? &backend->min_revision : NULL;

      ret = backend->protection_ops->advance_floor(backend->protection_ctx,
                                                   expected, revision);
      if (ret > 0) {
        ret = -EPROTO;
      }
    }
    if (ret == 0) {
      backend->min_revision = revision;
      backend->floor_present = true;
    }
  }

out:
  crypto_wipe(meta, sizeof(meta));
  crypto_wipe(s_encoded_entries, sizeof(s_encoded_entries));
  return ret;
}

static int zephyr_visit(const char *key, size_t len, settings_read_cb read_cb,
                        void *cb_arg, void *param) {
  struct zephyr_load_ctx *load_ctx = param;
  uint8_t value[RECORD_WIRE_MAX];
  ssize_t got;

  if (load_ctx->error != 0) {
    return load_ctx->error;
  }
  if (len > sizeof(value)) {
    load_ctx->error = -E2BIG;
    return load_ctx->error;
  }
  got = read_cb(cb_arg, value, len);
  if (got < 0) {
    load_ctx->error = (int)got;
    return load_ctx->error;
  }
  if ((size_t)got != len) {
    load_ctx->error = -EBADMSG;
    return load_ctx->error;
  }
  load_ctx->error = load_ctx->visit(key, value, len, load_ctx->user);
  return load_ctx->error;
}

static int zephyr_load(void *ctx, lichen_key_settings_visit_cb visit,
                       void *user) {
  struct zephyr_load_ctx load_ctx = {
      .visit = visit,
      .user = user,
  };
  int ret;

  ARG_UNUSED(ctx);
  ret = settings_load_subtree_direct(SETTINGS_SUBTREE, zephyr_visit, &load_ctx);
  return ret != 0 ? ret : load_ctx.error;
}

static int zephyr_save(void *ctx, const char *key, const uint8_t *value,
                       size_t value_len) {
  ARG_UNUSED(ctx);
  return settings_save_one(key, value, value_len);
}

static int zephyr_delete(void *ctx, const char *key) {
  ARG_UNUSED(ctx);
  return settings_delete(key);
}

static const struct lichen_key_settings_ops zephyr_ops = {
    .load = zephyr_load,
    .save = zephyr_save,
    .delete = zephyr_delete,
};

static int
backend_init(const uint8_t auth_key[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN],
             uint64_t min_revision, bool floor_present,
             const struct lichen_key_store_protection_ops *protection_ops,
             void *protection_ctx, const struct lichen_key_settings_ops *ops,
             void *ops_ctx) {
  if (auth_key == NULL || ops == NULL || ops->load == NULL ||
      ops->save == NULL || ops->delete == NULL) {
    return -EINVAL;
  }
  crypto_wipe(&s_backend, sizeof(s_backend));
  memcpy(s_backend.auth_key, auth_key, sizeof(s_backend.auth_key));
  s_backend.min_revision = min_revision;
  s_backend.floor_present = floor_present;
  s_backend.protection_ops = protection_ops;
  s_backend.protection_ctx = protection_ctx;
  s_backend.ops = ops;
  s_backend.ops_ctx = ops_ctx;
  return lichen_key_store_init(settings_backend_load, settings_backend_save,
                               &s_backend);
}

static int
validate_protection_ops(const struct lichen_key_store_protection_ops *ops) {
  if (ops == NULL || ops->derive_key == NULL || ops->load_floor == NULL ||
      ops->advance_floor == NULL) {
    return -EINVAL;
  }
  return 0;
}

static int
protected_init(const struct lichen_key_store_protection_ops *protection_ops,
               void *protection_ctx,
               const struct lichen_key_settings_ops *settings_ops,
               void *settings_ctx, bool initialize_settings) {
  static const uint8_t context[] = LICHEN_KEY_SETTINGS_DERIVATION_CONTEXT;
  uint8_t auth_key[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN] = {0};
  uint64_t floor = 0U;
  bool floor_present = false;
  uint8_t key_bits = 0U;
  int ret = validate_protection_ops(protection_ops);

  if (ret != 0 || settings_ops == NULL || settings_ops->load == NULL ||
      settings_ops->save == NULL || settings_ops->delete == NULL) {
    return -EINVAL;
  }
  ret = protection_ops->derive_key(protection_ctx, context,
                                   sizeof(context) - 1U, auth_key);
  if (ret > 0) {
    ret = -EPROTO;
  }
  if (ret != 0) {
    goto out;
  }
  for (size_t i = 0U; i < sizeof(auth_key); i++) {
    key_bits |= auth_key[i];
  }
  if (key_bits == 0U) {
    ret = -EKEYREJECTED;
    goto out;
  }
  ret = protection_ops->load_floor(protection_ctx, &floor);
  if (ret > 0) {
    ret = -EPROTO;
  }
  if (ret == 0) {
    if (floor == 0U) {
      ret = -EBADMSG;
      goto out;
    }
    floor_present = true;
  } else if (ret == -ENOENT) {
    floor = 0U;
    ret = 0;
  } else {
    goto out;
  }
  if (initialize_settings) {
    ret = settings_subsys_init();
    if (ret != 0) {
      goto out;
    }
  }
  ret = backend_init(auth_key, floor, floor_present, protection_ops,
                     protection_ctx, settings_ops, settings_ctx);

out:
  crypto_wipe(auth_key, sizeof(auth_key));
  return ret;
}

int lichen_key_store_settings_init_protected(
    const struct lichen_key_store_protection_ops *ops, void *user) {
  return protected_init(ops, user, &zephyr_ops, NULL, true);
}

#ifdef CONFIG_LICHEN_COAP_KEYS_TEST_HOOKS
int lichen_key_store_settings_test_init_protected(
    const struct lichen_key_store_protection_ops *protection_ops,
    void *protection_ctx, const struct lichen_key_settings_ops *settings_ops,
    void *settings_ctx) {
  return protected_init(protection_ops, protection_ctx, settings_ops,
                        settings_ctx, false);
}

int lichen_key_store_settings_test_init(
    const uint8_t auth_key[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN],
    uint64_t min_revision, const struct lichen_key_settings_ops *ops,
    void *ctx) {
  return backend_init(auth_key, min_revision, min_revision != 0U, NULL, NULL,
                      ops, ctx);
}

void lichen_key_store_settings_test_reset(void) {
  crypto_wipe(&s_backend, sizeof(s_backend));
  crypto_wipe(s_encoded_entries, sizeof(s_encoded_entries));
}
#endif
