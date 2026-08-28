/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/app_identity/identity_store.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/crc.h>

#include <lichen/link_ctx.h>
#include <monocypher.h>

#define IDENTITY_MAGIC UINT32_C(0x594b494c) /* "LIKY", little endian */
#define MARKER_MAGIC UINT32_C(0x4d494c)     /* "LIM", little endian */
#define RECORD_LEN 92U
#define MARKER_LEN 8U
#define RECORD_REVISION_OFFSET 8U
#define RECORD_EUI_OFFSET 16U
#define RECORD_SEED_OFFSET 24U
#define RECORD_PUBKEY_OFFSET 56U
#define RECORD_CRC_OFFSET 88U
#define INITIAL_REVISION UINT64_C(1)

BUILD_ASSERT(RECORD_LEN == LICHEN_APP_IDENTITY_STORE_BLOB_MAX,
             "public identity blob bound must equal the record format");

static K_MUTEX_DEFINE(s_identity_store_lock);

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
  for (size_t i = 0U; i < 8U; ++i) {
    out[i] = (uint8_t)(value >> (8U * i));
  }
}

static uint64_t get_le64(const uint8_t in[8]) {
  uint64_t value = 0U;

  for (size_t i = 0U; i < 8U; ++i) {
    value |= (uint64_t)in[i] << (8U * i);
  }
  return value;
}

static int validate_ops(const struct lichen_app_identity_store_ops *ops) {
  if (ops == NULL || ops->load == NULL || ops->save == NULL) {
    return -EINVAL;
  }
  return 0;
}

static int
validate_authority_ops(const struct lichen_app_identity_authority_ops *ops) {
  if (ops == NULL || ops->load == NULL || ops->commit == NULL) {
    return -EINVAL;
  }
  return 0;
}

static void encode_marker(uint8_t marker[MARKER_LEN]) {
  memset(marker, 0, MARKER_LEN);
  put_le32(marker, MARKER_MAGIC);
  marker[4] = LICHEN_APP_IDENTITY_STORE_FORMAT_VERSION;
}

static int validate_marker(const uint8_t marker[MARKER_LEN], size_t length) {
  if (length != MARKER_LEN || get_le32(marker) != MARKER_MAGIC ||
      marker[4] != LICHEN_APP_IDENTITY_STORE_FORMAT_VERSION ||
      marker[5] != 0U || marker[6] != 0U || marker[7] != 0U) {
    return -EBADMSG;
  }
  return 0;
}

static int encode_record(const uint8_t eui64[8], const uint8_t seed[32],
                         uint64_t revision, uint8_t record[RECORD_LEN]) {
  uint8_t public_key[LICHEN_PK_LEN];
  int ret = lichen_link_derive_pubkey(seed, public_key);

  if (ret != 0) {
    crypto_wipe(public_key, sizeof(public_key));
    return ret;
  }
  if (revision == 0U) {
    crypto_wipe(public_key, sizeof(public_key));
    return -EINVAL;
  }
  memset(record, 0, RECORD_LEN);
  put_le32(record, IDENTITY_MAGIC);
  record[4] = LICHEN_APP_IDENTITY_STORE_FORMAT_VERSION;
  put_le64(&record[RECORD_REVISION_OFFSET], revision);
  memcpy(&record[RECORD_EUI_OFFSET], eui64, LICHEN_EUI64_LEN);
  memcpy(&record[RECORD_SEED_OFFSET], seed, LICHEN_SEED_LEN);
  memcpy(&record[RECORD_PUBKEY_OFFSET], public_key, LICHEN_PK_LEN);
  put_le32(&record[RECORD_CRC_OFFSET], crc32_ieee(record, RECORD_CRC_OFFSET));
  crypto_wipe(public_key, sizeof(public_key));
  return 0;
}

static int validate_record(const uint8_t record[RECORD_LEN], size_t length,
                           const uint8_t eui64[8], uint8_t seed[32],
                           uint64_t *revision) {
  uint8_t derived_public_key[LICHEN_PK_LEN];
  uint32_t expected_crc;
  int ret;

  if (length != RECORD_LEN || get_le32(record) != IDENTITY_MAGIC ||
      record[4] != LICHEN_APP_IDENTITY_STORE_FORMAT_VERSION ||
      record[5] != 0U || record[6] != 0U || record[7] != 0U) {
    return -EBADMSG;
  }
  *revision = get_le64(&record[RECORD_REVISION_OFFSET]);
  if (*revision == 0U) {
    return -EBADMSG;
  }
  expected_crc = crc32_ieee(record, RECORD_CRC_OFFSET);
  if (get_le32(&record[RECORD_CRC_OFFSET]) != expected_crc) {
    return -EBADMSG;
  }
  if (memcmp(&record[RECORD_EUI_OFFSET], eui64, LICHEN_EUI64_LEN) != 0) {
    return -EKEYREJECTED;
  }
  ret = lichen_link_derive_pubkey(&record[RECORD_SEED_OFFSET],
                                  derived_public_key);
  if (ret == 0 &&
      crypto_verify32(derived_public_key, &record[RECORD_PUBKEY_OFFSET]) != 0) {
    ret = -EKEYREJECTED;
  }
  crypto_wipe(derived_public_key, sizeof(derived_public_key));
  if (ret != 0) {
    return ret;
  }
  memcpy(seed, &record[RECORD_SEED_OFFSET], LICHEN_SEED_LEN);
  return 0;
}

static void
digest_record(const uint8_t record[RECORD_LEN],
              uint8_t digest[LICHEN_APP_IDENTITY_AUTHORITY_DIGEST_LEN]) {
  crypto_blake2b(digest, LICHEN_APP_IDENTITY_AUTHORITY_DIGEST_LEN, record,
                 RECORD_LEN);
}

static int load_blob(const struct lichen_app_identity_store_ops *ops,
                     void *user, enum lichen_app_identity_store_blob blob,
                     uint8_t *out, size_t capacity, size_t *length) {
  *length = 0U;
  int ret = ops->load(user, blob, out, capacity, length);

  if (ret == 0 && *length > capacity) {
    return -EOVERFLOW;
  }
  return ret;
}

/* Return 0 with seed, -ENOENT only for an authorized virgin store. */
static int
restore_seed(const uint8_t eui64[8],
             const struct lichen_app_identity_store_ops *ops, void *user,
             const struct lichen_app_identity_authority_ops *authority_ops,
             void *authority_user, uint8_t seed[32]) {
  uint8_t marker[MARKER_LEN] = {0};
  uint8_t record[RECORD_LEN] = {0};
  uint8_t digest[LICHEN_APP_IDENTITY_AUTHORITY_DIGEST_LEN] = {0};
  struct lichen_app_identity_authority_state authority = {0};
  size_t marker_len = 0U;
  size_t record_len = 0U;
  uint64_t revision = 0U;
  int authority_ret;
  int marker_ret;
  int record_ret;
  int ret = 0;

  authority_ret = authority_ops->load(authority_user, &authority);
  marker_ret = load_blob(ops, user, LICHEN_APP_IDENTITY_STORE_ESTABLISHED,
                         marker, sizeof(marker), &marker_len);
  record_ret = load_blob(ops, user, LICHEN_APP_IDENTITY_STORE_RECORD, record,
                         sizeof(record), &record_len);

  if (authority_ret == -ENOENT) {
    if (marker_ret == -ENOENT && record_ret == -ENOENT) {
      ret = -ENOENT;
    } else if (marker_ret != 0 && marker_ret != -ENOENT) {
      ret = marker_ret;
    } else if (record_ret != 0 && record_ret != -ENOENT) {
      ret = record_ret;
    } else {
      ret = -EBADMSG;
    }
    goto out;
  }
  if (authority_ret != 0) {
    ret = authority_ret;
    goto out;
  }
  if (marker_ret != 0) {
    ret = marker_ret == -ENOENT ? -EBADMSG : marker_ret;
    goto out;
  }
  if (record_ret != 0) {
    ret = record_ret == -ENOENT ? -EBADMSG : record_ret;
    goto out;
  }
  ret = validate_marker(marker, marker_len);
  if (ret == 0) {
    ret = validate_record(record, record_len, eui64, seed, &revision);
  }
  if (ret != 0) {
    goto out;
  }
  digest_record(record, digest);
  if (authority.revision != revision) {
    ret = -ESTALE;
  } else if (crypto_verify32(authority.digest, digest) != 0) {
    ret = -EKEYREJECTED;
  }

out:
  crypto_wipe(&authority, sizeof(authority));
  crypto_wipe(digest, sizeof(digest));
  crypto_wipe(marker, sizeof(marker));
  crypto_wipe(record, sizeof(record));
  if (ret != 0) {
    crypto_wipe(seed, LICHEN_SEED_LEN);
  }
  return ret;
}

static int
persist_seed(const uint8_t eui64[8], const uint8_t seed[32],
             const struct lichen_app_identity_store_ops *ops, void *user,
             const struct lichen_app_identity_authority_ops *authority_ops,
             void *authority_user, uint64_t revision) {
  uint8_t record[RECORD_LEN] = {0};
  uint8_t marker[MARKER_LEN] = {0};
  struct lichen_app_identity_authority_state next = {.revision = revision};
  int ret = encode_record(eui64, seed, revision, record);

  if (ret != 0) {
    goto out;
  }
  encode_marker(marker);
  digest_record(record, next.digest);
  ret =
      ops->save(user, LICHEN_APP_IDENTITY_STORE_RECORD, record, sizeof(record));
  if (ret == 0) {
    ret = ops->save(user, LICHEN_APP_IDENTITY_STORE_ESTABLISHED, marker,
                    sizeof(marker));
  }
  if (ret == 0) {
    ret = authority_ops->commit(authority_user, NULL, &next);
  }

out:
  crypto_wipe(&next, sizeof(next));
  crypto_wipe(record, sizeof(record));
  crypto_wipe(marker, sizeof(marker));
  return ret;
}

static int install_seed(struct lichen_link_ctx *ctx, const uint8_t seed[32]) {
  if (ctx->has_key) {
    return -EALREADY;
  }
  return lichen_link_load_key(ctx, seed);
}

static int provision_locked(
    struct lichen_link_ctx *ctx, const uint8_t eui64[8], const uint8_t seed[32],
    const struct lichen_app_identity_store_ops *ops, void *store_user,
    const struct lichen_app_identity_authority_ops *authority_ops,
    void *authority_user) {
  uint8_t existing[LICHEN_SEED_LEN];
  int ret = restore_seed(eui64, ops, store_user, authority_ops, authority_user,
                         existing);

  crypto_wipe(existing, sizeof(existing));
  if (ret == 0) {
    return -EEXIST;
  }
  if (ret != -ENOENT) {
    return ret;
  }
  ret = persist_seed(eui64, seed, ops, store_user, authority_ops,
                     authority_user, INITIAL_REVISION);
  if (ret != 0) {
    return ret;
  }
  return install_seed(ctx, seed);
}

int lichen_app_identity_load_or_create_key(
    struct lichen_link_ctx *ctx, const uint8_t eui64[8],
    const struct lichen_app_identity_store_ops *ops, void *store_user,
    const struct lichen_app_identity_authority_ops *authority_ops,
    void *authority_user, lichen_app_identity_rng_fn rng, void *rng_user) {
  uint8_t seed[LICHEN_SEED_LEN];
  int ret;

  if (ctx == NULL || eui64 == NULL || rng == NULL || validate_ops(ops) != 0 ||
      validate_authority_ops(authority_ops) != 0) {
    return -EINVAL;
  }
  if (memcmp(ctx->eui64, eui64, LICHEN_EUI64_LEN) != 0) {
    return -EKEYREJECTED;
  }
  k_mutex_lock(&s_identity_store_lock, K_FOREVER);
  if (ctx->has_key) {
    ret = -EALREADY;
    goto out;
  }
  ret =
      restore_seed(eui64, ops, store_user, authority_ops, authority_user, seed);
  if (ret == -ENOENT) {
    ret = rng(rng_user, seed, sizeof(seed));
    if (ret > 0) {
      ret = -EIO;
    }
    if (ret == 0) {
      ret = persist_seed(eui64, seed, ops, store_user, authority_ops,
                         authority_user, INITIAL_REVISION);
    }
  }
  if (ret == 0) {
    ret = install_seed(ctx, seed);
  }

out:
  crypto_wipe(seed, sizeof(seed));
  k_mutex_unlock(&s_identity_store_lock);
  return ret;
}

int lichen_app_identity_provision_key(
    struct lichen_link_ctx *ctx, const uint8_t eui64[8], const uint8_t seed[32],
    const struct lichen_app_identity_store_ops *ops, void *store_user,
    const struct lichen_app_identity_authority_ops *authority_ops,
    void *authority_user) {
  int ret;

  if (ctx == NULL || eui64 == NULL || seed == NULL || validate_ops(ops) != 0 ||
      validate_authority_ops(authority_ops) != 0) {
    return -EINVAL;
  }
  if (memcmp(ctx->eui64, eui64, LICHEN_EUI64_LEN) != 0) {
    return -EKEYREJECTED;
  }
  k_mutex_lock(&s_identity_store_lock, K_FOREVER);
  ret = ctx->has_key ? -EALREADY
                     : provision_locked(ctx, eui64, seed, ops, store_user,
                                        authority_ops, authority_user);
  k_mutex_unlock(&s_identity_store_lock);
  return ret;
}

#undef RECORD_CRC_OFFSET
#undef RECORD_PUBKEY_OFFSET
#undef RECORD_SEED_OFFSET
#undef RECORD_EUI_OFFSET
#undef RECORD_REVISION_OFFSET
#undef INITIAL_REVISION
#undef MARKER_LEN
#undef RECORD_LEN
#undef MARKER_MAGIC
#undef IDENTITY_MAGIC
