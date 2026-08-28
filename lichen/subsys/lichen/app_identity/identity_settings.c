/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/app_identity/identity_store.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/settings/settings.h>

#define IDENTITY_SETTINGS_SUBTREE "lichen/identity"
#define IDENTITY_SETTINGS_RECORD_KEY IDENTITY_SETTINGS_SUBTREE "/key"
#define IDENTITY_SETTINGS_MARKER_KEY IDENTITY_SETTINGS_SUBTREE "/established"

struct settings_load_context {
  enum lichen_app_identity_store_blob requested;
  uint8_t *out;
  size_t capacity;
  size_t length;
  bool found;
  int error;
};

static K_MUTEX_DEFINE(s_authority_lock);
static const struct lichen_app_identity_authority_ops *s_authority_ops;
static void *s_authority_user;

static const char *blob_leaf(enum lichen_app_identity_store_blob blob) {
  switch (blob) {
  case LICHEN_APP_IDENTITY_STORE_RECORD:
    return "key";
  case LICHEN_APP_IDENTITY_STORE_ESTABLISHED:
    return "established";
  default:
    return NULL;
  }
}

static const char *blob_key(enum lichen_app_identity_store_blob blob) {
  switch (blob) {
  case LICHEN_APP_IDENTITY_STORE_RECORD:
    return IDENTITY_SETTINGS_RECORD_KEY;
  case LICHEN_APP_IDENTITY_STORE_ESTABLISHED:
    return IDENTITY_SETTINGS_MARKER_KEY;
  default:
    return NULL;
  }
}

static int settings_visit(const char *name, size_t length,
                          settings_read_cb read_cb, void *cb_arg, void *param) {
  struct settings_load_context *ctx = param;
  const char *requested = blob_leaf(ctx->requested);
  ssize_t got;

  if (ctx->error != 0) {
    return ctx->error;
  }
  if (strcmp(name, "key") != 0 && strcmp(name, "established") != 0) {
    ctx->error = -EBADMSG;
    return ctx->error;
  }
  if (strcmp(name, requested) != 0) {
    return 0;
  }
  if (ctx->found || length > ctx->capacity) {
    ctx->error = ctx->found ? -EBADMSG : -EOVERFLOW;
    return ctx->error;
  }
  got = read_cb(cb_arg, ctx->out, length);
  if (got < 0) {
    ctx->error = (int)got;
    return ctx->error;
  }
  if ((size_t)got != length) {
    ctx->error = -EBADMSG;
    return ctx->error;
  }
  ctx->length = length;
  ctx->found = true;
  return 0;
}

static int identity_settings_load(void *user,
                                  enum lichen_app_identity_store_blob blob,
                                  uint8_t *out, size_t capacity,
                                  size_t *length) {
  struct settings_load_context ctx = {
      .requested = blob,
      .out = out,
      .capacity = capacity,
  };
  int ret;

  ARG_UNUSED(user);
  if (blob_leaf(blob) == NULL || out == NULL || length == NULL) {
    return -EINVAL;
  }
  ret = settings_load_subtree_direct(IDENTITY_SETTINGS_SUBTREE, settings_visit,
                                     &ctx);
  if (ret != 0) {
    return ret;
  }
  if (ctx.error != 0) {
    return ctx.error;
  }
  if (!ctx.found) {
    return -ENOENT;
  }
  *length = ctx.length;
  return 0;
}

static int identity_settings_save(void *user,
                                  enum lichen_app_identity_store_blob blob,
                                  const uint8_t *value, size_t length) {
  const char *key = blob_key(blob);

  ARG_UNUSED(user);
  if (key == NULL || value == NULL || length == 0U ||
      length > LICHEN_APP_IDENTITY_STORE_BLOB_MAX) {
    return -EINVAL;
  }
  return settings_save_one(key, value, length);
}

static int settings_rng(void *user, uint8_t *out, size_t length) {
  ARG_UNUSED(user);
  return sys_csrand_get(out, length) == 0 ? 0 : -EIO;
}

static const struct lichen_app_identity_store_ops settings_ops = {
    .load = identity_settings_load,
    .save = identity_settings_save,
};

int lichen_app_identity_settings_register_rollback_authority(
    const struct lichen_app_identity_authority_ops *ops, void *user) {
  int ret = 0;

  if (ops == NULL || ops->load == NULL || ops->commit == NULL) {
    return -EINVAL;
  }
  k_mutex_lock(&s_authority_lock, K_FOREVER);
  if (s_authority_ops == NULL) {
    s_authority_ops = ops;
    s_authority_user = user;
  } else if (s_authority_ops != ops || s_authority_user != user) {
    ret = -EALREADY;
  }
  k_mutex_unlock(&s_authority_lock);
  return ret;
}

int lichen_app_identity_settings_load_or_create_key(struct lichen_link_ctx *ctx,
                                                    const uint8_t eui64[8]) {
  int ret;

  k_mutex_lock(&s_authority_lock, K_FOREVER);
  if (s_authority_ops == NULL) {
    ret = -EACCES;
    goto out;
  }
  ret = settings_subsys_init();
  if (ret != 0) {
    goto out;
  }
  ret = lichen_app_identity_load_or_create_key(
      ctx, eui64, &settings_ops, NULL, s_authority_ops, s_authority_user,
      settings_rng, NULL);
out:
  k_mutex_unlock(&s_authority_lock);
  return ret;
}

int lichen_app_identity_settings_provision_key(struct lichen_link_ctx *ctx,
                                               const uint8_t eui64[8],
                                               const uint8_t seed[32]) {
  int ret;

  k_mutex_lock(&s_authority_lock, K_FOREVER);
  if (s_authority_ops == NULL) {
    ret = -EACCES;
    goto out;
  }
  ret = settings_subsys_init();
  if (ret != 0) {
    goto out;
  }
  ret = lichen_app_identity_provision_key(ctx, eui64, seed, &settings_ops, NULL,
                                          s_authority_ops, s_authority_user);
out:
  k_mutex_unlock(&s_authority_lock);
  return ret;
}
