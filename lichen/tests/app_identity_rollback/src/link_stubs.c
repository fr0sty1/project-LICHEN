/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <lichen/link_ctx.h>
#include <monocypher.h>

int lichen_link_init(struct lichen_link_ctx *ctx, const uint8_t *eui64) {
  if (ctx == NULL || eui64 == NULL) {
    return -EINVAL;
  }
  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->eui64, eui64, LICHEN_EUI64_LEN);
  k_mutex_init(&ctx->seq_lock);
  return 0;
}

int lichen_link_derive_pubkey(const uint8_t seed[LICHEN_SEED_LEN],
                              uint8_t out_pk[LICHEN_PK_LEN]) {
  if (seed == NULL || out_pk == NULL) {
    return -EINVAL;
  }
  crypto_blake2b(out_pk, LICHEN_PK_LEN, seed, LICHEN_SEED_LEN);
  return 0;
}

int lichen_link_load_key(struct lichen_link_ctx *ctx,
                         const uint8_t seed[LICHEN_SEED_LEN]) {
  uint8_t public_key[LICHEN_PK_LEN];
  int ret;

  if (ctx == NULL || seed == NULL) {
    return -EINVAL;
  }
  ret = lichen_link_derive_pubkey(seed, public_key);
  if (ret == 0) {
    memcpy(ctx->ed25519_sk, seed, LICHEN_SK_LEN);
    memcpy(ctx->ed25519_pk, public_key, LICHEN_PK_LEN);
    ctx->has_key = true;
  }
  crypto_wipe(public_key, sizeof(public_key));
  return ret;
}
