/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_APP_IDENTITY_STORE_H_
#define LICHEN_APP_IDENTITY_STORE_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_APP_IDENTITY_STORE_FORMAT_VERSION 2U
#define LICHEN_APP_IDENTITY_STORE_BLOB_MAX 92U
#define LICHEN_APP_IDENTITY_AUTHORITY_DIGEST_LEN 32U

struct lichen_link_ctx;

enum lichen_app_identity_store_blob {
  LICHEN_APP_IDENTITY_STORE_RECORD = 0,
  LICHEN_APP_IDENTITY_STORE_ESTABLISHED,
};

/**
 * Atomic private-storage operations.
 *
 * load returns zero and the exact serialized length, -ENOENT only when the
 * named blob has never been committed, or another negative errno. save MUST
 * atomically replace one complete blob or leave the previous blob intact.
 * Callbacks are synchronous and MUST NOT re-enter this module.
 */
struct lichen_app_identity_store_ops {
  int (*load)(void *user, enum lichen_app_identity_store_blob blob,
              uint8_t *out, size_t capacity, size_t *length);
  int (*save)(void *user, enum lichen_app_identity_store_blob blob,
              const uint8_t *value, size_t length);
};

/** Rollback-resistant identity authority held outside ordinary Settings. */
struct lichen_app_identity_authority_state {
  uint64_t revision;
  uint8_t digest[LICHEN_APP_IDENTITY_AUTHORITY_DIGEST_LEN];
};

/**
 * Protected monotonic authority operations.
 *
 * load MUST return -ENOENT only for authenticated virgin hardware. Loss,
 * corruption, or unavailability after initialization MUST return another
 * negative errno. commit MUST atomically compare the current state with
 * @p expected and install @p next, or leave it unchanged. A NULL expected
 * state means "must still be virgin". The operation MUST have definitive
 * success/failure semantics and MUST resist deletion and rollback independently
 * of the ordinary Settings backend. A virgin commit MUST accept only revision
 * 1; subsequent commits MUST accept only expected.revision + 1 and MUST reject
 * overflow.
 */
struct lichen_app_identity_authority_ops {
  int (*load)(void *user, struct lichen_app_identity_authority_state *state);
  int (*commit)(void *user,
                const struct lichen_app_identity_authority_state *expected,
                const struct lichen_app_identity_authority_state *next);
};

/** Fill @p out with @p length bytes from a cryptographically secure RNG. */
typedef int (*lichen_app_identity_rng_fn)(void *user, uint8_t *out,
                                          size_t length);

/**
 * Restore the established identity or create it on an authorized virgin
 * store, then install it into a freshly initialized link context.
 *
 * Missing/corrupt state after the established marker, unsupported versions,
 * EUI binding mismatches, backend failures, and CSPRNG failures all fail
 * closed. Persistent state is committed before the link context is mutated.
 */
int lichen_app_identity_load_or_create_key(
    struct lichen_link_ctx *ctx, const uint8_t eui64[8],
    const struct lichen_app_identity_store_ops *ops, void *store_user,
    const struct lichen_app_identity_authority_ops *authority_ops,
    void *authority_user, lichen_app_identity_rng_fn rng, void *rng_user);

/**
 * Persist a provisioned 32-byte seed on a virgin store, then install it.
 *
 * Existing valid or established state is never replaced; explicit factory
 * reset is required before provisioning another identity.
 */
int lichen_app_identity_provision_key(
    struct lichen_link_ctx *ctx, const uint8_t eui64[8], const uint8_t seed[32],
    const struct lichen_app_identity_store_ops *ops, void *store_user,
    const struct lichen_app_identity_authority_ops *authority_ops,
    void *authority_user);

/**
 * Register the platform-protected rollback authority used by Settings APIs.
 *
 * The operations object and user context MUST remain valid for the lifetime of
 * the system. Registration is one-time; repeating the identical registration
 * is idempotent and a different registration returns -EALREADY.
 */
int lichen_app_identity_settings_register_rollback_authority(
    const struct lichen_app_identity_authority_ops *ops, void *user);

/** Production Settings backend using the platform CSPRNG. */
int lichen_app_identity_settings_load_or_create_key(struct lichen_link_ctx *ctx,
                                                    const uint8_t eui64[8]);

/** Production Settings backend for authenticated commissioning. */
int lichen_app_identity_settings_provision_key(struct lichen_link_ctx *ctx,
                                               const uint8_t eui64[8],
                                               const uint8_t seed[32]);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_APP_IDENTITY_STORE_H_ */
