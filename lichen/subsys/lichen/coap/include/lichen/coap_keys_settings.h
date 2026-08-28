/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_keys_settings.h
 * @brief Authenticated crash-safe Settings backend for the TOFU key store
 */

#ifndef LICHEN_COAP_KEYS_SETTINGS_H_
#define LICHEN_COAP_KEYS_SETTINGS_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_KEY_SETTINGS_AUTH_KEY_LEN 32U
#define LICHEN_KEY_SETTINGS_DERIVATION_CONTEXT "LICHEN-TOFU-SETTINGS-AUTH-v1"

/** Platform-protected root-key derivation and monotonic revision floor. */
struct lichen_key_store_protection_ops {
  /** Derive @p out from a non-exported device root and the given context. */
  int (*derive_key)(void *user, const uint8_t *context, size_t context_len,
                    uint8_t out[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN]);
  /** Return -ENOENT only for authenticated virgin protected storage. */
  int (*load_floor)(void *user, uint64_t *revision);
  /**
   * Atomically compare the floor with @p expected and advance it to
   * @p next_revision. NULL expected means the floor must still be virgin.
   */
  int (*advance_floor)(void *user, const uint64_t *expected,
                       uint64_t next_revision);
};

/**
 * Initialize Zephyr Settings/NVS and bind it to the durable TOFU store.
 *
 * The platform callbacks MUST derive a namespace-separated secret without
 * exporting the device root, distinguish authenticated virgin state from
 * loss/corruption, and atomically accept only revision 1 for a virgin floor or
 * expected + 1 thereafter. Settings metadata is committed before the floor;
 * keys are published only after both commits succeed. On reboot the selected
 * snapshot MUST exactly match the protected floor. Callbacks are synchronous,
 * return zero or a negative errno, and MUST NOT re-enter the key-store API.
 * Call this after the platform protected-root/floor service is ready and before
 * enabling any peer-key observation; initialization is not concurrent-safe.
 * The operations object and user context MUST remain valid for system life.
 */
int lichen_key_store_settings_init_protected(
    const struct lichen_key_store_protection_ops *ops, void *user);

typedef int (*lichen_key_settings_visit_cb)(const char *key,
                                            const uint8_t *value,
                                            size_t value_len, void *user);

struct lichen_key_settings_ops {
  int (*load)(void *ctx, lichen_key_settings_visit_cb visit, void *user);
  int (*save)(void *ctx, const char *key, const uint8_t *value,
              size_t value_len);
  int (*delete)(void *ctx, const char *key);
};

#ifdef CONFIG_LICHEN_COAP_KEYS_TEST_HOOKS
/** Bind a deterministic fake Settings store for focused tests. */
int lichen_key_store_settings_test_init(
    const uint8_t auth_key[LICHEN_KEY_SETTINGS_AUTH_KEY_LEN],
    uint64_t min_revision, const struct lichen_key_settings_ops *ops,
    void *ctx);

/** Bind deterministic Settings and protected-floor backends. */
int lichen_key_store_settings_test_init_protected(
    const struct lichen_key_store_protection_ops *protection_ops,
    void *protection_ctx, const struct lichen_key_settings_ops *settings_ops,
    void *settings_ctx);

/** Clear backend runtime state without modifying the fake durable store. */
void lichen_key_store_settings_test_reset(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_KEYS_SETTINGS_H_ */
