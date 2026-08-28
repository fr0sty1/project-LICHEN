/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_OSCORE_PERSIST_H_
#define LICHEN_OSCORE_PERSIST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OSCORE_PERSIST_FORMAT_VERSION 1U
#define OSCORE_PERSIST_BINDING_LEN 32U
#define OSCORE_PERSIST_TAG_LEN 32U
#define OSCORE_PERSIST_RECORD_LEN 96U
#define OSCORE_PERSIST_HEADER_LEN 20U
#define OSCORE_PERSIST_BLOB_MAX \
	(OSCORE_PERSIST_HEADER_LEN + \
	 (OSCORE_PERSIST_RECORD_LEN * CONFIG_LICHEN_OSCORE_MAX_CONTEXTS) + \
	 OSCORE_PERSIST_TAG_LEN)

enum oscore_persist_blob_slot {
	OSCORE_PERSIST_BLOB_A = 0,
	OSCORE_PERSIST_BLOB_B = 1,
};

struct oscore_persist_store_ops {
	int (*load)(void *user, enum oscore_persist_blob_slot slot,
		    uint8_t *out, size_t capacity, size_t *length);
	int (*save)(void *user, enum oscore_persist_blob_slot slot,
		    const uint8_t *value, size_t length);
};

struct oscore_persist_authority_state {
	uint64_t revision;
	uint8_t digest[OSCORE_PERSIST_TAG_LEN];
};

/**
 * Device-protected key and rollback authority.  This authority MUST use a
 * namespace dedicated to OSCORE state and MUST NOT live in ordinary Settings.
 * load returns -ENOENT only for authenticated virgin hardware.  commit is an
 * atomic compare-and-swap; expected is NULL only for the virgin transition.
 */
struct oscore_persist_protection_ops {
	int (*derive_key)(void *user, const uint8_t *context, size_t context_len,
			  uint8_t out[32]);
	int (*load)(void *user, struct oscore_persist_authority_state *state);
	int (*commit)(void *user,
		      const struct oscore_persist_authority_state *expected,
		      const struct oscore_persist_authority_state *next);
};

struct oscore_persist_state {
	uint64_t sender_seq;
	uint64_t recipient_seq;
	uint64_t response_piv_seq;
	uint64_t received_response_seq;
	uint64_t sent_response_seq;
	uint32_t replay_window;
	uint32_t response_piv_window;
	uint32_t received_response_window;
	uint32_t sent_response_window;
	bool sender_seq_valid;
	bool recipient_window_initialized;
	bool response_piv_window_initialized;
	bool received_response_window_initialized;
	bool sent_response_window_initialized;
};

struct oscore_persist_record {
	uint8_t binding[OSCORE_PERSIST_BINDING_LEN];
	struct oscore_persist_state state;
	bool active;
};

/** Fixed-size persistence state; callers allocate it statically. */
struct oscore_persist {
	const struct oscore_persist_store_ops *store_ops;
	void *store_user;
	const struct oscore_persist_protection_ops *protection_ops;
	void *protection_user;
	struct oscore_persist_authority_state authority;
	struct oscore_persist_record records[CONFIG_LICHEN_OSCORE_MAX_CONTEXTS];
	uint8_t auth_key[32];
	uint8_t blob[OSCORE_PERSIST_BLOB_MAX];
	bool ready;
	struct k_mutex lock;
};

int oscore_persist_open(
	struct oscore_persist *ctx,
	const struct oscore_persist_store_ops *store_ops, void *store_user,
	const struct oscore_persist_protection_ops *protection_ops,
	void *protection_user);

int oscore_persist_restore(
	struct oscore_persist *ctx,
	const uint8_t binding[OSCORE_PERSIST_BINDING_LEN],
	struct oscore_persist_state *state);

/** Persist-before-publish.  The old in-memory record remains on any failure. */
int oscore_persist_commit(
	struct oscore_persist *ctx,
	const uint8_t binding[OSCORE_PERSIST_BINDING_LEN],
	const struct oscore_persist_state *state);

void oscore_persist_close(struct oscore_persist *ctx);

/**
 * Register and load the namespace-separated Zephyr Settings backend.
 *
 * When CONFIG_LICHEN_OSCORE_SETTINGS is enabled this MUST succeed before any
 * oscore_ctx_create*() call.  Context creation otherwise fails closed with
 * OSCORE_ERR_NVM_FAILED.  Re-registering a different authority is rejected.
 */
int oscore_settings_register_protection(
	const struct oscore_persist_protection_ops *ops, void *user);
void oscore_settings_close(void);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_OSCORE_PERSIST_H_ */
