/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_REPLAY_PERSIST_H_
#define LICHEN_REPLAY_PERSIST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>
#include <lichen/replay.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_REPLAY_PERSIST_FORMAT_VERSION 1U
#define LICHEN_REPLAY_PERSIST_TAG_LEN 32U
#define LICHEN_REPLAY_PERSIST_BLOB_MAX \
	(52U + (36U * CONFIG_LICHEN_LINK_MAX_NEIGHBORS) + \
	 LICHEN_REPLAY_PERSIST_TAG_LEN)

enum lichen_replay_blob_slot {
	LICHEN_REPLAY_BLOB_A = 0,
	LICHEN_REPLAY_BLOB_B = 1,
};

struct lichen_replay_store_ops {
	int (*load)(void *user, enum lichen_replay_blob_slot slot, uint8_t *out,
		    size_t capacity, size_t *length);
	int (*save)(void *user, enum lichen_replay_blob_slot slot,
		    const uint8_t *value, size_t length);
};

struct lichen_replay_authority_state {
	uint64_t revision;
	uint8_t digest[LICHEN_REPLAY_PERSIST_TAG_LEN];
};

/**
 * Platform root and rollback authority. The authority namespace MUST be
 * dedicated to link replay state. load returns -ENOENT only for authenticated
 * virgin hardware. commit is an atomic compare-and-swap; NULL expected means
 * virgin. derive_key derives a non-exportable device-bound subkey for context.
 */
struct lichen_replay_protection_ops {
	int (*derive_key)(void *user, const uint8_t *context, size_t context_len,
			  uint8_t out[32]);
	int (*load)(void *user, struct lichen_replay_authority_state *state);
	int (*commit)(void *user,
		      const struct lichen_replay_authority_state *expected,
		      const struct lichen_replay_authority_state *next);
};

struct lichen_replay_floor {
	uint8_t public_key[LICHEN_PK_LEN];
	uint16_t seq_floor;
	uint8_t epoch;
	bool active;
};

/** Fixed-size persistence state; callers allocate it statically. */
struct lichen_replay_persist {
	struct lichen_replay_table *table;
	const struct lichen_replay_store_ops *store_ops;
	void *store_user;
	const struct lichen_replay_protection_ops *protection_ops;
	void *protection_user;
	struct lichen_replay_authority_state authority;
	struct lichen_replay_floor floors[CONFIG_LICHEN_LINK_MAX_NEIGHBORS];
	uint8_t local_public_key[LICHEN_PK_LEN];
	uint8_t auth_key[32];
	uint8_t blob[LICHEN_REPLAY_PERSIST_BLOB_MAX];
	uint8_t tx_epoch;
	bool ready;
	struct k_mutex lock;
};

/** Restore state and reserve this boot's TX epoch before returning it. */
int lichen_replay_persist_open(
	struct lichen_replay_persist *ctx, struct lichen_replay_table *table,
	const uint8_t local_public_key[LICHEN_PK_LEN], uint8_t fallback_epoch,
	const struct lichen_replay_store_ops *store_ops, void *store_user,
	const struct lichen_replay_protection_ops *protection_ops,
	void *protection_user, uint8_t *boot_epoch);

/** Persist the next finite TX epoch before making it usable. */
int lichen_replay_persist_reserve_tx_epoch(
	struct lichen_replay_persist *ctx, uint8_t current_epoch,
	uint8_t *next_epoch);

/** Wipe runtime state. Persistent state and authority remain intact. */
void lichen_replay_persist_close(struct lichen_replay_persist *ctx);

int lichen_replay_settings_register_protection(
	const struct lichen_replay_protection_ops *ops, void *user);
int lichen_replay_settings_open(
	struct lichen_replay_table *table,
	const uint8_t local_public_key[LICHEN_PK_LEN], uint8_t fallback_epoch,
	uint8_t *boot_epoch);
int lichen_replay_settings_reserve_tx_epoch(uint8_t current_epoch,
					    uint8_t *next_epoch);
void lichen_replay_settings_close(void);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_REPLAY_PERSIST_H_ */
