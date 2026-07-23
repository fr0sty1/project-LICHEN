/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file replay.c
 * @brief Sliding window replay protection
 *
 * Implements per-peer replay protection using a 32-slot bitmap window.
 * Ported from rust/lichen-link/src/replay.rs and python/src/lichen/link/replay.py
 *
 * Epochs and sequence numbers use finite ordering. A higher epoch starts a
 * fresh sequence window; lower epochs and sequence-number wraps are stale.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <lichen/replay.h>

/**
 * @brief Constant-time comparison for public keys
 *
 * Prevents timing side-channels when comparing public keys.
 * Returns 0 if equal, non-zero otherwise.
 */
static int public_key_ct_compare(const uint8_t a[LICHEN_PK_LEN],
				 const uint8_t b[LICHEN_PK_LEN])
{
	volatile uint8_t diff = 0;

	for (size_t i = 0; i < LICHEN_PK_LEN; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff;
}

void lichen_replay_init(struct lichen_replay_window *rw)
{
	rw->last_seq = 0;
	rw->epoch = 0;
	rw->bitmap = 0;
	rw->initialised = false;
}

bool lichen_replay_check(struct lichen_replay_window *rw, uint8_t epoch, uint16_t seq)
{
	if (!rw->initialised) {
		rw->epoch = epoch;
		rw->last_seq = seq;
		rw->bitmap = 1;
		rw->initialised = true;
		return true;
	}

	if (epoch < rw->epoch) {
		return false;
	}
	if (epoch > rw->epoch) {
		rw->epoch = epoch;
		rw->last_seq = seq;
		rw->bitmap = 1;
		return true;
	}
	if (seq > rw->last_seq) {
		uint32_t shift = (uint32_t)seq - rw->last_seq;

		if (shift >= 32) {
			rw->bitmap = 1;
		} else {
			rw->bitmap = (rw->bitmap << shift) | 1;
		}
		rw->last_seq = seq;
		return true;
	}
	if (seq == rw->last_seq) {
		return false;
	}

	uint32_t offset = (uint32_t)rw->last_seq - seq;

	if (offset >= 32) {
		/* Outside the window - too old to verify, reject */
		return false;
	}

	uint32_t bit = (uint32_t)1 << offset;

	if (rw->bitmap & bit) {
		/* Already seen */
		return false;
	}

	rw->bitmap |= bit;
	return true;

}

void lichen_replay_table_init(struct lichen_replay_table *table)
{
	memset(table, 0, sizeof(*table));
}

struct lichen_replay_window *lichen_replay_get(struct lichen_replay_table *table,
					       const uint8_t public_key[LICHEN_PK_LEN])
{
	/* Validate parameters */
	if (table == NULL || public_key == NULL) {
		return NULL;
	}

	size_t free_slot = CONFIG_LICHEN_LINK_MAX_NEIGHBORS; /* invalid sentinel */

	/* Search for an existing entry or the first free slot. */
	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (table->peers[i].active) {
			if (public_key_ct_compare(table->peers[i].public_key,
					  public_key) == 0) {
				/* Found: retain its replay history. */
				return &table->peers[i].window;
			}
		} else if (free_slot == CONFIG_LICHEN_LINK_MAX_NEIGHBORS) {
			free_slot = i;
		}
	}

	/* SECURITY: full table fails closed (project-LICHEN-bbti). Forgetting
	 * replay history would permit old authenticated frames again. No LRU. */
	if (free_slot == CONFIG_LICHEN_LINK_MAX_NEIGHBORS) {
		return NULL;
	}

	memcpy(table->peers[free_slot].public_key, public_key, LICHEN_PK_LEN);
	lichen_replay_init(&table->peers[free_slot].window);
	table->peers[free_slot].active = true;

	return &table->peers[free_slot].window;
}

void lichen_replay_remove(struct lichen_replay_table *table,
			  const uint8_t public_key[LICHEN_PK_LEN])
{
	if (table == NULL || public_key == NULL) {
		return;
	}

	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (table->peers[i].active &&
		    public_key_ct_compare(table->peers[i].public_key,
					  public_key) == 0) {
			table->peers[i].active = false;
			return;
		}
	}
}
