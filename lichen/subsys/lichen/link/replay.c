/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file replay.c
 * @brief Sliding window replay protection
 *
 * Implements per-peer replay protection using a 64-slot bitmap window.
 * Ported from rust/lichen-link/src/replay.rs and python/src/lichen/link/replay.py
 *
 * Uses a 24-bit logical counter formed from (epoch << 16) | seqnum to
 * prevent cross-epoch replay attacks. When tx_seq wraps from 0xFFFF to 0
 * and epoch increments, old (epoch, seqnum) pairs cannot be replayed.
 *
 * The window tracks counters relative to the highest seen.
 * Bit 0 = last_counter, bit i = last_counter - i. Counter arithmetic
 * wraps at 16M (24-bit space) with half-space normalization.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <lichen/replay.h>

/**
 * @brief Constant-time comparison for 8-byte values (EUI-64)
 *
 * Prevents timing side-channels when comparing addresses.
 * Returns 0 if equal, non-zero otherwise.
 */
static int eui64_ct_compare(const uint8_t a[LICHEN_EUI64_LEN],
			    const uint8_t b[LICHEN_EUI64_LEN])
{
	volatile uint8_t diff = 0;

	for (size_t i = 0; i < LICHEN_EUI64_LEN; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff;
}

void lichen_replay_init(struct lichen_replay_window *rw)
{
	rw->last_counter = 0;
	rw->bitmap = 0;
	rw->initialised = false;
}

/**
 * @brief Combine epoch and seqnum into a 24-bit logical counter.
 *
 * This ensures monotonicity across epoch boundaries: when seqnum wraps
 * from 0xFFFF to 0 and epoch increments, the counter continues to advance.
 */
static inline uint32_t logical_counter(uint8_t epoch, uint16_t seq)
{
	return ((uint32_t)epoch << 16) | (uint32_t)seq;
}

bool lichen_replay_check(struct lichen_replay_window *rw, uint8_t epoch, uint16_t seq)
{
	int32_t diff;
	uint32_t counter = logical_counter(epoch, seq);

	if (!rw->initialised) {
		rw->last_counter = counter;
		rw->bitmap = 1;
		rw->initialised = true;
		return true;
	}

	/* Signed distance: positive means counter is newer than last_counter.
	 * Use i32 arithmetic to handle wrapping correctly. */
	diff = (int32_t)counter - (int32_t)rw->last_counter;

	/*
	 * Half-space comparison for 24-bit counters (RFC 1982 Serial
	 * Number Arithmetic adapted to 24-bit space).
	 *
	 * The 24-bit counter has range [0, 16777215]. When it wraps
	 * (0 follows 16777215), naive comparison breaks.
	 *
	 * The fix: interpret any distance > 8388607 (half of 16M) as a
	 * backward wrap. We split the 24-bit space in half:
	 *   - Differences in [1, 8388607] mean counter is ahead (newer)
	 *   - Differences in [-8388608, -1] mean counter is behind (older)
	 *
	 * This works as long as no two valid counters are ever more than
	 * 8M apart - a safe assumption for any reasonable reordering window.
	 *
	 * See RFC 1982 Section 3.2 for the formal definition.
	 */
	#define COUNTER_HALF_SPACE 8388607  /* (1 << 23) - 1 = 0x7FFFFF */
	#define COUNTER_FULL_SPACE 16777216 /* 1 << 24 = 0x1000000 */

	if (diff > COUNTER_HALF_SPACE) {
		diff -= COUNTER_FULL_SPACE;
	} else if (diff < -COUNTER_HALF_SPACE - 1) {
		diff += COUNTER_FULL_SPACE;
	}

	if (diff > 0) {
		/*
		 * Newer than anything we've seen: advance the window.
		 *
		 * Validate diff is within the positive half-space.
		 * After normalization, diff should be in [-8388608, 8388607].
		 */
		if (diff > COUNTER_HALF_SPACE) {
			/* Should not happen after normalization - reject */
			return false;
		}

		uint32_t shift = (uint32_t)diff;

		if (shift >= 64) {
			/* Entire window is beyond what we've seen; reset it */
			rw->bitmap = 1;
		} else {
			rw->bitmap = (rw->bitmap << shift) | 1;
		}
		rw->last_counter = counter;
		return true;
	}

	if (diff == 0) {
		/* Exact duplicate of last_counter */
		return false;
	}

	/* Older than last_counter: check the bitmask */
	uint32_t offset = (uint32_t)(-diff);

	if (offset >= 64) {
		/* Outside the window - too old to verify, reject */
		return false;
	}

	uint64_t bit = (uint64_t)1 << offset;

	if (rw->bitmap & bit) {
		/* Already seen */
		return false;
	}

	rw->bitmap |= bit;
	return true;

	#undef COUNTER_HALF_SPACE
	#undef COUNTER_FULL_SPACE
}

void lichen_replay_table_init(struct lichen_replay_table *table)
{
	memset(table, 0, sizeof(*table));
}

/**
 * @brief Safely increment access counter with wrap handling.
 *
 * When the counter wraps, we re-normalize all timestamps by finding the
 * minimum and subtracting it from all entries, then continue from there.
 * This preserves relative ordering for LRU eviction.
 */
static void increment_access_counter(struct lichen_replay_table *table)
{
	if (table->access_counter == UINT32_MAX) {
		/* Counter would wrap - re-normalize all timestamps */
		uint32_t min_time = UINT32_MAX;

		/* Find minimum timestamp */
		for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
			if (table->peers[i].active &&
			    table->peers[i].last_used < min_time) {
				min_time = table->peers[i].last_used;
			}
		}

		/* Subtract minimum from all timestamps */
		if (min_time > 0) {
			for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
				if (table->peers[i].active) {
					table->peers[i].last_used -= min_time;
				}
			}
			table->access_counter -= min_time;
		}
	}
	table->access_counter++;
}

struct lichen_replay_window *lichen_replay_get(struct lichen_replay_table *table,
					       const uint8_t eui64[LICHEN_EUI64_LEN])
{
	/* Validate parameters */
	if (table == NULL || eui64 == NULL) {
		return NULL;
	}

	size_t free_slot = CONFIG_LICHEN_LINK_MAX_NEIGHBORS; /* invalid sentinel */
	size_t lru_slot = 0;
	uint32_t lru_time = UINT32_MAX;

	/* Search for existing entry, first free slot, and LRU candidate */
	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (table->peers[i].active) {
			if (eui64_ct_compare(table->peers[i].eui64, eui64) == 0) {
				/* Found: update LRU timestamp and return */
				increment_access_counter(table);
				table->peers[i].last_used = table->access_counter;
				return &table->peers[i].window;
			}
			/* Track LRU candidate for eviction */
			if (table->peers[i].last_used < lru_time) {
				lru_time = table->peers[i].last_used;
				lru_slot = i;
			}
		} else if (free_slot == CONFIG_LICHEN_LINK_MAX_NEIGHBORS) {
			free_slot = i;
		}
	}

	/* Not found - use free slot or evict LRU entry */
	size_t target_slot;

	if (free_slot < CONFIG_LICHEN_LINK_MAX_NEIGHBORS) {
		target_slot = free_slot;
	} else {
		/*
		 * Table full: evict LRU entry.
		 *
		 * WARNING: Unauthenticated eviction allows replay window poisoning.
		 * An attacker spoofing many source addresses can evict legitimate
		 * peer windows, enabling replay attacks against those peers.
		 * See lichen/replay.h for mitigation guidance.
		 */
		target_slot = lru_slot;
	}

	memcpy(table->peers[target_slot].eui64, eui64, LICHEN_EUI64_LEN);
	lichen_replay_init(&table->peers[target_slot].window);
	increment_access_counter(table);
	table->peers[target_slot].last_used = table->access_counter;
	table->peers[target_slot].active = true;

	return &table->peers[target_slot].window;
}

void lichen_replay_remove(struct lichen_replay_table *table,
			  const uint8_t eui64[LICHEN_EUI64_LEN])
{
	if (table == NULL || eui64 == NULL) {
		return;
	}

	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (table->peers[i].active &&
		    eui64_ct_compare(table->peers[i].eui64, eui64) == 0) {
			table->peers[i].active = false;
			return;
		}
	}
}
