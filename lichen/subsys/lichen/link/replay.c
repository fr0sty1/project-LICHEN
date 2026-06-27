/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file replay.c
 * @brief Sliding window replay protection
 *
 * Implements per-peer replay protection using a 64-slot bitmap window.
 * Ported from rust/lichen-link/src/replay.rs
 *
 * The window tracks sequence numbers relative to the highest seen.
 * Bit 0 = last_seq, bit i = last_seq - i. Sequence arithmetic wraps
 * at 65536 with half-space normalization to handle u16 wraparound.
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
	rw->last_seq = 0;
	rw->bitmap = 0;
	rw->initialised = false;
}

bool lichen_replay_check(struct lichen_replay_window *rw, uint16_t seq)
{
	int32_t diff;

	if (!rw->initialised) {
		rw->last_seq = seq;
		rw->bitmap = 1;
		rw->initialised = true;
		return true;
	}

	/* Signed distance: positive means seq is newer than last_seq.
	 * Use i32 arithmetic to handle wrapping correctly. */
	diff = (int32_t)seq - (int32_t)rw->last_seq;

	/*
	 * Half-space comparison for u16 sequence numbers (RFC 1982 Serial
	 * Number Arithmetic).
	 *
	 * When sequence numbers wrap (0 follows 65535), naive comparison
	 * breaks: 0 < 65535 suggests 0 is "older", but it's actually newer.
	 *
	 * The fix: interpret any distance > 32767 as a backward wrap.
	 * We split the 65536-value space in half around the current position:
	 *   - Differences in [1, 32767] mean seq is ahead (newer)
	 *   - Differences in [-32768, -1] mean seq is behind (older)
	 *
	 * Example: last_seq=65530, seq=5
	 *   Raw diff: 5 - 65530 = -65525 (in i32)
	 *   After normalisation: -65525 + 65536 = 11 (seq is 11 ahead, newer)
	 *
	 * Example: last_seq=5, seq=65530
	 *   Raw diff: 65530 - 5 = 65525 (in i32)
	 *   After normalisation: 65525 - 65536 = -11 (seq is 11 behind, older)
	 *
	 * This works as long as no two valid sequence numbers are ever more
	 * than 32767 apart - a safe assumption when packets arrive in roughly
	 * sequential order with a 64-slot window.
	 *
	 * See RFC 1982 Section 3.2 for the formal definition of serial number
	 * comparison with SERIAL_BITS=16.
	 */
	if (diff > 32767) {
		diff -= 65536;
	} else if (diff < -32768) {
		diff += 65536;
	}

	if (diff > 0) {
		/*
		 * Newer than anything we've seen: advance the window.
		 *
		 * Validate diff is within the positive half-space (1 to 32767).
		 * After RFC 1982 normalization, diff should be in [-32768, 32767].
		 * If diff > 32767 here, something is wrong with the normalization.
		 */
		if (diff > 32767) {
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
		rw->last_seq = seq;
		return true;
	}

	if (diff == 0) {
		/* Exact duplicate of last_seq */
		return false;
	}

	/* Older than last_seq: check the bitmask */
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
