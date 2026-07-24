/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file gradient.c
 * @brief Unified gradient table implementation (spec section 11)
 */

#include <lichen/routing/gradient.h>

#include <errno.h>
#include <string.h>

#if defined(CONFIG_LICHEN_ADAPTIVE_SF_ENABLED)
/* Default gradient table pointer. Set by application via
 * lichen_gradient_set_default_table() so the L2 RX path can update
 * per-neighbor SF tracking without direct access to the router.
 * NULL means SF updates are not applied (caller must provide table). */
static struct lichen_gradient_table *default_table;
#endif

/* Sequence number comparison window (RFC 1982) */
#define SEQ_HALF 0x8000U

bool lichen_seq_newer(uint16_t a, uint16_t b)
{
	/*
	 * RFC 1982: a > b iff (a - b) mod 2^N in (0, 2^(N-1))
	 * We check a != b first to handle equality.
	 */
	uint16_t diff = (uint16_t)(a - b);
	return a != b && diff < SEQ_HALF;
}

/**
 * Compare two entries for replacement priority.
 * Returns true if `new` should replace `old`.
 */
static bool entry_better(const struct lichen_gradient_entry *new_entry,
			 const struct lichen_gradient_entry *old_entry)
{
	/* Higher source priority wins */
	if (new_entry->source > old_entry->source) {
		return true;
	}
	if (new_entry->source < old_entry->source) {
		return false;
	}

	/* Same source: fresher sequence number wins */
	if (lichen_seq_newer(new_entry->seq_num, old_entry->seq_num)) {
		return true;
	}
	if (lichen_seq_newer(old_entry->seq_num, new_entry->seq_num)) {
		return false;
	}

	/* Same sequence: fewer hops wins */
	return new_entry->hop_count < old_entry->hop_count;
}

static struct lichen_gradient_entry *find_entry(
	struct lichen_gradient_table *table,
	const uint8_t destination_iid[8])
{
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTING_GRADIENT_MAX_ENTRIES; i++) {
		if (table->entries[i].valid &&
		    memcmp(table->entries[i].destination_iid, destination_iid, 8) == 0) {
			return &table->entries[i];
		}
	}
	return NULL;
}

static struct lichen_gradient_entry *find_free_slot(
	struct lichen_gradient_table *table)
{
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTING_GRADIENT_MAX_ENTRIES; i++) {
		if (!table->entries[i].valid) {
			return &table->entries[i];
		}
	}
	return NULL;
}

/**
 * Find least-recently-used entry for eviction.
 * Only called when table is full.
 */
static struct lichen_gradient_entry *find_lru(struct lichen_gradient_table *table)
{
	struct lichen_gradient_entry *lru = NULL;

	for (size_t i = 0; i < CONFIG_LICHEN_ROUTING_GRADIENT_MAX_ENTRIES; i++) {
		struct lichen_gradient_entry *e = &table->entries[i];
		if (!e->valid) {
			continue;
		}
		if (lru == NULL || (int32_t)(e->last_used_ms - lru->last_used_ms) < 0) {
			lru = e;
		}
	}
	return lru;
}

int lichen_gradient_table_init(struct lichen_gradient_table *table)
{
	if (table == NULL) {
		return -EINVAL;
	}
	memset(table, 0, sizeof(*table));
	return 0;
}

struct lichen_gradient_entry *lichen_gradient_lookup(
	struct lichen_gradient_table *table,
	const uint8_t destination_iid[8],
	uint32_t now_ms)
{
	if (table == NULL || destination_iid == NULL) {
		return NULL;
	}

	struct lichen_gradient_entry *entry = find_entry(table, destination_iid);
	if (entry == NULL) {
		return NULL;
	}

	/* Check expiry using wrapping comparison */
	if ((int32_t)(entry->expires_ms - now_ms) <= 0) {
		return NULL;
	}

	/* Update LRU timestamp */
	entry->last_used_ms = now_ms;
	return entry;
}

int lichen_gradient_update(struct lichen_gradient_table *table,
			   const struct lichen_gradient_entry *entry,
			   uint32_t now_ms)
{
	if (table == NULL || entry == NULL) {
		return -EINVAL;
	}

	struct lichen_gradient_entry *existing =
		find_entry(table, entry->destination_iid);

	if (existing != NULL) {
		/* Check if expired */
		bool expired = (int32_t)(existing->expires_ms - now_ms) <= 0;

		/* Replace if expired or new entry is better */
		if (expired || entry_better(entry, existing)) {
			memcpy(existing, entry, sizeof(*existing));
			existing->valid = true;
			existing->last_used_ms = now_ms;
			return 0;
		}
		/* Existing entry is better, no update */
		return 0;
	}

	/* New entry - find free slot or evict LRU */
	struct lichen_gradient_entry *slot = find_free_slot(table);
	if (slot == NULL) {
		slot = find_lru(table);
		if (slot == NULL) {
			return -ENOMEM;
		}
		if (table->count > 0) {
			table->count--;
		}
	}

	memcpy(slot, entry, sizeof(*slot));
	slot->valid = true;
	slot->last_used_ms = now_ms;
	table->count++;
	return 0;
}

void lichen_gradient_remove(struct lichen_gradient_table *table,
			    const uint8_t destination_iid[8])
{
	if (table == NULL || destination_iid == NULL) {
		return;
	}

	struct lichen_gradient_entry *entry =
		find_entry(table, destination_iid);
	if (entry != NULL) {
		entry->valid = false;
		if (table->count > 0) {
			table->count--;
		}
	}
}

int lichen_gradient_remove_via(struct lichen_gradient_table *table,
			       const uint8_t next_hop[16])
{
	if (table == NULL || next_hop == NULL) {
		return 0;
	}

	int removed = 0;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTING_GRADIENT_MAX_ENTRIES; i++) {
		struct lichen_gradient_entry *e = &table->entries[i];
		if (e->valid && memcmp(e->next_hop, next_hop, 16) == 0) {
			e->valid = false;
			removed++;
		}
	}
	if ((size_t)removed > table->count) {
		table->count = 0;
	} else {
		table->count -= (size_t)removed;
	}
	return removed;
}

#if defined(CONFIG_LICHEN_ADAPTIVE_SF_ENABLED)

/* SNR thresholds for adaptive SF (dB). These are reasonable default values for
 * LoRa at BW125: a neighbor with SNR > 8 dB can sustain SF7 (50ms airtime for
 * 60B), while SNR < -5 dB needs at least SF11 (~900ms airtime for 60B).
 * Derived from empirical LoRa sensitivity curves (Semtech AN1200.13).
 * Tune per deployment via Kconfig in future.
 */
#define LICHEN_SNR_UPGRADE_THRESHOLD  8
#define LICHEN_SNR_DOWNGRADE_THRESHOLD (-5)

/* How many consecutive samples above threshold before adjusting SF */
#define LICHEN_SF_UPGRADE_CONSECUTIVE 3
#define LICHEN_SF_DOWNGRADE_CONSECUTIVE 3

/* Minimum and maximum spreading factor values */
#define LICHEN_SF_MIN 7
#define LICHEN_SF_MAX 12

void lichen_gradient_update_sf(struct lichen_gradient_table *table,
			       const uint8_t neighbor_iid[8],
			       int8_t snr_db,
			       uint32_t now_ms)
{
	if (table == NULL || neighbor_iid == NULL) {
		return;
	}

	struct lichen_gradient_entry *entry = find_entry(table, neighbor_iid);
	if (entry == NULL) {
		return;
	}

	/* Initialize SF field on first update. current_sf=0 means uninitialized
	 * (the gradient entry is zero-initialized in the table). SF7-SF12 are
	 * the valid range, so 0 is a safe sentinel. SNR EWMA uses the same
	 * sentinel: a valid EWMA can be 0 dB, so we check current_sf instead. */
	if (entry->sf.current_sf == 0) {
		entry->sf.current_sf = CONFIG_LICHEN_DEFAULT_SF;
		entry->sf.snr_ewma = snr_db;
		entry->last_used_ms = now_ms;
		return;
	}

	/* Update SNR EWMA: ewma = (3 * ewma + sample) / 4 */
	int32_t ewma = ((int32_t)entry->sf.snr_ewma * 3 + (int32_t)snr_db) / 4;
	if (ewma < INT8_MIN) {
		entry->sf.snr_ewma = INT8_MIN;
	} else if (ewma > INT8_MAX) {
		entry->sf.snr_ewma = INT8_MAX;
	} else {
		entry->sf.snr_ewma = (int8_t)ewma;
	}

	/* Check upgrade (try lower SF = faster) */
	if (entry->sf.snr_ewma > LICHEN_SNR_UPGRADE_THRESHOLD) {
		entry->sf.upgrade_count++;
		entry->sf.downgrade_count = 0;
		if (entry->sf.upgrade_count >= LICHEN_SF_UPGRADE_CONSECUTIVE) {
			if (entry->sf.current_sf > LICHEN_SF_MIN) {
				entry->sf.current_sf--;
			}
			entry->sf.upgrade_count = 0;
		}
	} else if (entry->sf.snr_ewma < LICHEN_SNR_DOWNGRADE_THRESHOLD) {
		entry->sf.downgrade_count++;
		entry->sf.upgrade_count = 0;
		if (entry->sf.downgrade_count >= LICHEN_SF_DOWNGRADE_CONSECUTIVE) {
			if (entry->sf.current_sf < LICHEN_SF_MAX) {
				entry->sf.current_sf++;
			}
			entry->sf.downgrade_count = 0;
		}
	} else {
		entry->sf.upgrade_count = 0;
		entry->sf.downgrade_count = 0;
	}

	entry->last_used_ms = now_ms;
}

void lichen_gradient_set_default_table(struct lichen_gradient_table *table)
{
	default_table = table;
}

void lichen_gradient_update_sf_default(const uint8_t neighbor_iid[8],
				       int8_t snr_db,
				       uint32_t now_ms)
{
	if (default_table != NULL) {
		lichen_gradient_update_sf(default_table, neighbor_iid,
					  snr_db, now_ms);
	}
}
#endif /* CONFIG_LICHEN_ADAPTIVE_SF_ENABLED */

int lichen_gradient_expire(struct lichen_gradient_table *table, uint32_t now_ms)
{
	if (table == NULL) {
		return 0;
	}

	int expired = 0;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTING_GRADIENT_MAX_ENTRIES; i++) {
		struct lichen_gradient_entry *e = &table->entries[i];
		if (!e->valid) {
			continue;
		}
		/* Expired if expires_ms <= now_ms (wrapping comparison) */
		if ((int32_t)(e->expires_ms - now_ms) <= 0) {
			e->valid = false;
			expired++;
		}
	}
	if ((size_t)expired > table->count) {
		table->count = 0;
	} else {
		table->count -= (size_t)expired;
	}
	return expired;
}
