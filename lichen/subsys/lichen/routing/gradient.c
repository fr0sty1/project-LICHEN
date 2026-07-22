/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file gradient.c
 * @brief Unified gradient table implementation (spec section 11)
 */

#include <lichen/routing/gradient.h>

#include <errno.h>
#include <string.h>

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
