/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/routing/gradient.h
 * @brief Unified gradient table for LICHEN routing (spec section 11)
 *
 * A single table holds next-hop gradients toward destinations, populated by
 * all routing methods: Announce (section 9), LOADng RREP (section 10), RPL,
 * and passive learning from forwarded data (section 11.2).
 *
 * Replacement order for the same destination: higher source priority,
 * then higher sequence number (fresher), then lower hop count.
 * Capacity is bounded with LRU eviction.
 */

#ifndef LICHEN_ROUTING_GRADIENT_H_
#define LICHEN_ROUTING_GRADIENT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Default max entries (can be overridden by Kconfig) */
#ifndef CONFIG_LICHEN_ROUTING_GRADIENT_MAX_ENTRIES
#define CONFIG_LICHEN_ROUTING_GRADIENT_MAX_ENTRIES 32
#endif

/* Default gradient timeout in milliseconds (600 sec = 10 min, 2x announce interval) */
#ifndef CONFIG_LICHEN_ROUTING_GRADIENT_TIMEOUT_MS
#define CONFIG_LICHEN_ROUTING_GRADIENT_TIMEOUT_MS 600000
#endif

/* Data gradient timeout (shorter, opportunistic) */
#ifndef CONFIG_LICHEN_ROUTING_DATA_GRADIENT_TIMEOUT_MS
#define CONFIG_LICHEN_ROUTING_DATA_GRADIENT_TIMEOUT_MS 60000
#endif

/**
 * @brief How a gradient entry was learned (spec 11.1/11.3).
 *
 * Higher enum values have higher priority (explicitly-advertised wins).
 */
enum lichen_gradient_source {
	LICHEN_GRADIENT_DATA = 0,    /**< Opportunistic from forwarded data */
	LICHEN_GRADIENT_RPL = 1,     /**< RPL routing */
	LICHEN_GRADIENT_RREP = 2,    /**< LOADng route reply */
	LICHEN_GRADIENT_ANNOUNCE = 3 /**< Announce message (highest priority) */
};

/**
 * @brief A next-hop gradient toward a destination (spec 11.1).
 */
struct lichen_gradient_entry {
	uint8_t destination_iid[8]; /**< 8-byte IID of destination */
	uint8_t next_hop[16];       /**< IPv6 link-local of next hop */
	uint8_t hop_count;          /**< Distance in hops */
	uint16_t seq_num;           /**< Sequence number for freshness */
	enum lichen_gradient_source source; /**< How entry was learned */
	uint32_t expires_ms;        /**< Expiry timestamp (uptime ms) */
	uint32_t last_used_ms;      /**< Last access time for LRU eviction */
	int32_t lat_e7;             /**< Latitude (1e-7 degrees), 0 if unknown */
	int32_t lon_e7;             /**< Longitude (1e-7 degrees), 0 if unknown */
	bool coords_valid;          /**< True if lat/lon are valid */
	bool valid;                 /**< Slot in use */
#if defined(CONFIG_LICHEN_ADAPTIVE_SF_ENABLED)
	struct {
		uint8_t current_sf;     /**< SF7-SF12 for this neighbor */
		int8_t snr_ewma;        /**< Exponential weighted moving average SNR */
		uint8_t upgrade_count;  /**< Consecutive samples above upgrade threshold */
		uint8_t downgrade_count; /**< Consecutive samples below downgrade threshold */
	} sf;                       /**< Per-neighbor SF tracking (zrh2.2) */
#endif
};

/**
 * @brief Bounded gradient table with LRU eviction.
 */
struct lichen_gradient_table {
	struct lichen_gradient_entry entries[CONFIG_LICHEN_ROUTING_GRADIENT_MAX_ENTRIES];
	size_t count;
};

/**
 * @brief Initialize a gradient table.
 *
 * @param table Gradient table to initialize.
 * @return 0 on success, -EINVAL if table is NULL.
 */
int lichen_gradient_table_init(struct lichen_gradient_table *table);

/**
 * @brief Look up a gradient by destination IID.
 *
 * @param table Gradient table.
 * @param destination_iid 8-byte IID of destination.
 * @param now_ms Current time in milliseconds (for expiry check).
 * @return Pointer to entry if found and not expired, NULL otherwise.
 */
struct lichen_gradient_entry *lichen_gradient_lookup(
	struct lichen_gradient_table *table,
	const uint8_t destination_iid[8],
	uint32_t now_ms);

/**
 * @brief Update or insert a gradient entry.
 *
 * Replaces the existing entry if it is missing, expired, or worse in rank.
 * Rank ordering: source priority > sequence number > (1 - hop_count).
 *
 * @param table Gradient table.
 * @param entry Entry to insert/update (destination_iid is the key).
 * @param now_ms Current time in milliseconds.
 * @return 0 on success, negative errno on error.
 */
int lichen_gradient_update(struct lichen_gradient_table *table,
			   const struct lichen_gradient_entry *entry,
			   uint32_t now_ms);

/**
 * @brief Remove a gradient entry by destination IID.
 *
 * @param table Gradient table.
 * @param destination_iid 8-byte IID to remove.
 */
void lichen_gradient_remove(struct lichen_gradient_table *table,
			    const uint8_t destination_iid[8]);

/**
 * @brief Remove all gradients routing through a specific next hop.
 *
 * Used when a link failure is detected (RERR).
 *
 * @param table Gradient table.
 * @param next_hop 16-byte IPv6 address of failed next hop.
 * @return Number of entries removed.
 */
int lichen_gradient_remove_via(struct lichen_gradient_table *table,
			       const uint8_t next_hop[16]);

/**
 * @brief Expire old entries.
 *
 * @param table Gradient table.
 * @param now_ms Current time in milliseconds.
 * @return Number of entries expired.
 */
int lichen_gradient_expire(struct lichen_gradient_table *table, uint32_t now_ms);

/**
 * @brief RFC 1982 sequence number comparison.
 *
 * @param a First sequence number.
 * @param b Second sequence number.
 * @return true if a is newer than b.
 */
bool lichen_seq_newer(uint16_t a, uint16_t b);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_ROUTING_GRADIENT_H_ */
