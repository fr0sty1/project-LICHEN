/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/rpl_dodag.h
 * @brief RPL DODAG state machine with MRHOF parent selection (RFC 6550)
 *
 * Key behaviors:
 * - Node starts UNJOINED; on hearing a usable DIO it elects a preferred
 *   parent and becomes JOINED.
 * - Rank = preferred_parent.rank + round(link_etx * MinHopRankIncrease)
 * - Hysteresis: switch parent only if candidate improves path cost by
 *   more than PARENT_SWITCH_THRESHOLD.
 * - MaxRankIncrease: reject candidates that would take rank above the
 *   lowest rank we have ever held plus max_rank_increase.
 */

#ifndef LICHEN_RPL_DODAG_H_
#define LICHEN_RPL_DODAG_H_

#include <stdint.h>
#include <stdbool.h>
#include <lichen/rpl_messages.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────────────────── */

#define LICHEN_RPL_INFINITE_RANK          0xFFFF
#define LICHEN_RPL_ROOT_RANK              256
#define LICHEN_RPL_DEFAULT_MIN_HOP_RANK   256
#define LICHEN_RPL_DEFAULT_MAX_RANK_INC   1024
#define LICHEN_RPL_DEFAULT_SWITCH_THRESH  192

/* TDMA constants synced from constants.toml; see spec/02a-coordinated-capacity.md §2a.2
 * and test/vectors/ccp16.json, ccp_tdma.json for independent vectors on slot
 * assignment (hash via lichen_hash_32), 100ms guard boundaries, SFN wrap, and
 * drift compensation. Zephyr tests validate against these (no code oracle). */

#ifndef CONFIG_LICHEN_RPL_MAX_PARENTS
#define CONFIG_LICHEN_RPL_MAX_PARENTS 4
#endif

/* ── Types ─────────────────────────────────────────────────────────────────── */

/**
 * @brief Node's role in the DODAG
 */
enum lichen_rpl_role {
	LICHEN_RPL_UNJOINED,
	LICHEN_RPL_JOINED,
	LICHEN_RPL_ROOT,
};

/**
 * @brief A neighbor advertising membership in the DODAG
 *
 * For embedded use, we avoid floats by using fixed-point ETX (scaled by 256).
 * ETX=256 means perfect link (1.0), ETX=512 means 50% delivery (2.0).
 */
struct lichen_rpl_parent {
	uint8_t addr[16];
	uint16_t rank;
	uint16_t link_etx;
	uint8_t load_factor;
	uint32_t last_updated;
	bool valid;
};

/**
 * @brief RPL DODAG membership state for a single node
 *
 * All parent candidates are stored in a fixed-size array to avoid allocation.
 */
struct lichen_rpl_dodag {
	uint8_t rpl_instance_id;
	uint8_t dodag_id[16];
	uint8_t version;
	uint8_t dtsn;
	enum lichen_rpl_role role;
	uint16_t rank;
	uint8_t preferred_parent[16];
	bool has_preferred_parent;

	/* Configuration */
	uint16_t min_hop_rank_increase;
	uint16_t max_rank_increase;
	uint16_t parent_switch_threshold;

	/* Parent candidates */
	struct lichen_rpl_parent parents[CONFIG_LICHEN_RPL_MAX_PARENTS];

	/* Lowest rank ever achieved (for MaxRankIncrease check) */
	uint16_t lowest_rank;
};

/* ── Functions ─────────────────────────────────────────────────────────────── */

/**
 * @brief Initialize an unjoined node for the given DODAG.
 *
 * @return 0 on success, LICHEN_RPL_ERR_INVALID if d or dodag_id is NULL.
 */
int lichen_rpl_dodag_init(struct lichen_rpl_dodag *_Nonnull d,
			  uint8_t rpl_instance_id,
			  const uint8_t *_Nonnull dodag_id,
			  uint8_t version);

/**
 * @brief Initialize a DODAG root with rank = ROOT_RANK.
 *
 * @return 0 on success, LICHEN_RPL_ERR_INVALID if d or dodag_id is NULL.
 */
int lichen_rpl_dodag_init_root(struct lichen_rpl_dodag *_Nonnull d,
			       uint8_t rpl_instance_id,
			       const uint8_t *_Nonnull dodag_id,
			       uint8_t version);

/**
 * @brief Check if node is root.
 */
static inline bool lichen_rpl_dodag_is_root(const struct lichen_rpl_dodag *_Nonnull d)
{
	return d->role == LICHEN_RPL_ROOT;
}

/**
 * @brief Check if node is joined (either JOINED or ROOT).
 */
static inline bool lichen_rpl_dodag_is_joined(const struct lichen_rpl_dodag *_Nonnull d)
{
	return d->role == LICHEN_RPL_JOINED || d->role == LICHEN_RPL_ROOT;
}

/**
 * @brief Process a received DIO.
 *
 * @param d            DODAG state
 * @param dio          Parsed DIO message
 * @param neighbor_addr IPv6 address of the DIO sender (16 bytes)
 * @param link_etx     Fixed-point ETX estimate (256 = perfect link)
 * @param now          Current timestamp for lifetime tracking
 */
int lichen_rpl_dodag_process_dio(struct lichen_rpl_dodag *_Nonnull d,
				  const struct lichen_rpl_dio *_Nonnull dio,
				  const uint8_t *_Nonnull neighbor_addr,
				  uint16_t link_etx,
				  uint8_t load_factor,
				  uint32_t now);

/**
 * @brief Drop a neighbor (e.g., link failure) and re-select parent.
 *
 * @param d    DODAG state
 * @param addr IPv6 address of the neighbor to remove (16 bytes)
 */
void lichen_rpl_dodag_remove_parent(struct lichen_rpl_dodag *_Nonnull d,
				    const uint8_t *_Nonnull addr);

/**
 * @brief Get the number of parent candidates currently tracked.
 */
int lichen_rpl_dodag_parent_count(const struct lichen_rpl_dodag *_Nonnull d);

/**
 * @brief Force parent re-selection (e.g., after link quality change).
 */
void lichen_rpl_dodag_select_parent(struct lichen_rpl_dodag *_Nonnull d);

/**
 * @brief Expire stale parent candidates.
 *
 * Invalidates parents where (now - last_updated) exceeds max_age.
 * Triggers parent re-selection if any were expired.
 *
 * @param d       DODAG state, or NULL to expire no parents
 * @param now     Current timestamp (same units as last_updated)
 * @param max_age Maximum age in timestamp units before expiring
 * @return Number of parents expired
 */
static inline bool rpl_time_expired(uint32_t now, uint32_t last_updated,
				     uint32_t max_age)
{
	uint32_t deadline = last_updated + max_age;
	return (int32_t)(now - deadline) >= 0;
}

int lichen_rpl_dodag_expire_parents(struct lichen_rpl_dodag *_Nullable d,
				    uint32_t now, uint32_t max_age);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_DODAG_H_ */
