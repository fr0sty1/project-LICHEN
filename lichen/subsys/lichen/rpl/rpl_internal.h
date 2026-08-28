/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rpl_internal.h
 * @brief Internal declarations for RPL routing implementation
 *
 * This header is internal to the RPL subsystem and not part of the public API.
 */

#ifndef LICHEN_RPL_INTERNAL_H_
#define LICHEN_RPL_INTERNAL_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <lichen/rpl_addr.h>
#include <lichen/rpl_routing.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Routing Table internal helpers ──────────────────────────────────────── */

/**
 * @brief Find an existing /128 route by target address.
 * @return Pointer to the route entry, or NULL if not found.
 */
struct lichen_rpl_route *find_route(struct lichen_rpl_routing_table *rt,
				    const uint8_t *target);

/**
 * @brief Find an existing prefix route by prefix and length.
 * @return Pointer to the route entry, or NULL if not found.
 */
struct lichen_rpl_route *find_prefix_route(struct lichen_rpl_routing_table *rt,
					   const uint8_t *prefix, uint8_t prefix_len);

/**
 * @brief Find the first free (invalid) route slot.
 * @return Pointer to the route entry, or NULL if table is full.
 */
struct lichen_rpl_route *find_free_route(struct lichen_rpl_routing_table *rt);

/* ── DAO processing internal helpers ─────────────────────────────────────── */

/**
 * @brief Check if a timestamp has reached or passed a deadline (wraparound-safe).
 *
 * Uses signed comparison for 32-bit timestamp wraparound safety.
 * Works correctly for wraparound within ~24 days.
 */
static inline bool time_reached(uint32_t now, uint32_t deadline)
{
	return (int32_t)(now - deadline) >= 0;
}

/**
 * @brief Calculate a retain deadline from current time.
 *
 * Inactive snapshots are retained as tombstones to reject delayed equal-sequence
 * DAOs that arrive after the entry has been withdrawn or expired.
 */
static inline uint32_t retain_deadline(uint32_t now)
{
	return now + LICHEN_RPL_TOMBSTONE_RETENTION;
}

/**
 * @brief Compare two DAO candidates for equality.
 *
 * Two candidates are equal if they have the same parent, path_control,
 * path_lifetime, and external flag.
 */
static inline bool candidate_equal(const struct lichen_rpl_dao_candidate *a,
				   const struct lichen_rpl_dao_candidate *b)
{
	return rpl_addr_eq(a->parent, b->parent) &&
	       a->path_control == b->path_control &&
	       a->path_lifetime == b->path_lifetime &&
	       a->external == b->external;
}

/**
 * @brief Compare two DAO snapshots for equality.
 *
 * Two snapshots are equal if they have the same target, path_sequence,
 * descriptor (if present), and identical candidate sets.
 */
static inline bool snapshot_equal(const struct lichen_rpl_dao_snapshot *a,
				  const struct lichen_rpl_dao_snapshot *b)
{
	if (!rpl_addr_eq(a->target, b->target)) {
		return false;
	}
	if (a->path_sequence != b->path_sequence) {
		return false;
	}
	if (a->has_descriptor != b->has_descriptor) {
		return false;
	}
	if (a->has_descriptor && a->descriptor != b->descriptor) {
		return false;
	}
	if (a->candidate_count != b->candidate_count) {
		return false;
	}
	bool matched[CONFIG_LICHEN_RPL_MAX_PARENTS] = { false };
	for (int i = 0; i < a->candidate_count; i++) {
		bool found = false;

		for (int j = 0; j < b->candidate_count; j++) {
			if (!matched[j] && candidate_equal(&a->candidates[i], &b->candidates[j])) {
				matched[j] = true;
				found = true;
				break;
			}
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Finalize a target group by creating staged entries.
 *
 * Creates staged snapshot entries combining targets with their transit candidates.
 * Returns false on validation failure (no targets, no candidates, overflow, or
 * duplicate targets).
 *
 * @param staged       Output staging array
 * @param staged_count In/out count of staged entries
 * @param targets      Parsed target addresses with optional descriptors
 * @param target_count Number of targets
 * @param candidates   Transit candidates for this group
 * @param candidate_count Number of candidates
 * @param path_sequence Path sequence from transit info
 * @return true on success, false on validation failure
 */
bool finish_group(struct lichen_rpl_dao_stage *staged,
		  int *staged_count,
		  const struct lichen_rpl_dao_parsed_target *targets,
		  int target_count,
		  const struct lichen_rpl_dao_candidate *candidates,
		  int candidate_count,
		  uint8_t path_sequence);

/**
 * @brief Increment a lollipop sequence counter (RFC 6550 Section 7.2).
 *
 * Circular region [0..127]: wraps 127->0 (RFC 1982 serial space).
 * Linear region [128..255]: wraps 255->0 (restart/bootstrap).
 */
static inline uint8_t increment_lollipop(uint8_t sequence)
{
	return sequence == 127 || sequence == 255 ? 0 : sequence + 1;
}

/**
 * @brief Rebuild routing table from snapshots.
 *
 * Called internally after snapshot mutations to reconstruct the routing table.
 */
bool rebuild_routes(struct lichen_rpl_dao_manager *dm);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_INTERNAL_H_ */
