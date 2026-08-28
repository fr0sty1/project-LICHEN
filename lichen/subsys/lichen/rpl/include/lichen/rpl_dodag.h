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
 * - Hysteresis: switch parent when the candidate improves path cost by
 *   at least PARENT_SWITCH_THRESHOLD.
 * - MaxRankIncrease: reject candidates that would take rank above the
 *   lowest rank we have ever held plus max_rank_increase.
 */

#ifndef LICHEN_RPL_DODAG_H_
#define LICHEN_RPL_DODAG_H_

#include <stdint.h>
#include <stdbool.h>
#include <lichen/rpl_messages.h>
#include <lichen/rpl_trickle.h>

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
 * assignment (hash via lichen_hash_32), 50ms guard boundaries (spec/02a
 * §2a.2), SFN wrap, and
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
 * @brief Callback for DODAG state changes.
 *
 * @param joined true if node joined or re-joined a DODAG, false if it left
 * @param user_data User context pointer set in dodag struct
 */
typedef void (*lichen_rpl_dodag_state_cb)(bool joined, void *_Nullable user_data);

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
	/** DIO consistency timer, committed atomically with routing state. */
	struct lichen_trickle trickle;

	/* Parent candidates */
	struct lichen_rpl_parent parents[CONFIG_LICHEN_RPL_MAX_PARENTS];

	/* Gateway-centric mode (from DODAG Configuration option).
	 * Root-authoritative: see lichen_rpl_dodag_process_dio(). */
	bool gateway_centric;
	/* Last-known-good value advertised by the adopted root; restored to
	 * gateway_centric on every DIO without an authoritative option. */
	bool last_gateway_centric;

	/* Lowest rank ever achieved (for MaxRankIncrease check) */
	uint16_t lowest_rank;

	/* DODAG state change notification */
	lichen_rpl_dodag_state_cb _Nullable state_cb;
	void *_Nullable state_cb_user_data;
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
 * @param authenticated True if the DIO was received with a valid frame signature
 *
 * @note All RPL control messages MUST be received over an authenticated link
 *       (S=1 per LICHEN link-layer spec). Unauthenticated DIOs are rejected.
 *
 * DODAGVersionNumber is scoped to (RPLInstanceID, DODAGID). Every node
 * ignores a DIO with a different configured instance or DODAGID (no version
 * compare). Incomparable or older lollipop versions are ignored, not treated
 * as same-version. A newer version requires the separately authorized API;
 * the ordinary API fails closed. Roots ignore all DIOs.
 *
 * The DODAG Configuration option's gateway_centric flag is accepted only
 * from the adopted root (sender address == DODAGID); any other value is
 * ignored and the working flag reverts to the last-known-good root value.
 *
 * @return 1 if DTSN changed, 0 if the DIO was processed without a DTSN
 *         change, LICHEN_RPL_ERR_INVALID if d, dio, or neighbor_addr is
 *         NULL.
 */
int lichen_rpl_dodag_process_dio(struct lichen_rpl_dodag *_Nullable d,
				  const struct lichen_rpl_dio *_Nullable dio,
				  const struct lichen_rpl_dodag_config *_Nullable config,
				  const uint8_t *_Nullable neighbor_addr,
				  uint16_t link_etx,
				  uint8_t load_factor,
				  uint32_t now,
				  bool authenticated);

/**
 * Process a DIO with separately verified root-owned version authorization.
 * The ordinary API above passes false and therefore cannot advance the DODAG
 * version. All routing and Trickle changes are staged and committed together.
 */
int lichen_rpl_dodag_process_dio_authorized(
	struct lichen_rpl_dodag *_Nullable d,
	const struct lichen_rpl_dio *_Nullable dio,
	const struct lichen_rpl_dodag_config *_Nullable config,
	const uint8_t *_Nullable neighbor_addr,
	uint16_t link_etx, uint8_t load_factor, uint32_t now,
	bool authenticated, bool version_authorized);

/**
 * @brief Parse a received DIO from wire bytes and process it.
 *
 * @param d             DODAG state
 * @param dio_bytes     DIO wire bytes (base, plus options if present)
 * @param dio_len       Length of @p dio_bytes
 * @param neighbor_addr IPv6 address of the DIO sender (16 bytes)
 * @param link_etx      Fixed-point ETX estimate (256 = perfect link)
 * @param load_factor   Advertised load factor
 * @param now           Current timestamp for lifetime tracking
 * @param authenticated True if the DIO was received with a valid frame signature
 *
 * Strictly validates the complete option chain, requires the current SCHC
 * Rule Version option, and parses a DODAG Configuration option if present.
 * Unauthenticated DIOs are rejected. Parse, policy, routing, and Trickle
 * state changes are committed atomically.
 *
 * @return 0 or 1 from lichen_rpl_dodag_process_dio() on success,
 *         LICHEN_RPL_ERR_INVALID if d, dio_bytes, or neighbor_addr is NULL,
 *         or another negative LICHEN_RPL_ERR_* code if the bytes cannot be
 *         parsed.
 */
int lichen_rpl_dodag_process_dio_bytes(struct lichen_rpl_dodag *_Nullable d,
					const uint8_t *_Nullable dio_bytes,
					size_t dio_len,
					const uint8_t *_Nullable neighbor_addr,
					uint16_t link_etx,
					uint8_t load_factor,
					uint32_t now,
					bool authenticated);

/** Wire receive variant for a separately verified version authorization. */
int lichen_rpl_dodag_process_dio_bytes_authorized(
	struct lichen_rpl_dodag *_Nullable d,
	const uint8_t *_Nullable dio_bytes, size_t dio_len,
	const uint8_t *_Nullable neighbor_addr,
	uint16_t link_etx, uint8_t load_factor, uint32_t now,
	bool authenticated, bool version_authorized);

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
 * @brief Register a DODAG state change callback.
 *
 * Called whenever the node joins or leaves a DODAG (role transitions
 * between UNJOINED and JOINED/ROOT).
 *
 * @param d          DODAG state
 * @param cb         Callback, or NULL to unregister
 * @param user_data  Opaque context passed to callback
 */
void lichen_rpl_dodag_set_state_cb(struct lichen_rpl_dodag *_Nonnull d,
				   lichen_rpl_dodag_state_cb _Nullable cb,
				   void *_Nullable user_data);

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
	/* A parent exactly max_age old is still usable; it becomes stale on
	 * the first tick after the deadline. The signed comparison is safe for
	 * configured lifetimes shorter than half the 32-bit timer range. */
	return (int32_t)(now - deadline) > 0;
}

int lichen_rpl_dodag_expire_parents(struct lichen_rpl_dodag *_Nullable d,
				    uint32_t now, uint32_t max_age);

#ifdef LICHEN_RPL_TEST
/**
 * RFC 6550 Section 7.2 lollipop comparison (host-test hook).
 *
 * @return 1 if @p a is newer, -1 if older, 0 if equal, 2 if incomparable.
 *         Same-region comparisons first require an absolute difference no
 *         greater than SEQUENCE_WINDOW=16; cross-region pairs are always
 *         comparable (RFC 6550 Section 7.2 rules 3.1 and 3.2). See
 *         lichen/tests/rpl_dodag/main.c for the exhaustive check.
 */
int lichen_rpl_lollipop_cmp(uint8_t a, uint8_t b);

/**
 * True if @p new_ver is strictly newer than @p old_ver.
 *
 * The DODAG state machine preserves the explicitly observed adjacent 127->0
 * restart; all other relationships come from lichen_rpl_lollipop_cmp().
 */
bool lichen_rpl_version_is_newer(uint8_t new_ver, uint8_t old_ver);
#endif /* LICHEN_RPL_TEST */

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_DODAG_H_ */
