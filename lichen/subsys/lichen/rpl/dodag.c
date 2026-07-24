/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file dodag.c
 * @brief RPL DODAG state machine with MRHOF parent selection
 *
 * Ported from rust/lichen-rpl/src/dodag.rs
 *
 * ETX is stored as fixed-point (scaled by 256) to avoid floats on embedded.
 * path_cost = parent_rank + (link_etx * min_hop_rank_increase) / 256
 */

#include <lichen/rpl_dodag.h>
#include <lichen/rpl_addr.h>
#include <string.h>

/**
 * RFC 6550 Section 7.2: Lollipop sequence number comparison.
 *
 * RPL version numbers use a "lollipop" counter: values 0-127 are in the
 * linear region (restart), 128-255 are in the circular region (normal).
 *
 * Returns true if 'a' is newer than 'b' per lollipop semantics.
 * The circular region uses modular comparison with a window of SEQUENCE_WINDOW.
 */
#define LOLLIPOP_MAX_VALUE    255
#define LOLLIPOP_CIRCULAR_BIT 128
/*
 * SEQUENCE_WINDOW per RFC 1982 serial number arithmetic: 'a' is newer than 'b'
 * if (a - b) mod 128 is in (0, WINDOW]. Value 16 balances tolerance for
 * out-of-order delivery (~16 missed DIOs) against detecting true rollbacks.
 */
#define LOLLIPOP_SEQUENCE_WINDOW 16

static bool version_is_newer(uint8_t a, uint8_t b)
{
	/* If both in linear region (0-127), simple comparison */
	if (a < LOLLIPOP_CIRCULAR_BIT && b < LOLLIPOP_CIRCULAR_BIT) {
		return a > b;
	}

	/* If both in circular region (128-255), use modular comparison */
	if (a >= LOLLIPOP_CIRCULAR_BIT && b >= LOLLIPOP_CIRCULAR_BIT) {
		/*
		 * The circular region has 128 values (128-255).
		 * a is newer than b if (a - b) mod 128 is in (0, WINDOW].
		 * We mask with 0x7F to get the circular distance.
		 */
		uint8_t diff = (uint8_t)((a - b) & 0x7F);
		return diff > 0 && diff <= LOLLIPOP_SEQUENCE_WINDOW;
	}

	/*
	 * Mixed regions: linear (restart) is always newer than circular.
	 * A node restarting with version 0 should be accepted over version 250.
	 */
	return a < LOLLIPOP_CIRCULAR_BIT;
}

/**
 * Calculate path cost via this parent (MRHOF, RFC 6719 appendix B.1).
 *
 * path_cost = rank + (link_etx * mhri) / 256
 *
 * Using fixed-point: link_etx=256 means ETX=1.0, so we divide by 256.
 *
 * Overflow handling: multiplication is done in uint32_t (max product
 * 65535*65535 = 4,294,836,225 fits). Result saturates to 0xFFFF
 * (LICHEN_RPL_INFINITE_RANK) if the sum exceeds uint16_t range.
 */
static uint16_t path_cost(const struct lichen_rpl_parent *p, uint16_t mhri)
{
	uint32_t increment = ((uint32_t)p->link_etx * mhri) / 256;
	uint32_t cost = (uint32_t)p->rank + increment + ((uint32_t)p->load_factor * 8);
	return (cost > 0xFFFF) ? 0xFFFF : (uint16_t)cost;
}

static struct lichen_rpl_parent *find_parent(struct lichen_rpl_dodag *d,
					     const uint8_t *addr)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		if (d->parents[i].valid && rpl_addr_eq(d->parents[i].addr, addr)) {
			return &d->parents[i];
		}
	}
	return NULL;
}

static struct lichen_rpl_parent *find_free_slot(struct lichen_rpl_dodag *d)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		if (!d->parents[i].valid) {
			return &d->parents[i];
		}
	}
	return NULL;
}

/**
 * Find the worst parent (highest path cost) in the table.
 * Returns NULL if no valid parents exist.
 */
static struct lichen_rpl_parent *find_worst_parent(struct lichen_rpl_dodag *d)
{
	struct lichen_rpl_parent *worst = NULL;
	uint16_t worst_cost = 0;

	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		struct lichen_rpl_parent *p = &d->parents[i];
		if (!p->valid) {
			continue;
		}
		uint16_t cost = path_cost(p, d->min_hop_rank_increase);
		if (worst == NULL || cost > worst_cost) {
			worst = p;
			worst_cost = cost;
		}
	}
	return worst;
}

/**
 * Check if a candidate is admissible (MaxRankIncrease check).
 */
static bool is_admissible(const struct lichen_rpl_dodag *d,
			  const struct lichen_rpl_parent *p)
{
	uint16_t cost = path_cost(p, d->min_hop_rank_increase);

	if (d->lowest_rank == LICHEN_RPL_INFINITE_RANK) {
		return true;
	}

	uint32_t max_allowed = (uint32_t)d->lowest_rank + d->max_rank_increase;
	if (max_allowed > 0xFFFF) {
		max_allowed = 0xFFFF;
	}

	return cost <= max_allowed;
}

static void adopt_version(struct lichen_rpl_dodag *d,
			  const struct lichen_rpl_dio *dio)
{
	memcpy(d->dodag_id, dio->dodag_id, 16);
	d->rpl_instance_id = dio->rpl_instance_id;
	d->version = dio->version;
	d->dtsn = dio->dtsn;

	/* Clear all parent state */
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		d->parents[i].valid = false;
	}
	d->has_preferred_parent = false;
	d->rank = LICHEN_RPL_INFINITE_RANK;
	d->lowest_rank = LICHEN_RPL_INFINITE_RANK;
	d->role = LICHEN_RPL_UNJOINED;
}

/* ── Public API ────────────────────────────────────────────────────────────── */

int lichen_rpl_dodag_init(struct lichen_rpl_dodag *d,
			  uint8_t rpl_instance_id,
			  const uint8_t *dodag_id,
			  uint8_t version)
{
	if (d == NULL || dodag_id == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	memset(d, 0, sizeof(*d));

	d->rpl_instance_id = rpl_instance_id;
	memcpy(d->dodag_id, dodag_id, 16);
	d->version = version;
	d->dtsn = 0;
	d->role = LICHEN_RPL_UNJOINED;
	d->rank = LICHEN_RPL_INFINITE_RANK;
	d->has_preferred_parent = false;

	d->min_hop_rank_increase = LICHEN_RPL_DEFAULT_MIN_HOP_RANK;
	d->max_rank_increase = LICHEN_RPL_DEFAULT_MAX_RANK_INC;
	d->parent_switch_threshold = LICHEN_RPL_DEFAULT_SWITCH_THRESH;
	d->lowest_rank = LICHEN_RPL_INFINITE_RANK;
	return 0;
}

int lichen_rpl_dodag_init_root(struct lichen_rpl_dodag *d,
			       uint8_t rpl_instance_id,
			       const uint8_t *dodag_id,
			       uint8_t version)
{
	int err = lichen_rpl_dodag_init(d, rpl_instance_id, dodag_id, version);
	if (err != 0) {
		return err;
	}
	d->role = LICHEN_RPL_ROOT;
	d->rank = LICHEN_RPL_ROOT_RANK;
	d->lowest_rank = LICHEN_RPL_ROOT_RANK;
	return 0;
}

void lichen_rpl_dodag_select_parent(struct lichen_rpl_dodag *d)
{
	if (d == NULL) {
		return;
	}

	uint16_t mhri = d->min_hop_rank_increase;
	uint16_t threshold = d->parent_switch_threshold;

	/* Find best admissible parent */
	struct lichen_rpl_parent *best = NULL;
	uint16_t best_cost = 0xFFFF;

	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		struct lichen_rpl_parent *p = &d->parents[i];
		if (!p->valid || !is_admissible(d, p)) {
			continue;
		}
		uint16_t cost = path_cost(p, mhri);
		if (best == NULL || cost < best_cost) {
			best = p;
			best_cost = cost;
		}
	}

	/* No valid parent? */
	if (best == NULL) {
		if (d->role != LICHEN_RPL_ROOT) {
			d->role = LICHEN_RPL_UNJOINED;
			d->has_preferred_parent = false;
			d->rank = LICHEN_RPL_INFINITE_RANK;
		}
		return;
	}

	uint8_t *best_addr = best->addr;

	/* Hysteresis: only switch if improvement exceeds threshold */
	uint8_t *chosen_addr = best_addr;
	uint16_t chosen_cost = best_cost;

	if (d->has_preferred_parent && !rpl_addr_eq(d->preferred_parent, best_addr)) {
		struct lichen_rpl_parent *cur = find_parent(d, d->preferred_parent);
		/* SECURITY: Only apply hysteresis if current parent is still admissible.
		 * RFC 6550 Section 8.2.2.4: a node must not increase its rank beyond
		 * DAGMaxRankIncrease + cur_min_path_cost. */
		if (cur != NULL && is_admissible(d, cur)) {
			uint16_t cur_cost = path_cost(cur, mhri);
			/*
			 * Hysteresis: only switch if improvement exceeds threshold.
			 * Stay with current if: best_cost + threshold >= cur_cost
			 * This form avoids underflow when cur_cost <= threshold.
			 * Explicit casts prevent overflow if best_cost + threshold > 65535.
			 */
			if ((uint32_t)best_cost + (uint32_t)threshold >= (uint32_t)cur_cost) {
				/* Not enough improvement - stay with current */
				chosen_addr = cur->addr;
				chosen_cost = cur_cost;
			}
		}
	}

	memcpy(d->preferred_parent, chosen_addr, 16);
	d->has_preferred_parent = true;
	d->rank = chosen_cost;
	d->role = LICHEN_RPL_JOINED;

	if (chosen_cost < d->lowest_rank) {
		d->lowest_rank = chosen_cost;
	}
}

int lichen_rpl_dodag_process_dio(struct lichen_rpl_dodag *d,
				  const struct lichen_rpl_dio *dio,
				  const uint8_t *neighbor_addr,
				  uint16_t link_etx,
				  uint8_t load_factor,
				  uint32_t now,
				  bool authenticated)
{
	if (d == NULL || dio == NULL || neighbor_addr == NULL) {
		return 0;
	}

	if (d->role == LICHEN_RPL_ROOT) {
		return 0;
	}

	if (!authenticated) {
		return 0;
	}

	if (dio->mode_of_operation != 1 || !dio->grounded) {
		return 0;
	}

	if (lichen_rpl_dodag_is_joined(d) &&
	    !rpl_addr_eq(dio->dodag_id, d->dodag_id) &&
	    !version_is_newer(dio->version, d->version)) {
		return 0;
	}

	if (version_is_newer(dio->version, d->version) ||
	    !lichen_rpl_dodag_is_joined(d)) {
		adopt_version(d, dio);
	} else if (version_is_newer(d->version, dio->version)) {
		return 0;
	}

	int ret = 0;
	if (dio->dtsn != d->dtsn) {
		d->dtsn = dio->dtsn;
		ret = 1;
	}

	/* Poisoned route? Drop this candidate. */
	if (dio->rank == LICHEN_RPL_INFINITE_RANK) {
		struct lichen_rpl_parent *p = find_parent(d, neighbor_addr);
		if (p != NULL) {
			p->valid = false;
		}
		lichen_rpl_dodag_select_parent(d);
		return ret;
	}

	/*
	 * SECURITY: RFC 6550 Section 8.2.2.5 - reject parents with equal or
	 * higher rank to prevent routing loops. Only accept neighbors with
	 * strictly lower rank (unless we're unjoined with infinite rank).
	 */
	if (d->rank != LICHEN_RPL_INFINITE_RANK && dio->rank >= d->rank) {
		return ret;
	}

	/* Update or add parent candidate */
	struct lichen_rpl_parent *p = find_parent(d, neighbor_addr);
	if (p == NULL) {
		p = find_free_slot(d);
		if (p == NULL) {
			/*
			 * Table full - evict the worst parent if the new
			 * candidate would be better. Compute the new
			 * candidate's path cost to compare.
			 */
			struct lichen_rpl_parent *worst = find_worst_parent(d);
			if (worst == NULL) {
				return ret;
			}
			uint16_t worst_cost = path_cost(worst, d->min_hop_rank_increase);
			uint32_t new_increment = ((uint32_t)link_etx * d->min_hop_rank_increase) / 256;
			uint32_t new_cost = (uint32_t)dio->rank + new_increment + ((uint32_t)load_factor * 8);
			if (new_cost > 0xFFFF) {
				new_cost = 0xFFFF;
			}
			if (new_cost >= worst_cost) {
				return ret;
			}
			p = worst;
		}
		memcpy(p->addr, neighbor_addr, 16);
	}

	p->rank = dio->rank;
	p->link_etx = link_etx;
	p->load_factor = load_factor;
	p->last_updated = now;
	p->valid = true;

	lichen_rpl_dodag_select_parent(d);
	return ret;
}

void lichen_rpl_dodag_remove_parent(struct lichen_rpl_dodag *d,
				    const uint8_t *addr)
{
	if (d == NULL || addr == NULL) {
		return;
	}

	struct lichen_rpl_parent *p = find_parent(d, addr);
	if (p != NULL) {
		p->valid = false;
	}
	lichen_rpl_dodag_select_parent(d);
}

int lichen_rpl_dodag_parent_count(const struct lichen_rpl_dodag *d)
{
	if (d == NULL) {
		return 0;
	}

	int count = 0;
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		if (d->parents[i].valid) {
			count++;
		}
	}
	return count;
}

int lichen_rpl_dodag_expire_parents(struct lichen_rpl_dodag *d,
				    uint32_t now, uint32_t max_age)
{
	if (d == NULL) {
		return 0;
	}

	int expired = 0;

	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_PARENTS; i++) {
		struct lichen_rpl_parent *p = &d->parents[i];
		if (!p->valid) {
			continue;
		}

		/* Unsigned subtraction handles full 32-bit wraparound correctly:
		 * if now wrapped past last_updated, age is large (> max_age). */
		uint32_t age = now - p->last_updated;
		if (age > max_age) {
			p->valid = false;
			expired++;
		}
	}

	if (expired > 0) {
		lichen_rpl_dodag_select_parent(d);
	}

	return expired;
}
