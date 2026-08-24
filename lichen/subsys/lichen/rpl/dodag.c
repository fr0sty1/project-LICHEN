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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <lichen/rpl_dodag.h>
#include <lichen/rpl_addr.h>

/**
 * RFC 6550 Section 7.2: Lollipop sequence-counter comparison.
 *
 * Values in [128..255] are the linear region (restart/bootstrap); values
 * in [0..127] are the circular region, a 128-value serial number space per
 * RFC 1982. SEQUENCE_WINDOW is 16 (RFC MUST).
 *
 * Mirrors rust/lichen-rpl/src/routing.rs seq_is_newer():
 * - Same region: RFC 1982 serial arithmetic on the low 7 bits; newer iff
 *   the wrapped difference is in [1..SEQUENCE_WINDOW]. This accepts
 *   multi-step crossings of the 127->0 restart (e.g. 5 after 120) exactly
 *   as the Rust reference does.
 * - a linear, b circular: a is newer iff more than SEQUENCE_WINDOW steps
 *   past the 255->0 wrap, i.e. (256 + b - a) > SEQUENCE_WINDOW.
 * - a circular, b linear: a is newer iff within SEQUENCE_WINDOW steps of
 *   the 255->0 wrap, i.e. (256 + a - b) <= SEQUENCE_WINDOW.
 *
 * lollipop_cmp returns 1 if a is newer, -1 if older, 0 if equal, and
 * LOLLIPOP_INCOMPARABLE when neither direction is newer.
 *
 * Exhaustive cross-check against the Rust semantics:
 * lichen/tests/rpl_dao_sequence/sweep.c + golden_lollipop_sweep.txt.
 */
#define LOLLIPOP_LINEAR_BASE	 128
#define LOLLIPOP_SEQUENCE_WINDOW 16
#define LOLLIPOP_INCOMPARABLE	 2

static bool lollipop_is_newer(uint8_t new_seq, uint8_t old_seq)
{
	bool new_linear = new_seq >= LOLLIPOP_LINEAR_BASE;
	bool old_linear = old_seq >= LOLLIPOP_LINEAR_BASE;
	uint8_t diff;

	if (new_linear == old_linear) {
		/* RFC 1982 serial arithmetic inside one region (mod 128). */
		diff = (uint8_t)((uint8_t)(new_seq - old_seq) & 0x7Fu);
		return diff != 0 && diff <= LOLLIPOP_SEQUENCE_WINDOW;
	}
	if (new_linear) {
		/* New past the 255->0 wrap by more than SEQUENCE_WINDOW. */
		return (256u + old_seq - new_seq) > LOLLIPOP_SEQUENCE_WINDOW;
	}
	/* New within SEQUENCE_WINDOW steps of the 255->0 wrap. */
	return (256u + new_seq - old_seq) <= LOLLIPOP_SEQUENCE_WINDOW;
}

static int lollipop_cmp(uint8_t a, uint8_t b)
{
	if (a == b) {
		return 0;
	}
	if (lollipop_is_newer(a, b)) {
		return 1;
	}
	if (lollipop_is_newer(b, a)) {
		return -1;
	}
	return LOLLIPOP_INCOMPARABLE;
}

/**
 * True if a is strictly newer than b.
 *
 * Matches rust/lichen-rpl/src/routing.rs seq_is_newer(); the mod-128
 * serial form subsumes the increment_lollipop restarts (0 after 127 and
 * 0 after 255 are newer; the reverse pairs are stale).
 */
static bool version_is_newer(uint8_t a, uint8_t b)
{
	return lollipop_cmp(a, b) == 1;
}

#ifdef LICHEN_RPL_TEST
/* Prototypes live in rpl_dodag.h. External linkage is intentional
 * (lichen/tests/rpl_dodag). */
int lichen_rpl_lollipop_cmp(uint8_t a, uint8_t b) /* NOLINT(misc-use-internal-linkage) */
{
	return lollipop_cmp(a, b);
}

bool lichen_rpl_version_is_newer(uint8_t new_ver, uint8_t old_ver) /* NOLINT(misc-use-internal-linkage) */
{
	return version_is_newer(new_ver, old_ver);
}
#endif /* LICHEN_RPL_TEST */

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
	d->gateway_centric = false;
	d->last_gateway_centric = false;
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

	enum lichen_rpl_role prev_role = d->role;
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
		goto notify;
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

notify:
	/* Fire state change callback on role transition */
	if (d->state_cb != NULL && prev_role != d->role) {
		bool joined = (d->role == LICHEN_RPL_JOINED || d->role == LICHEN_RPL_ROOT);
		d->state_cb(joined, d->state_cb_user_data);
	}
}

int lichen_rpl_dodag_process_dio(struct lichen_rpl_dodag *d,
				  const struct lichen_rpl_dio *dio,
				  const struct lichen_rpl_dodag_config *config,
				  const uint8_t *neighbor_addr,
				  uint16_t link_etx,
				  uint8_t load_factor,
				  uint32_t now,
				  bool authenticated)
{
	if (d == NULL || dio == NULL || neighbor_addr == NULL) {
		return LICHEN_RPL_ERR_INVALID;
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

	/*
	 * SECURITY: DODAGVersionNumber is scoped to (RPLInstanceID, DODAGID).
	 * A JOINED node ignores a foreign DIO (no version compare, no adopt).
	 * An UNJOINED node may first-join a foreign DODAG without using leftover
	 * version bytes. Incomparable lollipop versions are not same-version.
	 */
	bool foreign = (dio->rpl_instance_id != d->rpl_instance_id) ||
		       !rpl_addr_eq(dio->dodag_id, d->dodag_id);

	if (foreign) {
		if (lichen_rpl_dodag_is_joined(d)) {
			return 0;
		}
		adopt_version(d, dio);
	} else if (version_is_newer(dio->version, d->version)) {
		adopt_version(d, dio);
	} else if (dio->version != d->version) {
		return 0;
	}

	/*
	 * Gateway-centric mode is root-authoritative: the DODAG Configuration
	 * option is honored only when this DIO was sent by the adopted root
	 * (the DODAGID is the root's address, RFC 6550 Section 2). Any joined
	 * peer could otherwise flap neighbors' announce scheduling per-DIO.
	 * Every DIO without an authoritative option restores the last-known-
	 * good root value so an earlier bad option cannot outlive one DIO.
	 */
	if (config != NULL && rpl_addr_eq(neighbor_addr, d->dodag_id)) {
		d->gateway_centric = config->gateway_centric;
		d->last_gateway_centric = config->gateway_centric;
	} else {
		d->gateway_centric = d->last_gateway_centric;
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

#ifndef LICHEN_RPL_TEST
int lichen_rpl_dodag_process_dio_bytes(struct lichen_rpl_dodag *d,
					const uint8_t *dio_bytes,
					size_t dio_len,
					const uint8_t *neighbor_addr,
					uint16_t link_etx,
					uint8_t load_factor,
					uint32_t now,
					bool authenticated)
{
	if (d == NULL || dio_bytes == NULL || neighbor_addr == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}

	struct lichen_rpl_dio dio;
	int ret = lichen_rpl_dio_parse(&dio, dio_bytes, dio_len);
	if (ret != LICHEN_RPL_OK) {
		return ret;
	}

	const uint8_t *opts = lichen_rpl_dio_options(dio_bytes, dio_len);
	size_t opts_len = lichen_rpl_dio_options_len(dio_len);

	/* Parse DODAG Configuration option; process_dio copies gateway_centric. */
	struct lichen_rpl_opt_iter it;
	struct lichen_rpl_raw_opt opt;
	struct lichen_rpl_dodag_config cfg;
	const struct lichen_rpl_dodag_config *config = NULL;
	lichen_rpl_opt_iter_init(&it, opts, opts_len);

	for (;;) {
		int oret = lichen_rpl_opt_iter_next(&it, &opt);
		if (oret == 1) {
			break;
		}
		if (oret != LICHEN_RPL_OK) {
			break;
		}
		if (opt.opt_type == LICHEN_RPL_OPT_DODAG_CONFIG) {
			ret = lichen_rpl_dodag_config_parse(&cfg, opt.data, opt.data_len);
			if (ret == LICHEN_RPL_OK) {
				config = &cfg;
			}
			break;
		}
	}

	return lichen_rpl_dodag_process_dio(d, &dio, config, neighbor_addr,
					    link_etx, load_factor, now,
					    authenticated);
}
#endif /* !LICHEN_RPL_TEST */

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

void lichen_rpl_dodag_set_state_cb(struct lichen_rpl_dodag *d,
				   lichen_rpl_dodag_state_cb cb,
				   void *user_data)
{
	if (d == NULL) {
		return;
	}
	d->state_cb = cb;
	d->state_cb_user_data = user_data;
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
