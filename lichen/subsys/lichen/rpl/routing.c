/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file routing.c
 * @brief RPL routing table and DAO manager implementation
 *
 * Ported from rust/lichen-rpl/src/routing.rs
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <lichen/rpl_addr.h>
#include <lichen/rpl_routing.h>

/* Ensure LICHEN_RPL_MAX_HOPS fits in uint8_t (used for num_addresses field) */
_Static_assert(LICHEN_RPL_MAX_HOPS <= 255,
	       "LICHEN_RPL_MAX_HOPS exceeds uint8_t range");
_Static_assert(CONFIG_LICHEN_RPL_MAX_ROUTES <= INT16_MAX,
	       "DAO stage slot cannot represent all route slots");

/* ── Source Routing Header ─────────────────────────────────────────────────── */

int lichen_rpl_srh_write(const struct lichen_rpl_srh *srh,
			 uint8_t *buf, size_t len)
{
	if (srh == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (srh->num_addresses > LICHEN_RPL_MAX_HOPS) {
		return LICHEN_RPL_ERR_INVALID;
	}
	/* segments_left must not exceed num_addresses */
	if (srh->segments_left > srh->num_addresses) {
		return LICHEN_RPL_ERR_INVALID;
	}
	size_t needed = 6 + (size_t)srh->num_addresses * 16;
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = 3;  /* routing type */
	buf[1] = srh->segments_left;
	buf[2] = 0;  /* CmprI */
	buf[3] = 0;  /* CmprE */
	buf[4] = 0;  /* reserved */
	buf[5] = 0;

	for (int i = 0; i < srh->num_addresses; i++) {
		memcpy(&buf[6 + i * 16], srh->addresses[i], 16);
	}

	return (int)needed;
}

int lichen_rpl_srh_parse(struct lichen_rpl_srh *srh,
			 const uint8_t *data, size_t len)
{
	if (srh == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < 6) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	if (data[0] != 3) {
		return LICHEN_RPL_ERR_BAD_RT;
	}

	/* SECURITY: Reject compressed SRHs (CmprI/CmprE > 0 per RFC 6554 Section 3).
	 * We only support uncompressed addresses (16 bytes each). Compressed SRHs
	 * would be parsed incorrectly, leading to misrouted packets. */
	if (data[2] != 0 || data[3] != 0) {
		return LICHEN_RPL_ERR_BAD_RT;
	}

	size_t addr_bytes = len - 6;
	if (addr_bytes % 16 != 0) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	size_t num_addrs = addr_bytes / 16;
	if (num_addrs > LICHEN_RPL_MAX_HOPS) {
		return LICHEN_RPL_ERR_OVERRUN;
	}

	uint8_t segments_left = data[1];

	/* segments_left must not exceed num_addresses */
	if (segments_left > num_addrs) {
		return LICHEN_RPL_ERR_BAD_RT;
	}

	srh->segments_left = segments_left;
	srh->num_addresses = (uint8_t)num_addrs;

	for (size_t i = 0; i < num_addrs; i++) {
		memcpy(srh->addresses[i], &data[6 + i * 16], 16);
	}

	return LICHEN_RPL_OK;
}

/* ── Routing Table ─────────────────────────────────────────────────────────── */

void lichen_rpl_routing_table_init(struct lichen_rpl_routing_table *rt)
{
	if (rt == NULL) {
		return;
	}
	memset(rt, 0, sizeof(*rt));
}

static struct lichen_rpl_route *
find_route(struct lichen_rpl_routing_table *rt, const uint8_t *target)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (rt->routes[i].valid && rpl_addr_eq(rt->routes[i].target, target)) {
			return &rt->routes[i];
		}
	}
	return NULL;
}

static struct lichen_rpl_route *find_free_route(struct lichen_rpl_routing_table *rt)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (!rt->routes[i].valid) {
			return &rt->routes[i];
		}
	}
	return NULL;
}

int lichen_rpl_routing_table_add(struct lichen_rpl_routing_table *rt,
				 const uint8_t *target,
				 const uint8_t path[][16],
				 uint8_t path_len)
{
	if (rt == NULL || target == NULL || path == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}

	/* A route with no hops is unusable - reject it */
	if (path_len == 0) {
		return LICHEN_RPL_ERR_INVALID;
	}

	if (path_len > LICHEN_RPL_MAX_HOPS) {
		return LICHEN_RPL_ERR_INVALID;
	}

	struct lichen_rpl_route *r = find_route(rt, target);
	if (r == NULL) {
		r = find_free_route(rt);
		if (r == NULL) {
			return LICHEN_RPL_ERR_FULL;  /* Table full */
		}
	}

	rpl_addr_copy(r->target, target);
	for (int i = 0; i < path_len; i++) {
		rpl_addr_copy(r->path[i], path[i]);
	}
	r->path_len = path_len;
	r->valid = true;

	return 0;
}

void lichen_rpl_routing_table_remove(struct lichen_rpl_routing_table *rt,
				     const uint8_t *target)
{
	if (rt == NULL || target == NULL) {
		return;
	}
	struct lichen_rpl_route *r = find_route(rt, target);
	if (r != NULL) {
		r->valid = false;
	}
}

const struct lichen_rpl_route *
lichen_rpl_routing_table_lookup(const struct lichen_rpl_routing_table *rt,
				const uint8_t *target)
{
	if (rt == NULL || target == NULL) {
		return NULL;
	}
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (rt->routes[i].valid && rpl_addr_eq(rt->routes[i].target, target)) {
			return &rt->routes[i];
		}
	}
	return NULL;
}

int lichen_rpl_routing_table_count(const struct lichen_rpl_routing_table *rt)
{
	if (rt == NULL) {
		return 0;
	}
	int count = 0;
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (rt->routes[i].valid) {
			count++;
		}
	}
	return count;
}

/* ── DAO Manager ───────────────────────────────────────────────────────────── */

int lichen_rpl_dao_manager_init(struct lichen_rpl_dao_manager *dm,
				const uint8_t *node_address,
				uint8_t rpl_instance_id,
				const uint8_t *dodag_id)
{
	if (dm == NULL || node_address == NULL || dodag_id == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	memset(dm, 0, sizeof(*dm));
	k_mutex_init(&dm->lock);
	rpl_addr_copy(dm->node_address, node_address);
	dm->rpl_instance_id = rpl_instance_id;
	rpl_addr_copy(dm->dodag_id, dodag_id);
	dm->is_root = false;
	dm->dao_sequence = 240;
	dm->path_sequence = 240;
	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_manager_init_root(struct lichen_rpl_dao_manager *dm,
				     const uint8_t *node_address,
				     uint8_t rpl_instance_id,
				     const uint8_t *dodag_id)
{
	int ret = lichen_rpl_dao_manager_init(dm, node_address, rpl_instance_id, dodag_id);
	if (ret != LICHEN_RPL_OK) {
		return ret;
	}
	dm->is_root = true;
	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_manager_bind_root_state(
	struct lichen_rpl_dao_manager *dm,
	struct lichen_rpl_dao_root_state *root_state)
{
	if (dm == NULL || root_state == NULL || !dm->is_root) {
		return LICHEN_RPL_ERR_INVALID;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	memset(root_state, 0, sizeof(*root_state));
	dm->root_state = root_state;
	k_mutex_unlock(&dm->lock);
	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_manager_lookup(struct lichen_rpl_dao_manager *dm,
				  const uint8_t *target,
				  struct lichen_rpl_route *route)
{
	if (dm == NULL || target == NULL || route == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	if (!dm->is_root || dm->root_state == NULL) {
		k_mutex_unlock(&dm->lock);
		return LICHEN_RPL_ERR_INVALID;
	}
	const struct lichen_rpl_route *found =
		lichen_rpl_routing_table_lookup(&dm->root_state->routing_table, target);
	if (found == NULL) {
		k_mutex_unlock(&dm->lock);
		return LICHEN_RPL_ERR_NOT_FOUND;
	}
	*route = *found;
	k_mutex_unlock(&dm->lock);
	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_manager_route_count(struct lichen_rpl_dao_manager *dm)
{
	if (dm == NULL) {
		return 0;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	int count = !dm->is_root || dm->root_state == NULL ? 0 :
		lichen_rpl_routing_table_count(&dm->root_state->routing_table);
	k_mutex_unlock(&dm->lock);
	return count;
}

static uint8_t increment_lollipop(uint8_t sequence)
{
	return sequence == 127 || sequence == 255 ? 0 : sequence + 1;
}

static int build_dao(struct lichen_rpl_dao_manager *dm,
		     const uint8_t *parent_addr, uint8_t path_lifetime,
		     uint8_t dao_sequence, uint8_t path_sequence,
		     uint8_t *buf, size_t len)
{
	/* Need: DAO(20) + Target(20) + TransitInfo(22) = 62 bytes, pad to 64 */
#define LICHEN_RPL_DAO_MIN_BUF 64
	if (dm == NULL || parent_addr == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_DAO_MIN_BUF) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	struct lichen_rpl_dao dao = {
		.rpl_instance_id = dm->rpl_instance_id,
		.ack_requested = true,
		.flags = 0,
		.dao_sequence = dao_sequence,
	};
	rpl_addr_copy(dao.dodag_id, dm->dodag_id);

	int pos = lichen_rpl_dao_write(&dao, buf, len);
	if (pos < 0) {
		return pos;
	}

	/* RPL Target option: advertise self */
	struct lichen_rpl_target target = {
		.prefix_len = 128,
	};
	rpl_addr_copy(target.prefix, dm->node_address);

	int n = lichen_rpl_target_write(&target, &buf[pos], len - pos);
	if (n < 0) {
		return n;
	}
	pos += n;

	/* Transit Info option: via parent */
	struct lichen_rpl_transit_info transit = {
		.path_control = 0x80,
		.path_sequence = path_sequence,
		.path_lifetime = path_lifetime,
	};
	rpl_addr_copy(transit.parent_address, parent_addr);

	n = lichen_rpl_transit_info_write(&transit, &buf[pos], len - pos);
	if (n < 0) {
		return n;
	}
	pos += n;

	return pos;
}

int lichen_rpl_dao_manager_build_dao_ack(struct lichen_rpl_dao_manager *dm,
				     uint8_t dao_sequence, uint8_t status,
				     uint8_t *buf, size_t len)
{
	if (dm == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < 20) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	struct lichen_rpl_dao_ack ack = {
		.rpl_instance_id = dm->rpl_instance_id,
		.flags = 0,
		.dao_sequence = dao_sequence,
		.status = status,
	};
	rpl_addr_copy(ack.dodag_id, dm->dodag_id);

	return lichen_rpl_dao_ack_write(&ack, buf, len);
}

/**
 * Extract target → parent edge from DAO options.
 *
 * Per RFC 6550 Section 6.7.7, Transit Information options apply to the
 * immediately preceding RPL Target option(s). This function extracts
 * the first valid (Target, Transit Info) pair.
 *
 * Note: Multiple targets may share a single Transit Info. This function
 * returns only the first target; a more complete implementation would
 * return all targets for the same transit info.
 */
static bool extract_edge(const uint8_t *dao_bytes, size_t len,
			 uint8_t *target_out, uint8_t *parent_out,
			 uint8_t *lifetime_out)
{
	const uint8_t *opts = lichen_rpl_dao_options(dao_bytes, len);
	size_t opts_len = lichen_rpl_dao_options_len_ex(dao_bytes, len);
	struct lichen_rpl_dao_stage *staged = workspace->stage;
	struct lichen_rpl_dao_parsed_target *targets = workspace->targets;
	struct lichen_rpl_dao_candidate *candidates = workspace->candidates;
	int target_count = 0;
	int candidate_count = 0;
	uint8_t path_sequence = 0;
	uint8_t path_lifetime = 0;
	bool external = false;
	bool have_transit = false;
	bool last_was_target = false;
	bool routes_closed = false;

	if (opts == NULL || opts_len == 0) {
		return false;
	}

	struct lichen_rpl_opt_iter it;
	struct lichen_rpl_raw_opt opt;
	lichen_rpl_opt_iter_init(&it, opts, opts_len);
	*staged_count = 0;

	for (;;) {
		int ret = lichen_rpl_opt_iter_next(&it, &opt);

		if (ret == 1) {
			break;
		}
		if (ret != LICHEN_RPL_OK) {
			return false;
		}
		if (opt.opt_type == LICHEN_RPL_OPT_RPL_TARGET) {
			struct lichen_rpl_target target;

			if (routes_closed) {
				return false;
			}

			if (candidate_count > 0) {
				if (!finish_group(staged, staged_count, targets, target_count,
						  candidates, candidate_count, path_sequence)) {
					return false;
				}
				target_count = 0;
				candidate_count = 0;
				have_transit = false;
			}
			if (opt.data_len != 18 ||
			    lichen_rpl_target_parse(&target, opt.data, opt.data_len) !=
				LICHEN_RPL_OK || target.prefix_len != 128 ||
			    target_count == CONFIG_LICHEN_RPL_MAX_ROUTES) {
				return false;
			}
			for (int i = 0; i < target_count; i++) {
				if (rpl_addr_eq(targets[i].target, target.prefix)) {
					return false;
				}
			}
			memset(&targets[target_count], 0, sizeof(targets[target_count]));
			rpl_addr_copy(targets[target_count].target, target.prefix);
			target_count++;
			last_was_target = true;
		} else if (opt.opt_type == LICHEN_RPL_OPT_RPL_TARGET_DESCRIPTOR) {
			if (routes_closed || !last_was_target || candidate_count > 0 ||
			    opt.data_len != 4) {
				return false;
			}
			targets[target_count - 1].descriptor =
				((uint32_t)opt.data[0] << 24) |
				((uint32_t)opt.data[1] << 16) |
				((uint32_t)opt.data[2] << 8) |
				(uint32_t)opt.data[3];
			targets[target_count - 1].has_descriptor = true;
			last_was_target = false;
		} else if (opt.opt_type == LICHEN_RPL_OPT_TRANSIT_INFO) {
			struct lichen_rpl_transit_info transit;

			if (routes_closed || target_count == 0 ||
			    opt.data_len != LICHEN_RPL_TRANSIT_INFO_DATA_LEN ||
			    opt.data[0] != 0 ||
			    lichen_rpl_transit_info_parse(&transit, opt.data, opt.data_len) !=
				LICHEN_RPL_OK) {
				return false;
			}
			transit.path_control &= LICHEN_RPL_PATH_CONTROL_MASK;
			if (transit.path_control == 0) {
				return false;
			}
			last_was_target = false;
			if (have_transit && (transit.path_sequence != path_sequence ||
					     transit.path_lifetime != path_lifetime)) {
				return false;
			}
			if (!have_transit) {
				path_sequence = transit.path_sequence;
				path_lifetime = transit.path_lifetime;
				external = false;
				have_transit = true;
			}

			struct lichen_rpl_dao_candidate candidate = {
				.path_control = transit.path_control,
				.path_lifetime = transit.path_lifetime,
				.external = false,
			};
			rpl_addr_copy(candidate.parent, transit.parent_address);
			for (int i = 0; i < candidate_count; i++) {
				if (!rpl_addr_eq(candidates[i].parent, candidate.parent)) {
					continue;
				}
				if (!candidate_equal(&candidates[i], &candidate)) {
					return false;
				}
				goto duplicate_candidate;
			}
			if (candidate_count == CONFIG_LICHEN_RPL_MAX_PARENTS) {
				return false;
			}
			candidates[candidate_count++] = candidate;
duplicate_candidate:
			;
		} else if (opt.opt_type == 0x12) {
			/* DAO Origin Signature (0x12). Per draft-lichen-rpl-lora-00.md §§7.3,7.5:
			 * MUST contain exactly one terminal option, Data Length=56 (u64 seq +
			 * Schnorr48). Root MUST send success DAO-ACK after replay-floor
			 * persistence for newly-accepted ack_requested DAOs. Equal-seq exact
			 * digest = idempotent retransmission (MAY resend ACK, MUST NOT rewrite
			 * floor). Matches Rust. Reference project-LICHEN-et78.2 */
			if (opt.data_len != 56) {
				return false;
			}
			/* Signature verification + replay floor update done by caller (link/OSCORE).
			 * Enforces MUST before semantic parsing. */
		} else {
			return false;
		}
	}

	if (routes_closed) {
		return *staged_count > 0;
	}
	return finish_group(staged, staged_count, targets, target_count,
			    candidates, candidate_count, path_sequence);
}

static const struct lichen_rpl_dao_snapshot *
proposed_snapshot(const struct lichen_rpl_dao_manager *dm,
		  const struct lichen_rpl_dao_stage *staged, int staged_count, int slot)
{
	for (int i = 0; i < staged_count; i++) {
		if (staged[i].changed && staged[i].slot == slot) {
			return &staged[i].snapshot;
		}
	}
	return &dm->root_state->snapshots[slot];
}

static int proposed_target_slot(const struct lichen_rpl_dao_manager *dm,
				const struct lichen_rpl_dao_stage *staged,
				int staged_count, const uint8_t *target)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		const struct lichen_rpl_dao_snapshot *snapshot =
			proposed_snapshot(dm, staged, staged_count, i);

		if (snapshot->valid && snapshot->active &&
		    rpl_addr_eq(snapshot->target, target)) {
			return i;
		}
	}
	return -1;
}

static bool validate_graph(const struct lichen_rpl_dao_manager *dm,
			   const struct lichen_rpl_dao_stage *staged, int staged_count)
{
	bool remaining[CONFIG_LICHEN_RPL_MAX_ROUTES] = { false };
	uint8_t max_depth[CONFIG_LICHEN_RPL_MAX_ROUTES] = { 0 };
	int active_count = 0;
	int candidate_count = 0;

	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		const struct lichen_rpl_dao_snapshot *snapshot =
			proposed_snapshot(dm, staged, staged_count, i);

		if (snapshot->valid && snapshot->active) {
			remaining[i] = true;
			active_count++;
			candidate_count += snapshot->candidate_count;
		}
	}
	if (candidate_count > CONFIG_LICHEN_RPL_MAX_ACTIVE_DAO_CANDIDATES) {
		return false;
	}

	for (int pass = 0; pass < CONFIG_LICHEN_RPL_MAX_ROUTES && active_count > 0; pass++) {
		bool removed = false;

		for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
			const struct lichen_rpl_dao_snapshot *snapshot;
			bool depends_on_remaining = false;

			if (!remaining[i]) {
				continue;
			}
			snapshot = proposed_snapshot(dm, staged, staged_count, i);
			for (int j = 0; j < snapshot->candidate_count; j++) {
				int parent_slot = proposed_target_slot(dm, staged, staged_count,
							       snapshot->candidates[j].parent);
				if (parent_slot >= 0 && remaining[parent_slot]) {
					depends_on_remaining = true;
					break;
				}
			}
			if (!depends_on_remaining) {
				remaining[i] = false;
				active_count--;
				removed = true;
			}
		}
		if (!removed) {
			return false;
		}
	}

	/* Reject any root-connected candidate chain that cannot fit an SRH. */
	for (int pass = 0; pass < CONFIG_LICHEN_RPL_MAX_ROUTES; pass++) {
		bool changed = false;

		for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
			const struct lichen_rpl_dao_snapshot *snapshot =
				proposed_snapshot(dm, staged, staged_count, i);
			uint8_t depth = max_depth[i];

			if (!snapshot->valid || !snapshot->active) {
				continue;
			}
			for (int j = 0; j < snapshot->candidate_count; j++) {
				uint8_t candidate_depth = 0;
				int parent_slot;

				if (rpl_addr_eq(snapshot->candidates[j].parent, dm->node_address)) {
					candidate_depth = 1;
				} else {
					parent_slot = proposed_target_slot(dm, staged, staged_count,
								       snapshot->candidates[j].parent);
					if (parent_slot >= 0 && max_depth[parent_slot] > 0) {
						candidate_depth = max_depth[parent_slot] + 1;
					}
				}
				if (candidate_depth > LICHEN_RPL_MAX_HOPS) {
					return false;
				}
				if (candidate_depth > depth) {
					depth = candidate_depth;
				}
			}
			if (depth != max_depth[i]) {
				max_depth[i] = depth;
				changed = true;
			}
		}
		if (!changed) {
			break;
		}
	}
	return active_count == 0;
}

static int path_control_priority(uint8_t path_control)
{
	for (int i = 0; i < 4; i++) {
		if (((path_control >> (6 - i * 2)) & 0x03U) != 0) {
			return i;
		}
	}
	return 4;
}

static int path_compare(const uint8_t a[][16], const uint8_t b[][16], uint8_t len)
{
	for (int i = 0; i < len; i++) {
		int cmp = memcmp(a[i], b[i], 16);

		if (cmp != 0) {
			return cmp;
		}
	}
	return 0;
}

static int path_compare_with_lengths(const uint8_t a[][16], uint8_t a_len,
				     const uint8_t b[][16], uint8_t b_len)
{
	uint8_t common = a_len < b_len ? a_len : b_len;
	int cmp = path_compare(a, b, common);

	if (cmp != 0) {
		return cmp;
	}
	return (int)a_len - (int)b_len;
}

static void rebuild_routes(struct lichen_rpl_dao_manager *dm)
{
	struct lichen_rpl_dao_root_state *root = dm->root_state;

	lichen_rpl_routing_table_init(&root->routing_table);
	memset(root->parent_map, 0, sizeof(root->parent_map));

	for (int pass = 0; pass < CONFIG_LICHEN_RPL_MAX_ROUTES; pass++) {
		bool changed = false;

		for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
			struct lichen_rpl_dao_snapshot *snapshot = &root->snapshots[i];
			uint8_t best_path[LICHEN_RPL_MAX_HOPS][16];
			uint8_t best_parent[16];
			uint8_t best_len = 0;
			uint8_t best_lifetime = 0;
			int best_priority = 4;

			if (!snapshot->valid || !snapshot->active) {
				continue;
			}
			for (int j = 0; j < snapshot->candidate_count; j++) {
				const struct lichen_rpl_dao_candidate *candidate =
					&snapshot->candidates[j];
				uint8_t candidate_path[LICHEN_RPL_MAX_HOPS][16];
				uint8_t candidate_len;
				int priority = path_control_priority(candidate->path_control);

				if (rpl_addr_eq(candidate->parent, dm->node_address)) {
					candidate_len = 1;
				} else {
					const struct lichen_rpl_route *parent =
						lichen_rpl_routing_table_lookup(&root->routing_table,
									candidate->parent);
					if (parent == NULL || parent->path_len >= LICHEN_RPL_MAX_HOPS) {
						continue;
					}
					candidate_len = parent->path_len + 1;
					memcpy(candidate_path, parent->path,
					       (size_t)parent->path_len * 16U);
				}
				rpl_addr_copy(candidate_path[candidate_len - 1], snapshot->target);
				if (best_len == 0 || priority < best_priority ||
				    (priority == best_priority &&
				     path_compare_with_lengths(candidate_path, candidate_len,
						       best_path, best_len) < 0)) {
					memcpy(best_path, candidate_path, (size_t)candidate_len * 16U);
					rpl_addr_copy(best_parent, candidate->parent);
					best_len = candidate_len;
					best_priority = priority;
					best_lifetime = candidate->path_lifetime;
				}
			}
			if (best_len > 0) {
				struct lichen_rpl_route *old = find_route(&root->routing_table,
								 snapshot->target);
				if (old == NULL || old->path_len != best_len ||
				    path_compare(old->path, best_path, best_len) != 0) {
					(void)lichen_rpl_routing_table_add(&root->routing_table,
									 snapshot->target,
									 best_path, best_len);
					changed = true;
				}
				struct lichen_rpl_route *route = find_route(&root->routing_table,
								       snapshot->target);
				route->path_lifetime = best_lifetime;
				route->last_updated = snapshot->last_updated;
				struct lichen_rpl_parent_edge *edge = &root->parent_map[i];
				rpl_addr_copy(edge->target, snapshot->target);
				rpl_addr_copy(edge->parent, best_parent);
				edge->path_lifetime = best_lifetime;
				edge->last_updated = snapshot->last_updated;
				edge->valid = true;
			}
		}
		if (!changed) {
			break;
		}
	}
}

/**
 * Process a received DAO message and update routing table.
 *
 * SECURITY: This function does not authenticate DAO messages. The caller
 * MUST ensure DAOs are received over an authenticated channel (OSCORE or
 * link-layer authentication per LICHEN security architecture). Unauthenticated
 * DAOs enable routing poisoning attacks where an attacker claims to be the
 * parent for arbitrary targets, redirecting traffic through themselves.
 *
 * The LICHEN frame layer provides Schnorr link signatures (48B) which
 * authenticate the immediate sender. For DAO security, verify that:
 * 1. The DAO was received from an authenticated link neighbor
 * 2. The claimed target/parent relationship is plausible (e.g., target
 *    is the immediate sender, or the sender is a known router)
 *
 * RFC 6550 Section 10 defines RPL security modes, but LICHEN relies on
 * the link-layer and OSCORE for authentication instead.
 *
 * @param dm         DAO manager (must be root)
 * @param dao_bytes  Raw DAO message bytes
 * @param len        Length of dao_bytes
 * @param now        Current timestamp for lifetime tracking
 * @return true if a route to the DAO target was successfully installed
 */
static enum lichen_rpl_dao_process_result process_dao(
	struct lichen_rpl_dao_manager *dm, const uint8_t *dao_bytes, size_t len,
	uint32_t now, bool *route_installed, bool *ack_requested,
	uint8_t *dao_sequence)
{
	struct lichen_rpl_dao_stage *staged;
	bool claimed[CONFIG_LICHEN_RPL_MAX_ROUTES] = { false };
	int staged_count;
	bool installed = false;
	bool changed = false;

	if (dm == NULL || dao_bytes == NULL) {
		return LICHEN_RPL_DAO_REJECTED;
	}
	if (!dm->is_root || dm->root_state == NULL) {
		return LICHEN_RPL_DAO_REJECTED;
	}
	struct lichen_rpl_dao_root_state *root = dm->root_state;
	staged = root->workspace.stage;

	/* Validate RPL instance ID and DODAG ID match our configuration.
	 * Reject DAOs from other DODAGs to prevent route poisoning. */
	struct lichen_rpl_dao dao;
	if (lichen_rpl_dao_parse(&dao, dao_bytes, len) != LICHEN_RPL_OK) {
		return LICHEN_RPL_DAO_REJECTED;
	}
	bool d_flag = (dao_bytes[1] & 0x40U) != 0;
	if (dao.rpl_instance_id != dm->rpl_instance_id ||
	    (d_flag && memcmp(dao.dodag_id, dm->dodag_id, 16) != 0)) {
		return LICHEN_RPL_DAO_REJECTED;
	}
	if (ack_requested != NULL) {
		*ack_requested = dao.ack_requested;
	}
	if (dao_sequence != NULL) {
		*dao_sequence = dao.dao_sequence;
	}
	if (!extract_updates(dao_bytes, len, &root->workspace, &staged_count)) {
		return LICHEN_RPL_DAO_REJECTED;
	}

	/* Existing targets reserve their own slots before new targets reclaim tombstones. */
	for (int i = 0; i < staged_count; i++) {
		for (int j = 0; j < CONFIG_LICHEN_RPL_MAX_ROUTES; j++) {
			if (root->snapshots[j].valid &&
			    rpl_addr_eq(root->snapshots[j].target, staged[i].snapshot.target)) {
				staged[i].slot = (int16_t)j;
				claimed[j] = true;
				break;
			}
		}
	}
	for (int i = 0; i < staged_count; i++) {
		struct lichen_rpl_dao_snapshot *incoming = &staged[i].snapshot;
		int existing = staged[i].slot;

		if (existing >= 0) {
			const struct lichen_rpl_dao_snapshot *current = &root->snapshots[existing];

			staged[i].slot = (int16_t)existing;
			enum lichen_rpl_sequence_relation relation =
				lichen_rpl_sequence_compare(incoming->path_sequence,
						    current->path_sequence);

			if (relation == LICHEN_RPL_SEQUENCE_EQUAL) {
				if (!snapshot_equal(incoming, current)) {
					return LICHEN_RPL_DAO_REJECTED;
				}
				continue;
			}
			if (relation != LICHEN_RPL_SEQUENCE_NEWER) {
				return LICHEN_RPL_DAO_REJECTED;
			}
			staged[i].changed = true;
		} else {
			for (int j = 0; j < CONFIG_LICHEN_RPL_MAX_ROUTES; j++) {
				if (!claimed[j] && (!root->snapshots[j].valid ||
				    (!root->snapshots[j].active &&
				     time_reached(now, root->snapshots[j].retain_until)))) {
					staged[i].slot = (int16_t)j;
					staged[i].changed = true;
					claimed[j] = true;
					break;
				}
			}
			if (staged[i].slot < 0) {
				return LICHEN_RPL_DAO_REJECTED;
			}
		}
		if (staged[i].changed) {
			incoming->last_updated = now;
			incoming->valid = true;
			incoming->active = incoming->candidates[0].path_lifetime != 0;
			incoming->disposition = incoming->active ? LICHEN_RPL_DAO_ACTIVE :
				LICHEN_RPL_DAO_WITHDRAWN;
			incoming->retain_until = incoming->active ? UINT32_MAX : retain_deadline(now);
		}
	}
	if (!validate_graph(dm, staged, staged_count)) {
		return LICHEN_RPL_DAO_REJECTED;
	}

	for (int i = 0; i < staged_count; i++) {
		if (staged[i].changed) {
			root->snapshots[staged[i].slot] = staged[i].snapshot;
			changed = true;
		}
	}
	rebuild_routes(dm);
	for (int i = 0; i < staged_count; i++) {
		if (lichen_rpl_routing_table_lookup(&root->routing_table,
						    staged[i].snapshot.target) != NULL) {
			installed = true;
		}
	}
	if (route_installed != NULL) {
		*route_installed = installed;
	}
	return changed ? LICHEN_RPL_DAO_APPLIED : LICHEN_RPL_DAO_IDEMPOTENT;
}

bool lichen_rpl_dao_manager_process_dao(struct lichen_rpl_dao_manager *dm,
					const uint8_t *dao_bytes, size_t len,
					uint32_t now)
{
	bool installed = false;

	if (dm == NULL) {
		return false;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	(void)process_dao(dm, dao_bytes, len, now, &installed, NULL, NULL);
	k_mutex_unlock(&dm->lock);
	return installed;
}

enum lichen_rpl_dao_process_result lichen_rpl_dao_manager_process_dao_ex(
	struct lichen_rpl_dao_manager *dm, const uint8_t *dao_bytes, size_t len,
	uint32_t now, uint8_t *ack_buf, size_t ack_buf_len)
{
	if (dm == NULL) {
		return LICHEN_RPL_DAO_REJECTED;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	bool ack_requested = false;
	uint8_t dao_sequence = 0;
	enum lichen_rpl_dao_process_result result = process_dao(dm, dao_bytes, len, now, NULL,
								&ack_requested, &dao_sequence);
	if (result != LICHEN_RPL_DAO_REJECTED && ack_requested && ack_buf != NULL &&
	    ack_buf_len >= 20) {
		(void)lichen_rpl_dao_manager_build_dao_ack(dm, dao_sequence, 0, ack_buf, ack_buf_len);
	}
	k_mutex_unlock(&dm->lock);
	return result;
}

int lichen_rpl_routing_table_expire(struct lichen_rpl_routing_table *rt,
				    uint32_t now, uint32_t lifetime_unit)
{
	if (rt == NULL) {
		return 0;
	}

	int expired = 0;

	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		const struct lichen_rpl_route *route = &rt->routes[i];

		if (route->valid && route->path_lifetime != 255) {
			uint64_t max_age = (uint64_t)route->path_lifetime * lifetime_unit;

			if (max_age == 0 || max_age > INT32_MAX) {
				return LICHEN_RPL_ERR_INVALID;
			}
		}
	}

	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		struct lichen_rpl_route *r = &rt->routes[i];
		if (!r->valid) {
			continue;
		}

		/* lifetime=255 means infinite (never expires) */
		if (r->path_lifetime == 255) {
			continue;
		}

		uint32_t max_age = (uint32_t)r->path_lifetime * lifetime_unit;
		/* Use signed comparison for 32-bit timestamp wraparound safety.
		 * Deadline is when entry should expire; entry is expired if
		 * now is at or past the deadline. Works for wraparound within ~24 days. */
		uint32_t deadline = r->last_updated + max_age;
		if ((int32_t)(now - deadline) >= 0) {
			r->valid = false;
			expired++;
		}
	}

	return expired;
}

int lichen_rpl_dao_manager_expire(struct lichen_rpl_dao_manager *dm,
				  uint32_t now, uint32_t lifetime_unit)
{
	if (dm == NULL) {
		return 0;
	}
	k_mutex_lock(&dm->lock, K_FOREVER);
	if (!dm->is_root || dm->root_state == NULL) {
		k_mutex_unlock(&dm->lock);
		return 0;
	}
	struct lichen_rpl_dao_root_state *root = dm->root_state;

	int expired = 0;
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		const struct lichen_rpl_dao_snapshot *snapshot = &root->snapshots[i];

		if (snapshot->valid && snapshot->active &&
		    snapshot->candidates[0].path_lifetime != 255) {
			uint64_t max_age =
				(uint64_t)snapshot->candidates[0].path_lifetime * lifetime_unit;

			if (max_age == 0 || max_age > INT32_MAX) {
				k_mutex_unlock(&dm->lock);
				return LICHEN_RPL_ERR_INVALID;
			}
		}
	}

	/* Expire active snapshots but retain their Path Sequence tombstones. */
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		struct lichen_rpl_dao_snapshot *snapshot = &root->snapshots[i];

		if (!snapshot->valid || !snapshot->active) {
			continue;
		}
		uint8_t lifetime = snapshot->candidates[0].path_lifetime;
		if (lifetime == 255) {
			continue;
		}

		uint32_t max_age = (uint32_t)e->path_lifetime * lifetime_unit;
		/* Use signed comparison for 32-bit timestamp wraparound safety.
		 * Deadline is when entry should expire; entry is expired if
		 * now is at or past the deadline. Works for wraparound within ~24 days. */
		uint32_t deadline = e->last_updated + max_age;
		if ((int32_t)(now - deadline) >= 0) {
			e->valid = false;
			expired++;
		}
	}
	if (expired > 0) {
		rebuild_routes(dm);
	}

	k_mutex_unlock(&dm->lock);
	return expired;
}
