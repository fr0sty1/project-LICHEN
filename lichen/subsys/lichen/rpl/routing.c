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

#include <lichen/rpl_routing.h>

/* Ensure LICHEN_RPL_MAX_HOPS fits in uint8_t (used for num_addresses field) */
_Static_assert(LICHEN_RPL_MAX_HOPS <= 255,
	       "LICHEN_RPL_MAX_HOPS exceeds uint8_t range");

/* ── Visited Set for O(1) Loop Detection ──────────────────────────────────── */

#define VISITED_BUCKETS 16  /* power of 2, >= LICHEN_RPL_MAX_HOPS */
_Static_assert((VISITED_BUCKETS & (VISITED_BUCKETS - 1)) == 0,
               "VISITED_BUCKETS must be power of 2 for bitwise AND optimization");
_Static_assert(VISITED_BUCKETS >= LICHEN_RPL_MAX_HOPS,
               "VISITED_BUCKETS must be >= LICHEN_RPL_MAX_HOPS for loop detection");

/** Hash an IPv6 address via XOR-folding for hash table indexing. */
static inline uint32_t addr_hash(const uint8_t *addr)
{
	/* XOR fold 16 bytes into 32 bits */
	uint32_t h = 0;
	for (int i = 0; i < 16; i += 4) {
		h ^= (uint32_t)addr[i] |
		     ((uint32_t)addr[i + 1] << 8) |
		     ((uint32_t)addr[i + 2] << 16) |
		     ((uint32_t)addr[i + 3] << 24);
	}
	return h;
}

/* Visited set for loop detection - open-addressed hash table */
struct visited_set {
	uint8_t addrs[VISITED_BUCKETS][16];
	bool occupied[VISITED_BUCKETS];
};

/** Reset a visited set to empty. */
static inline void visited_init(struct visited_set *v)
{
	memset(v->occupied, 0, sizeof(v->occupied));
}

/* Returns true if addr was already visited (loop), false if newly added */
static inline bool visited_check_and_add(struct visited_set *v, const uint8_t *addr)
{
	uint32_t bucket = addr_hash(addr) & (VISITED_BUCKETS - 1);
	uint32_t start = bucket;

	/* Linear probe for collision handling */
	do {
		if (!v->occupied[bucket]) {
			/* Empty slot - add and return "not visited" */
			memcpy(v->addrs[bucket], addr, 16);
			v->occupied[bucket] = true;
			return false;
		}
		if (rpl_addr_eq(v->addrs[bucket], addr)) {
			/* Found - loop detected */
			return true;
		}
		bucket = (bucket + 1) & (VISITED_BUCKETS - 1);
	} while (bucket != start);

	/* Table full - treat as loop to avoid infinite walk */
	return true;
}

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

uint8_t lichen_rpl_srh_hdr_ext_len(uint8_t num_addresses)
{
	return num_addresses * 2u;
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
	rpl_addr_copy(dm->node_address, node_address);
	dm->rpl_instance_id = rpl_instance_id;
	rpl_addr_copy(dm->dodag_id, dodag_id);
	dm->is_root = false;
	dm->dao_sequence = 0;
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
	lichen_rpl_routing_table_init(&dm->routing_table);
	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_manager_build_dao(struct lichen_rpl_dao_manager *dm,
				     const uint8_t *parent_addr,
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

	/* Use current sequence, then increment for next call.
	 * This ensures sequence 0 is used on the first DAO. */
	uint8_t seq = dm->dao_sequence;
	dm->dao_sequence++;

	struct lichen_rpl_dao dao = {
		.rpl_instance_id = dm->rpl_instance_id,
		.ack_requested = true,
		.flags = 0,
		.dao_sequence = seq,
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
		.path_control = 0,
		.path_sequence = 0,
		.path_lifetime = 255,
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

	if (opts == NULL || opts_len == 0) {
		return false;
	}

	struct lichen_rpl_opt_iter it;
	lichen_rpl_opt_iter_init(&it, opts, opts_len);

	bool have_target = false;
	uint8_t target[16];

	struct lichen_rpl_raw_opt opt;
	while (lichen_rpl_opt_iter_next(&it, &opt) == LICHEN_RPL_OK) {
		if (opt.opt_type == LICHEN_RPL_OPT_RPL_TARGET) {
			struct lichen_rpl_target t;
			if (lichen_rpl_target_parse(&t, opt.data, opt.data_len) == LICHEN_RPL_OK) {
				rpl_addr_copy(target, t.prefix);
				have_target = true;
			}
		} else if (opt.opt_type == LICHEN_RPL_OPT_TRANSIT_INFO) {
			/*
			 * Transit Info applies to the preceding Target(s).
			 * Return the first valid pair and stop.
			 */
			if (have_target) {
				struct lichen_rpl_transit_info ti;
				if (lichen_rpl_transit_info_parse(&ti, opt.data, opt.data_len) == LICHEN_RPL_OK) {
					rpl_addr_copy(target_out, target);
					rpl_addr_copy(parent_out, ti.parent_address);
					*lifetime_out = ti.path_lifetime;
					return true;
				}
			}
			/* No preceding target for this transit info - continue */
		}
	}

	return false;
}

/* Find parent edge entry by target */
static struct lichen_rpl_parent_edge *
find_edge(struct lichen_rpl_dao_manager *dm, const uint8_t *target)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (dm->parent_map[i].valid &&
		    rpl_addr_eq(dm->parent_map[i].target, target)) {
			return &dm->parent_map[i];
		}
	}
	return NULL;
}

static struct lichen_rpl_parent_edge *find_free_edge(struct lichen_rpl_dao_manager *dm)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (!dm->parent_map[i].valid) {
			return &dm->parent_map[i];
		}
	}
	return NULL;
}

/**
 * Walk target → parent → ... → root and return the downward path.
 * Returns path_len, or 0 if chain is incomplete or has a loop.
 *
 * Uses hash-based visited set for O(1) loop detection per hop,
 * making overall complexity O(n) instead of O(n^2).
 */
static int assemble_path(struct lichen_rpl_dao_manager *dm,
			 const uint8_t *target,
			 uint8_t path[][16])
{
	uint8_t chain[LICHEN_RPL_MAX_HOPS][16];
	int chain_len = 0;

	struct visited_set visited;
	visited_init(&visited);

	uint8_t node[16];
	rpl_addr_copy(node, target);

	/* Walk chain with O(1) loop detection via hash set */
	while (chain_len < LICHEN_RPL_MAX_HOPS) {
		if (rpl_addr_eq(node, dm->node_address)) {
			/* Reached root - reverse chain into path */
			for (int i = 0; i < chain_len; i++) {
				rpl_addr_copy(path[i], chain[chain_len - 1 - i]);
			}
			return chain_len;
		}

		/* Check for loop using visited set (O(1) amortized) */
		if (visited_check_and_add(&visited, node)) {
			return 0;  /* Loop detected */
		}

		rpl_addr_copy(chain[chain_len], node);
		chain_len++;

		/* Look up parent */
		struct lichen_rpl_parent_edge *edge = find_edge(dm, node);
		if (edge == NULL) {
			return 0;  /* Incomplete chain */
		}

		rpl_addr_copy(node, edge->parent);
	}

	return 0;  /* Too many hops */
}

/**
 * Rebuild route for a single target after its parent edge changed.
 *
 * @return 0 on success, negative LICHEN_RPL_ERR_* if assembly or install failed
 */
static int rebuild_single_route(struct lichen_rpl_dao_manager *dm,
				const uint8_t *target)
{
	uint8_t path[LICHEN_RPL_MAX_HOPS][16];
	int path_len = assemble_path(dm, target, path);

	if (path_len > 0) {
		return lichen_rpl_routing_table_add(&dm->routing_table,
						    target, path, (uint8_t)path_len);
	}
	return LICHEN_RPL_ERR_INVALID;  /* Path assembly failed (loop/incomplete) */
}

/**
 * Rebuild all routes that may be affected by a parent edge change.
 *
 * Complexity: O(E * H) where E = CONFIG_LICHEN_RPL_MAX_ROUTES edges,
 * H = LICHEN_RPL_MAX_HOPS. Each edge triggers assemble_path() which
 * walks up to H hops with O(1) visited-set lookups per hop.
 *
 * For small networks (E <= 32, H <= 16), this is acceptable. For larger
 * deployments, consider incremental updates: only rebuild routes whose
 * path includes the changed parent. This would require either:
 * 1. Tracking reverse dependencies (which routes transit each node), or
 * 2. Caching assembled paths and invalidating on parent change
 *
 * Current approach prioritizes simplicity and correctness over efficiency.
 */
static int rebuild_routes(struct lichen_rpl_dao_manager *dm)
{
	int failures = 0;

	/* Iterate all edges and try to assemble paths */
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (!dm->parent_map[i].valid) {
			continue;
		}

		/* Clear existing route before rebuilding to avoid stale entries
		 * if rebuild fails */
		lichen_rpl_routing_table_remove(&dm->routing_table,
						dm->parent_map[i].target);
		if (rebuild_single_route(dm, dm->parent_map[i].target) < 0) {
			failures++;
		}
	}

	return failures > 0 ? -1 : 0;
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
bool lichen_rpl_dao_manager_process_dao(struct lichen_rpl_dao_manager *dm,
					const uint8_t *dao_bytes, size_t len,
					uint32_t now)
{
	if (dm == NULL || dao_bytes == NULL) {
		return false;
	}
	if (!dm->is_root) {
		return false;
	}

	/* Validate RPL instance ID and DODAG ID match our configuration.
	 * Reject DAOs from other DODAGs to prevent route poisoning. */
	struct lichen_rpl_dao dao;
	if (lichen_rpl_dao_parse(&dao, dao_bytes, len) != LICHEN_RPL_OK) {
		return false;
	}
	if (dao.rpl_instance_id != dm->rpl_instance_id ||
	    memcmp(dao.dodag_id, dm->dodag_id, 16) != 0) {
		return false;
	}

	uint8_t target[16];
	uint8_t parent[16];
	uint8_t lifetime;

	if (!extract_edge(dao_bytes, len, target, parent, &lifetime)) {
		return false;
	}

	if (lifetime == 0) {
		struct lichen_rpl_parent_edge *edge = find_edge(dm, target);
		if (edge != NULL) {
			edge->valid = false;
		}
		lichen_rpl_routing_table_remove(&dm->routing_table, target);
		(void)rebuild_routes(dm);
		return false;
	}

	/* Update or add edge */
	struct lichen_rpl_parent_edge *edge = find_edge(dm, target);
	if (edge == NULL) {
		edge = find_free_edge(dm);
		if (edge == NULL) {
			return false;  /* Map full */
		}
	}

	rpl_addr_copy(edge->target, target);
	rpl_addr_copy(edge->parent, parent);
	edge->path_lifetime = lifetime;
	edge->last_updated = now;
	edge->valid = true;

	(void)rebuild_routes(dm);  /* Best-effort rebuild; lookup below determines success */

	/* Copy lifetime info to route */
	struct lichen_rpl_route *route = find_route(&dm->routing_table, target);
	if (route != NULL) {
		route->path_lifetime = lifetime;
		route->last_updated = now;
	}

	return route != NULL;
}

int lichen_rpl_routing_table_expire(struct lichen_rpl_routing_table *rt,
				    uint32_t now, uint32_t lifetime_unit)
{
	if (rt == NULL) {
		return 0;
	}

	int expired = 0;

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

	int expired = 0;

	/* Expire stale parent edges */
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		struct lichen_rpl_parent_edge *e = &dm->parent_map[i];
		if (!e->valid) {
			continue;
		}

		/* lifetime=255 means infinite (never expires) */
		if (e->path_lifetime == 255) {
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

	/* Also expire routes */
	expired += lichen_rpl_routing_table_expire(&dm->routing_table, now, lifetime_unit);

	/* Rebuild remaining routes after expiring edges */
	if (expired > 0) {
		(void)rebuild_routes(dm);
	}

	return expired;
}
