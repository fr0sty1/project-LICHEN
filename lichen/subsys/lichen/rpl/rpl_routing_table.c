/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rpl_routing_table.c
 * @brief RPL routing table implementation
 *
 * Ported from rust/lichen-rpl/src/routing.rs
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <lichen/rpl_addr.h>
#include <lichen/rpl_routing.h>
#include "rpl_internal.h"

_Static_assert(CONFIG_LICHEN_RPL_MAX_ROUTES <= INT16_MAX,
	       "DAO stage slot cannot represent all route slots");

/* ── Internal route lookup helpers ─────────────────────────────────────────── */

struct lichen_rpl_route *
find_route(struct lichen_rpl_routing_table *rt, const uint8_t *target)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (rt->routes[i].valid && rt->routes[i].prefix_len == 128 &&
		    rpl_addr_eq(rt->routes[i].target, target)) {
			return &rt->routes[i];
		}
	}
	return NULL;
}

struct lichen_rpl_route *
find_prefix_route(struct lichen_rpl_routing_table *rt, const uint8_t *prefix,
		  uint8_t prefix_len)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (rt->routes[i].valid && rt->routes[i].is_prefix &&
		    rt->routes[i].prefix_len == prefix_len &&
		    rpl_addr_eq(rt->routes[i].target, prefix)) {
			return &rt->routes[i];
		}
	}
	return NULL;
}

struct lichen_rpl_route *find_free_route(struct lichen_rpl_routing_table *rt)
{
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		if (!rt->routes[i].valid) {
			return &rt->routes[i];
		}
	}
	return NULL;
}

/* ── Public routing table API ──────────────────────────────────────────────── */

void lichen_rpl_routing_table_init(struct lichen_rpl_routing_table *rt)
{
	if (rt == NULL) {
		return;
	}
	memset(rt, 0, sizeof(*rt));
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
	r->prefix_len = 128;
	r->is_prefix = false;
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

int lichen_rpl_routing_table_add_prefix(struct lichen_rpl_routing_table *rt,
					const uint8_t *prefix,
					uint8_t prefix_len,
					const uint8_t *egress,
					const uint8_t path[][16],
					uint8_t path_len)
{
	if (rt == NULL || prefix == NULL || egress == NULL || path == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (prefix_len == 0 || prefix_len >= 128) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (path_len == 0 || path_len > LICHEN_RPL_MAX_HOPS) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (memcmp(path[path_len - 1], egress, 16) != 0) {
		return LICHEN_RPL_ERR_INVALID;
	}

	/* Check path does not contain the canonical prefix address */
	uint8_t canonical[16];
	memcpy(canonical, prefix, 16);
	(void)lichen_rpl_prefix_canonicalize(canonical, prefix_len);
	for (uint8_t i = 0; i < path_len; i++) {
		if (memcmp(path[i], canonical, 16) == 0) {
			return LICHEN_RPL_ERR_INVALID;
		}
	}

	struct lichen_rpl_route *r = find_prefix_route(rt, prefix, prefix_len);
	bool is_new = (r == NULL);
	if (r == NULL) {
		r = find_free_route(rt);
		if (r == NULL) {
			return LICHEN_RPL_ERR_FULL;
		}
	}
	rpl_addr_copy(r->target, canonical);
	r->prefix_len = prefix_len;
	r->is_prefix = true;
	for (uint8_t i = 0; i < path_len; i++) {
		rpl_addr_copy(r->path[i], path[i]);
	}
	r->path_len = path_len;
	r->valid = true;
	if (is_new) {
		rt->prefix_route_count++;
	}

	/* Update managed prefix tracking */
	bool is_managed = lichen_rpl_routing_table_is_managed_host(rt, egress);
	if (is_managed) {
		int slot = -1;
		for (int i = 0; i < (int)CONFIG_LICHEN_RPL_MAX_PREFIX_ROUTES; i++) {
			if (rt->rpl_managed_prefixes[i].prefix_len == prefix_len &&
			    memcmp(rt->rpl_managed_prefixes[i].prefix, canonical, 16) == 0) {
				slot = i;
				break;
			}
		}
		if (slot < 0) {
			for (int i = 0; i < (int)CONFIG_LICHEN_RPL_MAX_PREFIX_ROUTES; i++) {
				if (rt->rpl_managed_prefixes[i].prefix_len == 0) {
					slot = i;
					break;
				}
			}
		}
		if (slot >= 0) {
			memcpy(rt->rpl_managed_prefixes[slot].prefix, canonical, 16);
			rt->rpl_managed_prefixes[slot].prefix_len = prefix_len;
			memcpy(rt->rpl_managed_prefixes[slot].egress, egress, 16);
			if ((uint8_t)slot >= rt->rpl_managed_prefix_count) {
				rt->rpl_managed_prefix_count = (uint8_t)(slot + 1);
			}
		}
	} else {
		/* Remove from managed prefixes if present and now unmanaged */
		for (int i = 0; i < (int)CONFIG_LICHEN_RPL_MAX_PREFIX_ROUTES; i++) {
			if (rt->rpl_managed_prefixes[i].prefix_len == prefix_len &&
			    memcmp(rt->rpl_managed_prefixes[i].prefix, canonical, 16) == 0) {
				memset(&rt->rpl_managed_prefixes[i], 0,
				       sizeof(rt->rpl_managed_prefixes[i]));
				break;
			}
		}
	}

	return 0;
}

void lichen_rpl_routing_table_remove_prefix(struct lichen_rpl_routing_table *rt,
					    const uint8_t *prefix,
					    uint8_t prefix_len)
{
	if (rt == NULL || prefix == NULL) {
		return;
	}
	struct lichen_rpl_route *r = find_prefix_route(rt, prefix, prefix_len);
	if (r != NULL) {
		r->valid = false;
		if (rt->prefix_route_count > 0) {
			rt->prefix_route_count--;
		}
		/* Remove from managed prefixes */
		for (int i = 0; i < (int)CONFIG_LICHEN_RPL_MAX_PREFIX_ROUTES; i++) {
			if (rt->rpl_managed_prefixes[i].prefix_len == prefix_len &&
			    memcmp(rt->rpl_managed_prefixes[i].prefix, prefix, 16) == 0) {
				memset(&rt->rpl_managed_prefixes[i], 0,
				       sizeof(rt->rpl_managed_prefixes[i]));
				break;
			}
		}
	}
}

bool lichen_rpl_routing_table_mark_prefix_expired(struct lichen_rpl_routing_table *rt,
						  const uint8_t *prefix,
						  uint8_t prefix_len)
{
	if (rt == NULL || prefix == NULL || prefix_len == 128) {
		return false;
	}
	struct lichen_rpl_route *r = find_prefix_route(rt, prefix, prefix_len);
	if (r == NULL) {
		return false;
	}
	r->valid = false;
	if (rt->prefix_route_count > 0) {
		rt->prefix_route_count--;
	}
	return true;
}

bool lichen_rpl_routing_table_mark_stale(struct lichen_rpl_routing_table *rt,
					 const uint8_t *target)
{
	if (rt == NULL || target == NULL) {
		return false;
	}
	struct lichen_rpl_route *r = find_route(rt, target);
	if (r == NULL) {
		return false;
	}
	return true;
}

bool lichen_rpl_routing_table_mark_expired(struct lichen_rpl_routing_table *rt,
					   const uint8_t *target)
{
	if (rt == NULL || target == NULL) {
		return false;
	}
	struct lichen_rpl_route *r = find_route(rt, target);
	if (r == NULL) {
		return false;
	}
	r->valid = false;
	return true;
}

int lichen_rpl_routing_table_add_managed_host(struct lichen_rpl_routing_table *rt,
					      const uint8_t *egress)
{
	if (rt == NULL || egress == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	for (int i = 0; i < (int)rt->rpl_managed_host_count; i++) {
		if (memcmp(rt->rpl_managed_hosts[i], egress, 16) == 0) {
			return LICHEN_RPL_OK;
		}
	}
	if (rt->rpl_managed_host_count >= CONFIG_LICHEN_RPL_MAX_PREFIX_ROUTES) {
		return LICHEN_RPL_ERR_FULL;
	}
	memcpy(rt->rpl_managed_hosts[rt->rpl_managed_host_count], egress, 16);
	rt->rpl_managed_host_count++;
	return LICHEN_RPL_OK;
}

void lichen_rpl_routing_table_remove_managed_host(struct lichen_rpl_routing_table *rt,
						  const uint8_t *egress)
{
	if (rt == NULL || egress == NULL) {
		return;
	}
	for (int i = 0; i < (int)rt->rpl_managed_host_count; i++) {
		if (memcmp(rt->rpl_managed_hosts[i], egress, 16) == 0) {
			int last = (int)rt->rpl_managed_host_count - 1;
			if (i < last) {
				memcpy(rt->rpl_managed_hosts[i],
				       rt->rpl_managed_hosts[last], 16);
			}
			rt->rpl_managed_host_count--;
			return;
		}
	}
}

bool lichen_rpl_routing_table_is_managed_host(const struct lichen_rpl_routing_table *rt,
					      const uint8_t *egress)
{
	if (rt == NULL || egress == NULL) {
		return false;
	}
	for (int i = 0; i < (int)rt->rpl_managed_host_count; i++) {
		if (memcmp(rt->rpl_managed_hosts[i], egress, 16) == 0) {
			return true;
		}
	}
	return false;
}

const struct lichen_rpl_route *
lichen_rpl_routing_table_lookup(const struct lichen_rpl_routing_table *rt,
				const uint8_t *target)
{
	if (rt == NULL || target == NULL) {
		return NULL;
	}
	/* Fast path: no prefix routes, direct /128 match */
	if (rt->prefix_route_count == 0) {
		for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
			if (rt->routes[i].valid && !rt->routes[i].is_prefix &&
			    rpl_addr_eq(rt->routes[i].target, target)) {
				return &rt->routes[i];
			}
		}
		return NULL;
	}
	/* LPM: scan all non-expired routes, find most specific matching prefix */
	const struct lichen_rpl_route *best = NULL;
	uint8_t best_len = 0;
	for (int i = 0; i < CONFIG_LICHEN_RPL_MAX_ROUTES; i++) {
		const struct lichen_rpl_route *r = &rt->routes[i];
		if (!r->valid) {
			continue;
		}
		int match_len = 0;
		if (r->is_prefix) {
			if (lichen_rpl_prefix_contains(r->target, r->prefix_len, target)) {
				match_len = r->prefix_len;
			}
		} else {
			if (rpl_addr_eq(r->target, target)) {
				match_len = 128;
			}
		}
		if (match_len > 0 && match_len > (int)best_len) {
			best = r;
			best_len = (uint8_t)match_len;
		}
	}
	return best;
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
