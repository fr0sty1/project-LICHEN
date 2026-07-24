/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/routing/loadng.h>

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/atomic.h>

#ifndef CONFIG_LICHEN_LOADNG_ROUTE_CACHE_SIZE
#define CONFIG_LICHEN_LOADNG_ROUTE_CACHE_SIZE LICHEN_LOADNG_ROUTE_CACHE_SIZE
#endif

#ifndef CONFIG_LICHEN_LOADNG_SEEN_TABLE_SIZE
#define CONFIG_LICHEN_LOADNG_SEEN_TABLE_SIZE 16U
#endif

/* Expanding ring hop limits (spec B2.5). */
static const uint8_t expanding_ring[LICHEN_LOADNG_EXPANDING_RING_COUNT] = {
	LICHEN_LOADNG_EXPANDING_RING_0,
	LICHEN_LOADNG_EXPANDING_RING_1,
	LICHEN_LOADNG_EXPANDING_RING_2,
};

/* Route cache protected by mutex. */
static K_MUTEX_DEFINE(cache_mutex);
static struct lichen_loadng_route route_cache[CONFIG_LICHEN_LOADNG_ROUTE_CACHE_SIZE];
static uint32_t route_access_order[CONFIG_LICHEN_LOADNG_ROUTE_CACHE_SIZE];
static uint32_t access_counter;

/* Seen RREQ table protected by mutex. */
static K_MUTEX_DEFINE(seen_mutex);
static struct lichen_loadng_seen_rreq seen_table[CONFIG_LICHEN_LOADNG_SEEN_TABLE_SIZE];

#define PRUNE_INTERVAL 16
static atomic_t prune_countdown = ATOMIC_INIT(PRUNE_INTERVAL);

/*
 * Message codec implementations.
 */

int lichen_loadng_rreq_parse(const uint8_t *data, size_t len,
			     struct lichen_loadng_rreq *rreq)
{
	if (data == NULL || rreq == NULL) {
		return -EINVAL;
	}
	if (len < LICHEN_LOADNG_RREQ_RREP_LEN) {
		return -EMSGSIZE;
	}

	rreq->flags = data[0];
	rreq->hop_limit = data[1];
	rreq->seq_num = ((uint16_t)data[2] << 8) | data[3];
	memcpy(rreq->originator, &data[4], 16);
	memcpy(rreq->destination, &data[20], 16);

	return 0;
}

int lichen_loadng_rreq_write(const struct lichen_loadng_rreq *rreq,
			     uint8_t *buf, size_t buf_len)
{
	if (rreq == NULL || buf == NULL) {
		return -EINVAL;
	}
	if (buf_len < LICHEN_LOADNG_RREQ_RREP_LEN) {
		return -ENOMEM;
	}

	buf[0] = rreq->flags;
	buf[1] = rreq->hop_limit;
	buf[2] = (uint8_t)(rreq->seq_num >> 8);
	buf[3] = (uint8_t)rreq->seq_num;
	memcpy(&buf[4], rreq->originator, 16);
	memcpy(&buf[20], rreq->destination, 16);

	return LICHEN_LOADNG_RREQ_RREP_LEN;
}

int lichen_loadng_rrep_parse(const uint8_t *data, size_t len,
			     struct lichen_loadng_rrep *rrep)
{
	if (data == NULL || rrep == NULL) {
		return -EINVAL;
	}
	if (len < LICHEN_LOADNG_RREQ_RREP_LEN) {
		return -EMSGSIZE;
	}

	rrep->flags = data[0];
	rrep->hop_count = data[1];
	rrep->seq_num = ((uint16_t)data[2] << 8) | data[3];
	memcpy(rrep->originator, &data[4], 16);
	memcpy(rrep->destination, &data[20], 16);

	return 0;
}

int lichen_loadng_rrep_write(const struct lichen_loadng_rrep *rrep,
			     uint8_t *buf, size_t buf_len)
{
	if (rrep == NULL || buf == NULL) {
		return -EINVAL;
	}
	if (buf_len < LICHEN_LOADNG_RREQ_RREP_LEN) {
		return -ENOMEM;
	}

	buf[0] = rrep->flags;
	buf[1] = rrep->hop_count;
	buf[2] = (uint8_t)(rrep->seq_num >> 8);
	buf[3] = (uint8_t)rrep->seq_num;
	memcpy(&buf[4], rrep->originator, 16);
	memcpy(&buf[20], rrep->destination, 16);

	return LICHEN_LOADNG_RREQ_RREP_LEN;
}

int lichen_loadng_rerr_parse(const uint8_t *data, size_t len,
			     struct lichen_loadng_rerr *rerr)
{
	if (data == NULL || rerr == NULL) {
		return -EINVAL;
	}
	if (len < LICHEN_LOADNG_RERR_LEN) {
		return -EMSGSIZE;
	}

	rerr->flags = data[0];
	rerr->error_code = data[1];
	memcpy(rerr->unreachable, &data[2], 16);

	return 0;
}

int lichen_loadng_rerr_write(const struct lichen_loadng_rerr *rerr,
			     uint8_t *buf, size_t buf_len)
{
	if (rerr == NULL || buf == NULL) {
		return -EINVAL;
	}
	if (buf_len < LICHEN_LOADNG_RERR_LEN) {
		return -ENOMEM;
	}

	buf[0] = rerr->flags;
	buf[1] = rerr->error_code;
	memcpy(&buf[2], rerr->unreachable, 16);

	return LICHEN_LOADNG_RERR_LEN;
}

/*
 * Route cache implementation.
 */

void lichen_loadng_cache_init(void)
{
	k_mutex_lock(&cache_mutex, K_FOREVER);
	memset(route_cache, 0, sizeof(route_cache));
	memset(route_access_order, 0, sizeof(route_access_order));
	access_counter = 0;
	k_mutex_unlock(&cache_mutex);
}

static struct lichen_loadng_route *find_route_locked(const uint8_t destination[16])
{
	for (size_t i = 0; i < ARRAY_SIZE(route_cache); i++) {
		if (route_cache[i].active &&
		    memcmp(route_cache[i].destination, destination, 16) == 0) {
			return &route_cache[i];
		}
	}
	return NULL;
}

static size_t find_lru_slot_locked(void)
{
	size_t free_idx = ARRAY_SIZE(route_cache);
	size_t oldest_idx = 0;
	bool have_active = false;
	uint32_t oldest_access = 0;

	for (size_t i = 0; i < ARRAY_SIZE(route_cache); i++) {
		if (!route_cache[i].active) {
			if (free_idx == ARRAY_SIZE(route_cache)) {
				free_idx = i;
			}
			continue;
		}
		if (!have_active) {
			oldest_access = route_access_order[i];
			oldest_idx = i;
			have_active = true;
			continue;
		}
		/* SECURITY: signed comparison handles 32-bit access_counter wraparound safely */
		if ((int32_t)(route_access_order[i] - oldest_access) < 0) {
			oldest_access = route_access_order[i];
			oldest_idx = i;
		}
	}

	return (free_idx < ARRAY_SIZE(route_cache)) ? free_idx : (have_active ? oldest_idx : 0);
}

int lichen_loadng_cache_add(const struct lichen_loadng_route *route)
{
	if (route == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&cache_mutex, K_FOREVER);

	struct lichen_loadng_route *existing = find_route_locked(route->destination);
	size_t idx;

	if (existing != NULL) {
		/* RFC 1982 freshness check: reject if new seq_num is stale
		 * or if equal seq_num with worse-or-equal metric.
		 */
		if (lichen_loadng_seq_is_fresher(route->seq_num, existing->seq_num)) {
			/* New seq_num is actually older than existing */
			k_mutex_unlock(&cache_mutex);
			return 0;
		}
		if (route->seq_num == existing->seq_num &&
		    route->metric >= existing->metric) {
			/* Same seq_num but metric is not better */
			k_mutex_unlock(&cache_mutex);
			return 0;
		}
		idx = existing - route_cache;
	} else {
		idx = find_lru_slot_locked();
	}

	route_cache[idx] = *route;
	route_cache[idx].active = true;
	route_access_order[idx] = ++access_counter;

	k_mutex_unlock(&cache_mutex);
	return 0;
}

int lichen_loadng_cache_lookup(const uint8_t destination[16], uint32_t now_ms,
			       struct lichen_loadng_route *route)
{
	if (destination == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&cache_mutex, K_FOREVER);

	struct lichen_loadng_route *found = find_route_locked(destination);
	if (found == NULL) {
		k_mutex_unlock(&cache_mutex);
		return -ENOENT;
	}

	/* Check expiry if timestamp provided. */
	/* SECURITY: signed comparison handles 32-bit timestamp wraparound safely */
	if (now_ms != 0 && (int32_t)(found->valid_until_ms - now_ms) <= 0) {
		k_mutex_unlock(&cache_mutex);
		return -ENOENT;
	}

	/* Mark as recently used. */
	size_t idx = found - route_cache;
	route_access_order[idx] = ++access_counter;

	if (route != NULL) {
		*route = *found;
	}

	k_mutex_unlock(&cache_mutex);
	return 0;
}

void lichen_loadng_cache_remove(const uint8_t destination[16])
{
	if (destination == NULL) {
		return;
	}

	k_mutex_lock(&cache_mutex, K_FOREVER);

	struct lichen_loadng_route *found = find_route_locked(destination);
	if (found != NULL) {
		found->active = false;
	}

	k_mutex_unlock(&cache_mutex);
}

int lichen_loadng_cache_remove_via(const uint8_t next_hop[16])
{
	int removed = 0;

	if (next_hop == NULL) {
		return 0;
	}

	k_mutex_lock(&cache_mutex, K_FOREVER);

	for (size_t i = 0; i < ARRAY_SIZE(route_cache); i++) {
		if (route_cache[i].active &&
		    memcmp(route_cache[i].next_hop, next_hop, 16) == 0) {
			route_cache[i].active = false;
			removed++;
		}
	}

	k_mutex_unlock(&cache_mutex);
	return removed;
}

int lichen_loadng_cache_refresh(const uint8_t destination[16], uint32_t now_ms)
{
	if (destination == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&cache_mutex, K_FOREVER);

	struct lichen_loadng_route *found = find_route_locked(destination);
	if (found == NULL) {
		k_mutex_unlock(&cache_mutex);
		return -ENOENT;
	}

	found->valid_until_ms = now_ms + LICHEN_LOADNG_ROUTE_TIMEOUT_MS;
	size_t idx = found - route_cache;
	route_access_order[idx] = ++access_counter;

	k_mutex_unlock(&cache_mutex);
	return 0;
}

int lichen_loadng_cache_expire(uint32_t now_ms)
{
	int expired = 0;

	k_mutex_lock(&cache_mutex, K_FOREVER);

	for (size_t i = 0; i < ARRAY_SIZE(route_cache); i++) {
		/* SECURITY: signed comparison handles 32-bit timestamp wraparound safely */
		if (route_cache[i].active &&
		    (int32_t)(route_cache[i].valid_until_ms - now_ms) <= 0) {
			route_cache[i].active = false;
			route_access_order[i] = 0;
			expired++;
		}
	}

	k_mutex_unlock(&cache_mutex);
	return expired;
}

size_t lichen_loadng_cache_count(void)
{
	size_t count = 0;

	k_mutex_lock(&cache_mutex, K_FOREVER);

	for (size_t i = 0; i < ARRAY_SIZE(route_cache); i++) {
		if (route_cache[i].active) {
			count++;
		}
	}

	k_mutex_unlock(&cache_mutex);
	return count;
}

/*
 * Seen RREQ table for duplicate suppression.
 */

void lichen_loadng_seen_init(void)
{
	k_mutex_lock(&seen_mutex, K_FOREVER);
	memset(seen_table, 0, sizeof(seen_table));
	atomic_set(&prune_countdown, PRUNE_INTERVAL);
	k_mutex_unlock(&seen_mutex);
}

static bool rreq_matches_seen(const struct lichen_loadng_rreq *rreq,
			      const struct lichen_loadng_seen_rreq *seen)
{
	return seen->active &&
	       seen->seq_num == rreq->seq_num &&
	       memcmp(seen->originator, rreq->originator, 16) == 0 &&
	       memcmp(seen->destination, rreq->destination, 16) == 0;
}

static void prune_seen_locked(uint32_t now_ms)
{
	for (size_t i = 0; i < ARRAY_SIZE(seen_table); i++) {
		if (seen_table[i].active) {
			int32_t elapsed = (int32_t)(now_ms - seen_table[i].seen_at_ms);
			/* SECURITY: signed comparison handles future timestamps safely */
			if (elapsed >= (int32_t)LICHEN_LOADNG_SUPPRESS_WINDOW_MS) {
				seen_table[i].active = false;
			}
		}
	}
}

bool lichen_loadng_seen_check_and_mark(const struct lichen_loadng_rreq *rreq,
				       uint32_t now_ms)
{
	if (rreq == NULL) {
		return true; /* Suppress invalid input. */
	}

	k_mutex_lock(&seen_mutex, K_FOREVER);

	if (atomic_dec(&prune_countdown) <= 1) {
		prune_seen_locked(now_ms);
		atomic_set(&prune_countdown, PRUNE_INTERVAL);
	}

	/* Check if already seen. */
	for (size_t i = 0; i < ARRAY_SIZE(seen_table); i++) {
		if (rreq_matches_seen(rreq, &seen_table[i])) {
			/* SECURITY: signed comparison handles future timestamps safely */
			int32_t elapsed = (int32_t)(now_ms - seen_table[i].seen_at_ms);
			if (elapsed >= 0 && elapsed < (int32_t)LICHEN_LOADNG_SUPPRESS_WINDOW_MS) {
				k_mutex_unlock(&seen_mutex);
				return true; /* Suppress duplicate. */
			}
		}
	}

	/* Find a free or oldest slot. */
	size_t slot = 0;
	int32_t oldest_age = -1; /* No entry found yet */
	for (size_t i = 0; i < ARRAY_SIZE(seen_table); i++) {
		if (!seen_table[i].active) {
			slot = i;
			break;
		}
		/* SECURITY: signed comparison handles future timestamps safely */
		int32_t age = (int32_t)(now_ms - seen_table[i].seen_at_ms);
		if (age > oldest_age) {
			oldest_age = age;
			slot = i;
		}
	}

	/* Mark as seen. */
	seen_table[slot].active = true;
	memcpy(seen_table[slot].originator, rreq->originator, 16);
	memcpy(seen_table[slot].destination, rreq->destination, 16);
	seen_table[slot].seq_num = rreq->seq_num;
	seen_table[slot].seen_at_ms = now_ms;

	k_mutex_unlock(&seen_mutex);
	return false; /* Not suppressed, newly marked. */
}

void lichen_loadng_seen_prune(uint32_t now_ms)
{
	k_mutex_lock(&seen_mutex, K_FOREVER);
	prune_seen_locked(now_ms);
	atomic_set(&prune_countdown, PRUNE_INTERVAL);
	k_mutex_unlock(&seen_mutex);
}

/*
 * Route discovery state machine.
 */

int lichen_loadng_discovery_start(struct lichen_loadng_discovery *discovery,
				  const uint8_t originator[16],
				  const uint8_t destination[16],
				  uint16_t seq_num, uint32_t now_ms)
{
	if (discovery == NULL || originator == NULL || destination == NULL) {
		return -EINVAL;
	}

	memcpy(discovery->originator, originator, 16);
	memcpy(discovery->destination, destination, 16);
	discovery->seq_num = seq_num;
	discovery->ring_index = 0;
	discovery->state = LICHEN_LOADNG_DISCOVERY_SEARCHING;
	discovery->timeout_ms = now_ms + LICHEN_LOADNG_RREQ_WAIT_TIME_MS;

	return 0;
}

int lichen_loadng_discovery_get_rreq(const struct lichen_loadng_discovery *discovery,
				     struct lichen_loadng_rreq *rreq)
{
	if (discovery == NULL || rreq == NULL) {
		return -EINVAL;
	}
	if (discovery->state != LICHEN_LOADNG_DISCOVERY_SEARCHING) {
		return -EINVAL;
	}

	memset(rreq, 0, sizeof(*rreq));
	memcpy(rreq->originator, discovery->originator, 16);
	memcpy(rreq->destination, discovery->destination, 16);
	rreq->seq_num = discovery->seq_num;
	rreq->hop_limit = 0;
	rreq->flags = 0;

	return 0;
}

int lichen_loadng_discovery_advance(struct lichen_loadng_discovery *discovery,
				    uint32_t now_ms)
{
	if (discovery == NULL) {
		return -EINVAL;
	}
	if (discovery->state != LICHEN_LOADNG_DISCOVERY_SEARCHING) {
		return -EINVAL;
	}

	discovery->ring_index++;
	if (discovery->ring_index >= LICHEN_LOADNG_EXPANDING_RING_COUNT) {
		discovery->state = LICHEN_LOADNG_DISCOVERY_FAILED;
		return -ERANGE;
	}

	discovery->timeout_ms = now_ms + LICHEN_LOADNG_RREQ_WAIT_TIME_MS;
	return 0;
}

bool lichen_loadng_discovery_receive_rrep(struct lichen_loadng_discovery *discovery,
					  const struct lichen_loadng_rrep *rrep)
{
	if (discovery == NULL || rrep == NULL) {
		return false;
	}
	if (discovery->state != LICHEN_LOADNG_DISCOVERY_SEARCHING) {
		return false;
	}

	/* RREP originator must be our sought destination. */
	/* RREP destination must be us. */
	/* Sequence numbers must match. */
	if (memcmp(rrep->originator, discovery->destination, 16) != 0 ||
	    memcmp(rrep->destination, discovery->originator, 16) != 0 ||
	    rrep->seq_num != discovery->seq_num) {
		return false;
	}

	discovery->state = LICHEN_LOADNG_DISCOVERY_REPLIED;
	return true;
}

/*
 * RREQ/RREP processing.
 */

int lichen_loadng_process_rreq(const uint8_t our_addr[16],
			       const struct lichen_loadng_rreq *rreq,
			       const uint8_t from_neighbor[16],
			       uint32_t now_ms,
			       struct lichen_loadng_rreq_result *result)
{
	if (our_addr == NULL || rreq == NULL || from_neighbor == NULL ||
	    result == NULL) {
		return -EINVAL;
	}

	memset(result, 0, sizeof(*result));

	/* Drop if this is our own RREQ echoing back. */
	if (memcmp(rreq->originator, our_addr, 16) == 0) {
		result->suppressed = true;
		return 0;
	}

	/* Duplicate suppression. */
	if (lichen_loadng_seen_check_and_mark(rreq, now_ms)) {
		result->suppressed = true;
		return 0;
	}

	struct lichen_loadng_route reverse = {
		.hop_count = rreq->hop_limit + 1,
		.metric = rreq->hop_limit + 1,
		.seq_num = rreq->seq_num,
		.valid_until_ms = now_ms + LICHEN_LOADNG_ROUTE_TIMEOUT_MS,
		.active = true,
	};
	memcpy(reverse.destination, rreq->originator, 16);
	memcpy(reverse.next_hop, from_neighbor, 16);
	(void)lichen_loadng_cache_add(&reverse);

	/* Are we the destination? Generate RREP. */
	if (memcmp(rreq->destination, our_addr, 16) == 0) {
		result->has_reply = true;
		memcpy(result->reply.originator, our_addr, 16);
		memcpy(result->reply.destination, rreq->originator, 16);
		result->reply.seq_num = rreq->seq_num;
		result->reply.hop_count = 0;
		result->reply.flags = 0;
		memcpy(result->reply_next_hop, from_neighbor, 16);
		return 0;
	}

	if (rreq->hop_limit < 15) {
		result->has_forward = true;
		result->forward = *rreq;
		result->forward.hop_limit = rreq->hop_limit + 1;
	}

	return 0;
}

int lichen_loadng_process_rrep(const uint8_t our_addr[16],
			       const struct lichen_loadng_rrep *rrep,
			       const uint8_t from_neighbor[16],
			       uint32_t now_ms,
			       struct lichen_loadng_rrep_result *result)
{
	if (our_addr == NULL || rrep == NULL || from_neighbor == NULL ||
	    result == NULL) {
		return -EINVAL;
	}

	memset(result, 0, sizeof(*result));

	uint8_t install_hops = (uint8_t)MIN(rrep->hop_count + 1, 255);

	/* Install forward route toward the sought node (RREP originator). */
	struct lichen_loadng_route forward = {
		.hop_count = install_hops,
		.metric = install_hops,
		.seq_num = rrep->seq_num,
		.valid_until_ms = now_ms + LICHEN_LOADNG_ROUTE_TIMEOUT_MS,
		.active = true,
	};
	memcpy(forward.destination, rrep->originator, 16);
	memcpy(forward.next_hop, from_neighbor, 16);
	(void)lichen_loadng_cache_add(&forward);

	/* Are we the RREP destination (original requester)? */
	if (memcmp(rrep->destination, our_addr, 16) == 0) {
		result->delivered = true;
		return 0;
	}

	/* Forward along the reverse route. */
	struct lichen_loadng_route reverse_route;
	int ret = lichen_loadng_cache_lookup(rrep->destination, now_ms, &reverse_route);
	if (ret < 0) {
		result->dropped = true;
		return 0;
	}

	result->has_forward = true;
	result->forward = *rrep;
	result->forward.hop_count = install_hops;
	memcpy(result->forward_next_hop, reverse_route.next_hop, 16);

	return 0;
}

/*
 * Reset all state.
 */

void lichen_loadng_reset(void)
{
	lichen_loadng_cache_init();
	lichen_loadng_seen_init();
}
