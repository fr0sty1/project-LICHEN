/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file router.c
 * @brief Unified hybrid routing decision engine (spec section 7.2)
 */

#include <lichen/routing/router.h>
#include <zephyr/sys/atomic.h>

#include <errno.h>
#include <string.h>

/* Link-local prefix: fe80::/10 - inline check in is_link_local() */
#define LINK_LOCAL_PREFIX_LEN 10

/* ULA prefix: fd00::/8 - inline check in is_ula() */
#define ULA_PREFIX_LEN 8

/**
 * Check if an IPv6 address matches a prefix.
 */
static bool addr_in_prefix(const uint8_t addr[16],
			   const uint8_t *prefix,
			   size_t prefix_len)
{
	size_t full_bytes = prefix_len / 8;
	size_t remaining_bits = prefix_len % 8;

	/* Compare full bytes */
	if (memcmp(addr, prefix, full_bytes) != 0) {
		return false;
	}

	/* Compare remaining bits if any */
	if (remaining_bits > 0) {
		uint8_t mask = (uint8_t)(0xFF << (8 - remaining_bits));
		if ((addr[full_bytes] & mask) != (prefix[full_bytes] & mask)) {
			return false;
		}
	}

	return true;
}

/**
 * Check if address is link-local (fe80::/10).
 */
static bool is_link_local(const uint8_t addr[16])
{
	/* fe80::/10 means first 10 bits must be 1111111010 */
	return (addr[0] == 0xfe) && ((addr[1] & 0xc0) == 0x80);
}

/**
 * Check if address is ULA (fd00::/8).
 */
static bool is_ula(const uint8_t addr[16])
{
	return addr[0] == 0xfd;
}

/**
 * Extract IID from IPv6 address (last 8 bytes).
 */
static void extract_iid(const uint8_t addr[16], uint8_t iid[8])
{
	memcpy(iid, &addr[8], 8);
}

int lichen_router_init(struct lichen_router *router,
		       const uint8_t node_address[16])
{
	if (router == NULL || node_address == NULL) {
		return -EINVAL;
	}

	memset(router, 0, sizeof(*router));
	memcpy(router->node_address, node_address, 16);
	extract_iid(node_address, router->node_iid);
	lichen_gradient_table_init(&router->gradient_table);

	return 0;
}

void lichen_router_set_rpl(struct lichen_router *router,
			   const struct lichen_rpl_accessor *accessor)
{
	if (router == NULL) {
		return;
	}
	if (accessor != NULL) {
		router->rpl = *accessor;
	} else {
		memset(&router->rpl, 0, sizeof(router->rpl));
	}
}

void lichen_router_set_loadng(struct lichen_router *router,
			      const struct lichen_loadng_accessor *accessor)
{
	if (router == NULL) {
		return;
	}
	if (accessor != NULL) {
		router->loadng = *accessor;
	} else {
		memset(&router->loadng, 0, sizeof(router->loadng));
	}
}

enum lichen_addr_class lichen_router_classify(const struct lichen_router *router,
					      const uint8_t dst_addr[16])
{
	if (router == NULL || dst_addr == NULL) {
		return LICHEN_ADDR_EXTERNAL;
	}

	if (is_link_local(dst_addr)) {
		return LICHEN_ADDR_LINK_LOCAL;
	}

	if (is_ula(dst_addr) || dst_addr[0] == 0x02) {
		return LICHEN_ADDR_MESH_LOCAL;
	}

	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_MESH_PREFIXES; i++) {
		const struct lichen_mesh_prefix *p = &router->mesh_prefixes[i];
		if (!p->valid) {
			continue;
		}
		if (addr_in_prefix(dst_addr, p->prefix, p->prefix_len)) {
			return LICHEN_ADDR_MESH_LOCAL;
		}
	}

	return LICHEN_ADDR_EXTERNAL;
}

/**
 * Route to a link-local address (direct neighbor).
 * The destination IS the next hop.
 */
static int route_link_local(const uint8_t dst_addr[16],
			    struct lichen_route_result *result)
{
	result->decision = LICHEN_ROUTE_FORWARD;
	memcpy(result->next_hop, dst_addr, 16);
	return 0;
}

/**
 * Route to a mesh-local address (ULA or mesh GUA).
 * Look up gradient table, initiate LOADng discovery if needed.
 */
static int route_mesh_local(struct lichen_router *router,
			    const uint8_t dst_iid[8],
			    uint32_t now_ms,
			    struct lichen_route_result *result)
{
	/* Look up in gradient table */
	struct lichen_gradient_entry *entry =
		lichen_gradient_lookup(&router->gradient_table, dst_iid, now_ms);

	if (entry != NULL) {
		result->decision = LICHEN_ROUTE_FORWARD;
		memcpy(result->next_hop, entry->next_hop, 16);
		return 0;
	}

	/* No gradient - try LOADng discovery if configured */
	if (router->loadng.discover != NULL) {
		int ret = router->loadng.discover(router->loadng.user_data,
						  dst_iid);
		if (ret == 0) {
			result->decision = LICHEN_ROUTE_QUEUE;
			return 0;
		}
	}

	/* No LOADng - try GPSR fallback if we have destination coords */
	/* ponytail: GPSR lookup requires coords in gradient entry or out-of-band */

	/* Cannot route */
	result->decision = LICHEN_ROUTE_DROP;
	return 0;
}

/**
 * Route to an external address (via RPL border router).
 */
static int route_external(struct lichen_router *router,
			  struct lichen_route_result *result)
{
	/* Check if RPL is configured */
	if (router->rpl.is_joined == NULL ||
	    router->rpl.get_preferred_parent == NULL) {
		result->decision = LICHEN_ROUTE_DROP;
		return 0;
	}

	/* Check if joined to DODAG */
	if (!router->rpl.is_joined(router->rpl.user_data)) {
		result->decision = LICHEN_ROUTE_DROP;
		return 0;
	}

	/* Get preferred parent */
	int ret = router->rpl.get_preferred_parent(router->rpl.user_data,
						   result->next_hop);
	if (ret != 0) {
		result->decision = LICHEN_ROUTE_DROP;
		return 0;
	}

	result->decision = LICHEN_ROUTE_FORWARD;
	return 0;
}

int lichen_router_route(struct lichen_router *router,
			const uint8_t dst_addr[16],
			const uint8_t dst_iid[8],
			uint32_t now_ms,
			struct lichen_route_result *result)
{
	if (router == NULL || dst_addr == NULL || dst_iid == NULL ||
	    result == NULL) {
		return -EINVAL;
	}

	memset(result, 0, sizeof(*result));

	/* Check if packet is for this node */
	if (memcmp(dst_addr, router->node_address, 16) == 0) {
		result->decision = LICHEN_ROUTE_DELIVER_LOCAL;
		return 0;
	}

	enum lichen_addr_class addr_class = lichen_router_classify(router, dst_addr);

	switch (addr_class) {
	case LICHEN_ADDR_LINK_LOCAL:
		return route_link_local(dst_addr, result);

	case LICHEN_ADDR_MESH_LOCAL:
		return route_mesh_local(router, dst_iid, now_ms, result);

	case LICHEN_ADDR_YGGDRASIL:
	case LICHEN_ADDR_EXTERNAL:
		return route_external(router, result);
	default:
		result->decision = LICHEN_ROUTE_DROP;
		return 0;
	}
}

int lichen_router_queue_pending(struct lichen_router *router,
				const uint8_t dst_iid[8],
				const uint8_t *packet_data,
				size_t packet_len,
				uint32_t now_ms)
{
	if (router == NULL || dst_iid == NULL || packet_data == NULL) {
		return -EINVAL;
	}

	/* SECURITY: Reject packets larger than our static buffer to prevent
	 * truncation attacks. Caller must use smaller packets or increase
	 * CONFIG_LICHEN_ROUTER_MAX_PENDING_PACKET_SIZE. */
	if (packet_len > CONFIG_LICHEN_ROUTER_MAX_PENDING_PACKET_SIZE) {
		return -EMSGSIZE;
	}

	/* Count existing packets for this destination */
	int dest_count = 0;
	struct lichen_pending_packet *oldest_for_dest = NULL;

	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PENDING; i++) {
		struct lichen_pending_packet *p = &router->pending[i];
		if (!p->valid) {
			continue;
		}
		if (memcmp(p->destination_iid, dst_iid, 8) == 0) {
			dest_count++;
			if (oldest_for_dest == NULL ||
			    (int32_t)(p->queued_at_ms - oldest_for_dest->queued_at_ms) < 0) {
				oldest_for_dest = p;
			}
		}
	}

	/* If at per-dest limit, drop oldest for this dest */
	if (dest_count >= CONFIG_LICHEN_ROUTER_MAX_PENDING_PER_DEST) {
		if (oldest_for_dest != NULL) {
			oldest_for_dest->valid = false;
			router->pending_count--;
		}
	}

	/* Find free slot or evict oldest overall */
	struct lichen_pending_packet *slot = NULL;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PENDING; i++) {
		if (!router->pending[i].valid) {
			slot = &router->pending[i];
			break;
		}
	}

	if (slot == NULL) {
		/* Table full - evict oldest */
		struct lichen_pending_packet *oldest = NULL;
		for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PENDING; i++) {
			struct lichen_pending_packet *p = &router->pending[i];
			if (!p->valid) {
				continue;
			}
			if (oldest == NULL ||
			    (int32_t)(p->queued_at_ms - oldest->queued_at_ms) < 0) {
				oldest = p;
			}
		}
		slot = oldest;
		if (slot != NULL) {
			router->pending_count--;
		}
	}

	if (slot == NULL) {
		return -ENOMEM;
	}

	memset(slot, 0, sizeof(*slot));
	memcpy(slot->destination_iid, dst_iid, 8);
	/* SECURITY: Copy data into static buffer to prevent use-after-free
	 * if caller frees their buffer before packet is processed. */
	memcpy(slot->packet_data, packet_data, packet_len);
	slot->packet_len = packet_len;
	slot->queued_at_ms = now_ms;
	slot->valid = true;
	router->pending_count++;

	return 0;
}

int lichen_router_get_pending(struct lichen_router *router,
			      const uint8_t dst_iid[8],
			      struct lichen_pending_packet **out_packets,
			      size_t max_packets)
{
	if (router == NULL || dst_iid == NULL || out_packets == NULL) {
		return 0;
	}

	int count = 0;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PENDING && count < (int)max_packets; i++) {
		struct lichen_pending_packet *p = &router->pending[i];
		if (p->valid && memcmp(p->destination_iid, dst_iid, 8) == 0) {
			out_packets[count++] = p;
		}
	}
	return count;
}

int lichen_router_clear_pending(struct lichen_router *router,
				const uint8_t dst_iid[8])
{
	if (router == NULL || dst_iid == NULL) {
		return 0;
	}

	int cleared = 0;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PENDING; i++) {
		struct lichen_pending_packet *p = &router->pending[i];
		if (p->valid && memcmp(p->destination_iid, dst_iid, 8) == 0) {
			p->valid = false;
			cleared++;
		}
	}
	if ((size_t)cleared > router->pending_count) {
		router->pending_count = 0;
	} else {
		router->pending_count -= (size_t)cleared;
	}
	return cleared;
}

int lichen_router_expire_pending(struct lichen_router *router, uint32_t now_ms)
{
	if (router == NULL) {
		return 0;
	}

	int expired = 0;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PENDING; i++) {
		struct lichen_pending_packet *p = &router->pending[i];
		if (!p->valid) {
			continue;
		}
		uint32_t age = now_ms - p->queued_at_ms;
		if (age > CONFIG_LICHEN_ROUTER_PENDING_TIMEOUT_MS) {
			p->valid = false;
			expired++;
		}
	}
	if ((size_t)expired > router->pending_count) {
		router->pending_count = 0;
	} else {
		router->pending_count -= (size_t)expired;
	}
	return expired;
}

int lichen_router_add_mesh_prefix(struct lichen_router *router,
				  const uint8_t prefix[16],
				  uint8_t prefix_len)
{
	if (router == NULL || prefix == NULL || prefix_len > 128) {
		return -EINVAL;
	}

	/* Check if already present */
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_MESH_PREFIXES; i++) {
		struct lichen_mesh_prefix *p = &router->mesh_prefixes[i];
		if (p->valid && p->prefix_len == prefix_len &&
		    memcmp(p->prefix, prefix, 16) == 0) {
			return 0;  /* Already exists */
		}
	}

	/* Find free slot */
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_MESH_PREFIXES; i++) {
		struct lichen_mesh_prefix *p = &router->mesh_prefixes[i];
		if (!p->valid) {
			memcpy(p->prefix, prefix, 16);
			p->prefix_len = prefix_len;
			p->valid = true;
			return 0;
		}
	}

	return -ENOMEM;
}

void lichen_router_remove_mesh_prefix(struct lichen_router *router,
				      const uint8_t prefix[16],
				      uint8_t prefix_len)
{
	if (router == NULL || prefix == NULL) {
		return;
	}

	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_MESH_PREFIXES; i++) {
		struct lichen_mesh_prefix *p = &router->mesh_prefixes[i];
		if (p->valid && p->prefix_len == prefix_len &&
		    memcmp(p->prefix, prefix, 16) == 0) {
			p->valid = false;
			return;
		}
	}
}

int lichen_router_on_route_discovered(struct lichen_router *router,
				      const uint8_t dst_iid[8],
				      const uint8_t next_hop[16],
				      uint32_t now_ms)
{
	if (router == NULL || dst_iid == NULL || next_hop == NULL) {
		return 0;
	}

	/* Install gradient entry */
	struct lichen_gradient_entry entry = {
		.hop_count = 1,  /* LOADng discovery gives hop count in RREP */
		.seq_num = 0,
		.source = LICHEN_GRADIENT_RREP,
		.expires_ms = now_ms + CONFIG_LICHEN_ROUTING_GRADIENT_TIMEOUT_MS,
		.last_used_ms = now_ms,
		.coords_valid = false,
		.valid = true,
	};
	memcpy(entry.destination_iid, dst_iid, 8);
	memcpy(entry.next_hop, next_hop, 16);

	lichen_gradient_update(&router->gradient_table, &entry, now_ms);

	/* Count pending packets (caller must retrieve and forward them, then
	 * call lichen_router_clear_pending() explicitly) */
	int count = 0;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PENDING; i++) {
		struct lichen_pending_packet *p = &router->pending[i];
		if (p->valid && memcmp(p->destination_iid, dst_iid, 8) == 0) {
			count++;
		}
	}
	return count;
}

void lichen_router_set_coords(struct lichen_router *router,
			      int32_t lat_e7, int32_t lon_e7)
{
	if (router == NULL) {
		return;
	}
	router->node_lat_e7 = lat_e7;
	router->node_lon_e7 = lon_e7;
	router->node_coords_valid = true;
}

/**
 * Validate geographic coordinates in e7 format.
 * Returns false for null island (0,0), out-of-range values.
 */
static bool is_valid_coords_e7(int32_t lat_e7, int32_t lon_e7)
{
	/* Reject null island sentinel (almost always invalid GPS data) */
	if (lat_e7 == 0 && lon_e7 == 0) {
		return false;
	}

	/* Valid ranges: lat [-90, 90], lon [-180, 180] in e7 */
	const int32_t LAT_MAX_E7 = 900000000;   /* 90 degrees */
	const int32_t LON_MAX_E7 = 1800000000;  /* 180 degrees */

	if (lat_e7 < -LAT_MAX_E7 || lat_e7 > LAT_MAX_E7) {
		return false;
	}
	if (lon_e7 < -LON_MAX_E7 || lon_e7 > LON_MAX_E7) {
		return false;
	}

	return true;
}

/**
 * Haversine distance squared (avoids sqrt for comparison).
 * Input: coordinates in 1e-7 degrees.
 * Returns: distance in meters (approximate, using law of cosines for simplicity
 *          at mesh scales where haversine vs law-of-cosines error is negligible).
 *
 * For mesh-scale distances (<100km), spherical law of cosines is adequate
 * and avoids expensive trig functions. Full haversine is needed only for
 * intercontinental distances where the small-angle approximation breaks down.
 */
static uint64_t distance_approx_m(int32_t lat1_e7, int32_t lon1_e7,
				  int32_t lat2_e7, int32_t lon2_e7)
{
	/*
	 * Approximate 1 degree = 111km at equator.
	 * At most latitudes in practice, this is within ~0.5% error for
	 * distances under 100km, which is far more than LoRa mesh range.
	 *
	 * Convert e7 to microradians, then use Pythagorean approximation:
	 *   d = sqrt((dlat * 111km)^2 + (dlon * 111km * cos(lat))^2)
	 *
	 * For integer math, we compute d^2 in meters^2 without sqrt,
	 * since we only need relative comparison.
	 */

	/* Delta in e7 degrees */
	int64_t dlat_e7 = (int64_t)lat2_e7 - (int64_t)lat1_e7;
	int64_t dlon_e7 = (int64_t)lon2_e7 - (int64_t)lon1_e7;

	/*
	 * SECURITY: Scale down to e4 degrees to prevent integer overflow.
	 * Without this, dlat_e7 * 111 can reach ~2e11, and squaring that
	 * (~4e22) overflows both int64 and uint64, causing UB.
	 *
	 * Max dlat_e4 = 1.8e6, * 111 = ~2e8, squared = ~4e16, fits uint64.
	 */
	int64_t dlat_e4 = dlat_e7 / 1000;
	int64_t dlon_e4 = dlon_e7 / 1000;

	/* Convert to meters * 10 (1 degree ~= 111km, in e4: e4 * 111 / 10) */
	int64_t dlat_m10 = dlat_e4 * 111;
	int64_t dlon_m10 = dlon_e4 * 111;

	/* Approximate cos(lat) as 1 - lat^2/2 for small lat, or use lookup.
	 * For simplicity at mesh scales, just use cos(45deg) = 0.707 as average.
	 * This gives ~30% error at equator/poles, but GPSR is best-effort anyway. */
	dlon_m10 = (dlon_m10 * 707) / 1000;  /* cos(45 deg) approximation */

	/* SECURITY: Take absolute value and cast to uint64 BEFORE squaring
	 * to avoid signed overflow undefined behavior. */
	uint64_t dlat_abs = (dlat_m10 >= 0) ? (uint64_t)dlat_m10
					    : (uint64_t)(-dlat_m10);
	uint64_t dlon_abs = (dlon_m10 >= 0) ? (uint64_t)dlon_m10
					    : (uint64_t)(-dlon_m10);

	uint64_t dist_sq = (dlat_abs * dlat_abs) + (dlon_abs * dlon_abs);

	/* Return squared distance for comparison (exact units don't matter) */
	return dist_sq;
}

int lichen_router_gpsr_forward(struct lichen_router *router,
			       int32_t dst_lat_e7, int32_t dst_lon_e7,
			       uint8_t out_next_hop[16])
{
	if (router == NULL || out_next_hop == NULL) {
		return -EINVAL;
	}

	/* Validate destination coordinates */
	if (!is_valid_coords_e7(dst_lat_e7, dst_lon_e7)) {
		return -EINVAL;
	}

	/* Need our own coordinates */
	if (!router->node_coords_valid) {
		return -ENOENT;
	}
	if (!is_valid_coords_e7(router->node_lat_e7, router->node_lon_e7)) {
		return -ENOENT;
	}

	/* Calculate our distance to destination */
	uint64_t my_dist = distance_approx_m(router->node_lat_e7, router->node_lon_e7,
					     dst_lat_e7, dst_lon_e7);

	/* Search gradient table for neighbors with coords closer to destination */
	struct lichen_gradient_entry *best = NULL;
	uint64_t best_dist = my_dist;  /* Must make progress */

	for (size_t i = 0; i < CONFIG_LICHEN_ROUTING_GRADIENT_MAX_ENTRIES; i++) {
		struct lichen_gradient_entry *entry = &router->gradient_table.entries[i];

		if (!entry->valid || !entry->coords_valid) {
			continue;
		}

		/* Validate neighbor coordinates */
		if (!is_valid_coords_e7(entry->lat_e7, entry->lon_e7)) {
			continue;
		}

		uint64_t d = distance_approx_m(entry->lat_e7, entry->lon_e7,
					       dst_lat_e7, dst_lon_e7);
		if (d < best_dist) {
			best_dist = d;
			best = entry;
		}
	}

	if (best == NULL) {
		/* No progress possible (local minimum) */
		return -ENOENT;
	}

	memcpy(out_next_hop, best->next_hop, 16);
	return 0;
}

#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0

int lichen_router_dtn_buffer(struct lichen_router *router,
			     const uint8_t dst_iid[8],
			     const uint8_t *data,
			     size_t len,
			     uint32_t expiry_unix,
			     uint32_t now_ms)
{
	if (router == NULL || dst_iid == NULL || data == NULL) {
		return -EINVAL;
	}

	/* SECURITY: Reject messages larger than our static buffer to prevent
	 * truncation attacks. Caller must use smaller messages or increase
	 * CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGE_SIZE. */
	if (len > CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGE_SIZE) {
		return -EMSGSIZE;
	}

	/* Find free slot or evict oldest */
	struct lichen_router_dtn_message *slot = NULL;
	struct lichen_router_dtn_message *oldest = NULL;

	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGES; i++) {
		struct lichen_router_dtn_message *m = &router->dtn_buffer[i];
		if (!m->valid) {
			slot = m;
			break;
		}
		if (oldest == NULL ||
		    (int32_t)(m->buffered_at_ms - oldest->buffered_at_ms) < 0) {
			oldest = m;
		}
	}

	if (slot == NULL) {
		/* Evict oldest if buffer full */
		if (oldest != NULL) {
			router->dtn_buffer_bytes -= oldest->len;
			slot = oldest;
		} else {
			return -ENOMEM;
		}
	}

	memset(slot, 0, sizeof(*slot));
	memcpy(slot->destination_iid, dst_iid, 8);
	/* SECURITY: Copy data into static buffer to prevent use-after-free
	 * if caller frees their buffer before message is delivered. */
	memcpy(slot->data, data, len);
	slot->len = len;
	slot->expiry_unix = expiry_unix;
	slot->buffered_at_ms = now_ms;
	slot->valid = true;
	router->dtn_buffer_bytes += len;

	return 0;
}

int lichen_router_dtn_get_pending_iids(struct lichen_router *router,
				       uint8_t (*out_iids)[8],
				       size_t max_iids)
{
	if (router == NULL || out_iids == NULL) {
		return 0;
	}

	size_t count = 0;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGES && count < max_iids; i++) {
		struct lichen_router_dtn_message *m = &router->dtn_buffer[i];
		if (!m->valid) {
			continue;
		}

		/* Check if this IID already in output */
		bool found = false;
		for (size_t j = 0; j < count; j++) {
			if (memcmp(out_iids[j], m->destination_iid, 8) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			memcpy(out_iids[count], m->destination_iid, 8);
			count++;
		}
	}
	return (int)count;
}

int lichen_router_dtn_retrieve(struct lichen_router *router,
			       const uint8_t dst_iid[8],
			       struct lichen_router_dtn_message **out_messages,
			       size_t max_messages)
{
	if (router == NULL || dst_iid == NULL || out_messages == NULL) {
		return 0;
	}

	int count = 0;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGES && count < (int)max_messages; i++) {
		struct lichen_router_dtn_message *m = &router->dtn_buffer[i];
		if (m->valid && memcmp(m->destination_iid, dst_iid, 8) == 0) {
			out_messages[count++] = m;
			/* Note: keep valid=true so the slot remains reserved while
			 * the caller uses the returned pointer. Caller must call
			 * lichen_router_dtn_release() when done. */
		}
	}
	return count;
}

void lichen_router_dtn_release(struct lichen_router *router,
			       struct lichen_router_dtn_message *msg)
{
	if (router == NULL || msg == NULL || !msg->valid) {
		return;
	}
	router->dtn_buffer_bytes -= msg->len;
	msg->valid = false;
}

int lichen_router_dtn_expire(struct lichen_router *router, uint32_t now_unix)
{
	if (router == NULL) {
		return 0;
	}

	int expired = 0;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGES; i++) {
		struct lichen_router_dtn_message *m = &router->dtn_buffer[i];
		if (!m->valid) {
			continue;
		}
		/* Use signed comparison for timestamp wraparound safety */
		if ((int32_t)(m->expiry_unix - now_unix) <= 0) {
			router->dtn_buffer_bytes -= m->len;
			m->valid = false;
			expired++;
		}
	}
	return expired;
}

#endif /* CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0 */

/* ========================================================================
 * Forwarding buffer with backpressure (spec appendix-bufferbloat)
 * ======================================================================== */

#if CONFIG_LICHEN_ROUTER_FORWARDING_BUFFER

/**
 * Find a source slot by IID.
 * @return Pointer to source slot, or NULL if not found.
 */
static struct lichen_fwd_source *fwd_find_source(
	struct lichen_router *router,
	const uint8_t source_iid[8])
{
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_FORWARDING_SOURCES; i++) {
		struct lichen_fwd_source *src = &router->fwd_sources[i];
		if (src->valid && memcmp(src->source_iid, source_iid, 8) == 0) {
			return src;
		}
	}
	return NULL;
}

/**
 * Find or allocate a source slot.
 * If no free slots, evicts the oldest (LRU) source.
 */
static struct lichen_fwd_source *fwd_get_or_alloc_source(
	struct lichen_router *router,
	const uint8_t source_iid[8],
	uint32_t now_ms)
{
	/* Check if source already exists */
	struct lichen_fwd_source *existing = fwd_find_source(router, source_iid);
	if (existing != NULL) {
		return existing;
	}

	/* Find free slot or oldest slot for eviction */
	struct lichen_fwd_source *slot = NULL;
	struct lichen_fwd_source *oldest = NULL;

	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_FORWARDING_SOURCES; i++) {
		struct lichen_fwd_source *src = &router->fwd_sources[i];
		if (!src->valid) {
			slot = src;
			break;
		}
		/* Track oldest for LRU eviction */
		if (oldest == NULL ||
		    (int32_t)(src->last_activity_ms - oldest->last_activity_ms) < 0) {
			oldest = src;
		}
	}

	if (slot == NULL) {
		/* Evict oldest source - drop all its packets */
		slot = oldest;
		if (slot != NULL) {
			for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE; i++) {
				if (slot->packets[i].valid) {
					slot->packets[i].valid = false;
					atomic_inc((atomic_t *)&router->fwd_stats.packets_dropped_full);
				}
			}
		}
	}

	if (slot == NULL) {
		return NULL;  /* Should not happen */
	}

	/* Initialize new source slot */
	memset(slot, 0, sizeof(*slot));
	memcpy(slot->source_iid, source_iid, 8);
	slot->last_activity_ms = now_ms;
	slot->valid = true;

	return slot;
}

bool lichen_router_fwd_can_accept(const struct lichen_router *router,
				  const uint8_t source_iid[8])
{
	if (router == NULL || source_iid == NULL) {
		return false;
	}

	/* Find source slot */
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_FORWARDING_SOURCES; i++) {
		const struct lichen_fwd_source *src = &router->fwd_sources[i];
		if (src->valid && memcmp(src->source_iid, source_iid, 8) == 0) {
			/* Check if source has room */
			return src->packet_count < CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE;
		}
	}

	/* Source not found - can accept (will allocate new slot) */
	return true;
}

int lichen_router_fwd_enqueue(struct lichen_router *router,
			      const uint8_t source_iid[8],
			      uint8_t *data,
			      size_t len,
			      uint32_t now_ms)
{
	if (router == NULL || source_iid == NULL || data == NULL) {
		return -EINVAL;
	}

	/* Get or allocate source slot */
	struct lichen_fwd_source *src = fwd_get_or_alloc_source(
		router, source_iid, now_ms);
	if (src == NULL) {
		return -ENOMEM;
	}

	/* SECURITY: Check per-source limit to prevent one chatty source from
	 * monopolizing relay capacity */
	if (src->packet_count >= CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE) {
		atomic_inc((atomic_t *)&router->fwd_stats.packets_dropped_full);
		atomic_inc((atomic_t *)&router->fwd_stats.nacks_sent);
		return -ENOBUFS;
	}

	/* Find free packet slot */
	struct lichen_fwd_packet *slot = NULL;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE; i++) {
		if (!src->packets[i].valid) {
			slot = &src->packets[i];
			break;
		}
	}

	if (slot == NULL) {
		/* Should not happen if packet_count is correct */
		return -ENOMEM;
	}

	/* Store packet */
	slot->data = data;
	slot->len = len;
	slot->enqueued_at_ms = now_ms;
	slot->valid = true;
	src->packet_count++;
	src->last_activity_ms = now_ms;
	atomic_inc((atomic_t *)&router->fwd_stats.packets_queued);

	return 0;
}

int lichen_router_fwd_dequeue(struct lichen_router *router,
			      uint8_t out_source_iid[8],
			      uint8_t **out_data,
			      size_t *out_len)
{
	if (router == NULL || out_source_iid == NULL ||
	    out_data == NULL || out_len == NULL) {
		return -EINVAL;
	}

	/* Find oldest packet across all sources (FIFO) */
	struct lichen_fwd_source *oldest_src = NULL;
	struct lichen_fwd_packet *oldest_pkt = NULL;

	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_FORWARDING_SOURCES; i++) {
		struct lichen_fwd_source *src = &router->fwd_sources[i];
		if (!src->valid) {
			continue;
		}

		for (size_t j = 0; j < CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE; j++) {
			struct lichen_fwd_packet *pkt = &src->packets[j];
			if (!pkt->valid) {
				continue;
			}

			if (oldest_pkt == NULL ||
			    (int32_t)(pkt->enqueued_at_ms - oldest_pkt->enqueued_at_ms) < 0) {
				oldest_src = src;
				oldest_pkt = pkt;
			}
		}
	}

	if (oldest_pkt == NULL) {
		return -ENOENT;
	}

	/* Return packet info */
	memcpy(out_source_iid, oldest_src->source_iid, 8);
	*out_data = oldest_pkt->data;
	*out_len = oldest_pkt->len;

	/* Remove from buffer */
	oldest_pkt->valid = false;
	oldest_src->packet_count--;
	atomic_inc((atomic_t *)&router->fwd_stats.packets_forwarded);

	/* Update activity timestamp */
	oldest_src->last_activity_ms = oldest_pkt->enqueued_at_ms;

	/* If source has no more packets, mark it invalid for reuse */
	if (oldest_src->packet_count == 0) {
		oldest_src->valid = false;
	}

	return 0;
}

int lichen_router_fwd_expire(struct lichen_router *router, uint32_t now_ms)
{
	if (router == NULL) {
		return 0;
	}

	int expired = 0;

	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_FORWARDING_SOURCES; i++) {
		struct lichen_fwd_source *src = &router->fwd_sources[i];
		if (!src->valid) {
			continue;
		}

		for (size_t j = 0; j < CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE; j++) {
			struct lichen_fwd_packet *pkt = &src->packets[j];
			if (!pkt->valid) {
				continue;
			}

			uint32_t age = now_ms - pkt->enqueued_at_ms;
			if (age > CONFIG_LICHEN_ROUTER_FORWARDING_DEADLINE_MS) {
				pkt->valid = false;
				src->packet_count--;
				atomic_inc((atomic_t *)&router->fwd_stats.packets_dropped_deadline);
				expired++;
			}
		}

		/* Clean up empty source slots */
		if (src->packet_count == 0) {
			src->valid = false;
		}
	}

	return expired;
}

const struct lichen_fwd_stats *lichen_router_fwd_stats(
	const struct lichen_router *router)
{
	if (router == NULL) {
		return NULL;
	}
	return &router->fwd_stats;
}

size_t lichen_router_fwd_count(const struct lichen_router *router)
{
	if (router == NULL) {
		return 0;
	}

	size_t count = 0;
	for (size_t i = 0; i < CONFIG_LICHEN_ROUTER_MAX_FORWARDING_SOURCES; i++) {
		const struct lichen_fwd_source *src = &router->fwd_sources[i];
		if (src->valid) {
			count += src->packet_count;
		}
	}
	return count;
}

#endif /* CONFIG_LICHEN_ROUTER_FORWARDING_BUFFER */
