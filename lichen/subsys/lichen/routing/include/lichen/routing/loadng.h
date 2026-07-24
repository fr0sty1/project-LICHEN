/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file loadng.h
 * @brief LOADng reactive route discovery (spec section 10, appendix B2)
 *
 * LOADng provides reactive peer-to-peer route discovery. Messages are ICMPv6
 * type 158, with the code selecting the message type: RREQ (0), RREP (1),
 * RERR (2).
 *
 * Wire format (spec 10.3/10.4):
 *   RREQ/RREP: flags(1) + hop_limit/count(1) + seq_num(2) + originator(16) + destination(16) = 36 bytes
 *   RERR: flags(1) + error_code(1) + unreachable(16) = 18 bytes
 *
 * This implementation provides:
 * - Message codecs (parse/serialize)
 * - Route cache with LRU eviction and timeout
 * - Expanding ring discovery state machine
 */

#ifndef LICHEN_ROUTING_LOADNG_H_
#define LICHEN_ROUTING_LOADNG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Nullability annotations for pointer safety */
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

/** ICMPv6 type for LOADng messages (spec B2.4). */
#define LICHEN_LOADNG_ICMPV6_TYPE 158U

/** ICMPv6 codes for LOADng messages. */
#define LICHEN_LOADNG_CODE_RREQ 0U
#define LICHEN_LOADNG_CODE_RREP 1U
#define LICHEN_LOADNG_CODE_RERR 2U
#define LICHEN_LOADNG_CODE_RACK 3U /* Reserved */

/** Initial hop limit for expanding ring search (spec B2.5). */
#define LICHEN_LOADNG_INITIAL_HOP_LIMIT 4U

/** Maximum hop limit (spec B2.1). */
#define LICHEN_LOADNG_MAX_HOP_LIMIT 15U

/** RREQ/RREP wire length (spec 10.3/10.4). */
#define LICHEN_LOADNG_RREQ_RREP_LEN 36U

/** RERR wire length (spec 10.6). */
#define LICHEN_LOADNG_RERR_LEN 18U

/** Route cache size (spec B2.2). */
#define LICHEN_LOADNG_ROUTE_CACHE_SIZE 32U

/** Route validity timeout in ms (spec B2.2). */
#define LICHEN_LOADNG_ROUTE_TIMEOUT_MS 300000U

/** Route refresh threshold in ms (spec B2.2). */
#define LICHEN_LOADNG_ROUTE_REFRESH_MS 60000U

/** Duplicate RREQ suppression window in ms (spec B2.6). */
#define LICHEN_LOADNG_SUPPRESS_WINDOW_MS 10000U

/** RREQ wait time before retry in ms (spec B2.1). */
#define LICHEN_LOADNG_RREQ_WAIT_TIME_MS 5000U

/** Maximum RREQ retries (spec B2.1). */
#define LICHEN_LOADNG_RREQ_RETRIES 3U

/** Half the sequence number space for RFC 1982 serial number arithmetic. */
#define LICHEN_LOADNG_SEQ_HALF 0x8000U

/** Expanding ring hop limits (spec B2.5): [4, 8, 15]. */
#define LICHEN_LOADNG_EXPANDING_RING_0 4U
#define LICHEN_LOADNG_EXPANDING_RING_1 8U
#define LICHEN_LOADNG_EXPANDING_RING_2 15U
#define LICHEN_LOADNG_EXPANDING_RING_COUNT 3U

/**
 * @brief Route Request (RREQ) - flooded toward a destination (spec 10.3).
 */
struct lichen_loadng_rreq {
	uint8_t originator[16];   /**< IPv6 address of RREQ originator */
	uint8_t destination[16];  /**< IPv6 address of destination being sought */
	uint16_t seq_num;         /**< Sequence number (network order on wire) */
	uint8_t hop_limit;        /**< Remaining hop limit */
	uint8_t flags;            /**< Reserved flags */
};

/**
 * @brief Route Reply (RREP) - unicast back along reverse path (spec 10.4).
 */
struct lichen_loadng_rrep {
	uint8_t originator[16];   /**< IPv6 address of sought destination */
	uint8_t destination[16];  /**< IPv6 address of RREQ originator */
	uint16_t seq_num;         /**< Sequence number from RREQ */
	uint8_t hop_count;        /**< Accumulated hop count */
	uint8_t flags;            /**< Reserved flags */
};

/**
 * @brief Route Error (RERR) - sent when a link fails (spec 10.6).
 */
struct lichen_loadng_rerr {
	uint8_t unreachable[16];  /**< IPv6 address that is no longer reachable */
	uint8_t error_code;       /**< Error code (0 = general failure) */
	uint8_t flags;            /**< Reserved flags */
};

/**
 * @brief Cached LOADng route entry.
 */
struct lichen_loadng_route {
	uint8_t destination[16];  /**< IPv6 destination address */
	uint8_t next_hop[16];     /**< Next hop IPv6 address */
	uint16_t seq_num;         /**< Sequence number of route */
	uint8_t hop_count;        /**< Hop count to destination */
	uint8_t metric;           /**< Route metric (hop count by default) */
	uint32_t valid_until_ms;  /**< Timestamp when route expires */
	bool active;              /**< Slot in use */
};

/**
 * @brief Route discovery state.
 */
enum lichen_loadng_discovery_state {
	LICHEN_LOADNG_DISCOVERY_IDLE = 0,
	LICHEN_LOADNG_DISCOVERY_SEARCHING,
	LICHEN_LOADNG_DISCOVERY_REPLIED,
	LICHEN_LOADNG_DISCOVERY_FAILED,
};

/**
 * @brief Active route discovery session.
 */
struct lichen_loadng_discovery {
	uint8_t originator[16];   /**< Our IPv6 address */
	uint8_t destination[16];  /**< Destination being sought */
	uint16_t seq_num;         /**< Sequence number for this discovery */
	uint8_t ring_index;       /**< Current expanding ring index (0-2) */
	enum lichen_loadng_discovery_state state;
	uint32_t timeout_ms;      /**< Timestamp when current ring expires */
};

/**
 * @brief Seen RREQ entry for duplicate suppression (spec B2.6).
 */
struct lichen_loadng_seen_rreq {
	uint8_t originator[16];
	uint8_t destination[16];
	uint16_t seq_num;
	uint32_t seen_at_ms;
	bool active;
};

/**
 * @brief Result of processing an RREQ.
 */
struct lichen_loadng_rreq_result {
	bool suppressed;                       /**< RREQ was duplicate or own echo */
	struct lichen_loadng_rrep reply;       /**< RREP to send (valid if has_reply) */
	uint8_t reply_next_hop[16];            /**< Next hop for RREP */
	bool has_reply;                        /**< True if reply should be sent */
	struct lichen_loadng_rreq forward;     /**< RREQ to forward (valid if has_forward) */
	bool has_forward;                      /**< True if RREQ should be rebroadcast */
};

/**
 * @brief Result of processing an RREP.
 */
struct lichen_loadng_rrep_result {
	bool delivered;                        /**< RREP reached its destination (us) */
	bool dropped;                          /**< No reverse route available */
	struct lichen_loadng_rrep forward;     /**< RREP to forward (valid if has_forward) */
	uint8_t forward_next_hop[16];          /**< Next hop for forwarded RREP */
	bool has_forward;                      /**< True if RREP should be forwarded */
};

/**
 * @brief Parse RREQ from ICMPv6 body.
 *
 * @param data Input buffer (ICMPv6 body, after type/code/checksum)
 * @param len Length of input buffer
 * @param rreq Output RREQ structure
 *
 * @return 0 on success, -EINVAL if NULL, -EMSGSIZE if too short
 */
int lichen_loadng_rreq_parse(const uint8_t *_Nonnull data, size_t len,
			     struct lichen_loadng_rreq *_Nonnull rreq);

/**
 * @brief Serialize RREQ to buffer.
 *
 * @param rreq RREQ to serialize
 * @param buf Output buffer
 * @param buf_len Length of output buffer
 *
 * @return Bytes written (36) on success, negative errno on failure
 */
int lichen_loadng_rreq_write(const struct lichen_loadng_rreq *_Nonnull rreq,
			     uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Parse RREP from ICMPv6 body.
 *
 * @param data Input buffer
 * @param len Length of input buffer
 * @param rrep Output RREP structure
 *
 * @return 0 on success, negative errno on failure
 */
int lichen_loadng_rrep_parse(const uint8_t *_Nonnull data, size_t len,
			     struct lichen_loadng_rrep *_Nonnull rrep);

/**
 * @brief Serialize RREP to buffer.
 *
 * @param rrep RREP to serialize
 * @param buf Output buffer
 * @param buf_len Length of output buffer
 *
 * @return Bytes written (36) on success, negative errno on failure
 */
int lichen_loadng_rrep_write(const struct lichen_loadng_rrep *_Nonnull rrep,
			     uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Parse RERR from ICMPv6 body.
 *
 * @param data Input buffer
 * @param len Length of input buffer
 * @param rerr Output RERR structure
 *
 * @return 0 on success, negative errno on failure
 */
int lichen_loadng_rerr_parse(const uint8_t *_Nonnull data, size_t len,
			     struct lichen_loadng_rerr *_Nonnull rerr);

/**
 * @brief Serialize RERR to buffer.
 *
 * @param rerr RERR to serialize
 * @param buf Output buffer
 * @param buf_len Length of output buffer
 *
 * @return Bytes written (18) on success, negative errno on failure
 */
int lichen_loadng_rerr_write(const struct lichen_loadng_rerr *_Nonnull rerr,
			     uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Initialize the route cache.
 *
 * Clears all route entries.
 */
void lichen_loadng_cache_init(void);

/**
 * @brief Add or update a route in the cache.
 *
 * Uses LRU eviction if cache is full.
 *
 * @param route Route entry to add
 *
 * @return 0 on success, negative errno on failure
 */
int lichen_loadng_cache_add(const struct lichen_loadng_route *_Nonnull route);

/**
 * @brief Look up a route by destination.
 *
 * @param destination IPv6 destination address (16 bytes)
 * @param now_ms Current timestamp in ms (for expiry check, 0 to skip)
 * @param route Output route entry (if found)
 *
 * @return 0 if found, -ENOENT if not found or expired
 */
int lichen_loadng_cache_lookup(const uint8_t destination[_Nonnull 16],
			       uint32_t now_ms,
			       struct lichen_loadng_route *_Nullable route);

/**
 * @brief Remove a route by destination.
 *
 * @param destination IPv6 destination address
 */
void lichen_loadng_cache_remove(const uint8_t destination[_Nonnull 16]);

/**
 * @brief Remove all routes through a specific next hop.
 *
 * @param next_hop IPv6 next hop address
 *
 * @return Number of routes removed
 */
int lichen_loadng_cache_remove_via(const uint8_t next_hop[_Nonnull 16]);

/**
 * @brief Refresh a route's validity timer.
 *
 * @param destination IPv6 destination address
 * @param now_ms Current timestamp
 *
 * @return 0 if refreshed, -ENOENT if not found
 */
int lichen_loadng_cache_refresh(const uint8_t destination[_Nonnull 16],
				uint32_t now_ms);

/**
 * @brief Expire stale routes.
 *
 * @param now_ms Current timestamp
 *
 * @return Number of routes expired
 */
int lichen_loadng_cache_expire(uint32_t now_ms);

/**
 * @brief Get current number of active routes.
 *
 * @return Number of active routes in cache
 */
size_t lichen_loadng_cache_count(void);

/**
 * @brief Initialize the RREQ suppression table.
 */
void lichen_loadng_seen_init(void);

/**
 * @brief Check and mark an RREQ as seen.
 *
 * @param rreq RREQ to check
 * @param now_ms Current timestamp
 *
 * @return true if RREQ should be suppressed (duplicate), false if new
 */
bool lichen_loadng_seen_check_and_mark(const struct lichen_loadng_rreq *_Nonnull rreq,
				       uint32_t now_ms);

/**
 * @brief Prune stale entries from the seen table.
 *
 * @param now_ms Current timestamp
 */
void lichen_loadng_seen_prune(uint32_t now_ms);

/**
 * @brief Start a new route discovery.
 *
 * @param discovery Discovery session to initialize
 * @param originator Our IPv6 address (16 bytes)
 * @param destination Destination to discover (16 bytes)
 * @param seq_num Sequence number for this discovery
 * @param now_ms Current timestamp
 *
 * @return 0 on success
 */
int lichen_loadng_discovery_start(struct lichen_loadng_discovery *_Nonnull discovery,
				  const uint8_t originator[_Nonnull 16],
				  const uint8_t destination[_Nonnull 16],
				  uint16_t seq_num, uint32_t now_ms);

/**
 * @brief Get the RREQ to transmit for the current ring.
 *
 * @param discovery Discovery session
 * @param rreq Output RREQ
 *
 * @return 0 on success, -EINVAL if not in searching state
 */
int lichen_loadng_discovery_get_rreq(const struct lichen_loadng_discovery *_Nonnull discovery,
				     struct lichen_loadng_rreq *_Nonnull rreq);

/**
 * @brief Advance to the next expanding ring.
 *
 * @param discovery Discovery session
 * @param now_ms Current timestamp
 *
 * @return 0 if advanced, -ERANGE if all rings exhausted (discovery failed)
 */
int lichen_loadng_discovery_advance(struct lichen_loadng_discovery *_Nonnull discovery,
				    uint32_t now_ms);

/**
 * @brief Check if a received RREP matches this discovery.
 *
 * If matched, the discovery transitions to REPLIED state.
 *
 * @param discovery Discovery session
 * @param rrep Received RREP
 *
 * @return true if RREP matches, false otherwise
 */
bool lichen_loadng_discovery_receive_rrep(struct lichen_loadng_discovery *_Nonnull discovery,
					  const struct lichen_loadng_rrep *_Nonnull rrep);

/**
 * @brief Process a received RREQ.
 *
 * @param our_addr Our IPv6 address (16 bytes)
 * @param rreq Received RREQ
 * @param from_neighbor Neighbor that sent the RREQ (16 bytes)
 * @param now_ms Current timestamp
 * @param result Output result
 *
 * @return 0 on success
 */
int lichen_loadng_process_rreq(const uint8_t our_addr[_Nonnull 16],
			       const struct lichen_loadng_rreq *_Nonnull rreq,
			       const uint8_t from_neighbor[_Nonnull 16],
			       uint32_t now_ms,
			       struct lichen_loadng_rreq_result *_Nonnull result);

/**
 * @brief Process a received RREP.
 *
 * @param our_addr Our IPv6 address (16 bytes)
 * @param rrep Received RREP
 * @param from_neighbor Neighbor that sent the RREP (16 bytes)
 * @param now_ms Current timestamp
 * @param result Output result
 *
 * @return 0 on success
 */
int lichen_loadng_process_rrep(const uint8_t our_addr[_Nonnull 16],
			       const struct lichen_loadng_rrep *_Nonnull rrep,
			       const uint8_t from_neighbor[_Nonnull 16],
			       uint32_t now_ms,
			       struct lichen_loadng_rrep_result *_Nonnull result);

/**
 * @brief Compare two 16-bit sequence numbers per RFC 1982 serial number arithmetic.
 *
 * @param a First sequence number (existing)
 * @param b Second sequence number (new)
 *
 * @return true if \p b is fresher than \p a (i.e., b arrived later in the sequence)
 */
static inline bool lichen_loadng_seq_is_fresher(uint16_t a, uint16_t b)
{
	if (a == b) {
		return false;
	}
	uint16_t diff = (uint16_t)(b - a);
	return diff < LICHEN_LOADNG_SEQ_HALF;
}

/**
 * @brief Reset all LOADng state (cache, seen table).
 */
void lichen_loadng_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_ROUTING_LOADNG_H_ */
