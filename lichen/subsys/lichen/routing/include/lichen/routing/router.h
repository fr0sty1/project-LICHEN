/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/routing/router.h
 * @brief Unified hybrid routing decision engine (spec section 7.2)
 *
 * The Router decides how to forward each packet based on destination address:
 * 1. Link-local (fe80::/10): Direct neighbor delivery
 * 2. Mesh-local (Yggdrasil 02xx or configured GUA): Gradient lookup -> LOADng
 * 3. External/Yggdrasil-remote: Forward to border router/gateway
 *
 * Why separate Router from LOADng/RPL: Each protocol has its own state machine.
 * The Router orchestrates them based on address classification and route
 * availability.
 */

#ifndef LICHEN_ROUTING_ROUTER_H_
#define LICHEN_ROUTING_ROUTER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/routing/gradient.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Default configuration */
#ifndef CONFIG_LICHEN_ROUTER_MAX_PENDING
#define CONFIG_LICHEN_ROUTER_MAX_PENDING 8
#endif

#ifndef CONFIG_LICHEN_ROUTER_MAX_PENDING_PER_DEST
#define CONFIG_LICHEN_ROUTER_MAX_PENDING_PER_DEST 3
#endif

#ifndef CONFIG_LICHEN_ROUTER_PENDING_TIMEOUT_MS
#define CONFIG_LICHEN_ROUTER_PENDING_TIMEOUT_MS 15000
#endif

#ifndef CONFIG_LICHEN_ROUTER_MAX_PENDING_PACKET_SIZE
#define CONFIG_LICHEN_ROUTER_MAX_PENDING_PACKET_SIZE 256
#endif

#ifndef CONFIG_LICHEN_ROUTER_MAX_MESH_PREFIXES
#define CONFIG_LICHEN_ROUTER_MAX_MESH_PREFIXES 4
#endif

/* DTN store-and-forward (optional, spec 9.8) */
#ifndef CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE
#define CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE 0  /* 0 = disabled */
#endif

#ifndef CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGES
#define CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGES 8
#endif

#ifndef CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGE_SIZE
#define CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGE_SIZE 512
#endif

/* Forwarding buffer with backpressure (spec appendix-bufferbloat) */
#ifndef CONFIG_LICHEN_ROUTER_FORWARDING_BUFFER
#define CONFIG_LICHEN_ROUTER_FORWARDING_BUFFER 1
#endif

#ifndef CONFIG_LICHEN_ROUTER_MAX_FORWARDING_SOURCES
#define CONFIG_LICHEN_ROUTER_MAX_FORWARDING_SOURCES 8
#endif

#ifndef CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE
#define CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE 2
#endif

#ifndef CONFIG_LICHEN_ROUTER_FORWARDING_DEADLINE_MS
#define CONFIG_LICHEN_ROUTER_FORWARDING_DEADLINE_MS 10000
#endif

/**
 * @brief Classification of IPv6 destination address (spec 7.2).
 */
enum lichen_addr_class {
	LICHEN_ADDR_LINK_LOCAL,
	LICHEN_ADDR_MESH_LOCAL,
	LICHEN_ADDR_YGGDRASIL,
	LICHEN_ADDR_EXTERNAL
};

/**
 * @brief What to do with a packet after routing decision.
 */
enum lichen_route_decision {
	LICHEN_ROUTE_FORWARD,      /**< Forward to next_hop now */
	LICHEN_ROUTE_QUEUE,        /**< Queue pending LOADng discovery */
	LICHEN_ROUTE_DROP,         /**< No route, cannot discover */
	LICHEN_ROUTE_DELIVER_LOCAL /**< Packet is for this node */
};

/**
 * @brief A packet queued pending route discovery.
 *
 * SECURITY: packet_data is a static buffer; data is copied on enqueue to
 * prevent use-after-free if caller frees their buffer before packet expires.
 */
struct lichen_pending_packet {
	uint8_t destination_iid[8]; /**< IID we're discovering route to */
	uint8_t packet_data[CONFIG_LICHEN_ROUTER_MAX_PENDING_PACKET_SIZE]; /**< Copied packet data */
	size_t packet_len;          /**< Length of packet data */
	uint32_t queued_at_ms;      /**< Timestamp when queued */
	bool valid;                 /**< Slot in use */
};

/**
 * @brief IPv6 network prefix for mesh-local classification.
 */
struct lichen_mesh_prefix {
	uint8_t prefix[16];      /**< IPv6 prefix */
	uint8_t prefix_len;      /**< Prefix length in bits */
	bool valid;              /**< Slot in use */
};

/**
 * @brief DTN buffered message for router (spec 9.8).
 *
 * SECURITY: data is a static buffer; data is copied on enqueue to prevent
 * use-after-free if caller frees their buffer before message expires.
 */
struct lichen_router_dtn_message {
	uint8_t destination_iid[8]; /**< 8-byte IID of destination */
	uint8_t data[CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGE_SIZE]; /**< Copied message data */
	size_t len;                 /**< Message length */
	uint32_t expiry_unix;       /**< Absolute Unix timestamp expiry */
	uint32_t buffered_at_ms;    /**< When message was buffered */
	bool valid;                 /**< Slot in use */
};

#if CONFIG_LICHEN_ROUTER_FORWARDING_BUFFER
/**
 * @brief A packet in the forwarding buffer.
 */
struct lichen_fwd_packet {
	uint8_t *data;           /**< Packet data (caller-owned) */
	size_t len;              /**< Packet length */
	uint32_t enqueued_at_ms; /**< Timestamp when enqueued */
	bool valid;              /**< Slot in use */
};

/**
 * @brief Per-source forwarding queue (spec appendix-bufferbloat).
 *
 * Tracks packets queued for forwarding from a single source IID.
 * Prevents one chatty source from monopolizing relay capacity.
 */
struct lichen_fwd_source {
	uint8_t source_iid[8];   /**< Source IID (sender of packets) */
	struct lichen_fwd_packet packets[CONFIG_LICHEN_ROUTER_MAX_PACKETS_PER_SOURCE];
	uint8_t packet_count;    /**< Number of valid packets */
	uint32_t last_activity_ms; /**< Last packet queued/dequeued */
	bool valid;              /**< Slot in use */
};

/**
 * @brief Forwarding buffer statistics (spec appendix-bufferbloat).
 */
struct lichen_fwd_stats {
	uint32_t packets_queued;         /**< Total packets enqueued */
	uint32_t packets_forwarded;      /**< Total packets successfully forwarded */
	uint32_t packets_dropped_full;   /**< Dropped due to buffer full */
	uint32_t packets_dropped_deadline; /**< Dropped due to deadline expiry */
	uint32_t nacks_sent;             /**< NACK signals triggered */
};
#endif /* CONFIG_LICHEN_ROUTER_FORWARDING_BUFFER */

/**
 * @brief Routing decision result.
 */
struct lichen_route_result {
	enum lichen_route_decision decision; /**< What to do */
	uint8_t next_hop[16];                /**< Next hop IPv6 (if FORWARD) */
};

/**
 * @brief RPL DODAG state accessor interface.
 *
 * The router doesn't own DODAG state directly; it uses this interface
 * to query RPL state for external routing.
 */
struct lichen_rpl_accessor {
	/**
	 * Check if joined to a DODAG.
	 * @param user_data User context pointer.
	 * @return true if joined.
	 */
	bool (*is_joined)(void *user_data);

	/**
	 * Get preferred parent address.
	 * @param user_data User context pointer.
	 * @param out_parent Output buffer for 16-byte IPv6 address.
	 * @return 0 on success, -ENOENT if no parent.
	 */
	int (*get_preferred_parent)(void *user_data, uint8_t out_parent[16]);

	/** User context pointer passed to callbacks. */
	void *user_data;
};

/**
 * @brief LOADng discovery interface.
 *
 * The router calls this to initiate reactive route discovery.
 */
struct lichen_loadng_accessor {
	/**
	 * Initiate route discovery for a destination IID.
	 * @param user_data User context pointer.
	 * @param destination_iid 8-byte IID to discover.
	 * @return 0 on success, negative errno on error.
	 */
	int (*discover)(void *user_data, const uint8_t destination_iid[8]);

	/** User context pointer passed to callbacks. */
	void *user_data;
};

/**
 * @brief Unified hybrid router state (spec 7.2).
 *
 * Combines address classification, gradient lookup, RPL upward routing,
 * pending queue for LOADng, and optional DTN store-and-forward.
 */
struct lichen_router {
	/* This node's address */
	uint8_t node_address[16];
	uint8_t node_iid[8];

	/* Unified gradient table (spec 11) */
	struct lichen_gradient_table gradient_table;

	/* RPL interface for external routing */
	struct lichen_rpl_accessor rpl;

	/* LOADng interface for reactive discovery */
	struct lichen_loadng_accessor loadng;

	/* Mesh-local prefixes (spec 7.2 address classification) */
	struct lichen_mesh_prefix mesh_prefixes[CONFIG_LICHEN_ROUTER_MAX_MESH_PREFIXES];

	/* Pending packets awaiting route discovery */
	struct lichen_pending_packet pending[CONFIG_LICHEN_ROUTER_MAX_PENDING];
	size_t pending_count;

#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
	/* DTN store-and-forward buffer (spec 9.8) */
	struct lichen_router_dtn_message dtn_buffer[CONFIG_LICHEN_ROUTER_DTN_MAX_MESSAGES];
	size_t dtn_buffer_bytes;
#endif

#if CONFIG_LICHEN_ROUTER_FORWARDING_BUFFER
	/* Per-source forwarding buffer (spec appendix-bufferbloat) */
	struct lichen_fwd_source fwd_sources[CONFIG_LICHEN_ROUTER_MAX_FORWARDING_SOURCES];
	struct lichen_fwd_stats fwd_stats;
#endif

	/* GPSR state (spec 9.7) */
	int32_t node_lat_e7;
	int32_t node_lon_e7;
	bool node_coords_valid;
};

/**
 * @brief Initialize a router.
 *
 * @param router Router to initialize.
 * @param node_address This node's 16-byte IPv6 address.
 * @return 0 on success, negative errno on error.
 */
int lichen_router_init(struct lichen_router *router,
		       const uint8_t node_address[16]);

/**
 * @brief Set RPL accessor interface.
 *
 * @param router Router instance.
 * @param accessor RPL accessor callbacks.
 */
void lichen_router_set_rpl(struct lichen_router *router,
			   const struct lichen_rpl_accessor *accessor);

/**
 * @brief Set LOADng accessor interface.
 *
 * @param router Router instance.
 * @param accessor LOADng accessor callbacks.
 */
void lichen_router_set_loadng(struct lichen_router *router,
			      const struct lichen_loadng_accessor *accessor);

/**
 * @brief Classify an IPv6 destination address (spec 7.2).
 *
 * @param router Router instance.
 * @param dst_addr 16-byte IPv6 destination address.
 * @return Address classification.
 */
enum lichen_addr_class lichen_router_classify(const struct lichen_router *router,
					      const uint8_t dst_addr[16]);

/**
 * @brief Make a routing decision for a packet (spec 7.2).
 *
 * @param router Router instance.
 * @param dst_addr 16-byte IPv6 destination address.
 * @param dst_iid 8-byte destination IID (last 8 bytes of dst_addr).
 * @param now_ms Current time in milliseconds.
 * @param result Output routing decision.
 * @return 0 on success, negative errno on error.
 */
int lichen_router_route(struct lichen_router *router,
			const uint8_t dst_addr[16],
			const uint8_t dst_iid[8],
			uint32_t now_ms,
			struct lichen_route_result *result);

/**
 * @brief Queue a packet pending route discovery.
 *
 * @param router Router instance.
 * @param dst_iid 8-byte destination IID.
 * @param packet_data Packet data to queue (copied).
 * @param packet_len Length of packet data.
 * @param now_ms Current time in milliseconds.
 * @return 0 on success, negative errno on error.
 */
int lichen_router_queue_pending(struct lichen_router *router,
				const uint8_t dst_iid[8],
				const uint8_t *packet_data,
				size_t packet_len,
				uint32_t now_ms);

/**
 * @brief Get pending packets for a destination (after discovery succeeds).
 *
 * @param router Router instance.
 * @param dst_iid 8-byte destination IID.
 * @param out_packets Output array for packet pointers.
 * @param max_packets Maximum packets to return.
 * @return Number of packets returned.
 */
int lichen_router_get_pending(struct lichen_router *router,
			      const uint8_t dst_iid[8],
			      struct lichen_pending_packet **out_packets,
			      size_t max_packets);

/**
 * @brief Clear pending packets for a destination.
 *
 * @param router Router instance.
 * @param dst_iid 8-byte destination IID.
 * @return Number of packets cleared.
 */
int lichen_router_clear_pending(struct lichen_router *router,
				const uint8_t dst_iid[8]);

/**
 * @brief Expire old pending packets.
 *
 * @param router Router instance.
 * @param now_ms Current time in milliseconds.
 * @return Number of packets expired.
 */
int lichen_router_expire_pending(struct lichen_router *router, uint32_t now_ms);

/**
 * @brief Add a mesh-local prefix.
 *
 * @param router Router instance.
 * @param prefix 16-byte IPv6 prefix.
 * @param prefix_len Prefix length in bits.
 * @return 0 on success, -ENOMEM if no slots available.
 */
int lichen_router_add_mesh_prefix(struct lichen_router *router,
				  const uint8_t prefix[16],
				  uint8_t prefix_len);

/**
 * @brief Remove a mesh-local prefix.
 *
 * @param router Router instance.
 * @param prefix 16-byte IPv6 prefix.
 * @param prefix_len Prefix length in bits.
 */
void lichen_router_remove_mesh_prefix(struct lichen_router *router,
				      const uint8_t prefix[16],
				      uint8_t prefix_len);

/**
 * @brief Callback when LOADng discovers a route.
 *
 * Installs gradient and clears pending packets for dst (caller must
 * lichen_router_get_pending() first to retrieve/forward).
 *
 * @param router Router instance.
 * @param dst_iid 8-byte destination IID.
 * @param next_hop 16-byte next hop IPv6 address.
 * @param now_ms Current time in milliseconds.
 * @return Number of packets cleared.
 */
int lichen_router_on_route_discovered(struct lichen_router *router,
				      const uint8_t dst_iid[8],
				      const uint8_t next_hop[16],
				      uint32_t now_ms);

/**
 * @brief Set this node's geographic coordinates (spec 9.7).
 *
 * @param router Router instance.
 * @param lat_e7 Latitude in 1e-7 degrees.
 * @param lon_e7 Longitude in 1e-7 degrees.
 */
void lichen_router_set_coords(struct lichen_router *router,
			      int32_t lat_e7, int32_t lon_e7);

/**
 * @brief GPSR greedy forwarding (spec 9.7).
 *
 * Find neighbor closest to destination coordinates.
 *
 * @param router Router instance.
 * @param dst_lat_e7 Destination latitude in 1e-7 degrees.
 * @param dst_lon_e7 Destination longitude in 1e-7 degrees.
 * @param out_next_hop Output buffer for 16-byte next hop address.
 * @return 0 on success, -ENOENT if no progress possible.
 */
int lichen_router_gpsr_forward(struct lichen_router *router,
			       int32_t dst_lat_e7, int32_t dst_lon_e7,
			       uint8_t out_next_hop[16]);

#if CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0
/**
 * @brief Buffer a message for DTN store-and-forward (spec 9.8).
 *
 * @param router Router instance.
 * @param dst_iid 8-byte destination IID.
 * @param data Message data (copied).
 * @param len Message length.
 * @param expiry_unix Unix timestamp when message expires.
 * @param now_ms Current time in milliseconds.
 * @return 0 on success, negative errno on error.
 */
int lichen_router_dtn_buffer(struct lichen_router *router,
			     const uint8_t dst_iid[8],
			     const uint8_t *data,
			     size_t len,
			     uint32_t expiry_unix,
			     uint32_t now_ms);

/**
 * @brief Get list of destination IIDs with buffered DTN messages.
 *
 * @param router Router instance.
 * @param out_iids Output buffer for IIDs (8 bytes each).
 * @param max_iids Maximum IIDs to return.
 * @return Number of unique IIDs.
 */
int lichen_router_dtn_get_pending_iids(struct lichen_router *router,
				       uint8_t (*out_iids)[8],
				       size_t max_iids);

/**
 * @brief Retrieve all DTN messages for a destination.
 *
 * Returns pointers to messages in the DTN buffer for the given destination.
 * The messages remain valid (reserved) until explicitly released via
 * lichen_router_dtn_release(). The caller must release each message when
 * done to free the slot for reuse.
 *
 * @param router Router instance.
 * @param dst_iid 8-byte destination IID.
 * @param out_messages Output array for message pointers.
 * @param max_messages Maximum messages to return.
 * @return Number of messages retrieved.
 */
int lichen_router_dtn_retrieve(struct lichen_router *router,
			       const uint8_t dst_iid[8],
			       struct lichen_router_dtn_message **out_messages,
			       size_t max_messages);

/**
 * @brief Release a DTN message after processing.
 *
 * Marks the message slot as free for reuse. Must be called for each message
 * returned by lichen_router_dtn_retrieve() after the caller is done using it.
 *
 * @param router Router instance.
 * @param msg Message to release.
 */
void lichen_router_dtn_release(struct lichen_router *router,
			       struct lichen_router_dtn_message *msg);

/**
 * @brief Expire old DTN messages.
 *
 * @param router Router instance.
 * @param now_unix Current Unix timestamp.
 * @return Number of messages expired.
 */
int lichen_router_dtn_expire(struct lichen_router *router, uint32_t now_unix);
#endif /* CONFIG_LICHEN_ROUTER_DTN_BUFFER_SIZE > 0 */

#if CONFIG_LICHEN_ROUTER_FORWARDING_BUFFER
/**
 * @brief Check if the forwarding buffer can accept a packet from source.
 *
 * SECURITY: Call this before accepting a packet for forwarding to prevent
 * one chatty source from monopolizing relay capacity.
 *
 * @param router Router instance.
 * @param source_iid 8-byte source IID (packet originator).
 * @return true if packet can be accepted, false if source limit reached.
 */
bool lichen_router_fwd_can_accept(const struct lichen_router *router,
				  const uint8_t source_iid[8]);

/**
 * @brief Enqueue a packet for forwarding (spec appendix-bufferbloat).
 *
 * Adds a packet to the per-source forwarding buffer. Returns -ENOBUFS if
 * the source has reached its packet limit (MAX_PACKETS_PER_SOURCE).
 *
 * @param router Router instance.
 * @param source_iid 8-byte source IID (packet originator).
 * @param data Packet data (caller retains ownership).
 * @param len Packet length.
 * @param now_ms Current time in milliseconds.
 * @return 0 on success, -ENOBUFS if source limit reached, -EINVAL on error.
 */
int lichen_router_fwd_enqueue(struct lichen_router *router,
			      const uint8_t source_iid[8],
			      uint8_t *data,
			      size_t len,
			      uint32_t now_ms);

/**
 * @brief Dequeue the next packet for forwarding.
 *
 * Returns the oldest packet across all sources (FIFO). The packet is
 * removed from the buffer.
 *
 * @param router Router instance.
 * @param out_source_iid Output buffer for 8-byte source IID.
 * @param out_data Output pointer to packet data.
 * @param out_len Output pointer to packet length.
 * @return 0 on success, -ENOENT if buffer empty.
 */
int lichen_router_fwd_dequeue(struct lichen_router *router,
			      uint8_t out_source_iid[8],
			      uint8_t **out_data,
			      size_t *out_len);

/**
 * @brief Expire old packets from forwarding buffer.
 *
 * Drops packets older than FORWARDING_DEADLINE_MS.
 *
 * @param router Router instance.
 * @param now_ms Current time in milliseconds.
 * @return Number of packets expired.
 */
int lichen_router_fwd_expire(struct lichen_router *router, uint32_t now_ms);

/**
 * @brief Get forwarding buffer statistics.
 *
 * @param router Router instance.
 * @return Pointer to stats structure (valid while router exists).
 */
const struct lichen_fwd_stats *lichen_router_fwd_stats(
	const struct lichen_router *router);

/**
 * @brief Get total packets currently in forwarding buffer.
 *
 * @param router Router instance.
 * @return Number of packets queued.
 */
size_t lichen_router_fwd_count(const struct lichen_router *router);
#endif /* CONFIG_LICHEN_ROUTER_FORWARDING_BUFFER */

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_ROUTING_ROUTER_H_ */
