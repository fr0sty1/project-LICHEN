/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/rpl_routing.h
 * @brief RPL routing table and DAO manager (RFC 6550 non-storing mode)
 *
 * - RoutingTable: maps a /128 target to the ordered hop path from root to target
 * - DaoManager: builds DAOs (non-root) and assembles routes from DAOs (root)
 * - SourceRoutingHeader: RFC 6554 SRH encode/decode
 */

#ifndef LICHEN_RPL_ROUTING_H_
#define LICHEN_RPL_ROUTING_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <lichen/rpl_messages.h>

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

/* Default max routes (can be overridden by Kconfig) */
#ifndef CONFIG_LICHEN_RPL_MAX_ROUTES
#define CONFIG_LICHEN_RPL_MAX_ROUTES 32
#endif

/* Maximum hops in a source route */
#define LICHEN_RPL_MAX_HOPS 8

/* ── Source Routing Header (RFC 6554) ──────────────────────────────────────── */

/**
 * @brief RFC 6554 Source Routing Header, routing type 3 (uncompressed)
 */
struct lichen_rpl_srh {
	uint8_t segments_left;
	uint8_t num_addresses;
	uint8_t addresses[LICHEN_RPL_MAX_HOPS][16];
};

/**
 * @brief Encode SRH to RFC 6554 wire format starting at routing-type byte
 * (matches parse; for use as ExtensionHeader data after NextHdr/HdrLen).
 *
 * @param srh SRH to encode
 * @param buf Output buffer
 * @param len Buffer size
 * @return Bytes written (6 + 16*num_addresses), or negative error
 */
int lichen_rpl_srh_write(const struct lichen_rpl_srh *_Nonnull srh,
			 uint8_t *_Nonnull buf, size_t len);

/**
 * @brief Parse SRH from wire bytes.
 *
 * @param srh  Output structure
 * @param data Wire bytes (starting at routing-type byte)
 * @param len  Length of data
 * @return 0 on success, negative error code on failure
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_srh_parse(struct lichen_rpl_srh *_Nonnull srh,
			 const uint8_t *_Nonnull data, size_t len);

uint8_t lichen_rpl_srh_hdr_ext_len(uint8_t num_addresses);

/* ── Routing Table ─────────────────────────────────────────────────────────── */

/**
 * @brief Single route entry: target address and path to reach it
 */
struct lichen_rpl_route {
	uint8_t target[16];
	uint8_t path[LICHEN_RPL_MAX_HOPS][16];  /**< [0]=first hop, ..., [n-1]=target */
	uint8_t path_len;
	uint8_t path_lifetime;   /**< TTL in lifetime units (from Transit Info) */
	uint32_t last_updated;   /**< Timestamp when route was last updated (caller-provided) */
	bool valid;
};

/**
 * @brief Root-side routing table (non-storing mode)
 *
 * Maps target address to the ordered hop list [h1, ..., target].
 * First element is root's direct neighbor; last is the target.
 */
struct lichen_rpl_routing_table {
	struct lichen_rpl_route routes[CONFIG_LICHEN_RPL_MAX_ROUTES];
};

/**
 * @brief Initialize a routing table.
 *
 * @note No-op if @p rt is NULL.
 */
void lichen_rpl_routing_table_init(struct lichen_rpl_routing_table *_Nullable rt);

/**
 * @brief Add or update a route to a target.
 *
 * @param rt       Routing table
 * @param target   Target address (16 bytes)
 * @param path     Array of hop addresses
 * @param path_len Number of hops (includes target)
 * @return 0 on success, LICHEN_RPL_ERR_INVALID if NULL or path_len==0,
 *         LICHEN_RPL_ERR_OVERRUN if path too long or table full
 */
int lichen_rpl_routing_table_add(struct lichen_rpl_routing_table *_Nonnull rt,
				 const uint8_t *_Nonnull target,
				 const uint8_t path[][16],
				 uint8_t path_len);

/**
 * @brief Remove a route to a target.
 *
 * @note No-op if @p rt is NULL, @p target is NULL, or the target is not found.
 */
void lichen_rpl_routing_table_remove(struct lichen_rpl_routing_table *_Nullable rt,
				     const uint8_t *_Nullable target);

/**
 * @brief Lookup a route to a target.
 *
 * @param rt     Routing table
 * @param target Target address (16 bytes)
 * @return Pointer to route entry, or NULL if not found
 */
const struct lichen_rpl_route *_Nullable
lichen_rpl_routing_table_lookup(const struct lichen_rpl_routing_table *_Nullable rt,
				const uint8_t *_Nullable target);

/**
 * @brief Get number of valid routes.
 */
int lichen_rpl_routing_table_count(const struct lichen_rpl_routing_table *_Nullable rt);

/**
 * @brief Expire stale routes.
 *
 * Removes routes where (now - last_updated) exceeds path_lifetime * lifetime_unit.
 *
 * @param rt            Routing table
 * @param now           Current timestamp (same units as last_updated)
 * @param lifetime_unit Seconds per lifetime unit (RFC 6550 default: 60)
 * @return Number of routes expired
 */
int lichen_rpl_routing_table_expire(struct lichen_rpl_routing_table *_Nullable rt,
				    uint32_t now, uint32_t lifetime_unit);

/* ── DAO Manager ───────────────────────────────────────────────────────────── */

/**
 * @brief Parent map entry for assembling routes from DAOs
 */
struct lichen_rpl_parent_edge {
	uint8_t target[16];
	uint8_t parent[16];
	uint8_t path_lifetime;   /**< TTL in lifetime units (from Transit Info) */
	uint32_t last_updated;   /**< Timestamp when edge was last updated (caller-provided) */
	bool valid;
};

/**
 * @brief DAO Manager state
 *
 * On non-root nodes: builds DAOs advertising self with parent.
 * On root: processes incoming DAOs to build routing table.
 */
struct lichen_rpl_dao_manager {
	uint8_t node_address[16];
	uint8_t rpl_instance_id;
	uint8_t dodag_id[16];
	bool is_root;
	uint8_t dao_sequence;

	/* Root-only: routing table and parent map for path assembly */
	struct lichen_rpl_routing_table routing_table;
	struct lichen_rpl_parent_edge parent_map[CONFIG_LICHEN_RPL_MAX_ROUTES];
};

/**
 * @brief Initialize DAO manager for a non-root node.
 *
 * @param dm           DAO manager (must not be NULL)
 * @param node_address Node's IPv6 address (must not be NULL)
 * @param rpl_instance_id RPL instance ID
 * @param dodag_id     DODAG ID (must not be NULL)
 * @return 0 on success, LICHEN_RPL_ERR_INVALID if any pointer is NULL
 */
int lichen_rpl_dao_manager_init(struct lichen_rpl_dao_manager *_Nonnull dm,
				const uint8_t *_Nonnull node_address,
				uint8_t rpl_instance_id,
				const uint8_t *_Nonnull dodag_id);

/**
 * @brief Initialize DAO manager for root node.
 *
 * @param dm           DAO manager (must not be NULL)
 * @param node_address Node's IPv6 address (must not be NULL)
 * @param rpl_instance_id RPL instance ID
 * @param dodag_id     DODAG ID (must not be NULL)
 * @return 0 on success, LICHEN_RPL_ERR_INVALID if any pointer is NULL
 */
int lichen_rpl_dao_manager_init_root(struct lichen_rpl_dao_manager *_Nonnull dm,
				     const uint8_t *_Nonnull node_address,
				     uint8_t rpl_instance_id,
				     const uint8_t *_Nonnull dodag_id);

/**
 * @brief Build a DAO advertising this node with given parent.
 *
 * @param dm          DAO manager
 * @param parent_addr Parent's IPv6 address (16 bytes)
 * @param buf         Output buffer
 * @param len         Buffer size (needs ~64 bytes)
 * @return Number of bytes written, or negative error
 */
int lichen_rpl_dao_manager_build_dao(struct lichen_rpl_dao_manager *_Nonnull dm,
				     const uint8_t *_Nonnull parent_addr,
				     uint8_t *_Nonnull buf, size_t len);

int lichen_rpl_dao_manager_build_dao_ack(struct lichen_rpl_dao_manager *_Nonnull dm,
				     uint8_t dao_sequence, uint8_t status,
				     uint8_t *_Nonnull buf, size_t len);

/**
 * @brief Process a received DAO on the root.
 *
 * @warning This function does NOT authenticate DAO messages. The caller
 * MUST ensure DAOs are received over an authenticated channel (OSCORE or
 * link-layer authentication). Unauthenticated DAOs enable routing poisoning
 * attacks where an attacker claims arbitrary target/parent relationships.
 * LICHEN relies on Schnorr link signatures (48B) to authenticate the
 * immediate sender; verify that the DAO source is a known authenticated
 * neighbor before calling this function.
 *
 * @param dm        DAO manager (must be root)
 * @param dao_bytes Raw DAO wire bytes (base object + options)
 * @param len       Length of DAO bytes
 * @param now       Current timestamp for lifetime tracking
 * @return true if a route was installed, false otherwise
 */
bool lichen_rpl_dao_manager_process_dao(struct lichen_rpl_dao_manager *_Nonnull dm,
					const uint8_t *_Nonnull dao_bytes, size_t len,
					uint32_t now);

/**
 * @brief Expire stale parent edges and routes.
 *
 * @param dm            DAO manager (must be root)
 * @param now           Current timestamp (same units as last_updated)
 * @param lifetime_unit Seconds per lifetime unit (RFC 6550 default: 60)
 * @return Number of entries expired
 */
int lichen_rpl_dao_manager_expire(struct lichen_rpl_dao_manager *_Nonnull dm,
				  uint32_t now, uint32_t lifetime_unit);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_ROUTING_H_ */
