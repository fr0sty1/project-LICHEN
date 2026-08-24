/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/rpl_multi_instance.h
 * @brief RPL Multi-Instance Coordination for Gateway Cooperation (GCP-5)
 *
 * Per spec/08-gateway-coordination.md GCP-5:
 * - All cooperating gateways use the same RPLInstanceID
 * - Each gateway acts as DODAG root for that instance
 * - Nodes see a unified DODAG with multiple possible parents
 * - DAO messages propagate across backbone as needed for route aggregation
 *
 * Coordination model:
 * - Time master election: lowest IID wins (per GCP-6.1)
 * - Slot conflict resolution: lowest IID wins (per GCP-6.3)
 * - DODAG version synchronized via backbone CoAP
 */

#ifndef LICHEN_RPL_MULTI_INSTANCE_H_
#define LICHEN_RPL_MULTI_INSTANCE_H_

#include <stdbool.h>
#include <stdint.h>

#include <lichen/rpl_addr.h>

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

/* ── Constants ─────────────────────────────────────────────────────────────── */

/** Maximum number of peer gateways in a federation */
#ifndef CONFIG_LICHEN_RPL_MAX_FEDERATION_PEERS
#define CONFIG_LICHEN_RPL_MAX_FEDERATION_PEERS 8
#endif

/** Default RPLInstanceID (0 per RFC 6550) */
#define LICHEN_RPL_DEFAULT_INSTANCE_ID 0

/** Initial DODAG version (lollipop counter starts at 128) */
#define LICHEN_RPL_INITIAL_DODAG_VERSION 128

/** Root rank per RFC 6550 */
#define LICHEN_RPL_ROOT_RANK_VALUE 256

/* ── Types ─────────────────────────────────────────────────────────────────── */

/**
 * @brief Gateway role in the federation per GCP-5/GCP-6.
 */
enum lichen_rpl_gateway_role {
	/** Not part of a federation */
	LICHEN_RPL_ROLE_STANDALONE = 0,
	/** Elected time master (lowest IID) */
	LICHEN_RPL_ROLE_PRIMARY,
	/** Non-primary gateway */
	LICHEN_RPL_ROLE_SECONDARY,
};

/**
 * @brief Information about a cooperating gateway (per GCP-4.1).
 *
 * Contains IID, capabilities, slot map, superframe duration, and
 * supported federation modes as discovered via backbone multicast.
 */
struct lichen_rpl_gateway_info {
	/** Gateway IPv6 link-local address (IID) */
	uint8_t iid[16];
	/** Slot allocation style: 0=interleaved, 1=contiguous */
	uint8_t slot_style;
	/** Number of owned slots */
	uint8_t owned_slot_count;
	/** Superframe duration in seconds */
	uint16_t superframe_duration_s;
	/** Supports PSK federation mode */
	bool supports_psk;
	/** Supports Ed25519 federation mode */
	bool supports_ed25519;
	/** Has GPS time source */
	bool has_gps;
	/** Entry is valid/in-use */
	bool valid;
};

/**
 * @brief DAO target for backbone propagation.
 */
struct lichen_rpl_dao_target {
	/** Target IPv6 address */
	uint8_t target[16];
	/** Prefix length (typically 128 for /128, or 64 for prefix routes) */
	uint8_t prefix_length;
};

/**
 * @brief Transit information for backbone DAO propagation.
 */
struct lichen_rpl_transit_info {
	/** Parent IPv6 address (next hop toward root) */
	uint8_t parent[16];
	/** Path sequence number */
	uint8_t path_sequence;
	/** Path lifetime in units (route validity) */
	uint8_t path_lifetime;
	/** Path control flags */
	uint8_t path_control;
	/** External flag (route is external to DODAG) */
	bool external;
};

/**
 * @brief DAO backbone message for propagation between gateways.
 *
 * Per GCP-5, DAO messages propagate across backbone as needed for
 * route aggregation.
 */
struct lichen_rpl_dao_backbone_msg {
	/** Origin gateway IID */
	uint8_t origin_gateway[16];
	/** RPL instance ID (must match federation) */
	uint8_t rpl_instance_id;
	/** DAO sequence number */
	uint8_t dao_sequence;
	/** Number of targets in this message */
	uint8_t target_count;
	/** Targets (max CONFIG_LICHEN_RPL_MAX_PARENTS) */
	struct lichen_rpl_dao_target targets[CONFIG_LICHEN_RPL_MAX_PARENTS];
	/** Transit information */
	struct lichen_rpl_transit_info transit;
	/** Timestamp (monotonic, for staleness) */
	uint32_t timestamp;
};

/**
 * @brief Coordinator for multiple DODAG roots in the same RPL instance.
 *
 * Per GCP-5, all cooperating gateways use the same RPLInstanceID and each
 * acts as a DODAG root. This coordinator manages:
 * 1. Shared RPLInstanceID across all gateways
 * 2. DODAG version synchronization
 * 3. Gateway discovery and membership
 * 4. Time master election (lowest IID per GCP-6.1)
 */
struct lichen_rpl_multi_root_coordinator {
	/** Shared RPLInstanceID (must be 0-255) */
	uint8_t rpl_instance_id;
	/** Current DODAG version (lollipop counter) */
	uint8_t dodag_version;
	/** Local gateway info (NULL if not set) */
	struct lichen_rpl_gateway_info local_gateway;
	/** Whether local_gateway is valid */
	bool has_local_gateway;
	/** Peer gateways in the federation */
	struct lichen_rpl_gateway_info peers[CONFIG_LICHEN_RPL_MAX_FEDERATION_PEERS];
	/** Number of valid peers */
	uint8_t peer_count;
};

/* ── Functions ─────────────────────────────────────────────────────────────── */

/**
 * @brief Initialize a multi-root coordinator.
 *
 * @param coord Coordinator to initialize
 * @param rpl_instance_id RPLInstanceID (must be 0-255)
 * @return 0 on success, -EINVAL if instance_id is out of range
 */
int lichen_rpl_coordinator_init(
	struct lichen_rpl_multi_root_coordinator *_Nonnull coord,
	uint8_t rpl_instance_id);

/**
 * @brief Set the local gateway information.
 *
 * @param coord Coordinator
 * @param iid Local gateway IPv6 address (16 bytes)
 * @param has_gps Whether gateway has GPS time source
 * @return 0 on success, -EINVAL if parameters invalid
 */
int lichen_rpl_coordinator_set_local(
	struct lichen_rpl_multi_root_coordinator *_Nonnull coord,
	const uint8_t *_Nonnull iid,
	bool has_gps);

/**
 * @brief Add a peer gateway to the federation.
 *
 * Per GCP-4.1, gateways discover each other via backbone multicast.
 *
 * @param coord Coordinator
 * @param info Peer gateway info to add
 * @return 0 on success, -ENOMEM if peer table full, -EINVAL if params invalid
 */
int lichen_rpl_coordinator_add_peer(
	struct lichen_rpl_multi_root_coordinator *_Nonnull coord,
	const struct lichen_rpl_gateway_info *_Nonnull info);

/**
 * @brief Remove a peer gateway from the federation.
 *
 * @param coord Coordinator
 * @param iid Peer gateway IID to remove (16 bytes)
 * @return 0 on success, -ENOENT if peer not found
 */
int lichen_rpl_coordinator_remove_peer(
	struct lichen_rpl_multi_root_coordinator *_Nonnull coord,
	const uint8_t *_Nonnull iid);

/**
 * @brief Get a peer gateway by IID.
 *
 * @param coord Coordinator
 * @param iid Peer gateway IID (16 bytes)
 * @return Pointer to peer info, or NULL if not found
 */
const struct lichen_rpl_gateway_info *_Nullable lichen_rpl_coordinator_get_peer(
	const struct lichen_rpl_multi_root_coordinator *_Nonnull coord,
	const uint8_t *_Nonnull iid);

/**
 * @brief Elect time master by lowest IID (per GCP-6.1).
 *
 * For non-GPS gateways, the gateway with the lowest IID is elected
 * as time master. GPS-equipped gateways use GPS epoch directly.
 *
 * @param coord Coordinator
 * @param[out] master_iid Buffer to receive elected master's IID (16 bytes)
 * @return 0 on success, -ENOENT if no gateways known
 */
int lichen_rpl_coordinator_elect_time_master(
	const struct lichen_rpl_multi_root_coordinator *_Nonnull coord,
	uint8_t *_Nonnull master_iid);

/**
 * @brief Determine this gateway's role in the federation.
 *
 * @param coord Coordinator
 * @return Gateway role (STANDALONE, PRIMARY, or SECONDARY)
 */
enum lichen_rpl_gateway_role lichen_rpl_coordinator_get_role(
	const struct lichen_rpl_multi_root_coordinator *_Nonnull coord);

/**
 * @brief Get current DODAG version.
 *
 * @param coord Coordinator
 * @return Current DODAG version (lollipop counter)
 */
static inline uint8_t lichen_rpl_coordinator_get_dodag_version(
	const struct lichen_rpl_multi_root_coordinator *_Nonnull coord)
{
	return coord->dodag_version;
}

/**
 * @brief Increment DODAG version (lollipop semantics per RFC 6550 Section 7.2).
 *
 * The counter wraps from 255 to 0, entering the linear region.
 *
 * @param coord Coordinator
 * @return New DODAG version
 */
uint8_t lichen_rpl_coordinator_increment_version(
	struct lichen_rpl_multi_root_coordinator *_Nonnull coord);

/**
 * @brief Validate a DIO from a peer gateway.
 *
 * Per GCP-5, all cooperating gateways use the same RPLInstanceID.
 * Validates that an incoming DIO conforms to federation rules.
 *
 * @param coord Coordinator
 * @param dio_instance_id RPLInstanceID from received DIO
 * @param dio_rank Rank from received DIO
 * @return 0 if valid, -EINVAL if RPLInstanceID mismatch, -EPROTO if rank invalid
 */
int lichen_rpl_coordinator_validate_dio(
	const struct lichen_rpl_multi_root_coordinator *_Nonnull coord,
	uint8_t dio_instance_id,
	uint16_t dio_rank);

/**
 * @brief Compare two gateway IIDs for conflict resolution.
 *
 * Per GCP-6.3, conflicts are resolved by lowest IID.
 *
 * @param a First IID (16 bytes)
 * @param b Second IID (16 bytes)
 * @return -1 if a < b, 0 if a == b, 1 if a > b
 */
int lichen_rpl_iid_compare(
	const uint8_t *_Nonnull a,
	const uint8_t *_Nonnull b);

/**
 * @brief Resolve slot conflict between two gateways.
 *
 * Per GCP-6.3: If two gateways claim overlapping slot, lowest IID MUST win.
 *
 * @param claimant_a First claimant IID (16 bytes)
 * @param claimant_b Second claimant IID (16 bytes)
 * @param[out] winner_iid Buffer to receive winner's IID (16 bytes)
 */
void lichen_rpl_resolve_slot_conflict(
	const uint8_t *_Nonnull claimant_a,
	const uint8_t *_Nonnull claimant_b,
	uint8_t *_Nonnull winner_iid);

/**
 * @brief Validate RPLInstanceID range.
 *
 * Per RFC 6550, RPLInstanceID must be 0-255.
 *
 * @param instance_id Instance ID to validate
 * @return true if valid, false otherwise
 */
static inline bool lichen_rpl_validate_instance_id(uint8_t instance_id)
{
	/* uint8_t is always 0-255, so always valid */
	(void)instance_id;
	return true;
}

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_MULTI_INSTANCE_H_ */
