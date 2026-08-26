/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/sos_resource.h
 * @brief SOS resource state machine for CoAP /sos endpoint (spec 18.4)
 *
 * Implements the emergency beacon state machine:
 * - IDLE: No active emergency
 * - ACTIVE: SOS triggered, beaconing
 * - ACKNOWLEDGED: SOS received by coordinator/relay
 * - CANCELLED: SOS cancelled by originator
 *
 * State transitions:
 *   IDLE -> ACTIVE: POST /sos with valid payload
 *   ACTIVE -> ACKNOWLEDGED: Coordinator sends ACK
 *   ACTIVE -> CANCELLED: DELETE /sos from originator
 *   ACKNOWLEDGED -> CANCELLED: DELETE /sos from originator
 *   CANCELLED -> IDLE: Immediate transition (cancel is instantaneous)
 *   Any -> IDLE: Timeout or explicit reset
 *
 * This module provides the state machine logic; CoAP request handling
 * and CBOR encoding are handled by separate modules (coap_server.c,
 * sos_alert.h).
 */

#ifndef LICHEN_SOS_RESOURCE_H_
#define LICHEN_SOS_RESOURCE_H_

#include <stdint.h>
#include <stdbool.h>

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

/**
 * @brief SOS state machine states
 */
enum sos_state {
	SOS_STATE_IDLE = 0,        /**< No active emergency */
	SOS_STATE_ACTIVE = 1,      /**< SOS triggered, awaiting acknowledgment */
	SOS_STATE_ACKNOWLEDGED = 2, /**< SOS acknowledged by coordinator */
	SOS_STATE_CANCELLED = 3,   /**< SOS cancelled (transient state) */
};

/**
 * @brief SOS resource context
 *
 * Holds all state for a single SOS resource instance. Multiple instances
 * could track SOS from different nodes (e.g., on a coordinator).
 */
struct sos_resource {
	enum sos_state state;        /**< Current state machine state */
	uint8_t originator_iid[8];   /**< EUI-64 of SOS originator (when active) */
	uint64_t timestamp;          /**< Activation timestamp (uptime ms) */
	uint64_t ack_timestamp;      /**< Acknowledgment timestamp (uptime ms) */
	uint32_t sequence;           /**< Last accepted sequence number */
	bool originator_valid;       /**< True if originator_iid is set */
};

/**
 * @brief Initialize SOS resource to idle state
 *
 * @param res SOS resource context (must not be NULL)
 */
void sos_resource_init(struct sos_resource *_Nonnull res);

/**
 * @brief Get current SOS state
 *
 * @param res SOS resource context (must not be NULL)
 * @return Current state
 */
enum sos_state sos_resource_state(const struct sos_resource *_Nonnull res);

/**
 * @brief Check if SOS is currently active (ACTIVE or ACKNOWLEDGED)
 *
 * @param res SOS resource context (must not be NULL)
 * @return true if SOS is in an active state
 */
bool sos_resource_is_active(const struct sos_resource *_Nonnull res);

/**
 * @brief Activate SOS from a given originator
 *
 * Transitions IDLE -> ACTIVE. Returns error if already active.
 *
 * @param res SOS resource context (must not be NULL)
 * @param iid Originator EUI-64 (8 bytes, must not be NULL)
 * @param now Current uptime in milliseconds
 * @param seq Sequence number from origin signature
 * @return 0 on success, -EALREADY if already active, -EINVAL if iid is NULL
 */
int sos_resource_activate(struct sos_resource *_Nonnull res,
			  const uint8_t iid[_Nonnull 8],
			  uint64_t now,
			  uint32_t seq);

/**
 * @brief Acknowledge an active SOS
 *
 * Transitions ACTIVE -> ACKNOWLEDGED. Returns error if not in ACTIVE state.
 *
 * @param res SOS resource context (must not be NULL)
 * @param now Current uptime in milliseconds
 * @return 0 on success, -ENOENT if not in ACTIVE state
 */
int sos_resource_acknowledge(struct sos_resource *_Nonnull res, uint64_t now);

/**
 * @brief Cancel an active SOS
 *
 * Transitions ACTIVE or ACKNOWLEDGED -> IDLE (via transient CANCELLED).
 * Only the originator may cancel; sequence must advance.
 *
 * @param res SOS resource context (must not be NULL)
 * @param iid Cancelling node EUI-64 (8 bytes, must not be NULL)
 * @param seq Sequence number (must be > last accepted sequence)
 * @return 0 on success, -ENOENT if not active, -EACCES if not originator,
 *         -EALREADY if sequence not advancing
 */
int sos_resource_cancel(struct sos_resource *_Nonnull res,
			const uint8_t iid[_Nonnull 8],
			uint32_t seq);

/**
 * @brief Reset SOS to idle state
 *
 * Unconditional reset, typically after timeout or administrative clear.
 * Note: sequence is NOT reset to prevent replay attacks across resets.
 *
 * @param res SOS resource context (must not be NULL)
 */
void sos_resource_reset(struct sos_resource *_Nonnull res);

/**
 * @brief Get state name for logging
 *
 * @param state SOS state value
 * @return Human-readable state name (never NULL)
 */
const char *_Nonnull sos_state_name(enum sos_state state);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SOS_RESOURCE_H_ */
