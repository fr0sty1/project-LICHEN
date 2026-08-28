/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/rpl_trickle.h
 * @brief Trickle timer (RFC 6206) - deterministic state machine
 *
 * Caller-driven clock design: the caller is responsible for providing random
 * offsets (for reproducible tests) and polling next_event() to schedule timers.
 *
 * No async, no allocation, suitable for embedded systems.
 */

#ifndef LICHEN_RPL_TRICKLE_H_
#define LICHEN_RPL_TRICKLE_H_

#include <stdint.h>
#include <stdbool.h>

/** Canonical LICHEN RPL Trickle profile (packets-timing.json). */
#define LICHEN_RPL_TRICKLE_IMIN_MS 4000U
#define LICHEN_RPL_TRICKLE_IMAX_DOUBLINGS 8U
#define LICHEN_RPL_TRICKLE_IMAX_MS 1024000U
#define LICHEN_RPL_TRICKLE_K 10U

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

/**
 * @brief Trickle event type
 */
enum lichen_trickle_event_type {
	/** Transmit at or after at_ms if counter < k */
	LICHEN_TRICKLE_TRANSMIT,
	/** Current interval ends at at_ms; call expire */
	LICHEN_TRICKLE_EXPIRE,
};

/**
 * @brief Trickle scheduled event
 */
struct lichen_trickle_event {
	enum lichen_trickle_event_type type;
	uint32_t at_ms;
};

/**
 * @brief RFC 6206 Trickle timer state
 *
 * All times are integer milliseconds. The caller supplies random offsets
 * so the timer is deterministic and testable without a live RNG.
 */
struct lichen_trickle {
	uint32_t imin;           /**< Minimum interval (Imin) in ms */
	uint32_t max_interval;   /**< Maximum interval (Imax) in ms */
	uint32_t k;              /**< Redundancy constant */
	uint32_t interval;       /**< Current interval size in ms */
	uint32_t counter;        /**< Consistency counter (c) */
	uint32_t interval_start; /**< Start time of current interval */
	uint32_t transmit_time;  /**< Scheduled transmit time */
	bool initialized;        /**< Configuration passed validation */
	bool active;             /**< An interval has been started */
	bool transmitted;        /**< Whether transmit point has passed */
};

/**
 * @brief Initialize a Trickle timer.
 *
 * @param t              Timer to initialize
 * @param imin_ms        Minimum interval in milliseconds (at least 2)
 * @param imax_doublings Number of times imin is doubled to reach max
 * @param k              Redundancy constant (greater than zero)
 * @return 0, -EINVAL for an invalid pointer/value, or -ERANGE when Imax
 *         cannot be represented safely by the wrapping 32-bit clock
 */
int lichen_trickle_init(struct lichen_trickle *_Nullable t,
			uint32_t imin_ms,
			uint32_t imax_doublings,
			uint32_t k);

/** Initialize the canonical LICHEN RPL Trickle profile. */
static inline int lichen_trickle_init_profile(struct lichen_trickle *_Nullable t)
{
	return lichen_trickle_init(t, LICHEN_RPL_TRICKLE_IMIN_MS,
				   LICHEN_RPL_TRICKLE_IMAX_DOUBLINGS,
				   LICHEN_RPL_TRICKLE_K);
}

/**
 * @brief Begin the first interval (RFC 6206 step 1-2).
 *
 * @param t           Timer
 * @param now         Current time in ms
 * @param rand_offset Uniform random value in [0, floor(imin/2))
 * @return true if the interval was started; false for invalid state/input
 */
bool lichen_trickle_start(struct lichen_trickle *_Nullable t,
			 uint32_t now,
			 uint32_t rand_offset);

/**
 * @brief Get the absolute time when the current interval ends.
 *
 * The result uses normal uint32_t modular arithmetic, like Zephyr's
 * k_uptime_get_32().  All validated intervals are at most INT32_MAX, so the
 * usual signed-difference test remains unambiguous across clock wrap.
 */
static inline uint32_t lichen_trickle_interval_end(const struct lichen_trickle *_Nonnull t)
{
	return t->interval_start + t->interval;
}

/** Wrap-safe test for a 32-bit millisecond deadline. */
static inline bool lichen_trickle_time_reached(uint32_t now, uint32_t deadline)
{
	return (int32_t)(now - deadline) >= 0;
}

/**
 * @brief Record a consistent transmission from a neighbor (RFC 6206 step 3).
 *
 * Call this when receiving a DIO with the same DODAG version.
 * Uses saturating increment to prevent counter wrap causing spurious transmits.
 */
static inline void lichen_trickle_heard_consistent(struct lichen_trickle *_Nonnull t)
{
	if (t->active && t->counter < UINT32_MAX) {
		t->counter++;
	}
}

/**
 * @brief Check if a DIO should be sent at transmit time (c < k, RFC 6206 step 4).
 */
static inline bool lichen_trickle_should_transmit(const struct lichen_trickle *_Nonnull t)
{
	return t->active && t->counter < t->k;
}

/**
 * @brief Mark the transmit point reached.
 *
 * @pre t must be non-NULL and initialized via lichen_trickle_init()
 * @return true if a DIO should be sent (counter < k)
 */
bool lichen_trickle_fire_transmit(struct lichen_trickle *_Nullable t);

/**
 * @brief End the current interval: double (capped) and start the next (step 5).
 *
 * @pre t must be non-NULL and initialized via lichen_trickle_init()
 * @param t           Timer
 * @param now         Current time in ms
 * @param rand_offset Uniform random value in [0, floor(new_interval/2))
 * @return true if the next interval was started; false for invalid state/input
 */
bool lichen_trickle_expire(struct lichen_trickle *_Nullable t,
			  uint32_t now,
			  uint32_t rand_offset);

/**
 * @brief Handle an inconsistency: shrink to imin and restart (RFC 6206 step 6).
 *
 * This API represents a LICHEN-authorized external reset event.  Every call
 * atomically restarts Imin and samples a fresh transmit point, as required by
 * the canonical repeated-inconsistency vectors.  Callers decide which
 * received messages are authorized to invoke it.
 *
 * @pre t must be non-NULL and initialized via lichen_trickle_init()
 * @param t           Timer
 * @param now         Current time in ms
 * @param rand_offset Uniform random value in [0, floor(imin/2))
 * @return true if reset; false for invalid state/input
 */
bool lichen_trickle_reset(struct lichen_trickle *_Nullable t,
			 uint32_t now,
			 uint32_t rand_offset);


/**
 * @brief Get the next scheduled event.
 *
 * @param t   Timer
 * @param out Event to populate
 * @return true when an active timer has an event; false otherwise
 */
bool lichen_trickle_next_event(const struct lichen_trickle *_Nullable t,
			      struct lichen_trickle_event *_Nullable out);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_TRICKLE_H_ */
