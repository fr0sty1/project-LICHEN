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
	bool transmitted;        /**< Whether transmit point has passed */
};

/**
 * @brief Initialize a Trickle timer.
 *
 * @pre imin_ms > 0 (0 causes divide-by-zero or infinite loop in next_event/expire polling)
 *
 * @param t              Timer to initialize
 * @param imin_ms        Minimum interval in milliseconds
 * @param imax_doublings Number of times imin is doubled to reach max
 * @param k              Redundancy constant
 */
void lichen_trickle_init(struct lichen_trickle *_Nonnull t,
			 uint32_t imin_ms,
			 uint32_t imax_doublings,
			 uint32_t k);

/**
 * @brief Begin the first interval (RFC 6206 step 1-2).
 *
 * @param t           Timer
 * @param now         Current time in ms
 * @param rand_offset Random value in [0, imin/2) for transmit scheduling
 */
void lichen_trickle_start(struct lichen_trickle *_Nonnull t,
			  uint32_t now,
			  uint32_t rand_offset);

/**
 * @brief Get the absolute time when the current interval ends.
 *
 * Uses saturating addition to handle time wraparound after ~49.7 days.
 * When saturated, returns UINT32_MAX to avoid scheduling events in the past.
 */
static inline uint32_t lichen_trickle_interval_end(const struct lichen_trickle *_Nonnull t)
{
	uint32_t end = t->interval_start + t->interval;
	/* Saturate on overflow: if result < start, we wrapped */
	if (end < t->interval_start) {
		return UINT32_MAX;
	}
	return end;
}

/**
 * @brief Record a consistent transmission from a neighbor (RFC 6206 step 3).
 *
 * Call this when receiving a DIO with the same DODAG version.
 * Uses saturating increment to prevent counter wrap causing spurious transmits.
 */
static inline void lichen_trickle_heard_consistent(struct lichen_trickle *_Nonnull t)
{
	if (t->counter < UINT32_MAX) {
		t->counter++;
	}
}

/**
 * @brief Check if a DIO should be sent at transmit time (c < k, RFC 6206 step 4).
 */
static inline bool lichen_trickle_should_transmit(const struct lichen_trickle *_Nonnull t)
{
	return t->counter < t->k;
}

/**
 * @brief Mark the transmit point reached.
 *
 * @pre t must be non-NULL and initialized via lichen_trickle_init()
 * @return true if a DIO should be sent (counter < k)
 */
bool lichen_trickle_fire_transmit(struct lichen_trickle *_Nonnull t);

/**
 * @brief End the current interval: double (capped) and start the next (step 5).
 *
 * @pre t must be non-NULL and initialized via lichen_trickle_init()
 * @param t           Timer
 * @param now         Current time in ms
 * @param rand_offset Random value in [0, new_interval/2) for transmit scheduling
 */
void lichen_trickle_expire(struct lichen_trickle *_Nonnull t,
			   uint32_t now,
			   uint32_t rand_offset);

/**
 * @brief Handle inconsistency per RFC 6206 §4.2 rule 6: if not yet started
 * (interval == 0) or I > Imin, set I = Imin and restart timer.
 * No-op if already at Imin and running. Uses interval==0 sentinel for
 * cross-impl consistency (Rust uses state==Stopped, Python _generation==0).
 *
 * @pre t must be non-NULL and initialized via lichen_trickle_init()
 * @param t           Timer
 * @param now         Current time in ms
 * @param rand_offset Random value in [0, imin/2) for transmit scheduling
 */
void lichen_trickle_reset(struct lichen_trickle *_Nonnull t,
			  uint32_t now,
			  uint32_t rand_offset);


/**
 * @brief Get the next scheduled event.
 *
 * @pre t and out must be non-NULL; t must be initialized via lichen_trickle_init()
 * @param t   Timer
 * @param out Event to populate
 */
void lichen_trickle_next_event(const struct lichen_trickle *_Nonnull t,
			       struct lichen_trickle_event *_Nonnull out);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_TRICKLE_H_ */
