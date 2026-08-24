/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/recovery_countdown.h
 * @brief CCP desync recovery countdown timers (spec §2a.6, CCP-13a)
 *
 * Implements recovery countdown timers for T_DRIFT_MAX and T_GIVE_UP using
 * Zephyr hardware timers (k_timer). Tracks time spent in DRIFT and RECOVER
 * states, triggering callbacks when timeouts expire:
 *
 * - T_DRIFT_MAX: time in DRIFT before entering RECOVER
 * - T_GIVE_UP: time in RECOVER before abandoning and returning to UNJOINED
 *
 * Usage:
 *   struct lichen_recovery_countdown countdown;
 *   lichen_recovery_countdown_init(&countdown, on_drift_max, on_give_up, user_data);
 *
 *   // When entering DRIFT state:
 *   lichen_recovery_countdown_enter_drift(&countdown);
 *
 *   // When entering RECOVER state:
 *   lichen_recovery_countdown_enter_recover(&countdown);
 *
 *   // On valid beacon (recovery successful):
 *   lichen_recovery_countdown_reset(&countdown);
 *
 * The callbacks are invoked from timer context when the respective timeouts
 * expire. The callback can then transition the CCP FSM state.
 */

#ifndef LICHEN_RECOVERY_COUNTDOWN_H_
#define LICHEN_RECOVERY_COUNTDOWN_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __ZEPHYR__
#include <zephyr/kernel.h>
#endif

#include <lichen/link.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Callback type for recovery countdown expiration
 *
 * @param user_data User-provided context passed to init
 */
typedef void (*lichen_recovery_cb_t)(void *user_data);

/**
 * @brief Recovery countdown context
 *
 * Manages T_DRIFT_MAX and T_GIVE_UP countdown timers using Zephyr k_timer.
 * Initialize with lichen_recovery_countdown_init().
 */
struct lichen_recovery_countdown {
#ifdef __ZEPHYR__
	struct k_timer drift_timer;   /**< T_DRIFT_MAX countdown timer */
	struct k_timer recover_timer; /**< T_GIVE_UP countdown timer */
#endif
	uint16_t drift_max_threshold;  /**< Superframes before DRIFT→RECOVER */
	uint16_t give_up_threshold;    /**< Superframes before RECOVER→UNJOINED */
	uint16_t drift_count;          /**< Superframes elapsed in DRIFT */
	uint16_t recover_count;        /**< Superframes elapsed in RECOVER */
	bool in_drift;                 /**< Currently in DRIFT state */
	bool in_recover;               /**< Currently in RECOVER state */
	lichen_recovery_cb_t on_drift_max; /**< Callback when T_DRIFT_MAX expires */
	lichen_recovery_cb_t on_give_up;   /**< Callback when T_GIVE_UP expires */
	void *user_data;               /**< User context for callbacks */
};

/**
 * @brief Initialize recovery countdown with timeout thresholds
 *
 * @param ctx               Recovery countdown context to initialize
 * @param drift_max_sf      Superframes in DRIFT before RECOVER (default 6)
 * @param give_up_sf        Superframes in RECOVER before UNJOINED (default 10)
 * @param on_drift_max      Callback invoked when T_DRIFT_MAX expires (nullable)
 * @param on_give_up        Callback invoked when T_GIVE_UP expires (nullable)
 * @param user_data         User context passed to callbacks
 *
 * @return 0 on success, -EINVAL if ctx is NULL
 */
int lichen_recovery_countdown_init(struct lichen_recovery_countdown *ctx,
				   uint16_t drift_max_sf,
				   uint16_t give_up_sf,
				   lichen_recovery_cb_t on_drift_max,
				   lichen_recovery_cb_t on_give_up,
				   void *user_data);

/**
 * @brief Initialize with default thresholds
 *
 * Uses LICHEN_T_DRIFT_MAX_SUPERFRAMES and LICHEN_T_GIVE_UP_SUPERFRAMES.
 *
 * @param ctx               Recovery countdown context to initialize
 * @param on_drift_max      Callback invoked when T_DRIFT_MAX expires (nullable)
 * @param on_give_up        Callback invoked when T_GIVE_UP expires (nullable)
 * @param user_data         User context passed to callbacks
 *
 * @return 0 on success, -EINVAL if ctx is NULL
 */
int lichen_recovery_countdown_init_default(struct lichen_recovery_countdown *ctx,
					   lichen_recovery_cb_t on_drift_max,
					   lichen_recovery_cb_t on_give_up,
					   void *user_data);

/**
 * @brief Enter DRIFT state, start T_DRIFT_MAX countdown
 *
 * Resets the drift counter and starts the hardware timer. The timer fires
 * after drift_max_threshold superframes, invoking on_drift_max callback.
 *
 * @param ctx Recovery countdown context
 *
 * @return 0 on success, -EINVAL if ctx is NULL
 */
int lichen_recovery_countdown_enter_drift(struct lichen_recovery_countdown *ctx);

/**
 * @brief Enter RECOVER state, start T_GIVE_UP countdown
 *
 * Stops the drift timer, resets the recover counter, and starts the hardware
 * timer. The timer fires after give_up_threshold superframes, invoking
 * on_give_up callback.
 *
 * @param ctx Recovery countdown context
 *
 * @return 0 on success, -EINVAL if ctx is NULL
 */
int lichen_recovery_countdown_enter_recover(struct lichen_recovery_countdown *ctx);

/**
 * @brief Reset all countdowns (on valid beacon or join)
 *
 * Stops both hardware timers and clears all counters. Call this when a valid
 * beacon is received or the node successfully joins a DODAG.
 *
 * @param ctx Recovery countdown context
 *
 * @return 0 on success, -EINVAL if ctx is NULL
 */
int lichen_recovery_countdown_reset(struct lichen_recovery_countdown *ctx);

/**
 * @brief Manually advance DRIFT countdown by one superframe
 *
 * For polling-based implementations or testing. Checks if threshold is reached
 * and invokes callback if so. Use hardware timer-based operation for production.
 *
 * @param ctx Recovery countdown context
 *
 * @return true if T_DRIFT_MAX expired (should transition to RECOVER)
 * @return false if still counting or not in DRIFT
 */
bool lichen_recovery_countdown_tick_drift(struct lichen_recovery_countdown *ctx);

/**
 * @brief Manually advance RECOVER countdown by one superframe
 *
 * For polling-based implementations or testing. Checks if threshold is reached
 * and invokes callback if so. Use hardware timer-based operation for production.
 *
 * @param ctx Recovery countdown context
 *
 * @return true if T_GIVE_UP expired (should transition to UNJOINED)
 * @return false if still counting or not in RECOVER
 */
bool lichen_recovery_countdown_tick_recover(struct lichen_recovery_countdown *ctx);

/**
 * @brief Get superframes remaining before T_DRIFT_MAX expires
 *
 * @param ctx Recovery countdown context
 *
 * @return Superframes remaining (0 if expired or not in DRIFT)
 */
uint16_t lichen_recovery_countdown_drift_remaining(
	const struct lichen_recovery_countdown *ctx);

/**
 * @brief Get superframes remaining before T_GIVE_UP expires
 *
 * @param ctx Recovery countdown context
 *
 * @return Superframes remaining (0 if expired or not in RECOVER)
 */
uint16_t lichen_recovery_countdown_recover_remaining(
	const struct lichen_recovery_countdown *ctx);

/**
 * @brief Check if currently in DRIFT state
 *
 * @param ctx Recovery countdown context
 *
 * @return true if in DRIFT, false otherwise
 */
bool lichen_recovery_countdown_is_drifting(
	const struct lichen_recovery_countdown *ctx);

/**
 * @brief Check if currently in RECOVER state
 *
 * @param ctx Recovery countdown context
 *
 * @return true if in RECOVER, false otherwise
 */
bool lichen_recovery_countdown_is_recovering(
	const struct lichen_recovery_countdown *ctx);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RECOVERY_COUNTDOWN_H_ */
