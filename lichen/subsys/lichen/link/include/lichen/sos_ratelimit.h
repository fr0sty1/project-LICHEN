/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/sos_ratelimit.h
 * @brief SOS rate limiting with monotonic uptime (spec 18.4.3)
 *
 * Per-source rate limiting for SOS alerts using monotonic uptime
 * (k_uptime_get) to avoid wall-clock drift/jump issues. This module
 * provides types and functions to enforce:
 *
 * - 10-minute cooldown between alerts from the same source
 * - Maximum 3 alerts per hour per source
 * - Burst allowance for rapid successive alerts (separate bead)
 *
 * SECURITY: Rate limiting prevents SOS flooding attacks where a
 * compromised or malicious node attempts to exhaust resources or
 * trigger false emergency responses by spamming SOS alerts.
 *
 * Design rationale for monotonic uptime:
 * - Wall clock can jump backward (NTP corrections, manual changes)
 * - RTC may not be synchronized or accurate on embedded devices
 * - Monotonic uptime provides consistent elapsed-time measurements
 */

#ifndef LICHEN_SOS_RATELIMIT_H_
#define LICHEN_SOS_RATELIMIT_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default cooldown between alerts from same source (milliseconds). */
#define SOS_RATELIMIT_COOLDOWN_MS (600U * 1000U)  /* 10 minutes */

/** Default maximum alerts per hour per source. */
#define SOS_RATELIMIT_MAX_PER_HOUR 3U

/** Hourly window duration (milliseconds). */
#define SOS_RATELIMIT_HOUR_MS (3600U * 1000U)

/** Maximum number of alert timestamps to track per source. */
#define SOS_RATELIMIT_MAX_TIMESTAMPS 3U

/**
 * @brief Result of rate limit check.
 */
enum sos_ratelimit_result {
	/** Alert is allowed. */
	SOS_RATELIMIT_ALLOWED = 0,
	/** Alert denied: cooldown period active. */
	SOS_RATELIMIT_COOLDOWN_ACTIVE,
	/** Alert denied: hourly limit exceeded. */
	SOS_RATELIMIT_HOURLY_EXCEEDED,
};

/**
 * @brief Rate limit configuration.
 *
 * Default values per spec 18.4.3:
 * - cooldown_ms: 600000 (10 minutes)
 * - max_per_hour: 3
 */
struct sos_ratelimit_config {
	/** Minimum milliseconds between alerts from the same source. */
	uint32_t cooldown_ms;
	/** Maximum alerts per hour per source. */
	uint8_t max_per_hour;
};

/**
 * @brief Per-source rate limit state.
 *
 * Tracks timestamps of recent alerts from a single source using
 * monotonic uptime (k_uptime_get() milliseconds).
 *
 * The state stores:
 * - Timestamps of recent alerts within the hour window
 * - Number of valid entries in the timestamps array
 *
 * Use sos_ratelimit_check() to determine if an alert should be accepted,
 * then sos_ratelimit_record() to update state after accepting.
 */
struct sos_ratelimit_state {
	/**
	 * Timestamps of alerts within the current hour window.
	 * Stored as monotonic uptime in milliseconds (k_uptime_get()).
	 * Ordered oldest to newest, pruned on check.
	 */
	int64_t alert_times[SOS_RATELIMIT_MAX_TIMESTAMPS];
	/** Number of valid entries in alert_times. */
	uint8_t alert_count;
};

/**
 * @brief Initialize rate limit configuration with default values.
 *
 * Sets cooldown to 10 minutes and max_per_hour to 3.
 *
 * @param[out] config Configuration to initialize
 */
void sos_ratelimit_config_init(struct sos_ratelimit_config *config);

/**
 * @brief Initialize per-source rate limit state.
 *
 * @param[out] state State to initialize
 */
void sos_ratelimit_state_init(struct sos_ratelimit_state *state);

/**
 * @brief Check if an alert should be allowed at the given timestamp.
 *
 * Evaluates the rate limit rules against the current state:
 * 1. Hourly limit: reject if max_per_hour alerts already in window
 * 2. Cooldown: reject if last alert was within cooldown period
 *
 * Does NOT modify state. Call sos_ratelimit_record() after accepting.
 *
 * @param[in] state      Per-source state (not modified)
 * @param[in] now_ms     Current monotonic timestamp (k_uptime_get())
 * @param[in] config     Rate limit configuration
 * @param[out] remaining_ms  If denied, estimated ms until allowed (may be NULL)
 * @return SOS_RATELIMIT_ALLOWED if alert should be accepted,
 *         SOS_RATELIMIT_COOLDOWN_ACTIVE if cooldown not expired,
 *         SOS_RATELIMIT_HOURLY_EXCEEDED if hourly limit reached
 */
enum sos_ratelimit_result sos_ratelimit_check(
	const struct sos_ratelimit_state *state,
	int64_t now_ms,
	const struct sos_ratelimit_config *config,
	uint32_t *remaining_ms);

/**
 * @brief Record an accepted alert at the given timestamp.
 *
 * Call this after accepting an alert to update rate limit state.
 * Prunes old entries outside the hourly window before adding new one.
 *
 * @param[in,out] state  Per-source state to update
 * @param[in] now_ms     Current monotonic timestamp (k_uptime_get())
 */
void sos_ratelimit_record(struct sos_ratelimit_state *state, int64_t now_ms);

/**
 * @brief Check if a source has any recent activity.
 *
 * Returns true if the source has alerts within the tracking window.
 * Useful for LRU eviction when managing multiple source states.
 *
 * @param[in] state  Per-source state
 * @param[in] now_ms Current monotonic timestamp
 * @return true if source has recent activity, false if stale
 */
bool sos_ratelimit_has_activity(const struct sos_ratelimit_state *state,
				int64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SOS_RATELIMIT_H_ */
