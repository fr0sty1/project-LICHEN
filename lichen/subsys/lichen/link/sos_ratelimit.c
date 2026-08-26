/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file sos_ratelimit.c
 * @brief SOS rate limiting with monotonic uptime (spec 18.4.3)
 *
 * Implementation of per-source rate limiting for SOS alerts.
 * Uses monotonic uptime timestamps to avoid wall-clock issues.
 */

#include <lichen/sos_ratelimit.h>
#include <string.h>

void sos_ratelimit_config_init(struct sos_ratelimit_config *config)
{
	if (config == NULL) {
		return;
	}
	config->cooldown_ms = SOS_RATELIMIT_COOLDOWN_MS;
	config->max_per_hour = SOS_RATELIMIT_MAX_PER_HOUR;
	config->burst_allowance = SOS_RATELIMIT_BURST_ALLOWANCE;
}

void sos_ratelimit_state_init(struct sos_ratelimit_state *state)
{
	if (state == NULL) {
		return;
	}
	memset(state->alert_times, 0, sizeof(state->alert_times));
	state->alert_count = 0;
}

/**
 * @brief Count alerts within the hourly window.
 */
static uint8_t count_in_window(const struct sos_ratelimit_state *state,
			       int64_t cutoff_ms)
{
	uint8_t count = 0;

	for (uint8_t i = 0; i < state->alert_count; i++) {
		if (state->alert_times[i] >= cutoff_ms) {
			count++;
		}
	}
	return count;
}

/**
 * @brief Find the oldest alert timestamp within the window.
 *
 * @return Oldest timestamp in window, or 0 if none found.
 */
static int64_t oldest_in_window(const struct sos_ratelimit_state *state,
				int64_t cutoff_ms)
{
	int64_t oldest = 0;
	bool found = false;

	for (uint8_t i = 0; i < state->alert_count; i++) {
		if (state->alert_times[i] >= cutoff_ms) {
			if (!found || state->alert_times[i] < oldest) {
				oldest = state->alert_times[i];
				found = true;
			}
		}
	}
	return oldest;
}

/**
 * @brief Get the most recent alert timestamp.
 *
 * @return Most recent timestamp, or 0 if no alerts recorded.
 */
static int64_t most_recent(const struct sos_ratelimit_state *state)
{
	if (state->alert_count == 0) {
		return 0;
	}
	/* Timestamps are stored oldest-to-newest, so last valid is most recent */
	return state->alert_times[state->alert_count - 1];
}

/**
 * @brief Prune alert timestamps older than the cutoff.
 *
 * Compacts the array by removing entries older than cutoff_ms.
 */
static void prune_old(struct sos_ratelimit_state *state, int64_t cutoff_ms)
{
	uint8_t write_idx = 0;

	for (uint8_t read_idx = 0; read_idx < state->alert_count; read_idx++) {
		if (state->alert_times[read_idx] >= cutoff_ms) {
			state->alert_times[write_idx] = state->alert_times[read_idx];
			write_idx++;
		}
	}
	state->alert_count = write_idx;
}

enum sos_ratelimit_result sos_ratelimit_check(
	const struct sos_ratelimit_state *state,
	int64_t now_ms,
	const struct sos_ratelimit_config *config,
	uint32_t *remaining_ms)
{
	if (state == NULL || config == NULL) {
		/* Defensive: allow if state is invalid */
		return SOS_RATELIMIT_ALLOWED;
	}

	/* Calculate hourly window cutoff */
	int64_t hour_ago = now_ms - (int64_t)SOS_RATELIMIT_HOUR_MS;
	if (hour_ago < 0) {
		hour_ago = 0;
	}

	/* Check hourly limit first (more restrictive) */
	uint8_t valid_count = count_in_window(state, hour_ago);
	if (valid_count >= config->max_per_hour) {
		int64_t oldest = oldest_in_window(state, hour_ago);
		if (remaining_ms != NULL && oldest > 0) {
			/* Time until oldest alert exits the window */
			int64_t reset_at = oldest + (int64_t)SOS_RATELIMIT_HOUR_MS;
			if (reset_at > now_ms) {
				*remaining_ms = (uint32_t)(reset_at - now_ms);
			} else {
				*remaining_ms = 0;
			}
		}
		return SOS_RATELIMIT_HOURLY_EXCEEDED;
	}

	/* Check cooldown from most recent alert (only after burst exhausted) */
	if (valid_count >= config->burst_allowance) {
		int64_t last = most_recent(state);
		if (last > 0) {
			int64_t elapsed = now_ms - last;
			if (elapsed < (int64_t)config->cooldown_ms) {
				if (remaining_ms != NULL) {
					*remaining_ms = (uint32_t)((int64_t)config->cooldown_ms - elapsed);
				}
				return SOS_RATELIMIT_COOLDOWN_ACTIVE;
			}
		}
	}

	return SOS_RATELIMIT_ALLOWED;
}

void sos_ratelimit_record(struct sos_ratelimit_state *state, int64_t now_ms)
{
	if (state == NULL) {
		return;
	}

	/* Prune entries outside the hourly window */
	int64_t hour_ago = now_ms - (int64_t)SOS_RATELIMIT_HOUR_MS;
	if (hour_ago < 0) {
		hour_ago = 0;
	}
	prune_old(state, hour_ago);

	/* Add new timestamp */
	if (state->alert_count < SOS_RATELIMIT_MAX_TIMESTAMPS) {
		/* Space available, just append */
		state->alert_times[state->alert_count] = now_ms;
		state->alert_count++;
	} else {
		/* Array full, shift out oldest and append */
		for (uint8_t i = 0; i < SOS_RATELIMIT_MAX_TIMESTAMPS - 1; i++) {
			state->alert_times[i] = state->alert_times[i + 1];
		}
		state->alert_times[SOS_RATELIMIT_MAX_TIMESTAMPS - 1] = now_ms;
	}
}

bool sos_ratelimit_has_activity(const struct sos_ratelimit_state *state,
				int64_t now_ms)
{
	if (state == NULL || state->alert_count == 0) {
		return false;
	}

	/* Check if any alert is within the hourly window */
	int64_t hour_ago = now_ms - (int64_t)SOS_RATELIMIT_HOUR_MS;
	if (hour_ago < 0) {
		hour_ago = 0;
	}

	return count_in_window(state, hour_ago) > 0;
}
