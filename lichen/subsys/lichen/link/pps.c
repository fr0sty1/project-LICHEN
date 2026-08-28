/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/pps.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

static bool try_lock(struct lichen_pps_associator *state)
{
	return !atomic_flag_test_and_set_explicit(&state->lock,
						 memory_order_acquire);
}

static void unlock(struct lichen_pps_associator *state)
{
	atomic_flag_clear_explicit(&state->lock, memory_order_release);
}

static void increment_saturating(uint64_t *value, uint64_t increment)
{
	if (UINT64_MAX - *value < increment) {
		*value = UINT64_MAX;
	} else {
		*value += increment;
	}
}

static int elapsed_intervals(const struct lichen_pps_associator *state,
			     uint64_t edge_ns, uint64_t *intervals,
			     uint64_t *missed)
{
	uint64_t delta;
	uint64_t quotient;
	uint64_t remainder;
	uint64_t expected;
	uint64_t error;

	if (!state->has_last_edge) {
		*intervals = 1U;
		*missed = 0U;
		return 0;
	}
	if (edge_ns <= state->last_edge_ns) {
		return -ERANGE;
	}

	delta = edge_ns - state->last_edge_ns;
	quotient = delta / LICHEN_PPS_NSEC_PER_SECOND;
	remainder = delta % LICHEN_PPS_NSEC_PER_SECOND;
	if (remainder >= LICHEN_PPS_NSEC_PER_SECOND / 2U) {
		if (quotient == UINT64_MAX) {
			return -ERANGE;
		}
		quotient++;
	}
	if (quotient == 0U ||
	    quotient > UINT64_MAX / LICHEN_PPS_NSEC_PER_SECOND) {
		return -ERANGE;
	}

	expected = quotient * LICHEN_PPS_NSEC_PER_SECOND;
	error = delta >= expected ? delta - expected : expected - delta;
	if (error > state->maximum_edge_jitter_ns) {
		return -ERANGE;
	}

	*intervals = quotient;
	*missed = quotient - 1U;
	return 0;
}

int lichen_pps_associator_init(struct lichen_pps_associator *state,
			       uint64_t firmware_epoch_floor_s,
			       uint64_t maximum_message_delay_ns,
			       uint64_t maximum_edge_jitter_ns,
			       uint32_t source_generation)
{
	if (state == NULL || firmware_epoch_floor_s == 0U ||
	    firmware_epoch_floor_s > UINT64_MAX / LICHEN_PPS_USEC_PER_SECOND ||
	    maximum_message_delay_ns == 0U ||
	    maximum_edge_jitter_ns >= LICHEN_PPS_NSEC_PER_SECOND / 2U ||
	    source_generation == 0U) {
		return -EINVAL;
	}

	memset(state, 0, sizeof(*state));
	atomic_flag_clear_explicit(&state->lock, memory_order_relaxed);
	state->firmware_epoch_floor_s = firmware_epoch_floor_s;
	state->maximum_message_delay_ns = maximum_message_delay_ns;
	state->maximum_edge_jitter_ns = maximum_edge_jitter_ns;
	state->source_generation = source_generation;
	state->initialized = true;
	return 0;
}

int lichen_pps_capture_edge_isr(struct lichen_pps_associator *state,
				uint64_t edge_monotonic_ns,
				struct lichen_pps_capture_result *result)
{
	struct lichen_pps_capture_result captured;
	uint64_t intervals;
	uint64_t missed;
	int ret;

	if (state == NULL || result == NULL || !state->initialized) {
		return -EINVAL;
	}
	if (!try_lock(state)) {
		return -EBUSY;
	}

	ret = elapsed_intervals(state, edge_monotonic_ns, &intervals, &missed);
	if (ret != 0) {
		increment_saturating(&state->rejected_edges, 1U);
		unlock(state);
		return ret;
	}

	captured = (struct lichen_pps_capture_result) {
		.replaced_unassociated = state->has_pending_edge,
		.previous_edge_ns = state->has_pending_edge ?
			state->pending_edge_ns : 0U,
		.elapsed_intervals = intervals,
		.missed_pulses = missed,
	};
	if (state->has_pending_edge && state->has_last_association) {
		if (UINT64_MAX - state->pending_intervals < intervals) {
			increment_saturating(&state->rejected_edges, 1U);
			unlock(state);
			return -ERANGE;
		}
		intervals += state->pending_intervals;
	}
	if (state->has_pending_edge) {
		increment_saturating(&state->replaced_edges, 1U);
	}
	increment_saturating(&state->missed_pulses, missed);
	state->last_edge_ns = edge_monotonic_ns;
	state->has_last_edge = true;
	state->pending_edge_ns = edge_monotonic_ns;
	state->pending_intervals = intervals;
	state->has_pending_edge = true;
	unlock(state);

	*result = captured;
	return 0;
}

int lichen_pps_associate(struct lichen_pps_associator *state,
			 const struct lichen_pps_gnss_sample *sample,
			 struct lichen_pps_association *result)
{
	struct lichen_pps_association associated;
	uint64_t delay_ns;
	uint64_t expected_second_delta;
	int ret = 0;

	if (state == NULL || sample == NULL || result == NULL ||
	    !state->initialized) {
		return -EINVAL;
	}
	if (!try_lock(state)) {
		return -EBUSY;
	}
	if (!state->has_pending_edge) {
		ret = -EAGAIN;
	} else if (!sample->time_valid || !sample->source_authenticated ||
		   sample->scale != LICHEN_PPS_TIME_SCALE_UNIX_UTC ||
		   sample->source_generation != state->source_generation) {
		ret = -EACCES;
	} else if (state->has_last_message &&
		   sample->message_monotonic_ns <= state->last_message_ns) {
		ret = -ERANGE;
	} else if (sample->message_monotonic_ns < state->pending_edge_ns) {
		ret = -ERANGE;
	} else {
		delay_ns = sample->message_monotonic_ns - state->pending_edge_ns;
		if (delay_ns > state->maximum_message_delay_ns) {
			ret = -ESTALE;
		} else if (sample->unix_second < state->firmware_epoch_floor_s) {
			ret = -ESTALE;
		} else if (state->has_last_gnss_second &&
			   sample->unix_second <= state->last_gnss_second) {
			ret = -ERANGE;
		} else if (sample->unix_second >
			   UINT64_MAX / LICHEN_PPS_USEC_PER_SECOND) {
			ret = -EOVERFLOW;
		} else {
			expected_second_delta = state->pending_intervals;
			if (state->has_last_association &&
			    sample->unix_second - state->last_gnss_second !=
				expected_second_delta) {
				ret = -EBADMSG;
			} else {
				associated = (struct lichen_pps_association) {
					.edge_monotonic_ns = state->pending_edge_ns,
					.message_monotonic_ns =
						sample->message_monotonic_ns,
					.unix_second = sample->unix_second,
					.unix_time_us = sample->unix_second *
						LICHEN_PPS_USEC_PER_SECOND,
					.message_delay_ns = delay_ns,
					.elapsed_intervals =
						state->pending_intervals,
				};
			}
		}
	}

	if (ret != 0) {
		increment_saturating(&state->rejected_associations, 1U);
		unlock(state);
		return ret;
	}

	state->has_pending_edge = false;
	state->last_message_ns = sample->message_monotonic_ns;
	state->has_last_message = true;
	state->last_gnss_second = sample->unix_second;
	state->has_last_gnss_second = true;
	state->last_association = associated;
	state->has_last_association = true;
	unlock(state);

	*result = associated;
	return 0;
}

int lichen_pps_discard_pending(struct lichen_pps_associator *state,
			       uint64_t *discarded_edge_ns)
{
	uint64_t discarded;

	if (state == NULL || discarded_edge_ns == NULL || !state->initialized) {
		return -EINVAL;
	}
	if (!try_lock(state)) {
		return -EBUSY;
	}
	if (!state->has_pending_edge) {
		unlock(state);
		return -EAGAIN;
	}
	discarded = state->pending_edge_ns;
	state->has_pending_edge = false;
	unlock(state);

	*discarded_edge_ns = discarded;
	return 0;
}

int lichen_pps_associator_reset(struct lichen_pps_associator *state,
				uint32_t source_generation)
{
	if (state == NULL || !state->initialized || source_generation == 0U) {
		return -EINVAL;
	}
	if (!try_lock(state)) {
		return -EBUSY;
	}
	state->source_generation = source_generation;
	state->has_last_edge = false;
	state->has_pending_edge = false;
	state->has_last_message = false;
	state->has_last_gnss_second = false;
	state->has_last_association = false;
	state->last_edge_ns = 0U;
	state->pending_edge_ns = 0U;
	state->pending_intervals = 0U;
	state->last_message_ns = 0U;
	state->last_gnss_second = 0U;
	memset(&state->last_association, 0, sizeof(state->last_association));
	unlock(state);
	return 0;
}

int lichen_pps_snapshot_get(struct lichen_pps_associator *state,
			    struct lichen_pps_snapshot *snapshot)
{
	struct lichen_pps_snapshot current;

	if (state == NULL || snapshot == NULL || !state->initialized) {
		return -EINVAL;
	}
	if (!try_lock(state)) {
		return -EBUSY;
	}
	current = (struct lichen_pps_snapshot) {
		.pending = state->has_pending_edge,
		.pending_edge_ns = state->has_pending_edge ?
			state->pending_edge_ns : 0U,
		.associated = state->has_last_association,
		.last_association = state->last_association,
		.replaced_edges = state->replaced_edges,
		.missed_pulses = state->missed_pulses,
		.rejected_edges = state->rejected_edges,
		.rejected_associations = state->rejected_associations,
		.source_generation = state->source_generation,
	};
	unlock(state);

	*snapshot = current;
	return 0;
}
