/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/link.h>

#include <errno.h>
#include <limits.h>
#include <string.h>

static uint64_t magnitude_i64(int64_t value)
{
	return value < 0 ? (uint64_t)(-(value + 1)) + 1u : (uint64_t)value;
}

struct wide_u128 {
	uint64_t high;
	uint64_t low;
};

static struct wide_u128 multiply_u64(uint64_t left, uint64_t right)
{
	uint64_t left_low = (uint32_t)left;
	uint64_t left_high = left >> 32;
	uint64_t right_low = (uint32_t)right;
	uint64_t right_high = right >> 32;
	uint64_t product_low = left_low * right_low;
	uint64_t product_cross_a = left_low * right_high;
	uint64_t product_cross_b = left_high * right_low;
	uint64_t middle = (product_low >> 32) +
			  (uint32_t)product_cross_a +
			  (uint32_t)product_cross_b;

	return (struct wide_u128) {
		.high = left_high * right_high + (product_cross_a >> 32) +
			(product_cross_b >> 32) + (middle >> 32),
		.low = (middle << 32) | (uint32_t)product_low,
	};
}

static bool divide_u128_u64(struct wide_u128 numerator, uint64_t denominator,
			    uint64_t *quotient, uint64_t *remainder)
{
	if (denominator == 0u || numerator.high >= denominator) {
		return false;
	}

	uint64_t result = 0u;
	uint64_t rem = numerator.high;
	for (int bit = 63; bit >= 0; --bit) {
		bool carry = (rem >> 63) != 0u;
		rem = (rem << 1) | ((numerator.low >> bit) & 1u);
		if (carry || rem >= denominator) {
			rem -= denominator;
			result |= UINT64_C(1) << bit;
		}
	}
	*quotient = result;
	if (remainder != NULL) {
		*remainder = rem;
	}
	return true;
}

static int signed_scaled_ratio(bool negative, uint64_t magnitude,
			       uint64_t multiplier, uint64_t divisor,
			       int64_t *result)
{
	uint64_t quotient;
	if (!divide_u128_u64(multiply_u64(magnitude, multiplier), divisor,
			     &quotient, NULL)) {
		return -ERANGE;
	}
	if ((!negative && quotient > INT64_MAX) ||
	    (negative && quotient > (UINT64_C(1) << 63))) {
		return -ERANGE;
	}
	if (negative && quotient == (UINT64_C(1) << 63)) {
		*result = INT64_MIN;
	} else {
		*result = negative ? -(int64_t)quotient : (int64_t)quotient;
	}
	return 0;
}

static void signed_difference(int64_t left, int64_t right,
			      bool *negative, uint64_t *magnitude)
{
	if (left >= right) {
		*negative = false;
		*magnitude = (uint64_t)left - (uint64_t)right;
	} else {
		*negative = true;
		*magnitude = (uint64_t)right - (uint64_t)left;
	}
}

static bool source_valid(enum lichen_time_source_class source)
{
	switch (source) {
	case LICHEN_TIME_SOURCE_GNSS:
	case LICHEN_TIME_SOURCE_NETWORK:
	case LICHEN_TIME_SOURCE_LOCAL_CLIENT:
	case LICHEN_TIME_SOURCE_MANUAL:
	case LICHEN_TIME_SOURCE_INTERNAL_RTC:
		return true;
	case LICHEN_TIME_SOURCE_MONOTONIC:
	default:
		return false;
	}
}

static bool tracker_try_lock(struct lichen_drift_tracker *tracker)
{
	return !atomic_flag_test_and_set_explicit(&tracker->lock,
						 memory_order_acquire);
}

static void tracker_unlock(struct lichen_drift_tracker *tracker)
{
	atomic_flag_clear_explicit(&tracker->lock, memory_order_release);
}

int lichen_drift_bound_compute(uint64_t initial_bound, uint64_t rate,
			       uint64_t elapsed, uint64_t *bound)
{
	if (bound == NULL) {
		return -EINVAL;
	}

	uint64_t candidate;
	if (rate != 0u && elapsed > (UINT64_MAX - initial_bound) / rate) {
		candidate = UINT64_MAX;
	} else {
		candidate = initial_bound + rate * elapsed;
	}
	*bound = candidate;
	return 0;
}

int lichen_drift_ppm_compute(int64_t delta_ms, uint64_t interval_ms,
			     int64_t *drift_ppm)
{
	if (drift_ppm == NULL || interval_ms == 0u) {
		return -EINVAL;
	}

	return signed_scaled_ratio(delta_ms < 0, magnitude_i64(delta_ms),
				   1000000u, interval_ms, drift_ppm);
}

int lichen_drift_correction_ms(int64_t drift_ppm, int64_t future_delta_ms,
			       int64_t *correction_ms)
{
	if (correction_ms == NULL) {
		return -EINVAL;
	}

	bool negative = (drift_ppm < 0) != (future_delta_ms < 0);
	return signed_scaled_ratio(negative, magnitude_i64(drift_ppm),
				   magnitude_i64(future_delta_ms), 1000000u,
				   correction_ms);
}

bool lichen_drift_holdover_expired(int64_t measured_drift_ppm,
				    uint32_t guard_ppm)
{
	return magnitude_i64(measured_drift_ppm) > guard_ppm;
}

int lichen_drift_tracker_init(struct lichen_drift_tracker *tracker,
			      uint32_t oscillator_bound_ppm,
			      uint32_t max_holdover_ppm)
{
	if (tracker == NULL || oscillator_bound_ppm == 0u ||
	    max_holdover_ppm == 0u ||
	    oscillator_bound_ppm > max_holdover_ppm) {
		return -EINVAL;
	}

	memset(tracker, 0, sizeof(*tracker));
	atomic_flag_clear_explicit(&tracker->lock, memory_order_release);
	tracker->oscillator_bound_ppm = oscillator_bound_ppm;
	tracker->max_holdover_ppm = max_holdover_ppm;
	tracker->source = LICHEN_TIME_SOURCE_MONOTONIC;
	tracker->initialized = true;
	return 0;
}

int lichen_drift_tracker_observe(struct lichen_drift_tracker *tracker,
				 enum lichen_time_source_class source,
				 uint64_t observed_monotonic_ms,
				 int64_t offset_ms,
				 uint64_t measurement_bound_us)
{
	if (tracker == NULL || !tracker->initialized || !source_valid(source)) {
		return -EINVAL;
	}
	if (!tracker_try_lock(tracker)) {
		return -EBUSY;
	}

	if (tracker->has_observation &&
	    observed_monotonic_ms < tracker->last_observed_ms) {
		tracker->expired = true;
		tracker_unlock(tracker);
		return -ERANGE;
	}

	if (!tracker->has_observation || source != tracker->source) {
		tracker->last_observed_ms = observed_monotonic_ms;
		tracker->last_offset_ms = offset_ms;
		tracker->base_bound_us = measurement_bound_us;
		tracker->measured_drift_ppm = 0;
		tracker->source = source;
		tracker->has_observation = true;
		tracker->has_rate_estimate = false;
		tracker->expired = false;
		tracker_unlock(tracker);
		return 0;
	}

	uint64_t interval_ms = observed_monotonic_ms - tracker->last_observed_ms;
	if (interval_ms == 0u) {
		tracker->expired = offset_ms != tracker->last_offset_ms;
		tracker_unlock(tracker);
		return offset_ms == tracker->last_offset_ms ? 0 : -ERANGE;
	}

	bool negative;
	uint64_t offset_magnitude;
	int64_t measured_ppm;
	signed_difference(offset_ms, tracker->last_offset_ms, &negative,
			  &offset_magnitude);
	if (signed_scaled_ratio(negative, offset_magnitude, 1000000u,
				interval_ms, &measured_ppm) < 0) {
		tracker->expired = true;
		tracker_unlock(tracker);
		return -ERANGE;
	}
	if (lichen_drift_holdover_expired(measured_ppm,
					  tracker->max_holdover_ppm)) {
		tracker->measured_drift_ppm = measured_ppm;
		tracker->has_rate_estimate = true;
		tracker->expired = true;
		tracker_unlock(tracker);
		return -ERANGE;
	}

	tracker->last_observed_ms = observed_monotonic_ms;
	tracker->last_offset_ms = offset_ms;
	tracker->base_bound_us = measurement_bound_us;
	tracker->measured_drift_ppm = measured_ppm;
	tracker->has_rate_estimate = true;
	tracker->expired = false;
	tracker_unlock(tracker);
	return 0;
}

int lichen_drift_tracker_snapshot(struct lichen_drift_tracker *tracker,
				  uint64_t now_monotonic_ms,
				  struct lichen_drift_snapshot *snapshot)
{
	if (tracker == NULL || snapshot == NULL || !tracker->initialized) {
		return -EINVAL;
	}
	if (!tracker_try_lock(tracker)) {
		return -EBUSY;
	}
	if (!tracker->has_observation) {
		tracker_unlock(tracker);
		return -EAGAIN;
	}
	if (now_monotonic_ms < tracker->last_observed_ms) {
		tracker->expired = true;
		tracker_unlock(tracker);
		return -ERANGE;
	}

	uint64_t age_ms = now_monotonic_ms - tracker->last_observed_ms;
	uint64_t measured_rate = magnitude_i64(tracker->measured_drift_ppm);
	uint32_t rate_bound_ppm = tracker->oscillator_bound_ppm;
	if (measured_rate > rate_bound_ppm) {
		rate_bound_ppm = measured_rate > UINT32_MAX ? UINT32_MAX :
				 (uint32_t)measured_rate;
	}
	uint64_t growth;
	uint64_t remainder;
	if (!divide_u128_u64(multiply_u64(rate_bound_ppm, age_ms), 1000u,
			     &growth, &remainder)) {
		growth = UINT64_MAX;
	} else if (remainder != 0u) {
		growth = growth == UINT64_MAX ? UINT64_MAX : growth + 1u;
	}
	uint64_t bound = tracker->base_bound_us > UINT64_MAX - growth ?
			 UINT64_MAX : tracker->base_bound_us + growth;

	struct lichen_drift_snapshot candidate = {
		.age_ms = age_ms,
		.error_bound_us = bound,
		.measured_drift_ppm = tracker->measured_drift_ppm,
		.rate_bound_ppm = rate_bound_ppm,
		.source = tracker->source,
		.has_rate_estimate = tracker->has_rate_estimate,
		.expired = tracker->expired,
	};
	*snapshot = candidate;
	tracker_unlock(tracker);
	return 0;
}

static bool add_uncertainty(uint64_t *total, uint64_t value)
{
	if (*total > UINT64_MAX - value) {
		return false;
	}
	*total += value;
	return true;
}

int lichen_holdover_evaluate(struct lichen_drift_tracker *tracker,
			     uint64_t now_monotonic_ms,
			     const struct lichen_holdover_policy *policy,
			     struct lichen_holdover_decision *decision)
{
	if (tracker == NULL || policy == NULL || decision == NULL) {
		return -EINVAL;
	}

	struct lichen_holdover_decision candidate = {
		.state = LICHEN_HOLDOVER_INVALID,
		.tx_allowed = false,
	};
	int result = lichen_drift_tracker_snapshot(
		tracker, now_monotonic_ms, &candidate.drift);
	if (result == -EAGAIN) {
		*decision = candidate;
		return 0;
	}
	if (result < 0) {
		return result;
	}

	uint64_t required = candidate.drift.error_bound_us;
	bool budget_valid = add_uncertainty(&required, policy->peer_bound_us) &&
		add_uncertainty(&required, policy->local_jitter_us) &&
		add_uncertainty(&required, policy->peer_jitter_us) &&
		add_uncertainty(&required, policy->propagation_us) &&
		add_uncertainty(&required, policy->margin_us);
	candidate.required_guard_us = budget_valid ? required : UINT64_MAX;
	bool age_valid = candidate.drift.age_ms <= policy->max_holdover_ms;
	bool guard_valid = budget_valid && policy->guard_us >= required;
	if (candidate.drift.expired || !age_valid || !guard_valid) {
		candidate.state = LICHEN_HOLDOVER_EXPIRED;
	} else {
		candidate.state = candidate.drift.age_ms == 0u ?
			LICHEN_HOLDOVER_FRESH : LICHEN_HOLDOVER_VALID;
		candidate.remaining_guard_us = policy->guard_us - required;
		candidate.tx_allowed = true;
	}

	*decision = candidate;
	return 0;
}

bool lichen_holdover_tx_allowed(struct lichen_drift_tracker *tracker,
				 uint64_t now_monotonic_ms,
				 const struct lichen_holdover_policy *policy)
{
	struct lichen_holdover_decision decision;
	return lichen_holdover_evaluate(tracker, now_monotonic_ms, policy,
					&decision) == 0 && decision.tx_allowed;
}
