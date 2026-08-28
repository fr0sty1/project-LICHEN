/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <lichen/link.h>

#include "drift_bound_vectors.h"

#ifdef CONFIG_ZTEST
#include <zephyr/ztest.h>
#define CHECK(condition, ...) zassert_true(condition, __VA_ARGS__)
#else
#include <pthread.h>
#include <stdio.h>
#define CHECK(condition, ...)                                                   \
	do {                                                                      \
		if (!(condition)) {                                                 \
			fprintf(stderr, __VA_ARGS__);                                 \
			fprintf(stderr, "\n");                                      \
			return false;                                                  \
		}                                                                 \
	} while (0)
#endif

#ifndef CONFIG_ZTEST
struct snapshot_worker {
	struct lichen_drift_tracker *tracker;
	atomic_uint *successes;
	atomic_uint *busy;
	atomic_uint *errors;
};

static void *run_snapshot_worker(void *argument)
{
	struct snapshot_worker *worker = argument;
	struct lichen_drift_snapshot snapshot;
	int result = lichen_drift_tracker_snapshot(worker->tracker, 1000u,
						   &snapshot);
	if (result == 0 && snapshot.age_ms == 1000u && !snapshot.expired) {
		atomic_fetch_add_explicit(worker->successes, 1u,
					  memory_order_relaxed);
	} else if (result == -EBUSY) {
		atomic_fetch_add_explicit(worker->busy, 1u, memory_order_relaxed);
	} else {
		atomic_fetch_add_explicit(worker->errors, 1u,
					  memory_order_relaxed);
	}
	return NULL;
}
#endif

static bool test_canonical_vectors(void)
{
	for (size_t i = 0u; i < DRIFT_BOUND_VECTOR_COUNT; ++i) {
		uint64_t actual = UINT64_MAX;
		CHECK(lichen_drift_bound_compute(
			      drift_bound_vectors[i].initial_bound,
			      drift_bound_vectors[i].rate,
			      drift_bound_vectors[i].elapsed, &actual) == 0,
		      "%s: bound calculation failed", drift_bound_vectors[i].name);
		CHECK(actual == drift_bound_vectors[i].expected,
		      "%s: bound mismatch", drift_bound_vectors[i].name);
	}
	for (size_t i = 0u; i < HOLDOVER_VECTOR_COUNT; ++i) {
		CHECK(lichen_drift_holdover_expired(
			      holdover_vectors[i].measured_ppm,
			      holdover_vectors[i].guard_ppm) ==
			      holdover_vectors[i].expected_expired,
		      "%s: holdover decision mismatch", holdover_vectors[i].name);
	}
	for (size_t i = 0u; i < DRIFT_PPM_VECTOR_COUNT; ++i) {
		int64_t ppm = INT64_MAX;
		int64_t correction = INT64_MAX;
		CHECK(lichen_drift_ppm_compute(drift_ppm_vectors[i].delta_ms,
					       drift_ppm_vectors[i].interval_ms,
					       &ppm) == 0,
		      "%s: ppm calculation failed", drift_ppm_vectors[i].name);
		CHECK(ppm == drift_ppm_vectors[i].expected_ppm,
		      "%s: ppm mismatch", drift_ppm_vectors[i].name);
		CHECK(lichen_drift_correction_ms(
			      ppm, drift_ppm_vectors[i].future_delta_ms,
			      &correction) == 0,
		      "%s: correction failed", drift_ppm_vectors[i].name);
		CHECK(correction == drift_ppm_vectors[i].expected_correction_ms,
		      "%s: correction mismatch", drift_ppm_vectors[i].name);
	}
	return true;
}

static bool test_formula_edges(void)
{
	uint64_t bound = 77u;
	int64_t value = 88;
	CHECK(lichen_drift_bound_compute(UINT64_MAX, 1u, 1u, &bound) == 0 &&
	      bound == UINT64_MAX,
	      "bound overflow did not saturate");
	CHECK(lichen_drift_bound_compute(0u, 0u, UINT64_MAX, &bound) == 0 &&
	      bound == 0u,
	      "zero-rate bound changed");
	CHECK(lichen_drift_ppm_compute(1, 0u, &value) == -EINVAL && value == 88,
	      "zero interval mutated ppm output");
	CHECK(lichen_drift_ppm_compute(INT64_MIN, 1000000u, &value) == 0 &&
	      value == INT64_MIN,
	      "portable wide division mishandled INT64_MIN");
	value = 88;
	CHECK(lichen_drift_ppm_compute(INT64_MAX, 1u, &value) == -ERANGE &&
	      value == 88,
	      "overflowing ppm estimate did not fail atomically");
	CHECK(lichen_drift_correction_ms(INT64_MAX, INT64_MAX, &value) == -ERANGE &&
	      value == 88,
	      "overflowing correction did not fail atomically");
	CHECK(lichen_drift_holdover_expired(INT64_MIN, UINT32_MAX),
	      "INT64_MIN magnitude was not handled safely");
	return true;
}

static bool test_tracker_source_holdover_and_wrap(void)
{
	struct lichen_drift_tracker tracker;
	struct lichen_drift_snapshot snapshot;
	const struct lichen_drift_snapshot sentinel = {
		.age_ms = UINT64_C(0x1111111111111111),
		.error_bound_us = UINT64_C(0x2222222222222222),
	};

	CHECK(lichen_drift_tracker_init(&tracker, 0u, 5000u) == -EINVAL,
	      "zero oscillator bound accepted");
	CHECK(lichen_drift_tracker_init(&tracker, 5001u, 5000u) == -EINVAL,
	      "oscillator bound above holdover threshold accepted");
	CHECK(lichen_drift_tracker_init(
		      &tracker, LICHEN_DRIFT_TYPICAL_TCXO_PPM,
		      LICHEN_DRIFT_MAX_HOLDOVER_PPM) == 0,
	      "typical TCXO tracker init failed");
	snapshot = sentinel;
	CHECK(lichen_drift_tracker_snapshot(&tracker, 0u, &snapshot) == -EAGAIN &&
	      memcmp(&snapshot, &sentinel, sizeof(snapshot)) == 0,
	      "empty tracker snapshot was not output-atomic");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_MONOTONIC, 1000u, 0, 10u) == -EINVAL,
	      "monotonic-only source established drift reference");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 1000u, 0, 10u) == 0,
	      "initial GNSS observation failed");
	CHECK(lichen_drift_tracker_snapshot(&tracker, 6000u, &snapshot) == 0,
	      "initial holdover snapshot failed");
	CHECK(snapshot.source == LICHEN_TIME_SOURCE_GNSS &&
	      !snapshot.has_rate_estimate && !snapshot.expired &&
	      snapshot.age_ms == 5000u && snapshot.rate_bound_ppm == 20u &&
	      snapshot.error_bound_us == 110u,
	      "typical TCXO error envelope mismatch");

	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 101000u, 1, 20u) == 0,
	      "10ppm observation failed");
	CHECK(lichen_drift_tracker_snapshot(&tracker, 102000u, &snapshot) == 0,
	      "estimated snapshot failed");
	CHECK(snapshot.has_rate_estimate && snapshot.measured_drift_ppm == 10 &&
	      snapshot.rate_bound_ppm == 20u && snapshot.error_bound_us == 40u,
	      "measured drift/error envelope mismatch");

	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_NETWORK, 102000u, INT64_MAX, 30u) == 0,
	      "source change did not reset estimator");
	CHECK(lichen_drift_tracker_snapshot(&tracker, 102000u, &snapshot) == 0 &&
	      snapshot.source == LICHEN_TIME_SOURCE_NETWORK &&
	      !snapshot.has_rate_estimate && snapshot.measured_drift_ppm == 0 &&
	      snapshot.error_bound_us == 30u,
	      "source-change baseline mismatch");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_NETWORK, 102000u, INT64_MIN, 30u) ==
		      -ERANGE,
	      "contradictory duplicate sample accepted");
	CHECK(lichen_drift_tracker_snapshot(&tracker, 102000u, &snapshot) == 0 &&
	      snapshot.expired,
	      "duplicate-sample outlier did not expire holdover");

	CHECK(lichen_drift_tracker_init(&tracker, 20u, 5000u) == 0,
	      "outlier tracker init failed");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 0u, 0, 1u) == 0,
	      "outlier baseline failed");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 1000u, 5, 1u) == 0,
	      "5000ppm threshold should remain valid");
	CHECK(lichen_drift_tracker_snapshot(&tracker, 1000u, &snapshot) == 0 &&
	      !snapshot.expired && snapshot.measured_drift_ppm == 5000,
	      "threshold state mismatch");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 2000u, 11, 1u) == -ERANGE,
	      "6000ppm outlier accepted");
	CHECK(lichen_drift_tracker_snapshot(&tracker, 2000u, &snapshot) == 0 &&
	      snapshot.expired && snapshot.measured_drift_ppm == 6000,
	      "outlier expiry state mismatch");

	CHECK(lichen_drift_tracker_init(&tracker, 20u, 5000u) == 0,
	      "wrap tracker init failed");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, UINT64_MAX - 10u, 0, 1u) == 0,
	      "near-wrap baseline failed");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 5u, 0, 1u) == -ERANGE,
	      "timestamp wrap accepted");
	CHECK(lichen_drift_tracker_snapshot(&tracker, UINT64_MAX, &snapshot) == 0 &&
	      snapshot.expired,
	      "wrap did not expire holdover");

	CHECK(lichen_drift_tracker_init(&tracker, 5000u, 5000u) == 0,
	      "maximum-rate tracker init failed");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 0u, 0, UINT64_MAX - 1u) == 0,
	      "maximum-bound baseline failed");
	CHECK(lichen_drift_tracker_snapshot(&tracker, UINT64_MAX, &snapshot) == 0 &&
	      snapshot.error_bound_us == UINT64_MAX,
	      "maximum holdover envelope did not saturate");
	return true;
}

static bool test_contention_fails_closed(void)
{
	struct lichen_drift_tracker tracker;
	struct lichen_drift_snapshot snapshot = { .age_ms = 99u };
	CHECK(lichen_drift_tracker_init(&tracker, 20u, 5000u) == 0,
	      "contention tracker init failed");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 0u, 0, 1u) == 0,
	      "contention baseline failed");
	(void)atomic_flag_test_and_set_explicit(&tracker.lock, memory_order_acquire);
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 1000u, 0, 1u) == -EBUSY,
	      "contended update did not fail closed");
	CHECK(lichen_drift_tracker_snapshot(&tracker, 1000u, &snapshot) == -EBUSY &&
	      snapshot.age_ms == 99u,
	      "contended snapshot mutated output");
	atomic_flag_clear_explicit(&tracker.lock, memory_order_release);
	return true;
}

static bool test_holdover_policy(void)
{
	struct lichen_drift_tracker tracker;
	struct lichen_holdover_decision decision;
	const struct lichen_holdover_decision sentinel = {
		.required_guard_us = UINT64_C(0x1122334455667788),
	};
	struct lichen_holdover_policy policy = {
		.guard_us = 150u,
		.peer_bound_us = 10u,
		.local_jitter_us = 5u,
		.peer_jitter_us = 5u,
		.propagation_us = 5u,
		.margin_us = 5u,
		.max_holdover_ms = 6000u,
	};

	CHECK(lichen_drift_tracker_init(&tracker, 20u, 5000u) == 0,
	      "holdover tracker init failed");
	CHECK(lichen_holdover_evaluate(&tracker, 0u, &policy, &decision) == 0 &&
	      decision.state == LICHEN_HOLDOVER_INVALID && !decision.tx_allowed,
	      "unreferenced holdover did not fail closed");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 0u, 0, 10u) == 0,
	      "holdover reference failed");
	CHECK(lichen_holdover_evaluate(&tracker, 0u, &policy, &decision) == 0 &&
	      decision.state == LICHEN_HOLDOVER_FRESH && decision.tx_allowed &&
	      decision.required_guard_us == 40u &&
	      decision.remaining_guard_us == 110u,
	      "fresh holdover decision mismatch");
	CHECK(lichen_holdover_evaluate(&tracker, 5500u, &policy, &decision) == 0 &&
	      decision.state == LICHEN_HOLDOVER_VALID && decision.tx_allowed &&
	      decision.required_guard_us == 150u &&
	      decision.remaining_guard_us == 0u,
	      "exact guard-envelope boundary was not allowed");
	CHECK(lichen_holdover_evaluate(&tracker, 5501u, &policy, &decision) == 0 &&
	      decision.state == LICHEN_HOLDOVER_EXPIRED && !decision.tx_allowed &&
	      decision.required_guard_us == 151u,
	      "first over-guard microsecond was not expired");
	CHECK(!lichen_holdover_tx_allowed(&tracker, 5501u, &policy),
	      "scheduling helper permitted expired envelope");

	policy.guard_us = UINT64_MAX;
	policy.max_holdover_ms = 5500u;
	CHECK(lichen_holdover_evaluate(&tracker, 5500u, &policy, &decision) == 0 &&
	      decision.tx_allowed,
	      "exact maximum holdover age was rejected");
	CHECK(lichen_holdover_evaluate(&tracker, 5501u, &policy, &decision) == 0 &&
	      !decision.tx_allowed && decision.state == LICHEN_HOLDOVER_EXPIRED,
	      "holdover age above maximum was allowed");

	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_NETWORK, 5501u, 12345, 10u) == 0,
	      "holdover source reset failed");
	CHECK(lichen_holdover_evaluate(&tracker, 5501u, &policy, &decision) == 0 &&
	      decision.tx_allowed && decision.state == LICHEN_HOLDOVER_FRESH &&
	      decision.drift.source == LICHEN_TIME_SOURCE_NETWORK,
	      "source reset did not establish a fresh envelope");

	policy.peer_bound_us = UINT64_MAX;
	CHECK(lichen_holdover_evaluate(&tracker, 5501u, &policy, &decision) == 0 &&
	      !decision.tx_allowed && decision.required_guard_us == UINT64_MAX,
	      "uncertainty overflow approved scheduling");
	policy.peer_bound_us = 10u;

	decision = sentinel;
	(void)atomic_flag_test_and_set_explicit(&tracker.lock, memory_order_acquire);
	CHECK(lichen_holdover_evaluate(&tracker, 5501u, &policy, &decision) == -EBUSY &&
	      memcmp(&decision, &sentinel, sizeof(decision)) == 0,
	      "contended holdover decision was not output-atomic");
	CHECK(!lichen_holdover_tx_allowed(&tracker, 5501u, &policy),
	      "contended holdover permitted scheduling");
	atomic_flag_clear_explicit(&tracker.lock, memory_order_release);

	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_NETWORK, 1u, 12345, 10u) == -ERANGE,
	      "reboot/wrap observation accepted");
	decision = sentinel;
	CHECK(lichen_holdover_evaluate(&tracker, 1u, &policy, &decision) == -ERANGE &&
	      memcmp(&decision, &sentinel, sizeof(decision)) == 0,
	      "regressed scheduling clock did not fail atomically");
	CHECK(!lichen_holdover_tx_allowed(&tracker, 1u, &policy),
	      "regressed scheduling clock permitted TX");
	return true;
}

#ifndef CONFIG_ZTEST
static bool test_concurrent_snapshots(void)
{
	enum { WORKER_COUNT = 32 };
	struct lichen_drift_tracker tracker;
	pthread_t threads[WORKER_COUNT];
	atomic_uint successes = 0u;
	atomic_uint busy = 0u;
	atomic_uint errors = 0u;
	struct snapshot_worker worker = {
		.tracker = &tracker,
		.successes = &successes,
		.busy = &busy,
		.errors = &errors,
	};

	CHECK(lichen_drift_tracker_init(&tracker, 20u, 5000u) == 0,
	      "concurrency tracker init failed");
	CHECK(lichen_drift_tracker_observe(
		      &tracker, LICHEN_TIME_SOURCE_GNSS, 0u, 0, 1u) == 0,
	      "concurrency baseline failed");
	for (size_t i = 0u; i < WORKER_COUNT; ++i) {
		CHECK(pthread_create(&threads[i], NULL, run_snapshot_worker,
				     &worker) == 0,
		      "snapshot pthread_create failed at %zu", i);
	}
	for (size_t i = 0u; i < WORKER_COUNT; ++i) {
		CHECK(pthread_join(threads[i], NULL) == 0,
		      "snapshot pthread_join failed at %zu", i);
	}

	unsigned int successful = atomic_load_explicit(&successes,
						       memory_order_relaxed);
	unsigned int contended = atomic_load_explicit(&busy,
						      memory_order_relaxed);
	CHECK(atomic_load_explicit(&errors, memory_order_relaxed) == 0u,
	      "concurrent snapshot returned an invalid result");
	CHECK(successful > 0u && successful + contended == WORKER_COUNT,
	      "concurrent snapshot accounting mismatch");
	return true;
}
#endif

static bool run_all_tests(void)
{
	return test_canonical_vectors() && test_formula_edges() &&
	       test_tracker_source_holdover_and_wrap() &&
	       test_contention_fails_closed() && test_holdover_policy()
#ifndef CONFIG_ZTEST
	       && test_concurrent_snapshots()
#endif
		;
}

#ifdef CONFIG_ZTEST
ZTEST(drift_bound, test_drift_bound_tracker)
{
	zassert_true(run_all_tests(), "drift-bound tests failed");
}

ZTEST_SUITE(drift_bound, NULL, NULL, NULL, NULL, NULL);
#else
int main(void)
{
	return run_all_tests() ? 0 : 1;
}
#endif
