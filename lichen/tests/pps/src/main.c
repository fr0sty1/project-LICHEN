/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lichen/pps.h>

#ifdef CONFIG_ZTEST
#include <zephyr/ztest.h>
#define CHECK(condition, ...) zassert_true(condition, __VA_ARGS__)
#else
#include <pthread.h>
#define CHECK(condition, ...)                                                   \
	do {                                                                      \
		if (!(condition)) {                                                 \
			fprintf(stderr, __VA_ARGS__);                                 \
			fprintf(stderr, "\n");                                      \
			return false;                                                  \
		}                                                                 \
	} while (0)
#endif

#define BUILD_EPOCH_S UINT64_C(1704067200)
#define SOURCE_GENERATION UINT32_C(7)

static struct lichen_pps_gnss_sample trusted_sample(uint64_t second,
						    uint64_t received_ns)
{
	return (struct lichen_pps_gnss_sample) {
		.unix_second = second,
		.message_monotonic_ns = received_ns,
		.source_generation = SOURCE_GENERATION,
		.scale = LICHEN_PPS_TIME_SCALE_UNIX_UTC,
		.time_valid = true,
		.source_authenticated = true,
	};
}

static bool init_state(struct lichen_pps_associator *state)
{
	return lichen_pps_associator_init(state, BUILD_EPOCH_S, 500000U,
					   1000U, SOURCE_GENERATION) == 0;
}

static bool association_equal(const struct lichen_pps_association *left,
			      const struct lichen_pps_association *right)
{
	return memcmp(left, right, sizeof(*left)) == 0;
}

static bool test_python_rust_parity_and_boundary(void)
{
	struct lichen_pps_associator state;
	struct lichen_pps_capture_result capture;
	struct lichen_pps_association association;
	struct lichen_pps_gnss_sample sample;

	CHECK(init_state(&state), "init failed");
	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_C(10000000123),
					  &capture) == 0,
	      "capture failed");
	CHECK(!capture.replaced_unassociated && capture.elapsed_intervals == 1U,
	      "first capture metadata mismatch");
	sample = trusted_sample(BUILD_EPOCH_S + 4U, UINT64_C(10000125579));
	CHECK(lichen_pps_associate(&state, &sample, &association) == 0,
	      "association failed");
	CHECK(association.edge_monotonic_ns == UINT64_C(10000000123) &&
	      association.message_delay_ns == UINT64_C(125456) &&
	      association.unix_time_us == UINT64_C(1704067204000000),
	      "Python/Rust parity association mismatch");

	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_C(11000000623),
					  &capture) == 0,
	      "jittered edge capture failed");
	sample = trusted_sample(BUILD_EPOCH_S + 5U, UINT64_C(11000500623));
	CHECK(lichen_pps_associate(&state, &sample, &association) == 0 &&
	      association.message_delay_ns == UINT64_C(500000),
	      "inclusive message-delay boundary rejected");
	return true;
}

static bool test_missed_double_jitter_and_replacement(void)
{
	struct lichen_pps_associator state;
	struct lichen_pps_capture_result capture;
	struct lichen_pps_capture_result sentinel = {
		.replaced_unassociated = true,
		.previous_edge_ns = 11U,
		.elapsed_intervals = 22U,
		.missed_pulses = 33U,
	};
	struct lichen_pps_gnss_sample sample;
	struct lichen_pps_association association;

	CHECK(init_state(&state), "init failed");
	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_C(1000000000),
					  &capture) == 0,
	      "first capture failed");
	capture = sentinel;
	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_C(1000100000),
					  &capture) == -ERANGE &&
	      memcmp(&capture, &sentinel, sizeof(capture)) == 0,
	      "double edge was not rejected transactionally");
	capture = sentinel;
	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_C(2000001001),
					  &capture) == -ERANGE &&
	      memcmp(&capture, &sentinel, sizeof(capture)) == 0,
	      "jitter outlier was not rejected transactionally");
	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_C(3000000500),
					  &capture) == 0,
	      "missed-pulse edge failed");
	CHECK(capture.replaced_unassociated &&
	      capture.previous_edge_ns == UINT64_C(1000000000) &&
	      capture.elapsed_intervals == 2U && capture.missed_pulses == 1U,
	      "missed/replaced capture metadata mismatch");
	sample = trusted_sample(BUILD_EPOCH_S + 2U, UINT64_C(3000100500));
	CHECK(lichen_pps_associate(&state, &sample, &association) == 0,
	      "first missed-edge association failed");

	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_C(5000000000),
					  &capture) == 0 &&
	      capture.missed_pulses == 1U,
	      "second missed pulse not counted");
	sample = trusted_sample(BUILD_EPOCH_S + 3U, UINT64_C(5000100000));
	association = (struct lichen_pps_association) {
		.edge_monotonic_ns = 99U,
	};
	CHECK(lichen_pps_associate(&state, &sample, &association) == -EBADMSG &&
	      association.edge_monotonic_ns == 99U,
	      "GNSS/PPS interval mismatch was not atomic");
	sample.unix_second = BUILD_EPOCH_S + 4U;
	CHECK(lichen_pps_associate(&state, &sample, &association) == 0,
	      "matching missed-edge interval rejected");

	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_C(6000000000),
					  &capture) == 0,
	      "replacement sequence first edge failed");
	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_C(7000000000),
					  &capture) == 0 &&
	      capture.replaced_unassociated,
	      "replacement sequence second edge failed");
	sample = trusted_sample(BUILD_EPOCH_S + 6U, UINT64_C(7000100000));
	CHECK(lichen_pps_associate(&state, &sample, &association) == 0 &&
	      association.elapsed_intervals == 2U,
	      "replaced edges lost elapsed association interval");
	return true;
}

static bool expect_association_error(struct lichen_pps_associator *state,
				     struct lichen_pps_gnss_sample sample,
				     int expected, const char *name)
{
	const struct lichen_pps_association sentinel = {
		.edge_monotonic_ns = UINT64_C(0x1111111111111111),
		.message_monotonic_ns = UINT64_C(0x2222222222222222),
	};
	struct lichen_pps_association result = sentinel;

	CHECK(lichen_pps_associate(state, &sample, &result) == expected,
	      "%s returned wrong error", name);
	CHECK(association_equal(&result, &sentinel), "%s mutated output", name);
	return true;
}

static bool test_trust_stale_overflow_and_transactionality(void)
{
	struct lichen_pps_associator state;
	struct lichen_pps_capture_result capture;
	struct lichen_pps_gnss_sample sample;
	struct lichen_pps_association association;
	uint64_t maximum_second = UINT64_MAX / LICHEN_PPS_USEC_PER_SECOND;

	CHECK(lichen_pps_associator_init(&state, 0U, 1U, 0U,
					  SOURCE_GENERATION) == -EINVAL,
	      "zero build epoch accepted");
	CHECK(lichen_pps_associator_init(&state, UINT64_MAX, 1U, 0U,
					  SOURCE_GENERATION) == -EINVAL,
	      "overflowing build epoch accepted");
	CHECK(lichen_pps_associator_init(&state, BUILD_EPOCH_S, 0U, 0U,
					  SOURCE_GENERATION) == -EINVAL,
	      "zero delay accepted");
	CHECK(init_state(&state), "init failed");
	CHECK(lichen_pps_capture_edge_isr(&state, 1000U, &capture) == 0,
	      "capture failed");

	sample = trusted_sample(BUILD_EPOCH_S, 1100U);
	sample.time_valid = false;
	CHECK(expect_association_error(&state, sample, -EACCES, "invalid time"),
	      "invalid-time assertion failed");
	sample.time_valid = true;
	sample.source_authenticated = false;
	CHECK(expect_association_error(&state, sample, -EACCES,
				       "unauthenticated source"),
	      "authentication assertion failed");
	sample.source_authenticated = true;
	sample.source_generation++;
	CHECK(expect_association_error(&state, sample, -EACCES,
				       "source generation"),
	      "generation assertion failed");
	sample.source_generation = SOURCE_GENERATION;
	sample.scale = LICHEN_PPS_TIME_SCALE_INVALID;
	CHECK(expect_association_error(&state, sample, -EACCES, "raw GPS scale"),
	      "timescale assertion failed");
	sample.scale = LICHEN_PPS_TIME_SCALE_UNIX_UTC;
	sample.message_monotonic_ns = 999U;
	CHECK(expect_association_error(&state, sample, -ERANGE,
				       "message before edge"),
	      "early message assertion failed");
	sample.message_monotonic_ns = 501001U;
	CHECK(expect_association_error(&state, sample, -ESTALE, "stale edge"),
	      "stale assertion failed");
	sample.message_monotonic_ns = 1100U;
	sample.unix_second = BUILD_EPOCH_S - 1U;
	CHECK(expect_association_error(&state, sample, -ESTALE, "epoch floor"),
	      "floor assertion failed");

	CHECK(lichen_pps_associator_init(&state, maximum_second, 10U, 0U,
					  SOURCE_GENERATION) == 0,
	      "maximum epoch init failed");
	CHECK(lichen_pps_capture_edge_isr(&state, 200U, &capture) == 0,
	      "maximum epoch capture failed");
	sample = trusted_sample(maximum_second + 1U, 201U);
	CHECK(expect_association_error(&state, sample, -EOVERFLOW,
				       "microsecond overflow"),
	      "overflow assertion failed");
	CHECK(lichen_pps_discard_pending(&state, &sample.message_monotonic_ns) == 0 &&
	      sample.message_monotonic_ns == 200U,
	      "pending discard failed");
	CHECK(lichen_pps_discard_pending(&state, &sample.message_monotonic_ns) ==
		      -EAGAIN,
	      "empty discard did not fail");
	CHECK(lichen_pps_associate(&state, &sample, &association) == -EAGAIN,
	      "association without edge accepted");
	return true;
}

static bool test_reboot_source_reset_wrap_and_contention(void)
{
	struct lichen_pps_associator state;
	struct lichen_pps_capture_result capture;
	struct lichen_pps_capture_result sentinel = {
		.previous_edge_ns = 77U,
	};
	struct lichen_pps_snapshot snapshot = {
		.pending_edge_ns = 88U,
	};

	CHECK(init_state(&state), "init failed");
	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_MAX - 10U, &capture) == 0,
	      "near-wrap edge failed");
	capture = sentinel;
	CHECK(lichen_pps_capture_edge_isr(&state, 5U, &capture) == -ERANGE &&
	      memcmp(&capture, &sentinel, sizeof(capture)) == 0,
	      "monotonic wrap/reboot was not fail-closed");
	CHECK(lichen_pps_associator_reset(&state, SOURCE_GENERATION + 1U) == 0,
	      "source/reboot reset failed");
	CHECK(lichen_pps_capture_edge_isr(&state, 5U, &capture) == 0,
	      "post-reset edge rejected");
	CHECK(lichen_pps_snapshot_get(&state, &snapshot) == 0 && snapshot.pending &&
	      snapshot.pending_edge_ns == 5U &&
	      snapshot.source_generation == SOURCE_GENERATION + 1U &&
	      !snapshot.associated,
	      "reset snapshot mismatch");

	CHECK(!atomic_flag_test_and_set_explicit(&state.lock, memory_order_acquire),
	      "test lock acquisition failed");
	capture = sentinel;
	CHECK(lichen_pps_capture_edge_isr(&state, UINT64_C(1000000005),
					  &capture) == -EBUSY &&
	      memcmp(&capture, &sentinel, sizeof(capture)) == 0,
	      "ISR contention did not return atomically");
	snapshot.pending_edge_ns = 88U;
	CHECK(lichen_pps_snapshot_get(&state, &snapshot) == -EBUSY &&
	      snapshot.pending_edge_ns == 88U,
	      "snapshot contention mutated output");
	atomic_flag_clear_explicit(&state.lock, memory_order_release);
	return true;
}

#ifndef CONFIG_ZTEST
struct concurrency_args {
	struct lichen_pps_associator *state;
	atomic_bool *done;
	atomic_uint *errors;
};

static void *capture_worker(void *argument)
{
	struct concurrency_args *args = argument;
	struct lichen_pps_capture_result capture;
	uint64_t edge = UINT64_C(1000000000);

	for (unsigned int index = 0; index < 2000U; ++index) {
		int ret;
		do {
			ret = lichen_pps_capture_edge_isr(args->state, edge, &capture);
		} while (ret == -EBUSY);
		if (ret != 0) {
			atomic_fetch_add_explicit(args->errors, 1U,
						  memory_order_relaxed);
			break;
		}
		edge += LICHEN_PPS_NSEC_PER_SECOND;
	}
	atomic_store_explicit(args->done, true, memory_order_release);
	return NULL;
}

static void *snapshot_worker(void *argument)
{
	struct concurrency_args *args = argument;
	struct lichen_pps_snapshot snapshot;

	do {
		int ret = lichen_pps_snapshot_get(args->state, &snapshot);
		if (ret != 0 && ret != -EBUSY) {
			atomic_fetch_add_explicit(args->errors, 1U,
						  memory_order_relaxed);
		}
	} while (!atomic_load_explicit(args->done, memory_order_acquire));
	return NULL;
}

static bool test_threaded_capture_snapshot(void)
{
	struct lichen_pps_associator state;
	atomic_bool done;
	atomic_uint errors;
	struct concurrency_args args = {
		.state = &state,
		.done = &done,
		.errors = &errors,
	};
	pthread_t capture_thread;
	pthread_t snapshot_thread;
	struct lichen_pps_snapshot snapshot;

	atomic_init(&done, false);
	atomic_init(&errors, 0U);
	CHECK(init_state(&state), "threaded init failed");
	CHECK(pthread_create(&capture_thread, NULL, capture_worker, &args) == 0,
	      "capture thread create failed");
	CHECK(pthread_create(&snapshot_thread, NULL, snapshot_worker, &args) == 0,
	      "snapshot thread create failed");
	CHECK(pthread_join(capture_thread, NULL) == 0 &&
	      pthread_join(snapshot_thread, NULL) == 0,
	      "thread join failed");
	CHECK(atomic_load_explicit(&errors, memory_order_relaxed) == 0U,
	      "threaded operation failed");
	CHECK(lichen_pps_snapshot_get(&state, &snapshot) == 0 && snapshot.pending &&
	      snapshot.replaced_edges == 1999U,
	      "threaded final state mismatch");
	return true;
}
#endif

#ifdef CONFIG_ZTEST
ZTEST(pps, python_rust_parity_and_boundary)
{
	zassert_true(test_python_rust_parity_and_boundary(), "parity failed");
}

ZTEST(pps, missed_double_jitter_and_replacement)
{
	zassert_true(test_missed_double_jitter_and_replacement(), "edge cases failed");
}

ZTEST(pps, trust_stale_overflow_and_transactionality)
{
	zassert_true(test_trust_stale_overflow_and_transactionality(),
		     "trust/error cases failed");
}

ZTEST(pps, reboot_source_reset_wrap_and_contention)
{
	zassert_true(test_reboot_source_reset_wrap_and_contention(),
		     "reset/contention failed");
}

ZTEST_SUITE(pps, NULL, NULL, NULL, NULL, NULL);
#else
int main(void)
{
	if (!test_python_rust_parity_and_boundary() ||
	    !test_missed_double_jitter_and_replacement() ||
	    !test_trust_stale_overflow_and_transactionality() ||
	    !test_reboot_source_reset_wrap_and_contention() ||
	    !test_threaded_capture_snapshot()) {
		return 1;
	}
	puts("PPS tests passed");
	return 0;
}
#endif
