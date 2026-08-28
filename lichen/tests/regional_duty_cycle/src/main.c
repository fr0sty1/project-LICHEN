/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <lichen/duty_cycle.h>

#include "duty_cycle_vectors.h"

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
struct admission_worker {
	struct lichen_duty_cycle_ctx *ctx;
	atomic_uint *successes;
};

static void *run_admission_worker(void *argument)
{
	struct admission_worker *worker = argument;
	if (lichen_duty_cycle_try_record_tx(worker->ctx, 0u, 4000u)) {
		atomic_fetch_add_explicit(worker->successes, 1u,
					  memory_order_relaxed);
	}
	return NULL;
}
#endif

static bool test_profiles(void)
{
	struct lichen_duty_cycle_limit limit = {
		.duty_permille = UINT16_C(77),
		.max_dwell_time_ms = UINT32_C(88),
		.has_dwell_time = true,
	};
	const struct lichen_duty_cycle_limit unchanged = limit;

	CHECK(lichen_duty_cycle_limit_for_region(LICHEN_DUTY_CYCLE_REGION_EU868,
						    &limit) == 0,
	      "EU868 profile lookup failed");
	CHECK(limit.duty_permille == LICHEN_EU868_DUTY_PERMILLE,
	      "EU868 duty limit mismatch");
	CHECK(!limit.has_dwell_time && limit.max_dwell_time_ms == 0u,
	      "EU868 must not impose a dwell ceiling");

	CHECK(lichen_duty_cycle_limit_for_region(LICHEN_DUTY_CYCLE_REGION_US915,
						    &limit) == 0,
	      "US915 profile lookup failed");
	CHECK(limit.duty_permille == LICHEN_US915_DUTY_PERMILLE,
	      "US915 duty limit mismatch");
	CHECK(limit.has_dwell_time &&
	      limit.max_dwell_time_ms == LICHEN_US915_FCC_MAX_DWELL_MS,
	      "US915 dwell limit mismatch");

	limit = unchanged;
	CHECK(lichen_duty_cycle_limit_for_region(
		      (enum lichen_duty_cycle_region)99, &limit) == -EINVAL,
	      "unknown region accepted");
	CHECK(memcmp(&limit, &unchanged, sizeof(limit)) == 0,
	      "failed profile lookup mutated output");
	CHECK(lichen_duty_cycle_limit_for_region(
		      LICHEN_DUTY_CYCLE_REGION_EU868, NULL) == -EINVAL,
	      "NULL profile output accepted");
	return true;
}

static bool test_canonical_vectors(void)
{
	for (size_t i = 0u; i < DUTY_CYCLE_TRACKING_VECTOR_COUNT; ++i) {
		const struct duty_cycle_tracking_vector *vector =
			&duty_cycle_tracking_vectors[i];
		struct lichen_duty_cycle_ctx ctx;
		CHECK(lichen_duty_cycle_init_region(&ctx, vector->region) == 0,
		      "%s: init failed", vector->name);
		CHECK(ctx.configured && ctx.duty_permille == vector->duty_permille &&
		      ctx.has_dwell_time == vector->has_dwell_time &&
		      ctx.max_dwell_time_ms == vector->max_dwell_time_ms,
		      "%s: configured profile mismatch", vector->name);
		for (size_t tx = 0u; tx < vector->tx_count; ++tx) {
			CHECK(lichen_duty_cycle_record_tx(
				      &ctx, vector->transmissions[tx].start_ms,
				      vector->transmissions[tx].duration_ms),
			      "%s: transmission %zu rejected", vector->name, tx);
		}

		uint32_t remaining =
			lichen_duty_cycle_remaining_ms(&ctx, vector->query_ms);
		uint32_t maximum = (uint32_t)((LICHEN_DUTY_CYCLE_WINDOW_MS /
						  UINT64_C(1000)) *
						 vector->duty_permille);
		CHECK(remaining == vector->expected_remaining_ms,
		      "%s: remaining %u != %u", vector->name, remaining,
		      vector->expected_remaining_ms);
		CHECK(maximum - remaining == vector->expected_used_ms,
		      "%s: used airtime mismatch", vector->name);
		CHECK(lichen_duty_cycle_usage_permille(&ctx, vector->query_ms) ==
			      vector->expected_usage_permille,
		      "%s: usage mismatch", vector->name);
		CHECK(lichen_duty_cycle_can_transmit(
			      &ctx, vector->query_ms,
			      vector->proposed_duration_ms) ==
			      vector->expected_can_transmit,
		      "%s: transmit decision mismatch", vector->name);
	}
	return true;
}

static bool test_fail_closed_and_bounds(void)
{
	struct lichen_duty_cycle_ctx ctx;
	memset(&ctx, 0xa5, sizeof(ctx));
	CHECK(lichen_duty_cycle_init_region(
		      &ctx, (enum lichen_duty_cycle_region)99) == -EINVAL,
	      "invalid region initialized");
	CHECK(!ctx.configured && ctx.len == 0u,
	      "invalid region did not reset tracker");
	CHECK(lichen_duty_cycle_remaining_ms(&ctx, 0u) == 0u,
	      "unconfigured tracker exposed budget");
	CHECK(!lichen_duty_cycle_can_transmit(&ctx, 0u, 1u),
	      "unconfigured tracker permitted transmit");
	CHECK(!lichen_duty_cycle_record_tx(&ctx, 0u, 1u),
	      "unconfigured tracker recorded transmit");
	CHECK(lichen_duty_cycle_next_tx_available_ms(&ctx, 0u, 1u) == UINT64_MAX,
	      "unconfigured tracker exposed availability");

	lichen_duty_cycle_init(&ctx, 0u);
	CHECK(!ctx.configured, "zero custom duty limit accepted");
	lichen_duty_cycle_init(&ctx, 1001u);
	CHECK(!ctx.configured, "over-100-percent custom duty limit accepted");
	lichen_duty_cycle_init(&ctx, 10u);
	CHECK(ctx.configured && !ctx.has_dwell_time,
	      "valid custom duty limit rejected");
	CHECK(!lichen_duty_cycle_record_tx(&ctx, 0u, 0u),
	      "zero-duration transmission accepted");

	CHECK(lichen_duty_cycle_init_region(
		      &ctx, LICHEN_DUTY_CYCLE_REGION_US915) == 0,
	      "US915 init failed");
	CHECK(!lichen_duty_cycle_try_record_tx(
		      &ctx, 0u, LICHEN_US915_FCC_MAX_DWELL_MS + 1u),
	      "over-dwell transmission admitted");
	CHECK(ctx.len == 0u, "rejected dwell transmission mutated tracker");
	CHECK(lichen_duty_cycle_next_tx_available_ms(
		      &ctx, 0u, LICHEN_US915_FCC_MAX_DWELL_MS + 1u) == UINT64_MAX,
	      "over-dwell transmission received availability time");

	CHECK(lichen_duty_cycle_init_region(
		      &ctx, LICHEN_DUTY_CYCLE_REGION_EU868) == 0,
	      "EU868 capacity test init failed");
	for (uint32_t i = 0u; i < LICHEN_DUTY_CYCLE_RECORD_CAPACITY; ++i) {
		CHECK(lichen_duty_cycle_record_tx(&ctx, i, 1u),
		      "bounded record %u rejected", i);
	}
	CHECK(!lichen_duty_cycle_record_tx(
		      &ctx, LICHEN_DUTY_CYCLE_RECORD_CAPACITY, 1u),
	      "full bounded tracker accepted another record");
	CHECK(ctx.len == LICHEN_DUTY_CYCLE_RECORD_CAPACITY,
	      "full-record rejection mutated tracker");
	CHECK(lichen_duty_cycle_record_tx(
		      &ctx, LICHEN_DUTY_CYCLE_WINDOW_MS + 1u, 1u),
	      "stale record was not reclaimed at rolling-window boundary");

	CHECK(!lichen_duty_cycle_record_tx(NULL, 0u, 1u),
	      "NULL tracker recorded transmission");
	CHECK(lichen_duty_cycle_remaining_ms(NULL, 0u) == 0u,
	      "NULL tracker exposed remaining budget");
	CHECK(lichen_duty_cycle_usage_permille(NULL, 0u) == 0u,
	      "NULL tracker exposed usage");
	CHECK(!lichen_duty_cycle_can_transmit(NULL, 0u, 1u),
	      "NULL tracker permitted transmit");
	return true;
}

static bool test_admission_expiry_and_time_safety(void)
{
	struct lichen_duty_cycle_ctx ctx;
	CHECK(lichen_duty_cycle_init_region(
		      &ctx, LICHEN_DUTY_CYCLE_REGION_EU868) == 0,
	      "EU868 admission init failed");
	CHECK(lichen_duty_cycle_try_record_tx(&ctx, 0u, 36000u),
	      "exact EU868 budget was rejected");
	CHECK(!lichen_duty_cycle_try_record_tx(&ctx, 0u, 1u),
	      "over-budget admission succeeded");
	CHECK(ctx.len == 1u, "rejected admission mutated records");
	CHECK(lichen_duty_cycle_next_tx_available_ms(&ctx, 0u, 1u) ==
		      LICHEN_DUTY_CYCLE_WINDOW_MS + 36000u,
	      "expiry availability did not include transmission end");
	CHECK(lichen_duty_cycle_remaining_ms(
		      &ctx, LICHEN_DUTY_CYCLE_WINDOW_MS + 35999u) == 35999u,
	      "partial expiry accounting mismatch");
	CHECK(lichen_duty_cycle_remaining_ms(
		      &ctx, LICHEN_DUTY_CYCLE_WINDOW_MS + 36000u) == 36000u,
	      "full expiry did not restore budget");

	CHECK(lichen_duty_cycle_init_region(
		      &ctx, LICHEN_DUTY_CYCLE_REGION_EU868) == 0,
	      "monotonic-time init failed");
	CHECK(lichen_duty_cycle_try_record_tx(&ctx, 1000u, 100u),
	      "monotonic-time seed record failed");
	CHECK(lichen_duty_cycle_remaining_ms(&ctx, 999u) == 0u,
	      "regressed time exposed budget");
	CHECK(lichen_duty_cycle_usage_permille(&ctx, 999u) == UINT16_MAX,
	      "regressed time did not report fail-closed usage");
	CHECK(!lichen_duty_cycle_can_transmit(&ctx, 999u, 1u),
	      "regressed time permitted transmission");
	CHECK(lichen_duty_cycle_next_tx_available_ms(&ctx, 999u, 1u) == UINT64_MAX,
	      "regressed time exposed availability");
	CHECK(!lichen_duty_cycle_record_tx(&ctx, 999u, 1u),
	      "out-of-order transmission was recorded");
	CHECK(ctx.len == 1u, "time-regression rejection mutated records");

	CHECK(lichen_duty_cycle_init_region(
		      &ctx, LICHEN_DUTY_CYCLE_REGION_EU868) == 0,
	      "lock-contention init failed");
	(void)atomic_flag_test_and_set_explicit(&ctx.lock, memory_order_acquire);
	CHECK(lichen_duty_cycle_remaining_ms(&ctx, 0u) == 0u,
	      "contended tracker exposed budget");
	CHECK(lichen_duty_cycle_usage_permille(&ctx, 0u) == UINT16_MAX,
	      "contended tracker exposed safe usage");
	CHECK(!lichen_duty_cycle_try_record_tx(&ctx, 0u, 1u),
	      "contended tracker admitted transmission");
	CHECK(!lichen_duty_cycle_can_transmit(&ctx, 0u, 1u),
	      "contended tracker permitted transmission");
	CHECK(!lichen_duty_cycle_record_tx(&ctx, 0u, 1u),
	      "contended tracker recorded transmission");
	CHECK(lichen_duty_cycle_next_tx_available_ms(&ctx, 0u, 1u) == UINT64_MAX,
	      "contended tracker exposed availability");
	atomic_flag_clear_explicit(&ctx.lock, memory_order_release);

	CHECK(lichen_duty_cycle_init_region(
		      &ctx, LICHEN_DUTY_CYCLE_REGION_EU868) == 0,
	      "u64 ceiling init failed");
	CHECK(lichen_duty_cycle_try_record_tx(
		      &ctx, UINT64_MAX - 50u, 36000u),
	      "u64 ceiling admission failed");
	CHECK(lichen_duty_cycle_next_tx_available_ms(&ctx, UINT64_MAX, 1u) ==
		      UINT64_MAX,
	      "u64 expiry calculation wrapped");
	CHECK(!lichen_duty_cycle_can_transmit(&ctx, 0u, 1u),
	      "monotonic timestamp wrap permitted transmission");
	return true;
}

#ifndef CONFIG_ZTEST
static bool test_concurrent_admission(void)
{
	enum { WORKER_COUNT = 24 };
	struct lichen_duty_cycle_ctx ctx;
	pthread_t threads[WORKER_COUNT];
	atomic_uint successes = 0u;
	struct admission_worker worker = {
		.ctx = &ctx,
		.successes = &successes,
	};

	CHECK(lichen_duty_cycle_init_region(
		      &ctx, LICHEN_DUTY_CYCLE_REGION_EU868) == 0,
	      "concurrency init failed");
	for (size_t i = 0u; i < WORKER_COUNT; ++i) {
		CHECK(pthread_create(&threads[i], NULL, run_admission_worker,
				     &worker) == 0,
		      "pthread_create failed at %zu", i);
	}
	for (size_t i = 0u; i < WORKER_COUNT; ++i) {
		CHECK(pthread_join(threads[i], NULL) == 0,
		      "pthread_join failed at %zu", i);
	}

	unsigned int admitted = atomic_load_explicit(&successes,
						     memory_order_relaxed);
	CHECK(admitted > 0u && admitted <= 9u,
	      "concurrent admission oversubscribed budget: %u", admitted);
	CHECK(ctx.len == admitted, "concurrent record count mismatch");
	CHECK(lichen_duty_cycle_remaining_ms(&ctx, 0u) ==
		      36000u - admitted * 4000u,
	      "concurrent accounting mismatch");
	return true;
}
#endif

static bool run_all_tests(void)
{
	return test_profiles() && test_canonical_vectors() &&
	       test_fail_closed_and_bounds() &&
	       test_admission_expiry_and_time_safety()
#ifndef CONFIG_ZTEST
	       && test_concurrent_admission()
#endif
		;
}

#ifdef CONFIG_ZTEST
ZTEST(regional_duty_cycle, test_regional_policy_and_vectors)
{
	zassert_true(run_all_tests(), "regional duty-cycle tests failed");
}

ZTEST_SUITE(regional_duty_cycle, NULL, NULL, NULL, NULL, NULL);
#else
int main(void)
{
	return run_all_tests() ? 0 : 1;
}
#endif
