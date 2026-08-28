/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Trickle timer (RFC 6206) tests
 *
 * Tests ported from and kept in sync with rust/lichen-rpl/src/trickle.rs
 * (including odd-interval bias-free test per Worker23 fix in C/Python).
 */

#include <lichen/rpl_trickle.h>
#include <errno.h>
#include <stdio.h>

/* ─── test framework ──────────────────────────────────────────────────────── */

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %u, expected %u)\n", msg, (unsigned)(a), (unsigned)(b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_TRUE(cond, msg) do { \
	if (!(cond)) { \
		printf("  FAIL: %s\n", msg); \
		return 0; \
	} \
} while (0)

#define ASSERT_FALSE(cond, msg) ASSERT_TRUE(!(cond), msg)

/* ─── tests (from rust/lichen-rpl/src/trickle.rs) ─────────────────────────── */

static int test_transmit_time_in_second_half_of_interval(void)
{
	struct lichen_trickle t;
	struct lichen_trickle_event ev;

	lichen_trickle_init(&t, 1000, 4, 10);
	lichen_trickle_start(&t, 0, 0); /* rand_offset=0 -> transmit at 500ms */

	ASSERT_EQ(t.transmit_time, 500, "transmit_time");
	ASSERT_EQ(lichen_trickle_interval_end(&t), 1000, "interval_end");

	lichen_trickle_next_event(&t, &ev);
	ASSERT_EQ(ev.type, LICHEN_TRICKLE_TRANSMIT, "event_type");
	ASSERT_EQ(ev.at_ms, 500, "event_at_ms");

	return 1;
}

static int test_fire_transmit_sets_next_event_to_expire(void)
{
	struct lichen_trickle t;
	struct lichen_trickle_event ev;

	lichen_trickle_init(&t, 1000, 4, 10);
	lichen_trickle_start(&t, 0, 0);

	ASSERT_TRUE(lichen_trickle_fire_transmit(&t), "should transmit (c=0 < k=10)");

	lichen_trickle_next_event(&t, &ev);
	ASSERT_EQ(ev.type, LICHEN_TRICKLE_EXPIRE, "event_type after fire");
	ASSERT_EQ(ev.at_ms, 1000, "event_at_ms after fire");

	return 1;
}

static int test_heard_consistent_suppresses_transmit_when_ge_k(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 4, 2);
	lichen_trickle_start(&t, 0, 0);

	lichen_trickle_heard_consistent(&t);
	lichen_trickle_heard_consistent(&t); /* counter = 2 = k */

	ASSERT_FALSE(lichen_trickle_should_transmit(&t), "should_transmit when c >= k");
	ASSERT_FALSE(lichen_trickle_fire_transmit(&t), "fire_transmit when c >= k");

	return 1;
}

static int test_expire_doubles_interval_capped_at_max(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 2, 10); /* max = 4000 */
	lichen_trickle_start(&t, 0, 0);

	lichen_trickle_fire_transmit(&t);
	lichen_trickle_expire(&t, 1000, 0);
	ASSERT_EQ(t.interval, 2000, "interval after first expire");

	lichen_trickle_fire_transmit(&t);
	lichen_trickle_expire(&t, 3000, 0);
	ASSERT_EQ(t.interval, 4000, "interval after second expire");

	lichen_trickle_fire_transmit(&t);
	lichen_trickle_expire(&t, 7000, 0);
	ASSERT_EQ(t.interval, 4000, "interval capped at max");

	return 1;
}

static int test_reset_shrinks_to_imin(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 4, 10);
	lichen_trickle_start(&t, 0, 0);

	lichen_trickle_fire_transmit(&t);
	lichen_trickle_expire(&t, 1000, 0);
	ASSERT_EQ(t.interval, 2000, "interval after expire");

	lichen_trickle_reset(&t, 1000, 0);
	ASSERT_EQ(t.interval, 1000, "interval after reset");

	return 1;
}

static int test_reset_noop_when_already_at_imin(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 4, 10);
	lichen_trickle_start(&t, 0, 0);

	t.counter = 4;
	ASSERT_TRUE(lichen_trickle_reset(&t, 100, 499),
		    "authorized profile reset at Imin");
	ASSERT_EQ(t.interval_start, 100, "reset restarts interval at Imin");
	ASSERT_EQ(t.transmit_time, 1099, "reset samples a fresh transmit point");
	ASSERT_EQ(t.counter, 0, "reset clears counter");

	return 1;
}

static int test_rand_offset_shifts_transmit_time(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 4, 10);
	lichen_trickle_start(&t, 0, 200); /* rand_offset=200 < range=500 -> transmit at 700 */

	ASSERT_EQ(t.transmit_time, 700, "transmit_time with rand_offset");

	return 1;
}

static int test_odd_interval_bias_free_transmit_time(void)
{
	/* I=5 (odd): half=(5+1)/2=3, range=2 per Worker23 bias-free fix.
	 * transmit times: 3 or 4 (covers [2.5,5) uniformly). Matches Rust+Python. */
	struct lichen_trickle t, t2;

	lichen_trickle_init(&t, 5, 0, 10);
	lichen_trickle_start(&t, 0, 0);
	ASSERT_EQ(t.transmit_time, 3, "odd I=5 rand=0");
	ASSERT_EQ(lichen_trickle_interval_end(&t), 5, "interval_end");

	lichen_trickle_init(&t2, 5, 0, 10);
	lichen_trickle_start(&t2, 0, 1);
	ASSERT_EQ(t2.transmit_time, 4, "odd I=5 rand=1");

	return 1;
}

/* ─── RFC2119 validation tests for Trickle parameter MUST checks ──────────── */

static int test_init_rejects_zero_k(void)
{
	struct lichen_trickle t;

	/* RFC 6206 §4.1 defines k as a natural number greater than zero. */
	ASSERT_EQ(lichen_trickle_init(&t, 1000, 4, 0), -EINVAL,
		  "k=0 rejected");
	ASSERT_FALSE(t.initialized, "invalid timer remains uninitialized");
	ASSERT_FALSE(lichen_trickle_start(&t, 0, 0),
		     "invalid timer cannot start");

	return 1;
}

static int test_init_null_pointer_does_not_crash(void)
{
	ASSERT_EQ(lichen_trickle_init(NULL, 1000, 4, 10), -EINVAL,
		  "NULL init rejected");
	ASSERT_FALSE(lichen_trickle_start(NULL, 0, 0), "NULL start rejected");
	ASSERT_FALSE(lichen_trickle_fire_transmit(NULL), "NULL fire rejected");
	ASSERT_FALSE(lichen_trickle_expire(NULL, 0, 0), "NULL expire rejected");
	ASSERT_FALSE(lichen_trickle_reset(NULL, 0, 0), "NULL reset rejected");
	return 1;
}

static int test_start_null_pointer_does_not_crash(void)
{
	lichen_trickle_start(NULL, 0, 0);
	return 1;
}

static int test_fire_transmit_before_start_has_counter_below_k(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 4, 10);
	ASSERT_FALSE(lichen_trickle_fire_transmit(&t),
		     "fire before start rejected");
	return 1;
}

static int test_expire_before_start_interval_stays_zero(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 4, 10);
	ASSERT_FALSE(lichen_trickle_expire(&t, 0, 0),
		     "expire before start rejected");
	ASSERT_EQ(t.interval, 0, "expire before start: interval stays 0");
	ASSERT_EQ(t.transmit_time, 0, "expire before start: transmit_time=0");
	return 1;
}

static int test_next_event_before_start_returns_transmit(void)
{
	struct lichen_trickle t;
	struct lichen_trickle_event ev;

	lichen_trickle_init(&t, 1000, 4, 10);
	ASSERT_FALSE(lichen_trickle_next_event(&t, &ev),
		     "next_event before start reports no event");
	return 1;
}

static int test_next_event_null_output_does_not_crash(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 4, 10);
	lichen_trickle_next_event(&t, NULL);
	lichen_trickle_next_event(NULL, NULL);
	/* Must not crash */
	return 1;
}

static int test_redundancy_constant_zero_suppresses_always(void)
{
	struct lichen_trickle t;

	ASSERT_EQ(lichen_trickle_init(&t, 1000, 4, 0), -EINVAL,
		  "RFC-invalid k=0 is rejected");
	return 1;
}

static int test_expire_null_pointer_does_not_crash(void)
{
	lichen_trickle_expire(NULL, 0, 0);
	return 1;
}

static int test_reset_null_pointer_does_not_crash(void)
{
	lichen_trickle_reset(NULL, 0, 0);
	return 1;
}

static int test_repeated_start_resets_interval(void)
{
	struct lichen_trickle t;

	/* Calling start() twice: second call should restart the interval
	 * at Imin (same as a fresh start). */
	lichen_trickle_init(&t, 1000, 4, 10);
	lichen_trickle_start(&t, 0, 0);
	ASSERT_EQ(t.interval, 1000, "first start sets interval=imin");

	/* Manually grow interval (simulate expire + doublings) */
	t.interval = 4000;

	/* Second start should reset to imin */
	lichen_trickle_start(&t, 5000, 0);
	ASSERT_EQ(t.interval, 1000, "second start resets to imin");
	ASSERT_EQ(t.interval_start, 5000, "second start sets new interval_start");
	ASSERT_EQ(t.transmit_time, 5500, "second start sets transmit_time");
	ASSERT_EQ(t.counter, 0, "second start resets counter");
	return 1;
}

/* ─── additional tests for saturation and overflow ────────────────────────── */

static int test_max_interval_rejects_overflow(void)
{
	struct lichen_trickle t;

	/* Silent saturation changes the configured Imax and makes 32-bit deadline
	 * ordering ambiguous.  Invalid profiles fail closed instead. */
	ASSERT_EQ(lichen_trickle_init(&t, 1000, 32, 10), -ERANGE,
		  "max_interval overflow rejected");
	ASSERT_FALSE(t.initialized, "overflowed profile stays inactive");

	return 1;
}

static int test_counter_saturates_at_max(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 4, 10);
	lichen_trickle_start(&t, 0, 0);

	/* Force counter to UINT32_MAX */
	t.counter = UINT32_MAX;
	lichen_trickle_heard_consistent(&t);
	ASSERT_EQ(t.counter, UINT32_MAX, "counter saturates at UINT32_MAX");

	return 1;
}

static int test_zero_imin_uses_safe_default(void)
{
	struct lichen_trickle t;

	ASSERT_EQ(lichen_trickle_init(&t, 0, 4, 10), -EINVAL,
		  "zero Imin rejected");
	ASSERT_EQ(lichen_trickle_init(&t, 1, 4, 10), -EINVAL,
		  "one-tick Imin cannot represent [I/2,I)");

	return 1;
}

static int test_profile_constants_and_max_math(void)
{
	struct lichen_trickle t;

	ASSERT_EQ(lichen_trickle_init_profile(&t), 0, "profile init");
	ASSERT_EQ(t.imin, 4000, "canonical Imin");
	ASSERT_EQ(t.max_interval, 1024000, "canonical Imax");
	ASSERT_EQ(t.k, 10, "canonical k");
	return 1;
}

static int test_invalid_imax_overflow_fails_closed(void)
{
	struct lichen_trickle t;

	ASSERT_EQ(lichen_trickle_init(&t, 4000, 32, 10), -ERANGE,
		  "shift overflow rejected");
	ASSERT_FALSE(t.initialized, "overflow leaves timer invalid");
	ASSERT_EQ(lichen_trickle_init(&t, UINT32_MAX, 0, 10), -ERANGE,
		  "interval beyond wrap-safe horizon rejected");
	return 1;
}

static int test_random_offset_bounds_are_checked_atomically(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 4, 10);
	ASSERT_FALSE(lichen_trickle_start(&t, 10, 500),
		     "upper-exclusive random bound rejected");
	ASSERT_FALSE(t.active, "failed start leaves timer inactive");
	ASSERT_TRUE(lichen_trickle_start(&t, 10, 499), "last valid offset");
	ASSERT_EQ(t.transmit_time, 1009, "last point is strictly before I");

	t.counter = 7;
	ASSERT_FALSE(lichen_trickle_reset(&t, 20, 500),
		     "invalid reset offset rejected");
	ASSERT_EQ(t.interval_start, 10, "failed reset preserves start");
	ASSERT_EQ(t.counter, 7, "failed reset preserves counter");
	return 1;
}

static int test_uptime_wrap_uses_modular_deadlines(void)
{
	struct lichen_trickle t;
	struct lichen_trickle_event ev;
	uint32_t start = UINT32_MAX - 299U;

	lichen_trickle_init(&t, 1000, 0, 10);
	ASSERT_TRUE(lichen_trickle_start(&t, start, 0), "start near wrap");
	ASSERT_EQ(t.transmit_time, 200, "transmit deadline wraps");
	ASSERT_EQ(lichen_trickle_interval_end(&t), 700, "interval end wraps");
	ASSERT_FALSE(lichen_trickle_time_reached(UINT32_MAX, t.transmit_time),
		     "pre-wrap time remains before wrapped deadline");
	ASSERT_FALSE(lichen_trickle_time_reached(199, t.transmit_time),
		     "one tick before deadline");
	ASSERT_TRUE(lichen_trickle_time_reached(200, t.transmit_time),
		    "deadline reached across wrap");
	ASSERT_TRUE(lichen_trickle_next_event(&t, &ev), "event available");
	ASSERT_EQ(ev.at_ms, 200, "event exposes wrapped deadline");
	return 1;
}

static int test_state_transitions_reject_repeats(void)
{
	struct lichen_trickle t;

	lichen_trickle_init(&t, 1000, 1, 10);
	ASSERT_TRUE(lichen_trickle_start(&t, 0, 0), "start");
	ASSERT_TRUE(lichen_trickle_fire_transmit(&t), "first fire");
	ASSERT_FALSE(lichen_trickle_fire_transmit(&t), "repeated fire rejected");
	ASSERT_TRUE(lichen_trickle_expire(&t, 1000, 0), "expire after fire");
	ASSERT_FALSE(lichen_trickle_expire(&t, 1000, 0),
		     "early expire in new interval rejected");
	return 1;
}

/* ─── test runner ─────────────────────────────────────────────────────────── */

#define RUN_TEST(fn) do { \
	printf("  %s...", #fn); \
	tests_run++; \
	if (fn()) { \
		printf(" OK\n"); \
		tests_passed++; \
	} \
} while (0)

int main(void)
{
	printf("Trickle Timer Tests (RFC 6206)\n");
	printf("==============================\n\n");

	RUN_TEST(test_transmit_time_in_second_half_of_interval);
	RUN_TEST(test_fire_transmit_sets_next_event_to_expire);
	RUN_TEST(test_heard_consistent_suppresses_transmit_when_ge_k);
	RUN_TEST(test_expire_doubles_interval_capped_at_max);
	RUN_TEST(test_reset_shrinks_to_imin);
	RUN_TEST(test_reset_noop_when_already_at_imin);
	RUN_TEST(test_rand_offset_shifts_transmit_time);
	RUN_TEST(test_odd_interval_bias_free_transmit_time);
	RUN_TEST(test_max_interval_rejects_overflow);
	RUN_TEST(test_counter_saturates_at_max);
	RUN_TEST(test_zero_imin_uses_safe_default);
	RUN_TEST(test_profile_constants_and_max_math);
	RUN_TEST(test_invalid_imax_overflow_fails_closed);
	RUN_TEST(test_random_offset_bounds_are_checked_atomically);
	RUN_TEST(test_uptime_wrap_uses_modular_deadlines);
	RUN_TEST(test_state_transitions_reject_repeats);

	/* RFC2119 parameter validation */
	RUN_TEST(test_init_rejects_zero_k);
	RUN_TEST(test_init_null_pointer_does_not_crash);
	RUN_TEST(test_start_null_pointer_does_not_crash);
	RUN_TEST(test_fire_transmit_before_start_has_counter_below_k);
	RUN_TEST(test_expire_before_start_interval_stays_zero);
	RUN_TEST(test_next_event_before_start_returns_transmit);
	RUN_TEST(test_next_event_null_output_does_not_crash);
	RUN_TEST(test_redundancy_constant_zero_suppresses_always);
	RUN_TEST(test_expire_null_pointer_does_not_crash);
	RUN_TEST(test_reset_null_pointer_does_not_crash);
	RUN_TEST(test_repeated_start_resets_interval);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
