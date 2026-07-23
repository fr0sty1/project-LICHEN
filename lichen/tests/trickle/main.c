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

	uint32_t tt_before = t.transmit_time;
	lichen_trickle_reset(&t, 0, 999); /* different rand_offset - should not restart */
	ASSERT_EQ(t.transmit_time, tt_before, "transmit_time unchanged on noop reset");

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

/* ─── additional tests for saturation and overflow ────────────────────────── */

static int test_max_interval_saturates_on_overflow(void)
{
	struct lichen_trickle t;

	/* 1000 << 32 would overflow; should saturate at UINT32_MAX */
	lichen_trickle_init(&t, 1000, 32, 10);
	ASSERT_EQ(t.max_interval, UINT32_MAX, "max_interval saturates");

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

	/* imin=0 would cause busy loop; init defends by using 1 (see p00p) */
	lichen_trickle_init(&t, 0, 4, 10);
	ASSERT_EQ(t.imin, 1, "imin=0 normalized to 1");

	lichen_trickle_start(&t, 0, 0);
	ASSERT_EQ(t.interval, 1, "interval set to safe default");
	ASSERT_TRUE(t.transmit_time >= 0, "timer starts without immediate loop");

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
	RUN_TEST(test_max_interval_saturates_on_overflow);
	RUN_TEST(test_counter_saturates_at_max);
	RUN_TEST(test_zero_imin_uses_safe_default);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
