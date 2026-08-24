/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief RFC 6550 Section 7.2 DAO Path Sequence comparison tests
 *
 * Expected values are copied from RFC 6550 Section 7.2, the canonical
 * test/vectors/rpl_route_state.json sequence_relations, and the serial-
 * arithmetic formulation of rust/lichen-rpl/src/routing.rs seq_is_newer()
 * (lines 63-89), which accepts multi-step wraps inside each region. They
 * are not derived from the C implementation under test. The exhaustive
 * all-pairs check lives in sweep.c + golden_lollipop_sweep.txt.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <lichen/rpl_routing.h>

/* The enum comes from the real header above; pin the values that the
 * canonical JSON vectors and this file's tables are encoded against. */
_Static_assert(LICHEN_RPL_SEQUENCE_EQUAL == 0, "vector encoding drift");
_Static_assert(LICHEN_RPL_SEQUENCE_NEWER == 1, "vector encoding drift");
_Static_assert(LICHEN_RPL_SEQUENCE_STALE == 2, "vector encoding drift");
_Static_assert(LICHEN_RPL_SEQUENCE_INCOMPARABLE == 3, "vector encoding drift");

static int tests_run;
static int tests_passed;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", \
		       msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

/*
 * Canonical route-state sequence_relations (independent copy of
 * test/vectors/rpl_route_state.json). Path Sequence is an 8-bit lollipop
 * per RFC 6550 7.2; increment_lollipop 127->0 is newer.
 */
static const struct {
	const char *name;
	uint8_t current;
	uint8_t incoming;
	enum lichen_rpl_sequence_relation expected;
} sequence_relations[] = {
	{"equal", 10, 10, LICHEN_RPL_SEQUENCE_EQUAL},
	{"circular_exact_16_newer", 0, 16, LICHEN_RPL_SEQUENCE_NEWER},
	{"circular_exact_17_incomparable", 0, 17, LICHEN_RPL_SEQUENCE_INCOMPARABLE},
	{"circular_exact_16_stale", 16, 0, LICHEN_RPL_SEQUENCE_STALE},
	{"circular_wrap_127_to_0", 127, 0, LICHEN_RPL_SEQUENCE_NEWER},
	{"circular_wrap_reverse_stale", 0, 127, LICHEN_RPL_SEQUENCE_STALE},
	{"linear_exact_16_newer", 239, 255, LICHEN_RPL_SEQUENCE_NEWER},
	{"linear_exact_17_incomparable", 238, 255, LICHEN_RPL_SEQUENCE_INCOMPARABLE},
	{"linear_stale", 255, 250, LICHEN_RPL_SEQUENCE_STALE},
	{"linear_wrap_255_to_0", 255, 0, LICHEN_RPL_SEQUENCE_NEWER},
	{"cross_region_within_window", 250, 5, LICHEN_RPL_SEQUENCE_NEWER},
	{"cross_region_outside_window", 240, 5, LICHEN_RPL_SEQUENCE_STALE},
	{"cross_region_linear_newer", 120, 128, LICHEN_RPL_SEQUENCE_NEWER},
	{"cross_region_circular_stale", 128, 0, LICHEN_RPL_SEQUENCE_STALE},
};

/*
 * RFC 6550 7.2 / rust lichen-rpl lollipop_cmp table, mapped to sequence
 * relation. (0,127) is NEWER here because Path Sequence uses
 * increment_lollipop. Same-region comparisons use RFC 1982 serial
 * arithmetic, which accepts multi-step restart crossings.
 */
static const struct {
	uint8_t incoming;
	uint8_t current;
	enum lichen_rpl_sequence_relation expected;
} rfc_mapped_cases[] = {
	{0, 0, LICHEN_RPL_SEQUENCE_EQUAL},
	{128, 128, LICHEN_RPL_SEQUENCE_EQUAL},
	{16, 0, LICHEN_RPL_SEQUENCE_NEWER},
	{17, 0, LICHEN_RPL_SEQUENCE_INCOMPARABLE},
	{0, 16, LICHEN_RPL_SEQUENCE_STALE},
	{0, 17, LICHEN_RPL_SEQUENCE_INCOMPARABLE},
	{0, 127, LICHEN_RPL_SEQUENCE_NEWER},
	{127, 0, LICHEN_RPL_SEQUENCE_STALE},
	/* routing.rs seq_is_newer(5, 120): (5-120) & 0x7F = 13 <= 16, so
	 * current=5 is newer than incoming=120 across the 127->0 restart. */
	{120, 5, LICHEN_RPL_SEQUENCE_STALE},
	{255, 239, LICHEN_RPL_SEQUENCE_NEWER},
	{255, 238, LICHEN_RPL_SEQUENCE_INCOMPARABLE},
	{5, 250, LICHEN_RPL_SEQUENCE_NEWER},
	{5, 240, LICHEN_RPL_SEQUENCE_STALE},
	{0, 240, LICHEN_RPL_SEQUENCE_NEWER},
	{0, 239, LICHEN_RPL_SEQUENCE_STALE},
	{240, 5, LICHEN_RPL_SEQUENCE_NEWER},
	{250, 5, LICHEN_RPL_SEQUENCE_STALE},
};

static const struct {
	uint8_t incoming;
	uint8_t current;
	enum lichen_rpl_sequence_relation expected;
} window_boundary_cases[] = {
	{16, 0, LICHEN_RPL_SEQUENCE_NEWER},
	{15, 0, LICHEN_RPL_SEQUENCE_NEWER},
	{17, 0, LICHEN_RPL_SEQUENCE_INCOMPARABLE},
	{255, 239, LICHEN_RPL_SEQUENCE_NEWER},
	{255, 240, LICHEN_RPL_SEQUENCE_NEWER},
	{255, 238, LICHEN_RPL_SEQUENCE_INCOMPARABLE},
	{0, 240, LICHEN_RPL_SEQUENCE_NEWER},
	{0, 241, LICHEN_RPL_SEQUENCE_NEWER},
	{0, 239, LICHEN_RPL_SEQUENCE_STALE},
	{250, 10, LICHEN_RPL_SEQUENCE_STALE},
	{250, 9, LICHEN_RPL_SEQUENCE_STALE},
	{250, 11, LICHEN_RPL_SEQUENCE_NEWER},
};

/*
 * Multi-step wrap boundaries. routing.rs seq_is_newer() treats each region
 * as its own 128-value RFC 1982 space, so a counter that advanced past a
 * region-internal wrap stays comparable for SEQUENCE_WINDOW steps.
 */
static const struct {
	uint8_t incoming;
	uint8_t current;
	enum lichen_rpl_sequence_relation expected;
} multi_step_wrap_cases[] = {
	/* 13 steps across the circular-region 127->0 restart. */
	{5, 120, LICHEN_RPL_SEQUENCE_NEWER},
	{120, 5, LICHEN_RPL_SEQUENCE_STALE},
	/* 2 steps across the restart. */
	{1, 127, LICHEN_RPL_SEQUENCE_NEWER},
	{127, 1, LICHEN_RPL_SEQUENCE_STALE},
	/* Circular [128..255] region: 130 follows 250 across the 255->0
	 * wrap in serial space ((130-250) & 0x7F = 8). */
	{130, 250, LICHEN_RPL_SEQUENCE_NEWER},
	{250, 130, LICHEN_RPL_SEQUENCE_STALE},
	/* Region-adjacent pair at the [128..255] boundary: one step. */
	{128, 255, LICHEN_RPL_SEQUENCE_NEWER},
	{255, 128, LICHEN_RPL_SEQUENCE_STALE},
};

static int test_canonical_sequence_relations(void)
{
	size_t i;

	for (i = 0; i < sizeof(sequence_relations) / sizeof(sequence_relations[0]); i++) {
		enum lichen_rpl_sequence_relation got;
		char msg[80];

		got = lichen_rpl_sequence_compare(sequence_relations[i].incoming,
						  sequence_relations[i].current);
		(void)snprintf(msg, sizeof(msg), "%s", sequence_relations[i].name);
		ASSERT_EQ(got, sequence_relations[i].expected, msg);
	}
	return 1;
}

static int test_rfc_mapped_table(void)
{
	size_t i;

	for (i = 0; i < sizeof(rfc_mapped_cases) / sizeof(rfc_mapped_cases[0]); i++) {
		enum lichen_rpl_sequence_relation got;
		char msg[64];

		got = lichen_rpl_sequence_compare(rfc_mapped_cases[i].incoming,
						  rfc_mapped_cases[i].current);
		(void)snprintf(msg, sizeof(msg), "rfc (%u, %u)",
			       rfc_mapped_cases[i].incoming,
			       rfc_mapped_cases[i].current);
		ASSERT_EQ(got, rfc_mapped_cases[i].expected, msg);
	}
	return 1;
}

static int test_window_boundaries(void)
{
	size_t i;

	for (i = 0; i < sizeof(window_boundary_cases) / sizeof(window_boundary_cases[0]); i++) {
		enum lichen_rpl_sequence_relation got;
		char msg[64];

		got = lichen_rpl_sequence_compare(window_boundary_cases[i].incoming,
						  window_boundary_cases[i].current);
		(void)snprintf(msg, sizeof(msg), "window (%u, %u)",
			       window_boundary_cases[i].incoming,
			       window_boundary_cases[i].current);
		ASSERT_EQ(got, window_boundary_cases[i].expected, msg);
	}
	return 1;
}

static int test_multi_step_wraps(void)
{
	size_t i;

	for (i = 0; i < sizeof(multi_step_wrap_cases) / sizeof(multi_step_wrap_cases[0]); i++) {
		enum lichen_rpl_sequence_relation got;
		char msg[64];

		got = lichen_rpl_sequence_compare(multi_step_wrap_cases[i].incoming,
						  multi_step_wrap_cases[i].current);
		(void)snprintf(msg, sizeof(msg), "wrap (%u, %u)",
			       multi_step_wrap_cases[i].incoming,
			       multi_step_wrap_cases[i].current);
		ASSERT_EQ(got, multi_step_wrap_cases[i].expected, msg);
	}
	return 1;
}

int main(void)
{
	struct {
		const char *name;
		int (*fn)(void);
	} tests[] = {
		{"canonical sequence_relations", test_canonical_sequence_relations},
		{"RFC 7.2 mapped table", test_rfc_mapped_table},
		{"window boundaries", test_window_boundaries},
		{"multi-step serial wraps", test_multi_step_wraps},
	};
	size_t i;

	printf("RPL DAO sequence comparison (RFC 6550 Section 7.2)\n");

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		tests_run++;
		printf("  %s: ", tests[i].name);
		if (tests[i].fn() != 0) {
			printf("PASS\n");
			tests_passed++;
		}
	}

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
