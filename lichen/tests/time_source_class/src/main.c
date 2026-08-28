/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>

#include "vectors.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

#define TEST_BUILD_EPOCH 1700000000U

ZTEST(time_source_class, test_canonical_python_rust_vectors)
{
	for (size_t i = 0; i < ARRAY_SIZE(time_source_class_vectors); i++) {
		const struct time_source_class_vector *vector =
			&time_source_class_vectors[i];
		bool can_establish =
			lichen_time_source_can_establish_wall_clock(vector->source);

		zassert_equal((int)vector->source, (int)i,
			      "enum order differs at %zu", i);
		zassert_str_equal(lichen_time_source_class_str(vector->source),
				  vector->name, "wire name differs at %zu", i);
		zassert_equal(can_establish,
			vector->can_establish_wall_clock,
			"wall-clock capability differs at %zu", i);
	}
}

ZTEST(time_source_class, test_invalid_values_fail_closed)
{
	static const int invalid_values[] = {-1, 6, 255};

	for (size_t i = 0; i < ARRAY_SIZE(invalid_values); i++) {
		enum lichen_time_source_class source =
			(enum lichen_time_source_class)invalid_values[i];

		const char *name = lichen_time_source_class_str(source);
		bool can_establish =
			lichen_time_source_can_establish_wall_clock(source);

		zassert_str_equal(name, "Unknown",
				  "invalid source has a canonical name");
		zassert_false(can_establish,
			      "invalid source can establish wall clock");
	}
}

ZTEST(time_source_class, test_monotonic_uptime_vectors_and_errors)
{
	for (size_t i = 0; i < ARRAY_SIZE(monotonic_uptime_vectors); i++) {
		const struct monotonic_uptime_vector *vector =
			&monotonic_uptime_vectors[i];
		struct lichen_monotonic_uptime uptime;
		uint64_t last = 0U;

		zassert_ok(lichen_monotonic_uptime_init(&uptime));
		zassert_equal(lichen_monotonic_uptime_now(&uptime, &last),
			      -EAGAIN);
		for (size_t j = 0; j < vector->count; j++) {
			int err = lichen_monotonic_uptime_observe(
				&uptime, vector->observations[j]);

			zassert_equal(err == 0, vector->expected_acceptance[j],
				      "%s observation %zu", vector->name, j);
		}
		zassert_ok(lichen_monotonic_uptime_now(&uptime, &last));
		zassert_equal(last, vector->expected_last);
	}

}

ZTEST(time_source_class, test_default_and_configurable_precedence)
{
	struct lichen_time_source_precedence policy;
	struct lichen_time_source_precedence before;
	enum lichen_time_source_class selected = LICHEN_TIME_SOURCE_INTERNAL_RTC;
	uint8_t rank = UINT8_MAX;

	zassert_ok(lichen_time_source_precedence_default(&policy));
	for (size_t i = 0; i < LICHEN_TIME_SOURCE_CLASS_COUNT; i++) {
		zassert_equal(policy.order[i], default_precedence[i]);
		zassert_ok(lichen_time_source_precedence_rank(
			&policy, default_precedence[i], &rank));
		zassert_equal(rank, i);
	}

	zassert_ok(lichen_time_source_precedence_preferred(
		&policy, LICHEN_TIME_SOURCE_NETWORK, LICHEN_TIME_SOURCE_MANUAL,
		&selected));
	zassert_equal(selected, LICHEN_TIME_SOURCE_NETWORK);
	zassert_ok(lichen_time_source_precedence_preferred(
		&policy, LICHEN_TIME_SOURCE_NETWORK, LICHEN_TIME_SOURCE_NETWORK,
		&selected));
	zassert_equal(selected, LICHEN_TIME_SOURCE_NETWORK);

	zassert_ok(lichen_time_source_precedence_init(
		&policy, custom_precedence, LICHEN_TIME_SOURCE_CLASS_COUNT));
	zassert_ok(lichen_time_source_precedence_select(
		&policy, eligible_candidates, ARRAY_SIZE(eligible_candidates),
		&selected));
	zassert_equal(selected, LICHEN_TIME_SOURCE_MANUAL);

	before = policy;
	enum lichen_time_source_class duplicate[] = {
		LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_SOURCE_LOCAL_CLIENT,
		LICHEN_TIME_SOURCE_MANUAL,
		LICHEN_TIME_SOURCE_INTERNAL_RTC,
		LICHEN_TIME_SOURCE_MONOTONIC,
	};
	zassert_equal(lichen_time_source_precedence_init(
		&policy, duplicate, LICHEN_TIME_SOURCE_CLASS_COUNT), -EINVAL);
	zassert_mem_equal(&policy, &before, sizeof(policy));
	zassert_equal(lichen_time_source_precedence_init(
		&policy, custom_precedence, LICHEN_TIME_SOURCE_CLASS_COUNT - 1U),
		-EINVAL);
	zassert_mem_equal(&policy, &before, sizeof(policy));
}

ZTEST(time_source_class, test_freshness_validity_and_rollback_fallback)
{
	struct lichen_time_source_precedence policy;
	struct lichen_time_source_candidate candidates[] = {
		{LICHEN_TIME_SOURCE_GNSS, true, false, true, true},
		{LICHEN_TIME_SOURCE_NETWORK, true, true, true, true},
		{LICHEN_TIME_SOURCE_LOCAL_CLIENT, true, true, false, true},
		{LICHEN_TIME_SOURCE_MANUAL, true, true, true, false},
		{LICHEN_TIME_SOURCE_INTERNAL_RTC, false, true, true, true},
		{LICHEN_TIME_SOURCE_MONOTONIC, true, true, true, true},
	};
	enum lichen_time_source_class selected = LICHEN_TIME_SOURCE_INTERNAL_RTC;

	zassert_ok(lichen_time_source_precedence_default(&policy));
	zassert_ok(lichen_time_source_precedence_select(
		&policy, candidates, ARRAY_SIZE(candidates), &selected));
	zassert_equal(selected, LICHEN_TIME_SOURCE_NETWORK);

	candidates[1].fresh = false;
	zassert_equal(lichen_time_source_precedence_select(
		&policy, candidates, ARRAY_SIZE(candidates), &selected), -ENOENT);
	zassert_equal(selected, LICHEN_TIME_SOURCE_NETWORK,
		      "failed selection mutated output");

	candidates[5].source = (enum lichen_time_source_class)255;
	zassert_equal(lichen_time_source_precedence_select(
		&policy, candidates, ARRAY_SIZE(candidates), &selected), -EINVAL);
	zassert_equal(selected, LICHEN_TIME_SOURCE_NETWORK,
		      "invalid input mutated output");

	candidates[5].source = LICHEN_TIME_SOURCE_GNSS;
	zassert_equal(lichen_time_source_precedence_select(
		&policy, candidates, ARRAY_SIZE(candidates), &selected), -EINVAL);
	zassert_equal(selected, LICHEN_TIME_SOURCE_NETWORK,
		      "duplicate input mutated output");
}

ZTEST(time_source_class, test_wall_clock_validity_transitions)
{
	struct lichen_wall_clock_snapshot snapshot;
	struct lichen_build_epoch_snapshot build;

	zassert_ok(lichen_time_sync_init());
	zassert_ok(lichen_build_epoch_snapshot_get(&build));
	zassert_true(build.initialized);
	zassert_equal(build.unix_time, TEST_BUILD_EPOCH);
	zassert_ok(lichen_wall_clock_snapshot_get(0, &snapshot));
	zassert_false(snapshot.wall_clock_valid);
	zassert_equal(lichen_wall_clock_establish(
		TEST_BUILD_EPOCH - 1U,
		LICHEN_TIME_SOURCE_GNSS, LICHEN_TIME_STRATUM_GNSS_GPSD,
		0, 0, 10, 5), -ERANGE);
	zassert_ok(lichen_epoch_floor_init(1700000000U));
	zassert_equal(lichen_wall_clock_establish(
		1699999999U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 0, 10, 5), -ERANGE);
	zassert_equal(lichen_wall_clock_establish(
		1700000000U, LICHEN_TIME_SOURCE_MONOTONIC,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 0, 10, 5), -EINVAL);
	zassert_equal(lichen_wall_clock_establish(
		1700000000U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 2, 1, 10, 5), -ERANGE);
	zassert_equal(lichen_wall_clock_establish(
		1700000000U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 10001, 10, 5), -ETIME);

	zassert_ok(lichen_wall_clock_establish(
		1700000000U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 1000, 1000, 10, 5));
	zassert_ok(lichen_wall_clock_snapshot_get(11000, &snapshot));
	zassert_true(snapshot.wall_clock_valid);
	zassert_equal(snapshot.state, LICHEN_WALL_CLOCK_FRESH);
	zassert_equal(snapshot.unix_time, 1700000010U);
	zassert_ok(lichen_wall_clock_snapshot_get(11001, &snapshot));
	zassert_equal(snapshot.state, LICHEN_WALL_CLOCK_HOLDOVER);
	zassert_ok(lichen_wall_clock_snapshot_get(16000, &snapshot));
	zassert_true(snapshot.wall_clock_valid);
	zassert_equal(snapshot.unix_time, 1700000015U);
	zassert_ok(lichen_wall_clock_snapshot_get(16001, &snapshot));
	zassert_false(snapshot.wall_clock_valid);

	zassert_ok(lichen_wall_clock_establish(
		1700000020U, LICHEN_TIME_SOURCE_NETWORK,
		LICHEN_TIME_STRATUM_NTS, 16001, 16001, 10, 0));
	zassert_equal(lichen_wall_clock_establish(
		1700000019U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 16001, 16001, 10, 0),
		-EALREADY);
	zassert_ok(lichen_wall_clock_snapshot_get(16001, &snapshot));
	zassert_equal(snapshot.unix_time, 1700000020U);
	zassert_equal(snapshot.source, LICHEN_TIME_SOURCE_NETWORK);
	zassert_equal(lichen_wall_clock_snapshot_get(16000, &snapshot), -ERANGE);
	zassert_false(snapshot.wall_clock_valid);

	zassert_ok(lichen_wall_clock_establish(
		UINT32_MAX, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 0, 1, 0));
	zassert_equal(lichen_wall_clock_snapshot_get(1000, &snapshot), -EOVERFLOW);
	zassert_false(snapshot.wall_clock_valid);
}

ZTEST(time_source_class, test_build_epoch_metadata_is_immutable)
{
	struct lichen_build_epoch_snapshot before;
	struct lichen_build_epoch_snapshot after;
	const struct lichen_build_epoch_metadata overflow = {
		.unix_time = (uint64_t)UINT32_MAX + 1U,
		.source = LICHEN_BUILD_EPOCH_SOURCE_RELEASE,
	};
	const struct lichen_build_epoch_metadata rollback = {
		.unix_time = TEST_BUILD_EPOCH - 1U,
		.source = LICHEN_BUILD_EPOCH_SOURCE_FIXED_TEST,
	};

	zassert_ok(lichen_time_sync_init());
	zassert_ok(lichen_build_epoch_snapshot_get(&before));
	zassert_true(before.initialized);
	zassert_false(lichen_wall_clock_valid());
	zassert_equal(lichen_epoch_floor_init_metadata(&overflow), -EINVAL);
	zassert_equal(lichen_epoch_floor_init_metadata(&rollback), -EALREADY);
	zassert_ok(lichen_build_epoch_snapshot_get(&after));
	zassert_mem_equal(&after, &before, sizeof(before));
	zassert_false(lichen_wall_clock_valid());
}

ZTEST(time_source_class, test_epoch_floor_and_desync_invalidate_wall_clock)
{
	enum lichen_provision_status provision_status;

	zassert_ok(lichen_time_sync_init());
	zassert_ok(lichen_epoch_floor_init(1700000000U));
	zassert_ok(lichen_wall_clock_establish(
		1700000100U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 0, 300, 0));
	zassert_ok(lichen_epoch_floor_set_provision(
		1700000102U, true, 1000U, &provision_status));
	zassert_equal(provision_status, LICHEN_PROVISION_ACCEPTED);
	zassert_false(lichen_wall_clock_valid());

	zassert_ok(lichen_wall_clock_set(
		1700000200U, LICHEN_TIME_SOURCE_INTERNAL_RTC,
		LICHEN_TIME_STRATUM_CONSERVATIVE));
	zassert_true(lichen_wall_clock_valid());
	zassert_equal(lichen_wall_clock_get(), 1700000200U);
	zassert_equal(lichen_wall_clock_source(), LICHEN_TIME_SOURCE_INTERNAL_RTC);
	lichen_time_sync_desync();
	zassert_false(lichen_wall_clock_valid());
	zassert_equal(lichen_wall_clock_get(), 0U);
	zassert_equal(lichen_wall_clock_source(), LICHEN_TIME_SOURCE_MONOTONIC);
}

ZTEST_SUITE(time_source_class, NULL, NULL, NULL, NULL, NULL);
