/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "vectors.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int64_t lichen_test_uptime_ms;

struct epoch_init_thread_arg {
	struct lichen_build_epoch_metadata metadata;
	int result;
};

static void *epoch_initializer(void *opaque)
{
	struct epoch_init_thread_arg *arg = opaque;

	arg->result = lichen_epoch_floor_init_metadata(&arg->metadata);
	return NULL;
}

static void test_build_epoch_metadata(void)
{
	struct lichen_build_epoch_snapshot snapshot;
	const struct lichen_build_epoch_metadata release = {
		.unix_time = 1700000000U,
		.source = LICHEN_BUILD_EPOCH_SOURCE_RELEASE,
	};
	const struct lichen_build_epoch_metadata rollback = {
		.unix_time = 1699999999U,
		.source = LICHEN_BUILD_EPOCH_SOURCE_RELEASE,
	};
	const struct lichen_build_epoch_metadata overflow = {
		.unix_time = (uint64_t)UINT32_MAX + 1U,
		.source = LICHEN_BUILD_EPOCH_SOURCE_RELEASE,
	};
	const struct lichen_build_epoch_metadata invalid_source = {
		.unix_time = 1700000000U,
		.source = LICHEN_BUILD_EPOCH_SOURCE_INVALID,
	};
	const struct lichen_build_epoch_metadata generated = {
		.unix_time = 1700000001U,
		.source = LICHEN_BUILD_EPOCH_SOURCE_DEVELOPER_GENERATED,
	};

	assert(lichen_time_sync_init() == 0);
	assert(lichen_build_epoch_snapshot_get(&snapshot) == 0);
	assert(!snapshot.initialized);
	assert(!lichen_wall_clock_valid());
	assert(lichen_epoch_floor_init_metadata(&overflow) == -EINVAL);
	assert(lichen_epoch_floor_init_metadata(&invalid_source) == -EINVAL);
	assert(lichen_epoch_floor_init_metadata(&release) == 0);
	assert(!lichen_wall_clock_valid());
	assert(lichen_epoch_floor_init_metadata(&release) == 0);
	assert(lichen_epoch_floor_init_metadata(&rollback) == -EALREADY);
	assert(lichen_build_epoch_snapshot_get(&snapshot) == 0);
	assert(snapshot.initialized);
	assert(snapshot.unix_time == release.unix_time);
	assert(snapshot.source == LICHEN_BUILD_EPOCH_SOURCE_RELEASE);
	assert(snapshot.deterministic);
	assert(snapshot.production);
	assert(!lichen_epoch_floor_accepts((uint32_t)release.unix_time - 1U));
	assert(lichen_epoch_floor_accepts((uint32_t)release.unix_time));

	assert(lichen_time_sync_init() == 0);
	assert(lichen_epoch_floor_init_metadata(&generated) == 0);
	assert(lichen_build_epoch_snapshot_get(&snapshot) == 0);
	assert(snapshot.initialized);
	assert(!snapshot.deterministic);
	assert(!snapshot.production);
}

static void test_build_epoch_concurrent_initialization(void)
{
	pthread_t first_thread;
	pthread_t second_thread;
	struct lichen_build_epoch_snapshot snapshot;
	struct epoch_init_thread_arg first = {
		.metadata = {
			.unix_time = 1700000010U,
			.source = LICHEN_BUILD_EPOCH_SOURCE_RELEASE,
		},
	};
	struct epoch_init_thread_arg second = {
		.metadata = {
			.unix_time = 1700000020U,
			.source = LICHEN_BUILD_EPOCH_SOURCE_DATE_EPOCH,
		},
	};

	assert(lichen_time_sync_init() == 0);
	assert(pthread_create(&first_thread, NULL, epoch_initializer, &first) == 0);
	assert(pthread_create(&second_thread, NULL, epoch_initializer, &second) == 0);
	assert(pthread_join(first_thread, NULL) == 0);
	assert(pthread_join(second_thread, NULL) == 0);
	assert((first.result == 0 && second.result == -EALREADY) ||
	       (first.result == -EALREADY && second.result == 0));
	assert(lichen_build_epoch_snapshot_get(&snapshot) == 0);
	assert(snapshot.initialized);
	if (first.result == 0) {
		assert(snapshot.unix_time == first.metadata.unix_time);
		assert(snapshot.source == first.metadata.source);
	} else {
		assert(snapshot.unix_time == second.metadata.unix_time);
		assert(snapshot.source == second.metadata.source);
	}
}

static void test_canonical_epoch_floor_vectors(void)
{
	for (size_t i = 0; i < sizeof(epoch_floor_vectors) /
				       sizeof(epoch_floor_vectors[0]); i++) {
		const struct epoch_floor_vector *vector = &epoch_floor_vectors[i];
		enum lichen_provision_status status = LICHEN_PROVISION_MISSING;

		assert(lichen_time_sync_init() == 0);
		assert(lichen_epoch_floor_init(vector->build_epoch) == 0);
		if (vector->has_provision) {
			assert(lichen_epoch_floor_set_provision(
				       vector->provision_epoch, vector->authenticated,
				       vector->max_provision_lead_s, &status) == 0);
			assert(status == vector->expected_status);
		}
		assert(lichen_epoch_floor_get() == vector->expected_floor);
		assert(!lichen_epoch_floor_accepts(vector->expected_floor - 1U));
		assert(lichen_epoch_floor_accepts(vector->expected_floor));
	}
}

static void test_monotonic_uptime(void)
{
	for (size_t i = 0; i < sizeof(monotonic_uptime_vectors) /
				       sizeof(monotonic_uptime_vectors[0]); i++) {
		const struct monotonic_uptime_vector *vector =
			&monotonic_uptime_vectors[i];
		struct lichen_monotonic_uptime uptime;
		uint64_t last = 123U;

		assert(lichen_monotonic_uptime_init(&uptime) == 0);
		assert(lichen_monotonic_uptime_now(&uptime, &last) == -EAGAIN);
		assert(last == 123U);
		for (size_t j = 0; j < vector->count; j++) {
			int err = lichen_monotonic_uptime_observe(
				&uptime, vector->observations[j]);

			assert((err == 0) == vector->expected_acceptance[j]);
		}
		assert(lichen_monotonic_uptime_now(&uptime, &last) == 0);
		assert(last == vector->expected_last);
	}

	struct lichen_monotonic_uptime sampled;
	uint64_t ticks = 99U;

	assert(lichen_monotonic_uptime_init(&sampled) == 0);
	lichen_test_uptime_ms = 0;
	assert(lichen_monotonic_uptime_sample(&sampled, &ticks) == 0);
	assert(ticks == 0U);
	lichen_test_uptime_ms = 100;
	assert(lichen_monotonic_uptime_sample(&sampled, &ticks) == 0);
	assert(ticks == 100U);
	lichen_test_uptime_ms = 99;
	assert(lichen_monotonic_uptime_sample(&sampled, &ticks) == -ERANGE);
	assert(ticks == 100U);
	lichen_test_uptime_ms = -1;
	assert(lichen_monotonic_uptime_sample(&sampled, &ticks) == -EIO);
	assert(ticks == 100U);
}

static void test_precedence_policy(void)
{
	struct lichen_time_source_precedence policy;
	struct lichen_time_source_precedence before;
	enum lichen_time_source_class selected = LICHEN_TIME_SOURCE_INTERNAL_RTC;
	uint8_t rank = UINT8_MAX;

	assert(lichen_time_source_precedence_default(&policy) == 0);
	for (size_t i = 0; i < LICHEN_TIME_SOURCE_CLASS_COUNT; i++) {
		assert(policy.order[i] == default_precedence[i]);
		assert(lichen_time_source_precedence_rank(
			       &policy, default_precedence[i], &rank) == 0);
		assert(rank == i);
	}

	assert(lichen_time_source_precedence_preferred(
		       &policy, LICHEN_TIME_SOURCE_NETWORK,
		       LICHEN_TIME_SOURCE_MANUAL, &selected) == 0);
	assert(selected == LICHEN_TIME_SOURCE_NETWORK);
	assert(lichen_time_source_precedence_preferred(
		       &policy, LICHEN_TIME_SOURCE_NETWORK,
		       LICHEN_TIME_SOURCE_NETWORK, &selected) == 0);
	assert(selected == LICHEN_TIME_SOURCE_NETWORK);

	assert(lichen_time_source_precedence_init(
		       &policy, custom_precedence,
		       LICHEN_TIME_SOURCE_CLASS_COUNT) == 0);
	assert(lichen_time_source_precedence_select(
		       &policy, eligible_candidates,
		       sizeof(eligible_candidates) / sizeof(eligible_candidates[0]),
		       &selected) == 0);
	assert(selected == LICHEN_TIME_SOURCE_MANUAL);

	before = policy;
	enum lichen_time_source_class duplicate[] = {
		LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_SOURCE_LOCAL_CLIENT,
		LICHEN_TIME_SOURCE_MANUAL,
		LICHEN_TIME_SOURCE_INTERNAL_RTC,
		LICHEN_TIME_SOURCE_MONOTONIC,
	};
	assert(lichen_time_source_precedence_init(
		       &policy, duplicate, LICHEN_TIME_SOURCE_CLASS_COUNT) == -EINVAL);
	assert(memcmp(&policy, &before, sizeof(policy)) == 0);
	assert(lichen_time_source_precedence_init(
		       &policy, custom_precedence,
		       LICHEN_TIME_SOURCE_CLASS_COUNT - 1U) == -EINVAL);
	assert(memcmp(&policy, &before, sizeof(policy)) == 0);
}

static void test_precedence_fallback(void)
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

	assert(lichen_time_source_precedence_default(&policy) == 0);
	assert(lichen_time_source_precedence_select(
		       &policy, candidates,
		       sizeof(candidates) / sizeof(candidates[0]), &selected) == 0);
	assert(selected == LICHEN_TIME_SOURCE_NETWORK);

	candidates[1].fresh = false;
	assert(lichen_time_source_precedence_select(
		       &policy, candidates,
		       sizeof(candidates) / sizeof(candidates[0]), &selected) == -ENOENT);
	assert(selected == LICHEN_TIME_SOURCE_NETWORK);

	candidates[5].source = (enum lichen_time_source_class)255;
	assert(lichen_time_source_precedence_select(
		       &policy, candidates,
		       sizeof(candidates) / sizeof(candidates[0]), &selected) == -EINVAL);
	assert(selected == LICHEN_TIME_SOURCE_NETWORK);

	candidates[5].source = LICHEN_TIME_SOURCE_GNSS;
	assert(lichen_time_source_precedence_select(
		       &policy, candidates,
		       sizeof(candidates) / sizeof(candidates[0]), &selected) == -EINVAL);
	assert(selected == LICHEN_TIME_SOURCE_NETWORK);

	policy.order[0] = LICHEN_TIME_SOURCE_MONOTONIC;
	assert(lichen_time_source_precedence_rank(
		       &policy, LICHEN_TIME_SOURCE_NETWORK, &(uint8_t){99}) == -EINVAL);
}

static void test_wall_clock_transitions(void)
{
	struct lichen_wall_clock_snapshot snapshot;
	enum lichen_provision_status provision_status;

	assert(lichen_time_sync_init() == 0);
	assert(lichen_wall_clock_snapshot_get(0, &snapshot) == 0);
	assert(!snapshot.wall_clock_valid);
	assert(snapshot.state == LICHEN_WALL_CLOCK_INVALID);
	assert(snapshot.source == LICHEN_TIME_SOURCE_MONOTONIC);
	assert(lichen_wall_clock_establish(
		1700000000U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 0, 10, 5) == -EINVAL);
	assert(lichen_epoch_floor_init(1700000000U) == 0);

	assert(lichen_wall_clock_establish(
		1699999999U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 0, 10, 5) == -ERANGE);
	assert(lichen_wall_clock_establish(
		1700000000U, LICHEN_TIME_SOURCE_MONOTONIC,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 0, 10, 5) == -EINVAL);
	assert(lichen_wall_clock_establish(
		1700000000U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_NO_SYNC, 0, 0, 10, 5) == -EINVAL);
	assert(lichen_wall_clock_establish(
		1700000000U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 2, 1, 10, 5) == -ERANGE);
	assert(lichen_wall_clock_establish(
		1700000000U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 10001, 10, 5) == -ETIME);

	assert(lichen_wall_clock_establish(
		1700000000U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 1000, 1000, 10, 5) == 0);
	assert(lichen_wall_clock_snapshot_get(11000, &snapshot) == 0);
	assert(snapshot.wall_clock_valid);
	assert(snapshot.state == LICHEN_WALL_CLOCK_FRESH);
	assert(snapshot.unix_time == 1700000010U);
	assert(snapshot.age_s == 10U);
	assert(snapshot.source == LICHEN_TIME_SOURCE_GNSS);
	assert(lichen_wall_clock_snapshot_get(11001, &snapshot) == 0);
	assert(snapshot.wall_clock_valid);
	assert(snapshot.state == LICHEN_WALL_CLOCK_HOLDOVER);
	assert(lichen_wall_clock_snapshot_get(16000, &snapshot) == 0);
	assert(snapshot.wall_clock_valid);
	assert(snapshot.state == LICHEN_WALL_CLOCK_HOLDOVER);
	assert(snapshot.unix_time == 1700000015U);
	assert(lichen_wall_clock_snapshot_get(16001, &snapshot) == 0);
	assert(!snapshot.wall_clock_valid);

	assert(lichen_wall_clock_establish(
		1700000020U, LICHEN_TIME_SOURCE_NETWORK,
		LICHEN_TIME_STRATUM_NTS, 16001, 16001, 10, 0) == 0);
	assert(lichen_wall_clock_establish(
		1700000019U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 16001, 16001, 10, 0) == -EALREADY);
	assert(lichen_wall_clock_snapshot_get(16001, &snapshot) == 0);
	assert(snapshot.unix_time == 1700000020U);
	assert(snapshot.source == LICHEN_TIME_SOURCE_NETWORK);
	assert(lichen_wall_clock_snapshot_get(16000, &snapshot) == -ERANGE);
	assert(!snapshot.wall_clock_valid);

	assert(lichen_wall_clock_establish(
		UINT32_MAX, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 0, 1, 0) == 0);
	assert(lichen_wall_clock_snapshot_get(1000, &snapshot) == -EOVERFLOW);
	assert(!snapshot.wall_clock_valid);

	lichen_test_uptime_ms = 1000;
	assert(lichen_wall_clock_establish(
		1700000100U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 1000, 10, 0) == 0);
	assert(lichen_epoch_floor_set_provision(
		1700000102U, true, 1000U, &provision_status) == 0);
	assert(provision_status == LICHEN_PROVISION_ACCEPTED);
	assert(!lichen_wall_clock_valid());

	assert(lichen_wall_clock_set(
		1700000200U, LICHEN_TIME_SOURCE_INTERNAL_RTC,
		LICHEN_TIME_STRATUM_CONSERVATIVE) == 0);
	assert(lichen_wall_clock_valid());
	assert(lichen_wall_clock_get() == 1700000200U);
	assert(lichen_wall_clock_source() == LICHEN_TIME_SOURCE_INTERNAL_RTC);
	lichen_time_sync_desync();
	assert(!lichen_wall_clock_valid());
	assert(lichen_wall_clock_get() == 0U);
	assert(lichen_wall_clock_source() == LICHEN_TIME_SOURCE_MONOTONIC);
}

static void *wall_clock_writer(void *unused)
{
	(void)unused;
	for (size_t i = 0; i < 2000U; i++) {
		enum lichen_time_source_class source = (i & 1U) == 0U ?
			LICHEN_TIME_SOURCE_GNSS : LICHEN_TIME_SOURCE_NETWORK;
		uint8_t stratum = source == LICHEN_TIME_SOURCE_GNSS ?
			LICHEN_TIME_STRATUM_GNSS_GPSD : LICHEN_TIME_STRATUM_NTS;

		if (lichen_wall_clock_establish(1700000300U, source, stratum,
						 0, 0, 10, 5) != 0) {
			return (void *)1;
		}
	}
	return NULL;
}

static void *wall_clock_reader(void *unused)
{
	(void)unused;
	for (size_t i = 0; i < 2000U; i++) {
		struct lichen_wall_clock_snapshot snapshot;

		if (lichen_wall_clock_snapshot_get(0, &snapshot) != 0 ||
		    !snapshot.wall_clock_valid || snapshot.unix_time != 1700000300U) {
			return (void *)1;
		}
		if (!((snapshot.source == LICHEN_TIME_SOURCE_GNSS &&
		       snapshot.stratum == LICHEN_TIME_STRATUM_GNSS_GPSD) ||
		      (snapshot.source == LICHEN_TIME_SOURCE_NETWORK &&
		       snapshot.stratum == LICHEN_TIME_STRATUM_NTS))) {
			return (void *)1;
		}
	}
	return NULL;
}

static void test_wall_clock_concurrency(void)
{
	pthread_t writer;
	pthread_t reader;
	void *writer_result;
	void *reader_result;

	assert(lichen_time_sync_init() == 0);
	assert(lichen_epoch_floor_init(1700000000U) == 0);
	assert(lichen_wall_clock_establish(
		1700000300U, LICHEN_TIME_SOURCE_GNSS,
		LICHEN_TIME_STRATUM_GNSS_GPSD, 0, 0, 10, 5) == 0);
	assert(pthread_create(&writer, NULL, wall_clock_writer, NULL) == 0);
	assert(pthread_create(&reader, NULL, wall_clock_reader, NULL) == 0);
	assert(pthread_join(writer, &writer_result) == 0);
	assert(pthread_join(reader, &reader_result) == 0);
	assert(writer_result == NULL);
	assert(reader_result == NULL);
}

int main(void)
{
	for (size_t i = 0; i < sizeof(time_source_class_vectors) /
				       sizeof(time_source_class_vectors[0]); i++) {
		const struct time_source_class_vector *vector =
			&time_source_class_vectors[i];

		assert((int)vector->source == (int)i);
		assert(strcmp(lichen_time_source_class_str(vector->source),
			      vector->name) == 0);
		assert(lichen_time_source_can_establish_wall_clock(vector->source) ==
		       vector->can_establish_wall_clock);
	}

	assert(strcmp(lichen_time_source_class_str(
		      (enum lichen_time_source_class)-1), "Unknown") == 0);
	assert(strcmp(lichen_time_source_class_str(
		      (enum lichen_time_source_class)6), "Unknown") == 0);
	assert(!lichen_time_source_can_establish_wall_clock(
		(enum lichen_time_source_class)-1));
	assert(!lichen_time_source_can_establish_wall_clock(
		(enum lichen_time_source_class)6));
	test_build_epoch_metadata();
	test_build_epoch_concurrent_initialization();
	test_canonical_epoch_floor_vectors();
	test_monotonic_uptime();
	test_precedence_policy();
	test_precedence_fallback();
	test_wall_clock_transitions();
	test_wall_clock_concurrency();
	return 0;
}
