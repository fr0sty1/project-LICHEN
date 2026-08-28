/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_TEST_TIME_SOURCE_CLASS_VECTORS_H_
#define LICHEN_TEST_TIME_SOURCE_CLASS_VECTORS_H_

#include <stdbool.h>

#include <lichen/link.h>

struct time_source_class_vector {
	enum lichen_time_source_class source;
	const char *name;
	bool can_establish_wall_clock;
};

struct epoch_floor_vector {
	uint32_t build_epoch;
	bool has_provision;
	uint32_t provision_epoch;
	bool authenticated;
	uint32_t max_provision_lead_s;
	uint32_t expected_floor;
	enum lichen_provision_status expected_status;
};

#define MONOTONIC_UPTIME_MAX_OBSERVATIONS 4U

struct monotonic_uptime_vector {
	const char *name;
	uint64_t observations[MONOTONIC_UPTIME_MAX_OBSERVATIONS];
	bool expected_acceptance[MONOTONIC_UPTIME_MAX_OBSERVATIONS];
	size_t count;
	uint64_t expected_last;
};

/* Canonical Python/Rust strings and spec order. */
static const struct time_source_class_vector time_source_class_vectors[] = {
	{LICHEN_TIME_SOURCE_GNSS, "GNSS", true},
	{LICHEN_TIME_SOURCE_NETWORK, "Network", true},
	{LICHEN_TIME_SOURCE_LOCAL_CLIENT, "Local-client", true},
	{LICHEN_TIME_SOURCE_MANUAL, "Manual/static", true},
	{LICHEN_TIME_SOURCE_INTERNAL_RTC, "Internal RTC", true},
	{LICHEN_TIME_SOURCE_MONOTONIC, "Monotonic", false},
};

static const enum lichen_time_source_class default_precedence[] = {
	LICHEN_TIME_SOURCE_GNSS,
	LICHEN_TIME_SOURCE_NETWORK,
	LICHEN_TIME_SOURCE_LOCAL_CLIENT,
	LICHEN_TIME_SOURCE_MANUAL,
	LICHEN_TIME_SOURCE_INTERNAL_RTC,
	LICHEN_TIME_SOURCE_MONOTONIC,
};

static const enum lichen_time_source_class custom_precedence[] = {
	LICHEN_TIME_SOURCE_MANUAL,
	LICHEN_TIME_SOURCE_LOCAL_CLIENT,
	LICHEN_TIME_SOURCE_NETWORK,
	LICHEN_TIME_SOURCE_GNSS,
	LICHEN_TIME_SOURCE_INTERNAL_RTC,
	LICHEN_TIME_SOURCE_MONOTONIC,
};

static const struct lichen_time_source_candidate eligible_candidates[] = {
	{LICHEN_TIME_SOURCE_MANUAL, true, true, true, true},
	{LICHEN_TIME_SOURCE_NETWORK, true, true, true, true},
	{LICHEN_TIME_SOURCE_GNSS, true, true, true, true},
	{LICHEN_TIME_SOURCE_MONOTONIC, true, true, true, true},
};

/* test/vectors/packets-timing.json time_sync_epoch_floor cases. */
static const struct epoch_floor_vector epoch_floor_vectors[] = {
	{1700000000U, false, 0U, false, 0U, 1700000000U,
	 LICHEN_PROVISION_MISSING},
	{1700000000U, true, 1800000000U, true, 100000000U, 1800000000U,
	 LICHEN_PROVISION_ACCEPTED},
	{1900000000U, true, 1800000000U, true, 100000000U, 1900000000U,
	 LICHEN_PROVISION_BEFORE_BUILD},
	{1700000000U, true, 1800000001U, true, 100000000U, 1700000000U,
	 LICHEN_PROVISION_BEYOND_LEAD},
	{1700000000U, true, 1800000000U, false, 0U, 1700000000U,
	 LICHEN_PROVISION_UNAUTHENTICATED},
};

/* test/vectors/packets-timing.json monotonic_uptime_sequences cases. */
static const struct monotonic_uptime_vector monotonic_uptime_vectors[] = {
	{"boot_origin_zero", {0U}, {true}, 1U, 0U},
	{"strictly_increasing", {0U, 1U, 1000000U, UINT64_MAX},
	 {true, true, true, true}, 4U, UINT64_MAX},
	{"equal_observations_allowed", {42U, 42U, 43U},
	 {true, true, true}, 3U, 43U},
	{"regression_rejected", {100U, 99U}, {true, false}, 2U, 100U},
	{"wrap_to_zero_rejected", {UINT64_MAX, 0U},
	 {true, false}, 2U, UINT64_MAX},
};

#endif /* LICHEN_TEST_TIME_SOURCE_CLASS_VECTORS_H_ */
