/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file time_sync.c
 * @brief Time synchronization per spec 09 section 14.6
 *
 * Implements:
 * - Time source class tracking (GNSS, Network, Local-client, etc.)
 * - Time stratum (0-4) for DIO Time Option
 * - Epoch floor validation (firmware build + optional board provision)
 * - DIO Time Option encode/decode (provisional Type 0x15)
 * - Wall clock state with source provenance
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <lichen/link.h>

LOG_MODULE_REGISTER(lichen_time_sync, CONFIG_LICHEN_LINK_LOG_LEVEL);
K_MUTEX_DEFINE(s_wall_clock_lock);

/* ---- Static state ---- */

static uint32_t s_current_sfn;
static bool s_synced;
static uint8_t s_stratum;
static uint32_t s_wall_clock_unix;
static bool s_wall_clock_valid;
static enum lichen_time_source_class s_wall_clock_source;
static uint64_t s_wall_clock_observed_ms;
static uint32_t s_wall_clock_fresh_for_s;
static uint32_t s_wall_clock_holdover_s;
static uint32_t s_firmware_build_epoch;
static enum lichen_build_epoch_source s_firmware_build_epoch_source;
static uint32_t s_provision_epoch;
static bool s_provision_authenticated;

static const enum lichen_time_source_class s_default_source_precedence[] = {
	LICHEN_TIME_SOURCE_GNSS,
	LICHEN_TIME_SOURCE_NETWORK,
	LICHEN_TIME_SOURCE_LOCAL_CLIENT,
	LICHEN_TIME_SOURCE_MANUAL,
	LICHEN_TIME_SOURCE_INTERNAL_RTC,
	LICHEN_TIME_SOURCE_MONOTONIC,
};

int lichen_monotonic_uptime_init(struct lichen_monotonic_uptime *uptime)
{
	if (uptime == NULL) {
		return -EINVAL;
	}

	uptime->last_ticks = 0U;
	uptime->initialized = false;
	return 0;
}

int lichen_monotonic_uptime_observe(struct lichen_monotonic_uptime *uptime,
				    uint64_t ticks)
{
	if (uptime == NULL) {
		return -EINVAL;
	}
	if (uptime->initialized && ticks < uptime->last_ticks) {
		return -ERANGE;
	}

	uptime->last_ticks = ticks;
	uptime->initialized = true;
	return 0;
}

int lichen_monotonic_uptime_now(const struct lichen_monotonic_uptime *uptime,
				uint64_t *ticks)
{
	if (uptime == NULL || ticks == NULL) {
		return -EINVAL;
	}
	if (!uptime->initialized) {
		return -EAGAIN;
	}

	*ticks = uptime->last_ticks;
	return 0;
}

int lichen_monotonic_uptime_sample(struct lichen_monotonic_uptime *uptime,
				   uint64_t *ticks)
{
	int64_t sample;
	int err;

	if (uptime == NULL || ticks == NULL) {
		return -EINVAL;
	}

	sample = k_uptime_get();
	if (sample < 0) {
		return -EIO;
	}
	err = lichen_monotonic_uptime_observe(uptime, (uint64_t)sample);
	if (err != 0) {
		return err;
	}

	*ticks = (uint64_t)sample;
	return 0;
}

static uint32_t epoch_floor_get_locked(void)
{
	if (s_provision_authenticated &&
	    s_provision_epoch >= s_firmware_build_epoch) {
		return s_provision_epoch;
	}
	return s_firmware_build_epoch;
}

static void wall_clock_clear_locked(void)
{
	s_wall_clock_unix = 0U;
	s_wall_clock_valid = false;
	s_wall_clock_source = LICHEN_TIME_SOURCE_MONOTONIC;
	s_wall_clock_observed_ms = 0U;
	s_wall_clock_fresh_for_s = 0U;
	s_wall_clock_holdover_s = 0U;
	s_stratum = LICHEN_TIME_STRATUM_NO_SYNC;
}

static void wall_clock_invalid_snapshot(
	struct lichen_wall_clock_snapshot *snapshot)
{
	*snapshot = (struct lichen_wall_clock_snapshot) {
		.wall_clock_valid = false,
		.state = LICHEN_WALL_CLOCK_INVALID,
		.unix_time = 0U,
		.source = LICHEN_TIME_SOURCE_MONOTONIC,
		.stratum = LICHEN_TIME_STRATUM_NO_SYNC,
		.age_s = 0U,
	};
}

static int wall_clock_snapshot_locked(
	uint64_t now_monotonic_ms,
	struct lichen_wall_clock_snapshot *snapshot)
{
	uint64_t elapsed_ms;
	uint64_t fresh_ms;
	uint64_t lifetime_s;
	uint64_t lifetime_ms;
	uint64_t projected;

	wall_clock_invalid_snapshot(snapshot);
	if (!s_wall_clock_valid) {
		return 0;
	}
	if (s_firmware_build_epoch == 0U ||
	    !lichen_time_source_can_establish_wall_clock(s_wall_clock_source) ||
	    !lichen_time_stratum_valid(s_stratum) ||
	    s_stratum == LICHEN_TIME_STRATUM_NO_SYNC) {
		wall_clock_clear_locked();
		return -EINVAL;
	}
	if (now_monotonic_ms < s_wall_clock_observed_ms) {
		wall_clock_clear_locked();
		return -ERANGE;
	}

	elapsed_ms = now_monotonic_ms - s_wall_clock_observed_ms;
	fresh_ms = (uint64_t)s_wall_clock_fresh_for_s * 1000U;
	lifetime_s = (uint64_t)s_wall_clock_fresh_for_s +
		     (uint64_t)s_wall_clock_holdover_s;
	lifetime_ms = lifetime_s * 1000U;
	if (elapsed_ms > lifetime_ms) {
		wall_clock_clear_locked();
		return 0;
	}

	projected = (uint64_t)s_wall_clock_unix + elapsed_ms / 1000U;
	if (projected > UINT32_MAX) {
		wall_clock_clear_locked();
		return -EOVERFLOW;
	}
	if ((uint32_t)projected < epoch_floor_get_locked()) {
		wall_clock_clear_locked();
		return -ERANGE;
	}

	snapshot->wall_clock_valid = true;
	snapshot->state = elapsed_ms <= fresh_ms ?
		LICHEN_WALL_CLOCK_FRESH : LICHEN_WALL_CLOCK_HOLDOVER;
	snapshot->unix_time = (uint32_t)projected;
	snapshot->source = s_wall_clock_source;
	snapshot->stratum = s_stratum;
	snapshot->age_s = elapsed_ms / 1000U > UINT32_MAX ?
		UINT32_MAX : (uint32_t)(elapsed_ms / 1000U);
	return 0;
}

/* ---- Time source class ---- */

const char *lichen_time_source_class_str(enum lichen_time_source_class source)
{
	switch (source) {
	case LICHEN_TIME_SOURCE_GNSS:
		return "GNSS";
	case LICHEN_TIME_SOURCE_NETWORK:
		return "Network";
	case LICHEN_TIME_SOURCE_LOCAL_CLIENT:
		return "Local-client";
	case LICHEN_TIME_SOURCE_MANUAL:
		return "Manual/static";
	case LICHEN_TIME_SOURCE_INTERNAL_RTC:
		return "Internal RTC";
	case LICHEN_TIME_SOURCE_MONOTONIC:
		return "Monotonic";
	default:
		return "Unknown";
	}
}

bool lichen_time_source_can_establish_wall_clock(
	enum lichen_time_source_class source)
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

static int time_source_index(enum lichen_time_source_class source)
{
	switch (source) {
	case LICHEN_TIME_SOURCE_GNSS:
		return 0;
	case LICHEN_TIME_SOURCE_NETWORK:
		return 1;
	case LICHEN_TIME_SOURCE_LOCAL_CLIENT:
		return 2;
	case LICHEN_TIME_SOURCE_MANUAL:
		return 3;
	case LICHEN_TIME_SOURCE_INTERNAL_RTC:
		return 4;
	case LICHEN_TIME_SOURCE_MONOTONIC:
		return 5;
	default:
		return -EINVAL;
	}
}

static int time_source_precedence_validate(
	const struct lichen_time_source_precedence *policy)
{
	bool seen[LICHEN_TIME_SOURCE_CLASS_COUNT] = {false};

	if (policy == NULL) {
		return -EINVAL;
	}

	for (size_t i = 0; i < LICHEN_TIME_SOURCE_CLASS_COUNT; i++) {
		int index = time_source_index(policy->order[i]);

		if (index < 0 || seen[index]) {
			return -EINVAL;
		}
		seen[index] = true;
	}

	return 0;
}

int lichen_time_source_precedence_default(
	struct lichen_time_source_precedence *policy)
{
	if (policy == NULL) {
		return -EINVAL;
	}

	memcpy(policy->order, s_default_source_precedence,
	       sizeof(policy->order));
	return 0;
}

int lichen_time_source_precedence_init(
	struct lichen_time_source_precedence *policy,
	const enum lichen_time_source_class *order,
	size_t count)
{
	struct lichen_time_source_precedence candidate;

	if (policy == NULL || order == NULL ||
	    count != LICHEN_TIME_SOURCE_CLASS_COUNT) {
		return -EINVAL;
	}

	memcpy(candidate.order, order, sizeof(candidate.order));
	if (time_source_precedence_validate(&candidate) != 0) {
		return -EINVAL;
	}

	*policy = candidate;
	return 0;
}

int lichen_time_source_precedence_rank(
	const struct lichen_time_source_precedence *policy,
	enum lichen_time_source_class source,
	uint8_t *rank)
{
	if (rank == NULL || time_source_precedence_validate(policy) != 0 ||
	    time_source_index(source) < 0) {
		return -EINVAL;
	}

	for (size_t i = 0; i < LICHEN_TIME_SOURCE_CLASS_COUNT; i++) {
		if (policy->order[i] == source) {
			*rank = (uint8_t)i;
			return 0;
		}
	}

	return -EINVAL;
}

int lichen_time_source_precedence_preferred(
	const struct lichen_time_source_precedence *policy,
	enum lichen_time_source_class left,
	enum lichen_time_source_class right,
	enum lichen_time_source_class *preferred)
{
	uint8_t left_rank;
	uint8_t right_rank;

	if (preferred == NULL ||
	    lichen_time_source_precedence_rank(policy, left, &left_rank) != 0 ||
	    lichen_time_source_precedence_rank(policy, right, &right_rank) != 0) {
		return -EINVAL;
	}

	*preferred = left_rank <= right_rank ? left : right;
	return 0;
}

int lichen_time_source_precedence_select(
	const struct lichen_time_source_precedence *policy,
	const struct lichen_time_source_candidate *candidates,
	size_t count,
	enum lichen_time_source_class *selected)
{
	bool seen[LICHEN_TIME_SOURCE_CLASS_COUNT] = {false};
	bool have_best = false;
	uint8_t best_rank = UINT8_MAX;
	enum lichen_time_source_class best = LICHEN_TIME_SOURCE_MONOTONIC;

	if (selected == NULL || time_source_precedence_validate(policy) != 0 ||
	    count > LICHEN_TIME_SOURCE_CLASS_COUNT ||
	    (count > 0U && candidates == NULL)) {
		return -EINVAL;
	}

	/* Validate the complete input before selecting or mutating output. */
	for (size_t i = 0; i < count; i++) {
		int index = time_source_index(candidates[i].source);

		if (index < 0 || seen[index]) {
			return -EINVAL;
		}
		seen[index] = true;
	}

	for (size_t i = 0; i < count; i++) {
		const struct lichen_time_source_candidate *candidate =
			&candidates[i];
		uint8_t rank;

		if (!lichen_time_source_can_establish_wall_clock(candidate->source) ||
		    !candidate->source_valid || !candidate->fresh ||
		    !candidate->policy_accepted || !candidate->rollback_safe) {
			continue;
		}
		if (lichen_time_source_precedence_rank(policy, candidate->source,
						 &rank) != 0) {
			return -EINVAL;
		}
		if (!have_best || rank < best_rank) {
			best = candidate->source;
			best_rank = rank;
			have_best = true;
		}
	}

	if (!have_best) {
		return -ENOENT;
	}

	*selected = best;
	return 0;
}

/* ---- Time stratum ---- */

bool lichen_time_stratum_valid(uint8_t stratum)
{
	return stratum <= LICHEN_TIME_STRATUM_GNSS_GPSD;
}

/* ---- Epoch floor ---- */

static bool build_epoch_source_valid(enum lichen_build_epoch_source source)
{
	return source >= LICHEN_BUILD_EPOCH_SOURCE_DATE_EPOCH &&
	       source <= LICHEN_BUILD_EPOCH_SOURCE_FIXED_TEST;
}

static bool build_epoch_source_deterministic(
	enum lichen_build_epoch_source source)
{
	return source != LICHEN_BUILD_EPOCH_SOURCE_DEVELOPER_GENERATED &&
	       build_epoch_source_valid(source);
}

static bool build_epoch_source_production(
	enum lichen_build_epoch_source source)
{
	return source == LICHEN_BUILD_EPOCH_SOURCE_DATE_EPOCH ||
	       source == LICHEN_BUILD_EPOCH_SOURCE_RELEASE;
}

int lichen_epoch_floor_init_metadata(
	const struct lichen_build_epoch_metadata *metadata)
{
	if (metadata == NULL || metadata->unix_time == 0U ||
	    metadata->unix_time > UINT32_MAX ||
	    !build_epoch_source_valid(metadata->source)) {
		LOG_ERR("Invalid firmware build epoch metadata");
		return -EINVAL;
	}

	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	if (s_firmware_build_epoch != 0U) {
		bool identical =
			s_firmware_build_epoch == (uint32_t)metadata->unix_time &&
			s_firmware_build_epoch_source == metadata->source;

		k_mutex_unlock(&s_wall_clock_lock);
		return identical ? 0 : -EALREADY;
	}

	s_firmware_build_epoch = (uint32_t)metadata->unix_time;
	s_firmware_build_epoch_source = metadata->source;
	s_provision_epoch = 0;
	s_provision_authenticated = false;
	if (s_wall_clock_valid) {
		struct lichen_wall_clock_snapshot snapshot;
		int64_t now_ms = k_uptime_get();

		if (now_ms < 0) {
			wall_clock_clear_locked();
		} else {
			(void)wall_clock_snapshot_locked((uint64_t)now_ms, &snapshot);
		}
	}
	k_mutex_unlock(&s_wall_clock_lock);
	return 0;
}

int lichen_epoch_floor_init(uint32_t firmware_build_epoch)
{
	const struct lichen_build_epoch_metadata metadata = {
		.unix_time = firmware_build_epoch,
		.source = LICHEN_BUILD_EPOCH_SOURCE_FIXED_TEST,
	};

	return lichen_epoch_floor_init_metadata(&metadata);
}

int lichen_build_epoch_snapshot_get(
	struct lichen_build_epoch_snapshot *snapshot)
{
	if (snapshot == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	*snapshot = (struct lichen_build_epoch_snapshot) {
		.initialized = s_firmware_build_epoch != 0U,
		.unix_time = s_firmware_build_epoch,
		.source = s_firmware_build_epoch_source,
		.deterministic = build_epoch_source_deterministic(
			s_firmware_build_epoch_source),
		.production = build_epoch_source_production(
			s_firmware_build_epoch_source),
	};
	k_mutex_unlock(&s_wall_clock_lock);
	return 0;
}

int lichen_epoch_floor_set_provision(uint32_t provision_epoch,
				     bool authenticated,
				     uint32_t max_lead_s,
				     enum lichen_provision_status *status)
{
	if (status == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	if (s_firmware_build_epoch == 0U) {
		k_mutex_unlock(&s_wall_clock_lock);
		LOG_ERR("Epoch floor not initialized");
		return -EINVAL;
	}

	if (!authenticated) {
		*status = LICHEN_PROVISION_UNAUTHENTICATED;
		k_mutex_unlock(&s_wall_clock_lock);
		return 0;
	}

	if (provision_epoch < s_firmware_build_epoch) {
		*status = LICHEN_PROVISION_BEFORE_BUILD;
		k_mutex_unlock(&s_wall_clock_lock);
		return 0;
	}

	/* Check lead bound with overflow protection */
	uint32_t lead = provision_epoch - s_firmware_build_epoch;
	if (lead > max_lead_s) {
		*status = LICHEN_PROVISION_BEYOND_LEAD;
		k_mutex_unlock(&s_wall_clock_lock);
		return 0;
	}

	s_provision_epoch = provision_epoch;
	s_provision_authenticated = true;
	*status = LICHEN_PROVISION_ACCEPTED;
	if (s_wall_clock_valid) {
		struct lichen_wall_clock_snapshot snapshot;
		int64_t now_ms = k_uptime_get();

		if (now_ms < 0) {
			wall_clock_clear_locked();
		} else {
			(void)wall_clock_snapshot_locked((uint64_t)now_ms, &snapshot);
		}
	}
	k_mutex_unlock(&s_wall_clock_lock);
	return 0;
}

uint32_t lichen_epoch_floor_get(void)
{
	uint32_t floor;

	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	floor = epoch_floor_get_locked();
	k_mutex_unlock(&s_wall_clock_lock);
	return floor;
}

bool lichen_epoch_floor_accepts(uint32_t unix_time)
{
	bool accepted;

	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	accepted = unix_time >= epoch_floor_get_locked();
	k_mutex_unlock(&s_wall_clock_lock);
	return accepted;
}

const char *lichen_provision_status_str(enum lichen_provision_status status)
{
	switch (status) {
	case LICHEN_PROVISION_MISSING:
		return "missing";
	case LICHEN_PROVISION_ACCEPTED:
		return "accepted";
	case LICHEN_PROVISION_UNAUTHENTICATED:
		return "unauthenticated";
	case LICHEN_PROVISION_BEFORE_BUILD:
		return "before-build";
	case LICHEN_PROVISION_BEYOND_LEAD:
		return "beyond-lead";
	default:
		return "unknown";
	}
}

/* ---- DIO Time Option ---- */

int lichen_dio_time_option_encode(const struct lichen_dio_time_option *opt,
				  uint8_t *buf, size_t buflen)
{
	if (opt == NULL || buf == NULL) {
		return -EINVAL;
	}
	if (buflen < LICHEN_DIO_TIME_OPTION_LEN) {
		return -ENOMEM;
	}
	if (opt->stratum > LICHEN_TIME_STRATUM_GNSS_GPSD) {
		return -EINVAL;
	}
	/* NO_SYNC stratum MUST have zero timestamp */
	if (opt->stratum == LICHEN_TIME_STRATUM_NO_SYNC && opt->timestamp != 0) {
		return -EINVAL;
	}

	buf[0] = LICHEN_DIO_TIME_OPTION_TYPE;
	buf[1] = LICHEN_DIO_TIME_OPTION_DATA_LEN;
	buf[2] = opt->stratum;
	buf[3] = 0; /* Reserved */
	buf[4] = (opt->timestamp >> 24) & 0xFF;
	buf[5] = (opt->timestamp >> 16) & 0xFF;
	buf[6] = (opt->timestamp >> 8) & 0xFF;
	buf[7] = opt->timestamp & 0xFF;

	return LICHEN_DIO_TIME_OPTION_LEN;
}

int lichen_dio_time_option_decode(const uint8_t *buf, size_t buflen,
				  struct lichen_dio_time_option *opt)
{
	if (buf == NULL || opt == NULL) {
		return -EINVAL;
	}
	if (buflen < LICHEN_DIO_TIME_OPTION_LEN) {
		return -ENODATA;
	}
	if (buf[0] != LICHEN_DIO_TIME_OPTION_TYPE) {
		return -EPROTO;
	}
	if (buf[1] != LICHEN_DIO_TIME_OPTION_DATA_LEN) {
		return -EPROTO;
	}
	if (buf[3] != 0) {
		/* Reserved field must be zero */
		return -EPROTO;
	}
	if (buf[2] > LICHEN_TIME_STRATUM_GNSS_GPSD) {
		return -EPROTO;
	}

	opt->stratum = buf[2];
	opt->timestamp = ((uint32_t)buf[4] << 24) |
			 ((uint32_t)buf[5] << 16) |
			 ((uint32_t)buf[6] << 8) |
			 (uint32_t)buf[7];

	/* NO_SYNC stratum MUST have zero timestamp */
	if (opt->stratum == LICHEN_TIME_STRATUM_NO_SYNC && opt->timestamp != 0) {
		return -EPROTO;
	}

	return LICHEN_DIO_TIME_OPTION_LEN;
}

/* ---- Wall clock management ---- */

int lichen_wall_clock_establish(
	uint32_t unix_time,
	enum lichen_time_source_class source,
	uint8_t stratum,
	uint64_t observed_monotonic_ms,
	uint64_t now_monotonic_ms,
	uint32_t fresh_for_s,
	uint32_t holdover_s)
{
	struct lichen_wall_clock_snapshot current;
	uint64_t elapsed_ms;
	uint64_t candidate_projected;
	int current_status;

	if (!lichen_time_source_can_establish_wall_clock(source)) {
		LOG_WRN("Source %s cannot establish wall clock",
			lichen_time_source_class_str(source));
		return -EINVAL;
	}
	if (!lichen_time_stratum_valid(stratum) ||
	    stratum == LICHEN_TIME_STRATUM_NO_SYNC) {
		LOG_WRN("Invalid wall-clock stratum %u", stratum);
		return -EINVAL;
	}
	if (now_monotonic_ms < observed_monotonic_ms) {
		return -ERANGE;
	}

	elapsed_ms = now_monotonic_ms - observed_monotonic_ms;
	if (elapsed_ms > (uint64_t)fresh_for_s * 1000U) {
		return -ETIME;
	}
	candidate_projected = (uint64_t)unix_time + elapsed_ms / 1000U;
	if (candidate_projected > UINT32_MAX) {
		return -EOVERFLOW;
	}

	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	if (s_firmware_build_epoch == 0U) {
		k_mutex_unlock(&s_wall_clock_lock);
		return -EINVAL;
	}
	if ((uint32_t)candidate_projected < epoch_floor_get_locked()) {
		LOG_WRN("Unix time %u below epoch floor %u",
			(uint32_t)candidate_projected, epoch_floor_get_locked());
		k_mutex_unlock(&s_wall_clock_lock);
		return -ERANGE;
	}

	current_status = wall_clock_snapshot_locked(now_monotonic_ms, &current);
	if (current_status == 0 && current.wall_clock_valid &&
	    candidate_projected < current.unix_time) {
		k_mutex_unlock(&s_wall_clock_lock);
		return -EALREADY;
	}

	s_wall_clock_unix = unix_time;
	s_wall_clock_source = source;
	s_wall_clock_observed_ms = observed_monotonic_ms;
	s_wall_clock_fresh_for_s = fresh_for_s;
	s_wall_clock_holdover_s = holdover_s;
	s_stratum = stratum;
	s_wall_clock_valid = true;
	k_mutex_unlock(&s_wall_clock_lock);

	LOG_INF("Wall clock set: %u (source=%s, stratum=%u)",
		unix_time, lichen_time_source_class_str(source), stratum);

	return 0;
}

int lichen_wall_clock_snapshot_get(
	uint64_t now_monotonic_ms,
	struct lichen_wall_clock_snapshot *snapshot)
{
	int status;

	if (snapshot == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	status = wall_clock_snapshot_locked(now_monotonic_ms, snapshot);
	k_mutex_unlock(&s_wall_clock_lock);
	return status;
}

int lichen_wall_clock_set(uint32_t unix_time,
			  enum lichen_time_source_class source,
			  uint8_t stratum)
{
	int64_t now_ms = k_uptime_get();

	if (now_ms < 0) {
		return -ERANGE;
	}
	return lichen_wall_clock_establish(
		unix_time, source, stratum, (uint64_t)now_ms, (uint64_t)now_ms,
		LICHEN_WALL_CLOCK_DEFAULT_FRESH_S,
		LICHEN_WALL_CLOCK_DEFAULT_HOLDOVER_S);
}

bool lichen_wall_clock_valid(void)
{
	struct lichen_wall_clock_snapshot snapshot;
	int64_t now_ms = k_uptime_get();

	return now_ms >= 0 &&
	       lichen_wall_clock_snapshot_get((uint64_t)now_ms, &snapshot) == 0 &&
	       snapshot.wall_clock_valid;
}

uint32_t lichen_wall_clock_get(void)
{
	struct lichen_wall_clock_snapshot snapshot;
	int64_t now_ms = k_uptime_get();

	if (now_ms < 0 ||
	    lichen_wall_clock_snapshot_get((uint64_t)now_ms, &snapshot) != 0 ||
	    !snapshot.wall_clock_valid) {
		return 0U;
	}
	return snapshot.unix_time;
}

enum lichen_time_source_class lichen_wall_clock_source(void)
{
	struct lichen_wall_clock_snapshot snapshot;
	int64_t now_ms = k_uptime_get();

	if (now_ms < 0 ||
	    lichen_wall_clock_snapshot_get((uint64_t)now_ms, &snapshot) != 0 ||
	    !snapshot.wall_clock_valid) {
		return LICHEN_TIME_SOURCE_MONOTONIC;
	}
	return snapshot.source;
}

void lichen_wall_clock_invalidate(void)
{
	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	wall_clock_clear_locked();
	k_mutex_unlock(&s_wall_clock_lock);
	LOG_INF("Wall clock invalidated");
}

/* ---- SFN (Super Frame Number) management ---- */

uint32_t lichen_time_sync_get_sfn(void)
{
	return s_current_sfn;
}

int lichen_time_sync_set_sfn(uint32_t sfn)
{
	if (s_synced && sfn <= s_current_sfn) {
		return -EALREADY;
	}

	s_current_sfn = sfn;
	s_synced = true;

	return 0;
}

bool lichen_time_sync_is_synced(void)
{
	return s_synced;
}

void lichen_time_sync_advance_sfn(void)
{
	s_current_sfn++;
}

void lichen_time_sync_desync(void)
{
	s_synced = false;
	lichen_wall_clock_invalidate();
}

uint8_t lichen_time_sync_get_stratum(void)
{
	uint8_t stratum;

	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	stratum = s_stratum;
	k_mutex_unlock(&s_wall_clock_lock);
	return stratum;
}

int lichen_time_sync_set_stratum(uint8_t stratum)
{
	if (stratum > LICHEN_TIME_STRATUM_GNSS_GPSD) {
		return -EINVAL;
	}

	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	if (stratum == LICHEN_TIME_STRATUM_NO_SYNC) {
		wall_clock_clear_locked();
		k_mutex_unlock(&s_wall_clock_lock);
		return 0;
	}
	s_stratum = stratum;
	k_mutex_unlock(&s_wall_clock_lock);
	return 0;
}

int lichen_time_sync_update_from_parent(uint32_t sfn, uint8_t parent_stratum)
{
	if (parent_stratum == LICHEN_TIME_STRATUM_NO_SYNC ||
	    parent_stratum > LICHEN_TIME_STRATUM_GNSS_GPSD) {
		return -EINVAL;
	}

	int err = lichen_time_sync_set_sfn(sfn);
	if (err != 0) {
		return err;
	}

	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	s_stratum = LICHEN_TIME_STRATUM_CONSERVATIVE;
	k_mutex_unlock(&s_wall_clock_lock);
	return 0;
}

int lichen_time_sync_init(void)
{
	int err = 0;

	s_current_sfn = 0;
	s_synced = false;
	k_mutex_lock(&s_wall_clock_lock, K_FOREVER);
	wall_clock_clear_locked();
	s_firmware_build_epoch = 0;
	s_firmware_build_epoch_source = LICHEN_BUILD_EPOCH_SOURCE_INVALID;
	s_provision_epoch = 0;
	s_provision_authenticated = false;
	k_mutex_unlock(&s_wall_clock_lock);

#if defined(CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX)
	const struct lichen_build_epoch_metadata metadata = {
		.unix_time = CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX,
#if defined(CONFIG_LICHEN_TIME_BUILD_EPOCH_SOURCE_DATE_EPOCH)
		.source = LICHEN_BUILD_EPOCH_SOURCE_DATE_EPOCH,
#elif defined(CONFIG_LICHEN_TIME_BUILD_EPOCH_SOURCE_RELEASE)
		.source = LICHEN_BUILD_EPOCH_SOURCE_RELEASE,
#elif defined(CONFIG_LICHEN_TIME_BUILD_EPOCH_SOURCE_DEVELOPER_GENERATED)
		.source = LICHEN_BUILD_EPOCH_SOURCE_DEVELOPER_GENERATED,
#elif defined(CONFIG_LICHEN_TIME_BUILD_EPOCH_SOURCE_DEVELOPER_FIXED)
		.source = LICHEN_BUILD_EPOCH_SOURCE_DEVELOPER_FIXED,
#else
		.source = LICHEN_BUILD_EPOCH_SOURCE_FIXED_TEST,
#endif
	};

	err = lichen_epoch_floor_init_metadata(&metadata);
#endif
	return err;
}
