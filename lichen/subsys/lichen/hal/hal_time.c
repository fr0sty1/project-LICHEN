/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/hal.h>
#include "hal_internal.h"

struct time_provider_state lichen_hal_time_state;
K_MUTEX_DEFINE(lichen_hal_time_mutex);

static bool valid_time_source_class(
	enum lichen_hal_time_source_class source_class)
{
	return source_class > LICHEN_HAL_TIME_SOURCE_NONE &&
	       source_class <= LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC;
}

static uint32_t elapsed_seconds_since_ms(int64_t observed)
{
	int64_t now = lichen_hal_now_ms();
	uint64_t elapsed_ms;

	if (now <= observed) {
		return 0U;
	}
	if (observed < 0 && now >= 0) {
		elapsed_ms = (uint64_t)now + (uint64_t)(-(observed + 1)) + 1U;
	} else {
		elapsed_ms = (uint64_t)(now - observed);
	}
	if (elapsed_ms / 1000U > UINT32_MAX) {
		return UINT32_MAX;
	}

	return (uint32_t)(elapsed_ms / 1000U);
}

static uint32_t time_age_seconds(const struct lichen_hal_time_sample *sample)
{
	return elapsed_seconds_since_ms(sample->observed_uptime_ms);
}

static uint32_t time_build_epoch(void)
{
	return (uint32_t)CONFIG_LICHEN_TIME_BUILD_EPOCH_UNIX;
}

static uint32_t time_effective_epoch_floor_locked(void)
{
	uint32_t floor = time_build_epoch();

	if (lichen_hal_time_state.provision_epoch_valid &&
	    lichen_hal_time_state.provision_epoch > floor) {
		floor = lichen_hal_time_state.provision_epoch;
	}

	return floor;
}

static bool provision_epoch_in_lead_bound(uint32_t provision_epoch)
{
	uint32_t build_epoch = time_build_epoch();
	uint64_t max_epoch = (uint64_t)build_epoch +
			     (uint64_t)CONFIG_LICHEN_TIME_PROVISION_MAX_LEAD_S;

	return provision_epoch >= build_epoch && provision_epoch <= max_epoch;
}

static int time_source_priority(enum lichen_hal_time_source_class source_class)
{
	switch (source_class) {
	case LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC:
		return 6;
	case LICHEN_HAL_TIME_SOURCE_LOCAL_CLIENT:
		return 5;
	case LICHEN_HAL_TIME_SOURCE_NETWORK:
		return 4;
	case LICHEN_HAL_TIME_SOURCE_GNSS:
		return 3;
	case LICHEN_HAL_TIME_SOURCE_INTERNAL_RTC:
		return 2;
	case LICHEN_HAL_TIME_SOURCE_MONOTONIC_INTERNAL:
		return 1;
	case LICHEN_HAL_TIME_SOURCE_NONE:
	default:
		return 0;
	}
}

static bool time_sample_is_stale(const struct lichen_hal_time_sample *sample)
{
	return time_age_seconds(sample) > CONFIG_LICHEN_TIME_FRESHNESS_MAX_AGE_S;
}

static bool time_sample_passes_floor_locked(
	const struct lichen_hal_time_sample *sample)
{
	return sample->unix_time_valid &&
	       sample->unix_time >= time_effective_epoch_floor_locked();
}

static bool time_sample_can_establish_locked(
	const struct lichen_hal_time_sample *sample)
{
	return sample->source_class != LICHEN_HAL_TIME_SOURCE_MONOTONIC_INTERNAL &&
	       time_sample_passes_floor_locked(sample) &&
	       !time_sample_is_stale(sample);
}

static uint32_t time_sample_current_unix(
	const struct lichen_hal_time_sample *sample)
{
	uint64_t current = (uint64_t)sample->unix_time +
			   (uint64_t)time_age_seconds(sample);

	return current > UINT32_MAX ? UINT32_MAX : (uint32_t)current;
}

static const struct lichen_hal_time_sample *select_time_sample_locked(void)
{
	for (int source = LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC;
	     source > LICHEN_HAL_TIME_SOURCE_NONE; source--) {
		const struct lichen_hal_time_sample *sample =
			&lichen_hal_time_state.samples[source];

		if (!lichen_hal_time_state.has_sample[source]) {
			continue;
		}
		if (time_sample_can_establish_locked(sample)) {
			return sample;
		}
	}

	return NULL;
}

static const struct lichen_hal_time_sample *select_time_diagnostic_sample_locked(void)
{
	if (lichen_hal_time_state.has_diagnostic_sample &&
	    lichen_hal_time_state.last_rejection == LICHEN_HAL_TIME_REJECT_BELOW_EPOCH_FLOOR) {
		return &lichen_hal_time_state.diagnostic_sample;
	}
	for (int source = LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC;
	     source > LICHEN_HAL_TIME_SOURCE_NONE; source--) {
		if (lichen_hal_time_state.has_sample[source]) {
			return &lichen_hal_time_state.samples[source];
		}
	}

	return NULL;
}

static void time_set_rejection_locked(
	enum lichen_hal_time_rejection_reason reason)
{
	lichen_hal_time_state.last_rejection = reason;
}

static void time_store_sample_locked(const struct lichen_hal_time_sample *sample)
{
	lichen_hal_time_state.samples[sample->source_class] = *sample;
	if (sample->source_name != NULL) {
		strncpy(lichen_hal_time_state.source_names[sample->source_class],
			sample->source_name,
			sizeof(lichen_hal_time_state.source_names[sample->source_class]) - 1U);
		lichen_hal_time_state.source_names[sample->source_class]
			[sizeof(lichen_hal_time_state.source_names[sample->source_class]) - 1U] = '\0';
	} else {
		lichen_hal_time_state.source_names[sample->source_class][0] = '\0';
	}
	lichen_hal_time_state.samples[sample->source_class].source_name =
		lichen_hal_time_state.source_names[sample->source_class];
	lichen_hal_time_state.has_sample[sample->source_class] = true;
}

static void time_store_diagnostic_sample_locked(
	const struct lichen_hal_time_sample *sample)
{
	lichen_hal_time_state.diagnostic_sample = *sample;
	if (sample->source_name != NULL) {
		strncpy(lichen_hal_time_state.diagnostic_source_name,
			sample->source_name,
			sizeof(lichen_hal_time_state.diagnostic_source_name) - 1U);
		lichen_hal_time_state.diagnostic_source_name
			[sizeof(lichen_hal_time_state.diagnostic_source_name) - 1U] = '\0';
	} else {
		lichen_hal_time_state.diagnostic_source_name[0] = '\0';
	}
	lichen_hal_time_state.diagnostic_sample.source_name =
		lichen_hal_time_state.diagnostic_source_name;
	lichen_hal_time_state.has_diagnostic_sample = true;
}

static void time_clear_diagnostic_sample_locked(void)
{
	memset(&lichen_hal_time_state.diagnostic_sample, 0,
	       sizeof(lichen_hal_time_state.diagnostic_sample));
	memset(lichen_hal_time_state.diagnostic_source_name, 0,
	       sizeof(lichen_hal_time_state.diagnostic_source_name));
	lichen_hal_time_state.has_diagnostic_sample = false;
}

int lichen_hal_time_provision_epoch_set(uint32_t provision_epoch,
					bool authenticated)
{
	k_mutex_lock(&lichen_hal_time_mutex, K_FOREVER);
	if (!authenticated) {
		time_set_rejection_locked(
			LICHEN_HAL_TIME_REJECT_PROVISION_UNAUTHENTICATED);
		k_mutex_unlock(&lichen_hal_time_mutex);
		return -EINVAL;
	}
	if (provision_epoch == 0U || provision_epoch < time_build_epoch()) {
		time_set_rejection_locked(
			LICHEN_HAL_TIME_REJECT_PROVISION_INVALID);
		k_mutex_unlock(&lichen_hal_time_mutex);
		return -EINVAL;
	}
	if (!provision_epoch_in_lead_bound(provision_epoch)) {
		time_set_rejection_locked(
			LICHEN_HAL_TIME_REJECT_PROVISION_FUTURE);
		k_mutex_unlock(&lichen_hal_time_mutex);
		return -EINVAL;
	}

	lichen_hal_time_state.provision_epoch = provision_epoch;
	lichen_hal_time_state.provision_epoch_valid = true;
	time_clear_diagnostic_sample_locked();
	time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_NONE);
	k_mutex_unlock(&lichen_hal_time_mutex);
	return 0;
}

void lichen_hal_time_provision_epoch_clear(void)
{
	k_mutex_lock(&lichen_hal_time_mutex, K_FOREVER);
	lichen_hal_time_state.provision_epoch_valid = false;
	lichen_hal_time_state.provision_epoch = 0U;
	time_clear_diagnostic_sample_locked();
	time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_NONE);
	k_mutex_unlock(&lichen_hal_time_mutex);
}

int lichen_hal_time_submit(const struct lichen_hal_time_sample *sample)
{
	struct lichen_hal_time_sample copy;
	const struct lichen_hal_time_sample *selected;

	if (sample == NULL) {
		return -EINVAL;
	}
	if (!valid_time_source_class(sample->source_class)) {
		k_mutex_lock(&lichen_hal_time_mutex, K_FOREVER);
		time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_INVALID_SOURCE);
		k_mutex_unlock(&lichen_hal_time_mutex);
		return -EINVAL;
	}
	if (sample->source_class == LICHEN_HAL_TIME_SOURCE_MONOTONIC_INTERNAL ||
	    !sample->unix_time_valid) {
		k_mutex_lock(&lichen_hal_time_mutex, K_FOREVER);
		time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_MISSING_TIMESTAMP);
		k_mutex_unlock(&lichen_hal_time_mutex);
		return -EINVAL;
	}

	copy = *sample;
	if (!copy.observed_uptime_ms_valid) {
		copy.observed_uptime_ms = lichen_hal_now_ms();
		copy.observed_uptime_ms_valid = true;
	} else if (copy.observed_uptime_ms > lichen_hal_now_ms()) {
		copy.observed_uptime_ms = lichen_hal_now_ms();
	}

	k_mutex_lock(&lichen_hal_time_mutex, K_FOREVER);
	if (!time_sample_passes_floor_locked(&copy)) {
		time_store_diagnostic_sample_locked(&copy);
		time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_BELOW_EPOCH_FLOOR);
		k_mutex_unlock(&lichen_hal_time_mutex);
		return -ERANGE;
	}
	if (time_sample_is_stale(&copy)) {
		time_clear_diagnostic_sample_locked();
		time_store_sample_locked(&copy);
		time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_STALE);
		k_mutex_unlock(&lichen_hal_time_mutex);
		return -ETIME;
	}

	selected = select_time_sample_locked();
	if (selected != NULL &&
	    time_source_priority(copy.source_class) <
	    time_source_priority(selected->source_class) &&
	    copy.unix_time < time_sample_current_unix(selected)) {
		time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_LOWER_TRUST);
		k_mutex_unlock(&lichen_hal_time_mutex);
		return -EALREADY;
	}

	time_clear_diagnostic_sample_locked();
	time_store_sample_locked(&copy);
	time_set_rejection_locked(LICHEN_HAL_TIME_REJECT_NONE);
	k_mutex_unlock(&lichen_hal_time_mutex);
	return 0;
}

void lichen_hal_time_clear(void)
{
	k_mutex_lock(&lichen_hal_time_mutex, K_FOREVER);
	memset(lichen_hal_time_state.samples, 0, sizeof(lichen_hal_time_state.samples));
	memset(lichen_hal_time_state.source_names, 0, sizeof(lichen_hal_time_state.source_names));
	memset(lichen_hal_time_state.has_sample, 0, sizeof(lichen_hal_time_state.has_sample));
	time_clear_diagnostic_sample_locked();
	lichen_hal_time_state.last_rejection = LICHEN_HAL_TIME_REJECT_NONE;
	k_mutex_unlock(&lichen_hal_time_mutex);
}

int lichen_hal_time_snapshot_get(struct lichen_hal_time_snapshot *snapshot)
{
	const struct lichen_hal_time_sample *selected;
	const struct lichen_hal_time_sample *rejected;
	bool selected_valid = false;

	if (snapshot == NULL) {
		return -EINVAL;
	}

	*snapshot = (struct lichen_hal_time_snapshot){ 0 };
	snapshot->provider_available = lichen_hal_time_status() == 0;
	snapshot->build_epoch = time_build_epoch();

	k_mutex_lock(&lichen_hal_time_mutex, K_FOREVER);
	snapshot->effective_epoch_floor = time_effective_epoch_floor_locked();
	snapshot->provision_epoch_valid = lichen_hal_time_state.provision_epoch_valid;
	snapshot->provision_epoch = lichen_hal_time_state.provision_epoch;
	snapshot->last_rejection = lichen_hal_time_state.last_rejection;

	selected = select_time_sample_locked();
	selected_valid = selected != NULL;
	if (selected == NULL) {
		selected = select_time_diagnostic_sample_locked();
	}
	rejected = lichen_hal_time_state.has_diagnostic_sample &&
		   lichen_hal_time_state.last_rejection == LICHEN_HAL_TIME_REJECT_BELOW_EPOCH_FLOOR ?
		   &lichen_hal_time_state.diagnostic_sample : NULL;
	if (selected != NULL) {
		struct lichen_hal_time_sample sample = *selected;
		char source_name[sizeof(snapshot->source_name)];

		if (sample.source_name == NULL) {
			source_name[0] = '\0';
			if (sample.source_class >= LICHEN_HAL_TIME_SOURCE_NONE &&
			    sample.source_class <= LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC) {
				strncpy(source_name,
					lichen_hal_time_state.source_names[sample.source_class],
					sizeof(source_name) - 1U);
				source_name[sizeof(source_name) - 1U] = '\0';
			}
			sample.source_name = source_name;
		}

		snapshot->wall_clock_valid = selected_valid;
		snapshot->source_class_valid = true;
		snapshot->source_class = sample.source_class;
		strncpy(snapshot->source_name, sample.source_name,
			sizeof(snapshot->source_name) - 1U);
		snapshot->source_name[sizeof(snapshot->source_name) - 1U] = '\0';
		snapshot->unix_time_valid = selected_valid;
		if (selected_valid) {
			snapshot->unix_time = time_sample_current_unix(&sample);
		}
		snapshot->age_seconds_valid = sample.observed_uptime_ms_valid;
		snapshot->age_seconds = time_age_seconds(&sample);
		snapshot->accuracy_ms_valid = sample.accuracy_ms_valid;
		snapshot->accuracy_ms = sample.accuracy_ms;
		snapshot->quality_valid = sample.quality_valid;
		snapshot->quality = sample.quality;
		snapshot->passed_epoch_floor =
			time_sample_passes_floor_locked(&sample);
	}
	if (rejected != NULL) {
		snapshot->rejection_source_class_valid = true;
		snapshot->rejection_source_class = rejected->source_class;
		if (rejected->source_name != NULL) {
			strncpy(snapshot->rejection_source_name,
				rejected->source_name,
				sizeof(snapshot->rejection_source_name) - 1U);
			snapshot->rejection_source_name
				[sizeof(snapshot->rejection_source_name) - 1U] = '\0';
		}
		snapshot->rejection_passed_epoch_floor =
			time_sample_passes_floor_locked(rejected);
	}
	k_mutex_unlock(&lichen_hal_time_mutex);

	return 0;
}
