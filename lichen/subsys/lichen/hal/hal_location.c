/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/hal.h>
#include "hal_internal.h"

struct location_provider_state lichen_hal_location_state;
K_MUTEX_DEFINE(lichen_hal_location_mutex);

#ifdef CONFIG_ZTEST
bool lichen_hal_test_use_uptime;
int64_t lichen_hal_test_uptime_ms;
struct lichen_hal_location_time_snapshot lichen_hal_test_location_time_snapshot;
bool lichen_hal_test_has_location_time_snapshot;
#endif

int64_t lichen_hal_now_ms(void)
{
#ifdef CONFIG_ZTEST
	if (lichen_hal_test_use_uptime) {
		return lichen_hal_test_uptime_ms;
	}
#endif
	return k_uptime_get();
}

static bool valid_source_class(enum lichen_hal_location_source_class source_class)
{
	return source_class > LICHEN_HAL_LOCATION_SOURCE_NONE &&
	       source_class <= LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC;
}

static bool valid_fix_state(enum lichen_hal_location_fix_state fix_state)
{
	return fix_state >= LICHEN_HAL_LOCATION_FIX_NONE &&
	       fix_state <= LICHEN_HAL_LOCATION_FIX_ERROR &&
	       fix_state != LICHEN_HAL_LOCATION_FIX_STALE;
}

static bool valid_fix_source(enum lichen_hal_fix_source fix_source)
{
	return fix_source >= LICHEN_HAL_FIX_SOURCE_NONE &&
	       fix_source <= LICHEN_HAL_FIX_SOURCE_GNSS;
}

static bool valid_position_e7(int32_t latitude_e7, int32_t longitude_e7)
{
	return latitude_e7 >= -900000000 && latitude_e7 <= 900000000 &&
	       longitude_e7 >= -1800000000 && longitude_e7 <= 1800000000;
}

static uint32_t location_age_seconds(const struct lichen_hal_location_sample *sample)
{
	int64_t now = lichen_hal_now_ms();
	int64_t observed = sample->observed_uptime_ms;
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

static bool sample_is_stale(const struct lichen_hal_location_sample *sample)
{
	return location_age_seconds(sample) >
	       CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S;
}

static bool sample_has_usable_fix(const struct lichen_hal_location_sample *sample)
{
	return sample->latitude_e7_valid && sample->longitude_e7_valid &&
	       (sample->fix_state == LICHEN_HAL_LOCATION_FIX_2D ||
		sample->fix_state == LICHEN_HAL_LOCATION_FIX_3D);
}

static const struct lichen_hal_location_sample *select_location_sample(void)
{
	const struct lichen_hal_location_sample *best_metadata = NULL;

	for (int source = LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC;
	     source > LICHEN_HAL_LOCATION_SOURCE_NONE; source--) {
		const struct lichen_hal_location_sample *sample =
			&lichen_hal_location_state.samples[source];

		if (!lichen_hal_location_state.has_sample[source]) {
			continue;
		}
		if (!sample_is_stale(sample) && sample_has_usable_fix(sample)) {
			return sample;
		}
	}

	for (int source = LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC;
	     source > LICHEN_HAL_LOCATION_SOURCE_NONE; source--) {
		const struct lichen_hal_location_sample *sample =
			&lichen_hal_location_state.samples[source];

		if (!lichen_hal_location_state.has_sample[source]) {
			continue;
		}
		if (!sample_is_stale(sample)) {
			return sample;
		}
		if (best_metadata == NULL) {
			best_metadata = sample;
		}
	}

	return best_metadata;
}

int lichen_hal_location_submit(const struct lichen_hal_location_sample *sample)
{
	struct lichen_hal_location_sample copy;

	if (sample == NULL) {
		return -EINVAL;
	}
	if (!valid_source_class(sample->source_class) ||
	    !valid_fix_state(sample->fix_state) ||
	    !valid_fix_source(sample->fix_source)) {
		return -EINVAL;
	}
	if (sample->fix_source == LICHEN_HAL_FIX_SOURCE_GNSS &&
	    sample->source_class != LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE &&
	    sample->source_class != LICHEN_HAL_LOCATION_SOURCE_EXTERNAL_HARDWARE) {
		return -EINVAL;
	}
	if (sample->latitude_e7_valid != sample->longitude_e7_valid) {
		return -EINVAL;
	}
	if (sample->latitude_e7_valid &&
	    !valid_position_e7(sample->latitude_e7, sample->longitude_e7)) {
		return -EINVAL;
	}
	if ((sample->fix_state == LICHEN_HAL_LOCATION_FIX_2D ||
	     sample->fix_state == LICHEN_HAL_LOCATION_FIX_3D) &&
	    (!sample->latitude_e7_valid || !sample->longitude_e7_valid)) {
		return -EINVAL;
	}
	copy = *sample;
	if (!copy.observed_uptime_ms_valid) {
		copy.observed_uptime_ms = lichen_hal_now_ms();
		copy.observed_uptime_ms_valid = true;
	} else if (copy.observed_uptime_ms > lichen_hal_now_ms()) {
		copy.observed_uptime_ms = lichen_hal_now_ms();
	}

	k_mutex_lock(&lichen_hal_location_mutex, K_FOREVER);
	lichen_hal_location_state.samples[copy.source_class] = copy;
	if (sample->source_name != NULL) {
		strncpy(lichen_hal_location_state.source_names[copy.source_class],
			sample->source_name,
			sizeof(lichen_hal_location_state.source_names[copy.source_class]) - 1U);
		lichen_hal_location_state.source_names[copy.source_class]
			[sizeof(lichen_hal_location_state.source_names[copy.source_class]) - 1U] = '\0';
	} else {
		lichen_hal_location_state.source_names[copy.source_class][0] = '\0';
	}
	lichen_hal_location_state.samples[copy.source_class].source_name =
		lichen_hal_location_state.source_names[copy.source_class];
	lichen_hal_location_state.has_sample[copy.source_class] = true;
	k_mutex_unlock(&lichen_hal_location_mutex);

	return 0;
}

int lichen_hal_location_clear_source(
	enum lichen_hal_location_source_class source_class)
{
	if (!valid_source_class(source_class)) {
		return -EINVAL;
	}

	k_mutex_lock(&lichen_hal_location_mutex, K_FOREVER);
	lichen_hal_location_state.samples[source_class] =
		(struct lichen_hal_location_sample){ 0 };
	lichen_hal_location_state.source_names[source_class][0] = '\0';
	lichen_hal_location_state.has_sample[source_class] = false;
	k_mutex_unlock(&lichen_hal_location_mutex);

	return 0;
}

void lichen_hal_location_clear(void)
{
	k_mutex_lock(&lichen_hal_location_mutex, K_FOREVER);
	lichen_hal_location_state = (struct location_provider_state){ 0 };
	k_mutex_unlock(&lichen_hal_location_mutex);
}

static void snapshot_from_sample(struct lichen_hal_location_time_snapshot *snapshot,
				 const struct lichen_hal_location_sample *sample)
{
	const bool stale = sample_is_stale(sample);

	snapshot->location_provider_available = true;
	snapshot->source_class_valid = true;
	snapshot->source_class = sample->source_class;
	if (sample->source_name != NULL) {
		strncpy(snapshot->source_name, sample->source_name,
			sizeof(snapshot->source_name) - 1U);
		snapshot->source_name[sizeof(snapshot->source_name) - 1U] = '\0';
	}
	snapshot->fix_state_valid = true;
	snapshot->fix_state = stale ? LICHEN_HAL_LOCATION_FIX_STALE :
				      sample->fix_state;
	snapshot->age_seconds_valid = sample->observed_uptime_ms_valid;
	snapshot->age_seconds = location_age_seconds(sample);
	snapshot->horizontal_accuracy_mm_valid =
		!stale && sample->horizontal_accuracy_mm_valid;
	snapshot->horizontal_accuracy_mm = sample->horizontal_accuracy_mm;
	snapshot->vertical_accuracy_mm_valid =
		!stale && sample->vertical_accuracy_mm_valid;
	snapshot->vertical_accuracy_mm = sample->vertical_accuracy_mm;
	snapshot->fix_source_valid =
		!stale && sample_has_usable_fix(sample) &&
		sample->fix_source != LICHEN_HAL_FIX_SOURCE_NONE;
	snapshot->fix_source = sample->fix_source;
	snapshot->satellites_valid = !stale && sample->satellites_valid;
	snapshot->satellites = sample->satellites;
	snapshot->fix_time_unix_valid = !stale && sample->fix_time_unix_valid;
	snapshot->fix_time_unix = sample->fix_time_unix;
	snapshot->altitude_m_valid = !stale && sample->altitude_m_valid;
	snapshot->altitude_m = sample->altitude_m;
	snapshot->altitude_cm_valid = !stale && sample->altitude_cm_valid;
	snapshot->altitude_cm = sample->altitude_cm;

	if (!stale && sample_has_usable_fix(sample)) {
		snapshot->latitude_e7_valid = true;
		snapshot->latitude_e7 = sample->latitude_e7;
		snapshot->longitude_e7_valid = true;
		snapshot->longitude_e7 = sample->longitude_e7;
	}
}

int lichen_hal_location_time_snapshot_get(
	struct lichen_hal_location_time_snapshot *snapshot)
{
	if (snapshot == NULL) {
		return -EINVAL;
	}

#ifdef CONFIG_ZTEST
	if (lichen_hal_test_has_location_time_snapshot) {
		*snapshot = lichen_hal_test_location_time_snapshot;
		return 0;
	}
#endif

	*snapshot = (struct lichen_hal_location_time_snapshot){ 0 };

	const struct lichen_hal_location_sample *selected;

	k_mutex_lock(&lichen_hal_location_mutex, K_FOREVER);
	selected = select_location_sample();
	if (selected != NULL) {
		struct lichen_hal_location_sample sample = *selected;
		char source_name[sizeof(snapshot->source_name)];

		strncpy(source_name,
			lichen_hal_location_state.source_names[sample.source_class],
			sizeof(source_name) - 1U);
		source_name[sizeof(source_name) - 1U] = '\0';
		sample.source_name = source_name;

		k_mutex_unlock(&lichen_hal_location_mutex);
		snapshot_from_sample(snapshot, &sample);
		snapshot->time_provider_available =
			lichen_hal_caps.time == LICHEN_HAL_TIME_GNSS &&
			lichen_hal_time_status() == 0;
		return 0;
	}
	k_mutex_unlock(&lichen_hal_location_mutex);

	snapshot->location_provider_available =
		lichen_hal_location_status() == 0;
	snapshot->time_provider_available =
		lichen_hal_caps.time == LICHEN_HAL_TIME_GNSS && lichen_hal_time_status() == 0;

	if (lichen_hal_caps.location == LICHEN_HAL_LOCATION_GNSS &&
	    snapshot->location_provider_available) {
		snapshot->source_class_valid = true;
		snapshot->source_class = LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE;
		(void)snprintf(snapshot->source_name, sizeof(snapshot->source_name),
			       "gnss0");
		snapshot->fix_state_valid = true;
		snapshot->fix_state = LICHEN_HAL_LOCATION_FIX_NO_FIX;
		snapshot->fix_source = LICHEN_HAL_FIX_SOURCE_GNSS;
	}

	return 0;
}

#ifdef CONFIG_ZTEST
void lichen_hal_location_test_set_uptime_ms(int64_t uptime_ms)
{
	lichen_hal_test_uptime_ms = uptime_ms;
	lichen_hal_test_use_uptime = true;
}

void lichen_hal_location_test_use_real_uptime(void)
{
	lichen_hal_test_use_uptime = false;
	lichen_hal_test_uptime_ms = 0;
}

int64_t lichen_hal_location_test_now_ms(void)
{
	return lichen_hal_now_ms();
}

void lichen_hal_location_time_test_set_snapshot(
	const struct lichen_hal_location_time_snapshot *snapshot)
{
	if (snapshot == NULL) {
		lichen_hal_test_has_location_time_snapshot = false;
		lichen_hal_test_location_time_snapshot =
			(struct lichen_hal_location_time_snapshot){ 0 };
		return;
	}

	lichen_hal_test_location_time_snapshot = *snapshot;
	lichen_hal_test_has_location_time_snapshot = true;
}
#endif
