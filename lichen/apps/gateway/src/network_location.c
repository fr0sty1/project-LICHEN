/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "network_location.h"

#include <errno.h>
#include <string.h>

#include <lichen/app_interface/app_interface.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#define ANNOUNCE_COORDS_APP_DATA_TYPE 0x01U
#define ANNOUNCE_COORDS_APP_DATA_LEN 7U
#define ANNOUNCE_COORDS_SCALE_TO_E7 100
#define ANNOUNCE_RECORD_CAP 8U

struct announce_record {
	bool in_use;
	uint8_t peer_id_len;
	uint8_t peer_id[GATEWAY_NETWORK_LOCATION_ANNOUNCE_PEER_ID_MAX_LEN];
	struct gateway_network_location_announce_record location;
};

static struct announce_record announce_records[ANNOUNCE_RECORD_CAP];
static uint8_t published_peer_id[GATEWAY_NETWORK_LOCATION_ANNOUNCE_PEER_ID_MAX_LEN];
static uint8_t published_peer_id_len;
static bool published_peer_valid;
static K_MUTEX_DEFINE(announce_publish_mutex);
static K_MUTEX_DEFINE(announce_records_mutex);

static bool valid_lat_lon(int32_t latitude_e7, int32_t longitude_e7)
{
	return latitude_e7 >= -900000000 && latitude_e7 <= 900000000 &&
	       longitude_e7 >= -1800000000 && longitude_e7 <= 1800000000;
}

static int32_t read_int24_be(const uint8_t *data)
{
	int32_t value = ((int32_t)data[0] << 16) | ((int32_t)data[1] << 8) |
			(int32_t)data[2];

	if ((value & 0x00800000) != 0) {
		value |= (int32_t)0xff000000;
	}

	return value;
}

static bool valid_peer_id(const uint8_t *peer_id, size_t peer_id_len)
{
	return peer_id != NULL && peer_id_len > 0U &&
	       peer_id_len <= GATEWAY_NETWORK_LOCATION_ANNOUNCE_PEER_ID_MAX_LEN;
}

static bool record_matches(const struct announce_record *record,
			   const uint8_t *peer_id, size_t peer_id_len)
{
	return record->in_use && record->peer_id_len == peer_id_len &&
	       memcmp(record->peer_id, peer_id, peer_id_len) == 0;
}

static struct announce_record *find_announce_record(const uint8_t *peer_id,
						    size_t peer_id_len)
{
	for (size_t i = 0U; i < ARRAY_SIZE(announce_records); i++) {
		if (record_matches(&announce_records[i], peer_id, peer_id_len)) {
			return &announce_records[i];
		}
	}

	return NULL;
}

static bool serial_newer(uint32_t value, uint32_t previous)
{
	uint32_t delta = value - previous;

	return delta != 0U && delta < 0x80000000U;
}

static bool uptime_age(uint32_t now_uptime_s, uint32_t observed_uptime_s,
		       uint32_t *age_s)
{
	if (now_uptime_s == observed_uptime_s) {
		*age_s = 0U;
		return true;
	}
	if (!serial_newer(now_uptime_s, observed_uptime_s)) {
		return false;
	}

	*age_s = now_uptime_s - observed_uptime_s;
	return true;
}

static struct announce_record *allocate_announce_record(const uint8_t *peer_id,
							size_t peer_id_len,
							uint32_t now_uptime_s,
							struct announce_record *old_record,
							bool *old_record_valid)
{
	struct announce_record *oldest = NULL;
	uint32_t oldest_age = 0U;

	for (size_t i = 0U; i < ARRAY_SIZE(announce_records); i++) {
		if (!announce_records[i].in_use) {
			*old_record_valid = false;
			announce_records[i].in_use = true;
			announce_records[i].peer_id_len = (uint8_t)peer_id_len;
			memcpy(announce_records[i].peer_id, peer_id, peer_id_len);
			return &announce_records[i];
		}
	}

	for (size_t i = 0U; i < ARRAY_SIZE(announce_records); i++) {
		uint32_t age;

		if (published_peer_valid &&
		    record_matches(&announce_records[i], published_peer_id,
				   published_peer_id_len)) {
			continue;
		}
		if (!uptime_age(now_uptime_s,
				announce_records[i].location.observed_uptime_s,
				&age)) {
			continue;
		}
		if (oldest == NULL || age > oldest_age) {
			oldest = &announce_records[i];
			oldest_age = age;
		}
	}
	if (oldest == NULL) {
		return NULL;
	}

	*old_record = *oldest;
	*old_record_valid = true;
	*oldest = (struct announce_record){
		.in_use = true,
		.peer_id_len = (uint8_t)peer_id_len,
	};
	memcpy(oldest->peer_id, peer_id, peer_id_len);

	return oldest;
}

static void restore_announce_state(struct announce_record *record,
				   const struct announce_record *old_record,
				   bool old_record_valid,
				   const uint8_t *old_published_peer_id,
				   uint8_t old_published_peer_id_len,
				   bool old_published_peer_valid)
{
	if (old_record_valid) {
		*record = *old_record;
	} else {
		memset(record, 0, sizeof(*record));
	}

	memset(published_peer_id, 0, sizeof(published_peer_id));
	published_peer_id_len = old_published_peer_id_len;
	published_peer_valid = old_published_peer_valid;
	if (old_published_peer_valid) {
		memcpy(published_peer_id, old_published_peer_id,
		       old_published_peer_id_len);
	}
}

static bool announce_seq_newer(uint32_t seq_num, uint32_t previous_seq_num)
{
	return serial_newer(seq_num, previous_seq_num);
}

static bool announce_record_expired(
	const struct gateway_network_location_announce_sample *announce,
	const struct announce_record *record)
{
	uint32_t age_s;

	return uptime_age(announce->observed_uptime_s,
			  record->location.observed_uptime_s, &age_s) &&
	       age_s > CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S;
}

static bool announce_observed_older(
	const struct gateway_network_location_announce_sample *announce,
	const struct announce_record *record)
{
	uint32_t age_s;

	return !uptime_age(announce->observed_uptime_s,
			   record->location.observed_uptime_s, &age_s);
}

static bool published_peer_matches(const uint8_t *peer_id, size_t peer_id_len)
{
	return published_peer_valid && published_peer_id_len == peer_id_len &&
	       memcmp(published_peer_id, peer_id, peer_id_len) == 0;
}

static bool published_peer_fresher_than(const uint8_t *peer_id,
					size_t peer_id_len,
					uint32_t observed_uptime_s)
{
	const struct announce_record *published;

	if (!published_peer_valid) {
		return false;
	}
	if (published_peer_matches(peer_id, peer_id_len)) {
		return false;
	}

	published = find_announce_record(published_peer_id,
					 published_peer_id_len);
	if (published == NULL || !published->location.coords_valid) {
		return false;
	}

	return !serial_newer(observed_uptime_s,
			     published->location.observed_uptime_s);
}

static void build_announce_location_sample(
	const struct gateway_network_location_announce_record *record,
	uint32_t observed_uptime_s,
	struct gateway_network_location_sample *sample)
{
	uint32_t age_seconds = observed_uptime_s - record->observed_uptime_s;

	*sample = (struct gateway_network_location_sample){
		.latitude_e7_valid = true,
		.latitude_e7 = record->latitude_e7,
		.longitude_e7_valid = true,
		.longitude_e7 = record->longitude_e7,
		.age_seconds_valid = true,
		.age_seconds = age_seconds,
		.source_name_valid = true,
		.source_name = "mesh-announce",
	};
}

static const struct announce_record *latest_coords_record(uint32_t now_uptime_s)
{
	const struct announce_record *latest = NULL;

	for (size_t i = 0U; i < ARRAY_SIZE(announce_records); i++) {
		uint32_t age_s;

		if (!announce_records[i].in_use ||
		    !announce_records[i].location.coords_valid) {
			continue;
		}
		if (!uptime_age(now_uptime_s,
				announce_records[i].location.observed_uptime_s,
				&age_s) ||
		    age_s > CONFIG_LICHEN_LOCATION_FRESHNESS_MAX_AGE_S) {
			continue;
		}
		if (latest == NULL ||
		    serial_newer(
			    announce_records[i].location.observed_uptime_s,
			    latest->location.observed_uptime_s)) {
			latest = &announce_records[i];
		}
	}

	return latest;
}

static int submit_network_location_to_app(
	const struct gateway_network_location_sample *sample)
{
	struct lichen_app_location_time_snapshot location;

	if (sample == NULL ||
	    sample->latitude_e7_valid != sample->longitude_e7_valid ||
	    !sample->latitude_e7_valid ||
	    !valid_lat_lon(sample->latitude_e7, sample->longitude_e7)) {
		return -EINVAL;
	}

	location = (struct lichen_app_location_time_snapshot){
		.source_class_valid = true,
		.source_class = LICHEN_APP_LOCATION_SOURCE_NETWORK,
		.fix_state_valid = true,
		.fix_state = sample->altitude_m_valid ?
			     LICHEN_APP_LOCATION_FIX_3D :
			     LICHEN_APP_LOCATION_FIX_2D,
		.latitude_e7_valid = true,
		.latitude_e7 = sample->latitude_e7,
		.longitude_e7_valid = true,
		.longitude_e7 = sample->longitude_e7,
		.altitude_m_valid = sample->altitude_m_valid,
		.altitude_m = sample->altitude_m,
		.fix_time_unix_valid = sample->fix_time_unix_valid,
		.fix_time_unix = sample->fix_time_unix,
		.satellites_valid = sample->satellites_valid,
		.satellites = sample->satellites,
		.age_seconds_valid = sample->age_seconds_valid,
		.age_seconds = sample->age_seconds,
		.horizontal_accuracy_mm_valid =
			sample->horizontal_accuracy_mm_valid,
		.horizontal_accuracy_mm = sample->horizontal_accuracy_mm,
		.vertical_accuracy_mm_valid = sample->vertical_accuracy_mm_valid,
		.vertical_accuracy_mm = sample->vertical_accuracy_mm,
	};
	if (sample->source_name_valid) {
		strncpy(location.source_name, sample->source_name,
			sizeof(location.source_name) - 1U);
		location.source_name[sizeof(location.source_name) - 1U] = '\0';
	}

	return lichen_app_interface_submit_network_location(&location);
}

int gateway_network_location_submit(
	const struct gateway_network_location_sample *sample)
{
	int ret;

	k_mutex_lock(&announce_publish_mutex, K_FOREVER);
	ret = submit_network_location_to_app(sample);
	if (ret == 0) {
		k_mutex_lock(&announce_records_mutex, K_FOREVER);
		memset(published_peer_id, 0, sizeof(published_peer_id));
		published_peer_id_len = 0U;
		published_peer_valid = false;
		k_mutex_unlock(&announce_records_mutex);
	}
	k_mutex_unlock(&announce_publish_mutex);

	return ret;
}

int gateway_network_location_decode_announce_coords(const uint8_t *app_data,
						    size_t app_data_len,
						    int32_t *latitude_e7,
						    int32_t *longitude_e7)
{
	int32_t latitude;
	int32_t longitude;

	if (app_data == NULL || latitude_e7 == NULL || longitude_e7 == NULL ||
	    app_data_len < ANNOUNCE_COORDS_APP_DATA_LEN ||
	    app_data[0] != ANNOUNCE_COORDS_APP_DATA_TYPE) {
		return -ENOENT;
	}

	latitude = read_int24_be(&app_data[1]) * ANNOUNCE_COORDS_SCALE_TO_E7;
	longitude = read_int24_be(&app_data[4]) * ANNOUNCE_COORDS_SCALE_TO_E7;
	if (!valid_lat_lon(latitude, longitude)) {
		return -EINVAL;
	}

	*latitude_e7 = latitude;
	*longitude_e7 = longitude;

	return 0;
}

int gateway_network_location_submit_announce(
	const struct gateway_network_location_announce_sample *announce)
{
	struct announce_record *record;
	int32_t latitude_e7;
	int32_t longitude_e7;
	int ret;
	bool clear_published = false;
	struct gateway_network_location_sample submit_sample;
	struct announce_record old_record;
	bool old_record_valid;
	uint8_t old_published_peer_id[sizeof(published_peer_id)];
	uint8_t old_published_peer_id_len;
	bool old_published_peer_valid;

	if (announce == NULL ||
	    !valid_peer_id(announce->peer_id, announce->peer_id_len)) {
		return -EINVAL;
	}

	ret = gateway_network_location_decode_announce_coords(
		announce->app_data, announce->app_data_len, &latitude_e7,
		&longitude_e7);
	if (ret < 0 && ret != -ENOENT) {
		return ret;
	}

	k_mutex_lock(&announce_publish_mutex, K_FOREVER);
	k_mutex_lock(&announce_records_mutex, K_FOREVER);
	record = find_announce_record(announce->peer_id, announce->peer_id_len);
	old_record_valid = record != NULL;
	if (old_record_valid) {
		old_record = *record;
	}
	old_published_peer_valid = published_peer_valid;
	old_published_peer_id_len = published_peer_id_len;
	memcpy(old_published_peer_id, published_peer_id,
	       sizeof(old_published_peer_id));
	if (record != NULL && announce_observed_older(announce, record)) {
		k_mutex_unlock(&announce_records_mutex);
		k_mutex_unlock(&announce_publish_mutex);
		return -EALREADY;
	}
	if (record != NULL &&
	    !announce_record_expired(announce, record) &&
	    !announce_seq_newer(announce->seq_num, record->location.seq_num)) {
		k_mutex_unlock(&announce_records_mutex);
		k_mutex_unlock(&announce_publish_mutex);
		return -EALREADY;
	}

	if (ret == -ENOENT && record == NULL) {
		k_mutex_unlock(&announce_records_mutex);
		k_mutex_unlock(&announce_publish_mutex);
		return 0;
	}

	if (record == NULL) {
		record = allocate_announce_record(announce->peer_id,
						  announce->peer_id_len,
						  announce->observed_uptime_s,
						  &old_record,
						  &old_record_valid);
		if (record == NULL) {
			k_mutex_unlock(&announce_records_mutex);
			k_mutex_unlock(&announce_publish_mutex);
			return -ENOMEM;
		}
	}

	record->location.seq_num = announce->seq_num;
	record->location.observed_uptime_s = announce->observed_uptime_s;
	if (ret == -ENOENT) {
		const struct announce_record *fallback;
		struct gateway_network_location_sample fallback_sample;
		bool fallback_valid = false;
		int side_effect_ret = 0;

		record->location.coords_valid = false;
		clear_published = published_peer_matches(announce->peer_id,
							 announce->peer_id_len);
		if (clear_published) {
			fallback = latest_coords_record(announce->observed_uptime_s);
			if (fallback != NULL) {
				published_peer_valid = true;
				published_peer_id_len = fallback->peer_id_len;
				memcpy(published_peer_id, fallback->peer_id,
				       fallback->peer_id_len);
				build_announce_location_sample(
					&fallback->location,
					announce->observed_uptime_s,
					&fallback_sample);
				fallback_valid = true;
			} else {
				published_peer_valid = false;
				published_peer_id_len = 0U;
				memset(published_peer_id, 0,
				       sizeof(published_peer_id));
			}
		}
		k_mutex_unlock(&announce_records_mutex);
		if (fallback_valid) {
			side_effect_ret =
				submit_network_location_to_app(&fallback_sample);
		} else if (clear_published) {
			side_effect_ret =
				lichen_app_interface_clear_network_location();
		}
		if (side_effect_ret < 0) {
			k_mutex_lock(&announce_records_mutex, K_FOREVER);
			restore_announce_state(record, &old_record,
					       old_record_valid,
					       old_published_peer_id,
					       old_published_peer_id_len,
					       old_published_peer_valid);
			k_mutex_unlock(&announce_records_mutex);
		}
		k_mutex_unlock(&announce_publish_mutex);
		return side_effect_ret;
	}

	record->location.coords_valid = true;
	record->location.latitude_e7 = latitude_e7;
	record->location.longitude_e7 = longitude_e7;
	if (published_peer_fresher_than(announce->peer_id,
					announce->peer_id_len,
					announce->observed_uptime_s)) {
		k_mutex_unlock(&announce_records_mutex);
		k_mutex_unlock(&announce_publish_mutex);
		return 0;
	}

	build_announce_location_sample(&record->location,
				       announce->observed_uptime_s,
				       &submit_sample);
	published_peer_valid = true;
	published_peer_id_len = (uint8_t)announce->peer_id_len;
	memcpy(published_peer_id, announce->peer_id, announce->peer_id_len);
	k_mutex_unlock(&announce_records_mutex);
	ret = submit_network_location_to_app(&submit_sample);
	if (ret < 0) {
		k_mutex_lock(&announce_records_mutex, K_FOREVER);
		restore_announce_state(record, &old_record, old_record_valid,
				       old_published_peer_id,
				       old_published_peer_id_len,
				       old_published_peer_valid);
		k_mutex_unlock(&announce_records_mutex);
	}
	k_mutex_unlock(&announce_publish_mutex);

	return ret;
}

int gateway_network_location_announce_get(
	const uint8_t *peer_id, size_t peer_id_len,
	struct gateway_network_location_announce_record *record)
{
	const struct announce_record *stored;

	if (!valid_peer_id(peer_id, peer_id_len) || record == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&announce_records_mutex, K_FOREVER);
	stored = find_announce_record(peer_id, peer_id_len);
	if (stored == NULL) {
		k_mutex_unlock(&announce_records_mutex);
		return -ENOENT;
	}

	*record = stored->location;
	k_mutex_unlock(&announce_records_mutex);

	return 0;
}

void gateway_network_location_announce_reset(void)
{
	k_mutex_lock(&announce_publish_mutex, K_FOREVER);
	k_mutex_lock(&announce_records_mutex, K_FOREVER);
	memset(announce_records, 0, sizeof(announce_records));
	memset(published_peer_id, 0, sizeof(published_peer_id));
	published_peer_id_len = 0U;
	published_peer_valid = false;
	k_mutex_unlock(&announce_records_mutex);
	k_mutex_unlock(&announce_publish_mutex);
}
