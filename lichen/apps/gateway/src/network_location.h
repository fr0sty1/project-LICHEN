/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_NETWORK_LOCATION_H_
#define LICHEN_GATEWAY_NETWORK_LOCATION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GATEWAY_NETWORK_LOCATION_ANNOUNCE_PEER_ID_MAX_LEN 16U

struct gateway_network_location_sample {
	bool latitude_e7_valid;
	int32_t latitude_e7;
	bool longitude_e7_valid;
	int32_t longitude_e7;
	bool altitude_m_valid;
	int32_t altitude_m;
	bool fix_time_unix_valid;
	uint32_t fix_time_unix;
	bool satellites_valid;
	uint8_t satellites;
	bool age_seconds_valid;
	uint32_t age_seconds;
	bool horizontal_accuracy_mm_valid;
	uint32_t horizontal_accuracy_mm;
	bool vertical_accuracy_mm_valid;
	uint32_t vertical_accuracy_mm;
	bool source_name_valid;
	char source_name[24];
};

struct gateway_network_location_announce_sample {
	const uint8_t *peer_id;
	size_t peer_id_len;
	uint32_t seq_num;
	uint32_t observed_uptime_s;
	const uint8_t *app_data;
	size_t app_data_len;
};

struct gateway_network_location_announce_record {
	bool coords_valid;
	uint32_t seq_num;
	uint32_t observed_uptime_s;
	int32_t latitude_e7;
	int32_t longitude_e7;
};

int gateway_network_location_submit(
	const struct gateway_network_location_sample *sample);

int gateway_network_location_decode_announce_coords(const uint8_t *app_data,
						    size_t app_data_len,
						    int32_t *latitude_e7,
						    int32_t *longitude_e7);

int gateway_network_location_submit_announce(
	const struct gateway_network_location_announce_sample *announce);

int gateway_network_location_announce_get(
	const uint8_t *peer_id, size_t peer_id_len,
	struct gateway_network_location_announce_record *record);

void gateway_network_location_announce_reset(void);

#endif /* LICHEN_GATEWAY_NETWORK_LOCATION_H_ */
