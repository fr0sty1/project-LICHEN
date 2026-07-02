/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_NETWORK_LOCATION_H_
#define LICHEN_GATEWAY_NETWORK_LOCATION_H_

#include <stdbool.h>
#include <stdint.h>

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

int gateway_network_location_submit(
	const struct gateway_network_location_sample *sample);

#endif /* LICHEN_GATEWAY_NETWORK_LOCATION_H_ */
