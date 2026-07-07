/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_CONFIG_CBOR_H_
#define LICHEN_GATEWAY_CONFIG_CBOR_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define LICHEN_GATEWAY_TX_POWER_MIN_DBM -9
#define LICHEN_GATEWAY_TX_POWER_MAX_DBM 22
#define LICHEN_GATEWAY_MANUAL_LOCATION_SOURCE_NAME_MAX 24

struct lichen_gateway_manual_location_config {
	bool latitude_e7_valid;
	int32_t latitude_e7;
	bool longitude_e7_valid;
	int32_t longitude_e7;
	bool horizontal_accuracy_mm_valid;
	uint32_t horizontal_accuracy_mm;
	bool age_seconds_valid;
	uint32_t age_seconds;
	char source_name[LICHEN_GATEWAY_MANUAL_LOCATION_SOURCE_NAME_MAX];
};

struct lichen_gateway_config_update {
	bool has_tx_power_dbm;
	int8_t tx_power_dbm;
	bool has_manual_location;
	struct lichen_gateway_manual_location_config manual_location;
};

size_t lichen_gateway_encode_config_cbor(uint8_t *buf, size_t buf_size,
					 int8_t tx_power_dbm);
size_t lichen_gateway_encode_config_update_cbor(
	uint8_t *buf, size_t buf_size,
	int8_t tx_power_dbm,
	const struct lichen_gateway_manual_location_config *manual_location);

int lichen_gateway_decode_config_cbor(
	const uint8_t *buf, size_t len,
	struct lichen_gateway_config_update *update);

#endif /* LICHEN_GATEWAY_CONFIG_CBOR_H_ */
