/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_OP_CLASS_H_
#define LICHEN_OP_CLASS_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Operating class identifiers for regional channel plans (CCP-3/CCP-4).
 * Each value maps to a set of radio parameters and regulatory rules. */
#define LICHEN_OP_CLASS_US_CA  0
#define LICHEN_OP_CLASS_EU     1
#define LICHEN_OP_CLASS_AU_NZ  2

/* Radio parameters associated with a single operating class.
 * Matches the Rust OperatingClassParams struct in lichen-hal. */
struct lichen_op_class_params {
	uint8_t  class_id;
	const char *label;
	uint32_t frequency_hz;
	uint8_t  spreading_factor;
	uint32_t bandwidth_hz;
	uint8_t  coding_rate;
	int8_t   tx_power_dbm;
	uint8_t  duty_region;
	uint16_t duty_permille;
};

/* Operating class lookup table (CCP-3/CCP-4).
 * Provisioned at compile time; over-the-air messages MUST NOT expand it. */
static const struct lichen_op_class_params lichen_op_class_table[] = {
	{
		.class_id = LICHEN_OP_CLASS_US_CA,
		.label = "US/CA",
		.frequency_hz = 903900000,
		.spreading_factor = 10,
		.bandwidth_hz = 125000,
		.coding_rate = 5,
		.tx_power_dbm = 20,
		.duty_region = 1,
		.duty_permille = 1000,
	},
	{
		.class_id = LICHEN_OP_CLASS_EU,
		.label = "EU",
		.frequency_hz = 868100000,
		.spreading_factor = 10,
		.bandwidth_hz = 125000,
		.coding_rate = 5,
		.tx_power_dbm = 14,
		.duty_region = 0,
		.duty_permille = 10,
	},
	{
		.class_id = LICHEN_OP_CLASS_AU_NZ,
		.label = "AU/NZ",
		.frequency_hz = 916800000,
		.spreading_factor = 10,
		.bandwidth_hz = 125000,
		.coding_rate = 5,
		.tx_power_dbm = 30,
		.duty_region = 0,
		.duty_permille = 50,
	},
};

#define LICHEN_OP_CLASS_TABLE_SIZE \
	(sizeof(lichen_op_class_table) / sizeof(lichen_op_class_table[0]))

/* Look up operating class by class_id. Returns NULL if not found.
 * Matches Rust lookup_operating_class(). */
static inline const struct lichen_op_class_params *
lichen_op_class_lookup(uint8_t class_id)
{
	for (size_t i = 0; i < LICHEN_OP_CLASS_TABLE_SIZE; i++) {
		if (lichen_op_class_table[i].class_id == class_id) {
			return &lichen_op_class_table[i];
		}
	}
	return NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_OP_CLASS_H_ */
