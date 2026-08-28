/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_AIRTIME_H_
#define LICHEN_AIRTIME_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lichen_lora_ldro {
	LICHEN_LORA_LDRO_AUTO,
	LICHEN_LORA_LDRO_DISABLED,
	LICHEN_LORA_LDRO_ENABLED,
};

struct lichen_lora_airtime_config {
	uint8_t spreading_factor;
	uint32_t bandwidth_hz;
	uint8_t coding_rate;
	uint16_t preamble_symbols;
	bool crc_enabled;
	bool implicit_header;
	enum lichen_lora_ldro low_data_rate_optimization;
};

#define LICHEN_LORA_AIRTIME_CONFIG_DEFAULT                                                         \
	{                                                                                          \
		.spreading_factor = 10U,                                                           \
		.bandwidth_hz = 125000U,                                                           \
		.coding_rate = 5U,                                                                 \
		.preamble_symbols = 8U,                                                            \
		.crc_enabled = true,                                                               \
		.implicit_header = false,                                                          \
		.low_data_rate_optimization = LICHEN_LORA_LDRO_AUTO,                               \
	}

/**
 * Calculate SX127x-compatible LoRa packet airtime using integer arithmetic.
 *
 * @param payload_len PHY payload length in bytes (0..255).
 * @param config      SF/BW/CR/preamble/header/CRC/LDRO configuration.
 * @param airtime_us  Receives the truncated packet airtime in microseconds.
 * @return 0 on success, -EINVAL for an invalid parameter, or -ERANGE if an
 *         intermediate cannot be represented in uint64_t.
 */
int lichen_lora_airtime_us(uint16_t payload_len, const struct lichen_lora_airtime_config *config,
			   uint64_t *airtime_us);

/** Calculate airtime with the normative SF10/125 kHz LICHEN profile. */
int lichen_lora_airtime_default_us(uint16_t payload_len, uint64_t *airtime_us);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_AIRTIME_H_ */
