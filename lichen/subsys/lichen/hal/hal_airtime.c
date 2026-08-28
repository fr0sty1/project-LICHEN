/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/airtime.h>

#define LICHEN_LORA_MIN_PREAMBLE_SYMBOLS 6U

static const uint32_t supported_bandwidths_hz[] = {
	7800U, 10400U, 15600U, 20800U, 31250U, 41700U, 62500U, 125000U, 250000U, 500000U,
};

static bool bandwidth_supported(uint32_t bandwidth_hz)
{
	for (size_t i = 0U;
	     i < sizeof(supported_bandwidths_hz) / sizeof(supported_bandwidths_hz[0]); ++i) {
		if (supported_bandwidths_hz[i] == bandwidth_hz) {
			return true;
		}
	}

	return false;
}

static bool multiply_u64(uint64_t left, uint64_t right, uint64_t *result)
{
	if (left != 0U && right > UINT64_MAX / left) {
		return false;
	}

	*result = left * right;
	return true;
}

static int validate(uint16_t payload_len, const struct lichen_lora_airtime_config *config,
		    const uint64_t *airtime_us)
{
	if (config == NULL || airtime_us == NULL || payload_len > 255U) {
		return -EINVAL;
	}
	if (config->spreading_factor < 6U || config->spreading_factor > 12U) {
		return -EINVAL;
	}
	if (config->spreading_factor == 6U && !config->implicit_header) {
		return -EINVAL;
	}
	if (!bandwidth_supported(config->bandwidth_hz)) {
		return -EINVAL;
	}
	if (config->coding_rate < 5U || config->coding_rate > 8U) {
		return -EINVAL;
	}
	if (config->preamble_symbols < LICHEN_LORA_MIN_PREAMBLE_SYMBOLS) {
		return -EINVAL;
	}
	if (config->low_data_rate_optimization < LICHEN_LORA_LDRO_AUTO ||
	    config->low_data_rate_optimization > LICHEN_LORA_LDRO_ENABLED) {
		return -EINVAL;
	}

	return 0;
}

int lichen_lora_airtime_us(uint16_t payload_len, const struct lichen_lora_airtime_config *config,
			   uint64_t *airtime_us)
{
	uint64_t symbol_scale;
	uint64_t quarter_symbols;
	uint64_t numerator;
	uint64_t payload_symbols;
	int32_t payload_numerator;
	uint32_t payload_denominator;
	uint32_t coded_blocks;
	bool ldro;
	int ret;

	ret = validate(payload_len, config, airtime_us);
	if (ret != 0) {
		return ret;
	}

	symbol_scale = UINT64_C(1) << config->spreading_factor;
	if (config->low_data_rate_optimization == LICHEN_LORA_LDRO_AUTO) {
		ldro = symbol_scale * UINT64_C(1000) >= UINT64_C(16) * config->bandwidth_hz;
	} else {
		ldro = config->low_data_rate_optimization == LICHEN_LORA_LDRO_ENABLED;
	}

	payload_numerator = 8 * (int32_t)payload_len - 4 * (int32_t)config->spreading_factor + 28 +
			    (config->crc_enabled ? 16 : 0) - (config->implicit_header ? 20 : 0);
	payload_denominator = 4U * ((uint32_t)config->spreading_factor - (ldro ? 2U : 0U));
	coded_blocks = payload_numerator <= 0 ? 0U
					      : ((uint32_t)payload_numerator + payload_denominator -
						 1U) / payload_denominator;
	payload_symbols = UINT64_C(8) + (uint64_t)coded_blocks * config->coding_rate;

	/* Quarter-symbols preserve the Semtech preamble suffix of 4.25 exactly. */
	quarter_symbols = 4U * (uint64_t)config->preamble_symbols + 17U + 4U * payload_symbols;
	if (!multiply_u64(quarter_symbols, symbol_scale, &numerator) ||
	    !multiply_u64(numerator, UINT64_C(1000000), &numerator)) {
		return -ERANGE;
	}

	*airtime_us = numerator / (4U * (uint64_t)config->bandwidth_hz);
	return 0;
}

int lichen_lora_airtime_default_us(uint16_t payload_len, uint64_t *airtime_us)
{
	const struct lichen_lora_airtime_config config = LICHEN_LORA_AIRTIME_CONFIG_DEFAULT;

	return lichen_lora_airtime_us(payload_len, &config, airtime_us);
}
