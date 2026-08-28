/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdint.h>

#include <zephyr/ztest.h>

#include <lichen/airtime.h>

struct airtime_vector {
	uint16_t payload_len;
	uint8_t spreading_factor;
	uint32_t bandwidth_hz;
	uint8_t coding_rate;
	uint16_t preamble_symbols;
	bool crc_enabled;
	bool implicit_header;
	enum lichen_lora_ldro ldro;
	uint64_t expected_us;
};

/* These are the exact integer outputs shared with the Rust implementation. */
static const struct airtime_vector canonical_vectors[] = {
	{0U, 10U, 125000U, 5U, 8U, true, false, LICHEN_LORA_LDRO_AUTO, 206848U},
	{17U, 10U, 125000U, 5U, 8U, true, false, LICHEN_LORA_LDRO_AUTO, 329728U},
	{22U, 10U, 125000U, 5U, 8U, true, false, LICHEN_LORA_LDRO_AUTO, 370688U},
	{60U, 10U, 125000U, 5U, 8U, true, false, LICHEN_LORA_LDRO_AUTO, 698368U},
	{60U, 9U, 125000U, 5U, 8U, true, false, LICHEN_LORA_LDRO_AUTO, 369664U},
	{255U, 10U, 125000U, 5U, 8U, true, false, LICHEN_LORA_LDRO_DISABLED, 2295808U},
	{255U, 12U, 7800U, 8U, 65535U, true, false, LICHEN_LORA_LDRO_AUTO, 34634962051ULL},
};

static struct lichen_lora_airtime_config config_for(const struct airtime_vector *vector)
{
	return (struct lichen_lora_airtime_config){
		.spreading_factor = vector->spreading_factor,
		.bandwidth_hz = vector->bandwidth_hz,
		.coding_rate = vector->coding_rate,
		.preamble_symbols = vector->preamble_symbols,
		.crc_enabled = vector->crc_enabled,
		.implicit_header = vector->implicit_header,
		.low_data_rate_optimization = vector->ldro,
	};
}

ZTEST(airtime, test_semtech_and_rust_vectors)
{
	for (size_t i = 0U; i < ARRAY_SIZE(canonical_vectors); ++i) {
		struct lichen_lora_airtime_config config = config_for(&canonical_vectors[i]);
		uint64_t actual = 0U;

		zassert_ok(
			lichen_lora_airtime_us(canonical_vectors[i].payload_len, &config, &actual));
		zassert_equal(actual, canonical_vectors[i].expected_us, "vector %zu", i);
	}
}

ZTEST(airtime, test_all_sx127x_parameter_combinations)
{
	static const uint32_t bandwidths[] = {
		7800U, 10400U, 15600U, 20800U, 31250U, 41700U, 62500U, 125000U, 250000U, 500000U,
	};
	struct lichen_lora_airtime_config config = LICHEN_LORA_AIRTIME_CONFIG_DEFAULT;

	for (uint8_t sf = 6U; sf <= 12U; ++sf) {
		for (size_t bw = 0U; bw < ARRAY_SIZE(bandwidths); ++bw) {
			for (uint8_t cr = 5U; cr <= 8U; ++cr) {
				uint64_t airtime = 0U;

				config.spreading_factor = sf;
				config.bandwidth_hz = bandwidths[bw];
				config.coding_rate = cr;
				config.implicit_header = sf == 6U;
				zassert_ok(lichen_lora_airtime_us(255U, &config, &airtime));
				zassert_true(airtime > 0U);
			}
		}
	}
}

ZTEST(airtime, test_header_crc_ldro_and_preamble_boundaries)
{
	struct lichen_lora_airtime_config config = LICHEN_LORA_AIRTIME_CONFIG_DEFAULT;
	uint64_t automatic;
	uint64_t explicit_enabled;
	uint64_t explicit_disabled;
	uint64_t explicit_crc;
	uint64_t implicit_crc;
	uint64_t explicit_no_crc;

	config.spreading_factor = 11U;
	zassert_ok(lichen_lora_airtime_us(60U, &config, &automatic));
	config.low_data_rate_optimization = LICHEN_LORA_LDRO_ENABLED;
	zassert_ok(lichen_lora_airtime_us(60U, &config, &explicit_enabled));
	config.low_data_rate_optimization = LICHEN_LORA_LDRO_DISABLED;
	zassert_ok(lichen_lora_airtime_us(60U, &config, &explicit_disabled));
	zassert_equal(automatic, 1478656U);
	zassert_equal(automatic, explicit_enabled);
	zassert_true(explicit_enabled > explicit_disabled);

	config = (struct lichen_lora_airtime_config)LICHEN_LORA_AIRTIME_CONFIG_DEFAULT;
	config.spreading_factor = 7U;
	zassert_ok(lichen_lora_airtime_us(0U, &config, &explicit_crc));
	config.implicit_header = true;
	zassert_ok(lichen_lora_airtime_us(0U, &config, &implicit_crc));
	config.implicit_header = false;
	config.crc_enabled = false;
	zassert_ok(lichen_lora_airtime_us(0U, &config, &explicit_no_crc));
	zassert_equal(explicit_crc, 25856U);
	zassert_equal(implicit_crc, 20736U);
	zassert_equal(explicit_no_crc, 20736U);
}

ZTEST(airtime, test_invalid_parameters_fail_without_output_mutation)
{
	struct lichen_lora_airtime_config config = LICHEN_LORA_AIRTIME_CONFIG_DEFAULT;
	uint64_t output = UINT64_C(0x1122334455667788);

	zassert_equal(lichen_lora_airtime_us(256U, &config, &output), -EINVAL);
	config.spreading_factor = 5U;
	zassert_equal(lichen_lora_airtime_us(1U, &config, &output), -EINVAL);
	config.spreading_factor = 6U;
	zassert_equal(lichen_lora_airtime_us(1U, &config, &output), -EINVAL);
	config.spreading_factor = 10U;
	config.bandwidth_hz = 123456U;
	zassert_equal(lichen_lora_airtime_us(1U, &config, &output), -EINVAL);
	config.bandwidth_hz = 125000U;
	config.coding_rate = 4U;
	zassert_equal(lichen_lora_airtime_us(1U, &config, &output), -EINVAL);
	config.coding_rate = 5U;
	config.preamble_symbols = 5U;
	zassert_equal(lichen_lora_airtime_us(1U, &config, &output), -EINVAL);
	config.preamble_symbols = 8U;
	config.low_data_rate_optimization = (enum lichen_lora_ldro)99;
	zassert_equal(lichen_lora_airtime_us(1U, &config, &output), -EINVAL);
	zassert_equal(lichen_lora_airtime_us(1U, NULL, &output), -EINVAL);
	zassert_equal(lichen_lora_airtime_us(1U, &config, NULL), -EINVAL);
	zassert_equal(output, UINT64_C(0x1122334455667788));
}

ZTEST_SUITE(airtime, NULL, NULL, NULL, NULL, NULL);
