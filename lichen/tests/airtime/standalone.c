/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include <lichen/airtime.h>

int main(void)
{
	struct lichen_lora_airtime_config config = LICHEN_LORA_AIRTIME_CONFIG_DEFAULT;
	uint64_t airtime = 0U;

	assert(lichen_lora_airtime_default_us(60U, &airtime) == 0);
	assert(airtime == 698368U);
	config.spreading_factor = 9U;
	assert(lichen_lora_airtime_us(60U, &config, &airtime) == 0);
	assert(airtime == 369664U);
	config.spreading_factor = 10U;
	config.low_data_rate_optimization = LICHEN_LORA_LDRO_DISABLED;
	assert(lichen_lora_airtime_us(255U, &config, &airtime) == 0);
	assert(airtime == 2295808U);
	assert(lichen_lora_airtime_us(256U, &config, &airtime) == -EINVAL);

	return 0;
}
