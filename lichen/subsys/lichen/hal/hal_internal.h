/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_HAL_INTERNAL_H_
#define LICHEN_HAL_INTERNAL_H_

#include <zephyr/kernel.h>

#include <lichen/hal.h>

#define LICHEN_HAL_KNOWN_CAPS \
	(LICHEN_HAL_CAP_LORA | LICHEN_HAL_CAP_BLE_LOCAL | \
	 LICHEN_HAL_CAP_SERIAL_LOCAL | LICHEN_HAL_CAP_GNSS | \
	 LICHEN_HAL_CAP_BATTERY | LICHEN_HAL_CAP_PMIC | \
	 LICHEN_HAL_CAP_BUTTONS | LICHEN_HAL_CAP_LEDS | \
	 LICHEN_HAL_CAP_DISPLAY | LICHEN_HAL_CAP_EXTERNAL_FLASH)

#define LICHEN_HAL_BATTERY_NODE DT_ALIAS(battery0)
#define LICHEN_HAL_PMIC_NODE DT_ALIAS(pmic0)

#define LICHEN_HAL_BATTERY_IS_VOLTAGE_DIVIDER \
	DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, voltage_divider)
#define LICHEN_HAL_BATTERY_IS_FUEL_GAUGE \
	(DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, maxim_max17048) || \
	 DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, sbs_sbs_gauge_new_api) || \
	 DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, ti_bq27z746))
#define LICHEN_HAL_BATTERY_DRIVER_ENABLED \
	((DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, voltage_divider) && \
	  IS_ENABLED(CONFIG_VOLTAGE_DIVIDER)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, maxim_max17048) && \
	  IS_ENABLED(CONFIG_MAX17048)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, sbs_sbs_gauge_new_api) && \
	  IS_ENABLED(CONFIG_SBS_GAUGE_NEW_API)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_BATTERY_NODE, ti_bq27z746) && \
	  IS_ENABLED(CONFIG_BQ27Z746)))
#define LICHEN_HAL_PMIC_IS_CHARGER \
	(DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, sbs_sbs_charger) || \
	 DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, ti_bq24190) || \
	 DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, ti_bq25180) || \
	 DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, maxim_max20335_charger))
#define LICHEN_HAL_PMIC_DRIVER_ENABLED \
	((DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, sbs_sbs_charger) && \
	  IS_ENABLED(CONFIG_SBS_CHARGER)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, ti_bq24190) && \
	  IS_ENABLED(CONFIG_CHARGER_BQ24190)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, ti_bq25180) && \
	  IS_ENABLED(CONFIG_CHARGER_BQ25180)) || \
	 (DT_NODE_HAS_COMPAT(LICHEN_HAL_PMIC_NODE, maxim_max20335_charger) && \
	  IS_ENABLED(CONFIG_CHARGER_MAX20335)) || \
	 !LICHEN_HAL_PMIC_IS_CHARGER)

struct location_provider_state {
	struct lichen_hal_location_sample samples[LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC + 1];
	char source_names[LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC + 1]
			 [sizeof(((struct lichen_hal_location_time_snapshot *)0)->source_name)];
	bool has_sample[LICHEN_HAL_LOCATION_SOURCE_MANUAL_STATIC + 1];
};

struct time_provider_state {
	struct lichen_hal_time_sample samples[LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC + 1];
	struct lichen_hal_time_sample diagnostic_sample;
	char source_names[LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC + 1]
			 [sizeof(((struct lichen_hal_time_snapshot *)0)->source_name)];
	char diagnostic_source_name
		[sizeof(((struct lichen_hal_time_snapshot *)0)->source_name)];
	bool has_sample[LICHEN_HAL_TIME_SOURCE_MANUAL_STATIC + 1];
	bool has_diagnostic_sample;
	bool provision_epoch_valid;
	uint32_t provision_epoch;
	enum lichen_hal_time_rejection_reason last_rejection;
};

extern const struct lichen_hal_capabilities lichen_hal_caps;
extern struct location_provider_state lichen_hal_location_state;
extern struct k_mutex lichen_hal_location_mutex;
extern struct time_provider_state lichen_hal_time_state;
extern struct k_mutex lichen_hal_time_mutex;

#ifdef CONFIG_ZTEST
extern bool lichen_hal_test_use_uptime;
extern int64_t lichen_hal_test_uptime_ms;
extern bool lichen_hal_test_reset_request_valid;
extern enum lichen_hal_reset_request lichen_hal_test_reset_request;
extern struct lichen_hal_location_time_snapshot lichen_hal_test_location_time_snapshot;
extern bool lichen_hal_test_has_location_time_snapshot;
#endif

int64_t lichen_hal_now_ms(void);

#endif /* LICHEN_HAL_INTERNAL_H_ */
