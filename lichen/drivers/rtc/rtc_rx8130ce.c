/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Måns Ansgariusson <mansgariusson@gmail.com>
 * Copyright (c) 2026 The contributors to the LICHEN project
 *
 * Zephyr RTC driver for the Epson RX8130CE, adapted from the upstream
 * Zephyr drivers/rtc/rtc_rx8130ce.c (Zephyr >= 4.1) so boards pinned to
 * Zephyr v3.7.0 (which has no RX8130CE driver) can use the same chip.
 *
 * LICHEN adaptation scope:
 *   - compatible is "lichen,rx8130ce-rtc" (upstream binding/driver claims
 *     "epson,rx8130ce-rtc" and would collide with it in shared Zephyr
 *     workspaces >= 4.1)
 *   - only the mandatory RTC API is implemented (get/set time, init);
 *     alarms, update callback and calibration are not supported
 *
 * The RX8130CE keeps time across power cycles from its backup supply.
 */

#define DT_DRV_COMPAT lichen_rx8130ce_rtc

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/sys/util.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/drivers/rtc.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(lichen_rx8130ce, CONFIG_RTC_LOG_LEVEL);

enum rx8130ce_reg_addr {
	RX8130CE_REG_TIME	= 0x10,
	RX8130CE_REG_ALARM	= 0x17,
	/* control registers */
	RX8130CE_REG_EXTENSION	= 0x1C,
	RX8130CE_REG_FLAG	= 0x1D,
	RX8130CE_REG_CTRL0	= 0x1E,
	RX8130CE_REG_CTRL1	= 0x1F,
};

#define RX8130CE_SECONDS_MASK	GENMASK(6, 0)
#define RX8130CE_MINUTES_MASK	GENMASK(6, 0)
#define RX8130CE_HOURS_MASK	GENMASK(5, 0)
#define RX8130CE_DAYS_MASK	GENMASK(5, 0)
#define RX8130CE_WEEKDAYS_MASK	GENMASK(6, 0)
#define RX8130CE_MONTHS_MASK	GENMASK(4, 0)
#define RX8130CE_YEARS_MASK	GENMASK(7, 0)

#define RX8130CE_MONTHS_OFFSET	(1)
#define RX8130CE_YEARS_OFFSET	(100)

/* Extension reg(0x1C) bit field */
#define RX8130CE_EXT_TE		BIT(4)
#define RX8130CE_EXT_FSEL0	BIT(6)
#define RX8130CE_EXT_FSEL1	BIT(7)

/* Control1 reg(0x1F) bit field */
#define RX8130CE_CTRL1_INIEN	BIT(4)
#define RX8130CE_CTRL1_CHGEN	BIT(5)

/* rx8130ce control registers, contiguous from EXTENSION (0x1C):
 *   0x1C extension, 0x1D flag, 0x1E control0, 0x1F control1
 */
struct __packed rx8130ce_registers {
	uint8_t extension;
	uint8_t flag;
	uint8_t ctrl0;
	uint8_t ctrl1;
};

struct __packed rx8130ce_time {
	uint8_t second;
	uint8_t minute;
	uint8_t hour;
	uint8_t weekday;
	uint8_t day;
	uint8_t month;
	uint8_t year;
};

struct rx8130ce_config {
	struct i2c_dt_spec i2c;
	uint16_t clockout_frequency;
	uint8_t battery_switchover;
};

struct rx8130ce_data {
	struct k_sem lock;
	struct rx8130ce_registers reg;
};

/* The weekday register is a 1-bit-per-day mask, bit 0 = Sunday. */
static inline uint8_t wday2rtc(uint8_t wday)
{
	return 1 << wday;
}

static inline uint8_t rtc2wday(uint8_t rtc_wday)
{
	for (size_t bit = 0; bit < 7; bit++) {
		if (rtc_wday & (1 << bit)) {
			return (uint8_t)bit;
		}
	}
	return 0;
}

static int rx8130ce_get_time(const struct device *dev, struct rtc_time *timeptr)
{
	int rc = 0;
	struct rx8130ce_time rtc_time;
	const struct rx8130ce_config *cfg = dev->config;
	struct rx8130ce_data *data = dev->data;

	memset(timeptr, 0U, sizeof(*timeptr));

	k_sem_take(&data->lock, K_FOREVER);
	rc = i2c_burst_read_dt(&cfg->i2c, RX8130CE_REG_TIME,
			       (uint8_t *)&rtc_time, sizeof(rtc_time));
	if (rc != 0) {
		LOG_ERR("Failed to read time");
		goto error;
	}
	timeptr->tm_sec = bcd2bin(rtc_time.second & RX8130CE_SECONDS_MASK);
	timeptr->tm_min = bcd2bin(rtc_time.minute & RX8130CE_MINUTES_MASK);
	timeptr->tm_hour = bcd2bin(rtc_time.hour & RX8130CE_HOURS_MASK);
	timeptr->tm_mday = bcd2bin(rtc_time.day & RX8130CE_DAYS_MASK);
	timeptr->tm_wday = rtc2wday(rtc_time.weekday & RX8130CE_WEEKDAYS_MASK);
	timeptr->tm_mon = bcd2bin(rtc_time.month & RX8130CE_MONTHS_MASK) -
			  RX8130CE_MONTHS_OFFSET;
	timeptr->tm_year = bcd2bin(rtc_time.year & RX8130CE_YEARS_MASK) +
			   RX8130CE_YEARS_OFFSET;
	timeptr->tm_yday = -1;
	timeptr->tm_isdst = -1;

error:
	k_sem_give(&data->lock);
	return rc;
}

static int rx8130ce_set_time(const struct device *dev, const struct rtc_time *timeptr)
{
	int rc = 0;
	struct rx8130ce_time rtc_time;
	const struct rx8130ce_config *cfg = dev->config;
	struct rx8130ce_data *data = dev->data;

	rtc_time.second = bin2bcd(timeptr->tm_sec);
	rtc_time.minute = bin2bcd(timeptr->tm_min);
	rtc_time.hour = bin2bcd(timeptr->tm_hour);
	rtc_time.weekday = wday2rtc(timeptr->tm_wday);
	rtc_time.day = bin2bcd(timeptr->tm_mday);
	rtc_time.month = bin2bcd(timeptr->tm_mon + RX8130CE_MONTHS_OFFSET);
	rtc_time.year = bin2bcd(timeptr->tm_year -
			  (timeptr->tm_year >= RX8130CE_YEARS_OFFSET ?
			   RX8130CE_YEARS_OFFSET : 0));

	k_sem_take(&data->lock, K_FOREVER);

	rc = i2c_burst_write_dt(&cfg->i2c, RX8130CE_REG_TIME,
				(uint8_t *)&rtc_time, sizeof(rtc_time));
	if (rc != 0) {
		LOG_ERR("Failed to write time");
		goto error;
	}
	LOG_DBG("set time: year = %d, mon = %d, mday = %d, hour = %d, min = %d, sec = %d",
		timeptr->tm_year, timeptr->tm_mon, timeptr->tm_mday,
		timeptr->tm_hour, timeptr->tm_min, timeptr->tm_sec);
error:
	k_sem_give(&data->lock);
	return rc;
}

static int rx8130ce_init(const struct device *dev)
{
	int rc;
	const struct rx8130ce_config *cfg = dev->config;
	struct rx8130ce_data *data = dev->data;

	k_sem_init(&data->lock, 1, 1);
	if (!i2c_is_ready_dt(&cfg->i2c)) {
		LOG_ERR("I2C bus not ready");
		return -ENODEV;
	}

	/* read all control registers */
	rc = i2c_burst_read_dt(&cfg->i2c, RX8130CE_REG_EXTENSION,
			       (uint8_t *)&data->reg, sizeof(data->reg));
	if (rc != 0) {
		LOG_ERR("Failed to read control registers");
		return rc;
	}

	/* clear all status flags (voltage-low, reset, alarm, timer, update) */
	data->reg.flag = 0x00;
	/* stop the countdown timer; not used */
	data->reg.extension &= ~RX8130CE_EXT_TE;

	switch (cfg->clockout_frequency) {
	case 0: /* FOUT off */
		data->reg.extension |= RX8130CE_EXT_FSEL1 | RX8130CE_EXT_FSEL0;
		break;
	case 1: /* 1 Hz */
		data->reg.extension &= ~RX8130CE_EXT_FSEL0;
		data->reg.extension |= RX8130CE_EXT_FSEL1;
		break;
	case 1024: /* 1.024 kHz */
		data->reg.extension |= RX8130CE_EXT_FSEL0;
		data->reg.extension &= ~RX8130CE_EXT_FSEL1;
		break;
	case 32768: /* 32.768 kHz */
		data->reg.extension &= ~(RX8130CE_EXT_FSEL1 | RX8130CE_EXT_FSEL0);
		break;
	default:
		LOG_ERR("Invalid clockout frequency option: %d", cfg->clockout_frequency);
		return -EINVAL;
	}

	if (cfg->battery_switchover != 0) {
		/* Enable initial voltage detection first; the datasheet
		 * requires INIEN to be committed before the switchover mode
		 * unless INIEN was already set once (one-time latch).
		 */
		data->reg.ctrl1 |= RX8130CE_CTRL1_INIEN;
		rc = i2c_burst_write_dt(&cfg->i2c, RX8130CE_REG_CTRL1,
					&data->reg.ctrl1, sizeof(data->reg.ctrl1));
		if (rc != 0) {
			LOG_ERR("Failed to write ctrl1 register");
			return rc;
		}
	}

	switch (cfg->battery_switchover) {
	case 1: /* power switch-over on, non-rechargeable backup battery */
		data->reg.ctrl1 |= RX8130CE_CTRL1_INIEN;
		break;
	case 2: /* power switch-over on, rechargeable backup battery */
		data->reg.ctrl1 &= ~(RX8130CE_CTRL1_INIEN | RX8130CE_CTRL1_CHGEN);
		break;
	case 3: /* power switch-over on, rechargeable, i2c & FOUT off below Vdet1 */
		data->reg.ctrl1 |= RX8130CE_CTRL1_CHGEN | RX8130CE_CTRL1_INIEN;
		break;
	case 4: /* power switch-over on, rechargeable, i2c & FOUT always on */
		data->reg.ctrl1 |= RX8130CE_CTRL1_CHGEN;
		data->reg.ctrl1 &= ~RX8130CE_CTRL1_INIEN;
		break;
	}

	rc = i2c_burst_write_dt(&cfg->i2c, RX8130CE_REG_EXTENSION,
				(uint8_t *)&data->reg, sizeof(data->reg));
	if (rc != 0) {
		LOG_ERR("Failed to write control registers");
		return rc;
	}
	return 0;
}

static const struct rtc_driver_api rx8130ce_driver_api = {
	.set_time = rx8130ce_set_time,
	.get_time = rx8130ce_get_time,
};

#define RX8130CE_INIT(inst)								\
	static const struct rx8130ce_config rx8130ce_config_##inst = {			\
		.i2c = I2C_DT_SPEC_INST_GET(inst),					\
		.clockout_frequency = DT_INST_PROP_OR(inst, clockout_frequency, 0),	\
		.battery_switchover = DT_INST_PROP_OR(inst, battery_switchover, 0),	\
	};										\
											\
	static struct rx8130ce_data rx8130ce_data_##inst;				\
											\
	DEVICE_DT_INST_DEFINE(inst, &rx8130ce_init, NULL,				\
			      &rx8130ce_data_##inst, &rx8130ce_config_##inst, POST_KERNEL, \
			      CONFIG_RTC_INIT_PRIORITY, &rx8130ce_driver_api);

DT_INST_FOREACH_STATUS_OKAY(RX8130CE_INIT)
