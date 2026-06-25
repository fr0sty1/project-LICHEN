/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 The contributors to the LICHEN project
 *
 * Zephyr GNSS driver for the Airoha AG3335 series.
 *
 * Power sequence (T1000-E schematic / Meshtastic variant.h):
 *   1. VRTC_EN → HIGH  (RTC backup supply; never toggled after init)
 *   2. SLEEP_INT → HIGH (hold for normal operation)
 *   3. GPS_EN → HIGH   (main power)
 *   4. 200ms settling
 *   5. RESET → HIGH 10ms → LOW; 100ms post-reset boot
 *
 * After power-on the AG3335 streams NMEA-0183 at 115200 baud with no
 * further init required.
 */

#include <zephyr/drivers/gnss.h>
#include <zephyr/drivers/gnss/gnss_publish.h>
#include <zephyr/modem/chat.h>
#include <zephyr/modem/backend/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <string.h>

#include "gnss_nmea0183.h"
#include "gnss_nmea0183_match.h"
#include "gnss_parse.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(gnss_ag3335, CONFIG_GNSS_LOG_LEVEL);

#define DT_DRV_COMPAT airoha_ag3335

#define UART_RX_BUF_SZ   (256 + IS_ENABLED(CONFIG_GNSS_SATELLITES) * 512)
#define UART_TX_BUF_SZ   64
#define CHAT_RECV_BUF_SZ 256
#define CHAT_ARGV_SZ     32

struct gnss_ag3335_config {
	const struct device    *uart;
	struct gpio_dt_spec     enable_gpio;
	struct gpio_dt_spec     vrtc_gpio;
	struct gpio_dt_spec     sleep_int_gpio;
	struct gpio_dt_spec     reset_gpio;
};

struct gnss_ag3335_data {
	struct gnss_nmea0183_match_data match_data;
#if CONFIG_GNSS_SATELLITES
	struct gnss_satellite satellites[CONFIG_GNSS_AG3335_SATELLITES_COUNT];
#endif

	struct modem_pipe        *uart_pipe;
	struct modem_backend_uart uart_backend;
	uint8_t uart_backend_receive_buf[UART_RX_BUF_SZ];
	uint8_t uart_backend_transmit_buf[UART_TX_BUF_SZ];

	struct modem_chat chat;
	uint8_t           chat_receive_buf[CHAT_RECV_BUF_SZ];
	uint8_t          *chat_argv[CHAT_ARGV_SZ];
};

MODEM_CHAT_MATCHES_DEFINE(unsol_matches,
	MODEM_CHAT_MATCH_WILDCARD("$??GGA,", ",*", gnss_nmea0183_match_gga_callback),
	MODEM_CHAT_MATCH_WILDCARD("$??RMC,", ",*", gnss_nmea0183_match_rmc_callback),
#if CONFIG_GNSS_SATELLITES
	MODEM_CHAT_MATCH_WILDCARD("$??GSV,", ",*", gnss_nmea0183_match_gsv_callback),
#endif
);

MODEM_CHAT_SCRIPT_EMPTY_DEFINE(gnss_ag3335_init_chat_script);

static int gnss_ag3335_resume(const struct device *dev)
{
	struct gnss_ag3335_data *data = dev->data;
	int ret;

	ret = modem_pipe_open(data->uart_pipe);
	if (ret < 0) {
		return ret;
	}

	ret = modem_chat_attach(&data->chat, data->uart_pipe);
	if (ret < 0) {
		modem_pipe_close(data->uart_pipe);
		return ret;
	}

	ret = modem_chat_run_script(&data->chat, &gnss_ag3335_init_chat_script);
	if (ret < 0) {
		modem_pipe_close(data->uart_pipe);
	}
	return ret;
}

static const struct gnss_driver_api gnss_ag3335_api = {
};

static int gnss_ag3335_init_match(const struct device *dev)
{
	struct gnss_ag3335_data *data = dev->data;

	const struct gnss_nmea0183_match_config match_config = {
		.gnss = dev,
#if CONFIG_GNSS_SATELLITES
		.satellites      = data->satellites,
		.satellites_size = ARRAY_SIZE(data->satellites),
#endif
	};

	return gnss_nmea0183_match_init(&data->match_data, &match_config);
}

static void gnss_ag3335_init_pipe(const struct device *dev)
{
	const struct gnss_ag3335_config *cfg = dev->config;
	struct gnss_ag3335_data *data = dev->data;

	const struct modem_backend_uart_config uart_backend_config = {
		.uart              = cfg->uart,
		.receive_buf       = data->uart_backend_receive_buf,
		.receive_buf_size  = sizeof(data->uart_backend_receive_buf),
		.transmit_buf      = data->uart_backend_transmit_buf,
		.transmit_buf_size = sizeof(data->uart_backend_transmit_buf),
	};

	data->uart_pipe = modem_backend_uart_init(&data->uart_backend, &uart_backend_config);
}

static uint8_t gnss_ag3335_char_delimiter[] = {'\r', '\n'};

static int gnss_ag3335_init_chat(const struct device *dev)
{
	struct gnss_ag3335_data *data = dev->data;

	const struct modem_chat_config chat_config = {
		.user_data          = data,
		.receive_buf        = data->chat_receive_buf,
		.receive_buf_size   = sizeof(data->chat_receive_buf),
		.delimiter          = gnss_ag3335_char_delimiter,
		.delimiter_size     = ARRAY_SIZE(gnss_ag3335_char_delimiter),
		.filter             = NULL,
		.filter_size        = 0,
		.argv               = data->chat_argv,
		.argv_size          = ARRAY_SIZE(data->chat_argv),
		.unsol_matches      = unsol_matches,
		.unsol_matches_size = ARRAY_SIZE(unsol_matches),
	};

	return modem_chat_init(&data->chat, &chat_config);
}

static int gnss_ag3335_power_on(const struct device *dev)
{
	const struct gnss_ag3335_config *cfg = dev->config;

	if (gpio_pin_configure_dt(&cfg->vrtc_gpio,      GPIO_OUTPUT_INACTIVE) < 0 ||
	    gpio_pin_configure_dt(&cfg->sleep_int_gpio,  GPIO_OUTPUT_INACTIVE) < 0 ||
	    gpio_pin_configure_dt(&cfg->reset_gpio,      GPIO_OUTPUT_INACTIVE) < 0 ||
	    gpio_pin_configure_dt(&cfg->enable_gpio,     GPIO_OUTPUT_INACTIVE) < 0) {
		LOG_ERR("GPIO configuration failed");
		return -EIO;
	}

	gpio_pin_set_dt(&cfg->vrtc_gpio,      1); /* RTC backup — hold always */
	gpio_pin_set_dt(&cfg->sleep_int_gpio, 1); /* normal op  — hold always */
	gpio_pin_set_dt(&cfg->enable_gpio,    1); /* main power on */
	k_sleep(K_MSEC(200));                     /* settling */

	gpio_pin_set_dt(&cfg->reset_gpio, 1);     /* reset pulse */
	k_sleep(K_MSEC(10));
	gpio_pin_set_dt(&cfg->reset_gpio, 0);
	k_sleep(K_MSEC(100));                     /* boot after reset */

	return 0;
}

static int gnss_ag3335_init(const struct device *dev)
{
	int ret;

	ret = gnss_ag3335_power_on(dev);
	if (ret < 0) {
		return ret;
	}

	ret = gnss_ag3335_init_match(dev);
	if (ret < 0) {
		return ret;
	}

	gnss_ag3335_init_pipe(dev);

	ret = gnss_ag3335_init_chat(dev);
	if (ret < 0) {
		return ret;
	}

	return gnss_ag3335_resume(dev);
}

#define GNSS_AG3335_DEFINE(inst)                                                    \
	static const struct gnss_ag3335_config gnss_ag3335_config_##inst = {        \
		.uart           = DEVICE_DT_GET(DT_INST_BUS(inst)),                 \
		.enable_gpio    = GPIO_DT_SPEC_INST_GET(inst, enable_gpios),        \
		.vrtc_gpio      = GPIO_DT_SPEC_INST_GET(inst, vrtc_gpios),         \
		.sleep_int_gpio = GPIO_DT_SPEC_INST_GET(inst, sleep_int_gpios),    \
		.reset_gpio     = GPIO_DT_SPEC_INST_GET(inst, reset_gpios),        \
	};                                                                          \
                                                                                    \
	static struct gnss_ag3335_data gnss_ag3335_data_##inst;                     \
                                                                                    \
	DEVICE_DT_INST_DEFINE(inst, gnss_ag3335_init, NULL,                         \
			      &gnss_ag3335_data_##inst, &gnss_ag3335_config_##inst, \
			      POST_KERNEL, CONFIG_GNSS_INIT_PRIORITY,               \
			      &gnss_ag3335_api);

DT_INST_FOREACH_STATUS_OKAY(GNSS_AG3335_DEFINE)
