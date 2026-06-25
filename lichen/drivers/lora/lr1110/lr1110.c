/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 The contributors to the LICHEN project
 *
 * Zephyr LoRa driver for the Semtech LR1110.
 *
 * Implements lora_driver_api directly using the lr1110_driver library.
 * IRQ routing: TXDONE/RXDONE/errors → DIO9 → k_work → k_sem.
 */

#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "lr1110_hal.h"
#include "lr1110_radio.h"
#include "lr1110_regmem.h"
#include "lr1110_system.h"

LOG_MODULE_REGISTER(lr1110, CONFIG_LORA_LOG_LEVEL);

#define DT_DRV_COMPAT semtech_lr1110

/* IRQ mask bits routed to DIO9 */
#define LR1110_IRQ_RADIO (LR1110_SYSTEM_IRQ_TXDONE_MASK    | \
			  LR1110_SYSTEM_IRQ_RXDONE_MASK    | \
			  LR1110_SYSTEM_IRQ_HEADERERR_MASK | \
			  LR1110_SYSTEM_IRQ_CRCERR_MASK    | \
			  LR1110_SYSTEM_IRQ_TIMEOUT_MASK)

/* "Continuous RX" sentinel for lr1110_radio_set_rx */
#define LR1110_RX_CONTINUOUS  0x00FFFFFFu

#define LR1110_MAX_PAYLOAD 255U

/* PA selection — overridden per-board via hp-max-power DTS property */
#if DT_INST_NODE_HAS_PROP(0, hp_max_power)
#define LR1110_PA_SEL       LR1110_RADIO_PA_SEL_HP
#define LR1110_PA_SUPPLY    LR1110_RADIO_PA_REG_SUPPLY_VBAT
#define LR1110_PA_DC        4U
#define LR1110_PA_HP_SEL    7U
#else
#define LR1110_PA_SEL       LR1110_RADIO_PA_SEL_LP
#define LR1110_PA_SUPPLY    LR1110_RADIO_PA_REG_SUPPLY_DCDC
#define LR1110_PA_DC        4U
#define LR1110_PA_HP_SEL    0U
#endif

/* --------------------------------------------------------------------------
 * Hardware resources — shared with lr1110_hal.c
 * -------------------------------------------------------------------------- */

/* These three are extern-declared in lr1110_hal.c */
const struct spi_dt_spec  lr1110_bus =
	SPI_DT_SPEC_INST_GET(0, SPI_WORD_SET(8) | SPI_TRANSFER_MSB, 0);
const struct gpio_dt_spec lr1110_gpio_reset =
	GPIO_DT_SPEC_INST_GET(0, reset_gpios);
const struct gpio_dt_spec lr1110_gpio_busy =
	GPIO_DT_SPEC_INST_GET(0, busy_gpios);

static const struct gpio_dt_spec lr1110_gpio_dio9 =
	GPIO_DT_SPEC_INST_GET(0, dio9_gpios);

#if DT_INST_NODE_HAS_PROP(0, tx_enable_gpios)
static const struct gpio_dt_spec lr1110_gpio_tx_enable =
	GPIO_DT_SPEC_INST_GET(0, tx_enable_gpios);
#endif

/* --------------------------------------------------------------------------
 * Driver state
 * -------------------------------------------------------------------------- */

struct lr1110_data {
	struct gpio_callback dio9_cb;
	struct k_work        irq_work;
	struct k_sem         radio_sem;
	uint32_t             last_irq;
};

static struct lr1110_data dev_data;

/* Used as the lr1110_driver "context" pointer in all library calls */
static const struct device *lr1110_dev;

/* --------------------------------------------------------------------------
 * Enum mapping: Zephyr → LR1110
 * -------------------------------------------------------------------------- */

static inline lr1110_radio_lora_sf_t map_sf(enum lora_datarate dr)
{
	/* Zephyr SF_6..SF_12 == 6..12; LR1110 SF6..SF12 == 0x06..0x0C */
	return (lr1110_radio_lora_sf_t)dr;
}

static lr1110_radio_lora_bw_t map_bw(enum lora_signal_bandwidth bw)
{
	switch (bw) {
	case BW_125_KHZ: return LR1110_RADIO_LORA_BW125;
	case BW_250_KHZ: return LR1110_RADIO_LORA_BW250;
	case BW_500_KHZ: return LR1110_RADIO_LORA_BW500;
	default:         return LR1110_RADIO_LORA_BW125;
	}
}

static inline lr1110_radio_lora_cr_t map_cr(enum lora_coding_rate cr)
{
	/* Zephyr CR_4_5..CR_4_8 == 1..4; LR1110 CR45..CR48 == 0x01..0x04 */
	return (lr1110_radio_lora_cr_t)cr;
}

/* --------------------------------------------------------------------------
 * DIO9 interrupt handling
 * -------------------------------------------------------------------------- */

static void lr1110_irq_work_handler(struct k_work *work)
{
	struct lr1110_data *data = CONTAINER_OF(work, struct lr1110_data, irq_work);
	lr1110_system_stat1_t stat1;
	lr1110_system_stat2_t stat2;
	uint32_t irq = 0;

	lr1110_system_get_status(lr1110_dev, &stat1, &stat2, &irq);
	lr1110_system_clear_irq(lr1110_dev, irq);
	data->last_irq = irq;
	k_sem_give(&data->radio_sem);
}

static void lr1110_dio9_isr(const struct device *port,
			    struct gpio_callback *cb, uint32_t pins)
{
	ARG_UNUSED(port);
	ARG_UNUSED(pins);
	struct lr1110_data *data = CONTAINER_OF(cb, struct lr1110_data, dio9_cb);

	k_work_submit(&data->irq_work);
}

/* --------------------------------------------------------------------------
 * lora_driver_api
 * -------------------------------------------------------------------------- */

static int lr1110_lora_config(const struct device *dev,
			      struct lora_modem_config *cfg)
{
	lr1110_hal_reset(dev);

	lr1110_radio_set_packet_type(dev, LR1110_RADIO_PACKET_LORA);
	lr1110_radio_set_rf_frequency(dev, cfg->frequency);

	lr1110_radio_modulation_param_lora_t mod = {
		.spreading_factor = map_sf(cfg->datarate),
		.bandwidth        = map_bw(cfg->bandwidth),
		.coding_rate      = map_cr(cfg->coding_rate),
		.ppm_offset       = 0,
	};
	lr1110_radio_set_modulation_param_lora(dev, &mod);

	lr1110_radio_packet_param_lora_t pkt = {
		.preamble_length_in_symb = cfg->preamble_len,
		.header_type             = LR1110_RADIO_LORA_HEADER_EXPLICIT,
		.payload_length_in_byte  = LR1110_MAX_PAYLOAD,
		.crc                     = LR1110_RADIO_LORA_CRC_ON,
		.iq = cfg->iq_inverted ? LR1110_RADIO_LORA_IQ_INVERTED
				       : LR1110_RADIO_LORA_IQ_STANDARD,
	};
	lr1110_radio_set_packet_param_lora(dev, &pkt);

	lr1110_radio_pa_config_t pa = {
		.pa_sel        = LR1110_PA_SEL,
		.pa_reg_supply = LR1110_PA_SUPPLY,
		.pa_dutycycle  = LR1110_PA_DC,
		.pa_hp_sel     = LR1110_PA_HP_SEL,
	};
	lr1110_radio_set_pa_config(dev, &pa);
	lr1110_radio_set_tx_params(dev, cfg->tx_power, LR1110_RADIO_RAMP_TIME_40U);

	lr1110_system_set_dio_irq_params(dev, LR1110_IRQ_RADIO, 0);

#if DT_INST_NODE_HAS_PROP(0, tx_enable_gpios)
	gpio_pin_set_dt(&lr1110_gpio_tx_enable, cfg->tx ? 1 : 0);
#endif

	gpio_pin_interrupt_configure_dt(&lr1110_gpio_dio9, GPIO_INT_EDGE_TO_ACTIVE);

	LOG_INF("LR1110 cfg: %u Hz SF%u BW%u CR4/%u pwr=%d tx=%d",
		cfg->frequency,
		(unsigned)cfg->datarate,
		cfg->bandwidth == BW_125_KHZ ? 125u :
		cfg->bandwidth == BW_250_KHZ ? 250u : 500u,
		(unsigned)cfg->coding_rate + 4u,
		cfg->tx_power, (int)cfg->tx);

	return 0;
}

static int lr1110_lora_send(const struct device *dev, uint8_t *data,
			    uint32_t data_len)
{
	struct lr1110_data *drv = dev->data;

	if (data_len > LR1110_MAX_PAYLOAD) {
		return -EMSGSIZE;
	}

	k_sem_reset(&drv->radio_sem);
	lr1110_regmem_write_buffer8(dev, data, (uint8_t)data_len);
	lr1110_radio_set_tx(dev, 0);

	if (k_sem_take(&drv->radio_sem, K_SECONDS(10)) != 0) {
		LOG_ERR("TX timeout");
		return -ETIMEDOUT;
	}

	if (drv->last_irq & LR1110_SYSTEM_IRQ_TXDONE_MASK) {
		return 0;
	}
	LOG_ERR("TX error irq=0x%08x", drv->last_irq);
	return -EIO;
}

static int lr1110_lora_send_async(const struct device *dev, uint8_t *data,
				  uint32_t data_len, struct k_poll_signal *async)
{
	ARG_UNUSED(async);
	return lr1110_lora_send(dev, data, data_len);
}

static int lr1110_lora_recv(const struct device *dev, uint8_t *data,
			    uint8_t size, k_timeout_t timeout,
			    int16_t *rssi, int8_t *snr)
{
	struct lr1110_data *drv = dev->data;

	k_sem_reset(&drv->radio_sem);
	lr1110_radio_set_rx(dev, LR1110_RX_CONTINUOUS);

	if (k_sem_take(&drv->radio_sem, timeout) != 0) {
		return -EAGAIN;
	}

	if (!(drv->last_irq & LR1110_SYSTEM_IRQ_RXDONE_MASK)) {
		if (drv->last_irq & LR1110_SYSTEM_IRQ_TIMEOUT_MASK) {
			return -EAGAIN;
		}
		LOG_WRN("RX error irq=0x%08x", drv->last_irq);
		return -EIO;
	}

	lr1110_radio_rxbuffer_status_t buf_status;
	lr1110_radio_get_rxbuffer_status(dev, &buf_status);

	uint8_t len = MIN(buf_status.rx_payload_length, size);
	lr1110_regmem_read_buffer8(dev, data, buf_status.rx_start_buffer_pointer, len);

	if (rssi || snr) {
		lr1110_radio_packet_status_lora_t pkt_status;
		lr1110_radio_get_packet_status_lora(dev, &pkt_status);
		if (rssi) {
			*rssi = pkt_status.rssi_packet_in_dbm;
		}
		if (snr) {
			*snr = pkt_status.snr_packet_in_db;
		}
	}

	return (int)len;
}

static int lr1110_lora_recv_async(const struct device *dev, lora_recv_cb cb)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(cb);
	return -ENOTSUP;
}

static const struct lora_driver_api lr1110_lora_api = {
	.config     = lr1110_lora_config,
	.send       = lr1110_lora_send,
	.send_async = lr1110_lora_send_async,
	.recv       = lr1110_lora_recv,
	.recv_async = lr1110_lora_recv_async,
};

/* --------------------------------------------------------------------------
 * Driver init
 * -------------------------------------------------------------------------- */

static int lr1110_init(const struct device *dev)
{
	struct lr1110_data *data = dev->data;

	lr1110_dev = dev;

	if (!spi_is_ready_dt(&lr1110_bus)) {
		LOG_ERR("SPI bus not ready");
		return -ENODEV;
	}

	if (gpio_pin_configure_dt(&lr1110_gpio_reset, GPIO_OUTPUT_INACTIVE) ||
	    gpio_pin_configure_dt(&lr1110_gpio_busy,  GPIO_INPUT)            ||
	    gpio_pin_configure_dt(&lr1110_gpio_dio9,  GPIO_INPUT)) {
		LOG_ERR("GPIO configuration failed");
		return -EIO;
	}

#if DT_INST_NODE_HAS_PROP(0, tx_enable_gpios)
	if (gpio_pin_configure_dt(&lr1110_gpio_tx_enable, GPIO_OUTPUT_INACTIVE)) {
		LOG_ERR("TX-enable GPIO configuration failed");
		return -EIO;
	}
#endif

	k_sem_init(&data->radio_sem, 0, 1);
	k_work_init(&data->irq_work, lr1110_irq_work_handler);

	gpio_init_callback(&data->dio9_cb, lr1110_dio9_isr,
			   BIT(lr1110_gpio_dio9.pin));
	if (gpio_add_callback(lr1110_gpio_dio9.port, &data->dio9_cb)) {
		LOG_ERR("Failed to add DIO9 callback");
		return -EIO;
	}
	gpio_pin_interrupt_configure_dt(&lr1110_gpio_dio9, GPIO_INT_DISABLE);

	LOG_DBG("LR1110 initialized");
	return 0;
}

DEVICE_DT_INST_DEFINE(0, lr1110_init, NULL, &dev_data, NULL,
		      POST_KERNEL, CONFIG_LORA_INIT_PRIORITY, &lr1110_lora_api);
