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

/* Heartbeat hook — the application overrides this (strong definition) to feed a
 * progress watchdog from inside the TX/RX poll loops, so a genuinely stuck SPI
 * transfer is caught quickly while normal multi-second waits are not. Weak
 * no-op by default so the driver stands alone. */
__attribute__((weak)) void lichen_radio_progress(void) { }

BUILD_ASSERT(DT_NUM_INST_STATUS_OKAY(DT_DRV_COMPAT) <= 1,
	     "LR1110 driver supports only one instance (uses global state)");

/* IRQ mask bits enabled for radio operations. PREAMBLEDETECTED and
 * SYNCWORD_HEADERVALID are included so the recv poll loop can hold its
 * window open while a frame is arriving instead of aborting mid-reception
 * (the enable mask also gates the IRQ status register we poll). */
#define LR1110_IRQ_RADIO (LR1110_SYSTEM_IRQ_TXDONE_MASK              | \
			  LR1110_SYSTEM_IRQ_RXDONE_MASK              | \
			  LR1110_SYSTEM_IRQ_PREAMBLEDETECTED_MASK    | \
			  LR1110_SYSTEM_IRQ_SYNCWORD_HEADERVALID_MASK | \
			  LR1110_SYSTEM_IRQ_HEADERERR_MASK           | \
			  LR1110_SYSTEM_IRQ_CRCERR_MASK              | \
			  LR1110_SYSTEM_IRQ_TIMEOUT_MASK)

/* Hold-open bound: remaining airtime of a full 255-byte SF10/125 kHz frame
 * after its preamble, with margin. */
#define LR1110_RX_HOLD_MS 2500

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

void lr1110_hal_clear_last_error(void);
int lr1110_hal_get_last_error(void);

#define LR1110_RETURN_ON_HAL_ERROR(expr)                                      \
	do {                                                                  \
		lr1110_hal_clear_last_error();                                 \
		expr;                                                         \
		int err__ = lr1110_hal_get_last_error();                       \
		if (err__ < 0) {                                               \
			LOG_ERR("%s failed: %d", #expr, err__);                \
			return err__;                                          \
		}                                                             \
	} while (0)

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
	/* LoRa packet params from the last config, kept so lora_send() can set
	 * the real payload length per-TX (explicit header). Without this the
	 * chip transmits a full LR1110_MAX_PAYLOAD-byte packet every time. */
	lr1110_radio_packet_param_lora_t pkt_params;
};

/*
 * Single-instance limitation: This driver uses a global dev_data struct and
 * lr1110_dev pointer, so only one LR1110 device is supported. Multi-instance
 * support would require passing instance data through the lr1110_driver HAL
 * context pointer and refactoring the DT macros to allocate per-instance data.
 */
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

	lr1110_hal_clear_last_error();
	lr1110_system_get_status(lr1110_dev, &stat1, &stat2, &irq);
	if (lr1110_hal_get_last_error() < 0) {
		data->last_irq = 0;
		k_sem_give(&data->radio_sem);
		return;
	}

	lr1110_hal_clear_last_error();
	lr1110_system_clear_irq(lr1110_dev, irq);
	if (lr1110_hal_get_last_error() < 0) {
		data->last_irq = 0;
		k_sem_give(&data->radio_sem);
		return;
	}

	data->last_irq = irq;
	k_sem_give(&data->radio_sem);

	/* Re-arm the DIO9 edge interrupt now that clear_irq has deasserted the
	 * line. The hard ISR disables it on entry to prevent an interrupt storm
	 * if DIO9 stays asserted (nRF GPIO SENSE re-triggers on a held level). */
	gpio_pin_interrupt_configure_dt(&lr1110_gpio_dio9, GPIO_INT_EDGE_TO_ACTIVE);
}

static void lr1110_dio9_isr(const struct device *port,
			    struct gpio_callback *cb, uint32_t pins)
{
	ARG_UNUSED(port);
	ARG_UNUSED(pins);
	struct lr1110_data *data = CONTAINER_OF(cb, struct lr1110_data, dio9_cb);

	/* Disable the interrupt immediately: if DIO9 stays asserted (the LR1110
	 * holds it high until the IRQ is cleared over SPI), an nRF SENSE-based
	 * "edge" interrupt re-fires continuously and pegs the CPU in this ISR,
	 * starving every thread — including the k_sem_take timeout. The work
	 * handler re-arms it after clearing the chip IRQ (which deasserts DIO9). */
	gpio_pin_interrupt_configure_dt(&lr1110_gpio_dio9, GPIO_INT_DISABLE);
	k_work_submit(&data->irq_work);
}

/* --------------------------------------------------------------------------
 * lora_driver_api
 * -------------------------------------------------------------------------- */

static int lr1110_lora_config(const struct device *dev,
			      struct lora_modem_config *cfg)
{
	/* Disable DIO9 interrupt before reset: the LR1110 asserts DIO9 during
	 * its boot sequence. Without this, a spurious ISR races the SPI bus
	 * against the calibration sequence. (We drive TX/RX by polling and never
	 * re-enable this interrupt — see the note near clear_irq below.) */
	gpio_pin_interrupt_configure_dt(&lr1110_gpio_dio9, GPIO_INT_DISABLE);

	LR1110_RETURN_ON_HAL_ERROR(lr1110_hal_reset(dev));

	/* The Seeed T1000-E clocks the LR1110 from a TCXO. It must be powered
	 * (via set_tcxo_mode) BEFORE calibration, otherwise the HF crystal never
	 * starts and every RF command (set_tx) fails with a command error.
	 * 1.8 V supply; timeout in 30.52 us RTC steps. */
	LR1110_RETURN_ON_HAL_ERROR(
		lr1110_system_set_tcxo_mode(dev, LR1110_SYSTEM_TCXO_SUPPLY_VOLTAGE_1_8V, 4096));

	LR1110_RETURN_ON_HAL_ERROR(lr1110_system_calibrate(dev, 0x3Fu)); /* all 6 calibration blocks */

	/* RF switch: the T1000-E routes the antenna through a switch driven by
	 * DIO5-DIO8. Without this the chip never selects the RX path — TX
	 * happens to work on the default state, but RX is completely deaf
	 * (RXDONE never fires; bd r002). Table from Meshtastic's proven
	 * T1000-E support (variants/nrf52840/tracker-t1000-e/rfswitch.h):
	 *   RX = DIO5+DIO8, TX = DIO5+DIO6+DIO8, TX_HP = DIO6+DIO8,
	 *   GNSS = DIO7. */
	{
		const lr1110_system_rfswitch_config_t rfswitch = {
			.enable = LR1110_SYSTEM_RFSW0_HIGH |
				  LR1110_SYSTEM_RFSW1_HIGH |
				  LR1110_SYSTEM_RFSW2_HIGH |
				  LR1110_SYSTEM_RFSW3_HIGH,
			.standby = 0,
			.rx = LR1110_SYSTEM_RFSW0_HIGH | LR1110_SYSTEM_RFSW3_HIGH,
			.tx = LR1110_SYSTEM_RFSW0_HIGH | LR1110_SYSTEM_RFSW1_HIGH |
			      LR1110_SYSTEM_RFSW3_HIGH,
			.tx_hp = LR1110_SYSTEM_RFSW1_HIGH | LR1110_SYSTEM_RFSW3_HIGH,
			.tx_hf = 0,
			.gnss = LR1110_SYSTEM_RFSW2_HIGH,
			.wifi = 0,
		};

		LR1110_RETURN_ON_HAL_ERROR(
			lr1110_system_set_dio_as_rf_switch(dev, &rfswitch));
	}

	LR1110_RETURN_ON_HAL_ERROR(lr1110_system_clear_errors(dev));
	LR1110_RETURN_ON_HAL_ERROR(lr1110_radio_set_packet_type(dev, LR1110_RADIO_PACKET_LORA));
	LR1110_RETURN_ON_HAL_ERROR(lr1110_radio_set_rf_frequency(dev, cfg->frequency));

	lr1110_radio_modulation_param_lora_t mod = {
		.spreading_factor = map_sf(cfg->datarate),
		.bandwidth        = map_bw(cfg->bandwidth),
		.coding_rate      = map_cr(cfg->coding_rate),
		.ppm_offset       = 0,
	};
	LR1110_RETURN_ON_HAL_ERROR(lr1110_radio_set_modulation_param_lora(dev, &mod));

	struct lr1110_data *cfg_data = dev->data;

	cfg_data->pkt_params = (lr1110_radio_packet_param_lora_t){
		.preamble_length_in_symb = cfg->preamble_len,
		.header_type             = LR1110_RADIO_LORA_HEADER_EXPLICIT,
		/* RX uses the max as the accept ceiling; TX overrides this with the
		 * real length in lora_send(). */
		.payload_length_in_byte  = LR1110_MAX_PAYLOAD,
		.crc                     = LR1110_RADIO_LORA_CRC_ON,
		.iq = cfg->iq_inverted ? LR1110_RADIO_LORA_IQ_INVERTED
				       : LR1110_RADIO_LORA_IQ_STANDARD,
	};
	LR1110_RETURN_ON_HAL_ERROR(
		lr1110_radio_set_packet_param_lora(dev, &cfg_data->pkt_params));

	lr1110_radio_pa_config_t pa = {
		.pa_sel        = LR1110_PA_SEL,
		.pa_reg_supply = LR1110_PA_SUPPLY,
		.pa_dutycycle  = LR1110_PA_DC,
		.pa_hp_sel     = LR1110_PA_HP_SEL,
	};
	LR1110_RETURN_ON_HAL_ERROR(lr1110_radio_set_pa_config(dev, &pa));
	LR1110_RETURN_ON_HAL_ERROR(lr1110_radio_set_tx_params(dev, cfg->tx_power,
							      LR1110_RADIO_RAMP_TIME_40U));
	LR1110_RETURN_ON_HAL_ERROR(lr1110_system_set_dio_irq_params(dev, LR1110_IRQ_RADIO, 0));
	LR1110_RETURN_ON_HAL_ERROR(
		lr1110_radio_set_rx_tx_fallback_mode(
			dev, LR1110_RADIO_RX_TX_FALLBACK_MODE_STDBYRC));
	LR1110_RETURN_ON_HAL_ERROR(
		lr1110_radio_set_lora_sync_word(
			dev, cfg->public_network ? LR1110_RADIO_LORA_NETWORK_PUBLIC
						 : LR1110_RADIO_LORA_NETWORK_PRIVATE));

#if DT_INST_NODE_HAS_PROP(0, tx_enable_gpios)
	gpio_pin_set_dt(&lr1110_gpio_tx_enable, cfg->tx ? 1 : 0);
#endif

	/* Clear any IRQ flags the chip set during boot/calibration.
	 *
	 * NOTE: we deliberately DO NOT enable the DIO9 GPIO interrupt. TX and RX
	 * both poll the IRQ status over SPI. Enabling the interrupt lets its
	 * work handler issue SPI transactions concurrently with the polling
	 * loop; that race intermittently wedges an SPI transfer and hangs the
	 * main thread. Pure polling keeps all radio SPI on one thread. */
	lr1110_system_clear_irq(dev, 0xFFFFFFFFu);

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
	if (dev == NULL || data == NULL) {
		return -EINVAL;
	}
	struct lr1110_data *drv = dev->data;

	if (data_len > LR1110_MAX_PAYLOAD) {
		return -EMSGSIZE;
	}

	/* Poll for TXDONE over SPI rather than via the DIO9 interrupt: the LR1110
	 * signals TX/RX errors (CMDERR, ERR) on IRQ bits that are NOT routed to
	 * DIO9, so a failed TX would otherwise never wake a waiting semaphore.
	 * Polling lets us observe the true status and bound the wait. */
	gpio_pin_interrupt_configure_dt(&lr1110_gpio_dio9, GPIO_INT_DISABLE);

	/* STANDBY_XOSC before loading the buffer: the recv() timeout path
	 * parks the chip in STANDBY_RC, where it processes long WriteBuffer8
	 * commands too slowly — payload bytes past ~32 are silently dropped
	 * (the chip still reports TXDONE and transmits stale buffer contents;
	 * bd lora_ipv6_mesh-r002). On XOSC the full payload lands. */
	LR1110_RETURN_ON_HAL_ERROR(
		lr1110_system_set_standby(dev, LR1110_SYSTEM_STDBY_CONFIG_XOSC));

	/* Set the real payload length for this TX (explicit header). Config
	 * leaves it at LR1110_MAX_PAYLOAD for RX; without this the chip would
	 * transmit a full 255-byte packet (real data + buffer garbage). */
	drv->pkt_params.payload_length_in_byte = (uint8_t)data_len;
	LR1110_RETURN_ON_HAL_ERROR(
		lr1110_radio_set_packet_param_lora(dev, &drv->pkt_params));

	/* Load the TX buffer with the opcode and payload in ONE contiguous
	 * SPI buffer. lr1110_regmem_write_buffer8() scatters {opcode, data}
	 * across two spi_bufs, which the nRF SPIM driver executes as separate
	 * DMA sub-transfers — and on this chip only the first ~32 payload
	 * bytes of such a command ever land in the buffer (each retry
	 * restarts at offset 0, so on-air frames carry stale bytes past
	 * offset 32; bd r002). A single uninterrupted transfer carries the
	 * whole command. */
	{
		static uint8_t txcmd[2 + LR1110_MAX_PAYLOAD];

		txcmd[0] = 0x01; /* LR1110_REGMEM_WRITE_BUFFER8_OC >> 8 */
		txcmd[1] = 0x09; /* LR1110_REGMEM_WRITE_BUFFER8_OC & 0xff */
		memcpy(&txcmd[2], data, data_len);
		if (lr1110_hal_write(dev, txcmd, (uint16_t)(2U + data_len),
				     NULL, 0) != LR1110_HAL_STATUS_OK) {
			return lr1110_hal_get_last_error();
		}
	}

	LR1110_RETURN_ON_HAL_ERROR(lr1110_radio_set_tx(dev, 0));

	/* SF10/BW125 airtime for a short frame is well under 1 s. Poll every
	 * 10 ms (up to 3 s) — infrequent enough to keep SPIM traffic light (it
	 * contends with USB EasyDMA), fast enough for prompt TXDONE detection. */
	lr1110_system_stat1_t stat1;
	lr1110_system_stat2_t stat2;
	uint32_t irq = 0;
	for (int i = 0; i < 300; i++) {
		lichen_radio_progress();
		k_sleep(K_MSEC(10));
		lr1110_system_get_status(dev, &stat1, &stat2, &irq);
		if (irq & LR1110_SYSTEM_IRQ_TXDONE_MASK) {
			break;
		}
	}
	lr1110_system_clear_irq(dev, irq);
	int ret = lr1110_hal_get_last_error();
	if (ret < 0) {
		return ret;
	}

	if (irq & LR1110_SYSTEM_IRQ_TXDONE_MASK) {
		return 0;
	}
	LOG_ERR("TX no TXDONE irq=0x%08x", irq);
	return -ETIMEDOUT;
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
	if (dev == NULL || data == NULL || size == 0) {
		return -EINVAL;
	}

	struct lr1110_data *drv = dev->data;

	ARG_UNUSED(drv);

	/* Poll for RXDONE over SPI, mirroring the TX path. The DIO9 interrupt +
	 * work-handler get_status sequence intermittently hard-freezes the CPU
	 * when it runs on a received packet, so we drive RX by polling too. */
	gpio_pin_interrupt_configure_dt(&lr1110_gpio_dio9, GPIO_INT_DISABLE);

	/* Restore the RX accept ceiling: lora_send() rewrites the chip's
	 * packet params with payload_length = the TX frame's length, and in
	 * explicit-header mode that field caps what RX will accept — after a
	 * 9-byte beacon TX the radio silently rejects every longer frame
	 * (total RX deafness; bd r002). */
	if (drv->pkt_params.payload_length_in_byte != LR1110_MAX_PAYLOAD) {
		drv->pkt_params.payload_length_in_byte = LR1110_MAX_PAYLOAD;
		LR1110_RETURN_ON_HAL_ERROR(
			lr1110_radio_set_packet_param_lora(dev, &drv->pkt_params));
	}

	LR1110_RETURN_ON_HAL_ERROR(lr1110_radio_set_rx(dev, LR1110_RX_CONTINUOUS));

	int64_t deadline = k_uptime_get() + k_ticks_to_ms_floor64(timeout.ticks);
	lr1110_system_stat1_t stat1;
	lr1110_system_stat2_t stat2;
	uint32_t irq = 0;
	bool held = false;
	do {
		lichen_radio_progress();
		k_sleep(K_MSEC(20));
		lr1110_system_get_status(dev, &stat1, &stat2, &irq);

		/* A frame is arriving (preamble/sync/header seen): hold the
		 * window open long enough for it to finish instead of
		 * aborting mid-reception. Single bounded extension — the
		 * status bits latch until clear_irq below, so re-checking
		 * would not re-extend anyway. */
		if (!held &&
		    (irq & (LR1110_SYSTEM_IRQ_PREAMBLEDETECTED_MASK |
			    LR1110_SYSTEM_IRQ_SYNCWORD_HEADERVALID_MASK))) {
			int64_t hold_until = k_uptime_get() + LR1110_RX_HOLD_MS;

			if (hold_until > deadline) {
				deadline = hold_until;
			}
			held = true;
		}
	} while (!(irq & (LR1110_SYSTEM_IRQ_RXDONE_MASK |
			  LR1110_SYSTEM_IRQ_TIMEOUT_MASK)) &&
		 k_uptime_get() < deadline);

	lr1110_system_clear_irq(dev, irq);

	if (!(irq & LR1110_SYSTEM_IRQ_RXDONE_MASK)) {
		/* No packet — return the radio to standby (don't leave it in RX),
		 * mirroring upstream's error-path hygiene. */
		LR1110_RETURN_ON_HAL_ERROR(
			lr1110_system_set_standby(dev, LR1110_SYSTEM_STDBY_CONFIG_RC));
		return -EAGAIN;
	}

	lr1110_radio_rxbuffer_status_t buf_status;
	LR1110_RETURN_ON_HAL_ERROR(lr1110_radio_get_rxbuffer_status(dev, &buf_status));

	if (buf_status.rx_payload_length > size) {
		LOG_ERR("recv: packet too large for buffer: %u > %u",
			buf_status.rx_payload_length, size);
		return -EMSGSIZE;
	}

	uint8_t len = buf_status.rx_payload_length;
	LR1110_RETURN_ON_HAL_ERROR(
		lr1110_regmem_read_buffer8(dev, data, buf_status.rx_start_buffer_pointer, len));

	if (rssi || snr) {
		lr1110_radio_packet_status_lora_t pkt_status;
		LR1110_RETURN_ON_HAL_ERROR(lr1110_radio_get_packet_status_lora(dev, &pkt_status));
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
