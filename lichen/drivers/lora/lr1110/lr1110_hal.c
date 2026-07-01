/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 The contributors to the LICHEN project
 *
 * Zephyr HAL implementation for the Semtech LR1110.
 *
 * The LR1110 SPI protocol is two-phase for reads:
 *   Write:      CS↓ [opcode+params] [data] CS↑  → wait BUSY↓
 *   Read:       CS↓ [opcode+params]        CS↑  → wait BUSY↓
 *               CS↓ [NOP×(1+N)]            CS↑  → receive [stat, data×N]
 *               (no trailing BUSY wait — chip is ready before data phase)
 *   Sleep:      CS↓ [0x01 0x1B ...]       CS↑  → 1ms (no BUSY — chip sleeps immediately)
 *   Write+Read: CS↓ [cmd×N] simultaneous rx [resp×N] CS↑  (GetStatus only)
 */

#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>
#include <hal/nrf_spim.h>

#include <errno.h>

#include "lr1110_hal.h"

LOG_MODULE_DECLARE(lr1110, CONFIG_LORA_LOG_LEVEL);

/* Provided by lr1110.c — single-instance statics */
extern const struct spi_dt_spec  lr1110_bus;
extern const struct gpio_dt_spec lr1110_gpio_busy;

/* The LR1110 is on spi2 == SPIM2. USB-CDC EasyDMA can contend with the SPIM
 * EasyDMA and wedge a transfer so the blocking SPI API waits forever, hanging
 * the main thread. Do transfers via the async API bounded by a timeout; if a
 * transfer stalls, trigger the SPIM STOP task so the driver's transaction
 * completes and releases the bus, then return an error instead of blocking. */
#define LR1110_SPIM               NRF_SPIM2
#define LR1110_SPI_XFER_TIMEOUT   K_MSEC(50)

/* Application-provided progress hook (weak no-op in lr1110.c). */
extern void lichen_radio_progress(void);

static int lr1110_spi_bounded(const struct spi_buf_set *tx,
			      const struct spi_buf_set *rx)
{
	struct k_poll_signal sig;
	struct k_poll_event evt = K_POLL_EVENT_INITIALIZER(
		K_POLL_TYPE_SIGNAL, K_POLL_MODE_NOTIFY_ONLY, &sig);

	k_poll_signal_init(&sig);

	int ret = spi_transceive_signal(lr1110_bus.bus, &lr1110_bus.config,
					tx, rx, &sig);
	if (ret) {
		return ret;
	}

	if (k_poll(&evt, 1, LR1110_SPI_XFER_TIMEOUT) == -EAGAIN) {
		/* Transfer stalled — abort the SPIM so the driver completes and
		 * releases the bus lock (STOPPED completes the nrfx transaction). */
		LOG_ERR("LR1110 SPI transfer stalled — aborting SPIM");
		nrf_spim_task_trigger(LR1110_SPIM, NRF_SPIM_TASK_STOP);
		(void)k_poll(&evt, 1, K_MSEC(20));
		lichen_radio_progress(); /* we recovered — not a true stall for WDT */
		return -ETIMEDOUT;
	}

	unsigned int signaled;
	int result;

	k_poll_signal_check(&sig, &signaled, &result);
	return signaled ? result : 0;
}
extern const struct gpio_dt_spec lr1110_gpio_reset;

/* LR1110 SetSleep command opcode (puts chip to sleep immediately) */
#define LR1110_CMD_SET_SLEEP_0 0x01
#define LR1110_CMD_SET_SLEEP_1 0x1B

/*
 * LR1110 SPI buffer limits (LR1110 datasheet section 5.2).
 *
 * The radio buffer is 256 bytes. For reads, the two-phase protocol clocks out
 * 1 status byte followed by up to 256 data bytes; we transmit NOPs to generate
 * the clock while receiving. For writes, the largest transfer is a full TX
 * payload (255 bytes per LoRa spec). Command opcodes are at most 2 bytes.
 *
 * Firmware updates require a streaming code path and are not supported here.
 */
#define LR1110_HAL_MAX_READ_DATA  256U
#define LR1110_HAL_MAX_WRITE_DATA 256U
static const uint8_t nop_pad[1U + LR1110_HAL_MAX_READ_DATA];
static atomic_t last_error;

/* Timeout for BUSY pin to go low after command. 1s is generous for any
 * LR1110 operation; if exceeded, hardware is likely faulted.
 */
#define LR1110_BUSY_TIMEOUT_MS 1000

void lr1110_hal_clear_last_error(void)
{
	atomic_set(&last_error, 0);
}

int lr1110_hal_get_last_error(void)
{
	return (int)atomic_get(&last_error);
}

static void record_error(int err)
{
	atomic_set(&last_error, err);
}

static int wait_busy(void)
{
	int timeout = LR1110_BUSY_TIMEOUT_MS;

	while (gpio_pin_get_dt(&lr1110_gpio_busy) > 0 && timeout > 0) {
		k_sleep(K_MSEC(1));
		timeout--;
	}

	if (timeout == 0) {
		LOG_ERR("LR1110 BUSY timeout - hardware fault?");
		record_error(-ETIMEDOUT);
		return -ETIMEDOUT;
	}
	return 0;
}

lr1110_hal_status_t lr1110_hal_write(const void *context,
				     const uint8_t *command,
				     const uint16_t command_length,
				     const uint8_t *data,
				     const uint16_t data_length)
{
	ARG_UNUSED(context);

	if (data_length > LR1110_HAL_MAX_WRITE_DATA) {
		LOG_ERR("Write length %u exceeds max %u", data_length,
			LR1110_HAL_MAX_WRITE_DATA);
		record_error(-EMSGSIZE);
		return LR1110_HAL_STATUS_ERROR;
	}

	struct spi_buf tx_bufs[2] = {
		{ .buf = (void *)command, .len = command_length },
		{ .buf = (void *)data,    .len = data_length    },
	};
	const struct spi_buf_set tx = {
		.buffers = tx_bufs,
		.count   = data_length ? 2U : 1U,
	};

	if (lr1110_spi_bounded(&tx, NULL)) {
		LOG_ERR("SPI write failed");
		record_error(-EIO);
		return LR1110_HAL_STATUS_ERROR;
	}

	/* SetSleep puts the chip to sleep immediately — no BUSY transition */
	if (command_length >= 2 &&
	    command[0] == LR1110_CMD_SET_SLEEP_0 &&
	    command[1] == LR1110_CMD_SET_SLEEP_1) {
		k_busy_wait(1000);
	} else {
		if (wait_busy() < 0) {
			return LR1110_HAL_STATUS_ERROR;
		}
	}
	return LR1110_HAL_STATUS_OK;
}

lr1110_hal_status_t lr1110_hal_read(const void *context,
				    const uint8_t *command,
				    const uint16_t command_length,
				    uint8_t *data,
				    const uint16_t data_length)
{
	ARG_UNUSED(context);

	if (data_length > LR1110_HAL_MAX_READ_DATA) {
		LOG_ERR("Read length %u exceeds max %u", data_length,
			LR1110_HAL_MAX_READ_DATA);
		record_error(-EMSGSIZE);
		return LR1110_HAL_STATUS_ERROR;
	}

	/* Phase 1: send command */
	struct spi_buf cmd_buf = { .buf = (void *)command, .len = command_length };
	const struct spi_buf_set cmd_tx = { .buffers = &cmd_buf, .count = 1 };

	if (lr1110_spi_bounded(&cmd_tx, NULL)) {
		LOG_ERR("SPI cmd write failed");
		record_error(-EIO);
		return LR1110_HAL_STATUS_ERROR;
	}
	if (wait_busy() < 0) {
		return LR1110_HAL_STATUS_ERROR;
	}

	/* Phase 2: send NOPs, receive [stat1 (discarded), data×N] */
	uint8_t stat_byte;
	struct spi_buf tx_buf  = { .buf = (void *)nop_pad, .len = 1U + data_length };
	struct spi_buf rx_bufs[2] = {
		{ .buf = &stat_byte, .len = 1          },
		{ .buf = data,       .len = data_length },
	};
	const struct spi_buf_set rx_tx = { .buffers = &tx_buf,  .count = 1 };
	const struct spi_buf_set rx_rx = { .buffers = rx_bufs,  .count = 2 };

	if (lr1110_spi_bounded(&rx_tx, &rx_rx)) {
		LOG_ERR("SPI read failed");
		record_error(-EIO);
		return LR1110_HAL_STATUS_ERROR;
	}
	return LR1110_HAL_STATUS_OK;
}

lr1110_hal_status_t lr1110_hal_write_read(const void *context,
					  const uint8_t *command,
					  uint8_t *data,
					  const uint16_t data_length)
{
	ARG_UNUSED(context);

	/* Full-duplex — used only by lr1110_system_get_status */
	struct spi_buf tx_buf = { .buf = (void *)command, .len = data_length };
	struct spi_buf rx_buf = { .buf = data,            .len = data_length };
	const struct spi_buf_set tx = { .buffers = &tx_buf, .count = 1 };
	const struct spi_buf_set rx = { .buffers = &rx_buf, .count = 1 };

	if (lr1110_spi_bounded(&tx, &rx)) {
		LOG_ERR("SPI write_read failed");
		record_error(-EIO);
		return LR1110_HAL_STATUS_ERROR;
	}
	return LR1110_HAL_STATUS_OK;
}

void lr1110_hal_reset(const void *context)
{
	ARG_UNUSED(context);

	int ret = gpio_pin_set_dt(&lr1110_gpio_reset, 1);
	if (ret < 0) {
		LOG_ERR("Failed to assert reset GPIO: %d", ret);
		record_error(-EIO);
		return;
	}
	k_busy_wait(1000);

	ret = gpio_pin_set_dt(&lr1110_gpio_reset, 0);
	if (ret < 0) {
		LOG_ERR("Failed to deassert reset GPIO: %d", ret);
		record_error(-EIO);
		return;
	}
	k_busy_wait(1000);
	k_sleep(K_MSEC(200)); /* wait for internal firmware to load */
}

lr1110_hal_status_t lr1110_hal_wakeup(const void *context)
{
	ARG_UNUSED(context);

	/*
	 * CS pulse (no SPI bytes) wakes the LR1110 from sleep.
	 * CS is active-low: assert LOW to wake, then release HIGH.
	 *
	 * gpio_pin_set_dt() interprets values relative to GPIO_ACTIVE_* flags:
	 *   value=1 → logical active (asserted) → LOW for ACTIVE_LOW
	 *   value=0 → logical inactive (deasserted) → HIGH for ACTIVE_LOW
	 */
	int ret = gpio_pin_set_dt(&lr1110_bus.config.cs.gpio, 1);
	if (ret < 0) {
		LOG_ERR("Failed to assert CS GPIO: %d", ret);
		record_error(-EIO);
		return LR1110_HAL_STATUS_ERROR;
	}
	k_busy_wait(100);

	ret = gpio_pin_set_dt(&lr1110_bus.config.cs.gpio, 0);
	if (ret < 0) {
		LOG_ERR("Failed to deassert CS GPIO: %d", ret);
		record_error(-EIO);
		return LR1110_HAL_STATUS_ERROR;
	}
	if (wait_busy() < 0) {
		return LR1110_HAL_STATUS_ERROR;
	}
	return LR1110_HAL_STATUS_OK;
}
