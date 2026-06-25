/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 The contributors to the LICHEN project
 *
 * Zephyr HAL implementation for the Semtech LR1110.
 *
 * The LR1110 SPI protocol is two-phase for reads:
 *   Write:      CS↓ [opcode+params] [data] CS↑  → wait BUSY↓
 *   Read:       CS↓ [opcode+params]        CS↑  → wait BUSY↓
 *               CS↓ [NOP×(1+N)]            CS↑  → receive [stat, data×N]
 *               → wait BUSY↓
 *   Write+Read: CS↓ [cmd×N] simultaneous rx [resp×N] CS↑  (GetStatus only)
 */

#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "lr1110_hal.h"

LOG_MODULE_DECLARE(lr1110, CONFIG_LORA_LOG_LEVEL);

/* Provided by lr1110.c — single-instance statics */
extern const struct spi_dt_spec  lr1110_bus;
extern const struct gpio_dt_spec lr1110_gpio_busy;
extern const struct gpio_dt_spec lr1110_gpio_reset;

/* Zero-filled NOP pad for the read response phase (max 256 data + 1 stat) */
static const uint8_t nop_pad[257];

static void wait_busy(void)
{
	while (gpio_pin_get_dt(&lr1110_gpio_busy) > 0) {
		k_sleep(K_MSEC(1));
	}
}

lr1110_hal_status_t lr1110_hal_write(const void *context,
				     const uint8_t *command,
				     const uint16_t command_length,
				     const uint8_t *data,
				     const uint16_t data_length)
{
	ARG_UNUSED(context);

	struct spi_buf tx_bufs[2] = {
		{ .buf = (void *)command, .len = command_length },
		{ .buf = (void *)data,    .len = data_length    },
	};
	const struct spi_buf_set tx = {
		.buffers = tx_bufs,
		.count   = data_length ? 2U : 1U,
	};

	if (spi_write_dt(&lr1110_bus, &tx)) {
		LOG_ERR("SPI write failed");
		return LR1110_HAL_STATUS_ERROR;
	}
	wait_busy();
	return LR1110_HAL_STATUS_OK;
}

lr1110_hal_status_t lr1110_hal_read(const void *context,
				    const uint8_t *command,
				    const uint16_t command_length,
				    uint8_t *data,
				    const uint16_t data_length)
{
	ARG_UNUSED(context);

	/* Phase 1: send command */
	struct spi_buf cmd_buf = { .buf = (void *)command, .len = command_length };
	const struct spi_buf_set cmd_tx = { .buffers = &cmd_buf, .count = 1 };

	if (spi_write_dt(&lr1110_bus, &cmd_tx)) {
		LOG_ERR("SPI cmd write failed");
		return LR1110_HAL_STATUS_ERROR;
	}
	wait_busy();

	/* Phase 2: send NOPs, receive [stat1 (discarded), data×N] */
	uint8_t stat_byte;
	struct spi_buf tx_buf  = { .buf = (void *)nop_pad, .len = 1U + data_length };
	struct spi_buf rx_bufs[2] = {
		{ .buf = &stat_byte, .len = 1          },
		{ .buf = data,       .len = data_length },
	};
	const struct spi_buf_set rx_tx = { .buffers = &tx_buf,  .count = 1 };
	const struct spi_buf_set rx_rx = { .buffers = rx_bufs,  .count = 2 };

	if (spi_transceive_dt(&lr1110_bus, &rx_tx, &rx_rx)) {
		LOG_ERR("SPI read failed");
		return LR1110_HAL_STATUS_ERROR;
	}
	wait_busy();
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

	if (spi_transceive_dt(&lr1110_bus, &tx, &rx)) {
		LOG_ERR("SPI write_read failed");
		return LR1110_HAL_STATUS_ERROR;
	}
	return LR1110_HAL_STATUS_OK;
}

void lr1110_hal_reset(const void *context)
{
	ARG_UNUSED(context);
	gpio_pin_set_dt(&lr1110_gpio_reset, 1);
	k_sleep(K_MSEC(10));
	gpio_pin_set_dt(&lr1110_gpio_reset, 0);
	k_sleep(K_MSEC(10));
}

lr1110_hal_status_t lr1110_hal_wakeup(const void *context)
{
	ARG_UNUSED(context);

	/* CS toggle with a dummy byte wakes the chip from sleep */
	uint8_t dummy = 0x00;
	struct spi_buf buf = { .buf = &dummy, .len = 1 };
	const struct spi_buf_set tx = { .buffers = &buf, .count = 1 };

	spi_write_dt(&lr1110_bus, &tx);
	wait_busy();
	return LR1110_HAL_STATUS_OK;
}
