/*
 * LICHEN LoRa driver for Renode LichenSubGHz peripheral.
 *
 * Memory-mapped interface to the C# peripheral which bridges to lichen-sim.
 * For use in Renode simulation of STM32WL firmware.
 *
 * Polling Design Note:
 *   TX uses fixed 1ms polling intervals, RX uses 10ms intervals. These are
 *   simple and sufficient for simulation where timing is not critical.
 *   A production driver on real hardware could use interrupts or k_poll(),
 *   but the Renode peripheral doesn't support GPIO interrupts, so polling
 *   is the appropriate model for this simulation environment.
 *
 * Memory map (base from devicetree, typically 0x58010000):
 *   0x000: TX_LEN (write) - payload length
 *   0x004: TX_TRIGGER (write) - any write triggers TX
 *   0x008: TX_STATUS (read) - 0=idle, 1=busy, 2=done, 3=fail
 *   0x00C: TX_AIRTIME (read) - last TX airtime in us
 *   0x010: RX_STATUS (read) - 0=empty, 1=packet available
 *   0x014: RX_LEN (read) - received payload length
 *   0x018: RX_RSSI (read) - RSSI in dBm (int16)
 *   0x01C: RX_SNR (read) - SNR * 10 (int16)
 *   0x020: RX_CONSUME (write) - consume RX packet
 *   0x024: CONNECT (write) - trigger socket connect to lichen-sim
 *   0x100-0x1FF: TX_BUFFER (256 bytes)
 *   0x200-0x2FF: RX_BUFFER (256 bytes)
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(lora_renode, CONFIG_LORA_LOG_LEVEL);

#define DT_DRV_COMPAT lichen_lora_renode

/* Register offsets */
#define REG_TX_LEN      0x000
#define REG_TX_TRIGGER  0x004
#define REG_TX_STATUS   0x008
#define REG_TX_AIRTIME  0x00C
#define REG_RX_STATUS   0x010
#define REG_RX_LEN      0x014
#define REG_RX_RSSI     0x018
#define REG_RX_SNR      0x01C
#define REG_RX_CONSUME  0x020
#define REG_CONNECT     0x024
#define REG_TX_BUFFER   0x100
#define REG_RX_BUFFER   0x200

/* TX_STATUS values */
#define TX_IDLE  0
#define TX_BUSY  1
#define TX_DONE  2
#define TX_FAIL  3

/* RX_STATUS values */
#define RX_EMPTY    0
#define RX_AVAILABLE 1

struct lora_renode_config {
	volatile uint32_t *base;
};

struct lora_renode_data {
	bool connected;
};

static inline uint32_t reg_read(const struct lora_renode_config *cfg, uint32_t off)
{
	return cfg->base[off / 4];
}

static inline void reg_write(const struct lora_renode_config *cfg, uint32_t off, uint32_t val)
{
	cfg->base[off / 4] = val;
}

static inline void buf_write(const struct lora_renode_config *cfg,
			     uint32_t off, const uint8_t *data, uint32_t len)
{
	volatile uint8_t *dst = (volatile uint8_t *)cfg->base + off;

	for (uint32_t i = 0; i < len; i++) {
		dst[i] = data[i];
	}
}

static inline void buf_read(const struct lora_renode_config *cfg,
			    uint32_t off, uint8_t *data, uint32_t len)
{
	volatile uint8_t *src = (volatile uint8_t *)cfg->base + off;

	for (uint32_t i = 0; i < len; i++) {
		data[i] = src[i];
	}
}

/* --- LoRa API callbacks ------------------------------------------------- */

static int lora_renode_config(const struct device *dev,
			      struct lora_modem_config *config)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(config);
	/* Simulator ignores RF config; the medium model controls propagation. */
	return 0;
}

static int lora_renode_send(const struct device *dev,
			    uint8_t *data, uint32_t data_len)
{
	if (dev == NULL || data == NULL) {
		return -EINVAL;
	}
	const struct lora_renode_config *cfg = dev->config;
	struct lora_renode_data *drv = dev->data;
	if (!drv->connected) {
		LOG_WRN("not connected to lichen-sim");
		return -ENOTCONN;
	}
	if (data_len > 255) {
		return -EMSGSIZE;
	}

	/* Write payload to TX buffer */
	buf_write(cfg, REG_TX_BUFFER, data, data_len);

	/* Set TX length */
	reg_write(cfg, REG_TX_LEN, data_len);

	/* Trigger TX */
	reg_write(cfg, REG_TX_TRIGGER, 1);

	/* Poll for completion.
	 * TX_TIMEOUT_MS covers the longest LoRa airtime: SF12/125kHz with 255B
	 * payload takes ~1.3s. 2 seconds provides margin for simulation overhead.
	 * Timeout indicates a stuck radio.
	 */
	#define TX_TIMEOUT_MS 2000
	uint32_t status;
	int retries = TX_TIMEOUT_MS;

	do {
		status = reg_read(cfg, REG_TX_STATUS);
		if (status == TX_DONE) {
			LOG_DBG("TX done, airtime=%u us, len=%u", reg_read(cfg, REG_TX_AIRTIME), data_len);
			return 0;
		}
		if (status == TX_FAIL) {
			LOG_ERR("TX failed, len=%u", data_len);
			return -EIO;
		}
		k_sleep(K_MSEC(1));
	} while (--retries > 0);

	LOG_ERR("TX timeout");
	return -ETIMEDOUT;
}

static int lora_renode_recv(const struct device *dev,
			    uint8_t *data, uint8_t size,
			    k_timeout_t timeout,
			    int16_t *rssi, int8_t *snr)
{
	const struct lora_renode_config *cfg = dev->config;
	struct lora_renode_data *drv = dev->data;

	if (!drv->connected) {
		return -ENOTCONN;
	}

	bool forever = K_TIMEOUT_EQ(timeout, K_FOREVER);
	uint32_t timeout_ms = forever ? 0 : k_ticks_to_ms_floor32(timeout.ticks);
	uint32_t elapsed = 0;

	/* Poll RX_STATUS until packet or timeout */
	while (forever || elapsed < timeout_ms) {
		uint32_t status = reg_read(cfg, REG_RX_STATUS);

		if (status == RX_AVAILABLE) {
			uint16_t rx_len = (uint16_t)reg_read(cfg, REG_RX_LEN);

			if (rx_len > size) {
				/* Consume the packet to prevent infinite loop,
				 * then return error */
				reg_write(cfg, REG_RX_CONSUME, 1);
				LOG_ERR("recv: packet too large for buffer: %u > %u",
					rx_len, size);
				return -EMSGSIZE;
			}

			buf_read(cfg, REG_RX_BUFFER, data, rx_len);

			if (rssi) {
				*rssi = (int16_t)reg_read(cfg, REG_RX_RSSI);
			}
			if (snr) {
				/* SNR stored as *10, convert to int8 */
				int16_t snr_x10 = (int16_t)reg_read(cfg, REG_RX_SNR);
				*snr = (int8_t)(snr_x10 / 10);
			}

			/* Consume the packet */
			reg_write(cfg, REG_RX_CONSUME, 1);

			LOG_DBG("RX: %u bytes, RSSI=%d, SNR=%d", rx_len,
				rssi ? *rssi : 0, snr ? *snr : 0);
			return rx_len;
		}

		k_sleep(K_MSEC(10));
		elapsed += 10;
	}

	return -EAGAIN; /* Timeout */
}

/* --- device init -------------------------------------------------------- */

static int lora_renode_init(const struct device *dev)
{
	const struct lora_renode_config *cfg = dev->config;
	struct lora_renode_data *data = dev->data;

	/* Trigger connection to lichen-sim */
	reg_write(cfg, REG_CONNECT, 1);

	/* Brief delay for connection */
	k_sleep(K_MSEC(100));

	/* Check if we can read TX_STATUS (any value means peripheral is alive) */
	uint32_t status = reg_read(cfg, REG_TX_STATUS);

	if (status <= TX_FAIL) {
		data->connected = true;
		LOG_INF("initialized, connected to lichen-sim");
		return 0;
	}

	LOG_WRN("peripheral not responding, continuing anyway");
	data->connected = true; /* Try anyway */
	return 0;
}

static int lora_renode_cad(const struct device *dev, k_timeout_t timeout,
			    bool *busy)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(timeout);
	if (busy) *busy = false; /* renode sim assumes clear */
	return 0;
}

static const struct lora_driver_api lora_renode_api = {
	.config = lora_renode_config,
	.send   = lora_renode_send,
	.recv   = lora_renode_recv,
	.cad    = lora_renode_cad,
};

#define LORA_RENODE_DEFINE(inst)					\
	static const struct lora_renode_config lora_renode_config_##inst = { \
		.base = (volatile uint32_t *)DT_INST_REG_ADDR(inst),	\
	};								\
	static struct lora_renode_data lora_renode_data_##inst;		\
	DEVICE_DT_INST_DEFINE(inst, lora_renode_init, NULL,		\
			      &lora_renode_data_##inst,			\
			      &lora_renode_config_##inst,		\
			      POST_KERNEL, CONFIG_LORA_INIT_PRIORITY,	\
			      &lora_renode_api);

DT_INST_FOREACH_STATUS_OKAY(LORA_RENODE_DEFINE)

int sx1302_read_register(uint16_t address, uint8_t *buffer, uint16_t size) {
	return 0;
}
int sx1302_write_register(uint16_t address, const uint8_t *buffer, uint16_t size) {
	return 0;
}
