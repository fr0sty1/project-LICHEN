/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: The contributors to the LICHEN project
 *
 * LoRa loopback driver for native_sim.
 *
 * Simple test driver that loops transmitted packets back to the receiver.
 * No external simulator or hardware required. Uses k_msgq for the internal
 * packet queue.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/logging/log.h>
#include <string.h>

LOG_MODULE_REGISTER(lora_loopback, CONFIG_LORA_LOG_LEVEL);

#define DT_DRV_COMPAT lichen_lora_loopback

/* Maximum LoRa payload size */
#define LORA_MAX_PAYLOAD 255

/* Queue depth for loopback packets */
#define LOOPBACK_QUEUE_DEPTH CONFIG_LORA_LOOPBACK_QUEUE_DEPTH

/* Packet structure for the message queue */
struct loopback_packet {
	uint8_t data[LORA_MAX_PAYLOAD];
	uint8_t len;
};

struct lora_loopback_data {
	struct k_msgq rx_queue;
	char __aligned(4) rx_queue_buf[LOOPBACK_QUEUE_DEPTH * sizeof(struct loopback_packet)];
	struct lora_modem_config config;
	bool configured;
};

static int lora_loopback_config(const struct device *dev,
				struct lora_modem_config *config)
{
	struct lora_loopback_data *data = dev->data;

	if (config == NULL) {
		return -EINVAL;
	}

	memcpy(&data->config, config, sizeof(*config));
	data->configured = true;

	LOG_DBG("configured: freq=%u, sf=%d, bw=%d, tx=%d",
		config->frequency, config->datarate, config->bandwidth, config->tx);

	return 0;
}

static int lora_loopback_send(const struct device *dev,
			      uint8_t *payload, uint32_t payload_len)
{
	struct lora_loopback_data *data = dev->data;
	struct loopback_packet pkt;
	int ret;

	if (payload == NULL || payload_len == 0) {
		return -EINVAL;
	}

	if (payload_len > CONFIG_LORA_LOOPBACK_MTU) {
		LOG_ERR("payload exceeds MTU: %u > %u", payload_len, CONFIG_LORA_LOOPBACK_MTU);
		return -EMSGSIZE;
	}

	memcpy(pkt.data, payload, payload_len);
	pkt.len = (uint8_t)payload_len;

	ret = k_msgq_put(&data->rx_queue, &pkt, K_NO_WAIT);
	if (ret != 0) {
		LOG_WRN("loopback queue full, packet dropped");
		return -ENOBUFS;
	}

	LOG_DBG("sent %u bytes (looped back to rx queue)", payload_len);
	return 0;
}

static int lora_loopback_recv(const struct device *dev,
			      uint8_t *payload, uint8_t size,
			      k_timeout_t timeout,
			      int16_t *rssi, int8_t *snr)
{
	struct lora_loopback_data *data = dev->data;
	struct loopback_packet pkt;
	int ret;

	if (payload == NULL || size == 0) {
		return -EINVAL;
	}

	ret = k_msgq_get(&data->rx_queue, &pkt, timeout);
	if (ret == -EAGAIN || ret == -ENOMSG) {
		return -EAGAIN;
	}
	if (ret != 0) {
		return ret;
	}

	if (pkt.len > size) {
		LOG_ERR("recv: packet too large for buffer: %u > %u", pkt.len, size);
		return -EMSGSIZE;
	}

	memcpy(payload, pkt.data, pkt.len);

	/* Provide simulated RSSI and SNR values */
	if (rssi != NULL) {
		*rssi = CONFIG_LORA_LOOPBACK_RSSI;
	}
	if (snr != NULL) {
		*snr = CONFIG_LORA_LOOPBACK_SNR;
	}

	LOG_DBG("received %u bytes (from loopback queue)", pkt.len);
	return pkt.len;
}

static int lora_loopback_init(const struct device *dev)
{
	struct lora_loopback_data *data = dev->data;

	k_msgq_init(&data->rx_queue, data->rx_queue_buf,
		    sizeof(struct loopback_packet), LOOPBACK_QUEUE_DEPTH);

	data->configured = false;

	LOG_INF("LoRa loopback driver initialized (queue depth=%d)",
		LOOPBACK_QUEUE_DEPTH);

	return 0;
}

static const struct lora_driver_api lora_loopback_api = {
	.config = lora_loopback_config,
	.send   = lora_loopback_send,
	.recv   = lora_loopback_recv,
};

#define LORA_LOOPBACK_DEFINE(inst)					\
	static struct lora_loopback_data lora_loopback_data_##inst;	\
	DEVICE_DT_INST_DEFINE(inst, lora_loopback_init, NULL,		\
			      &lora_loopback_data_##inst, NULL,		\
			      POST_KERNEL, CONFIG_LORA_INIT_PRIORITY,	\
			      &lora_loopback_api);

DT_INST_FOREACH_STATUS_OKAY(LORA_LOOPBACK_DEFINE)
