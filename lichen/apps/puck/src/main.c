/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>

#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(lichen_puck, LOG_LEVEL_INF);

/* LoRa parameters per LICHEN spec: SF10 / 125 kHz / CR4-5 @ 868 MHz (EU). */
#define LORA_FREQ_HZ       868000000U
#define LORA_MAX_FRAME     255
#define BEACON_INTERVAL_MS 60000

/*
 * Minimal LICHEN announce frame — no payload, no addresses, no MIC.
 *   [0] length = 5   (total frame size)
 *   [1] llsec  = 0x00  (AddrMode=0, no sig, no enc)
 *   [2] epoch  = 0
 *   [3] seqhi  = 0
 *   [4] seqlo  = incremented on each TX
 */
static uint8_t s_beacon[5] = { 0x05, 0x00, 0x00, 0x00, 0x00 };
static uint8_t s_seqnum;

static int lora_set_mode(const struct device *dev, bool tx)
{
	struct lora_modem_config cfg = {
		.frequency     = LORA_FREQ_HZ,
		.bandwidth     = BW_125_KHZ,
		.datarate      = SF_10,
		.coding_rate   = CR_4_5,
		.preamble_len  = 8,
		.tx_power      = 14,
		.tx            = tx,
		.public_network = false,
	};
	return lora_config(dev, &cfg);
}

static void send_beacon(const struct device *dev)
{
	s_beacon[4] = ++s_seqnum;

	if (lora_set_mode(dev, true) < 0) {
		LOG_ERR("TX config failed");
		return;
	}
	int ret = lora_send(dev, s_beacon, sizeof(s_beacon));
	if (ret < 0) {
		LOG_ERR("beacon TX failed: %d", ret);
	} else {
		LOG_INF("beacon seq=%u", s_seqnum);
	}
	lora_set_mode(dev, false);
}

int main(void)
{
	LOG_INF("LICHEN puck starting");

	const struct device *lora_dev = DEVICE_DT_GET(DT_NODELABEL(lora0));

	if (!device_is_ready(lora_dev)) {
		LOG_ERR("LoRa radio not ready");
		return -ENODEV;
	}

	if (lora_set_mode(lora_dev, false) < 0) {
		LOG_ERR("LoRa config failed");
		return -EIO;
	}
	LOG_INF("LoRa SF10/125kHz/CR4-5 @ %u Hz", LORA_FREQ_HZ);

	uint8_t buf[LORA_MAX_FRAME];
	int16_t rssi;
	int8_t  snr;
	int64_t last_tx_ms = -(int64_t)BEACON_INTERVAL_MS; /* beacon on first loop */

	while (1) {
		int len = lora_recv(lora_dev, buf, sizeof(buf),
				    K_SECONDS(5), &rssi, &snr);

		if (len > 0) {
			LOG_INF("RX %d B rssi=%d snr=%d [%02x %02x]",
				len, rssi, snr,
				buf[0], len > 1 ? buf[1] : 0u);
		}

		if (k_uptime_get() - last_tx_ms >= BEACON_INTERVAL_MS) {
			send_beacon(lora_dev);
			last_tx_ms = k_uptime_get();
		}
	}
}
