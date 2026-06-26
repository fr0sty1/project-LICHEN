/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/kernel.h>
#include <zephyr/pm/device.h>
#include <zephyr/logging/log.h>

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
#include <lichen/native.h>
#endif

LOG_MODULE_REGISTER(lichen_puck, LOG_LEVEL_INF);

/* LoRa parameters per LICHEN spec: SF10 / 125 kHz / CR4-5 @ 868 MHz (EU). */
#define LORA_FREQ_HZ       868000000U
#define LORA_MAX_FRAME     255
#define BEACON_INTERVAL_MS 60000

/* Placeholder IID — in production derive from nRF52840 FICR. */
static const uint8_t s_iid[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

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

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
/* Radio stats forwarded to native protocol */
static struct ln_radio_stats s_radio_stats;

/* Last known GPS fix */
static struct ln_gps_info s_gps;
#endif

/* --------------------------------------------------------------------------
 * GNSS callback (called from GNSS driver context)
 * -------------------------------------------------------------------------- */

#if IS_ENABLED(CONFIG_GNSS) && IS_ENABLED(CONFIG_LICHEN_NATIVE)
#include <zephyr/drivers/gnss.h>

static void on_gnss_data(const struct device *dev, const struct gnss_data *data)
{
	ARG_UNUSED(dev);

	if (data->info.fix_status == GNSS_FIX_STATUS_NO_FIX) {
		s_gps.valid = false;
		return;
	}

	s_gps.lat_udeg  = (int32_t)(data->nav_data.latitude  / 1000); /* nanodeg → microdeg */
	s_gps.lon_udeg  = (int32_t)(data->nav_data.longitude / 1000);
	s_gps.alt_cm    = data->nav_data.altitude / 10;              /* mm → cm */
	s_gps.valid     = true;
}

GNSS_DATA_CALLBACK_DEFINE(DEVICE_DT_GET(DT_ALIAS(gnss0)), on_gnss_data);
#endif

/* --------------------------------------------------------------------------
 * LICHEN Native incoming message handler
 * -------------------------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
static void on_native_rx(uint8_t msg_type, const uint8_t *buf, size_t len)
{
	/*
	 * lichen_native_handle_rx handles hello and log_subscribe internally.
	 * send_message (0x20) → transmit on LoRa.
	 */
	if (msg_type == LN_TYPE_SEND_MESSAGE) {
		/* Minimal: ignore routing, blast the payload over LoRa.
		 * Full implementation would parse dest IID and route. */
		LOG_DBG("host send_message — LoRa TX not yet implemented");
	} else {
		lichen_native_handle_rx(msg_type, buf, len);
	}
}
#endif

/* --------------------------------------------------------------------------
 * LoRa helpers
 * -------------------------------------------------------------------------- */

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
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
		s_radio_stats.tx_pkts++;
#endif
	}
	lora_set_mode(dev, false);
}

/* --------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------- */

int main(void)
{
	LOG_INF("LICHEN puck starting");

	/* LoRa radio */
	const struct device *lora_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_lora));
	if (!device_is_ready(lora_dev)) {
		LOG_ERR("LoRa radio not ready");
		return -ENODEV;
	}
	if (lora_set_mode(lora_dev, false) < 0) {
		LOG_ERR("LoRa config failed");
		return -EIO;
	}
	LOG_INF("LoRa SF10/125kHz/CR4-5 @ %u Hz", LORA_FREQ_HZ);

	/* GNSS power-on (PM_DEVICE start) */
#if IS_ENABLED(CONFIG_GNSS_AG3335)
	const struct device *gnss_dev = DEVICE_DT_GET(DT_ALIAS(gnss0));
	if (device_is_ready(gnss_dev)) {
		pm_device_action_run(gnss_dev, PM_DEVICE_ACTION_RESUME);
	}
#endif

	/* LICHEN Native over USB CDC-ACM */
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
	if (lichen_native_init(on_native_rx) == 0) {
		LOG_INF("LICHEN Native ready");
		lichen_native_send_hello();
	}
#endif

	/* Main loop: RX with 5s timeout, beacon every 60s. */
	uint8_t buf[LORA_MAX_FRAME];
	int16_t rssi;
	int8_t  snr;
	int64_t last_tx_ms  = -(int64_t)BEACON_INTERVAL_MS;
	int64_t last_info_ms = 0;

	while (1) {
		int len = lora_recv(lora_dev, buf, sizeof(buf),
				    K_SECONDS(5), &rssi, &snr);

		if (len > 0) {
			LOG_INF("RX %d B rssi=%d snr=%d [%02x %02x]",
				len, rssi, snr,
				buf[0], len > 1 ? buf[1] : 0u);
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
			s_radio_stats.rx_pkts++;
			/* Forward to connected host.
			 * src_iid is unknown at this layer — send zeros. */
			static const uint8_t unknown_iid[8];
			lichen_native_send_message_received(unknown_iid,
							    buf, len,
							    rssi, snr);
#endif
		}

		int64_t now = k_uptime_get();

		if (now - last_tx_ms >= BEACON_INTERVAL_MS) {
			send_beacon(lora_dev);
			last_tx_ms = now;
		}

		/* Send node_info every 60s */
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
		if (now - last_info_ms >= 60000) {
			lichen_native_send_node_info(
				"t1000-puck",
				"lichen-fw-0.1.0",
				"t1000_e",
				(uint64_t)now,
				s_iid,
				s_gps.valid ? &s_gps : NULL,
				&s_radio_stats);
			last_info_ms = now;
		}
#endif
	}
}
