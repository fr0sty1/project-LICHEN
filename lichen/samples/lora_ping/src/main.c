/*
 * Simple LoRa ping test - transmits a packet and waits for response.
 * Used to verify LoRa driver works in Renode + lichen-sim.
 *
 * Note: This sample calls lora_config() on each TX/RX switch for clarity.
 * Production code would use lora_set_mode() which is lighter weight, but
 * the full config call is preferred here because:
 * 1. It exercises the complete driver configuration path
 * 2. It's more explicit about what's being changed
 * 3. Performance is not critical for this test sample
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(lora_ping, LOG_LEVEL_INF);

BUILD_ASSERT(DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_lora), okay),
	     "lora_ping requires an enabled devicetree chosen zephyr,lora");

int main(void)
{
	const struct device *lora = DEVICE_DT_GET(DT_CHOSEN(zephyr_lora));
	struct lora_modem_config config = {
		.frequency = 915000000,
		.bandwidth = BW_125_KHZ,
		.datarate = SF_10,
		.coding_rate = CR_4_5,
		.preamble_len = 8,
		.tx_power = 14,
		.tx = true,
	};
	int ret;

	if (!device_is_ready(lora)) {
		LOG_ERR("LoRa device not ready");
		return -1;
	}

	ret = lora_config(lora, &config);
	if (ret < 0) {
		LOG_ERR("lora_config failed: %d", ret);
		return ret;
	}

	LOG_INF("LoRa configured, starting ping loop");

	uint8_t tx_buf[] = "PING";
	uint8_t rx_buf[64];
	int16_t rssi;
	int8_t snr;
	int count = 0;

	while (1) {
		LOG_INF("TX: PING #%d", ++count);
		ret = lora_send(lora, tx_buf, sizeof(tx_buf) - 1);
		if (ret < 0) {
			LOG_ERR("lora_send failed: %d", ret);
		} else {
			LOG_INF("TX done");
		}

		/* Wait for response */
		config.tx = false;
		ret = lora_config(lora, &config);
		if (ret < 0) {
			LOG_ERR("lora_config (RX) failed: %d", ret);
			continue;
		}

		ret = lora_recv(lora, rx_buf, sizeof(rx_buf),
				K_SECONDS(5), &rssi, &snr);
		if (ret > 0) {
			LOG_INF("RX: %d bytes, RSSI=%d, SNR=%d", ret, rssi, snr);
			LOG_HEXDUMP_INF(rx_buf, ret, "payload");
		} else if (ret == -EAGAIN) {
			LOG_INF("RX timeout");
		} else {
			LOG_ERR("lora_recv failed: %d", ret);
		}

		config.tx = true;
		ret = lora_config(lora, &config);
		if (ret < 0) {
			LOG_ERR("lora_config (TX) failed: %d", ret);
			continue;
		}

		k_sleep(K_SECONDS(2));
	}

	return 0;
}
