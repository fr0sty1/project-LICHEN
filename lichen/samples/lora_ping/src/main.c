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
#include <zephyr/sys/crc.h>
#include <string.h>

LOG_MODULE_REGISTER(lora_ping, LOG_LEVEL_DBG);

BUILD_ASSERT(DT_NODE_HAS_STATUS(DT_CHOSEN(zephyr_lora), okay),
	     "lora_ping requires an enabled devicetree chosen zephyr,lora");

/* Packet telemetry metrics */
static struct {
	uint32_t tx_count;
	uint32_t rx_count;
	uint32_t tx_bytes;
	uint32_t rx_bytes;
	uint32_t errors;
	uint32_t unique_hashes_seen;
	uint32_t hash_overflows;
	uint32_t seen_hashes[64];
	size_t seen_hash_count;
} metrics;

/* Compute keyed packet hash using b"LICHEN" (0x4c494348454e) as initializer.
 * Prefixes key before CRC32 to match Rust lichen_link::identity::hash_32(),
 * updated tuple_crc in link_ctx.c, and spec 02a-coordinated-capacity.md.
 * Independent oracle from Python zlib.crc32(key + data).
 */
static uint32_t packet_hash(const uint8_t *data, size_t len)
{
	const uint8_t key[] = "LICHEN";
	uint8_t combined[6 + 256]; /* safe upper bound for sample packets */
	memcpy(combined, key, 6);
	if (len > 256) {
		len = 256;
	}
	memcpy(combined + 6, data, len);
	return crc32_ieee(combined, 6 + len);
}

static void track_hash(uint32_t hash)
{
	for (size_t i = 0; i < metrics.seen_hash_count; i++) {
		if (metrics.seen_hashes[i] == hash) {
			return;
		}
	}
	if (metrics.seen_hash_count < ARRAY_SIZE(metrics.seen_hashes)) {
		metrics.seen_hashes[metrics.seen_hash_count++] = hash;
		metrics.unique_hashes_seen++;
	} else {
		metrics.hash_overflows++;
		if (metrics.hash_overflows == 1) {
			LOG_WRN("hash set full, %zu unique tracked", ARRAY_SIZE(metrics.seen_hashes));
		}
	}
}

/* Log metrics summary */
static void log_metrics(void)
{
	LOG_INF("METRICS: tx=%u rx=%u tx_bytes=%u rx_bytes=%u errors=%u unique=%u overflows=%u",
		metrics.tx_count, metrics.rx_count,
		metrics.tx_bytes, metrics.rx_bytes,
		metrics.errors, metrics.unique_hashes_seen, metrics.hash_overflows);
}

/* Parse announce packet to extract peer IID */
static void parse_announce(const uint8_t *data, size_t len)
{
	/* Announce format: dispatch=0x15, type=0x01, iid at offset 5 */
	if (len >= 13 && data[0] == 0x15 && data[1] == 0x01) {
		const uint8_t *peer_iid = &data[5];
		LOG_INF("[RX] announce from %02x%02x%02x%02x%02x%02x%02x%02x",
			peer_iid[0], peer_iid[1], peer_iid[2], peer_iid[3],
			peer_iid[4], peer_iid[5], peer_iid[6], peer_iid[7]);
	}
}

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
	uint32_t hash;

	while (1) {
		/* TX path with telemetry */
		hash = packet_hash(tx_buf, sizeof(tx_buf) - 1);
		LOG_INF("[TX] len=%zu hash=%08x PING #%d",
			sizeof(tx_buf) - 1, hash, ++count);
		LOG_HEXDUMP_DBG(tx_buf, sizeof(tx_buf) - 1, "TX payload");

		ret = lora_send(lora, tx_buf, sizeof(tx_buf) - 1);
		if (ret < 0) {
			LOG_ERR("lora_send failed: %d", ret);
			metrics.errors++;
		} else {
			LOG_INF("TX done");
			metrics.tx_count++;
			metrics.tx_bytes += sizeof(tx_buf) - 1;
			track_hash(hash);
		}

		/* Wait for response */
		config.tx = false;
		ret = lora_config(lora, &config);
		if (ret < 0) {
			LOG_ERR("lora_config (RX) failed: %d", ret);
			metrics.errors++;
			continue;
		}

		ret = lora_recv(lora, rx_buf, sizeof(rx_buf),
				K_SECONDS(5), &rssi, &snr);
		if (ret > 0) {
			/* RX path with telemetry */
			hash = packet_hash(rx_buf, ret);
			LOG_INF("[RX] len=%d rssi=%d snr=%d hash=%08x",
				ret, rssi, snr, hash);
			LOG_HEXDUMP_DBG(rx_buf, ret, "RX payload");

			metrics.rx_count++;
			metrics.rx_bytes += ret;
			track_hash(hash);

			/* Parse announce packets for peer IID */
			parse_announce(rx_buf, ret);
		} else if (ret == -EAGAIN) {
			LOG_INF("RX timeout");
		} else {
			LOG_ERR("lora_recv failed: %d", ret);
			metrics.errors++;
		}

		config.tx = true;
		ret = lora_config(lora, &config);
		if (ret < 0) {
			LOG_ERR("lora_config (TX) failed: %d", ret);
			metrics.errors++;
			continue;
		}

		/* Log metrics every 5 iterations */
		if (count % 5 == 0) {
			log_metrics();
		}

		k_sleep(K_SECONDS(2));
	}

	return 0;
}
