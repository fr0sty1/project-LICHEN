/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lora_l2.c
 * @brief LICHEN LoRa L2 network interface driver implementation
 *
 * This module provides the bridge between Zephyr's IPv6 stack and LoRa radio.
 * It's structured as a service that can be attached to the default interface
 * rather than creating its own network device (which requires more complex
 * devicetree integration).
 *
 * Architecture:
 *   Application calls lichen_lora_l2_start()
 *       -> Configures LoRa radio
 *       -> Starts RX thread
 *       -> TX is called directly via lichen_lora_l2_tx()
 *
 * Threading model:
 * - TX is synchronous (called from application context)
 * - RX runs in dedicated thread, can invoke callbacks for received packets
 */

#include "lora_l2.h"

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/drivers/hwinfo.h>

#include "lichen_util.h"

LOG_MODULE_REGISTER(lichen_lora_l2, CONFIG_LICHEN_LORA_L2_LOG_LEVEL);

/* RX thread configuration */
#define RX_THREAD_STACK_SIZE 2048
#define RX_THREAD_PRIORITY   7
#define RX_TIMEOUT_MS        5000
#define RX_ERROR_WARN_THRESHOLD 5

/* LoRa device - aliased in devicetree */
#define LORA_DEV DEVICE_DT_GET(DT_ALIAS(lora0))

/* RX thread and stack */
static K_THREAD_STACK_DEFINE(rx_stack, RX_THREAD_STACK_SIZE);
static struct k_thread rx_thread_data;

/* Mutex protecting state transitions and callback registration */
static K_MUTEX_DEFINE(lora_mutex);

/* Module state - access running under lora_mutex or use atomic read for polling */
static struct {
    const struct device *lora_dev;
    atomic_t running;
    atomic_t initialized;
    uint8_t eui64[8];
    lichen_lora_rx_cb_t rx_callback;
    void *rx_callback_user_data;
} lora_state;

/**
 * @brief Generate stable EUI-64 from hardware device ID
 *
 * Hashes the full hardware ID using SHA-256 to produce a collision-resistant
 * EUI-64. This avoids issues with MCU-specific hwid layouts:
 * - STM32: 12-byte UID where bytes 0-3 are lot/wafer (shared across chips)
 * - ESP32: 6-byte MAC (would leave 2 bytes unfilled)
 * - nRF52: 8-byte unique ID
 *
 * By hashing the full hwid, we mix all available entropy bits uniformly.
 * Returns error if no stable identity is available - a mesh network node
 * must not start with an unstable EUI-64 that changes on each reboot.
 *
 * Future: derive from Ed25519 public key per spec 6.2.
 *
 * @param eui64 Output buffer for 8-byte EUI-64
 * @return 0 on success, negative errno on failure
 */
static int generate_eui64(uint8_t *eui64)
{
    int ret;
    uint8_t hwid[32];  /* Large enough for all supported MCUs */
    ssize_t hwid_len;
    uint8_t hash[TC_SHA256_DIGEST_SIZE];

    hwid_len = hwinfo_get_device_id(hwid, sizeof(hwid));
    if (hwid_len <= 0) {
        /* SECURITY: Refusing to start without stable identity. A random EUI-64
         * would change on each reboot, breaking IPv6 NDP and mesh routing. */
        LOG_ERR("No hardware ID available - cannot generate stable EUI-64");
        return -ENODEV;
    }
    if ((size_t)hwid_len > sizeof(hwid)) {
        LOG_ERR("hwinfo returned invalid length: %d", (int)hwid_len);
        return -EINVAL;
    }

    /* Hash the full hardware ID to avoid MCU-specific layout issues.
     * SECURITY: SHA-256 provides collision resistance - two different
     * hwids will produce different EUI-64s with overwhelming probability. */
    ret = lichen_sha256(hwid, (size_t)hwid_len, hash);
    if (ret != 0) {
        LOG_ERR("EUI-64: SHA-256 failed");
        goto cleanup;
    }

    /*
     * SECURITY: Using first 64 bits of SHA-256 for EUI-64 derivation.
     * This is safe for identifier derivation (not key material) because:
     * 1. Birthday collision requires 2^32 attempts (4B devices) for 50% collision
     * 2. Preimage resistance remains at 2^64 (sufficient for device identity)
     * 3. Matches RFC 7343 (ORCHID) approach for cryptographic identifiers
     */
    memcpy(eui64, hash, 8);
    LOG_DBG("EUI-64 from hashed hardware ID (%d bytes)", (int)hwid_len);

    /* EUI-64 first octet: bit 0 = multicast, bit 1 = U/L (locally administered) */
    /* Set U/L bit, clear multicast bit */
    eui64[0] = (eui64[0] | 0x02) & 0xFE;

    LOG_DBG("EUI-64: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            eui64[0], eui64[1], eui64[2], eui64[3],
            eui64[4], eui64[5], eui64[6], eui64[7]);

cleanup:
    /* SECURITY: Zero hash on all paths (sha_state zeroed by helper) */
    secure_zero(hash, sizeof(hash));
    return ret;
}

/**
 * @brief RX thread - continuously receives LoRa packets
 */
static void rx_thread(void *arg1, void *arg2, void *arg3)
{
    ARG_UNUSED(arg1);
    ARG_UNUSED(arg2);
    ARG_UNUSED(arg3);

    int ret;
    uint8_t rx_buf[LICHEN_LORA_MAX_PHY_PAYLOAD];
    BUILD_ASSERT(sizeof(rx_buf) == LICHEN_LORA_MAX_PHY_PAYLOAD,
                 "rx_buf must match lora_recv max size");
    int16_t rssi;
    int8_t snr;
    int consecutive_errors = 0;

    LOG_INF("LoRa L2 RX thread started");

    while (atomic_get(&lora_state.running)) {
        ret = lora_recv(lora_state.lora_dev, rx_buf, sizeof(rx_buf),
                        K_MSEC(RX_TIMEOUT_MS), &rssi, &snr);

        if (ret < 0) {
            if (ret == -EAGAIN) {
                consecutive_errors = 0;  /* Timeout is normal, reset counter */
                continue;
            }
            consecutive_errors++;
            LOG_ERR("LoRa RX error: %d", ret);
            if (consecutive_errors > 0 && consecutive_errors % RX_ERROR_WARN_THRESHOLD == 0) {
                LOG_WRN("LoRa RX: %d consecutive errors - check hardware",
                        consecutive_errors);
            }
            /* Backoff on persistent errors to avoid log flooding and CPU starvation */
            k_sleep(K_MSEC(1000));
            continue;
        }
        consecutive_errors = 0;  /* Successful receive, reset counter */

        if (ret == 0) {
            continue;  /* Empty packet */
        }

        /* Sanity check: if driver returned more than buffer size, corruption
         * already occurred. Log and continue - we can't recover but can detect. */
        if (ret > (int)sizeof(rx_buf)) {
            LOG_ERR("CRITICAL: lora_recv returned %d > buffer size %zu - driver bug",
                    ret, sizeof(rx_buf));
            continue;
        }

        LOG_DBG("RX %d bytes, RSSI=%d dBm, SNR=%d dB", ret, rssi, snr);

        /* Invoke callback if registered - snapshot under lock for consistency */
        k_mutex_lock(&lora_mutex, K_FOREVER);
        lichen_lora_rx_cb_t cb = lora_state.rx_callback;
        void *cb_user_data = lora_state.rx_callback_user_data;
        k_mutex_unlock(&lora_mutex);

        if (cb) {
            cb(rx_buf, ret, rssi, snr, cb_user_data);
        }
    }

    LOG_INF("LoRa L2 RX thread exiting");
}

int lichen_lora_l2_init(void)
{
    int ret = 0;

    k_mutex_lock(&lora_mutex, K_FOREVER);

    /* Idempotent: if already initialized, return success immediately.
     * This prevents EUI-64 regeneration on double-init (e.g., from both
     * main.c and NET_DEVICE_INIT calling this function).
     * SECURITY: Check under mutex to prevent TOCTOU race where two threads
     * both pass the check and generate different EUI-64 values. */
    if (atomic_get(&lora_state.initialized)) {
        k_mutex_unlock(&lora_mutex);
        return 0;
    }

    lora_state.lora_dev = LORA_DEV;
    atomic_set(&lora_state.running, 0);
    lora_state.rx_callback = NULL;

    if (!device_is_ready(lora_state.lora_dev)) {
        LOG_ERR("LoRa device not ready");
        ret = -ENODEV;
        goto out;
    }

    ret = generate_eui64(lora_state.eui64);
    if (ret < 0) {
        LOG_ERR("Failed to generate stable EUI-64 - cannot initialize");
        goto out;
    }

    atomic_set(&lora_state.initialized, 1);

    LOG_INF("LICHEN LoRa L2 initialized");

out:
    k_mutex_unlock(&lora_mutex);
    return ret;
}

int lichen_lora_l2_start(void)
{
    /* SECURITY: Check initialization before accessing lora_dev */
    if (!atomic_get(&lora_state.initialized)) {
        LOG_ERR("LoRa L2 not initialized - call lichen_lora_l2_init() first");
        return -EINVAL;
    }

    k_mutex_lock(&lora_mutex, K_FOREVER);

    if (atomic_get(&lora_state.running)) {
        k_mutex_unlock(&lora_mutex);
        return 0;  /* Already running */
    }

    /* Configure LoRa radio using Kconfig options */
    struct lora_modem_config config = {
        .frequency = CONFIG_LICHEN_LORA_FREQUENCY,
        .bandwidth = BW_125_KHZ,
        .datarate = SF_10,
        .coding_rate = CR_4_5,
        .preamble_len = 8,
        .tx_power = CONFIG_LICHEN_LORA_TX_POWER,
        .tx = true,
    };

    int ret = lora_config(lora_state.lora_dev, &config);
    if (ret < 0) {
        LOG_ERR("LoRa config failed: %d", ret);
        k_mutex_unlock(&lora_mutex);
        return ret;
    }

    atomic_set(&lora_state.running, 1);

    /* Start RX thread.
     * k_thread_create() returns the thread pointer passed in (first arg).
     * It cannot fail at runtime - thread/stack resources are sized at build time. */
    k_thread_create(&rx_thread_data, rx_stack,
                    K_THREAD_STACK_SIZEOF(rx_stack),
                    rx_thread, NULL, NULL, NULL,
                    RX_THREAD_PRIORITY, 0, K_NO_WAIT);
    /* Thread naming is best-effort - failure is non-fatal but logged for debugging */
    int name_ret = k_thread_name_set(&rx_thread_data, "lora_rx");
    if (name_ret < 0) {
        LOG_WRN("Failed to set thread name: %d", name_ret);
    }

    k_mutex_unlock(&lora_mutex);

    LOG_INF("LoRa L2 started: SF10, BW125, %uMHz, %ddBm",
            CONFIG_LICHEN_LORA_FREQUENCY / 1000000, CONFIG_LICHEN_LORA_TX_POWER);
    return 0;
}

int lichen_lora_l2_stop(void)
{
    k_mutex_lock(&lora_mutex, K_FOREVER);

    if (!atomic_get(&lora_state.running)) {
        k_mutex_unlock(&lora_mutex);
        return 0;
    }

    /*
     * Clear RX callback BEFORE signaling thread to exit.
     * This prevents new callbacks from starting after we begin shutdown.
     * Any in-flight callback (already past the snapshot in rx_thread) will
     * complete and release rx_mutex before lichen_l2_enable's cleanup runs,
     * since cleanup acquires rx_mutex.
     */
    lora_state.rx_callback = NULL;
    lora_state.rx_callback_user_data = NULL;

    /* Signal RX thread to exit */
    atomic_set(&lora_state.running, 0);

    /* Release mutex before joining - allows any in-flight TX to complete */
    k_mutex_unlock(&lora_mutex);

    /*
     * Wait for RX thread to exit gracefully. Use a short initial timeout for
     * the common case where the thread exits quickly (running flag cleared
     * while not blocked in lora_recv). If that times out, wait up to one
     * full RX timeout cycle. If still stuck, forcibly abort to ensure thread
     * struct is safe to reuse on subsequent start().
     */
    int join_ret = k_thread_join(&rx_thread_data, K_MSEC(100));
    if (join_ret == -EAGAIN) {
        /* Thread still running - may be blocked in lora_recv(), wait longer */
        join_ret = k_thread_join(&rx_thread_data, K_MSEC(RX_TIMEOUT_MS));
        if (join_ret == -EAGAIN) {
            LOG_WRN("RX thread join timed out after %dms, aborting thread. "
                    "Any in-flight packet processing was terminated.",
                    100 + RX_TIMEOUT_MS);
            k_thread_abort(&rx_thread_data);
            k_thread_join(&rx_thread_data, K_FOREVER);
        }
    }

    LOG_INF("LoRa L2 stopped");
    return 0;
}

int lichen_lora_l2_tx(uint8_t *data, size_t len)
{
    if (data == NULL) {
        LOG_ERR("TX data pointer is NULL");
        return -EINVAL;
    }

    if (len > LICHEN_LORA_MAX_PHY_PAYLOAD) {
        LOG_ERR("Packet too large: %zu (max %d)", len, LICHEN_LORA_MAX_PHY_PAYLOAD);
        return -EMSGSIZE;
    }

    /*
     * Check running state atomically without mutex. The lora_send() call
     * below blocks for the entire TX airtime (~500ms at SF10/255 bytes).
     * Holding lora_mutex during this period would starve the RX thread,
     * which needs the mutex to snapshot its callback pointer.
     *
     * This is safe because:
     * - running is atomic_t, read is naturally atomic
     * - lora_send() is thread-safe (Zephyr driver serializes internally)
     * - If stop() races with send(), the driver handles in-flight TX
     */
    if (!atomic_get(&lora_state.running)) {
        LOG_WRN("LoRa L2 not running");
        return -ENETDOWN;
    }

    LOG_DBG("TX %zu bytes", len);

    int ret = lora_send(lora_state.lora_dev, data, len);

    if (ret < 0) {
        LOG_ERR("LoRa TX failed: %d", ret);
        return ret;
    }

    return 0;
}

void lichen_lora_l2_set_rx_callback(lichen_lora_rx_cb_t cb, void *user_data)
{
    /*
     * Use mutex to ensure atomic update of callback + user_data pair.
     * The RX thread reads both fields, so they must be updated together
     * to avoid invoking a callback with mismatched user_data.
     */
    k_mutex_lock(&lora_mutex, K_FOREVER);
    lora_state.rx_callback_user_data = user_data;
    lora_state.rx_callback = cb;
    k_mutex_unlock(&lora_mutex);
}

const uint8_t *lichen_lora_l2_get_eui64(void)
{
    if (!atomic_get(&lora_state.initialized)) {
        LOG_ERR("LoRa L2 not initialized");
        return NULL;
    }
    return lora_state.eui64;
}

bool lichen_lora_l2_is_running(void)
{
    return atomic_get(&lora_state.running) != 0;
}
