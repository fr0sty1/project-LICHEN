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

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/drivers/hwinfo.h>

LOG_MODULE_REGISTER(lichen_lora_l2, CONFIG_LICHEN_LORA_L2_LOG_LEVEL);

/* RX thread configuration */
#define RX_THREAD_STACK_SIZE 2048
#define RX_THREAD_PRIORITY   7
#define RX_TIMEOUT_MS        5000

/* LoRa device - aliased in devicetree */
#define LORA_DEV DEVICE_DT_GET(DT_ALIAS(lora0))

/* RX thread and stack */
static K_THREAD_STACK_DEFINE(rx_stack, RX_THREAD_STACK_SIZE);
static struct k_thread rx_thread_data;

/* Mutex protecting state transitions and TX operations */
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
 * Uses Zephyr hwinfo API to get hardware-unique device ID. Falls back to
 * random if hwinfo unavailable (with warning). Future: derive from Ed25519
 * public key per spec 6.2.
 */
static void generate_eui64(uint8_t *eui64)
{
    uint8_t hwid[16];
    ssize_t hwid_len;

    hwid_len = hwinfo_get_device_id(hwid, sizeof(hwid));
    if (hwid_len >= 8) {
        /* Use first 8 bytes of hardware ID */
        memcpy(eui64, hwid, 8);
        LOG_INF("EUI-64 from hardware ID (%d bytes)", (int)hwid_len);
    } else {
        /* Fallback: random (not stable across reboots) */
        sys_rand_get(eui64, 8);
        LOG_WRN("No hardware ID available, using random EUI-64 (unstable)");
    }

    /* Set locally administered bit (bit 1 of first byte) */
    /* Clear multicast bit (bit 0 of first byte) */
    eui64[0] = (eui64[0] | 0x02) & 0xFE;

    LOG_INF("EUI-64: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            eui64[0], eui64[1], eui64[2], eui64[3],
            eui64[4], eui64[5], eui64[6], eui64[7]);
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
    uint8_t rx_buf[256];
    int16_t rssi;
    int8_t snr;

    LOG_INF("LoRa L2 RX thread started");

    while (atomic_get(&lora_state.running)) {
        ret = lora_recv(lora_state.lora_dev, rx_buf, sizeof(rx_buf),
                        K_MSEC(RX_TIMEOUT_MS), &rssi, &snr);

        if (ret < 0) {
            if (ret == -EAGAIN) {
                continue;  /* Timeout - normal */
            }
            LOG_ERR("LoRa RX error: %d", ret);
            continue;
        }

        if (ret == 0) {
            continue;  /* Empty packet */
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
    lora_state.lora_dev = LORA_DEV;
    atomic_set(&lora_state.running, 0);
    atomic_set(&lora_state.initialized, 0);
    lora_state.rx_callback = NULL;

    if (!device_is_ready(lora_state.lora_dev)) {
        LOG_ERR("LoRa device not ready");
        return -ENODEV;
    }

    generate_eui64(lora_state.eui64);
    atomic_set(&lora_state.initialized, 1);

    LOG_INF("LICHEN LoRa L2 initialized");
    return 0;
}

int lichen_lora_l2_start(void)
{
    k_mutex_lock(&lora_mutex, K_FOREVER);

    if (atomic_get(&lora_state.running)) {
        k_mutex_unlock(&lora_mutex);
        return 0;  /* Already running */
    }

    /* Configure LoRa radio for LICHEN defaults */
    struct lora_modem_config config = {
        .frequency = 915000000,
        .bandwidth = BW_125_KHZ,
        .datarate = SF_10,
        .coding_rate = CR_4_5,
        .preamble_len = 8,
        .tx_power = 22,
        .tx = true,
    };

    int ret = lora_config(lora_state.lora_dev, &config);
    if (ret < 0) {
        LOG_ERR("LoRa config failed: %d", ret);
        k_mutex_unlock(&lora_mutex);
        return ret;
    }

    atomic_set(&lora_state.running, 1);

    /* Start RX thread */
    k_tid_t tid = k_thread_create(&rx_thread_data, rx_stack,
                                  K_THREAD_STACK_SIZEOF(rx_stack),
                                  rx_thread, NULL, NULL, NULL,
                                  RX_THREAD_PRIORITY, 0, K_NO_WAIT);
    if (tid == NULL) {
        atomic_set(&lora_state.running, 0);
        LOG_ERR("Failed to create LoRa RX thread");
        k_mutex_unlock(&lora_mutex);
        return -ENOMEM;
    }
    k_thread_name_set(&rx_thread_data, "lora_rx");

    k_mutex_unlock(&lora_mutex);

    LOG_INF("LoRa L2 started: SF10, BW125, 915MHz");
    return 0;
}

int lichen_lora_l2_stop(void)
{
    k_mutex_lock(&lora_mutex, K_FOREVER);

    if (!atomic_get(&lora_state.running)) {
        k_mutex_unlock(&lora_mutex);
        return 0;
    }

    /* Signal RX thread to exit */
    atomic_set(&lora_state.running, 0);

    /* Release mutex before joining - allows any in-flight TX to complete */
    k_mutex_unlock(&lora_mutex);

    /* Wait for RX thread to exit */
    k_thread_join(&rx_thread_data, K_MSEC(RX_TIMEOUT_MS + 1000));

    LOG_INF("LoRa L2 stopped");
    return 0;
}

int lichen_lora_l2_tx(const uint8_t *data, size_t len)
{
    if (data == NULL) {
        LOG_ERR("TX data pointer is NULL");
        return -EINVAL;
    }

    if (len > 255) {
        LOG_ERR("Packet too large: %zu", len);
        return -EMSGSIZE;
    }

    k_mutex_lock(&lora_mutex, K_FOREVER);

    if (!atomic_get(&lora_state.running)) {
        k_mutex_unlock(&lora_mutex);
        LOG_WRN("LoRa L2 not running");
        return -ENETDOWN;
    }

    LOG_DBG("TX %zu bytes", len);

    /* Copy to local buffer - Zephyr's lora_send takes non-const uint8_t* */
    uint8_t tx_buf[256];
    memcpy(tx_buf, data, len);

    int ret = lora_send(lora_state.lora_dev, tx_buf, len);

    k_mutex_unlock(&lora_mutex);

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
