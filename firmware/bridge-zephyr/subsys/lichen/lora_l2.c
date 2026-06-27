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

/* RX thread configuration - use Kconfig values */
#define RX_THREAD_STACK_SIZE CONFIG_LICHEN_LORA_L2_RX_STACK_SIZE
#define RX_THREAD_PRIORITY   CONFIG_LICHEN_LORA_L2_RX_PRIORITY
#define RX_TIMEOUT_MS        CONFIG_LICHEN_LORA_L2_RX_TIMEOUT_MS
#define RX_ERROR_WARN_THRESHOLD 5

/* Join timeout for RX thread when not blocked in lora_recv() */
#define RX_THREAD_QUICK_JOIN_MS 100

/*
 * Join timeout for deinit() best-effort recovery.
 * Short timeout because: if stop() completed normally, thread is already dead
 * (instant return); if truly stuck, waiting longer won't help. 10ms is enough
 * for kernel to finalize thread termination.
 */
#define DEINIT_JOIN_TIMEOUT_MS 10

/* LoRa device - aliased in devicetree */
BUILD_ASSERT(DT_NODE_EXISTS(DT_ALIAS(lora0)),
             "LoRa device alias 'lora0' not defined in devicetree. "
             "Add 'aliases { lora0 = &your_lora_node; };' to your board's .dts file.");
#define LORA_DEV DEVICE_DT_GET(DT_ALIAS(lora0))

/* RX thread and stack */
static K_THREAD_STACK_DEFINE(rx_stack, RX_THREAD_STACK_SIZE);
static struct k_thread rx_thread_data;

/* Mutex protecting state transitions and callback registration */
static K_MUTEX_DEFINE(lora_mutex);

/* Mutex protecting TX buffer access - serializes concurrent transmissions.
 * Separate from lora_mutex because TX may block for ~500ms at SF10/255 bytes;
 * holding lora_mutex that long would starve RX callback registration. */
static K_MUTEX_DEFINE(tx_buf_mutex);

/*
 * Internal TX buffer - copied before lora_send() to protect caller's data.
 * Zephyr's lora_send() takes a non-const pointer because some radio drivers
 * may modify the buffer (e.g., for DMA alignment or in-place encryption).
 */
static uint8_t tx_buf[LICHEN_LORA_MAX_PHY_PAYLOAD];

/*
 * Module state.
 *
 * Access patterns:
 *   - Atomic fields (running, initialized, aborted): Read without mutex for
 *     fast-path checks (e.g., TX hot path). Write under lora_mutex for state
 *     transitions. atomic_t prevents torn reads under aggressive optimization.
 *   - Mutex-protected fields (lora_dev, eui64, rx_callback, rx_callback_user_data):
 *     Must hold lora_mutex for both read and write. Callers read callback pair
 *     atomically via snapshot under lock (see rx_thread).
 */
static struct {
    /* Mutex-protected: device pointer set once during init */
    const struct device *lora_dev;
    /* Atomic: fast-path status checks without mutex */
    atomic_t running;
    atomic_t initialized;
    atomic_t aborted;  /* Set when k_thread_abort() was used; requires re-init */
    /* Mutex-protected: stable after init; alias returned by get_eui64() */
    uint8_t eui64[8];
    /* Mutex-protected: callback + user_data updated as a pair */
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
    /* hwid_len is ssize_t; cast to int is safe since hwinfo_get_device_id()
     * returns at most sizeof(hwid) (32 bytes), well within int range. */
    LOG_DBG("EUI-64 from hashed hardware ID (%d bytes)", (int)hwid_len);

    /* EUI-64 first octet: bit 0 = multicast, bit 1 = U/L (locally administered) */
    /* Set U/L bit, clear multicast bit */
    eui64[0] = (eui64[0] | 0x02) & 0xFE;

    LOG_DBG("EUI-64: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            eui64[0], eui64[1], eui64[2], eui64[3],
            eui64[4], eui64[5], eui64[6], eui64[7]);

cleanup:
    /* SECURITY: Zero intermediate buffers on all paths (sha_state zeroed by helper) */
    secure_zero(hwid, sizeof(hwid));
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
    /*
     * rx_buf sized to LICHEN_LORA_MAX_PHY_PAYLOAD (255 bytes) - the maximum
     * that lora_recv() can return. The callback receives (data, len) where
     * len is bounded by this buffer size. Callers implementing the callback
     * must be prepared to handle up to LICHEN_LORA_MAX_PHY_PAYLOAD bytes.
     */
    uint8_t rx_buf[LICHEN_LORA_MAX_PHY_PAYLOAD];
    BUILD_ASSERT(sizeof(rx_buf) == LICHEN_LORA_MAX_PHY_PAYLOAD,
                 "rx_buf size must equal LICHEN_LORA_MAX_PHY_PAYLOAD for "
                 "callback buffer sizing guarantees");
    int16_t rssi;
    int8_t snr;
    int consecutive_errors = 0;

    LOG_INF("LoRa L2 RX thread started");

    while (atomic_get(&lora_state.running)) {
        ret = lora_recv(lora_state.lora_dev, rx_buf, sizeof(rx_buf),
                        K_MSEC(RX_TIMEOUT_MS), &rssi, &snr);

        if (ret < 0) {
            if (ret == -EAGAIN) {
                /* Timeout is normal operation, not an error - reset counter */
                consecutive_errors = 0;
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

        /* Non-negative return means radio responded successfully - reset error counter.
         * This includes both ret==0 (empty packet) and ret>0 (data received). */
        consecutive_errors = 0;

        if (ret == 0) {
            continue;  /* Empty packet */
        }

        /*
         * SECURITY: If driver returned more than buffer size, stack corruption
         * has ALREADY occurred. rx_buf is stack-allocated, so out-of-bounds
         * writes may have corrupted the return address, saved registers, or
         * other stack frames. There is no safe recovery from this state.
         *
         * We panic rather than continue because:
         * 1. Corruption already happened - the damage is done
         * 2. Continuing risks exploiting the corrupted state
         * 3. A restart gives the system a clean slate
         * 4. This is a driver bug that needs immediate attention, not silent handling
         */
        /* lora_recv() returns int: negative errno on error, byte count on success.
         * sizeof(rx_buf) is size_t. Cast sizeof to int for comparison since
         * LICHEN_LORA_MAX_PHY_PAYLOAD (255) fits safely in int. */
        if (ret > (int)sizeof(rx_buf)) {
            LOG_ERR("CRITICAL: lora_recv returned %d > buffer size %d - "
                    "stack corruption likely, aborting",
                    ret, (int)sizeof(rx_buf));
            k_panic();
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
    atomic_set(&lora_state.aborted, 0);
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

    /*
     * Check aborted flag BEFORE acquiring mutex. If k_thread_abort() was used
     * during a previous stop(), the RX thread may have been terminated while
     * holding lora_mutex or while inside a callback that holds other resources.
     * The module is in an undefined state and requires full re-initialization.
     */
    if (atomic_get(&lora_state.aborted)) {
        LOG_ERR("LoRa L2 in undefined state after forced abort - "
                "call lichen_lora_l2_deinit() then lichen_lora_l2_init()");
        return -ECANCELED;
    }

    k_mutex_lock(&lora_mutex, K_FOREVER);

    if (atomic_get(&lora_state.running)) {
        k_mutex_unlock(&lora_mutex);
        return 0;  /* Already running */
    }

    /*
     * Configure LoRa radio using Kconfig options and LICHEN protocol defaults.
     * Modulation parameters (from <zephyr/drivers/lora.h> enums):
     *   - BW_125_KHZ: 125kHz bandwidth (good range/throughput balance)
     *   - SF_10: Spreading factor 10 (long range, ~980 bps at BW125)
     *   - CR_4_5: Coding rate 4/5 (minimal FEC overhead)
     * These match the LICHEN spec for mesh operation. Preamble length 8
     * is the LoRa default (sufficient for synchronization at SF10).
     */
    struct lora_modem_config config = {
        .frequency = CONFIG_LICHEN_LORA_FREQUENCY,
        .bandwidth = BW_125_KHZ,   /* Zephyr enum: 125kHz */
        .datarate = SF_10,         /* Zephyr enum: spreading factor 10 */
        .coding_rate = CR_4_5,     /* Zephyr enum: 4/5 coding rate */
        .preamble_len = 8,         /* LoRa default preamble symbols */
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
     * Wait for RX thread to exit gracefully. Use a short initial timeout
     * (RX_THREAD_QUICK_JOIN_MS) for the common case where the thread exits
     * quickly (running flag cleared while not blocked in lora_recv). This is
     * ample time for a thread that checked running between lora_recv() calls;
     * if still blocked, it's inside lora_recv() and needs up to RX_TIMEOUT_MS
     * to return. If that times out, wait up to one full RX timeout cycle.
     * If still stuck, forcibly abort to ensure thread struct is safe to reuse
     * on subsequent start().
     */
    int join_ret = k_thread_join(&rx_thread_data, K_MSEC(RX_THREAD_QUICK_JOIN_MS));
    if (join_ret == -EAGAIN) {
        /* Thread still running - may be blocked in lora_recv(), wait longer */
        join_ret = k_thread_join(&rx_thread_data, K_MSEC(RX_TIMEOUT_MS));
        if (join_ret == -EAGAIN) {
            LOG_WRN("RX thread join timed out after %dms, aborting thread. "
                    "Any in-flight packet processing was terminated.",
                    RX_THREAD_QUICK_JOIN_MS + RX_TIMEOUT_MS);
            k_thread_abort(&rx_thread_data);
            k_thread_join(&rx_thread_data, K_FOREVER);
            /*
             * Mark module as requiring re-initialization. k_thread_abort()
             * may have terminated the thread while it held lora_mutex or
             * while inside a callback. The callback may hold its own locks
             * or have allocated resources that are now leaked. Safe restart
             * requires full de-init/re-init cycle.
             */
            atomic_set(&lora_state.aborted, 1);
            LOG_WRN("Module requires lichen_lora_l2_deinit() before restart");
        }
    }

    LOG_INF("LoRa L2 stopped");
    return 0;
}

int lichen_lora_l2_deinit(void)
{
    /*
     * Check running state first without mutex - if still running, reject.
     * This avoids acquiring lora_mutex when we know we'll fail anyway.
     */
    if (atomic_get(&lora_state.running)) {
        LOG_ERR("LoRa L2 still running - call lichen_lora_l2_stop() first");
        return -EBUSY;
    }

    /*
     * Best-effort recovery: ensure the RX thread is actually terminated before
     * touching the mutex. In normal operation, stop() already joined the thread.
     * However, if called after a hardware fault or forced abort where the thread
     * is in an unexpected state, this join provides a final safety check.
     *
     * If the join times out, we proceed anyway - this is best-effort recovery
     * and the alternative (refusing to deinit) leaves the system in a worse state.
     */
    int join_ret = k_thread_join(&rx_thread_data, K_MSEC(DEINIT_JOIN_TIMEOUT_MS));
    if (join_ret == -EAGAIN) {
        LOG_WRN("RX thread join timed out in deinit - proceeding with "
                "best-effort recovery (thread may still be terminating)");
    }

    /*
     * Note: We do NOT acquire lora_mutex here. If we got into the aborted
     * state, the mutex may be left locked by the aborted thread. Attempting
     * to lock it would deadlock. Instead, we reinitialize it.
     *
     * This is best-effort recovery. In the rare case where the thread is in
     * an undefined state that the join above didn't resolve, reinitializing
     * the mutex may have undefined behavior. However:
     * - The join above should catch most cases
     * - Refusing to recover leaves the module permanently unusable
     * - The system is already in a degraded state if we reached this path
     */

    /* Clear initialized flag first - this blocks any concurrent operations */
    atomic_set(&lora_state.initialized, 0);

    /* Clear aborted flag - module is now in clean uninitialized state */
    atomic_set(&lora_state.aborted, 0);

    /* Clear state - defensive, init will overwrite anyway */
    lora_state.rx_callback = NULL;
    lora_state.rx_callback_user_data = NULL;

    /*
     * SECURITY: Reinitializing a mutex that may still be held by a dead
     * thread is UNDEFINED BEHAVIOR per POSIX and Zephyr semantics. If the
     * RX thread was aborted while holding lora_mutex, the mutex's internal
     * state (owner, lock count, wait queue) is corrupted. Calling
     * k_mutex_init() on such a mutex may:
     * - Appear to succeed but leave internal state inconsistent
     * - Cause subsequent lock/unlock operations to corrupt kernel data
     * - Trigger assertion failures in debug builds
     *
     * We proceed anyway because:
     * 1. The alternative (refusing to deinit) leaves the module permanently
     *    unusable until full system reset
     * 2. In practice, most abort scenarios terminate the thread outside the
     *    critical section (the mutex is held only briefly for callback
     *    pointer snapshots)
     * 3. The aborted flag forces a full deinit/init cycle, which resets all
     *    module state including this mutex
     *
     * The ONLY truly safe recovery from a thread-abort scenario is a full
     * system reset (k_sys_reboot). Applications requiring guaranteed
     * correctness after RX thread abort should reboot rather than attempt
     * module restart via deinit/init.
     *
     * K_MUTEX_DEFINE created it statically, so we use k_mutex_init to reset.
     *
     * Note: k_mutex_init() returns int but cannot fail in Zephyr kernel mode
     * (it only initializes fields and the wait queue). The return value check
     * is defensive against future Zephyr API changes or userspace builds.
     */
    int mutex_ret = k_mutex_init(&lora_mutex);
    if (mutex_ret != 0) {
        /* k_mutex_init() should not fail in kernel mode, but log if it does.
         * There is no recovery action - we've already committed to resetting
         * the module and proceeding is better than leaving it unusable. */
        LOG_ERR("k_mutex_init failed: %d - module may be unstable", mutex_ret);
    }

    LOG_INF("LoRa L2 deinitialized");
    return 0;
}

int lichen_lora_l2_tx(const uint8_t *data, size_t len)
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
     * Check initialized and running state atomically without mutex. The
     * lora_send() call below blocks for the entire TX airtime (~500ms at
     * SF10/255 bytes). Holding lora_mutex during this period would starve
     * the RX thread, which needs the mutex to snapshot its callback pointer.
     *
     * This is safe because:
     * - initialized/running are atomic_t, reads are naturally atomic
     * - lora_send() is thread-safe (Zephyr driver serializes internally)
     * - If stop() races with send(), the driver handles in-flight TX
     *
     * The initialized check is defense-in-depth: start() already enforces
     * that running implies initialized, but checking both protects against
     * future refactors that might break that invariant.
     */
    if (!atomic_get(&lora_state.initialized)) {
        LOG_ERR("LoRa L2 not initialized");
        return -ENODEV;
    }

    if (!atomic_get(&lora_state.running)) {
        LOG_WRN("LoRa L2 not running");
        return -ENETDOWN;
    }

    LOG_DBG("TX %zu bytes", len);

    /*
     * Serialize TX operations with tx_buf_mutex. This protects the memcpy
     * and lora_send() sequence from concurrent callers corrupting tx_buf.
     * The mutex is held for the full TX duration (~500ms at SF10/255 bytes),
     * which serializes concurrent transmissions - acceptable since the radio
     * can only transmit one packet at a time anyway.
     *
     * This is separate from lora_mutex because TX blocking would starve RX
     * callback registration if we held lora_mutex here.
     */
    k_mutex_lock(&tx_buf_mutex, K_FOREVER);

    /*
     * Copy into internal buffer before lora_send(). Zephyr's lora_send()
     * takes a non-const pointer because some radio drivers may modify the
     * buffer. Copying protects the caller's data.
     */
    memcpy(tx_buf, data, len);

    /*
     * lora_send() follows the same error semantics as lora_config():
     * returns 0 on success, negative errno on failure. Common errors:
     *   -EBUSY: radio busy (CAD or prior TX in progress)
     *   -EIO: SPI/hardware communication failure
     *   -EINVAL: invalid parameters
     */
    int ret = lora_send(lora_state.lora_dev, tx_buf, len);

    k_mutex_unlock(&tx_buf_mutex);

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

bool lichen_lora_l2_needs_reinit(void)
{
    return atomic_get(&lora_state.aborted) != 0;
}
