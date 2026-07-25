/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lora_l2_rx.c
 * @brief LICHEN LoRa L2 receive thread and callback management
 *
 * Handles continuous packet reception via dedicated RX thread.
 */

#include "lora_l2_internal.h"
#include "crash_info.h"

#include <limits.h>

#include <zephyr/logging/log.h>
#include <zephyr/drivers/lora.h>

LOG_MODULE_DECLARE(lichen_lora_l2, CONFIG_LICHEN_LORA_L2_LOG_LEVEL);

/*
 * Radio-liveness hook. Apps that gate a watchdog feed on radio progress
 * (puck main.c) provide a strong definition; standalone builds fall back to
 * this no-op. Same pattern as lichen/lib/native/native.c.
 */
__attribute__((weak)) void lichen_radio_progress(void)
{
}

/**
 * @brief RX thread - continuously receives LoRa packets
 */
void rx_thread(void *arg1, void *arg2, void *arg3)
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

    /*
     * Capture lora_dev under mutex once at thread startup. This ensures
     * proper synchronization with init() and avoids repeated mutex
     * acquisition in the hot path. The device pointer is immutable after
     * init(), so a single snapshot is sufficient.
     *
     * SAFETY (project-LICHEN-0li1.5): The cached pointer cannot become stale
     * because stop() joins this thread (waits for termination) before returning,
     * and deinit() can only be called after stop() completes (state machine
     * enforces STOPPED->DEINITING transition). The shutdown sequence is:
     *   1. stop() transitions to STOPPED
     *   2. This thread sees STOPPED, exits the loop
     *   3. stop() joins this thread (k_thread_join)
     *   4. stop() returns
     *   5. Only then can deinit() be called
     * Thus deinit() never runs while this thread holds the cached pointer.
     */
    k_mutex_lock(&lora_mutex, K_FOREVER);
    const struct device *dev = lora_data.lora_dev;
    k_mutex_unlock(&lora_mutex);

    LOG_INF("lora_l2: RX thread started");

    /*
     * Loop condition: checking LORA_RUNNING is sufficient because ABORTED
     * can only be set AFTER this thread is terminated. The shutdown sequence
     * in stop() is: (1) transition to STOPPED, (2) join/abort thread,
     * (3) only then transition to ABORTED if abort was needed. So this thread
     * will either exit gracefully when it sees STOPPED, or be forcibly
     * terminated by k_thread_abort() before ABORTED is ever set.
     */
    while (lora_get_state() == LORA_RUNNING) {
        /*
         * Radio-liveness heartbeat: apps gate their watchdog feed on this
         * (see puck main.c). Each loop pass proves the radio path is not
         * wedged; without it, an app main thread legitimately blocked in a
         * long network call (CoAP request, ND resolution) has no other
         * progress source and the watchdog resets the SoC.
         */
        lichen_radio_progress();

        /*
         * Yield the modem to a pending TX. Without this, back-to-back
         * lora_recv() calls hold the modem near-continuously and
         * lichen_lora_l2_tx() can never acquire it (see tx_pending above).
         */
        if (atomic_get(&tx_pending) > 0) {
            k_sleep(K_MSEC(10));
            continue;
        }

        k_mutex_lock(&modem_mutex, K_FOREVER);
        ret = lora_recv(dev, rx_buf, sizeof(rx_buf),
                        K_MSEC(RX_TIMEOUT_MS), &rssi, &snr);
        k_mutex_unlock(&modem_mutex);

        if (ret < 0) {
            if (ret == -EAGAIN) {
                /* Timeout is normal operation, not an error - reset counter */
                consecutive_errors = 0;
                continue;
            }
            if (ret == -EBUSY) {
                /* TX owns the modem (half-duplex). Expected during a send;
                 * yield briefly and re-arm - not a hardware error. */
                consecutive_errors = 0;
                k_sleep(K_MSEC(50));
                continue;
            }
            if (consecutive_errors < INT_MAX) {
                consecutive_errors++;
            } else {
                consecutive_errors = RX_ERROR_WARN_THRESHOLD;
            }
            LOG_ERR("lora_l2: RX error (%d)", ret);
            if (consecutive_errors % RX_ERROR_WARN_THRESHOLD == 0) {
                LOG_WRN("lora_l2: %d consecutive RX errors, check hardware",
                        consecutive_errors);
            }
            /*
             * Backoff on persistent errors to avoid log flooding and CPU starvation.
             *
             * TIMING INTERACTION (project-LICHEN-i1gk.103): This 1000ms sleep is NOT
             * interruptible. If stop() is called while the thread is in this backoff:
             * - stop() uses join timeout: RX_THREAD_QUICK_JOIN_MS (100ms) + RX_TIMEOUT_MS
             * - Default RX_TIMEOUT_MS is 1000ms, so total join timeout is 1100ms
             * - The backoff can last up to 1000ms, which is within the 1100ms budget
             *
             * However, if CONFIG_LICHEN_LORA_L2_RX_TIMEOUT_MS is configured lower than
             * 1000ms (e.g., 100ms for fast response), the join timeout becomes 200ms and
             * this 1000ms backoff will cause forced thread abort. This is acceptable:
             * - Error backoff indicates the radio is misbehaving
             * - Forced abort triggers ABORTED state requiring deinit/init cycle
             * - Recovery from persistent hardware errors requires reinitialization anyway
             *
             * A production system experiencing persistent LoRa errors should address
             * the root cause (hardware fault, interference, misconfiguration) rather
             * than relying on fast stop/start cycling.
             */
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
         * At this point ret > 0 (we checked ret < 0 and ret == 0 above), so cast
         * ret to size_t for a type-safe comparison against sizeof(rx_buf). */
        if ((size_t)ret > sizeof(rx_buf)) {
            /*
             * Driver returned more bytes than buffer size - corruption likely.
             * Store crash info for post-mortem, transition to ABORTED, and
             * exit the RX loop. Watchdog will reset us if we're stuck.
             */
            LOG_ERR("lora_l2: recv overflow (%d > %d)", ret, (int)sizeof(rx_buf));
            /*
             * Best-effort retained telemetry only: crash_info_store() cannot
             * report failure, so recovery must not depend on this write.
             */
            crash_info_store(CRASH_DRIVER_OVERFLOW, __LINE__, (uint32_t)ret);
            atomic_set(&current_state, LORA_ABORTED);
            break;  /* Exit RX loop - let watchdog reset if needed */
        }

        LOG_DBG("lora_l2: RX %d bytes (RSSI %d dBm, SNR %d dB)", ret, rssi, snr);

        /*
         * Invoke callback if registered - snapshot under lock for consistency.
         *
         * LOCK ORDER INVARIANT (project-LICHEN-i1gk.45): lora_mutex is released
         * BEFORE the callback is invoked. The callback (lichen_l2_input) acquires
         * rx_mutex. This ordering is safe because:
         *
         * 1. lora_mutex protects callback registration, not callback execution
         * 2. The callback never calls back into lora_l2.c functions that need
         *    lora_mutex (tx uses tx_buf_mutex only, not lora_mutex)
         * 3. This ensures no lock ordering between lora_mutex and rx_mutex exists
         *
         * CROSS-MODULE INVARIANT: lora_l2_tx() must NOT acquire lora_mutex.
         * If TX ever needs lora_mutex while a callback holds rx_mutex, and that
         * callback's caller needed rx_mutex before acquiring lora_mutex, we'd have
         * ABBA deadlock. Currently tx_buf_mutex is independent, preserving safety.
         * See lichen_lora_l2_tx() which explicitly documents using only tx_buf_mutex.
         */
        k_mutex_lock(&lora_mutex, K_FOREVER);
        lichen_lora_rx_cb_t cb = lora_data.rx_callback;
        void *cb_user_data = lora_data.rx_callback_user_data;
        k_mutex_unlock(&lora_mutex);

        if (cb) {
            /*
             * SECURITY: Callback interruption risk during k_thread_abort().
             *
             * If stop() times out and calls k_thread_abort() while this
             * callback is executing, the callback will be terminated
             * mid-execution. This can leave the callback's resources in an
             * inconsistent state (held locks, partial allocations, etc.).
             *
             * Recovery mechanism: After abort, stop() sets LORA_ABORTED state.
             * Callers must check lichen_lora_l2_needs_reinit() and perform a
             * full deinit()/init() cycle before restart. The callback owner
             * is responsible for detecting the abort (via needs_reinit() or
             * its own timeout/watchdog) and cleaning up any leaked resources.
             *
             * This is a known limitation of thread abort - there is no safe
             * way to interrupt an arbitrary callback. The ABORTED state
             * ensures callers are aware recovery action is required.
             */
            cb(rx_buf, ret, rssi, snr, cb_user_data);
        }
    }

    LOG_INF("lora_l2: RX thread exiting");
}

int lichen_lora_l2_set_rx_callback(lichen_lora_rx_cb_t cb, void *user_data)
{
    enum lora_state state = lora_get_state();

    if (state == LORA_UNINIT) {
        LOG_WRN("lora_l2: cannot set RX callback, not initialized");
        return -ENODEV;
    }
    if (state == LORA_DEINITING) {
        LOG_WRN("lora_l2: cannot set RX callback during deinit");
        return -EBUSY;
    }
    if (state == LORA_ABORTED || lichen_lora_l2_needs_reinit()) {
        LOG_WRN("lora_l2: cannot set RX callback until reinit after abort");
        return -ECANCELED;
    }

    /*
     * Use mutex to ensure atomic update of callback + user_data pair.
     * The RX thread reads both fields, so they must be updated together
     * to avoid invoking a callback with mismatched user_data.
     *
     * Order matters: user_data MUST be set before callback. If the callback
     * pointer is read non-NULL, user_data must already be valid. This order
     * is safe even for lock-free reads (though we use mutex here).
     *
     * Ownership: caller retains ownership of user_data. This module stores
     * the pointer and passes it back on invocation, but never frees it.
     * Callers should clean up their user_data before calling stop() or
     * deinit() if the memory would otherwise be orphaned.
     */
    k_mutex_lock(&lora_mutex, K_FOREVER);
    lora_data.rx_callback_user_data = user_data;
    lora_data.rx_callback = cb;
    k_mutex_unlock(&lora_mutex);

    return 0;
}
