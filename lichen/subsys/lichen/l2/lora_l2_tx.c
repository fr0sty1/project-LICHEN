/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lora_l2_tx.c
 * @brief LICHEN LoRa L2 transmit functions
 *
 * Handles packet transmission including CCA, duty cycle, and queue management.
 */

#include "lora_l2_internal.h"
#include "lichen_util.h"

#include <zephyr/logging/log.h>
#include <zephyr/drivers/lora.h>

#include <lichen/op_class.h>

LOG_MODULE_DECLARE(lichen_lora_l2, CONFIG_LICHEN_LORA_L2_LOG_LEVEL);

bool lichen_lora_perform_cca(uint32_t timeout_ms)
{
    if (lora_data.lora_dev == NULL) {
        return false;
    }

    bool busy = false;
    int ret = lora_cad(lora_data.lora_dev, K_MSEC(timeout_ms), &busy);
    if (ret < 0) {
        if (ret != -ENOSYS) {
            LOG_WRN("lora_l2: CCA failed (%d), treating as clear", ret);
        }
        return true;
    }
    return !busy;
}

int lichen_lora_l2_tx(const uint8_t *data, size_t len, uint8_t channel)
{
    if (data == NULL) {
        LOG_ERR("lora_l2: TX data pointer is NULL");
        return -EINVAL;
    }

    if (len == 0) {
        LOG_ERR("lora_l2: TX with zero length");
        return -EINVAL;
    }

    if (len > LICHEN_LORA_MAX_PHY_PAYLOAD) {
        LOG_ERR("lora_l2: packet too large (%zu > %d)", len, LICHEN_LORA_MAX_PHY_PAYLOAD);
        return -EMSGSIZE;
    }

    uint8_t effective_channel = 0;
    if (IS_ENABLED(CONFIG_LICHEN_MULTI_CHANNEL_ENABLED)) {
        if (channel < CONFIG_LICHEN_N_CHANNELS) {
            effective_channel = channel;
        } else {
            static uint8_t next = 1;
            effective_channel = next;
            next = (next % (CONFIG_LICHEN_N_CHANNELS - 1)) + 1;
        }
    }
    lora_data.rx_channel = effective_channel;

    /* Configure data channels via operating class lookup table (CCP-3/CCP-4).
     * CH0 uses the base frequency from the plan; data channels use
     * base + ch * spacing derived from the plan's channel mask.
     * Falls back to Kconfig values when no plan entry matches.
     */
    if (IS_ENABLED(CONFIG_LICHEN_MULTI_CHANNEL_ENABLED) && effective_channel > 0 && lora_data.lora_dev != NULL) {
        uint32_t plan_freq = CONFIG_LICHEN_LORA_FREQUENCY;
        uint32_t plan_bw = BW_125_KHZ;
        uint8_t plan_sf = SF_10;
        uint8_t plan_cr = CR_4_5;
        int8_t plan_power = CONFIG_LICHEN_LORA_TX_POWER;

        const struct lichen_op_class_params *oc = lichen_op_class_lookup(CONFIG_LICHEN_OP_CLASS_ID);
        if (oc != NULL) {
            plan_freq = oc->frequency_hz;
            plan_bw = oc->bandwidth_hz;
            plan_sf = oc->spreading_factor;
            plan_cr = oc->coding_rate;
            plan_power = oc->tx_power_dbm;
        }

        uint32_t ch_freq = plan_freq + (uint32_t)effective_channel * 200000U;
        struct lora_modem_config ch_config = {
            .frequency = ch_freq,
            .bandwidth = plan_bw,
            .datarate = plan_sf,
            .coding_rate = plan_cr,
            .preamble_len = 8,
            .tx_power = plan_power,
            .tx = true,
        };
        int cfg_ret = lora_config(lora_data.lora_dev, &ch_config);
        if (cfg_ret < 0) {
            LOG_WRN("lora_l2: ch%u freq config failed (%d)", effective_channel, cfg_ret);
        }
    }

    /*
     * Check state atomically without mutex. The lora_send() call below blocks
     * for the entire TX airtime (~500ms at SF10/255 bytes). Holding lora_mutex
     * during this period would starve the RX thread, which needs the mutex to
     * snapshot its callback pointer.
     *
     * This is safe because:
     * - State is atomic_t, reads are naturally atomic
     * - lora_send() is thread-safe (Zephyr driver serializes internally)
     * - If stop() races with send(), the driver handles in-flight TX
     *
     * State coverage (project-LICHEN-tvfm.92):
     *   UNINIT    -> -ENODEV (not initialized)
     *   STOPPED   -> -ENETDOWN (check below: state != RUNNING)
     *   RUNNING   -> proceed with TX
     *   ABORTED   -> -ENETDOWN (state != RUNNING; deinit required)
     *   DEINITING -> -ENETDOWN (state != RUNNING; stop() already ran,
     *                          setting running=0 before deinit() begins)
     *
     * DEINITING case is safe: deinit() requires stop() first (state machine
     * only allows STOPPED->DEINITING), and stop() clears RUNNING. Any TX
     * attempt during deinit fails at the state != RUNNING check.
     *
     * TOCTOU analysis (project-LICHEN-i1gk.65): There is a TOCTOU window between
     * the state check here and tx_buf_mutex acquisition below. Re-check state
     * after acquiring tx_buf_mutex so a stop/deinit transition that wins this
     * window prevents a stale TX before airtime is spent.
     */
    enum lora_state state = lora_get_state();
    if (state == LORA_UNINIT) {
        LOG_ERR("lora_l2: not initialized");
        return -ENODEV;
    }
    if (state != LORA_RUNNING) {
        LOG_WRN("lora_l2: not running (state=%s)", state_names[state]);
        return -ENETDOWN;
    }

    LOG_DBG("lora_l2: TX %zu bytes", len);

    /*
     * Serialize TX operations with tx_buf_mutex. This protects the queue
     * and lora_send() sequence from concurrent callers.
     * The mutex is held for the full TX duration (~500ms at SF10/255 bytes),
     * which serializes concurrent transmissions - acceptable since the radio
     * can only transmit one packet at a time anyway.
     *
     * This is separate from lora_mutex because TX blocking would starve RX
     * callback registration if we held lora_mutex here.
     */
    k_mutex_lock(&tx_buf_mutex, K_FOREVER);

    state = lora_get_state();
    if (state != LORA_RUNNING) {
        LOG_WRN("lora_l2: not running after TX lock (state=%s)", state_names[state]);
        k_mutex_unlock(&tx_buf_mutex);
        return -ENETDOWN;
    }

    /*
     * Push packet to TX queue. Uses default deadline based on priority.
     * TX_PRIORITY_BULK is the default for application data.
     * Queue tracks statistics for diagnostics (/status/queues endpoint).
     *
     * Note: Currently operating in synchronous mode - push then immediately
     * pop and send. A future async TX thread could drain the queue
     * asynchronously for better bufferbloat handling under contention.
     */
    int ret = tx_queue_push_default_deadline(&tx_queue, data, (uint16_t)len,
                                              TX_PRIORITY_BULK);
    if (ret < 0) {
        LOG_WRN("lora_l2: TX queue push failed (%d)", ret);
        k_mutex_unlock(&tx_buf_mutex);
        return ret;
    }

    /*
     * Pop packet from queue into tx_buf for transmission.
     * In sync mode this immediately retrieves what we just pushed.
     */
    uint16_t pop_len = sizeof(tx_buf);
    uint32_t latency_ms = 0;
    ret = tx_queue_pop(&tx_queue, tx_buf, &pop_len, &latency_ms);
    if (ret < 0) {
        /* Should not happen in sync mode - queue can't be empty */
        LOG_ERR("lora_l2: TX queue pop failed (%d)", ret);
        k_mutex_unlock(&tx_buf_mutex);
        return ret;
    }
#if IS_ENABLED(CONFIG_LICHEN_DUTY_CYCLE)
    /*
     * CCP-13: the budget ceiling tracks the current density adaptively so
     * the remaining-time check below always evaluates against the policy in
     * force now, not a stale boot-time value.
     */
    lora_data.duty.duty_permille =
        adaptive_duty_permille(lora_data.density, lora_l2_duty_region());
    uint32_t dur = 80U + (uint32_t)pop_len * 6U;
    if (!lichen_duty_cycle_can_transmit(&lora_data.duty, k_uptime_get(), dur)) {
        k_mutex_unlock(&tx_buf_mutex);
        return -EBUSY;
    }
#endif

    /*
     * lora_send() follows the same error semantics as lora_config():
     * returns 0 on success, negative errno on failure. Common errors:
     *   -EBUSY: radio busy (CAD or prior TX in progress)
     *   -EIO: SPI/hardware communication failure
     *   -EINVAL: invalid parameters
     *
     * Cast pop_len (uint16_t) to uint32_t: lora_send() expects uint32_t data_len.
     * This cast is safe because pop_len was bounded by TX_QUEUE_MAX_PACKET_SIZE.
     */
    BUILD_ASSERT(LICHEN_LORA_MAX_PHY_PAYLOAD <= UINT32_MAX,
                 "LoRa max PHY payload no longer fits lora_send() uint32_t length");

    /*
     * Arbitrate with the RX thread (see tx_pending above): raise tx_pending
     * so RX stops re-arming, then retry -EBUSY until the in-flight RX window
     * drains. Bounded by RX_TIMEOUT_MS plus margin so a wedged radio still
     * surfaces -EBUSY to the caller rather than blocking forever.
     */
    atomic_inc(&tx_pending);

    if (k_mutex_lock(&modem_mutex, K_MSEC(RX_TIMEOUT_MS + 1000)) != 0) {
        atomic_dec(&tx_pending);
        secure_zero(tx_buf, sizeof(tx_buf));
        k_mutex_unlock(&tx_buf_mutex);
        return -EBUSY;
    }

    /* CCP-15 CCA: check channel before TX. Mutex held during CAD. */
    if (lora_data.cca_enabled && !lichen_lora_perform_cca(CONFIG_LICHEN_LORA_CCA_TIMEOUT_MS)) {
        LOG_INF("lora_l2: CCA detected busy channel, aborting TX");
        k_mutex_unlock(&modem_mutex);
        atomic_dec(&tx_pending);
        secure_zero(tx_buf, sizeof(tx_buf));
        k_mutex_unlock(&tx_buf_mutex);
        return -EBUSY;
    }

    ret = lora_send(lora_data.lora_dev, tx_buf, (uint32_t)pop_len);
    k_mutex_unlock(&modem_mutex);
#if IS_ENABLED(CONFIG_LICHEN_DUTY_CYCLE)
    if (ret >= 0) lichen_duty_cycle_record_tx(&lora_data.duty, k_uptime_get(), dur);
#endif

    atomic_dec(&tx_pending);

    /*
     * SECURITY: Zero tx_buf after use to prevent leaking previous payload
     * data. While lora_send() only transmits `pop_len` bytes, zeroing provides
     * defense-in-depth against:
     * - Driver bugs that read beyond len
     * - Debug logging that dumps the full buffer
     * - Future code changes that access stale data
     */
    secure_zero(tx_buf, sizeof(tx_buf));

    k_mutex_unlock(&tx_buf_mutex);

    if (ret < 0) {
        LOG_ERR("lora_l2: TX failed (%d)", ret);
        return ret;
    }

    return 0;
}

uint8_t lora_l2_duty_region(void)
{
    const struct lichen_op_class_params *oc =
        lichen_op_class_lookup(CONFIG_LICHEN_OP_CLASS_ID);

    return (oc != NULL) ? oc->duty_region : 0;
}

uint16_t adaptive_duty_permille(uint8_t density, uint8_t region)
{
    if (density > 8) {
        return (region == 0) ? 5 : 10;
    }
    if (density < 3) {
        return (region == 0) ? 20 : 50;
    }
    return (region == 0) ? 10 : 20;
}

void lichen_lora_l2_set_density(uint8_t density)
{
#if IS_ENABLED(CONFIG_LICHEN_DUTY_CYCLE)
    lora_data.density = density;
    lora_data.duty.duty_permille =
        adaptive_duty_permille(density, lora_l2_duty_region());
#else
    ARG_UNUSED(density);
#endif
}

uint16_t lichen_lora_l2_current_duty_permille(void)
{
#if IS_ENABLED(CONFIG_LICHEN_DUTY_CYCLE)
    return lora_data.duty.duty_permille;
#else
    return 0;
#endif
}

int lichen_lora_l2_queue_stats_get(struct tx_queue_stats *stats)
{
    if (stats == NULL) {
        return -EINVAL;
    }

    enum lora_state state = lora_get_state();
    if (state == LORA_UNINIT) {
        return -ENODEV;
    }

    /*
     * tx_queue_stats_get() now acquires internal lock for atomic snapshot.
     * No tx_buf_mutex needed: queue lock serializes with TX path.
     */
    return tx_queue_stats_get(&tx_queue, stats);
}
