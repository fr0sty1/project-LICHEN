/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lora_l2_internal.h
 * @brief Internal shared state for LICHEN LoRa L2 module
 *
 * This header is shared across the split lora_l2_*.c files. It contains
 * state machine definitions, shared mutexes, buffers, and internal functions
 * that are not part of the public API.
 *
 * NOT part of the public API - do not include from outside l2/.
 */

#ifndef LORA_L2_INTERNAL_H_
#define LORA_L2_INTERNAL_H_

#include "lora_l2.h"

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/logging/log.h>

#include <lichen/hal.h>
#include <lichen/tx_queue.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Configuration constants
 * -------------------------------------------------------------------------- */

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

/* --------------------------------------------------------------------------
 * State machine
 * -------------------------------------------------------------------------- */

enum lora_state {
    LORA_UNINIT = 0,   /* Not initialized */
    LORA_STOPPED,      /* Initialized, not running */
    LORA_RUNNING,      /* Initialized and running */
    LORA_ABORTED,      /* Thread was forcibly aborted, needs full reinit */
    LORA_DEINITING,    /* Deinit in progress */
    LORA_STATE_COUNT
};

/* State name strings for logging */
extern const char *state_names[];

/* Valid state transitions: valid_transitions[from][to] = 1 if allowed */
extern const uint8_t valid_transitions[LORA_STATE_COUNT][LORA_STATE_COUNT];

/* Current state - atomic for lock-free reads */
extern atomic_t current_state;

/**
 * @brief Transition to a new state with validation
 *
 * Returns error and forces ABORTED state if the transition is invalid.
 * This catches state machine bugs at runtime.
 *
 * @param new_state Target state
 * @return 0 on success, -EINVAL if transition invalid (state forced to ABORTED)
 */
int lora_transition(enum lora_state new_state);

/**
 * @brief Atomically transition from expected state to new state
 *
 * @param expected Expected current state
 * @param new_state Target state
 * @return 0 on success, -EAGAIN if current state != expected, -EINVAL if transition invalid
 */
int lora_transition_from(enum lora_state expected, enum lora_state new_state);

/**
 * @brief Get current state (lock-free)
 */
static inline enum lora_state lora_get_state(void)
{
    return atomic_get(&current_state);
}

/* --------------------------------------------------------------------------
 * Shared resources
 * -------------------------------------------------------------------------- */

/* RX thread and stack */
extern struct k_thread rx_thread_data;
extern k_thread_stack_t rx_stack[];

/* Mutex protecting state transitions and callback registration */
extern struct k_mutex lora_mutex;

/* Mutex protecting TX buffer access - serializes concurrent transmissions */
extern struct k_mutex tx_buf_mutex;

/* Mutex for modem access - hard mutual exclusion for driver calls */
extern struct k_mutex modem_mutex;

/* TX/RX modem arbitration flag */
extern atomic_t tx_pending;

/* Internal TX buffer */
extern uint8_t tx_buf[LICHEN_LORA_MAX_PHY_PAYLOAD];

/* TX queue for bufferbloat avoidance */
extern struct tx_queue tx_queue;

/*
 * Module data (not state - state is managed by current_state atomic).
 */
struct lora_l2_data {
    const struct device *lora_dev;
    uint8_t eui64[8];
    lichen_lora_rx_cb_t rx_callback;
    void *rx_callback_user_data;
    bool cca_enabled;
    uint8_t rx_channel;
#if IS_ENABLED(CONFIG_LICHEN_DUTY_CYCLE)
    struct lichen_duty_cycle_ctx duty;
    uint8_t density;
#endif
};

extern struct lora_l2_data lora_data;

/**
 * @brief Duty region for the configured operating class (CCP-4 duty_region)
 *
 * @return 0 for strictly duty-cycle-limited regions (EU, AU/NZ),
 *         1 for lenient regions (US/CA)
 */
uint8_t lora_l2_duty_region(void);

/* --------------------------------------------------------------------------
 * Internal functions
 * -------------------------------------------------------------------------- */

/**
 * @brief RX thread entry point
 */
void rx_thread(void *arg1, void *arg2, void *arg3);

/**
 * @brief Generate stable EUI-64 from hardware device ID
 *
 * @param eui64 Output buffer for 8-byte EUI-64
 * @return 0 on success, negative errno on failure
 */
int generate_eui64(uint8_t *eui64);

#ifdef __cplusplus
}
#endif

#endif /* LORA_L2_INTERNAL_H_ */
