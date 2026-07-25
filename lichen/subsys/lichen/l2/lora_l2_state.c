/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lora_l2_state.c
 * @brief LICHEN LoRa L2 state machine implementation
 *
 * State machine transitions and validation for the LoRa L2 module.
 */

#include "lora_l2_internal.h"

#include <zephyr/logging/log.h>

LOG_MODULE_DECLARE(lichen_lora_l2, CONFIG_LICHEN_LORA_L2_LOG_LEVEL);

/* --------------------------------------------------------------------------
 * State machine definitions
 * -------------------------------------------------------------------------- */

const char *state_names[] = {
    [LORA_UNINIT]    = "UNINIT",
    [LORA_STOPPED]   = "STOPPED",
    [LORA_RUNNING]   = "RUNNING",
    [LORA_ABORTED]   = "ABORTED",
    [LORA_DEINITING] = "DEINITING",
};

/* Compile-time check: state_names must have exactly LORA_STATE_COUNT entries.
 * Catches mismatch if enum values are added/removed without updating array. */
BUILD_ASSERT(ARRAY_SIZE(state_names) == LORA_STATE_COUNT,
             "state_names array size must match LORA_STATE_COUNT");

/* Valid state transitions: valid_transitions[from][to] = 1 if allowed */
const uint8_t valid_transitions[LORA_STATE_COUNT][LORA_STATE_COUNT] = {
    /*                    UNINIT STOPPED RUNNING ABORTED DEINITING */
    [LORA_UNINIT]    = {  0,     1,      0,      0,      0 },  /* init -> STOPPED */
    [LORA_STOPPED]   = {  0,     0,      1,      0,      1 },  /* start -> RUNNING, deinit -> DEINITING */
    [LORA_RUNNING]   = {  0,     1,      0,      1,      0 },  /* stop -> STOPPED or ABORTED */
    [LORA_ABORTED]   = {  0,     0,      0,      0,      1 },  /* deinit -> DEINITING */
    [LORA_DEINITING] = {  1,     0,      0,      0,      0 },  /* -> UNINIT */
};

/* Current state - atomic for lock-free reads */
atomic_t current_state = ATOMIC_INIT(LORA_UNINIT);

/* --------------------------------------------------------------------------
 * State machine functions
 * -------------------------------------------------------------------------- */

int lora_transition(enum lora_state new_state)
{
    if (new_state >= LORA_STATE_COUNT) {
        LOG_ERR("lora_l2: invalid state (%d), forcing ABORTED", new_state);
        atomic_set(&current_state, LORA_ABORTED);
        return -EINVAL;
    }

    while (1) {
        enum lora_state old_state = atomic_get(&current_state);

        if (!valid_transitions[old_state][new_state]) {
            LOG_ERR("lora_l2: invalid transition %s -> %s, forcing ABORTED",
                    state_names[old_state], state_names[new_state]);
            atomic_set(&current_state, LORA_ABORTED);
            return -EINVAL;
        }

        if (atomic_cas(&current_state, old_state, new_state)) {
            LOG_DBG("lora_l2: state %s -> %s", state_names[old_state], state_names[new_state]);
            return 0;
        }
    }
}

int lora_transition_from(enum lora_state expected, enum lora_state new_state)
{
    /* Validate transition BEFORE attempting CAS to avoid momentarily invalid state */
    if (expected >= LORA_STATE_COUNT || new_state >= LORA_STATE_COUNT) {
        LOG_ERR("lora_l2: invalid state value (expected=%d, new=%d), forcing ABORTED",
                expected, new_state);
        atomic_set(&current_state, LORA_ABORTED);
        return -EINVAL;
    }
    if (!valid_transitions[expected][new_state]) {
        LOG_ERR("lora_l2: invalid transition %s -> %s, forcing ABORTED",
                state_names[expected], state_names[new_state]);
        atomic_set(&current_state, LORA_ABORTED);
        return -EINVAL;
    }

    if (!atomic_cas(&current_state, expected, new_state)) {
        return -EAGAIN;
    }
    LOG_DBG("lora_l2: state %s -> %s", state_names[expected], state_names[new_state]);
    return 0;
}
