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
#include "lichen_l2.h"
#include "crash_info.h"

#include <limits.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/drivers/hwinfo.h>

#include "lichen_util.h"

LOG_MODULE_REGISTER(lichen_lora_l2, CONFIG_LICHEN_LORA_L2_LOG_LEVEL);

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

static const char *state_names[] = {
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
static const uint8_t valid_transitions[LORA_STATE_COUNT][LORA_STATE_COUNT] = {
    /*                    UNINIT STOPPED RUNNING ABORTED DEINITING */
    [LORA_UNINIT]    = {  0,     1,      0,      0,      0 },  /* init -> STOPPED */
    [LORA_STOPPED]   = {  0,     0,      1,      0,      1 },  /* start -> RUNNING, deinit -> DEINITING */
    [LORA_RUNNING]   = {  0,     1,      0,      1,      0 },  /* stop -> STOPPED or ABORTED */
    [LORA_ABORTED]   = {  0,     0,      0,      0,      1 },  /* deinit -> DEINITING */
    [LORA_DEINITING] = {  1,     0,      0,      0,      0 },  /* -> UNINIT */
};

static atomic_t current_state = ATOMIC_INIT(LORA_UNINIT);

/**
 * @brief Transition to a new state with validation
 *
 * Returns error and forces ABORTED state if the transition is invalid.
 * This catches state machine bugs at runtime.
 *
 * @param new_state Target state
 * @return 0 on success, -EINVAL if transition invalid (state forced to ABORTED)
 */
static int lora_transition(enum lora_state new_state)
{
    enum lora_state old_state = atomic_get(&current_state);

    if (new_state >= LORA_STATE_COUNT) {
        LOG_ERR("lora_l2: invalid state (%d), forcing ABORTED", new_state);
        atomic_set(&current_state, LORA_ABORTED);
        return -EINVAL;
    }

    if (!valid_transitions[old_state][new_state]) {
        LOG_ERR("lora_l2: invalid transition %s -> %s, forcing ABORTED",
                state_names[old_state], state_names[new_state]);
        atomic_set(&current_state, LORA_ABORTED);
        return -EINVAL;
    }

    atomic_set(&current_state, new_state);
    LOG_DBG("lora_l2: state %s -> %s", state_names[old_state], state_names[new_state]);
    return 0;
}

/**
 * @brief Atomically transition from expected state to new state
 *
 * @param expected Expected current state
 * @param new_state Target state
 * @return 0 on success, -EAGAIN if current state != expected, -EINVAL if transition invalid
 */
static int lora_transition_from(enum lora_state expected, enum lora_state new_state)
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

static inline enum lora_state lora_get_state(void)
{
    return atomic_get(&current_state);
}

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

/*
 * LoRa device - aliased in devicetree.
 *
 * ARCHITECTURAL LIMITATION (project-LICHEN-tvfm.110): This module uses static
 * global state (rx_stack, rx_thread_data, lora_mutex, tx_buf, lora_data) and
 * supports only ONE LoRa radio instance per system. The LORA_DEV macro
 * hardcodes DT_ALIAS(lora0) with no lora1/lora2 support.
 *
 * This is a deliberate simplification for LICHEN's target use case (single-
 * radio mesh nodes). Multi-radio support would require:
 * 1. Per-instance context structs instead of static globals
 * 2. Devicetree-driven instance enumeration
 * 3. Thread pool or per-instance RX threads
 * 4. API changes to accept instance handle
 *
 * Most boards have one LoRa radio. The rare multi-radio expansion boards can
 * be supported by instantiating separate firmware images on each radio.
 */
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
 * Module data (not state - state is managed by current_state atomic).
 *
 * Access patterns:
 *   - Mutex-protected fields (lora_dev, eui64, rx_callback, rx_callback_user_data):
 *     Must hold lora_mutex for both read and write. Callers read callback pair
 *     atomically via snapshot under lock (see rx_thread).
 */
static struct {
    /* Mutex-protected: device pointer set once during init */
    const struct device *lora_dev;
    /* Mutex-protected: stable after init; copied by copy_eui64() */
    uint8_t eui64[8];
    /* Mutex-protected: callback + user_data updated as a pair */
    lichen_lora_rx_cb_t rx_callback;
    void *rx_callback_user_data;
} lora_data;

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
 * SECURITY: EUI-64 is derived from hardware ID only, NOT cryptographically
 * bound to the node's Ed25519 identity keypair. This is an architectural
 * limitation with the following implications:
 * - EUI-64 provides device identification, not authentication
 * - An attacker with a victim's private key can sign frames with any EUI-64
 * - The Ed25519 public key (verified via Schnorr signature) is the true
 *   cryptographic identity - EUI-64 is just a stable routing identifier
 * - Frame authenticity depends on signature verification, not EUI-64 matching
 *
 * Future work: LICHEN spec section 6.2 suggests deriving IID from Ed25519
 * public key. This would cryptographically bind EUI-64 to the keypair,
 * but requires keypair provisioning before network initialization.
 *
 * @param eui64 Output buffer for 8-byte EUI-64
 * @return 0 on success, negative errno on failure
 */
/*
 * SECURITY: Domain separation prefix for EUI-64 derivation.
 * This ensures SHA-256(prefix || hwid) produces different output than
 * other uses of SHA-256 on the same hwid (e.g., key derivation).
 * The prefix is a fixed ASCII string with no trailing NUL in the hash input.
 */
#define EUI64_DOMAIN_PREFIX "LICHEN-EUI64-v1"
#define EUI64_DOMAIN_PREFIX_LEN (sizeof(EUI64_DOMAIN_PREFIX) - 1)
#define LICHEN_HWID_MAX_LEN 32U
#define LICHEN_EXPECTED_MAX_HWID_LEN 16U

BUILD_ASSERT(LICHEN_HWID_MAX_LEN >= LICHEN_EXPECTED_MAX_HWID_LEN,
             "hardware ID buffer must cover supported MCU IDs");

static int generate_eui64(uint8_t *eui64)
{
    int ret = 0;
    uint8_t hwid[LICHEN_HWID_MAX_LEN];
    ssize_t hwid_len;
    uint8_t hash[TC_SHA256_DIGEST_SIZE];
    uint8_t hash_input[EUI64_DOMAIN_PREFIX_LEN + sizeof(hwid)];
    BUILD_ASSERT(sizeof(hwid) == LICHEN_HWID_MAX_LEN,
                 "hwid buffer must match declared max hardware ID length");
    BUILD_ASSERT(sizeof(hash_input) == EUI64_DOMAIN_PREFIX_LEN + LICHEN_HWID_MAX_LEN,
                 "hash_input must cover domain prefix plus max hardware ID");

    hwid_len = hwinfo_get_device_id(hwid, sizeof(hwid));
    if (hwid_len < 0) {
        /* SECURITY: Refusing to start without stable identity. A random EUI-64
         * would change on each reboot, breaking IPv6 NDP and mesh routing. */
        LOG_ERR("lora_l2: hwinfo_get_device_id failed (%d)", (int)hwid_len);
        /* Cast safe: hwinfo errors are negative errno (-E*), always fit in int */
        ret = (int)hwid_len;
        goto cleanup;
    }
    if (hwid_len == 0) {
        /* SECURITY: Zero-length hwid means no unique identity available */
        LOG_ERR("lora_l2: no hardware ID available, cannot generate stable EUI-64");
        ret = -ENODEV;
        goto cleanup;
    }
    if ((size_t)hwid_len > sizeof(hwid)) {
        LOG_ERR("lora_l2: hwinfo returned invalid length (%d)", (int)hwid_len);
        ret = -EINVAL;
        goto cleanup;
    }
    const size_t checked_hwid_len = (size_t)hwid_len;

    /* SECURITY: Reject all-zeros hwid which would cause EUI-64 collisions.
     * Some MCUs return zeros when fuses aren't programmed or in debug mode. */
    uint8_t nonzero = 0;
    for (ssize_t i = 0; i < hwid_len; i++) {
        nonzero |= hwid[i];
    }
    if (nonzero == 0) {
        LOG_ERR("lora_l2: hardware ID is all zeros, cannot generate unique EUI-64");
        ret = -EINVAL;
        goto cleanup;
    }

    /*
     * Hash prefix || hwid to derive EUI-64 with domain separation.
     * SECURITY: SHA-256 provides collision resistance - two different
     * hwids will produce different EUI-64s with overwhelming probability.
     * The domain prefix ensures this derivation is independent of other
     * SHA-256 uses (e.g., ipv6_addr.c:pubkey_to_iid uses different input).
     */
    memcpy(hash_input, EUI64_DOMAIN_PREFIX, EUI64_DOMAIN_PREFIX_LEN);
    memcpy(hash_input + EUI64_DOMAIN_PREFIX_LEN, hwid, checked_hwid_len);
    ret = lichen_sha256(hash_input, EUI64_DOMAIN_PREFIX_LEN + checked_hwid_len, hash);
    if (ret != 0) {
        LOG_ERR("lora_l2: EUI-64 SHA-256 failed");
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
    LOG_DBG("lora_l2: EUI-64 from hashed hardware ID (%d bytes)", (int)hwid_len);

    /*
     * IEEE 802 EUI-64 first octet bit definitions (LSB numbering):
     *   Bit 0 (0x01): Individual/Group (I/G) - 0=unicast, 1=multicast
     *   Bit 1 (0x02): Universal/Local (U/L)  - 0=universally administered (OUI),
     *                                          1=locally administered
     *
     * We set U/L=1 because this EUI-64 is derived from device hardware ID,
     * not from an IEEE-assigned OUI. We clear I/G=0 to mark this as a unicast
     * address (individual device, not a multicast group).
     *
     * Reference: IEEE 802-2014 section 8.2, IEEE Guidelines for EUI-64.
     */
    eui64[0] = (eui64[0] | 0x02) & 0xFE;  /* Set U/L bit, clear I/G bit */

    LOG_DBG("lora_l2: EUI-64 %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            eui64[0], eui64[1], eui64[2], eui64[3],
            eui64[4], eui64[5], eui64[6], eui64[7]);

cleanup:
    /* SECURITY: Zero intermediate buffers and output on all error paths.
     * Defense-in-depth: ensure caller never sees undefined eui64 on failure,
     * even though callers should check return value. */
    secure_zero(hwid, sizeof(hwid));
    secure_zero(hash_input, sizeof(hash_input));
    secure_zero(hash, sizeof(hash));
    if (ret != 0) {
        secure_zero(eui64, 8);
    }
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
        ret = lora_recv(dev, rx_buf, sizeof(rx_buf),
                        K_MSEC(RX_TIMEOUT_MS), &rssi, &snr);

        if (ret < 0) {
            if (ret == -EAGAIN) {
                /* Timeout is normal operation, not an error - reset counter */
                consecutive_errors = 0;
                continue;
            }
            if (consecutive_errors < INT_MAX) {
                consecutive_errors++;
            }
            LOG_ERR("lora_l2: RX error (%d)", ret);
            if (consecutive_errors > 0 && consecutive_errors % RX_ERROR_WARN_THRESHOLD == 0) {
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
         * sizeof(rx_buf) is size_t. Cast sizeof to int for comparison since
         * LICHEN_LORA_MAX_PHY_PAYLOAD (255) fits safely in int. */
        if (ret > (int)sizeof(rx_buf)) {
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

int lichen_lora_l2_init(void)
{
    int ret = 0;

    /*
     * Always acquire mutex before checking state. This ensures:
     * 1. If another thread is initializing, we wait until it completes
     * 2. We see the fully initialized state (not partial state mid-init)
     * 3. No TOCTOU race where we return success before EUI-64 is generated
     *
     * The mutex acquisition is the serialization point - we cannot use a
     * fast-path early-return check because that would return success to a
     * caller while another thread is still inside init() generating the EUI-64.
     */
    k_mutex_lock(&lora_mutex, K_FOREVER);

    /* Idempotent: if already initialized, return success. Safe to check here
     * because we hold the mutex, so init is either complete or not started. */
    if (lora_get_state() != LORA_UNINIT) {
        k_mutex_unlock(&lora_mutex);
        return 0;
    }

    lora_data.lora_dev = LORA_DEV;
    lora_data.rx_callback = NULL;
    lora_data.rx_callback_user_data = NULL;

    if (!device_is_ready(lora_data.lora_dev)) {
        LOG_ERR("lora_l2: device not ready");
        ret = -ENODEV;
        goto out;
    }

    ret = generate_eui64(lora_data.eui64);
    if (ret < 0) {
        LOG_ERR("lora_l2: failed to generate stable EUI-64, cannot initialize");
        goto out;
    }

    if (lora_transition(LORA_STOPPED) != 0) {
        ret = -EIO;
        goto out;
    }
    LOG_INF("lora_l2: initialized");

out:
    k_mutex_unlock(&lora_mutex);
    return ret;
}

int lichen_lora_l2_start(void)
{
    enum lora_state state = lora_get_state();

    switch (state) {
    case LORA_UNINIT:
        LOG_ERR("lora_l2: not initialized, call lichen_lora_l2_init() first");
        return -EINVAL;
    case LORA_ABORTED:
        LOG_ERR("lora_l2: in ABORTED state, call deinit() then init()");
        return -ECANCELED;
    case LORA_DEINITING:
        LOG_ERR("lora_l2: deinit in progress, cannot start");
        return -EBUSY;
    case LORA_RUNNING:
        return 0;  /* Already running */
    case LORA_STOPPED:
        break;  /* Proceed */
    default:
        LOG_ERR("lora_l2: unknown state (%d), forcing ABORTED", state);
        atomic_set(&current_state, LORA_ABORTED);
        return -EINVAL;
    }

    k_mutex_lock(&lora_mutex, K_FOREVER);

    /* Double-check state under mutex */
    if (lora_get_state() != LORA_STOPPED) {
        k_mutex_unlock(&lora_mutex);
        return -EAGAIN;
    }

    /*
     * Configure LoRa radio using Kconfig options and LICHEN protocol defaults.
     * Modulation parameters (from <zephyr/drivers/lora.h> enums):
     *   - BW_125_KHZ: 125kHz bandwidth (good range/throughput balance)
     *   - SF_10: Spreading factor 10 (long range, ~980 bps at BW125)
     *   - CR_4_5: Coding rate 4/5 (minimal FEC overhead)
     * These match the LICHEN spec for mesh operation. Preamble length 8
     * is the LoRa default (sufficient for synchronization at SF10).
     *
     * Static struct: safe even if a driver retains the pointer, since
     * lichen_lora_l2_start() holds lora_mutex and is non-re-entrant.
     *
     * Zephyr's lora_modem_config.tx selects the direction being configured.
     * This L2 implementation is targeted at Zephyr's SX126x/SX127x path used
     * by the supported Meshtastic-class boards. For that driver family,
     * lora_config(... .tx = true) stores the TX parameters needed by
     * lora_send(), while lora_recv() explicitly enters RX mode for each
     * receive operation.
     *
     * Do not change this to a post-config RX pass without auditing the driver:
     * drivers such as RYLR keep .tx as persistent direction state and reject
     * lora_send() after an RX config. Supporting those drivers would require a
     * per-operation config strategy around both lora_send() and lora_recv().
     */
    static struct lora_modem_config config = {
        .frequency = CONFIG_LICHEN_LORA_FREQUENCY,
        .bandwidth = BW_125_KHZ,   /* Zephyr enum: 125kHz */
        .datarate = SF_10,         /* Zephyr enum: spreading factor 10 */
        .coding_rate = CR_4_5,     /* Zephyr enum: 4/5 coding rate */
        .preamble_len = 8,         /* LoRa default preamble symbols */
        .tx_power = CONFIG_LICHEN_LORA_TX_POWER,
        .tx = true,                /* SX12xx TX config cache; see note above */
    };

    int ret = lora_config(lora_data.lora_dev, &config);
    if (ret < 0) {
        LOG_ERR("lora_l2: config failed (%d)", ret);
        k_mutex_unlock(&lora_mutex);
        return ret;
    }

    if (lora_transition(LORA_RUNNING) != 0) {
        k_mutex_unlock(&lora_mutex);
        return -EIO;
    }

    /* Start RX thread.
     * k_thread_create() returns the thread pointer passed in (first arg).
     * It cannot fail at runtime - thread/stack resources are sized at build time.
     *
     * RX_THREAD_PRIORITY is CONFIG_LICHEN_LORA_L2_RX_PRIORITY, which Kconfig
     * validates via "range 0 NUM_PREEMPT_PRIORITIES". Invalid priorities are
     * rejected at build time. (project-LICHEN-tvfm.73) */
    k_thread_create(&rx_thread_data, rx_stack,
                    K_THREAD_STACK_SIZEOF(rx_stack),
                    rx_thread, NULL, NULL, NULL,
                    RX_THREAD_PRIORITY, 0, K_NO_WAIT);
    /* Thread naming is best-effort - failure is non-fatal but logged for debugging */
    int name_ret = k_thread_name_set(&rx_thread_data, "lora_rx");
    if (name_ret < 0) {
        LOG_DBG("lora_l2: failed to set thread name (%d)", name_ret);
    }

    k_mutex_unlock(&lora_mutex);

    LOG_INF("lora_l2: started (%u MHz, %d dBm, SF10)",
            CONFIG_LICHEN_LORA_FREQUENCY / 1000000, CONFIG_LICHEN_LORA_TX_POWER);
    return 0;
}

int lichen_lora_l2_stop(void)
{
    int ret = 0;

    if (lora_get_state() != LORA_RUNNING) {
        return 0;  /* Not running, nothing to stop */
    }

    k_mutex_lock(&lora_mutex, K_FOREVER);

    /* Double-check state under mutex */
    if (lora_get_state() != LORA_RUNNING) {
        k_mutex_unlock(&lora_mutex);
        return 0;
    }

    /*
     * Clear RX callback BEFORE signaling thread to exit.
     * This prevents new callbacks from starting after we begin shutdown.
     * Any in-flight callback (already past the snapshot in rx_thread) will
     * complete and release rx_mutex before lichen_l2_enable's cleanup runs,
     * since cleanup acquires rx_mutex.
     *
     * CONTRACT (project-LICHEN-i1gk.48): stop() ALWAYS clears the RX callback.
     * lichen_l2_enable() relies on this to re-register its callback on enable.
     * If this behavior changes, update lichen_l2_enable() which assumes it must
     * call lichen_lora_l2_set_rx_callback() after every stop()/start() cycle.
     * See also lora_l2.h lichen_lora_l2_stop() documentation.
     */
    lora_data.rx_callback = NULL;
    lora_data.rx_callback_user_data = NULL;

    /* Transition to STOPPED before releasing mutex - thread will see this */
    if (lora_transition(LORA_STOPPED) != 0) {
        k_mutex_unlock(&lora_mutex);
        return -EIO;
    }

    /* Release mutex before joining - allows any in-flight TX to complete */
    k_mutex_unlock(&lora_mutex);

    /*
     * Wait for RX thread to exit gracefully. Use a short initial timeout
     * (RX_THREAD_QUICK_JOIN_MS) for the common case where the thread exits
     * quickly (state changed while not blocked in lora_recv). This is
     * ample time for a thread that checked state between lora_recv() calls;
     * if still blocked, it's inside lora_recv() and needs up to RX_TIMEOUT_MS
     * to return. If that times out, wait up to one full RX timeout cycle.
     * If still stuck, forcibly abort to ensure thread struct is safe to reuse
     * on subsequent start().
     */
    int join_ret = k_thread_join(&rx_thread_data, K_MSEC(RX_THREAD_QUICK_JOIN_MS));
    if (join_ret == -EAGAIN) {
        /*
         * Thread still running - likely blocked in lora_recv(). Wait for the
         * full RX_TIMEOUT_MS because worst-case lora_recv() just started when
         * we set the stop flag. (We cannot know how long it has been blocked,
         * so we must budget for a fresh call.)
         */
        join_ret = k_thread_join(&rx_thread_data, K_MSEC(RX_TIMEOUT_MS));
        if (join_ret == -EAGAIN) {
            LOG_WRN("lora_l2: RX thread join timed out after %d ms, aborting",
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
            /* Note: lora_transition() may fail here since we're already in
             * STOPPED state, so set ABORTED directly. */
            atomic_set(&current_state, LORA_ABORTED);
            LOG_WRN("lora_l2: module requires deinit() before restart");
            ret = -ECANCELED;
        }
    }

    LOG_INF("lora_l2: stopped");
    return ret;
}

int lichen_lora_l2_deinit(void)
{
    enum lora_state state = lora_get_state();

    /*
     * Only STOPPED or ABORTED states can transition to DEINITING.
     *
     * SECURITY: This appears to be a TOCTOU pattern (read state, then act on it),
     * but is actually safe: lora_transition_from() uses atomic CAS internally,
     * so if the state changes between lora_get_state() and the CAS, the CAS
     * fails atomically and we return -EBUSY. The initial read is merely an
     * optimization to select which expected-state to pass to the CAS. Two
     * concurrent deinit() calls racing on the same state will have exactly
     * one succeed (CAS guarantee), the other returns -EBUSY.
     */
    if (state == LORA_STOPPED) {
        if (lora_transition_from(LORA_STOPPED, LORA_DEINITING) != 0) {
            LOG_ERR("lora_l2: deinit race, state changed");
            return -EBUSY;
        }
    } else if (state == LORA_ABORTED) {
        if (lora_transition_from(LORA_ABORTED, LORA_DEINITING) != 0) {
            LOG_ERR("lora_l2: deinit race, state changed");
            return -EBUSY;
        }
    } else if (state == LORA_DEINITING) {
        LOG_ERR("lora_l2: deinit already in progress");
        return -EBUSY;
    } else if (state == LORA_RUNNING) {
        LOG_ERR("lora_l2: still running, call stop() first");
        return -EBUSY;
    } else if (state == LORA_UNINIT) {
        return 0;  /* Already uninitialized */
    } else {
        LOG_ERR("lora_l2: unknown state (%d), forcing ABORTED", state);
        atomic_set(&current_state, LORA_ABORTED);
        return -EINVAL;
    }

    /*
     * Wait for any in-flight TX to complete before cleanup. TX holds tx_buf_mutex
     * for the entire lora_send() duration (~500ms at SF10/255 bytes). By acquiring
     * this mutex here, we ensure:
     * 1. No TX is currently using tx_buf
     * 2. No new TX will start (deinit state check in tx() will fail after we
     *    transitioned to DEINITING above)
     *
     * Note: tx_buf_mutex may be legitimately held for a long time (~500ms).
     * We wait forever here because refusing to deinit leaves worse state.
     */
    k_mutex_lock(&tx_buf_mutex, K_FOREVER);
    /* tx_buf is now safe - no active TX. We'll reinitialize the mutex below. */
    k_mutex_unlock(&tx_buf_mutex);

    /*
     * Abort recovery only: ensure the RX thread is actually terminated before
     * touching mutexes or callback state. Normal STOPPED teardown skips this
     * join because stop() already joined the RX thread, and init-without-start
     * has no valid RX thread object to join.
     *
     * If this join fails, deinit is incomplete. Continuing would let callers
     * reuse or reinitialize resources while the RX thread may still access
     * them. Leave the module in ABORTED and return the join error so callers
     * can treat a system reboot as the only guaranteed recovery.
     */
    if (state == LORA_ABORTED) {
        int join_ret = k_thread_join(&rx_thread_data, K_MSEC(DEINIT_JOIN_TIMEOUT_MS));

        if (join_ret != 0) {
            LOG_ERR("lora_l2: RX thread join failed in deinit (%d); "
                    "deinit incomplete, reboot required for guaranteed recovery",
                    join_ret);
            atomic_set(&current_state, LORA_ABORTED);
            return join_ret;
        }
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

    /* Best-effort check: trylock to detect if mutex is held. If trylock
     * succeeds, we own it and can safely reinit after unlock. If it fails,
     * we log a warning but proceed with reinit anyway (documented UB). */
    int trylock_ret = k_mutex_lock(&lora_mutex, K_NO_WAIT);
    if (trylock_ret == 0) {
        /* We acquired it - mutex was free. Unlock before reinit. */
        k_mutex_unlock(&lora_mutex);
    } else {
        /* Trylock failed - mutex is held by another context (likely dead thread).
         * SECURITY: Proceeding with k_mutex_init() is UNDEFINED BEHAVIOR.
         * Log at ERR level since this indicates the system is in a degraded
         * state where full reboot is the only guaranteed recovery. */
        LOG_ERR("lora_l2: lora_mutex held during deinit (trylock=%d), "
                "reinit is UB - consider k_sys_reboot for guaranteed recovery",
                trylock_ret);
    }
    int mutex_ret = k_mutex_init(&lora_mutex);
    if (mutex_ret != 0) {
        /* k_mutex_init() should not fail in kernel mode, but log if it does.
         * There is no recovery action - we've already committed to resetting
         * the module and proceeding is better than leaving it unusable. */
        LOG_ERR("lora_l2: k_mutex_init failed (%d), module may be unstable", mutex_ret);
    }

    /* Also reinitialize tx_buf_mutex for completeness during abort recovery.
     * In normal shutdown, we already acquired/released it above to wait for TX,
     * but in abort scenarios the mutex state may be corrupted. */
    mutex_ret = k_mutex_init(&tx_buf_mutex);
    if (mutex_ret != 0) {
        LOG_ERR("lora_l2: k_mutex_init(tx_buf_mutex) failed (%d), module may be unstable",
                mutex_ret);
    }

    /*
     * Clear callback state. No mutex needed: the RX thread was joined above
     * and DEINITING state blocks new operations, so no concurrent access.
     */
    lora_data.rx_callback = NULL;
    lora_data.rx_callback_user_data = NULL;

    /*
     * Reinitialize lichen_l2's rx_mutex (project-LICHEN-dq6n.22).
     *
     * If the RX thread was aborted while executing lichen_l2_input(), it may
     * have been holding rx_mutex (which lives in lichen_l2.c, not here).
     * Without reinitializing that mutex, subsequent RX callbacks would deadlock.
     *
     * This call has the same UNDEFINED BEHAVIOR caveats as our lora_mutex
     * reinitialization above. See the SECURITY comment at line ~545 for the
     * full analysis.
     *
     * Only needed when CONFIG_LICHEN_L2 is enabled (lichen_l2.c is compiled).
     * In standalone mode, there's no rx_mutex to reinitialize.
     */
#if defined(CONFIG_LICHEN_L2)
    lichen_l2_reinit_after_abort();
#endif

    /*
     * Final transition to UNINIT - module ready for re-initialization.
     * Use atomic CAS to ensure no state race: while DEINITING can only
     * transition to UNINIT, using lora_transition_from() guarantees the
     * state hasn't been corrupted by a bug elsewhere.
     */
    if (lora_transition_from(LORA_DEINITING, LORA_UNINIT) != 0) {
        /* Should be impossible - we hold DEINITING exclusively */
        LOG_ERR("lora_l2: deinit state corrupted, forcing ABORTED");
        atomic_set(&current_state, LORA_ABORTED);
        return -EIO;
    }

    LOG_INF("lora_l2: deinitialized");
    return 0;
}

int lichen_lora_l2_tx(const uint8_t *data, size_t len)
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

    state = lora_get_state();
    if (state != LORA_RUNNING) {
        LOG_WRN("lora_l2: not running after TX lock (state=%s)", state_names[state]);
        k_mutex_unlock(&tx_buf_mutex);
        return -ENETDOWN;
    }

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
     *
     * Cast len (size_t) to uint32_t: lora_send() expects uint32_t data_len.
     * This cast is safe because:
     * 1. len was validated above to not exceed LICHEN_LORA_MAX_PHY_PAYLOAD (255)
     * 2. On target platforms (32-bit MCUs), size_t == uint32_t (asserted below)
     *
     * The BUILD_ASSERT guards against 64-bit platforms where size_t > UINT32_MAX
     * could theoretically wrap. This is purely defensive - LICHEN targets
     * embedded 32-bit systems (nRF52/STM32/ESP32) where size_t fits in uint32_t.
     */
    BUILD_ASSERT(sizeof(size_t) <= sizeof(uint32_t),
                 "size_t larger than uint32_t - review lora_send() cast");
    int ret = lora_send(lora_data.lora_dev, tx_buf, (uint32_t)len);

    /*
     * SECURITY: Zero tx_buf after use to prevent leaking previous payload
     * data. While lora_send() only transmits `len` bytes, zeroing provides
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
     */
    k_mutex_lock(&lora_mutex, K_FOREVER);
    lora_data.rx_callback_user_data = user_data;
    lora_data.rx_callback = cb;
    k_mutex_unlock(&lora_mutex);

    return 0;
}

int lichen_lora_l2_copy_eui64(uint8_t out[8])
{
    enum lora_state state;
    int ret = 0;

    if (out == NULL) {
        return -EINVAL;
    }

    k_mutex_lock(&lora_mutex, K_FOREVER);
    state = lora_get_state();
    switch (state) {
    case LORA_STOPPED:
    case LORA_RUNNING:
        memcpy(out, lora_data.eui64, sizeof(lora_data.eui64));
        break;
    case LORA_UNINIT:
        LOG_ERR("lora_l2: not initialized");
        ret = -ENODEV;
        break;
    case LORA_ABORTED:
        LOG_ERR("lora_l2: EUI-64 unavailable until reinit after abort");
        ret = -ECANCELED;
        break;
    case LORA_DEINITING:
        LOG_ERR("lora_l2: EUI-64 unavailable during deinit");
        ret = -EBUSY;
        break;
    default:
        LOG_ERR("lora_l2: invalid state while copying EUI-64 (%d)", state);
        ret = -EINVAL;
        break;
    }
    k_mutex_unlock(&lora_mutex);
    return ret;
}

/*
 * Compatibility API: returns an alias to internal eui64 storage after a
 * mutex-protected state check. New callers should use copy_eui64() instead.
 *
 * Thread safety contract (caller responsibility):
 * - No mutex is held after return; concurrent deinit() can zero the backing memory
 * - Caller must prevent concurrent deinit() while using the pointer
 */
const uint8_t *lichen_lora_l2_get_eui64(void)
{
    const uint8_t *eui64 = NULL;
    enum lora_state state;

    k_mutex_lock(&lora_mutex, K_FOREVER);
    state = lora_get_state();
    if (state == LORA_STOPPED || state == LORA_RUNNING) {
        eui64 = lora_data.eui64;
    } else if (state == LORA_UNINIT) {
        LOG_ERR("lora_l2: not initialized");
    } else {
        LOG_ERR("lora_l2: EUI-64 unavailable in state %d", state);
    }
    k_mutex_unlock(&lora_mutex);

    return eui64;
}

bool lichen_lora_l2_is_running(void)
{
    return lora_get_state() == LORA_RUNNING;
}

bool lichen_lora_l2_needs_reinit(void)
{
    return lora_get_state() == LORA_ABORTED;
}
