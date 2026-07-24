/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lora_l2.h
 * @brief LICHEN LoRa L2 layer for Zephyr
 *
 * This module provides the bridge between application code and the LoRa radio.
 * It handles:
 * - LoRa radio initialization and configuration
 * - Packet transmission
 * - Packet reception (via callback)
 * - EUI-64 address generation
 *
 * Usage:
 *   lichen_lora_l2_init();
 *   lichen_lora_l2_set_rx_callback(my_rx_handler, NULL);
 *   lichen_lora_l2_start();
 *   ...
 *   lichen_lora_l2_tx(data, len);
 *   ...
 *   lichen_lora_l2_stop();
 *
 * MTU considerations:
 * - LoRa packets are limited (~255 bytes at SF10/BW125)
 * - SCHC compression reduces IPv6/UDP headers from ~48 bytes to ~3-6 bytes
 * - Effective payload per packet: ~200 bytes
 * - For larger packets, SCHC fragmentation is required
 */

#ifndef LICHEN_LORA_L2_H_
#define LICHEN_LORA_L2_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <lichen/schnorr48.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief MTU for LICHEN LoRa interface
 *
 * Derivation (see lichen/link.h wire layout and lichen/schnorr48.h):
 *
 *   Max LoRa payload at SF10/BW125:     255 bytes
 *
 *   LICHEN frame header (fixed):
 *     Length field:                       1 byte
 *     LLSec flags:                         1 byte
 *     Epoch:                               1 byte
 *     Sequence number:                     2 bytes
 *     Subtotal:                            5 bytes
 *
 *   Unsigned MIC:                           0 bytes
 *   Schnorr-48 signature MIC:              SCHNORR48_SIG_LEN
 *   ----------------------------------------
 *   Total fixed overhead:            5 + SCHNORR48_SIG_LEN
 *
 *   We use 5 + SCHNORR48_SIG_LEN + 2 rather than 5 + SCHNORR48_SIG_LEN + 4
 *   (project-LICHEN-tvfm.95):
 *   The MTU computation is: 255 - FRAME_OVERHEAD = MTU.
 *   Using 55 yields MTU=200 (vs 198 with 57). The 2-byte "savings" means:
 *   - SCHC rule ID (1-2 bytes) is accounted for in the 57-byte real overhead
 *   - We're optimistically assuming rule IDs fit within header space
 *   - If compressed payload + rule ID exceeds 200 bytes, TX will fail at
 *     the size check in lichen_l2_send()
 *
 *   Result: 255 - 55 = 200 bytes nominal MTU for IPv6 payload
 *
 * If frame format or signature size changes, update these constants.
 */
#define LICHEN_LORA_MAX_PHY_PAYLOAD 255
#define LICHEN_LORA_FRAME_OVERHEAD   (5 + SCHNORR48_SIG_LEN + 2)  /* header + sig + 2-byte headroom */
#define LICHEN_LORA_MTU (LICHEN_LORA_MAX_PHY_PAYLOAD - LICHEN_LORA_FRAME_OVERHEAD)

/**
 * @brief Link-layer address length (EUI-64)
 */
#define LICHEN_LORA_L2_ADDR_LEN 8

/**
 * @brief RX callback function type
 *
 * @param data Received packet data
 * @param len Length of received data
 * @param rssi RSSI in dBm (int16_t matches Zephyr lora_recv() output type)
 * @param snr SNR in dB (int8_t matches Zephyr lora_recv() output type)
 * @param user_data User-provided context
 *
 * @note rssi/snr types match Zephyr's lora_recv() API (zephyr/drivers/lora.h).
 *       If Zephyr changes these types, this typedef should be updated to match.
 *       (project-LICHEN-tvfm.70)
 */
typedef void (*lichen_lora_rx_cb_t)(const uint8_t *data, size_t len,
                                    int16_t rssi, int8_t snr,
                                    void *user_data);

/**
 * @brief Initialize the LoRa L2 module
 *
 * Must be called before any other function. Generates EUI-64 address
 * and validates LoRa device is ready. Idempotent: returns 0 if already
 * initialized.
 *
 * When using the Zephyr network interface path, lichen_l2_iface_init()
 * calls this during NET_DEVICE_INIT before copying the EUI-64 or registering
 * RX callbacks. Code that bypasses that path and calls lichen_lora_l2_start()
 * directly must call this first; start() returns -EINVAL from the UNINIT state.
 *
 * Idempotency guarantee: If init() fails partway through, subsequent calls
 * retry from the beginning. All module fields (lora_dev, eui64, rx_callback)
 * are re-written before any state transition, so a failed init followed by
 * a successful retry produces correct state. Partial state from a failed
 * attempt is always overwritten.
 *
 * @return 0 on success, negative errno on failure
 */
int lichen_lora_l2_init(void);

/**
 * @brief Start the LoRa L2 layer
 *
 * Configures the radio and starts the RX thread.
 * Requires init() to have been called. Idempotent: returns 0 if already running.
 *
 * @return 0 on success (idempotent if already running)
 * @return -EINVAL if not initialized (call init() first)
 * @return -ECANCELED if module needs re-init after forced abort (call deinit() then init())
 * @return Other negative errno from lora_config() on radio configuration failure
 */
int lichen_lora_l2_start(void);

/**
 * @brief Stop the LoRa L2 layer
 *
 * Stops the RX thread. Idempotent: safe to call when already stopped.
 * Blocks until RX thread exits.
 *
 * @note Maximum blocking time: 100ms + CONFIG_LICHEN_LORA_L2_RX_TIMEOUT_MS
 * (default 1000ms, configurable 100-10000ms). The function uses a two-phase
 * join: a quick 100ms wait for the common case, then up to RX_TIMEOUT_MS if
 * the thread is blocked in lora_recv(). If both timeouts expire, the thread
 * is forcibly aborted and joined with K_FOREVER (typically immediate).
 *
 * If the RX thread does not exit gracefully within the timeout, it will be
 * forcibly aborted. After a forced abort, the module enters an undefined
 * state and requires lichen_lora_l2_deinit() followed by lichen_lora_l2_init()
 * before it can be restarted.
 *
 * @note RX callback clearing: stop() ALWAYS clears the RX callback to NULL.
 * Callers that need to receive packets after restart must re-register their
 * callback via lichen_lora_l2_set_rx_callback() before calling start().
 *
 * @return 0 on success (graceful stop)
 * @return -ECANCELED if RX thread had to be forcibly aborted (requires deinit/init cycle)
 */
int lichen_lora_l2_stop(void);

/**
 * @brief Deinitialize the LoRa L2 module
 *
 * Releases resources and resets state to allow re-initialization.
 * Required after a forced thread abort in stop() before the module can be
 * restarted. Must be called when the module is stopped (not running).
 *
 * After deinit, lichen_lora_l2_init() must be called before any other
 * operations.
 *
 * @return 0 on success
 * @return -EBUSY if module is still running (call stop() first)
 */
int lichen_lora_l2_deinit(void);

/**
 * @brief Transmit a packet over LoRa
 *
 * Copies data into an internal buffer before transmission.
 * The caller's buffer is never modified.
 *
 * @param data Packet data to send
 * @param len Length of data (max 255 bytes)
 *
 * @return 0 on success, negative errno on failure
 */
int lichen_lora_l2_tx(const uint8_t *data, size_t len);

/**
 * @brief Set the RX callback
 *
 * @param cb Callback function (NULL to disable)
 * @param user_data Context passed to callback
 * @return 0 on success, -ENODEV if not initialized
 */
int lichen_lora_l2_set_rx_callback(lichen_lora_rx_cb_t cb, void *user_data);

/**
 * @brief Get this node's EUI-64 address
 *
 * Copies the EUI-64 under the LoRa L2 mutex so callers never observe a
 * partially-cleared value during concurrent deinit().
 *
 * @param out Output buffer for 8-byte EUI-64
 *
 * @return 0 on success
 * @return -EINVAL if out is NULL
 * @return -ENODEV if not initialized
 * @return -ECANCELED if abort recovery is required
 * @return -EBUSY if deinit is in progress
 */
int lichen_lora_l2_copy_eui64(uint8_t out[8]);

/**
 * @brief Get this node's EUI-64 address
 *
 * Returns a pointer to internal state; caller must copy if persistent
 * access is needed. The EUI-64 value is stable after init() completes
 * and does not change until deinit().
 *
 * Prefer lichen_lora_l2_copy_eui64() for all new code.
 *
 * @warning The returned pointer aliases internal state. Do NOT modify.
 * @warning Thread safety: Returns internal pointer after releasing the mutex.
 *          Caller must ensure no concurrent deinit() while using the pointer.
 *          A concurrent deinit() will zero the backing memory, causing stale
 *          or partial reads. Either copy immediately, or hold application-level
 *          synchronization that prevents deinit during use.
 *
 * @return Pointer to 8-byte EUI-64, or NULL if not initialized
 */
const uint8_t *lichen_lora_l2_get_eui64(void);

/**
 * @brief Check if LoRa L2 is running
 *
 * @return true if started, false otherwise
 */
bool lichen_lora_l2_is_running(void);

/**
 * @brief Check if module requires re-initialization
 *
 * Returns true if the RX thread was forcibly aborted during stop().
 * When true, the module is in an undefined state and requires
 * lichen_lora_l2_deinit() followed by lichen_lora_l2_init() before
 * it can be used again.
 *
 * @return true if re-initialization is required, false otherwise
 */
bool lichen_lora_l2_needs_reinit(void);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LORA_L2_H_ */
