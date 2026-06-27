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
 *   MIC (32-bit minimum):                  4 bytes
 *   Schnorr-48 signature:                 48 bytes (SCHNORR48_SIG_LEN)
 *   ----------------------------------------
 *   Total fixed overhead:                 57 bytes
 *
 *   Rounding down to 55 provides 2 bytes margin for:
 *   - SCHC rule ID (1-2 bytes in compressed payload)
 *   - Future address field use (currently elided for broadcast)
 *
 *   Result: 255 - 55 = 200 bytes available for IPv6 payload
 *
 * If frame format or signature size changes, update this constant.
 */
#define LICHEN_LORA_MAX_PHY_PAYLOAD 255
#define LICHEN_LORA_FRAME_OVERHEAD   55  /* 57 raw - 2 margin = 5 hdr + 4 MIC + 48 sig - 2 */
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
 * @param rssi RSSI in dBm
 * @param snr SNR in dB
 * @param user_data User-provided context
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
 * @return 0 on success, negative errno on failure
 */
int lichen_lora_l2_init(void);

/**
 * @brief Start the LoRa L2 layer
 *
 * Configures the radio and starts the RX thread.
 * Requires init() to have been called. Idempotent: returns 0 if already running.
 *
 * @return 0 on success, negative errno on failure
 */
int lichen_lora_l2_start(void);

/**
 * @brief Stop the LoRa L2 layer
 *
 * Stops the RX thread. Idempotent: returns 0 if not running.
 * Blocks until RX thread exits.
 *
 * If the RX thread does not exit gracefully within the timeout, it will be
 * forcibly aborted. After a forced abort, the module enters an undefined
 * state and requires lichen_lora_l2_deinit() followed by lichen_lora_l2_init()
 * before it can be restarted.
 *
 * @return 0 on success, negative errno on failure
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
 */
void lichen_lora_l2_set_rx_callback(lichen_lora_rx_cb_t cb, void *user_data);

/**
 * @brief Get this node's EUI-64 address
 *
 * @warning The returned pointer aliases internal state. Do NOT modify.
 *          Contents are stable after init() completes.
 *
 * @return Pointer to 8-byte EUI-64 (valid after init)
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
