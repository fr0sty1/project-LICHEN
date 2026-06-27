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
 * Derivation (must match lichen/schnorr48.h and frame format):
 *   Max LoRa payload at SF10/BW125:     255 bytes
 *   LICHEN frame overhead:               ~10 bytes (length, flags, epoch, seqnum, addr, mic)
 *   Schnorr-48 signature:                 48 bytes (SCHNORR48_SIG_LEN)
 *   Margin for SCHC rule ID:               ~2 bytes
 *   ----------------------------------------
 *   Available for IPv6 payload:          ~195 bytes, rounded to 200
 *
 * If frame format or signature size changes, update this constant.
 */
#define LICHEN_LORA_MAX_PHY_PAYLOAD 255
#define LICHEN_LORA_FRAME_OVERHEAD   55  /* 10 + 48 - margin rounded */
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
 * @return 0 on success, negative errno on failure
 */
int lichen_lora_l2_stop(void);

/**
 * @brief Transmit a packet over LoRa
 *
 * @param data Packet data to send. Buffer must remain valid during TX.
 *             NOTE: The underlying Zephyr lora_send() API takes a non-const
 *             pointer because some radio drivers may modify the buffer
 *             (e.g., for DMA alignment or in-place encryption). Do not
 *             assume buffer contents are preserved after this call returns.
 *             Use a dedicated TX buffer rather than passing const data.
 * @param len Length of data (max 255 bytes)
 *
 * @return 0 on success, negative errno on failure
 */
int lichen_lora_l2_tx(uint8_t *data, size_t len);

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

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LORA_L2_H_ */
