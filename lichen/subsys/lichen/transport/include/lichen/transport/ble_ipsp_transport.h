/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ble_ipsp_transport.h
 * @brief BLE IPSP transport binding for LCI
 *
 * Implements LCI transport bindings for Bluetooth Low Energy per spec/11-lci.md
 * section 17.3.2:
 *
 * Option A (Required): SLIP over BLE UART (Nordic UART Service)
 *   - NUS UUID: 6E400001-B5A3-F393-E0A9-E50E24DCCA9E
 *   - TX/RX characteristics carry SLIP-framed IPv6
 *   - Simple, works with existing BLE serial libraries
 *
 * Option B (Optional): 6LoWPAN over BLE (RFC 7668)
 *   - Standard IPSP (Internet Protocol Support Profile)
 *   - L2CAP connection-oriented channels
 *   - Header compression via 6LoWPAN IPHC
 *
 * Security: BLE pairing (LE Secure Connections) is required for non-read-only
 * access. Raw diagnostic resources under /diag/raw/ require LE Secure Connections.
 */

#ifndef LICHEN_TRANSPORT_BLE_IPSP_TRANSPORT_H_
#define LICHEN_TRANSPORT_BLE_IPSP_TRANSPORT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <lichen/transport/slip_transport.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Maximum BLE MTU for SLIP transport
 *
 * NUS typically uses 20-byte packets (default ATT MTU - 3), but can negotiate
 * up to 247 bytes with DLE. We reassemble SLIP frames from multiple packets.
 */
#define LICHEN_BLE_SLIP_MTU 247

/**
 * @brief Maximum IPv6 packet size for BLE transport
 *
 * Same as LICHEN_L2_MTU to maintain consistency across transports.
 */
#define LICHEN_BLE_IPV6_MTU 200

/**
 * @brief BLE transport connection state
 */
enum lichen_ble_conn_state {
	LICHEN_BLE_DISCONNECTED,
	LICHEN_BLE_CONNECTED,
	LICHEN_BLE_PAIRED,
	LICHEN_BLE_SECURE, /* LE Secure Connections established */
};

/**
 * @brief BLE transport statistics
 */
struct lichen_ble_transport_stats {
	uint32_t rx_packets;
	uint32_t tx_packets;
	uint32_t rx_bytes;
	uint32_t tx_bytes;
	uint32_t rx_errors;
	uint32_t tx_errors;
	uint32_t slip_frame_errors;
	uint32_t connections;
	uint32_t disconnections;
};

/**
 * @brief Callback for received IPv6 packets
 *
 * @param data  IPv6 packet data
 * @param len   Length of packet
 * @param ctx   User context (passed to lichen_ble_transport_init)
 */
typedef void (*lichen_ble_rx_cb_t)(const uint8_t *data, size_t len, void *ctx);

/**
 * @brief Callback for connection state changes
 *
 * @param state  New connection state
 * @param ctx    User context
 */
typedef void (*lichen_ble_conn_cb_t)(enum lichen_ble_conn_state state, void *ctx);

/**
 * @brief BLE transport configuration
 */
struct lichen_ble_transport_config {
	lichen_ble_rx_cb_t rx_cb;
	lichen_ble_conn_cb_t conn_cb;
	void *user_ctx;
	bool require_secure; /* Require LE Secure Connections for all access */
};

/**
 * @brief Initialize BLE SLIP transport (Option A)
 *
 * Sets up the Nordic UART Service (NUS) with SLIP framing for IPv6 packet
 * transport. This is the required transport option per LCI spec.
 *
 * @param config  Transport configuration
 *
 * @return 0 on success
 * @return -EINVAL if config is NULL or callbacks missing
 * @return -EALREADY if already initialized
 * @return -ENOTSUP if BLE not supported
 * @return -ENOMEM on resource allocation failure
 */
int lichen_ble_slip_init(const struct lichen_ble_transport_config *config);

/**
 * @brief Initialize BLE IPSP transport (Option B)
 *
 * Sets up RFC 7668 6LoWPAN over BLE with IPSP profile. This is the optional
 * standard-compliant transport option.
 *
 * @param config  Transport configuration
 *
 * @return 0 on success
 * @return -ENOTSUP if IPSP not enabled in Kconfig
 * @return other negative errno on failure
 */
int lichen_ble_ipsp_init(const struct lichen_ble_transport_config *config);

/**
 * @brief Start BLE advertising
 *
 * Begins advertising the configured BLE services. Call after init.
 *
 * @return 0 on success
 * @return -EINVAL if not initialized
 * @return negative errno on BLE stack error
 */
int lichen_ble_transport_start(void);

/**
 * @brief Stop BLE advertising and disconnect clients
 *
 * @return 0 on success
 * @return -EINVAL if not initialized
 */
int lichen_ble_transport_stop(void);

/**
 * @brief Send an IPv6 packet over BLE SLIP
 *
 * SLIP-encodes the packet and sends over NUS TX characteristic.
 * Packets are fragmented if they exceed the negotiated ATT MTU.
 *
 * @param data  IPv6 packet data
 * @param len   Length of packet (max LICHEN_BLE_IPV6_MTU)
 *
 * @return Number of bytes sent on success (len)
 * @return -EINVAL if data is NULL or len > MTU
 * @return -ENOTCONN if no client connected
 * @return -EACCES if security requirements not met
 * @return -ENOMEM if TX buffer full
 */
int lichen_ble_slip_send(const uint8_t *data, size_t len);

/**
 * @brief Send an IPv6 packet over IPSP (Option B)
 *
 * Sends via RFC 7668 L2CAP channel. Only available when IPSP is enabled.
 *
 * @param data  IPv6 packet data
 * @param len   Length of packet
 *
 * @return Number of bytes sent on success
 * @return -ENOTSUP if IPSP not enabled
 * @return -ENOTCONN if no L2CAP channel established
 */
int lichen_ble_ipsp_send(const uint8_t *data, size_t len);

/**
 * @brief Get current connection state
 *
 * @return Current connection state
 */
enum lichen_ble_conn_state lichen_ble_transport_get_state(void);

/**
 * @brief Check if transport has an active secure connection
 *
 * @return true if LE Secure Connections established
 */
bool lichen_ble_transport_is_secure(void);

/**
 * @brief Get transport statistics
 *
 * @param stats  Output structure for statistics
 *
 * @return 0 on success
 * @return -EINVAL if stats is NULL
 */
int lichen_ble_transport_get_stats(struct lichen_ble_transport_stats *stats);

/**
 * @brief Reset transport statistics
 */
void lichen_ble_transport_reset_stats(void);

/**
 * @brief Deinitialize BLE transport
 *
 * Stops advertising, disconnects clients, and releases resources.
 */
void lichen_ble_transport_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_TRANSPORT_BLE_IPSP_TRANSPORT_H_ */
