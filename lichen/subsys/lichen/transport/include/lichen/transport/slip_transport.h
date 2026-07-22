/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file slip_transport.h
 * @brief SLIP transport for LCI (Local Client Interface)
 *
 * Implements RFC 1055 SLIP framing over UART or USB-CDC for IPv6 packet
 * transport per spec/11-lci.md section 17.3.1.
 *
 * This provides a Zephyr network interface with fixed link-local addresses:
 * - Node (gateway) address: fe80::1
 * - Client address: fe80::2
 *
 * The transport works with standard SLIP tools (slattach, tunslip6) and
 * any CoAP client that can route to the link-local address.
 */

#ifndef LICHEN_TRANSPORT_SLIP_TRANSPORT_H_
#define LICHEN_TRANSPORT_SLIP_TRANSPORT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/net_if.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SLIP_END
#define SLIP_END     0xC0u
#define SLIP_ESC     0xDBu
#define SLIP_ESC_END 0xDCu
#define SLIP_ESC_ESC 0xDDu
#endif

/** IPv6 minimum MTU (RFC 8200) */
#define SLIP_LCI_MTU 1280u

/** Node link-local IID (produces fe80::1) */
#define SLIP_LCI_NODE_IID { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }

/** Client link-local IID (produces fe80::2) */
#define SLIP_LCI_CLIENT_IID { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }

/**
 * @brief SLIP transport statistics
 */
struct slip_transport_stats {
	uint32_t rx_packets;
	uint32_t tx_packets;
	uint32_t rx_bytes;
	uint32_t tx_bytes;
	uint32_t rx_errors;
	uint32_t tx_errors;
	uint32_t slip_frame_errors;
	uint32_t rx_overflow;
};

/**
 * @brief Initialize the SLIP transport
 *
 * Sets up synchronization primitives, optional UART device (via
 * devicetree chosen { lichen,slip-uart = &uart0; }), starts RX thread.
 * UART is optional for test modes using test helpers; warning logged if
 * unavailable. Network interface is always available.
 *
 * @return 0 on success (or -EALREADY if already initialized)
 */
int slip_transport_init(void);

/**
 * @brief Get the SLIP transport network interface
 *
 * @return Pointer to the network interface, or NULL if not initialized
 */
struct net_if *slip_transport_iface_get(void);

/**
 * @brief Send an IPv6 packet over SLIP
 *
 * Encodes the packet with SLIP framing and transmits over UART.
 * This function is thread-safe.
 *
 * @param ipv6 Pointer to IPv6 packet data
 * @param len  Length of the packet in bytes (max SLIP_LCI_MTU)
 *
 * @return 0 on success
 * @return -EINVAL if ipv6 is NULL with len > 0
 * @return -EMSGSIZE if len > SLIP_LCI_MTU
 * @return -ENODEV if UART device not available
 */
int slip_transport_send(const uint8_t *ipv6, size_t len);

/**
 * @brief Get transport statistics
 *
 * @param stats  Output structure for statistics
 *
 * @return 0 on success
 * @return -EINVAL if stats is NULL
 */
int slip_transport_get_stats(struct slip_transport_stats *stats);

/**
 * @brief Reset transport statistics
 */
void slip_transport_reset_stats(void);

/**
 * @brief Check if SLIP transport is initialized and ready
 *
 * UART device is optional (test mode uses inject/get_last_tx helpers).
 * Matches kiss_transport_is_ready() pattern.
 *
 * @return true if transport has been initialized
 */
bool slip_transport_is_ready(void);

#ifdef CONFIG_ZTEST
/**
 * @brief Test helper: inject raw bytes as if received from UART
 *
 * Processes bytes through the SLIP state machine synchronously.
 *
 * @param data Raw SLIP-framed data
 * @param len  Length of data
 * @return Number of complete packets processed
 */
int slip_transport_test_inject_rx(const uint8_t *data, size_t len);

/**
 * @brief Test helper: get last transmitted SLIP frame
 *
 * @param buf   Output buffer for frame data
 * @param max   Maximum bytes to copy
 * @param len   Output: actual frame length
 * @return 0 on success
 * @return -EINVAL if buf or len is NULL
 */
int slip_transport_test_get_last_tx(uint8_t *buf, size_t max, size_t *len);

/**
 * @brief Test helper: reset transport state for test isolation
 */
void slip_transport_test_reset(void);
#endif /* CONFIG_ZTEST */

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_TRANSPORT_SLIP_TRANSPORT_H_ */
