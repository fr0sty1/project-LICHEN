/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef BLE_UART_H_
#define BLE_UART_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <zephyr/bluetooth/conn.h>

/**
 * Initialise the BLE stack and start advertising the NUS service.
 * Must be called from a thread context (bt_enable blocks).
 *
 * Returns 0 on success, negative errno on failure.
 */
int ble_uart_init(void);

/**
 * Send an IPv6 packet to the connected phone as a SLIP-framed BLE UART
 * notification.  Frames larger than the ATT MTU are split across multiple
 * bt_gatt_notify calls.
 *
 * Returns 0, -ENOTCONN if no phone is connected, -ENOMEM if the SLIP-encoded
 * frame exceeds buffer capacity, or negative errno on other failures.
 */
int ble_uart_send_slip(const uint8_t *ipv6, size_t len);

#ifdef CONFIG_ZTEST
struct ble_uart_test_state {
	uint16_t rx_len;
	bool rx_esc;
	bool rx_overflow;
	bool has_connection;
};

struct ble_uart_test_tx_state {
	struct bt_conn *conn;
	uint8_t data[64];
	uint16_t len;
	uint32_t notify_count;
};

void ble_uart_test_seed_rx_state(uint16_t rx_len, bool rx_esc,
				 bool rx_overflow);
int ble_uart_test_copy_state(struct ble_uart_test_state *state);
void ble_uart_test_set_tx_backend(uint16_t mtu, int notify_ret);
int ble_uart_test_copy_tx_state(struct ble_uart_test_tx_state *state);
#endif

#endif /* BLE_UART_H_ */
