/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef BLE_UART_H_
#define BLE_UART_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include <zephyr/bluetooth/conn.h>

/**
 * Initialise the BLE stack and start advertising the native BLE LCI service.
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
	uint8_t data[128];
	uint16_t len;
	uint16_t total_len;
	uint32_t notify_count;
};

struct ble_uart_test_profile {
	uint8_t service_uuid[16];
	uint8_t rx_uuid[16];
	uint8_t tx_uuid[16];
	uint8_t version_uuid[16];
	uint8_t capabilities_uuid[16];
	uint8_t version[2];
	uint8_t capabilities[4];
	bool legacy_nus;
	bool has_version_capabilities;
};

struct ble_uart_test_gatt_shape {
	size_t attr_count;
	uint8_t service_uuid[16];
	uint8_t rx_chrc_uuid[16];
	uint8_t rx_value_uuid[16];
	uint8_t tx_chrc_uuid[16];
	uint8_t tx_value_uuid[16];
	uint8_t version_chrc_uuid[16];
	uint8_t version_value_uuid[16];
	uint8_t capabilities_chrc_uuid[16];
	uint8_t capabilities_value_uuid[16];
	uint8_t rx_chrc_props;
	uint8_t tx_chrc_props;
	uint8_t version_chrc_props;
	uint8_t capabilities_chrc_props;
	uint16_t rx_value_perm;
	uint16_t tx_value_perm;
	uint16_t tx_ccc_perm;
	uint16_t version_value_perm;
	uint16_t capabilities_value_perm;
	bool rx_has_write;
	bool tx_has_read_write;
	bool version_has_read;
	bool capabilities_has_read;
};

int ble_uart_test_copy_profile(struct ble_uart_test_profile *profile);
int ble_uart_test_copy_gatt_shape(struct ble_uart_test_gatt_shape *shape);
ssize_t ble_uart_test_write_rx(struct bt_conn *conn, const uint8_t *data,
			       uint16_t len);
ssize_t ble_uart_test_read_version(uint8_t *buf, uint16_t len,
				   uint16_t offset);
ssize_t ble_uart_test_read_capabilities(uint8_t *buf, uint16_t len,
					uint16_t offset);
void ble_uart_test_seed_rx_state(uint16_t rx_len, bool rx_esc,
				 bool rx_overflow);
int ble_uart_test_copy_state(struct ble_uart_test_state *state);
void ble_uart_test_set_tx_backend(uint16_t mtu, int notify_ret);
int ble_uart_test_copy_tx_state(struct ble_uart_test_tx_state *state);
#endif

#endif /* BLE_UART_H_ */
