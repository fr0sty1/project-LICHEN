/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
#pragma once

#include <stddef.h>
#include <stdint.h>

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
 * Returns 0, -ENOTCONN if no phone is connected, or negative errno.
 */
int ble_uart_send_slip(const uint8_t *ipv6, size_t len);
