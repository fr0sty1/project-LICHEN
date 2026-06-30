/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef BLE_INGRESS_H_
#define BLE_INGRESS_H_

#include <stddef.h>
#include <stdint.h>

struct net_if;

/**
 * Inject one BLE-originated IPv6 packet into the Zephyr network ingress path.
 *
 * On success, ownership of the allocated net_pkt is transferred to the Zephyr
 * RX path. On failure, this function releases any packet buffer it allocated.
 */
int ble_ingress_ipv6(struct net_if *iface, const uint8_t *ipv6, size_t len);

/**
 * Inject through the default network interface.
 */
int ble_ingress_ipv6_default(const uint8_t *ipv6, size_t len);

#endif /* BLE_INGRESS_H_ */
