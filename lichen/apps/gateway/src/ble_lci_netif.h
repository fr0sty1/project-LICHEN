/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef BLE_LCI_NETIF_H_
#define BLE_LCI_NETIF_H_

#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/net_if.h>

struct net_if *ble_lci_netif_get(void);
int ble_lci_netif_send_ipv6(const uint8_t *ipv6, size_t len);

#ifdef CONFIG_ZTEST
int ble_lci_netif_test_send_ipv6(const uint8_t *ipv6, size_t len);
#endif

#endif /* BLE_LCI_NETIF_H_ */
