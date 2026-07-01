/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef FAKE_BLE_MESHCORE_H_
#define FAKE_BLE_MESHCORE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void fake_ble_meshcore_reset(uint32_t tx_cap);
int fake_ble_meshcore_push_rx(const uint8_t *frame, size_t len,
			      uint32_t session_epoch);
void fake_ble_meshcore_set_epoch(uint32_t session_epoch);
void fake_ble_meshcore_set_connected(bool connected);
void fake_ble_meshcore_disconnect_on_next_enqueue(void);
size_t fake_ble_meshcore_tx_count(void);
const uint8_t *fake_ble_meshcore_tx(size_t index, size_t *len);

#endif /* FAKE_BLE_MESHCORE_H_ */
