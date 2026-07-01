/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef FAKE_BLE_MESHTASTIC_H_
#define FAKE_BLE_MESHTASTIC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void fake_ble_meshtastic_reset(size_t from_radio_cap);
void fake_ble_meshtastic_set_connected(bool connected);
void fake_ble_meshtastic_disconnect_on_next_enqueue(void);
size_t fake_ble_meshtastic_from_radio_count(void);
const uint8_t *fake_ble_meshtastic_from_radio(size_t index, size_t *len);

#endif /* FAKE_BLE_MESHTASTIC_H_ */
