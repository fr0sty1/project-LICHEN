/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef BLE_MESHTASTIC_H_
#define BLE_MESHTASTIC_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Initialise the Meshtastic-compatible BLE service and start advertising.
 * Must be called from a thread context because bt_enable() may block.
 */
int ble_meshtastic_init(void);

/*
 * Queue one complete raw FromRadio protobuf value for the connected app.
 * The payload is copied into a fixed queue slot and FromNum is notified when
 * a client is subscribed. Returns -EMSGSIZE for values above the Meshtastic
 * FromRadio protobuf budget and -ENOMEM when the queue is full.
 */
int ble_meshtastic_enqueue_from_radio(const uint8_t *from_radio, size_t len);

/*
 * Drain one complete raw ToRadio protobuf value written by the app.
 * Returns the copied byte count, 0 when no value is queued, or a negative errno.
 */
int ble_meshtastic_dequeue_to_radio(uint8_t *to_radio, size_t buflen);

#endif /* BLE_MESHTASTIC_H_ */
