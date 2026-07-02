/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef BLE_MESHTASTIC_H_
#define BLE_MESHTASTIC_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

struct bt_conn;

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
 * Returns 1 when a value is copied, 0 when no value is queued, or a negative
 * errno. Zero-length protobuf values are valid and reported through out_len.
 */
int ble_meshtastic_dequeue_to_radio(uint8_t *to_radio, size_t buflen,
				    size_t *out_len,
				    uint32_t *out_session_epoch);

/*
 * Clear queued app-session state after a polite ToRadio.disconnect.
 */
void ble_meshtastic_reset_session(void);
int ble_meshtastic_reset_session_if_epoch(uint32_t session_epoch);

uint32_t ble_meshtastic_session_epoch(void);
bool ble_meshtastic_session_active(void);
bool ble_meshtastic_session_epoch_current(uint32_t session_epoch);
int ble_meshtastic_enqueue_from_radio_if_session(uint32_t session_epoch,
						 const uint8_t *from_radio,
						 size_t len);

uint32_t ble_meshtastic_from_radio_free(void);
uint32_t ble_meshtastic_from_radio_capacity(void);

#ifdef CONFIG_ZTEST
int ble_meshtastic_test_read_from_radio(uint8_t *buf, size_t len,
					size_t offset);
int ble_meshtastic_test_write_to_radio(const uint8_t *buf, size_t len);
int ble_meshtastic_test_write_to_radio_conn(const uint8_t *buf, size_t len,
					    void *conn);
void ble_meshtastic_test_connect(void);
void ble_meshtastic_test_advance_owner_after_match(void *conn);
struct ble_meshtastic_test_from_num_notify_state {
	struct bt_conn *conn;
	uint8_t data[sizeof(uint32_t)];
	uint16_t len;
	uint32_t notify_count;
};
int ble_meshtastic_test_set_from_num_notify(bool enabled, int notify_ret);
int ble_meshtastic_test_copy_from_num_notify_state(
	struct ble_meshtastic_test_from_num_notify_state *state);
#endif

#endif /* BLE_MESHTASTIC_H_ */
