/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef BLE_MESHCORE_H_
#define BLE_MESHCORE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Initialise the MeshCore-compatible BLE service and start advertising.
 * Must be called from a thread context because bt_enable() may block.
 */
int ble_meshcore_init(void);

/*
 * Drain one complete raw MeshCore command frame written by the app.
 * The MeshCore dispatcher/pump owns calling this API and producing responses;
 * the BLE transport intentionally does not parse or execute commands.
 * Returns 1 when a frame is copied, 0 when no frame is queued, or a negative
 * errno. Frames are copied exactly as received from BLE without serial/TCP
 * length headers.
 */
int ble_meshcore_dequeue_rx(uint8_t *frame, size_t buflen, size_t *out_len,
			    uint32_t *out_session_epoch);

/*
 * Queue one complete raw MeshCore response or push frame for the connected
 * app. The frame is copied into a fixed queue slot and notified when the app
 * enables the TX CCC. Returns -EMSGSIZE for oversize frames, -ENOMEM when the
 * queue is full, -ENOTCONN when no app session is active, or -ESTALE for a
 * stale guarded session.
 */
int ble_meshcore_enqueue_tx(const uint8_t *frame, size_t len);
int ble_meshcore_enqueue_tx_if_session(uint32_t session_epoch,
				       const uint8_t *frame, size_t len);

void ble_meshcore_reset_session(void);
int ble_meshcore_reset_session_if_epoch(uint32_t session_epoch);

uint32_t ble_meshcore_session_epoch(void);
bool ble_meshcore_session_active(void);
bool ble_meshcore_session_epoch_current(uint32_t session_epoch);

uint32_t ble_meshcore_tx_free(void);
uint32_t ble_meshcore_tx_capacity(void);

#ifdef CONFIG_ZTEST
int ble_meshcore_test_write_rx(const uint8_t *buf, size_t len);
int ble_meshcore_test_write_rx_conn(const uint8_t *buf, size_t len,
				    void *conn);
int ble_meshcore_test_set_tx_notify(bool enabled);
void ble_meshcore_test_connect(void);
void ble_meshcore_test_advance_owner_after_match(void *conn);
void ble_meshcore_test_disconnect(void);
#endif

#endif /* BLE_MESHCORE_H_ */
