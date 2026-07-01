/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef BLE_APP_OWNER_H_
#define BLE_APP_OWNER_H_

#include <stddef.h>
#include <stdbool.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>

enum ble_app_owner_surface {
	BLE_APP_OWNER_SURFACE_NATIVE,
	BLE_APP_OWNER_SURFACE_MESHTASTIC,
	BLE_APP_OWNER_SURFACE_MESHCORE,
};

typedef int (*ble_app_owner_prepare_fn)(void);
typedef void (*ble_app_owner_connected_fn)(struct bt_conn *conn, uint8_t err,
					   uint32_t generation);
typedef void (*ble_app_owner_disconnected_fn)(struct bt_conn *conn,
					      uint8_t reason,
					      uint32_t generation);

struct ble_app_owner_advertising {
	enum ble_app_owner_surface surface;
	const struct bt_data *ad;
	size_t ad_len;
	const struct bt_data *sd;
	size_t sd_len;
	const char *name;
	ble_app_owner_prepare_fn prepare;
	ble_app_owner_connected_fn connected;
	ble_app_owner_disconnected_fn disconnected;
};

int ble_app_owner_start(const struct ble_app_owner_advertising *adv);
int ble_app_owner_stop(enum ble_app_owner_surface surface);
int ble_app_owner_restart(enum ble_app_owner_surface surface);
int ble_app_owner_conn_ref(enum ble_app_owner_surface surface,
			   struct bt_conn **conn);
void ble_app_owner_conn_unref(struct bt_conn *conn);
uint32_t ble_app_owner_conn_generation(enum ble_app_owner_surface surface);
bool ble_app_owner_conn_matches(enum ble_app_owner_surface surface,
				const struct bt_conn *conn,
				uint32_t *generation);

#ifdef CONFIG_ZTEST
struct ble_app_owner_test_state {
	uint32_t enable_count;
	uint32_t adv_start_count;
	uint32_t adv_stop_count;
	uint32_t adv_options;
	enum ble_app_owner_surface surface;
	const struct bt_data *ad;
	size_t ad_len;
	const struct bt_data *sd;
	size_t sd_len;
	bool has_surface;
	bool has_connected;
	bool has_disconnected;
	bool has_connection;
	uint32_t conn_ref_count;
	uint32_t conn_unref_count;
};

void ble_app_owner_test_reset(void);
void ble_app_owner_test_set_backend(int enable_ret, int adv_start_ret,
				    int adv_stop_ret);
int ble_app_owner_test_copy_state(struct ble_app_owner_test_state *state);
int ble_app_owner_test_validate_modes(bool native, bool meshtastic,
				      bool meshcore);
int ble_app_owner_test_validate_advertising(
	const struct ble_app_owner_advertising *adv);
void ble_app_owner_test_connected(struct bt_conn *conn, uint8_t err);
void ble_app_owner_test_disconnected(struct bt_conn *conn, uint8_t reason);
#endif

#endif /* BLE_APP_OWNER_H_ */
