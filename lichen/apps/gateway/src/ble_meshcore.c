/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
/*
 * MeshCore-compatible BLE GATT surface.
 *
 * BLE carries one raw MeshCore inner frame per GATT write/notification. The
 * serial/TCP 0x3c/0x3e length headers are not valid on BLE and are rejected
 * before frames enter the dispatcher queue.
 */

#include "ble_app_owner.h"
#include "ble_meshcore.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/bluetooth/att.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include <lichen/meshcore/limits.h>

LOG_MODULE_REGISTER(ble_meshcore, LOG_LEVEL_INF);

/* MeshCore BLE uses the Nordic UART Service UUID triplet exactly. */
#define BT_UUID_NUS_VAL \
	BT_UUID_128_ENCODE(0x6e400001, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)
#define BT_UUID_NUS_RX_VAL \
	BT_UUID_128_ENCODE(0x6e400002, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)
#define BT_UUID_NUS_TX_VAL \
	BT_UUID_128_ENCODE(0x6e400003, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)

#define MESHCORE_QUEUE_DEPTH CONFIG_LORA_LICHEN_MESHCORE_BLE_QUEUE_DEPTH
#define MESHCORE_SERIAL_MAGIC0 0x3cU
#define MESHCORE_SERIAL_MAGIC1 0x3eU

#if defined(CONFIG_ZTEST)
#define MESHCORE_RX_PERM BT_GATT_PERM_WRITE
#define MESHCORE_TX_CCC_PERM (BT_GATT_PERM_READ | BT_GATT_PERM_WRITE)
#else
#define MESHCORE_RX_PERM BT_GATT_PERM_WRITE_AUTHEN
#define MESHCORE_TX_CCC_PERM (BT_GATT_PERM_READ_AUTHEN | BT_GATT_PERM_WRITE_AUTHEN)
#endif

struct meshcore_frame_slot {
	uint8_t data[LICHEN_MESHCORE_FRAME_MAX];
	uint16_t len;
	uint32_t session_epoch;
};

static struct bt_uuid_128 nus_svc_uuid = BT_UUID_INIT_128(BT_UUID_NUS_VAL);
static struct bt_uuid_128 nus_rx_uuid = BT_UUID_INIT_128(BT_UUID_NUS_RX_VAL);
static struct bt_uuid_128 nus_tx_uuid = BT_UUID_INIT_128(BT_UUID_NUS_TX_VAL);

static K_MUTEX_DEFINE(s_conn_mutex);
static uint32_t s_session_epoch;
static bool s_session_active;
static uint32_t s_owner_generation;

static K_MUTEX_DEFINE(s_rx_mutex);
static struct meshcore_frame_slot s_rx_queue[MESHCORE_QUEUE_DEPTH];
static uint8_t s_rx_head;
static uint8_t s_rx_tail;
static uint8_t s_rx_count;

static K_MUTEX_DEFINE(s_tx_mutex);
static struct meshcore_frame_slot s_tx_queue[MESHCORE_QUEUE_DEPTH];
static uint8_t s_tx_head;
static uint8_t s_tx_tail;
static uint8_t s_tx_count;
static bool s_tx_notify_enabled;

static void reset_session_locked(void);
static void notify_tx(void);
#ifdef CONFIG_ZTEST
static bool s_test_advance_owner_after_match;
static struct bt_conn *s_test_advance_owner_conn;
#endif

static uint32_t session_epoch_locked(void)
{
	return s_session_epoch;
}

static void session_epoch_bump_locked(void)
{
	s_session_epoch++;
}

static bool has_serial_header(const uint8_t *data, size_t len)
{
	return len >= 3U &&
	       (data[0] == MESHCORE_SERIAL_MAGIC0 ||
		data[0] == MESHCORE_SERIAL_MAGIC1) &&
	       sys_get_le16(&data[1]) == len - 3U;
}

static int conn_ref_get(struct bt_conn **out)
{
	return ble_app_owner_conn_ref(BLE_APP_OWNER_SURFACE_MESHCORE, out);
}

static bool owner_conn_matches_with_generation(struct bt_conn *conn,
					       uint32_t *generation)
{
	return ble_app_owner_conn_matches(BLE_APP_OWNER_SURFACE_MESHCORE,
					  conn, generation);
}

static bool owner_generation_current(uint32_t generation)
{
	return generation != 0U && s_owner_generation == generation;
}

static void maybe_test_advance_owner_after_match(void)
{
#ifdef CONFIG_ZTEST
	if (s_test_advance_owner_after_match) {
		s_test_advance_owner_after_match = false;
		ble_app_owner_test_disconnected(s_test_advance_owner_conn, 19U);
		ble_app_owner_test_connected((struct bt_conn *)0x7, 0U);
	}
#endif
}

static ssize_t nus_rx_write(struct bt_conn *conn,
			    const struct bt_gatt_attr *attr,
			    const void *buf, uint16_t len,
			    uint16_t offset, uint8_t flags)
{
	const uint8_t *data = buf;
	uint32_t owner_generation = 0U;

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (data == NULL || len == 0U || len > LICHEN_MESHCORE_FRAME_MAX ||
	    has_serial_header(data, len)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	if (offset != 0U) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

#ifdef CONFIG_ZTEST
	if (conn != NULL &&
	    !owner_conn_matches_with_generation(conn, &owner_generation)) {
#else
	if (conn == NULL ||
	    !owner_conn_matches_with_generation(conn, &owner_generation)) {
#endif
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	maybe_test_advance_owner_after_match();
	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	if (conn != NULL && !owner_generation_current(owner_generation)) {
		k_mutex_unlock(&s_conn_mutex);
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}
	k_mutex_lock(&s_rx_mutex, K_FOREVER);
	if (s_rx_count == ARRAY_SIZE(s_rx_queue)) {
		k_mutex_unlock(&s_rx_mutex);
		k_mutex_unlock(&s_conn_mutex);
		return BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES);
	}

	memcpy(s_rx_queue[s_rx_tail].data, data, len);
	s_rx_queue[s_rx_tail].len = len;
	s_rx_queue[s_rx_tail].session_epoch = session_epoch_locked();
	s_rx_tail = (s_rx_tail + 1U) % ARRAY_SIZE(s_rx_queue);
	s_rx_count++;
	k_mutex_unlock(&s_rx_mutex);
	k_mutex_unlock(&s_conn_mutex);

	LOG_DBG("Queued MeshCore RX frame %u B", len);
	return len;
}

static void nus_tx_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	s_tx_notify_enabled = (value == BT_GATT_CCC_NOTIFY);
	k_mutex_unlock(&s_tx_mutex);

	LOG_INF("MeshCore TX notify %s",
		(value == BT_GATT_CCC_NOTIFY) ? "enabled" : "disabled");
	if (value == BT_GATT_CCC_NOTIFY) {
		notify_tx();
	}
}

/*
 * GATT attribute layout:
 *   0 service
 *   1 RX declaration
 *   2 RX value
 *   3 TX declaration
 *   4 TX value
 *   5 TX CCCD
 */
#define NUS_TX_VAL_IDX 4

BT_GATT_SERVICE_DEFINE(meshcore_svc,
	BT_GATT_PRIMARY_SERVICE(&nus_svc_uuid),
	BT_GATT_CHARACTERISTIC(&nus_rx_uuid.uuid,
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP,
			       MESHCORE_RX_PERM,
			       NULL, nus_rx_write, NULL),
	BT_GATT_CHARACTERISTIC(&nus_tx_uuid.uuid,
			       BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_NONE,
			       NULL, NULL, NULL),
	BT_GATT_CCC(nus_tx_ccc_changed, MESHCORE_TX_CCC_PERM),
);

static int tx_peek_locked(uint8_t *buf, size_t buflen, uint16_t *out_len)
{
	uint16_t len;

	if (s_tx_count == 0U) {
		*out_len = 0U;
		return 0;
	}

	len = s_tx_queue[s_tx_head].len;
	if (buflen < len) {
		return -ENOMEM;
	}

	memcpy(buf, s_tx_queue[s_tx_head].data, len);
	*out_len = len;
	return 1;
}

static void tx_pop_locked(void)
{
	if (s_tx_count == 0U) {
		return;
	}

	s_tx_head = (s_tx_head + 1U) % ARRAY_SIZE(s_tx_queue);
	s_tx_count--;
}

static void notify_tx(void)
{
	struct bt_conn *conn;
	uint8_t frame[LICHEN_MESHCORE_FRAME_MAX];
	uint16_t len = 0U;
	bool notify;
	int ret;

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	notify = s_tx_notify_enabled;
	ret = tx_peek_locked(frame, sizeof(frame), &len);
	k_mutex_unlock(&s_tx_mutex);

	if (!notify || ret <= 0 || conn_ref_get(&conn) < 0) {
		return;
	}

	ret = bt_gatt_notify(conn, &meshcore_svc.attrs[NUS_TX_VAL_IDX],
			     frame, len);
	ble_app_owner_conn_unref(conn);
	if (ret < 0) {
		LOG_WRN("MeshCore TX notify failed: %d", ret);
		return;
	}

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	tx_pop_locked();
	k_mutex_unlock(&s_tx_mutex);
}

static const struct bt_data s_ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_NUS_VAL),
};

static const struct bt_data s_sd[] = {
	BT_DATA(BT_DATA_NAME_SHORTENED, CONFIG_LORA_LICHEN_MESHCORE_BLE_NAME,
		sizeof(CONFIG_LORA_LICHEN_MESHCORE_BLE_NAME) - 1U),
};

int ble_meshcore_set_passkey(uint32_t passkey)
{
	if (passkey != 0U && (passkey < 100000U || passkey > 999999U)) {
		return -EINVAL;
	}
#if defined(CONFIG_BT_FIXED_PASSKEY) && !defined(CONFIG_ZTEST)
	return bt_passkey_set(passkey == 0U ? BT_PASSKEY_INVALID : passkey);
#else
	ARG_UNUSED(passkey);
	return 0;
#endif
}

static int prepare_meshcore(void)
{
#if defined(CONFIG_BT_FIXED_PASSKEY) && !defined(CONFIG_ZTEST)
	int err = ble_meshcore_set_passkey(
		CONFIG_LORA_LICHEN_MESHCORE_BLE_PASSKEY);

	if (err) {
		LOG_ERR("MeshCore BLE passkey setup failed: %d", err);
		return err;
	}
#endif
	return 0;
}

static void on_connected(struct bt_conn *conn, uint8_t err,
			 uint32_t generation)
{
	ARG_UNUSED(conn);

	if (err) {
		LOG_ERR("MeshCore BLE connect error %u", err);
		return;
	}

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	s_session_active = true;
	s_owner_generation = generation;
	session_epoch_bump_locked();
	k_mutex_unlock(&s_conn_mutex);

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	s_tx_notify_enabled = false;
	k_mutex_unlock(&s_tx_mutex);

	LOG_INF("MeshCore BLE client connected");
}

static void on_disconnected(struct bt_conn *conn, uint8_t reason,
			    uint32_t generation)
{
	ARG_UNUSED(conn);

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	s_session_active = false;
	s_owner_generation = generation;
	reset_session_locked();
	k_mutex_unlock(&s_conn_mutex);

	LOG_INF("MeshCore BLE client disconnected (reason %u)", reason);
	(void)ble_app_owner_restart(BLE_APP_OWNER_SURFACE_MESHCORE);
}

int ble_meshcore_dequeue_rx(uint8_t *frame, size_t buflen, size_t *out_len,
			    uint32_t *out_session_epoch)
{
	uint16_t len;

	if (frame == NULL || out_len == NULL || out_session_epoch == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_rx_mutex, K_FOREVER);
	if (s_rx_count == 0U) {
		k_mutex_unlock(&s_rx_mutex);
		return 0;
	}

	len = s_rx_queue[s_rx_head].len;
	if (buflen < len) {
		k_mutex_unlock(&s_rx_mutex);
		return -ENOMEM;
	}

	memcpy(frame, s_rx_queue[s_rx_head].data, len);
	*out_session_epoch = s_rx_queue[s_rx_head].session_epoch;
	s_rx_head = (s_rx_head + 1U) % ARRAY_SIZE(s_rx_queue);
	s_rx_count--;
	k_mutex_unlock(&s_rx_mutex);

	*out_len = len;
	return 1;
}

static int enqueue_tx_locked(const uint8_t *frame, size_t len)
{
	if (frame == NULL || len == 0U) {
		return -EINVAL;
	}
	if (len > LICHEN_MESHCORE_FRAME_MAX || has_serial_header(frame, len)) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	if (s_tx_count == ARRAY_SIZE(s_tx_queue)) {
		k_mutex_unlock(&s_tx_mutex);
		return -ENOMEM;
	}

	memcpy(s_tx_queue[s_tx_tail].data, frame, len);
	s_tx_queue[s_tx_tail].len = len;
	s_tx_queue[s_tx_tail].session_epoch = session_epoch_locked();
	s_tx_tail = (s_tx_tail + 1U) % ARRAY_SIZE(s_tx_queue);
	s_tx_count++;
	k_mutex_unlock(&s_tx_mutex);

	return 0;
}

int ble_meshcore_enqueue_tx(const uint8_t *frame, size_t len)
{
	int ret;

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	if (!s_session_active) {
		k_mutex_unlock(&s_conn_mutex);
		return -ENOTCONN;
	}
	ret = enqueue_tx_locked(frame, len);
	k_mutex_unlock(&s_conn_mutex);
	if (ret < 0) {
		return ret;
	}

	notify_tx();
	return 0;
}

int ble_meshcore_enqueue_tx_if_session(uint32_t session_epoch,
				       const uint8_t *frame, size_t len)
{
	int ret;

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	if (session_epoch_locked() != session_epoch) {
		k_mutex_unlock(&s_conn_mutex);
		return -ESTALE;
	}
	if (!s_session_active) {
		k_mutex_unlock(&s_conn_mutex);
		return -ENOTCONN;
	}
	ret = enqueue_tx_locked(frame, len);
	k_mutex_unlock(&s_conn_mutex);
	if (ret < 0) {
		return ret;
	}

	notify_tx();
	return 0;
}

uint32_t ble_meshcore_session_epoch(void)
{
	uint32_t epoch;

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	epoch = session_epoch_locked();
	k_mutex_unlock(&s_conn_mutex);

	return epoch;
}

bool ble_meshcore_session_active(void)
{
	bool active;

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	active = s_session_active;
	k_mutex_unlock(&s_conn_mutex);

	return active;
}

bool ble_meshcore_session_epoch_current(uint32_t session_epoch)
{
	bool current;

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	current = session_epoch_locked() == session_epoch;
	k_mutex_unlock(&s_conn_mutex);

	return current;
}

static void reset_session_locked(void)
{
	session_epoch_bump_locked();

	k_mutex_lock(&s_rx_mutex, K_FOREVER);
	s_rx_head = 0U;
	s_rx_tail = 0U;
	s_rx_count = 0U;
	k_mutex_unlock(&s_rx_mutex);

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	s_tx_head = 0U;
	s_tx_tail = 0U;
	s_tx_count = 0U;
	s_tx_notify_enabled = false;
	k_mutex_unlock(&s_tx_mutex);
}

void ble_meshcore_reset_session(void)
{
	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	s_session_active = false;
	s_owner_generation = 0U;
	reset_session_locked();
	k_mutex_unlock(&s_conn_mutex);
}

int ble_meshcore_reset_session_if_epoch(uint32_t session_epoch)
{
	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	if (session_epoch_locked() != session_epoch) {
		k_mutex_unlock(&s_conn_mutex);
		return -ESTALE;
	}

	reset_session_locked();
	k_mutex_unlock(&s_conn_mutex);
	return 0;
}

uint32_t ble_meshcore_tx_free(void)
{
	uint32_t free_slots;

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	free_slots = ARRAY_SIZE(s_tx_queue) - s_tx_count;
	k_mutex_unlock(&s_tx_mutex);

	return free_slots;
}

uint32_t ble_meshcore_tx_capacity(void)
{
	return ARRAY_SIZE(s_tx_queue);
}

#ifdef CONFIG_ZTEST
int ble_meshcore_test_write_rx(const uint8_t *buf, size_t len)
{
	if (len > UINT16_MAX) {
		return -EINVAL;
	}

	return nus_rx_write(NULL, NULL, buf, (uint16_t)len, 0U, 0U);
}

int ble_meshcore_test_write_rx_conn(const uint8_t *buf, size_t len, void *conn)
{
	if (len > UINT16_MAX) {
		return -EINVAL;
	}

	return nus_rx_write(conn, NULL, buf, (uint16_t)len, 0U, 0U);
}

int ble_meshcore_test_set_tx_notify(bool enabled)
{
	nus_tx_ccc_changed(NULL, enabled ? BT_GATT_CCC_NOTIFY : 0U);
	return 0;
}

void ble_meshcore_test_connect(void)
{
	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	s_session_active = true;
	session_epoch_bump_locked();
	k_mutex_unlock(&s_conn_mutex);
}

void ble_meshcore_test_advance_owner_after_match(void *conn)
{
	s_test_advance_owner_after_match = true;
	s_test_advance_owner_conn = conn;
}

void ble_meshcore_test_disconnect(void)
{
	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	s_session_active = false;
	reset_session_locked();
	k_mutex_unlock(&s_conn_mutex);
}
#endif

int ble_meshcore_init(void)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_MESHCORE,
		.ad = s_ad,
		.ad_len = ARRAY_SIZE(s_ad),
		.sd = s_sd,
		.sd_len = ARRAY_SIZE(s_sd),
		.name = CONFIG_LORA_LICHEN_MESHCORE_BLE_NAME,
		.prepare = prepare_meshcore,
		.connected = on_connected,
		.disconnected = on_disconnected,
	};

	return ble_app_owner_start(&adv);
}
