/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
/*
 * Meshtastic-compatible BLE GATT surface.
 *
 * BLE carries one raw protobuf value per GATT operation. Serial/TCP StreamAPI
 * length headers are rejected here so the dispatcher only sees ToRadio bytes.
 */

#include "ble_app_owner.h"
#include "ble_meshtastic.h"

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

#include <lichen/meshtastic/codec.h>

LOG_MODULE_REGISTER(ble_meshtastic, LOG_LEVEL_INF);

#define BT_UUID_MESH_SVC_VAL \
	BT_UUID_128_ENCODE(0x6ba1b218, 0x15a8, 0x461f, 0x9fa8, 0x5dcae273eafd)
#define BT_UUID_MESH_TORADIO_VAL \
	BT_UUID_128_ENCODE(0xf75c76d2, 0x129e, 0x4dad, 0xa1dd, 0x7866124401e7)
#define BT_UUID_MESH_FROMRADIO_VAL \
	BT_UUID_128_ENCODE(0x2c55e69e, 0x4993, 0x11ed, 0xb878, 0x0242ac120002)
#define BT_UUID_MESH_FROMNUM_VAL \
	BT_UUID_128_ENCODE(0xed9da18c, 0xa800, 0x4f66, 0xa670, 0xaa7547e34453)

#define MESHTASTIC_FROM_RADIO_QUEUE_DEPTH CONFIG_LORA_LICHEN_MESHTASTIC_BLE_QUEUE_DEPTH
#define MESHTASTIC_TO_RADIO_QUEUE_DEPTH \
	CONFIG_LORA_LICHEN_MESHTASTIC_BLE_TO_RADIO_QUEUE_DEPTH
#define MESHTASTIC_STREAM_MAGIC0 0x94U
#define MESHTASTIC_STREAM_MAGIC1 0xc3U
#define MESHTASTIC_ADV_NAME "LICHEN"

struct msg_slot {
	uint8_t data[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
	uint16_t len;
	uint32_t num;
};

struct to_radio_slot {
	uint8_t data[LICHEN_MESHTASTIC_TO_RADIO_MAX];
	uint16_t len;
	uint32_t session_epoch;
};

static struct bt_uuid_128 mesh_svc_uuid = BT_UUID_INIT_128(BT_UUID_MESH_SVC_VAL);
static struct bt_uuid_128 to_radio_uuid = BT_UUID_INIT_128(BT_UUID_MESH_TORADIO_VAL);
static struct bt_uuid_128 from_radio_uuid = BT_UUID_INIT_128(BT_UUID_MESH_FROMRADIO_VAL);
static struct bt_uuid_128 from_num_uuid = BT_UUID_INIT_128(BT_UUID_MESH_FROMNUM_VAL);

static K_MUTEX_DEFINE(s_conn_mutex);
static uint32_t s_session_epoch;
static bool s_session_active;
static uint32_t s_owner_generation;

static K_MUTEX_DEFINE(s_rx_mutex);
static struct to_radio_slot s_rx_queue[MESHTASTIC_TO_RADIO_QUEUE_DEPTH];
static uint8_t s_rx_head;
static uint8_t s_rx_tail;
static uint8_t s_rx_count;

static K_MUTEX_DEFINE(s_tx_mutex);
static struct msg_slot s_tx_queue[MESHTASTIC_FROM_RADIO_QUEUE_DEPTH];
static uint8_t s_tx_head;
static uint8_t s_tx_tail;
static uint8_t s_tx_count;
static uint32_t s_from_num;
static bool s_from_num_notify_enabled;

static uint8_t s_read_buf[LICHEN_MESHTASTIC_FROM_RADIO_MAX];
static uint16_t s_read_len;
static uint16_t s_read_next_offset;
static uint8_t s_read_slot;
static bool s_read_active;

static void reset_session_locked(void);
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

static bool has_stream_prefix(const uint8_t *data, size_t len)
{
	return len >= 2U && data[0] == MESHTASTIC_STREAM_MAGIC0 &&
	       data[1] == MESHTASTIC_STREAM_MAGIC1;
}

static bool from_num_before(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b) < 0;
}

static int conn_ref_get(struct bt_conn **out)
{
	return ble_app_owner_conn_ref(BLE_APP_OWNER_SURFACE_MESHTASTIC, out);
}

static bool owner_conn_matches_with_generation(struct bt_conn *conn,
					       uint32_t *generation)
{
	return ble_app_owner_conn_matches(BLE_APP_OWNER_SURFACE_MESHTASTIC,
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

static ssize_t to_radio_write(struct bt_conn *conn,
			      const struct bt_gatt_attr *attr,
			      const void *buf, uint16_t len,
			      uint16_t offset, uint8_t flags)
{
	struct lichen_meshtastic_to_radio decoded;
	const uint8_t *data = buf;
	uint32_t owner_generation = 0U;
	int ret;

	ARG_UNUSED(conn);
	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (data == NULL && len > 0U) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	if ((size_t)offset + len > LICHEN_MESHTASTIC_TO_RADIO_MAX ||
	    (offset == 0U && has_stream_prefix(data, len))) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	if (flags & BT_GATT_WRITE_FLAG_PREPARE) {
		return 0;
	}
	if (offset != 0U) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	ret = lichen_meshtastic_decode_to_radio(data, len, &decoded);
	if (ret < 0 && ret != -ENODATA) {
		LOG_WRN("Meshtastic ToRadio rejected: %d", ret);
		return BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED);
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

	LOG_DBG("Queued Meshtastic ToRadio %u B", len);
	return len;
}

static int from_radio_peek_locked(uint8_t *buf, size_t buflen, uint8_t *slot)
{
	uint16_t len;

	if (s_tx_count == 0U) {
		return 0;
	}

	len = s_tx_queue[s_tx_head].len;
	if (buflen < len) {
		return -ENOMEM;
	}

	memcpy(buf, s_tx_queue[s_tx_head].data, len);
	*slot = s_tx_head;
	return len;
}

static void from_radio_pop_read_slot_locked(void)
{
	if (s_tx_count > 0U && s_read_slot == s_tx_head) {
		s_tx_head = (s_tx_head + 1U) % ARRAY_SIZE(s_tx_queue);
		s_tx_count--;
	}
}

static ssize_t from_radio_read(struct bt_conn *conn,
			       const struct bt_gatt_attr *attr,
			       void *buf, uint16_t len,
			       uint16_t offset)
{
	int ret;

	ARG_UNUSED(conn);
	ARG_UNUSED(attr);

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	if (offset == 0U) {
		ret = from_radio_peek_locked(s_read_buf, sizeof(s_read_buf),
					     &s_read_slot);
		if (ret < 0) {
			k_mutex_unlock(&s_tx_mutex);
			return BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES);
		}
		s_read_len = (uint16_t)ret;
		s_read_next_offset = 0U;
		s_read_active = ret > 0;
	} else if (!s_read_active || offset != s_read_next_offset) {
		k_mutex_unlock(&s_tx_mutex);
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	ret = bt_gatt_attr_read(conn, attr, buf, len, offset, s_read_buf, s_read_len);
	if (ret >= 0 && ((uint16_t)ret < len ||
			 (uint32_t)offset + (uint32_t)ret >= s_read_len)) {
		from_radio_pop_read_slot_locked();
		s_read_active = false;
		s_read_len = 0U;
		s_read_next_offset = 0U;
	} else if (ret > 0) {
		s_read_next_offset = offset + (uint16_t)ret;
	}
	k_mutex_unlock(&s_tx_mutex);

	return ret;
}

#ifdef CONFIG_ZTEST
int ble_meshtastic_test_read_from_radio(uint8_t *buf, size_t len,
					size_t offset)
{
	if (len > UINT16_MAX || offset > UINT16_MAX) {
		return -EINVAL;
	}

	return from_radio_read(NULL, NULL, buf, (uint16_t)len,
			       (uint16_t)offset);
}

int ble_meshtastic_test_write_to_radio(const uint8_t *buf, size_t len)
{
	if (len > UINT16_MAX) {
		return -EINVAL;
	}

	return to_radio_write(NULL, NULL, buf, (uint16_t)len, 0U, 0U);
}

int ble_meshtastic_test_write_to_radio_conn(const uint8_t *buf, size_t len,
					    void *conn)
{
	if (len > UINT16_MAX) {
		return -EINVAL;
	}

	return to_radio_write(conn, NULL, buf, (uint16_t)len, 0U, 0U);
}

void ble_meshtastic_test_connect(void)
{
	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	s_session_active = true;
	session_epoch_bump_locked();
	k_mutex_unlock(&s_conn_mutex);
}

void ble_meshtastic_test_advance_owner_after_match(void *conn)
{
	s_test_advance_owner_after_match = true;
	s_test_advance_owner_conn = conn;
}
#endif

static ssize_t from_num_read(struct bt_conn *conn,
			     const struct bt_gatt_attr *attr,
			     void *buf, uint16_t len,
			     uint16_t offset)
{
	uint8_t value[sizeof(uint32_t)];

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	sys_put_le32(s_from_num, value);
	k_mutex_unlock(&s_tx_mutex);

	return bt_gatt_attr_read(conn, attr, buf, len, offset, value, sizeof(value));
}

static ssize_t from_num_write(struct bt_conn *conn,
			      const struct bt_gatt_attr *attr,
			      const void *buf, uint16_t len,
			      uint16_t offset, uint8_t flags)
{
	const uint8_t *data = buf;

	ARG_UNUSED(conn);
	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (offset != 0U) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}
	if (data == NULL || len != sizeof(uint32_t)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	uint32_t requested = sys_get_le32(data);

	while (s_tx_count > 0U && from_num_before(s_tx_queue[s_tx_head].num, requested)) {
		s_tx_head = (s_tx_head + 1U) % ARRAY_SIZE(s_tx_queue);
		s_tx_count--;
	}
	s_read_active = false;
	s_read_len = 0U;
	s_read_slot = 0U;
	k_mutex_unlock(&s_tx_mutex);

	return len;
}

static void from_num_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	s_from_num_notify_enabled = (value == BT_GATT_CCC_NOTIFY);
	k_mutex_unlock(&s_tx_mutex);

	LOG_INF("Meshtastic FromNum notify %s",
		(value == BT_GATT_CCC_NOTIFY) ? "enabled" : "disabled");
}

/*
 * GATT attribute layout:
 *   0 service
 *   1 ToRadio declaration
 *   2 ToRadio value
 *   3 FromRadio declaration
 *   4 FromRadio value
 *   5 FromNum declaration
 *   6 FromNum value
 *   7 FromNum CCCD
 */
#define FROM_NUM_VAL_IDX 6

BT_GATT_SERVICE_DEFINE(meshtastic_svc,
	BT_GATT_PRIMARY_SERVICE(&mesh_svc_uuid),
	BT_GATT_CHARACTERISTIC(&to_radio_uuid.uuid,
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP,
			       BT_GATT_PERM_WRITE | BT_GATT_PERM_PREPARE_WRITE,
			       NULL, to_radio_write, NULL),
	BT_GATT_CHARACTERISTIC(&from_radio_uuid.uuid,
			       BT_GATT_CHRC_READ,
			       BT_GATT_PERM_READ,
			       from_radio_read, NULL, NULL),
	BT_GATT_CHARACTERISTIC(&from_num_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE |
			       BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			       from_num_read, from_num_write, NULL),
	BT_GATT_CCC(from_num_ccc_changed,
		    BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
);

static void notify_from_num(void)
{
	struct bt_conn *conn;
	uint8_t value[sizeof(uint32_t)];
	bool notify;

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	sys_put_le32(s_from_num, value);
	notify = s_from_num_notify_enabled;
	k_mutex_unlock(&s_tx_mutex);

	if (!notify || conn_ref_get(&conn) < 0) {
		return;
	}

	(void)bt_gatt_notify(conn, &meshtastic_svc.attrs[FROM_NUM_VAL_IDX],
			     value, sizeof(value));
	ble_app_owner_conn_unref(conn);
}

static const struct bt_data s_ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_MESH_SVC_VAL),
};

static const struct bt_data s_sd[] = {
	BT_DATA(BT_DATA_NAME_SHORTENED, MESHTASTIC_ADV_NAME,
		sizeof(MESHTASTIC_ADV_NAME) - 1U),
};

static void on_connected(struct bt_conn *conn, uint8_t err,
			 uint32_t generation)
{
	ARG_UNUSED(conn);

	if (err) {
		LOG_ERR("Meshtastic BLE connect error %u", err);
		return;
	}

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	s_session_active = true;
	s_owner_generation = generation;
	session_epoch_bump_locked();
	k_mutex_unlock(&s_conn_mutex);

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	s_read_active = false;
	s_read_len = 0U;
	s_read_next_offset = 0U;
	s_read_slot = 0U;
	k_mutex_unlock(&s_tx_mutex);

	LOG_INF("Meshtastic BLE client connected");
}

static void on_disconnected(struct bt_conn *conn, uint8_t reason,
			    uint32_t generation)
{
	ARG_UNUSED(conn);

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	s_session_active = false;
	s_owner_generation = generation;
	reset_session_locked();

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	s_from_num_notify_enabled = false;
	k_mutex_unlock(&s_tx_mutex);
	k_mutex_unlock(&s_conn_mutex);

	LOG_INF("Meshtastic BLE client disconnected (reason %u)", reason);
	(void)ble_app_owner_restart(BLE_APP_OWNER_SURFACE_MESHTASTIC);
}

static int enqueue_from_radio_locked(const uint8_t *from_radio, size_t len)
{
	if (from_radio == NULL && len > 0U) {
		return -EINVAL;
	}
	if (len > LICHEN_MESHTASTIC_FROM_RADIO_MAX) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	if (s_tx_count == ARRAY_SIZE(s_tx_queue)) {
		k_mutex_unlock(&s_tx_mutex);
		return -ENOMEM;
	}

	if (len > 0U) {
		memcpy(s_tx_queue[s_tx_tail].data, from_radio, len);
	}
	s_tx_queue[s_tx_tail].len = len;
	s_tx_queue[s_tx_tail].num = s_from_num + 1U;
	s_tx_tail = (s_tx_tail + 1U) % ARRAY_SIZE(s_tx_queue);
	s_tx_count++;
	s_from_num++;
	k_mutex_unlock(&s_tx_mutex);

	return 0;
}

int ble_meshtastic_enqueue_from_radio(const uint8_t *from_radio, size_t len)
{
	int ret;

	ret = enqueue_from_radio_locked(from_radio, len);
	if (ret < 0) {
		return ret;
	}

	notify_from_num();
	return 0;
}

int ble_meshtastic_enqueue_from_radio_if_session(uint32_t session_epoch,
						 const uint8_t *from_radio,
						 size_t len)
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

	ret = enqueue_from_radio_locked(from_radio, len);
	k_mutex_unlock(&s_conn_mutex);
	if (ret < 0) {
		return ret;
	}

	notify_from_num();
	return 0;
}

int ble_meshtastic_dequeue_to_radio(uint8_t *to_radio, size_t buflen,
				    size_t *out_len,
				    uint32_t *out_session_epoch)
{
	uint16_t len;

	if (to_radio == NULL || out_len == NULL || out_session_epoch == NULL) {
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

	if (len > 0U) {
		memcpy(to_radio, s_rx_queue[s_rx_head].data, len);
	}
	*out_session_epoch = s_rx_queue[s_rx_head].session_epoch;
	s_rx_head = (s_rx_head + 1U) % ARRAY_SIZE(s_rx_queue);
	s_rx_count--;
	k_mutex_unlock(&s_rx_mutex);

	*out_len = len;
	return 1;
}

uint32_t ble_meshtastic_session_epoch(void)
{
	uint32_t epoch;

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	epoch = session_epoch_locked();
	k_mutex_unlock(&s_conn_mutex);

	return epoch;
}

bool ble_meshtastic_session_active(void)
{
	bool active;

	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	active = s_session_active;
	k_mutex_unlock(&s_conn_mutex);

	return active;
}

bool ble_meshtastic_session_epoch_current(uint32_t session_epoch)
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
	s_read_active = false;
	s_read_len = 0U;
	s_read_next_offset = 0U;
	s_read_slot = 0U;
	k_mutex_unlock(&s_tx_mutex);
}

void ble_meshtastic_reset_session(void)
{
	k_mutex_lock(&s_conn_mutex, K_FOREVER);
	s_session_active = false;
	s_owner_generation = 0U;
	reset_session_locked();
	k_mutex_unlock(&s_conn_mutex);
}

int ble_meshtastic_reset_session_if_epoch(uint32_t session_epoch)
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

uint32_t ble_meshtastic_from_radio_free(void)
{
	uint32_t free_slots;

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	free_slots = ARRAY_SIZE(s_tx_queue) - s_tx_count;
	k_mutex_unlock(&s_tx_mutex);

	return free_slots;
}

uint32_t ble_meshtastic_from_radio_capacity(void)
{
	return ARRAY_SIZE(s_tx_queue);
}

int ble_meshtastic_init(void)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_MESHTASTIC,
		.ad = s_ad,
		.ad_len = ARRAY_SIZE(s_ad),
		.sd = s_sd,
		.sd_len = ARRAY_SIZE(s_sd),
		.name = MESHTASTIC_ADV_NAME,
		.connected = on_connected,
		.disconnected = on_disconnected,
	};

	return ble_app_owner_start(&adv);
}
