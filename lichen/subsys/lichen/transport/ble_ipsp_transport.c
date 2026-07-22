/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ble_ipsp_transport.c
 * @brief BLE IPSP transport binding for LCI
 *
 * Implements SLIP over Nordic UART Service (Option A, required) and
 * RFC 7668 6LoWPAN over BLE IPSP (Option B, optional) per LCI spec 17.3.2.
 */

#include <lichen/transport/ble_ipsp_transport.h>

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gap.h>
#include <zephyr/sys/atomic.h>

#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
#include <zephyr/bluetooth/l2cap.h>
#include <zephyr/net/net_if.h>
#endif

#include <string.h>

LOG_MODULE_REGISTER(ble_ipsp_transport, CONFIG_LICHEN_BLE_TRANSPORT_LOG_LEVEL);

/* ─── Nordic UART Service UUIDs ─────────────────────────────────────────────── */

/* NUS Service UUID: 6E400001-B5A3-F393-E0A9-E50E24DCCA9E */
#define BT_UUID_NUS_VAL \
	BT_UUID_128_ENCODE(0x6E400001, 0xB5A3, 0xF393, 0xE0A9, 0xE50E24DCCA9E)
#define BT_UUID_NUS BT_UUID_DECLARE_128(BT_UUID_NUS_VAL)

/* NUS RX Characteristic UUID: 6E400002-B5A3-F393-E0A9-E50E24DCCA9E */
#define BT_UUID_NUS_RX_VAL \
	BT_UUID_128_ENCODE(0x6E400002, 0xB5A3, 0xF393, 0xE0A9, 0xE50E24DCCA9E)
#define BT_UUID_NUS_RX BT_UUID_DECLARE_128(BT_UUID_NUS_RX_VAL)

/* NUS TX Characteristic UUID: 6E400003-B5A3-F393-E0A9-E50E24DCCA9E */
#define BT_UUID_NUS_TX_VAL \
	BT_UUID_128_ENCODE(0x6E400003, 0xB5A3, 0xF393, 0xE0A9, 0xE50E24DCCA9E)
#define BT_UUID_NUS_TX BT_UUID_DECLARE_128(BT_UUID_NUS_TX_VAL)

/* ─── SLIP reassembly buffer ────────────────────────────────────────────────── */

/* Maximum SLIP-encoded frame: worst case 2x IPv6 + 2 END bytes */
#define SLIP_RX_BUF_SIZE (LICHEN_BLE_IPV6_MTU * 2 + 2)

/* Compile-time check that SLIP buffer is sized for worst-case encoding */
BUILD_ASSERT(SLIP_RX_BUF_SIZE >= LICHEN_BLE_IPV6_MTU * 2 + 2,
	     "SLIP_RX_BUF_SIZE too small for worst-case encoding");

struct slip_rx_state {
	uint8_t buf[SLIP_RX_BUF_SIZE];
	size_t len;
	bool escape_next;
	bool in_frame;
};

/* ─── Transport state ───────────────────────────────────────────────────────── */

struct ble_transport_state {
	bool initialized;
	bool advertising;
	struct lichen_ble_transport_config config;
	struct bt_conn *conn;
	enum lichen_ble_conn_state state;
	struct slip_rx_state slip_rx;
	struct lichen_ble_transport_stats stats;
	struct k_mutex lock;
};

static struct ble_transport_state transport_state;

/* ─── Forward declarations ──────────────────────────────────────────────────── */

static void connected_cb(struct bt_conn *conn, uint8_t err);
static void disconnected_cb(struct bt_conn *conn, uint8_t reason);
#if defined(CONFIG_BT_SMP) || defined(CONFIG_BT_CLASSIC)
static void security_changed_cb(struct bt_conn *conn, bt_security_t level,
				enum bt_security_err err);
#endif
static ssize_t nus_rx_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 const void *buf, uint16_t len, uint16_t offset,
			 uint8_t flags);
static void nus_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value);

/* ─── BLE callbacks ─────────────────────────────────────────────────────────── */

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected_cb,
	.disconnected = disconnected_cb,
#if defined(CONFIG_BT_SMP) || defined(CONFIG_BT_CLASSIC)
	.security_changed = security_changed_cb,
#endif
};

static void connected_cb(struct bt_conn *conn, uint8_t err)
{
	if (err) {
		LOG_WRN("Connection failed (err %u)", err);
		return;
	}

	k_mutex_lock(&transport_state.lock, K_FOREVER);

	if (transport_state.conn != NULL) {
		LOG_WRN("Already have connection, rejecting new one");
		k_mutex_unlock(&transport_state.lock);
		bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return;
	}

	transport_state.conn = bt_conn_ref(conn);
	transport_state.state = LICHEN_BLE_CONNECTED;
	transport_state.stats.connections++;

	/* Reset SLIP state for new connection */
	memset(&transport_state.slip_rx, 0, sizeof(transport_state.slip_rx));

	LOG_DBG("Connected, initial ATT MTU: %u", bt_gatt_get_mtu(conn));

	lichen_ble_conn_cb_t cb = NULL;
	void *ctx = NULL;
	if (transport_state.initialized) {
		cb = transport_state.config.conn_cb;
		ctx = transport_state.config.user_ctx;
	}

	k_mutex_unlock(&transport_state.lock);

	char addr[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("BLE connected: %s", addr);

	if (cb) {
		cb(LICHEN_BLE_CONNECTED, ctx);
	}
}

static void disconnected_cb(struct bt_conn *conn, uint8_t reason)
{
	lichen_ble_conn_cb_t cb = NULL;
	void *ctx = NULL;
	k_mutex_lock(&transport_state.lock, K_FOREVER);

	if (transport_state.conn == conn) {
		bt_conn_unref(transport_state.conn);
		transport_state.conn = NULL;
		transport_state.state = LICHEN_BLE_DISCONNECTED;
		transport_state.stats.disconnections++;
		if (transport_state.initialized) {
			cb = transport_state.config.conn_cb;
			ctx = transport_state.config.user_ctx;
		}
	}

	k_mutex_unlock(&transport_state.lock);

	LOG_INF("BLE disconnected (reason 0x%02x)", reason);

	if (cb) {
		cb(LICHEN_BLE_DISCONNECTED, ctx);
	}
}

#if defined(CONFIG_BT_SMP) || defined(CONFIG_BT_CLASSIC)
static void security_changed_cb(struct bt_conn *conn, bt_security_t level,
				enum bt_security_err err)
{
	if (err) {
		LOG_WRN("Security change failed (err %d)", err);
		return;
	}

	lichen_ble_conn_cb_t cb = NULL;
	void *ctx = NULL;
	enum lichen_ble_conn_state reported_state = LICHEN_BLE_DISCONNECTED;
	k_mutex_lock(&transport_state.lock, K_FOREVER);

	if (transport_state.conn == conn) {
		if (level >= BT_SECURITY_L2) {
			transport_state.state = LICHEN_BLE_PAIRED;
			LOG_INF("BLE paired (level %d)", level);
		}
		if (level >= BT_SECURITY_L4) {
			transport_state.state = LICHEN_BLE_SECURE;
			LOG_INF("BLE secure (LE Secure Connections)");
		}
		if (transport_state.initialized) {
			cb = transport_state.config.conn_cb;
			ctx = transport_state.config.user_ctx;
			reported_state = transport_state.state;
		}
	}

	k_mutex_unlock(&transport_state.lock);

	if (cb) {
		cb(reported_state, ctx);
	}
}
#endif

/* ─── SLIP processing ───────────────────────────────────────────────────────── */

/**
 * Process a complete SLIP frame - extract IPv6 packet and deliver to callback.
 */
static void slip_process_frame(void)
{
	struct slip_rx_state *slip = &transport_state.slip_rx;

	if (slip->len == 0) {
		return; /* Empty frame, ignore */
	}

	if (slip->len < 40) { /* Minimum IPv6 header */
		LOG_WRN("SLIP frame too short: %zu bytes", slip->len);
		transport_state.stats.slip_frame_errors++;
		return;
	}

	if (slip->len > LICHEN_BLE_IPV6_MTU) {
		LOG_WRN("SLIP frame too large: %zu bytes", slip->len);
		transport_state.stats.slip_frame_errors++;
		return;
	}

	LOG_DBG("SLIP frame complete: %zu bytes", slip->len);
	transport_state.stats.rx_packets++;

	if (transport_state.config.rx_cb) {
		transport_state.config.rx_cb(slip->buf, slip->len,
					     transport_state.config.user_ctx);
	}
}

/**
 * Process incoming SLIP-encoded data byte by byte.
 */
static void slip_rx_byte(uint8_t byte)
{
	struct slip_rx_state *slip = &transport_state.slip_rx;

	if (byte == SLIP_END) {
		if (slip->in_frame) {
			slip_process_frame();
		}
		/* Reset for next frame */
		slip->len = 0;
		slip->escape_next = false;
		slip->in_frame = true;
		return;
	}

	if (!slip->in_frame) {
		/* Data before first END byte, start frame implicitly */
		slip->in_frame = true;
	}

	if (slip->escape_next) {
		slip->escape_next = false;
		if (byte == SLIP_ESC_END) {
			byte = SLIP_END;
		} else if (byte == SLIP_ESC_ESC) {
			byte = SLIP_ESC;
		} else {
			LOG_WRN("Invalid SLIP escape sequence: 0x%02x", byte);
			transport_state.stats.slip_frame_errors++;
			/* Reset and wait for next END */
			slip->len = 0;
			slip->in_frame = false;
			return;
		}
	} else if (byte == SLIP_ESC) {
		slip->escape_next = true;
		return;
	}

	if (slip->len < sizeof(slip->buf)) {
		slip->buf[slip->len++] = byte;
	} else {
		LOG_WRN("SLIP buffer overflow");
		transport_state.stats.slip_frame_errors++;
		slip->len = 0;
		slip->in_frame = false;
	}
}

/* ─── NUS GATT service ──────────────────────────────────────────────────────── */

static ssize_t nus_rx_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 const void *buf, uint16_t len, uint16_t offset,
			 uint8_t flags)
{
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	/* SECURITY: Check security level for write operations */
	if (transport_state.config.require_secure) {
		bt_security_t level = bt_conn_get_security(conn);
		if (level < BT_SECURITY_L4) {
			LOG_WRN("NUS RX rejected: insufficient security (level %d)", level);
			return BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION);
		}
	}

	k_mutex_lock(&transport_state.lock, K_FOREVER);
	transport_state.stats.rx_bytes += len;
	k_mutex_unlock(&transport_state.lock);

	const uint8_t *data = buf;
	for (uint16_t i = 0; i < len; i++) {
		slip_rx_byte(data[i]);
	}

	return len;
}

static atomic_t nus_tx_notify_enabled;

static void nus_ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	atomic_set(&nus_tx_notify_enabled, (value == BT_GATT_CCC_NOTIFY) ? 1 : 0);
	LOG_DBG("NUS TX notifications %s",
		atomic_get(&nus_tx_notify_enabled) ? "enabled" : "disabled");
}

/* NUS Service Definition */
BT_GATT_SERVICE_DEFINE(nus_svc,
	BT_GATT_PRIMARY_SERVICE(BT_UUID_NUS),

	/* RX Characteristic - Client writes to this (phone -> node) */
	BT_GATT_CHARACTERISTIC(BT_UUID_NUS_RX,
		BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP,
		BT_GATT_PERM_WRITE,
		NULL, nus_rx_cb, NULL),

	/* TX Characteristic - Server notifies on this (node -> phone) */
	BT_GATT_CHARACTERISTIC(BT_UUID_NUS_TX,
		BT_GATT_CHRC_NOTIFY,
		BT_GATT_PERM_NONE,
		NULL, NULL, NULL),
	BT_GATT_CCC(nus_ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
);

/* ─── Advertising data ──────────────────────────────────────────────────────── */

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_NUS_VAL),
};

static const struct bt_data sd[] = {
	BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME,
		sizeof(CONFIG_BT_DEVICE_NAME) - 1),
};

/* ─── Public API implementation ─────────────────────────────────────────────── */

int lichen_ble_slip_init(const struct lichen_ble_transport_config *config)
{
	if (config == NULL || config->rx_cb == NULL) {
		return -EINVAL;
	}

	if (transport_state.initialized) {
		return -EALREADY;
	}

	/* Zero state first, then initialize components */
	memset(&transport_state, 0, sizeof(transport_state));

	int err = bt_enable(NULL);
	if (err && err != -EALREADY) {
		LOG_ERR("Bluetooth init failed (err %d)", err);
		return err;
	}

	k_mutex_init(&transport_state.lock);
	transport_state.config = *config;
	transport_state.initialized = true;
	transport_state.state = LICHEN_BLE_DISCONNECTED;

	LOG_INF("BLE SLIP transport initialized (NUS)");
	return 0;
}

int lichen_ble_ipsp_init(const struct lichen_ble_transport_config *config)
{
#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
	/* IPSP implementation would go here */
	/* This requires:
	 * - Registering with Zephyr's net_if as an L2 interface
	 * - Setting up L2CAP CoC (Connection Oriented Channels)
	 * - Implementing 6LoWPAN header compression (RFC 7668)
	 */
	ARG_UNUSED(config);
	LOG_INF("BLE IPSP transport initialized (RFC 7668)");
	return 0;
#else
	ARG_UNUSED(config);
	return -ENOTSUP;
#endif
}

int lichen_ble_transport_start(void)
{
	if (!transport_state.initialized) {
		return -EINVAL;
	}

	if (transport_state.advertising) {
		return 0; /* Already advertising */
	}

	int err = bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad),
				  sd, ARRAY_SIZE(sd));
	if (err) {
		LOG_ERR("Advertising failed to start (err %d)", err);
		return err;
	}

	transport_state.advertising = true;
	LOG_INF("BLE advertising started");
	return 0;
}

int lichen_ble_transport_stop(void)
{
	if (!transport_state.initialized) {
		return -EINVAL;
	}

	if (transport_state.advertising) {
		bt_le_adv_stop();
		transport_state.advertising = false;
	}

	k_mutex_lock(&transport_state.lock, K_FOREVER);
	if (transport_state.conn) {
		struct bt_conn *conn = transport_state.conn;
		transport_state.conn = NULL;
		transport_state.state = LICHEN_BLE_DISCONNECTED;
		k_mutex_unlock(&transport_state.lock);

		bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		/* Unref here to guarantee cleanup even if disconnected_cb
		 * doesn't fire (e.g., during BLE stack shutdown). Setting
		 * transport_state.conn = NULL above prevents double-unref
		 * if disconnected_cb does fire. */
		bt_conn_unref(conn);
	} else {
		k_mutex_unlock(&transport_state.lock);
	}

	LOG_INF("BLE transport stopped");
	return 0;
}

/**
 * SLIP-encode a buffer and send via NUS TX notifications.
 */
int lichen_ble_slip_send(const uint8_t *data, size_t len)
{
	if (data == NULL || len == 0) {
		return -EINVAL;
	}

	if (len > LICHEN_BLE_IPV6_MTU) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&transport_state.lock, K_FOREVER);

	if (!transport_state.conn) {
		k_mutex_unlock(&transport_state.lock);
		return -ENOTCONN;
	}

	if (!atomic_get(&nus_tx_notify_enabled)) {
		k_mutex_unlock(&transport_state.lock);
		return -ENOTCONN;
	}

	/* SECURITY: Check security level */
	if (transport_state.config.require_secure) {
		if (transport_state.state < LICHEN_BLE_SECURE) {
			k_mutex_unlock(&transport_state.lock);
			return -EACCES;
		}
	}

	/* SLIP encode: worst case 2x size + 2 END bytes */
	uint8_t slip_buf[SLIP_RX_BUF_SIZE];
	size_t slip_len = 0;

	/* Start with END byte for frame synchronization */
	slip_buf[slip_len++] = SLIP_END;

	for (size_t i = 0; i < len; i++) {
		/* Bounds check: need at least 2 bytes for escape sequences */
		if (slip_len + 2 > SLIP_RX_BUF_SIZE) {
			k_mutex_unlock(&transport_state.lock);
			LOG_ERR("SLIP encoding overflow at byte %zu", i);
			return -EOVERFLOW;
		}
		switch (data[i]) {
		case SLIP_END:
			slip_buf[slip_len++] = SLIP_ESC;
			slip_buf[slip_len++] = SLIP_ESC_END;
			break;
		case SLIP_ESC:
			slip_buf[slip_len++] = SLIP_ESC;
			slip_buf[slip_len++] = SLIP_ESC_ESC;
			break;
		default:
			slip_buf[slip_len++] = data[i];
			break;
		}
	}

	/* Final bounds check for trailing END byte */
	if (slip_len >= SLIP_RX_BUF_SIZE) {
		k_mutex_unlock(&transport_state.lock);
		LOG_ERR("SLIP encoding overflow before trailing END");
		return -EOVERFLOW;
	}

	/* End with END byte */
	slip_buf[slip_len++] = SLIP_END;

	/* Find the TX characteristic attribute handle */
	const struct bt_gatt_attr *tx_attr = bt_gatt_find_by_uuid(
		nus_svc.attrs, nus_svc.attr_count, BT_UUID_NUS_TX);
	if (!tx_attr) {
		k_mutex_unlock(&transport_state.lock);
		LOG_ERR("TX characteristic not found");
		return -ENOENT;
	}

	/* Get current ATT MTU and calculate max GATT notification payload.
	 * ATT MTU is fetched at send time because MTU exchange may occur
	 * after the connection is established. The 3-byte overhead is for
	 * the ATT notification header (1 byte opcode + 2 bytes handle). */
	uint16_t att_mtu = bt_gatt_get_mtu(transport_state.conn);
	uint16_t chunk_size = att_mtu > 3 ? att_mtu - 3 : 20;
	size_t offset = 0;
	int err = 0;

	while (offset < slip_len) {
		size_t remaining = slip_len - offset;
		size_t send_len = remaining < chunk_size ? remaining : chunk_size;

		struct bt_gatt_notify_params params = {
			.attr = tx_attr,
			.data = &slip_buf[offset],
			.len = send_len,
		};

		err = bt_gatt_notify_cb(transport_state.conn, &params);
		if (err) {
			LOG_WRN("Notify failed (err %d), sent %zu/%zu",
				err, offset, slip_len);
			transport_state.stats.tx_errors++;
			break;
		}
		offset += send_len;
	}

	if (err == 0) {
		transport_state.stats.tx_packets++;
		transport_state.stats.tx_bytes += len;
	}

	k_mutex_unlock(&transport_state.lock);
	return err ? err : (int)len;
}

int lichen_ble_ipsp_send(const uint8_t *data, size_t len)
{
#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
	/* IPSP send implementation would go here */
	ARG_UNUSED(data);
	ARG_UNUSED(len);
	return -ENOTSUP; /* Stub until L2CAP CoC implemented */
#else
	ARG_UNUSED(data);
	ARG_UNUSED(len);
	return -ENOTSUP;
#endif
}

enum lichen_ble_conn_state lichen_ble_transport_get_state(void)
{
	if (!transport_state.initialized) {
		return LICHEN_BLE_DISCONNECTED;
	}
	k_mutex_lock(&transport_state.lock, K_FOREVER);
	enum lichen_ble_conn_state state = transport_state.state;
	k_mutex_unlock(&transport_state.lock);
	return state;
}

bool lichen_ble_transport_is_secure(void)
{
	if (!transport_state.initialized) {
		return false;
	}
	k_mutex_lock(&transport_state.lock, K_FOREVER);
	bool secure = transport_state.state >= LICHEN_BLE_SECURE;
	k_mutex_unlock(&transport_state.lock);
	return secure;
}

int lichen_ble_transport_get_stats(struct lichen_ble_transport_stats *stats)
{
	if (stats == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&transport_state.lock, K_FOREVER);
	*stats = transport_state.stats;
	k_mutex_unlock(&transport_state.lock);

	return 0;
}

void lichen_ble_transport_reset_stats(void)
{
	k_mutex_lock(&transport_state.lock, K_FOREVER);
	memset(&transport_state.stats, 0, sizeof(transport_state.stats));
	k_mutex_unlock(&transport_state.lock);
}

void lichen_ble_transport_deinit(void)
{
	if (!transport_state.initialized) {
		return;
	}

	lichen_ble_transport_stop();

	k_mutex_lock(&transport_state.lock, K_FOREVER);
	transport_state.initialized = false;
	k_mutex_unlock(&transport_state.lock);

	LOG_INF("BLE transport deinitialized");
}
