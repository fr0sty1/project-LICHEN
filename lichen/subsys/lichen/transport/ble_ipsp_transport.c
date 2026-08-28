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
#include <zephyr/net/net_ip.h>
#include <zephyr/net_buf.h>
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

#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
#define BT_UUID_IPSS BT_UUID_DECLARE_16(LICHEN_BLE_IPSS_UUID)
#define IPHC_DISPATCH 0x60U
#define IPHC_DISPATCH_MASK 0xE0U
#define IPHC_BASE_HEADER_LEN 40U
#endif

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
#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
	bool ipsp_enabled;
#endif
};

static struct ble_transport_state transport_state;

#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
struct ipsp_transport_state {
	bool server_registered;
	bool channel_ready;
	struct bt_l2cap_le_chan channel;
};

static struct ipsp_transport_state ipsp_state;

NET_BUF_POOL_FIXED_DEFINE(ipsp_sdu_pool, 2,
			  BT_L2CAP_SDU_BUF_SIZE(LICHEN_BLE_IPSP_SDU_MTU),
			  CONFIG_BT_CONN_TX_USER_DATA_SIZE, NULL);
#endif

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

#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
static int ipsp_accept(struct bt_conn *conn, struct bt_l2cap_server *server,
		       struct bt_l2cap_chan **chan);

static struct bt_l2cap_server ipsp_server = {
	.psm = LICHEN_BLE_IPSP_PSM,
	.accept = ipsp_accept,
};
#endif

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

	lichen_ble_conn_cb_t cb = NULL;
	void *ctx = NULL;
	enum lichen_ble_conn_state reported_state = LICHEN_BLE_DISCONNECTED;
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

	if (transport_state.initialized) {
		cb = transport_state.config.conn_cb;
		ctx = transport_state.config.user_ctx;
		reported_state = transport_state.state;
	}

	k_mutex_unlock(&transport_state.lock);

	char addr[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	LOG_INF("BLE connected: %s", addr);

	if (cb) {
		cb(reported_state, ctx);
	}
}

static void disconnected_cb(struct bt_conn *conn, uint8_t reason)
{
	lichen_ble_conn_cb_t cb = NULL;
	void *ctx = NULL;
	k_mutex_lock(&transport_state.lock, K_FOREVER);

	if (transport_state.conn == conn) {
#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
		ipsp_state.channel_ready = false;
#endif
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

#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
/* IPSS has no characteristics; it advertises the SIG-assigned IPSP PSM. */
BT_GATT_SERVICE_DEFINE(ipss_svc,
	BT_GATT_PRIMARY_SERVICE(BT_UUID_IPSS),
);
#endif

/* ─── Advertising data ──────────────────────────────────────────────────────── */

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_NUS_VAL),
#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
	BT_DATA_BYTES(BT_DATA_UUID16_ALL, BT_UUID_16_ENCODE(LICHEN_BLE_IPSS_UUID)),
#endif
};

static const struct bt_data sd[] = {
	BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME,
		sizeof(CONFIG_BT_DEVICE_NAME) - 1),
};

#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
/* A conservative RFC 6282 encoding: IPHC is used, while traffic class, flow
 * label, next header, hop limit, and both IPv6 addresses remain inline.  This
 * is interoperable, allocation-free, and provides a lossless baseline before
 * the separate MTU/advanced-compression work negotiates more compact modes. */
static int ipsp_encode(const uint8_t *ipv6, size_t ipv6_len,
		       uint8_t *out, size_t out_size, size_t *out_len)
{
	uint16_t payload_len;
	uint8_t traffic_class;

	if (ipv6 == NULL || out == NULL || out_len == NULL ||
	    ipv6_len < IPHC_BASE_HEADER_LEN) {
		return -EINVAL;
	}
	if (ipv6_len > LICHEN_BLE_IPV6_MTU) {
		return -EMSGSIZE;
	}
	payload_len = ((uint16_t)ipv6[4] << 8) | ipv6[5];
	if ((ipv6[0] >> 4) != 6U || payload_len != ipv6_len - IPHC_BASE_HEADER_LEN) {
		return -EBADMSG;
	}
	if (out_size < ipv6_len) {
		return -ENOBUFS;
	}

	traffic_class = ((ipv6[0] & 0x0fU) << 4) | (ipv6[1] >> 4);
	out[0] = IPHC_DISPATCH; /* TF=00, NH=0, HLIM=00. */
	out[1] = 0x00U;         /* Stateless, full source and destination. */
	out[2] = ((traffic_class & 0x03U) << 6) | (traffic_class >> 2);
	out[3] = ipv6[1] & 0x0fU;
	out[4] = ipv6[2];
	out[5] = ipv6[3];
	out[6] = ipv6[6];
	out[7] = ipv6[7];
	memcpy(&out[8], &ipv6[8], 32U);
	memcpy(&out[IPHC_BASE_HEADER_LEN], &ipv6[IPHC_BASE_HEADER_LEN],
	       ipv6_len - IPHC_BASE_HEADER_LEN);
	*out_len = ipv6_len;
	return 0;
}

static int ipsp_decode(const uint8_t *sdu, size_t sdu_len,
		       uint8_t *out, size_t out_size, size_t *out_len)
{
	uint8_t traffic_class;
	uint16_t payload_len;

	if (sdu == NULL || out == NULL || out_len == NULL ||
	    sdu_len < IPHC_BASE_HEADER_LEN) {
		return -EINVAL;
	}
	if (sdu_len > LICHEN_BLE_IPSP_SDU_MTU) {
		return -EMSGSIZE;
	}
	if ((sdu[0] & IPHC_DISPATCH_MASK) != IPHC_DISPATCH ||
	    sdu[0] != IPHC_DISPATCH || sdu[1] != 0U) {
		return -ENOTSUP;
	}
	if (out_size < sdu_len) {
		return -ENOBUFS;
	}

	traffic_class = ((sdu[2] & 0x3fU) << 2) | (sdu[2] >> 6);
	out[0] = 0x60U | (traffic_class >> 4);
	out[1] = ((traffic_class & 0x0fU) << 4) | (sdu[3] & 0x0fU);
	out[2] = sdu[4];
	out[3] = sdu[5];
	payload_len = (uint16_t)(sdu_len - IPHC_BASE_HEADER_LEN);
	out[4] = (uint8_t)(payload_len >> 8);
	out[5] = (uint8_t)(payload_len & 0xffU);
	out[6] = sdu[6];
	out[7] = sdu[7];
	memcpy(&out[8], &sdu[8], 32U);
	memcpy(&out[IPHC_BASE_HEADER_LEN], &sdu[IPHC_BASE_HEADER_LEN], payload_len);
	*out_len = sdu_len;
	return 0;
}

static struct net_buf *ipsp_alloc_buf(struct bt_l2cap_chan *chan)
{
	ARG_UNUSED(chan);
	return net_buf_alloc(&ipsp_sdu_pool, K_NO_WAIT);
}

static void ipsp_connected(struct bt_l2cap_chan *chan)
{
	k_mutex_lock(&transport_state.lock, K_FOREVER);
	ipsp_state.channel_ready = chan == &ipsp_state.channel.chan;
	k_mutex_unlock(&transport_state.lock);
}

static void ipsp_disconnected(struct bt_l2cap_chan *chan)
{
	k_mutex_lock(&transport_state.lock, K_FOREVER);
	if (chan == &ipsp_state.channel.chan) {
		ipsp_state.channel_ready = false;
	}
	k_mutex_unlock(&transport_state.lock);
}

static int ipsp_recv(struct bt_l2cap_chan *chan, struct net_buf *buf)
{
	uint8_t ipv6[LICHEN_BLE_IPV6_MTU];
	lichen_ble_rx_cb_t cb;
	void *ctx;
	size_t ipv6_len = 0U;
	int ret;

	k_mutex_lock(&transport_state.lock, K_FOREVER);
	if (!transport_state.initialized || !transport_state.ipsp_enabled ||
	    !ipsp_state.channel_ready || chan != &ipsp_state.channel.chan) {
		k_mutex_unlock(&transport_state.lock);
		return -ESHUTDOWN;
	}
	if (transport_state.config.require_secure &&
	    transport_state.state < LICHEN_BLE_SECURE) {
		transport_state.stats.rx_errors++;
		k_mutex_unlock(&transport_state.lock);
		return -EACCES;
	}
	ret = ipsp_decode(buf->data, buf->len, ipv6, sizeof(ipv6), &ipv6_len);
	if (ret < 0) {
		transport_state.stats.rx_errors++;
		k_mutex_unlock(&transport_state.lock);
		return 0; /* Drop malformed SDUs without closing the channel. */
	}
	transport_state.stats.rx_packets++;
	transport_state.stats.rx_bytes += ipv6_len;
	cb = transport_state.config.rx_cb;
	ctx = transport_state.config.user_ctx;
	k_mutex_unlock(&transport_state.lock);

	cb(ipv6, ipv6_len, ctx);
	return 0;
}

static const struct bt_l2cap_chan_ops ipsp_chan_ops = {
	.connected = ipsp_connected,
	.disconnected = ipsp_disconnected,
	.alloc_buf = ipsp_alloc_buf,
	.recv = ipsp_recv,
};

static int ipsp_accept(struct bt_conn *conn, struct bt_l2cap_server *server,
		       struct bt_l2cap_chan **chan)
{
	ARG_UNUSED(server);
	if (chan == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&transport_state.lock, K_FOREVER);
	if (!transport_state.initialized || !transport_state.ipsp_enabled) {
		k_mutex_unlock(&transport_state.lock);
		return -ESHUTDOWN;
	}
	if (transport_state.conn != conn) {
		k_mutex_unlock(&transport_state.lock);
		return -EACCES;
	}
	if (ipsp_state.channel.chan.conn != NULL || ipsp_state.channel_ready) {
		k_mutex_unlock(&transport_state.lock);
		return -ENOMEM;
	}
	memset(&ipsp_state.channel, 0, sizeof(ipsp_state.channel));
	ipsp_state.channel.chan.ops = &ipsp_chan_ops;
	ipsp_state.channel.rx.mtu = LICHEN_BLE_IPSP_SDU_MTU;
	*chan = &ipsp_state.channel.chan;
	k_mutex_unlock(&transport_state.lock);
	return 0;
}
#endif

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
	bool fresh = false;
	int err;

	if (config == NULL || config->rx_cb == NULL) {
		return -EINVAL;
	}
	if (transport_state.initialized) {
		if (transport_state.ipsp_enabled) {
			return -EALREADY;
		}
		if (transport_state.config.rx_cb != config->rx_cb ||
		    transport_state.config.conn_cb != config->conn_cb ||
		    transport_state.config.user_ctx != config->user_ctx ||
		    transport_state.config.require_secure != config->require_secure) {
			return -EBUSY;
		}
	} else {
		err = bt_enable(NULL);
		if (err < 0 && err != -EALREADY) {
			return err;
		}
		memset(&transport_state, 0, sizeof(transport_state));
		k_mutex_init(&transport_state.lock);
		transport_state.config = *config;
		transport_state.initialized = true;
		transport_state.state = LICHEN_BLE_DISCONNECTED;
		fresh = true;
	}

	ipsp_server.sec_level = config->require_secure ? BT_SECURITY_L4 : BT_SECURITY_L1;
	if (!ipsp_state.server_registered) {
		err = bt_l2cap_server_register(&ipsp_server);
		if (err < 0) {
			if (fresh) {
				transport_state.initialized = false;
			}
			return err;
		}
		ipsp_state.server_registered = true;
	}
	transport_state.ipsp_enabled = true;
	ipsp_state.channel_ready = false;
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
#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
		ipsp_state.channel_ready = false;
#endif
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
			LOG_WRN("Notify failed (err %d), sent %zu/%zu bytes of SLIP frame",
				err, offset, slip_len);
			transport_state.stats.tx_errors++;
			break;
		}
		offset += send_len;
	}

	if (err && offset < slip_len) {
		/* Partial SLIP frame was sent (protocol corruption risk).
		 * Send a terminating END byte to allow client SLIP decoder
		 * to resync and discard the incomplete frame. Best effort. */
		uint8_t end_byte = SLIP_END;
		struct bt_gatt_notify_params end_params = {
			.attr = tx_attr,
			.data = &end_byte,
			.len = 1,
		};
		(void)bt_gatt_notify_cb(transport_state.conn, &end_params);
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
	uint8_t sdu[LICHEN_BLE_IPSP_SDU_MTU];
	struct net_buf *buf;
	size_t sdu_len = 0U;
	int ret = ipsp_encode(data, len, sdu, sizeof(sdu), &sdu_len);

	if (ret < 0) {
		return ret;
	}
	if (!transport_state.initialized) {
		return -ENOTCONN;
	}
	k_mutex_lock(&transport_state.lock, K_FOREVER);
	if (!transport_state.initialized || !transport_state.ipsp_enabled ||
	    transport_state.conn == NULL || !ipsp_state.channel_ready ||
	    ipsp_state.channel.chan.conn == NULL) {
		k_mutex_unlock(&transport_state.lock);
		return -ENOTCONN;
	}
	if (transport_state.config.require_secure &&
	    transport_state.state < LICHEN_BLE_SECURE) {
		k_mutex_unlock(&transport_state.lock);
		return -EACCES;
	}
	if (sdu_len > ipsp_state.channel.tx.mtu) {
		transport_state.stats.tx_errors++;
		k_mutex_unlock(&transport_state.lock);
		return -EMSGSIZE;
	}
	buf = net_buf_alloc(&ipsp_sdu_pool, K_NO_WAIT);
	if (buf == NULL) {
		transport_state.stats.tx_errors++;
		k_mutex_unlock(&transport_state.lock);
		return -ENOMEM;
	}
	net_buf_reserve(buf, BT_L2CAP_SDU_CHAN_SEND_RESERVE);
	net_buf_add_mem(buf, sdu, sdu_len);
	ret = bt_l2cap_chan_send(&ipsp_state.channel.chan, buf);
	if (ret < 0) {
		net_buf_unref(buf);
		transport_state.stats.tx_errors++;
	} else {
		transport_state.stats.tx_packets++;
		transport_state.stats.tx_bytes += len;
		ret = (int)len;
	}
	k_mutex_unlock(&transport_state.lock);
	return ret;
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
	struct bt_l2cap_chan *ipsp_chan = NULL;

	if (!transport_state.initialized) {
		return;
	}
	k_mutex_lock(&transport_state.lock, K_FOREVER);
	if (!transport_state.initialized) {
		k_mutex_unlock(&transport_state.lock);
		return;
	}

	transport_state.initialized = false;
	struct bt_conn *conn = transport_state.conn;
	transport_state.conn = NULL;
	transport_state.state = LICHEN_BLE_DISCONNECTED;
	transport_state.advertising = false;
#if IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
	transport_state.ipsp_enabled = false;
	if (ipsp_state.channel.chan.conn != NULL) {
		ipsp_chan = &ipsp_state.channel.chan;
	}
	ipsp_state.channel_ready = false;
#endif
	k_mutex_unlock(&transport_state.lock);

	if (ipsp_chan != NULL) {
		(void)bt_l2cap_chan_disconnect(ipsp_chan);
	}
	if (conn != NULL) {
		bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		bt_conn_unref(conn);
	}
	(void)bt_le_adv_stop();

	LOG_INF("BLE transport deinitialized");
}

#if defined(CONFIG_ZTEST) && IS_ENABLED(CONFIG_LICHEN_BLE_IPSP)
int lichen_ble_ipsp_test_encode(const uint8_t *ipv6, size_t ipv6_len,
				uint8_t *out, size_t out_size, size_t *out_len)
{
	return ipsp_encode(ipv6, ipv6_len, out, out_size, out_len);
}

int lichen_ble_ipsp_test_decode(const uint8_t *sdu, size_t sdu_len,
				uint8_t *out, size_t out_size, size_t *out_len)
{
	return ipsp_decode(sdu, sdu_len, out, out_size, out_len);
}

void lichen_ble_ipsp_test_set_channel_ready(bool ready)
{
	ipsp_state.channel_ready = ready;
}

bool lichen_ble_ipsp_test_channel_ready(void)
{
	return ipsp_state.channel_ready;
}
#endif
