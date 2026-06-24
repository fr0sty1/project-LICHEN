/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
/*
 * BLE UART bridge — Nordic UART Service (NUS) with SLIP framing.
 *
 * Two NUS characteristics:
 *   RX  (6E400002…) — phone writes SLIP-framed IPv6 packets to the gateway
 *   TX  (6E400003…) — gateway notifies SLIP-framed IPv6 packets to the phone
 *
 * SLIP framing (RFC 1055) is identical to the wired SLIP interface so the
 * client stack works regardless of whether it connects via USB-serial or BLE.
 */

#include "ble_uart.h"

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(ble_uart, LOG_LEVEL_INF);

/* RFC 1055 SLIP byte values */
#define SLIP_END     0xC0u
#define SLIP_ESC     0xDBu
#define SLIP_ESC_END 0xDCu
#define SLIP_ESC_ESC 0xDDu

/* Maximum IPv6 packet size (RFC 8200 §5) */
#define SLIP_BUF_SIZE 1280u

/* NUS UUIDs — 128-bit, little-endian as Zephyr expects */
#define BT_UUID_NUS_VAL \
	BT_UUID_128_ENCODE(0x6e400001, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)
#define BT_UUID_NUS_RX_VAL \
	BT_UUID_128_ENCODE(0x6e400002, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)
#define BT_UUID_NUS_TX_VAL \
	BT_UUID_128_ENCODE(0x6e400003, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e)

static struct bt_uuid_128 nus_svc_uuid = BT_UUID_INIT_128(BT_UUID_NUS_VAL);
static struct bt_uuid_128 nus_rx_uuid  = BT_UUID_INIT_128(BT_UUID_NUS_RX_VAL);
static struct bt_uuid_128 nus_tx_uuid  = BT_UUID_INIT_128(BT_UUID_NUS_TX_VAL);

/* Active connection (NULL when no phone is connected) */
static struct bt_conn *s_conn;

/* SLIP reassembly state — written only from the BT RX thread */
static uint8_t  s_rx_buf[SLIP_BUF_SIZE];
static uint16_t s_rx_len;
static bool     s_rx_esc;

/* --------------------------------------------------------------------------
 * Packet dispatch: phone → mesh
 * -------------------------------------------------------------------------- */

static void slip_dispatch(const uint8_t *pkt, size_t len)
{
	/*
	 * TODO: inject the IPv6 packet into the mesh via the Zephyr net_pkt
	 * API once the RPL/net integration layer lands.  Until then, log and
	 * drop so the BLE UART layer is exercisable independently.
	 */
	LOG_INF("BLE UART RX %zu B (IPv6; mesh injection deferred)", len);
	ARG_UNUSED(pkt);
}

/* --------------------------------------------------------------------------
 * GATT service definition
 * -------------------------------------------------------------------------- */

static ssize_t nus_rx_write(struct bt_conn *conn,
			    const struct bt_gatt_attr *attr,
			    const void *buf, uint16_t len,
			    uint16_t offset, uint8_t flags)
{
	const uint8_t *data = buf;

	ARG_UNUSED(conn);
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	for (uint16_t i = 0; i < len; i++) {
		uint8_t b = data[i];

		if (s_rx_esc) {
			s_rx_esc = false;
			if (b == SLIP_ESC_END) {
				b = SLIP_END;
			} else if (b == SLIP_ESC_ESC) {
				b = SLIP_ESC;
			}
			/* unknown escape sequence: pass byte through */
		} else if (b == SLIP_ESC) {
			s_rx_esc = true;
			continue;
		} else if (b == SLIP_END) {
			if (s_rx_len > 0) {
				slip_dispatch(s_rx_buf, s_rx_len);
				s_rx_len = 0;
			}
			continue;
		}

		if (s_rx_len < sizeof(s_rx_buf)) {
			s_rx_buf[s_rx_len++] = b;
		}
	}
	return len;
}

static void nus_tx_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	LOG_INF("BLE UART TX notify %s",
		(value == BT_GATT_CCC_NOTIFY) ? "enabled" : "disabled");
}

/*
 * GATT attribute layout (index → attribute):
 *   0  Primary Service declaration
 *   1  RX Characteristic declaration
 *   2  RX Characteristic value
 *   3  TX Characteristic declaration
 *   4  TX Characteristic value  ← bt_gatt_notify target
 *   5  TX CCCD
 */
#define NUS_TX_VAL_IDX 4

BT_GATT_SERVICE_DEFINE(nus_svc,
	BT_GATT_PRIMARY_SERVICE(&nus_svc_uuid),
	BT_GATT_CHARACTERISTIC(&nus_rx_uuid.uuid,
			       BT_GATT_CHRC_WRITE_WITHOUT_RESP,
			       BT_GATT_PERM_WRITE,
			       NULL, nus_rx_write, NULL),
	BT_GATT_CHARACTERISTIC(&nus_tx_uuid.uuid,
			       BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_NONE,
			       NULL, NULL, NULL),
	BT_GATT_CCC(nus_tx_ccc_changed,
		    BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
);

/* --------------------------------------------------------------------------
 * Connection management
 * -------------------------------------------------------------------------- */

static const struct bt_data s_ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_NUS_VAL),
};

static void adv_start(void)
{
	int err = bt_le_adv_start(
		BT_LE_ADV_PARAM(BT_LE_ADV_OPT_CONNECTABLE | BT_LE_ADV_OPT_USE_NAME,
				BT_GAP_ADV_FAST_INT_MIN_2,
				BT_GAP_ADV_FAST_INT_MAX_2,
				NULL),
		s_ad, ARRAY_SIZE(s_ad), NULL, 0);

	if (err) {
		LOG_ERR("adv_start failed: %d", err);
	} else {
		LOG_INF("BLE advertising as \"%s\"", CONFIG_BT_DEVICE_NAME);
	}
}

static void on_connected(struct bt_conn *conn, uint8_t err)
{
	if (err) {
		LOG_ERR("BLE connect error %u", err);
		return;
	}
	s_conn = bt_conn_ref(conn);
	s_rx_len = 0;
	s_rx_esc = false;
	LOG_INF("BLE phone connected");
}

static void on_disconnected(struct bt_conn *conn, uint8_t reason)
{
	ARG_UNUSED(conn);
	if (s_conn) {
		bt_conn_unref(s_conn);
		s_conn = NULL;
	}
	LOG_INF("BLE phone disconnected (reason %u)", reason);
	adv_start();
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected    = on_connected,
	.disconnected = on_disconnected,
};

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int ble_uart_send_slip(const uint8_t *ipv6, size_t len)
{
	/* Worst-case SLIP frame: every byte escaped → 2× len, plus 2 END bytes */
	static uint8_t s_tx_frame[SLIP_BUF_SIZE * 2u + 2u];
	uint16_t fi = 0;

	if (!s_conn) {
		return -ENOTCONN;
	}

	/* Encode SLIP frame */
	s_tx_frame[fi++] = SLIP_END;
	for (size_t i = 0; i < len && fi < sizeof(s_tx_frame) - 1u; i++) {
		if (ipv6[i] == SLIP_END) {
			s_tx_frame[fi++] = SLIP_ESC;
			s_tx_frame[fi++] = SLIP_ESC_END;
		} else if (ipv6[i] == SLIP_ESC) {
			s_tx_frame[fi++] = SLIP_ESC;
			s_tx_frame[fi++] = SLIP_ESC_ESC;
		} else {
			s_tx_frame[fi++] = ipv6[i];
		}
	}
	s_tx_frame[fi++] = SLIP_END;

	/* Send in chunks ≤ (ATT_MTU − 3) bytes; default MTU gives 20 bytes */
	uint16_t mtu    = bt_gatt_get_mtu(s_conn);
	uint16_t chunk  = (mtu > 3u) ? (uint16_t)(mtu - 3u) : 20u;

	for (uint16_t off = 0; off < fi; off += chunk) {
		uint16_t n  = MIN(chunk, (uint16_t)(fi - off));
		int      rc = bt_gatt_notify(s_conn,
					     &nus_svc.attrs[NUS_TX_VAL_IDX],
					     &s_tx_frame[off], n);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}

int ble_uart_init(void)
{
	int err = bt_enable(NULL);

	if (err) {
		LOG_ERR("bt_enable failed: %d", err);
		return err;
	}
	adv_start();
	return 0;
}
