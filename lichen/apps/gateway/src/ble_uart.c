/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
/*
 * BLE native LCI bridge with SLIP framing.
 *
 * Two stream characteristics:
 *   RX — phone writes SLIP-framed IPv6 packets to the gateway
 *   TX — gateway notifies SLIP-framed IPv6 packets to the phone
 *
 * SLIP framing (RFC 1055) is identical to the wired SLIP interface so the
 * client stack works regardless of whether it connects via USB-serial or BLE.
 * New native clients use LICHEN-specific LCI UUIDs. Existing mutually
 * exclusive native product images may opt into the legacy NUS UUID triplet.
 */

#include "ble_ingress.h"
#include "ble_app_owner.h"
#include "ble_uart.h"

#include <string.h>

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

/* LICHEN native BLE LCI UUIDs; see docs/ble-app-surface-owner.md. */
#define BT_UUID_LICHEN_LCI_VAL \
	BT_UUID_128_ENCODE(0xe665960c, 0x7c84, 0x5606, 0xa8d3, 0x884507d0b7a8)
#define BT_UUID_LICHEN_LCI_RX_VAL \
	BT_UUID_128_ENCODE(0x5e6e304a, 0x29af, 0x52d9, 0xa813, 0x306f0f888586)
#define BT_UUID_LICHEN_LCI_TX_VAL \
	BT_UUID_128_ENCODE(0xbe4d4a23, 0x876b, 0x592b, 0xb252, 0x440367e18e43)
#define BT_UUID_LICHEN_LCI_VERSION_VAL \
	BT_UUID_128_ENCODE(0x9158dca0, 0x14ea, 0x5e1c, 0x8580, 0xb97e7c6381b8)
#define BT_UUID_LICHEN_LCI_CAPABILITIES_VAL \
	BT_UUID_128_ENCODE(0x3d3c63f3, 0xce23, 0x5451, 0xb357, 0x738a12c20df7)

#if IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS)
#define BLE_UART_SERVICE_UUID_VAL BT_UUID_NUS_VAL
#define BLE_UART_RX_UUID_VAL      BT_UUID_NUS_RX_VAL
#define BLE_UART_TX_UUID_VAL      BT_UUID_NUS_TX_VAL
#else
#define BLE_UART_SERVICE_UUID_VAL BT_UUID_LICHEN_LCI_VAL
#define BLE_UART_RX_UUID_VAL      BT_UUID_LICHEN_LCI_RX_VAL
#define BLE_UART_TX_UUID_VAL      BT_UUID_LICHEN_LCI_TX_VAL
#endif

#define BLE_LCI_VERSION_1 0x0001u
#define BLE_LCI_CAP_SLIP_IPV6 BIT(0)

static struct bt_uuid_128 ble_uart_svc_uuid =
	BT_UUID_INIT_128(BLE_UART_SERVICE_UUID_VAL);
static struct bt_uuid_128 ble_uart_rx_uuid =
	BT_UUID_INIT_128(BLE_UART_RX_UUID_VAL);
static struct bt_uuid_128 ble_uart_tx_uuid =
	BT_UUID_INIT_128(BLE_UART_TX_UUID_VAL);
#if !IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS)
static struct bt_uuid_128 ble_uart_version_uuid =
	BT_UUID_INIT_128(BT_UUID_LICHEN_LCI_VERSION_VAL);
static struct bt_uuid_128 ble_uart_capabilities_uuid =
	BT_UUID_INIT_128(BT_UUID_LICHEN_LCI_CAPABILITIES_VAL);
static const uint8_t s_lci_version[] = {
	BLE_LCI_VERSION_1 & 0xffu,
	(BLE_LCI_VERSION_1 >> 8) & 0xffu,
};
static const uint8_t s_lci_capabilities[] = {
	BLE_LCI_CAP_SLIP_IPV6 & 0xffu,
	(BLE_LCI_CAP_SLIP_IPV6 >> 8) & 0xffu,
	(BLE_LCI_CAP_SLIP_IPV6 >> 16) & 0xffu,
	(BLE_LCI_CAP_SLIP_IPV6 >> 24) & 0xffu,
};
#endif

/* Mutex protecting SLIP reassembly state */
static K_MUTEX_DEFINE(s_rx_mutex);

/* Mutex protecting TX buffer */
static K_MUTEX_DEFINE(s_tx_mutex);

#ifdef CONFIG_ZTEST
static uint16_t s_test_mtu = 23U;
static int s_test_notify_ret;
static struct ble_uart_test_tx_state s_test_tx_state;
#endif

/* SLIP reassembly state — protected by s_rx_mutex */
static uint8_t  s_rx_buf[SLIP_BUF_SIZE];
static uint16_t s_rx_len;
static bool     s_rx_esc;
static bool     s_rx_overflow;

/* --------------------------------------------------------------------------
 * Packet dispatch: phone -> mesh
 * -------------------------------------------------------------------------- */

static void slip_dispatch(const uint8_t *pkt, size_t len)
{
	int ret;

	ret = ble_ingress_ipv6_default(pkt, len);
	if (ret < 0) {
		LOG_WRN("BLE UART RX %zu B dropped: %d", len, ret);
		return;
	}

	LOG_DBG("BLE UART RX %zu B injected into IPv6 ingress", len);
}

/* --------------------------------------------------------------------------
 * GATT service definition
 * -------------------------------------------------------------------------- */

static ssize_t ble_lci_rx_write(struct bt_conn *conn,
				const struct bt_gatt_attr *attr,
				const void *buf, uint16_t len,
				uint16_t offset, uint8_t flags)
{
	const uint8_t *data = buf;

	ARG_UNUSED(conn);
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	k_mutex_lock(&s_rx_mutex, K_FOREVER);

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

			/* Check buffer space BEFORE writing decoded escape byte */
			if (s_rx_len >= sizeof(s_rx_buf)) {
				s_rx_overflow = true;
				continue;
			}
			s_rx_buf[s_rx_len++] = b;
		} else if (b == SLIP_ESC) {
			s_rx_esc = true;
		} else if (b == SLIP_END) {
			if (s_rx_len > 0) {
				if (s_rx_overflow) {
					LOG_WRN("BLE UART RX frame dropped (overflow)");
				} else {
					slip_dispatch(s_rx_buf, s_rx_len);
				}
				s_rx_len = 0;
				s_rx_overflow = false;
			}
		} else {
			/* Regular byte — store if buffer has space */
			if (s_rx_len < sizeof(s_rx_buf)) {
				s_rx_buf[s_rx_len++] = b;
			} else {
				s_rx_overflow = true;
			}
		}
	}

	k_mutex_unlock(&s_rx_mutex);
	return len;
}

static void ble_lci_tx_ccc_changed(const struct bt_gatt_attr *attr,
				   uint16_t value)
{
	ARG_UNUSED(attr);
	LOG_INF("BLE UART TX notify %s",
		(value == BT_GATT_CCC_NOTIFY) ? "enabled" : "disabled");
}

#if !IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS)
static ssize_t ble_lci_read_static(struct bt_conn *conn,
				   const struct bt_gatt_attr *attr, void *buf,
				   uint16_t len, uint16_t offset)
{
	const struct bt_uuid *uuid = attr->user_data;
	const uint8_t *data;
	size_t data_len;

	if (uuid == &ble_uart_version_uuid.uuid) {
		data = s_lci_version;
		data_len = sizeof(s_lci_version);
	} else {
		data = s_lci_capabilities;
		data_len = sizeof(s_lci_capabilities);
	}

	return bt_gatt_attr_read(conn, attr, buf, len, offset, data, data_len);
}
#endif

/*
 * GATT attribute layout (index → attribute):
 *   0  Primary Service declaration
 *   1  RX Characteristic declaration
 *   2  RX Characteristic value
 *   3  TX Characteristic declaration
 *   4  TX Characteristic value  ← bt_gatt_notify target
 *   5  TX CCCD
 *   6+ Native LCI version/capabilities characteristics (non-legacy profile)
 */
#define NUS_TX_VAL_IDX 4

BT_GATT_SERVICE_DEFINE(nus_svc,
	BT_GATT_PRIMARY_SERVICE(&ble_uart_svc_uuid),
	BT_GATT_CHARACTERISTIC(&ble_uart_rx_uuid.uuid,
			       BT_GATT_CHRC_WRITE_WITHOUT_RESP,
			       BT_GATT_PERM_WRITE,
			       NULL, ble_lci_rx_write, NULL),
	BT_GATT_CHARACTERISTIC(&ble_uart_tx_uuid.uuid,
			       BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_NONE,
			       NULL, NULL, NULL),
	BT_GATT_CCC(ble_lci_tx_ccc_changed,
		    BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
#if !IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS)
	BT_GATT_CHARACTERISTIC(&ble_uart_version_uuid.uuid,
			       BT_GATT_CHRC_READ,
			       BT_GATT_PERM_READ,
			       ble_lci_read_static, NULL,
			       &ble_uart_version_uuid.uuid),
	BT_GATT_CHARACTERISTIC(&ble_uart_capabilities_uuid.uuid,
			       BT_GATT_CHRC_READ,
			       BT_GATT_PERM_READ,
			       ble_lci_read_static, NULL,
			       &ble_uart_capabilities_uuid.uuid),
#endif
);

static uint16_t uart_bt_gatt_get_mtu(struct bt_conn *conn)
{
#ifdef CONFIG_ZTEST
	ARG_UNUSED(conn);
	return s_test_mtu;
#else
	return bt_gatt_get_mtu(conn);
#endif
}

static int uart_bt_gatt_notify(struct bt_conn *conn,
			       const struct bt_gatt_attr *attr,
			       const void *data, uint16_t len)
{
#ifdef CONFIG_ZTEST
	ARG_UNUSED(attr);
	s_test_tx_state.conn = conn;
	s_test_tx_state.notify_count++;
	s_test_tx_state.len = MIN(len, (uint16_t)sizeof(s_test_tx_state.data));
	if (s_test_tx_state.total_len < sizeof(s_test_tx_state.data)) {
		uint16_t copy_len = MIN(len, (uint16_t)(sizeof(s_test_tx_state.data) -
						       s_test_tx_state.total_len));

		memcpy(&s_test_tx_state.data[s_test_tx_state.total_len], data,
		       copy_len);
	}
	s_test_tx_state.total_len += len;
	return s_test_notify_ret;
#else
	return bt_gatt_notify(conn, attr, data, len);
#endif
}

/* --------------------------------------------------------------------------
 * Connection management
 * -------------------------------------------------------------------------- */

static const struct bt_data s_ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BLE_UART_SERVICE_UUID_VAL),
};

static void on_connected(struct bt_conn *conn, uint8_t err,
			 uint32_t generation)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(generation);

	if (err) {
		LOG_ERR("BLE connect error %u", err);
		return;
	}

	k_mutex_lock(&s_rx_mutex, K_FOREVER);
	s_rx_len = 0;
	s_rx_esc = false;
	s_rx_overflow = false;
	k_mutex_unlock(&s_rx_mutex);
	LOG_INF("BLE phone connected");
}

static void on_disconnected(struct bt_conn *conn, uint8_t reason,
			    uint32_t generation)
{
	ARG_UNUSED(conn);
	ARG_UNUSED(generation);

	k_mutex_lock(&s_rx_mutex, K_FOREVER);
	s_rx_len = 0;
	s_rx_esc = false;
	s_rx_overflow = false;
	k_mutex_unlock(&s_rx_mutex);

	LOG_INF("BLE phone disconnected (reason %u)", reason);
	(void)ble_app_owner_restart(BLE_APP_OWNER_SURFACE_NATIVE);
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int ble_uart_send_slip(const uint8_t *ipv6, size_t len)
{
	/* Worst-case SLIP frame: every byte escaped → 2x len, plus 2 END bytes.
	 * Protected by s_tx_mutex below. */
	static uint8_t s_tx_frame[SLIP_BUF_SIZE * 2u + 2u];
	uint16_t fi = 0;
	int rc = 0;
	struct bt_conn *conn;

	rc = ble_app_owner_conn_ref(BLE_APP_OWNER_SURFACE_NATIVE, &conn);
	if (rc < 0) {
		return rc;
	}

	/* Validate input length to prevent overflow */
	if (len > SLIP_BUF_SIZE) {
		rc = -ENOMEM;
		goto out_unref;
	}

	if (ipv6 == NULL && len > 0u) {
		rc = -EINVAL;
		goto out_unref;
	}

	k_mutex_lock(&s_tx_mutex, K_FOREVER);

	/* Encode SLIP frame — check space before each write to prevent overflow */
	s_tx_frame[fi++] = SLIP_END;
	for (size_t i = 0; i < len; i++) {
		if (ipv6[i] == SLIP_END) {
			/* Escape sequence needs 2 bytes + 1 reserved for trailing END */
			if (fi + 2u > sizeof(s_tx_frame) - 1u) {
				rc = -ENOMEM;
				goto out;
			}
			s_tx_frame[fi++] = SLIP_ESC;
			s_tx_frame[fi++] = SLIP_ESC_END;
		} else if (ipv6[i] == SLIP_ESC) {
			/* Escape sequence needs 2 bytes + 1 reserved for trailing END */
			if (fi + 2u > sizeof(s_tx_frame) - 1u) {
				rc = -ENOMEM;
				goto out;
			}
			s_tx_frame[fi++] = SLIP_ESC;
			s_tx_frame[fi++] = SLIP_ESC_ESC;
		} else {
			/* Regular byte needs 1 byte + 1 reserved for trailing END */
			if (fi + 1u > sizeof(s_tx_frame) - 1u) {
				rc = -ENOMEM;
				goto out;
			}
			s_tx_frame[fi++] = ipv6[i];
		}
	}
	s_tx_frame[fi++] = SLIP_END;

	/* Send in chunks ≤ (ATT_MTU − 3) bytes; default MTU gives 20 bytes */
	uint16_t mtu    = uart_bt_gatt_get_mtu(conn);
	uint16_t chunk  = (mtu > 3u) ? (uint16_t)(mtu - 3u) : 20u;

	for (uint16_t off = 0; off < fi; off += chunk) {
		uint16_t n = MIN(chunk, (uint16_t)(fi - off));
		rc = uart_bt_gatt_notify(conn,
					 &nus_svc.attrs[NUS_TX_VAL_IDX],
					 &s_tx_frame[off], n);
		if (rc < 0) {
			goto out;
		}
	}
	rc = 0;

out:
	k_mutex_unlock(&s_tx_mutex);
out_unref:
	ble_app_owner_conn_unref(conn);
	return rc;
}

int ble_uart_init(void)
{
	const struct ble_app_owner_advertising adv = {
		.surface = BLE_APP_OWNER_SURFACE_NATIVE,
		.ad = s_ad,
		.ad_len = ARRAY_SIZE(s_ad),
		.name = CONFIG_BT_DEVICE_NAME,
		.connected = on_connected,
		.disconnected = on_disconnected,
	};

	return ble_app_owner_start(&adv);
}

#ifdef CONFIG_ZTEST
enum {
	BLE_UART_ATTR_SERVICE = 0,
	BLE_UART_ATTR_RX_CHRC = 1,
	BLE_UART_ATTR_RX_VALUE = 2,
	BLE_UART_ATTR_TX_CHRC = 3,
	BLE_UART_ATTR_TX_VALUE = 4,
	BLE_UART_ATTR_TX_CCC = 5,
	BLE_UART_ATTR_VERSION_CHRC = 6,
	BLE_UART_ATTR_VERSION_VALUE = 7,
	BLE_UART_ATTR_CAPABILITIES_CHRC = 8,
	BLE_UART_ATTR_CAPABILITIES_VALUE = 9,
};

static void copy_uuid128(uint8_t dst[16], const struct bt_uuid_128 *uuid)
{
	memcpy(dst, uuid->val, 16U);
}

static void copy_attr_uuid128(uint8_t dst[16], const struct bt_gatt_attr *attr)
{
	const struct bt_uuid_128 *uuid = CONTAINER_OF(attr->uuid,
						      struct bt_uuid_128,
						      uuid);

	copy_uuid128(dst, uuid);
}

static void copy_chrc_uuid128(uint8_t dst[16], const struct bt_gatt_attr *attr)
{
	const struct bt_gatt_chrc *chrc = attr->user_data;
	const struct bt_uuid_128 *uuid = CONTAINER_OF(chrc->uuid,
						      struct bt_uuid_128,
						      uuid);

	copy_uuid128(dst, uuid);
}

static void copy_service_uuid128(uint8_t dst[16], const struct bt_gatt_attr *attr)
{
	const struct bt_uuid_128 *uuid = CONTAINER_OF(attr->user_data,
						      struct bt_uuid_128,
						      uuid);

	copy_uuid128(dst, uuid);
}

static uint8_t chrc_props(const struct bt_gatt_attr *attr)
{
	const struct bt_gatt_chrc *chrc = attr->user_data;

	return chrc->properties;
}

int ble_uart_test_copy_profile(struct ble_uart_test_profile *profile)
{
	if (profile == NULL) {
		return -EINVAL;
	}

	memset(profile, 0, sizeof(*profile));
	profile->legacy_nus =
		IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS);
	profile->has_version_capabilities = !profile->legacy_nus;
	copy_uuid128(profile->service_uuid, &ble_uart_svc_uuid);
	copy_uuid128(profile->rx_uuid, &ble_uart_rx_uuid);
	copy_uuid128(profile->tx_uuid, &ble_uart_tx_uuid);
#if !IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS)
	copy_uuid128(profile->version_uuid, &ble_uart_version_uuid);
	copy_uuid128(profile->capabilities_uuid, &ble_uart_capabilities_uuid);
	memcpy(profile->version, s_lci_version, sizeof(profile->version));
	memcpy(profile->capabilities, s_lci_capabilities,
	       sizeof(profile->capabilities));
#endif

	return 0;
}

int ble_uart_test_copy_gatt_shape(struct ble_uart_test_gatt_shape *shape)
{
	if (shape == NULL) {
		return -EINVAL;
	}

	memset(shape, 0, sizeof(*shape));
	shape->attr_count = nus_svc.attr_count;
	copy_service_uuid128(shape->service_uuid,
			     &nus_svc.attrs[BLE_UART_ATTR_SERVICE]);
	copy_chrc_uuid128(shape->rx_chrc_uuid,
			  &nus_svc.attrs[BLE_UART_ATTR_RX_CHRC]);
	copy_attr_uuid128(shape->rx_value_uuid,
			  &nus_svc.attrs[BLE_UART_ATTR_RX_VALUE]);
	copy_chrc_uuid128(shape->tx_chrc_uuid,
			  &nus_svc.attrs[BLE_UART_ATTR_TX_CHRC]);
	copy_attr_uuid128(shape->tx_value_uuid,
			  &nus_svc.attrs[BLE_UART_ATTR_TX_VALUE]);
	shape->rx_chrc_props = chrc_props(&nus_svc.attrs[BLE_UART_ATTR_RX_CHRC]);
	shape->tx_chrc_props = chrc_props(&nus_svc.attrs[BLE_UART_ATTR_TX_CHRC]);
	shape->rx_value_perm = nus_svc.attrs[BLE_UART_ATTR_RX_VALUE].perm;
	shape->tx_value_perm = nus_svc.attrs[BLE_UART_ATTR_TX_VALUE].perm;
	shape->tx_ccc_perm = nus_svc.attrs[BLE_UART_ATTR_TX_CCC].perm;
	shape->rx_has_write =
		nus_svc.attrs[BLE_UART_ATTR_RX_VALUE].write == ble_lci_rx_write;
	shape->tx_has_read_write =
		nus_svc.attrs[BLE_UART_ATTR_TX_VALUE].read == NULL &&
		nus_svc.attrs[BLE_UART_ATTR_TX_VALUE].write == NULL;

#if !IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS)
	copy_chrc_uuid128(shape->version_chrc_uuid,
			  &nus_svc.attrs[BLE_UART_ATTR_VERSION_CHRC]);
	copy_attr_uuid128(shape->version_value_uuid,
			  &nus_svc.attrs[BLE_UART_ATTR_VERSION_VALUE]);
	copy_chrc_uuid128(shape->capabilities_chrc_uuid,
			  &nus_svc.attrs[BLE_UART_ATTR_CAPABILITIES_CHRC]);
	copy_attr_uuid128(shape->capabilities_value_uuid,
			  &nus_svc.attrs[BLE_UART_ATTR_CAPABILITIES_VALUE]);
	shape->version_chrc_props =
		chrc_props(&nus_svc.attrs[BLE_UART_ATTR_VERSION_CHRC]);
	shape->capabilities_chrc_props =
		chrc_props(&nus_svc.attrs[BLE_UART_ATTR_CAPABILITIES_CHRC]);
	shape->version_value_perm =
		nus_svc.attrs[BLE_UART_ATTR_VERSION_VALUE].perm;
	shape->capabilities_value_perm =
		nus_svc.attrs[BLE_UART_ATTR_CAPABILITIES_VALUE].perm;
	shape->version_has_read =
		nus_svc.attrs[BLE_UART_ATTR_VERSION_VALUE].read ==
		ble_lci_read_static;
	shape->capabilities_has_read =
		nus_svc.attrs[BLE_UART_ATTR_CAPABILITIES_VALUE].read ==
		ble_lci_read_static;
#endif

	return 0;
}

ssize_t ble_uart_test_write_rx(struct bt_conn *conn, const uint8_t *data,
			       uint16_t len)
{
	return nus_svc.attrs[BLE_UART_ATTR_RX_VALUE].write(
		conn, &nus_svc.attrs[BLE_UART_ATTR_RX_VALUE], data, len, 0U, 0U);
}

ssize_t ble_uart_test_read_version(uint8_t *buf, uint16_t len, uint16_t offset)
{
#if IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS)
	ARG_UNUSED(buf);
	ARG_UNUSED(len);
	ARG_UNUSED(offset);
	return -ENOTSUP;
#else
	return nus_svc.attrs[BLE_UART_ATTR_VERSION_VALUE].read(
		NULL, &nus_svc.attrs[BLE_UART_ATTR_VERSION_VALUE], buf, len,
		offset);
#endif
}

ssize_t ble_uart_test_read_capabilities(uint8_t *buf, uint16_t len,
					uint16_t offset)
{
#if IS_ENABLED(CONFIG_LORA_LICHEN_BLE_LEGACY_NUS)
	ARG_UNUSED(buf);
	ARG_UNUSED(len);
	ARG_UNUSED(offset);
	return -ENOTSUP;
#else
	return nus_svc.attrs[BLE_UART_ATTR_CAPABILITIES_VALUE].read(
		NULL, &nus_svc.attrs[BLE_UART_ATTR_CAPABILITIES_VALUE], buf, len,
		offset);
#endif
}

void ble_uart_test_seed_rx_state(uint16_t rx_len, bool rx_esc,
				 bool rx_overflow)
{
	k_mutex_lock(&s_rx_mutex, K_FOREVER);
	s_rx_len = MIN(rx_len, (uint16_t)sizeof(s_rx_buf));
	s_rx_esc = rx_esc;
	s_rx_overflow = rx_overflow;
	k_mutex_unlock(&s_rx_mutex);
}

int ble_uart_test_copy_state(struct ble_uart_test_state *state)
{
	struct ble_app_owner_test_state owner_state;

	if (state == NULL) {
		return -EINVAL;
	}

	state->has_connection =
		ble_app_owner_test_copy_state(&owner_state) == 0 &&
		owner_state.has_connection;

	k_mutex_lock(&s_rx_mutex, K_FOREVER);
	state->rx_len = s_rx_len;
	state->rx_esc = s_rx_esc;
	state->rx_overflow = s_rx_overflow;
	k_mutex_unlock(&s_rx_mutex);

	return 0;
}

void ble_uart_test_set_tx_backend(uint16_t mtu, int notify_ret)
{
	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	s_test_mtu = mtu;
	s_test_notify_ret = notify_ret;
	memset(&s_test_tx_state, 0, sizeof(s_test_tx_state));
	k_mutex_unlock(&s_tx_mutex);
}

int ble_uart_test_copy_tx_state(struct ble_uart_test_tx_state *state)
{
	if (state == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	*state = s_test_tx_state;
	k_mutex_unlock(&s_tx_mutex);

	return 0;
}
#endif
