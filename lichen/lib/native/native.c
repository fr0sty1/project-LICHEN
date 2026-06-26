/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/*
 * LICHEN Native protocol — USB CDC-ACM transport + CBOR framing.
 *
 * Framing (spec/lichen-native/01-framing.md):
 *   [0xC1][LEN_HI][LEN_LO][CBOR payload of LEN bytes]
 *
 * Transport: the device whose alias is "native-uart" in the chosen node
 * (must be a CDC-ACM UART).  The board overlay sets:
 *   / { chosen { lichen,native-uart = &cdc_acm_uart0; }; };
 */

#include <lichen/native.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#if IS_ENABLED(CONFIG_USB_DEVICE_STACK)
#include <zephyr/usb/usb_device.h>
#include <zephyr/init.h>
#endif
#include <string.h>

LOG_MODULE_REGISTER(lichen_native, LOG_LEVEL_INF);

#if IS_ENABLED(CONFIG_USB_DEVICE_STACK)
/* Enable USB early so CDC-ACM enumerates before peripheral drivers start,
 * allowing console output even if LoRa/GNSS init fails. */
static int lichen_usb_early_init(void)
{
	int ret = usb_enable(NULL);
	return (ret == -EALREADY) ? 0 : ret;
}
SYS_INIT(lichen_usb_early_init, APPLICATION, 0);
#endif

/* --------------------------------------------------------------------------
 * Minimal CBOR encoding helpers — integer-keyed map only
 * -------------------------------------------------------------------------- */

/* Returns new position after writing, or -1 if buffer exhausted.
 * All helpers propagate -1 from a prior call so callers can chain them. */
static int cbor_uint(uint8_t *buf, int pos, int cap, uint64_t val)
{
	if (pos < 0) { return -1; }
	if (val <= 0x17u) {
		if (pos + 1 > cap) { return -1; }
		buf[pos++] = (uint8_t)(0x00u | val);
	} else if (val <= 0xFFu) {
		if (pos + 2 > cap) { return -1; }
		buf[pos++] = 0x18u;
		buf[pos++] = (uint8_t)val;
	} else if (val <= 0xFFFFu) {
		if (pos + 3 > cap) { return -1; }
		buf[pos++] = 0x19u;
		buf[pos++] = (uint8_t)(val >> 8);
		buf[pos++] = (uint8_t)val;
	} else if (val <= 0xFFFFFFFFu) {
		if (pos + 5 > cap) { return -1; }
		buf[pos++] = 0x1au;
		buf[pos++] = (uint8_t)(val >> 24);
		buf[pos++] = (uint8_t)(val >> 16);
		buf[pos++] = (uint8_t)(val >> 8);
		buf[pos++] = (uint8_t)val;
	} else {
		if (pos + 9 > cap) { return -1; }
		buf[pos++] = 0x1bu;
		for (int i = 7; i >= 0; i--) {
			buf[pos++] = (uint8_t)(val >> (i * 8));
		}
	}
	return pos;
}

static int cbor_int(uint8_t *buf, int pos, int cap, int64_t val)
{
	if (pos < 0) { return -1; }
	if (val >= 0) {
		return cbor_uint(buf, pos, cap, (uint64_t)val);
	}
	/* negative: encode as 0x20 | (n - 1) where n = -val */
	uint64_t n = (uint64_t)(-(val + 1));
	if (n <= 0x17u) {
		if (pos + 1 > cap) { return -1; }
		buf[pos++] = (uint8_t)(0x20u | n);
	} else if (n <= 0xFFu) {
		if (pos + 2 > cap) { return -1; }
		buf[pos++] = 0x38u;
		buf[pos++] = (uint8_t)n;
	} else if (n <= 0xFFFFu) {
		if (pos + 3 > cap) { return -1; }
		buf[pos++] = 0x39u;
		buf[pos++] = (uint8_t)(n >> 8);
		buf[pos++] = (uint8_t)n;
	} else {
		if (pos + 5 > cap) { return -1; }
		buf[pos++] = 0x3au;
		buf[pos++] = (uint8_t)(n >> 24);
		buf[pos++] = (uint8_t)(n >> 16);
		buf[pos++] = (uint8_t)(n >> 8);
		buf[pos++] = (uint8_t)n;
	}
	return pos;
}

static int cbor_bstr(uint8_t *buf, int pos, int cap, const uint8_t *data, size_t len)
{
	if (pos < 0) { return -1; }
	/* header */
	if (len <= 0x17u) {
		if (pos + 1 > cap) { return -1; }
		buf[pos++] = (uint8_t)(0x40u | len);
	} else if (len <= 0xFFu) {
		if (pos + 2 > cap) { return -1; }
		buf[pos++] = 0x58u;
		buf[pos++] = (uint8_t)len;
	} else {
		if (pos + 3 > cap) { return -1; }
		buf[pos++] = 0x59u;
		buf[pos++] = (uint8_t)(len >> 8);
		buf[pos++] = (uint8_t)len;
	}
	if (pos + (int)len > cap) { return -1; }
	memcpy(buf + pos, data, len);
	return pos + (int)len;
}

static int cbor_tstr(uint8_t *buf, int pos, int cap, const char *s)
{
	if (pos < 0) { return -1; }
	size_t len = strlen(s);
	if (len <= 0x17u) {
		if (pos + 1 > cap) { return -1; }
		buf[pos++] = (uint8_t)(0x60u | len);
	} else if (len <= 0xFFu) {
		if (pos + 2 > cap) { return -1; }
		buf[pos++] = 0x78u;
		buf[pos++] = (uint8_t)len;
	} else {
		if (pos + 3 > cap) { return -1; }
		buf[pos++] = 0x79u;
		buf[pos++] = (uint8_t)(len >> 8);
		buf[pos++] = (uint8_t)len;
	}
	if (pos + (int)len > cap) { return -1; }
	memcpy(buf + pos, s, len);
	return pos + (int)len;
}

static int cbor_map(uint8_t *buf, int pos, int cap, uint32_t n_items)
{
	if (pos < 0) { return -1; }
	if (n_items <= 0x17u) {
		if (pos + 1 > cap) { return -1; }
		buf[pos++] = (uint8_t)(0xa0u | n_items);
	} else if (n_items <= 0xFFu) {
		if (pos + 2 > cap) { return -1; }
		buf[pos++] = 0xb8u;
		buf[pos++] = (uint8_t)n_items;
	} else {
		return -1;
	}
	return pos;
}

static int cbor_array(uint8_t *buf, int pos, int cap, uint32_t n_items)
{
	if (pos < 0) { return -1; }
	if (n_items <= 0x17u) {
		if (pos + 1 > cap) { return -1; }
		buf[pos++] = (uint8_t)(0x80u | n_items);
	} else {
		return -1;
	}
	return pos;
}

static int cbor_bool(uint8_t *buf, int pos, int cap, bool val)
{
	if (pos < 0) { return -1; }
	if (pos + 1 > cap) { return -1; }
	buf[pos++] = val ? 0xf5u : 0xf4u;
	return pos;
}

/* --------------------------------------------------------------------------
 * TX path: framing + UART write
 * -------------------------------------------------------------------------- */

#define TX_BUF_SIZE CONFIG_LICHEN_NATIVE_TX_BUF_SIZE
#define RX_BUF_SIZE CONFIG_LICHEN_NATIVE_RX_BUF_SIZE

static const struct device *s_uart;
static K_MUTEX_DEFINE(s_tx_mutex);
static uint8_t s_tx_buf[TX_BUF_SIZE];

static bool s_log_subscribed;
static lichen_native_rx_cb_t s_rx_cb;

/* Write a complete frame: [0xC1][LEN_HI][LEN_LO][payload] */
static int native_send_frame(const uint8_t *payload, uint16_t len)
{
	int ret = 0;

	if (!s_uart || !device_is_ready(s_uart)) {
		return -ENODEV;
	}

	k_mutex_lock(&s_tx_mutex, K_FOREVER);

	uart_poll_out(s_uart, 0xC1u);
	uart_poll_out(s_uart, (uint8_t)(len >> 8));
	uart_poll_out(s_uart, (uint8_t)len);
	for (uint16_t i = 0; i < len; i++) {
		uart_poll_out(s_uart, payload[i]);
	}

	k_mutex_unlock(&s_tx_mutex);
	return ret;
}

/* Encode CBOR payload into s_tx_buf and send. */
static int send_payload(int pos)
{
	if (pos < 0 || pos > TX_BUF_SIZE) {
		LOG_ERR("CBOR encode overflow");
		return -ENOMEM;
	}
	return native_send_frame(s_tx_buf, (uint16_t)pos);
}

/* --------------------------------------------------------------------------
 * RX path: interrupt-driven byte stream → frame reassembly → callback
 * -------------------------------------------------------------------------- */

#define RX_STACK_SIZE CONFIG_LICHEN_NATIVE_RX_STACK_SIZE

K_THREAD_STACK_DEFINE(s_rx_stack, RX_STACK_SIZE);
static struct k_thread s_rx_thread;

/* Ring buffer for RX bytes from ISR */
K_MSGQ_DEFINE(s_rx_msgq, 1, 512, 1);

static uint8_t s_rx_payload[RX_BUF_SIZE];

static void uart_rx_isr(const struct device *dev, void *user_data)
{
	ARG_UNUSED(user_data);

	if (!uart_irq_update(dev) || !uart_irq_rx_ready(dev)) {
		return;
	}

	uint8_t byte;
	while (uart_fifo_read(dev, &byte, 1) == 1) {
		k_msgq_put(&s_rx_msgq, &byte, K_NO_WAIT);
	}
}

/* Pre-parse CBOR map key 0 (message type) from payload. Returns -1 if unparseable. */
static int parse_msg_type(const uint8_t *buf, size_t len)
{
	if (len < 2) {
		return -1;
	}
	/* expect map header (0xa1..0xb7 or 0xb8) at byte 0, then key 0 (0x00), then type */
	size_t pos = 0;
	uint8_t b = buf[pos++];
	if ((b & 0xe0u) != 0xa0u) {
		return -1; /* not a map */
	}
	/* key 0 */
	if (pos >= len || buf[pos++] != 0x00u) {
		return -1;
	}
	/* value = message type uint */
	if (pos >= len) {
		return -1;
	}
	b = buf[pos];
	if (b <= 0x17u) {
		return (int)b;
	}
	if (b == 0x18u && pos + 1 < len) {
		return (int)buf[pos + 1];
	}
	return -1;
}

static void rx_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);

	enum { S_SYNC, S_LEN_HI, S_LEN_LO, S_PAYLOAD } state = S_SYNC;
	uint16_t expected_len = 0;
	uint16_t rx_pos = 0;
	uint8_t byte;

	while (1) {
		k_msgq_get(&s_rx_msgq, &byte, K_FOREVER);

		switch (state) {
		case S_SYNC:
			if (byte == 0xC1u) {
				state = S_LEN_HI;
			}
			break;

		case S_LEN_HI:
			expected_len = (uint16_t)byte << 8;
			state = S_LEN_LO;
			break;

		case S_LEN_LO:
			expected_len |= byte;
			rx_pos = 0;
			if (expected_len == 0 || expected_len > RX_BUF_SIZE) {
				LOG_WRN("bad frame len %u — resyncing", expected_len);
				state = S_SYNC;
			} else {
				state = S_PAYLOAD;
			}
			break;

		case S_PAYLOAD:
			s_rx_payload[rx_pos++] = byte;
			if (rx_pos == expected_len) {
				int type = parse_msg_type(s_rx_payload, expected_len);
				if (type < 0) {
					LOG_WRN("CBOR parse failed — dropping frame");
				} else if (s_rx_cb) {
					s_rx_cb((uint8_t)type, s_rx_payload, expected_len);
				}
				state = S_SYNC;
			}
			break;
		}
	}
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int lichen_native_init(lichen_native_rx_cb_t rx_cb)
{
	s_rx_cb = rx_cb;
	s_log_subscribed = false;

#if IS_ENABLED(CONFIG_USB_DEVICE_STACK)
	int usb_ret = usb_enable(NULL);
	if (usb_ret && usb_ret != -EALREADY) {
		LOG_ERR("USB enable failed: %d", usb_ret);
	}
#endif

#if DT_HAS_CHOSEN(lichen_native_uart)
	s_uart = DEVICE_DT_GET(DT_CHOSEN(lichen_native_uart));
#else
	LOG_ERR("lichen,native-uart not set in chosen");
	return -ENODEV;
#endif

	if (!device_is_ready(s_uart)) {
		LOG_ERR("native UART not ready");
		return -ENODEV;
	}

	uart_irq_callback_set(s_uart, uart_rx_isr);
	uart_irq_rx_enable(s_uart);

	k_thread_create(&s_rx_thread, s_rx_stack, RX_STACK_SIZE,
			rx_thread_fn, NULL, NULL, NULL,
			K_PRIO_COOP(7), 0, K_NO_WAIT);
	k_thread_name_set(&s_rx_thread, "native_rx");

	return 0;
}

int lichen_native_send_hello(void)
{
	/* Supported message types we implement on the device side */
	static const uint8_t supported[] = {
		LN_TYPE_HELLO,
		LN_TYPE_CONFIG_GET,
		LN_TYPE_CONFIG_RESULT,
		LN_TYPE_SEND_MESSAGE,
		LN_TYPE_MESSAGE_RECEIVED,
		LN_TYPE_NODE_INFO,
		LN_TYPE_LOG_ENTRY,
		LN_TYPE_LOG_SUBSCRIBE,
	};
	const int N_SUPPORTED = ARRAY_SIZE(supported);

	/*
	 * hello map has 5 fixed keys + 1 features sub-map:
	 *   0:type  1:version  2:[types]  3:fw  7:{4:has_gps}
	 * Count: 5 top-level keys
	 */
	int pos = 0;
	const int cap = TX_BUF_SIZE;

#if IS_ENABLED(CONFIG_GNSS_AG3335)
	const bool has_gps = true;
#else
	const bool has_gps = false;
#endif

	int n_top = 5; /* 0,1,2,3,7 */
	pos = cbor_map(s_tx_buf, pos, cap, n_top);
	/* 0: type = hello */
	pos = cbor_uint(s_tx_buf, pos, cap, 0);
	pos = cbor_uint(s_tx_buf, pos, cap, LN_TYPE_HELLO);
	/* 1: protocol version = 1 */
	pos = cbor_uint(s_tx_buf, pos, cap, 1);
	pos = cbor_uint(s_tx_buf, pos, cap, 1);
	/* 2: supported types array */
	pos = cbor_uint(s_tx_buf, pos, cap, 2);
	pos = cbor_array(s_tx_buf, pos, cap, N_SUPPORTED);
	for (int i = 0; i < N_SUPPORTED; i++) {
		pos = cbor_uint(s_tx_buf, pos, cap, supported[i]);
	}
	/* 3: firmware string */
	pos = cbor_uint(s_tx_buf, pos, cap, 3);
	pos = cbor_tstr(s_tx_buf, pos, cap, "lichen-fw-0.1.0");
	/* 7: features {4: has_gps} */
	pos = cbor_uint(s_tx_buf, pos, cap, 7);
	pos = cbor_map(s_tx_buf, pos, cap, 1);
	pos = cbor_uint(s_tx_buf, pos, cap, 4);
	pos = cbor_bool(s_tx_buf, pos, cap, has_gps);

	return send_payload(pos);
}

int lichen_native_send_node_info(const char *name,
				 const char *fw_version,
				 const char *hw_model,
				 uint64_t uptime_ms,
				 const uint8_t iid[8],
				 const struct ln_gps_info *gps,
				 const struct ln_radio_stats *radio)
{
	int pos = 0;
	const int cap = TX_BUF_SIZE;

	/* Count how many optional top-level keys we'll include */
	int n_top = 5; /* 0,1,5 always + name(2),fw(3),hw(4),uptime(5)... */
	n_top = 1;     /* 0: type */
	n_top += 1;    /* 1: iid */
	if (name)       { n_top++; } /* 2 */
	if (fw_version) { n_top++; } /* 3 */
	if (hw_model)   { n_top++; } /* 4 */
	n_top += 1;                  /* 5: uptime */
	if (gps && gps->valid) { n_top++; }   /* 7 */
	if (radio) { n_top++; }               /* 8 */

	pos = cbor_map(s_tx_buf, pos, cap, n_top);

	/* 0: node_info type */
	pos = cbor_uint(s_tx_buf, pos, cap, 0);
	pos = cbor_uint(s_tx_buf, pos, cap, LN_TYPE_NODE_INFO);

	/* 1: IID */
	pos = cbor_uint(s_tx_buf, pos, cap, 1);
	pos = cbor_bstr(s_tx_buf, pos, cap, iid, 8);

	/* 2: name */
	if (name) {
		pos = cbor_uint(s_tx_buf, pos, cap, 2);
		pos = cbor_tstr(s_tx_buf, pos, cap, name);
	}

	/* 3: firmware */
	if (fw_version) {
		pos = cbor_uint(s_tx_buf, pos, cap, 3);
		pos = cbor_tstr(s_tx_buf, pos, cap, fw_version);
	}

	/* 4: hardware */
	if (hw_model) {
		pos = cbor_uint(s_tx_buf, pos, cap, 4);
		pos = cbor_tstr(s_tx_buf, pos, cap, hw_model);
	}

	/* 5: uptime_ms */
	pos = cbor_uint(s_tx_buf, pos, cap, 5);
	pos = cbor_uint(s_tx_buf, pos, cap, uptime_ms);

	/* 7: GPS */
	if (gps && gps->valid) {
		/* gps_info keys: 1=lat 2=lon 3=alt 5=sats (4 keys) */
		int n_gps = 4;
		pos = cbor_uint(s_tx_buf, pos, cap, 7);
		pos = cbor_map(s_tx_buf, pos, cap, n_gps);
		pos = cbor_uint(s_tx_buf, pos, cap, 1);
		pos = cbor_int(s_tx_buf, pos, cap, gps->lat_udeg);
		pos = cbor_uint(s_tx_buf, pos, cap, 2);
		pos = cbor_int(s_tx_buf, pos, cap, gps->lon_udeg);
		pos = cbor_uint(s_tx_buf, pos, cap, 3);
		pos = cbor_int(s_tx_buf, pos, cap, gps->alt_cm);
		pos = cbor_uint(s_tx_buf, pos, cap, 5);
		pos = cbor_uint(s_tx_buf, pos, cap, gps->satellites);
	}

	/* 8: radio stats */
	if (radio) {
		pos = cbor_uint(s_tx_buf, pos, cap, 8);
		pos = cbor_map(s_tx_buf, pos, cap, 2);
		pos = cbor_uint(s_tx_buf, pos, cap, 1);
		pos = cbor_uint(s_tx_buf, pos, cap, radio->tx_pkts);
		pos = cbor_uint(s_tx_buf, pos, cap, 2);
		pos = cbor_uint(s_tx_buf, pos, cap, radio->rx_pkts);
	}

	return send_payload(pos);
}

int lichen_native_send_message_received(const uint8_t src_iid[8],
					const uint8_t *payload, size_t len,
					int16_t rssi, int8_t snr)
{
	int pos = 0;
	const int cap = TX_BUF_SIZE;

	/* keys: 0,1,2,5,6 = 5 items */
	pos = cbor_map(s_tx_buf, pos, cap, 5);

	pos = cbor_uint(s_tx_buf, pos, cap, 0);
	pos = cbor_uint(s_tx_buf, pos, cap, LN_TYPE_MESSAGE_RECEIVED);

	pos = cbor_uint(s_tx_buf, pos, cap, 1);
	pos = cbor_bstr(s_tx_buf, pos, cap, src_iid, 8);

	pos = cbor_uint(s_tx_buf, pos, cap, 2);
	pos = cbor_bstr(s_tx_buf, pos, cap, payload, len);

	pos = cbor_uint(s_tx_buf, pos, cap, 5);
	pos = cbor_int(s_tx_buf, pos, cap, rssi);

	pos = cbor_uint(s_tx_buf, pos, cap, 6);
	pos = cbor_int(s_tx_buf, pos, cap, snr);

	return send_payload(pos);
}

bool lichen_native_log_is_subscribed(void)
{
	return s_log_subscribed;
}

int lichen_native_send_log_entry(uint8_t level, const char *module, const char *msg)
{
	if (!s_log_subscribed) {
		return 0;
	}

	int pos = 0;
	const int cap = TX_BUF_SIZE;

	/* keys: 0,1,2,3,4 = 5 items (type, level, msg, module, uptime) */
	pos = cbor_map(s_tx_buf, pos, cap, 5);

	pos = cbor_uint(s_tx_buf, pos, cap, 0);
	pos = cbor_uint(s_tx_buf, pos, cap, LN_TYPE_LOG_ENTRY);

	pos = cbor_uint(s_tx_buf, pos, cap, 1);
	pos = cbor_uint(s_tx_buf, pos, cap, level);

	pos = cbor_uint(s_tx_buf, pos, cap, 2);
	pos = cbor_tstr(s_tx_buf, pos, cap, msg);

	pos = cbor_uint(s_tx_buf, pos, cap, 3);
	pos = cbor_tstr(s_tx_buf, pos, cap, module ? module : "");

	pos = cbor_uint(s_tx_buf, pos, cap, 4);
	pos = cbor_uint(s_tx_buf, pos, cap, (uint64_t)k_uptime_get());

	return send_payload(pos);
}

/* --------------------------------------------------------------------------
 * Incoming message handler (called by RX thread)
 * -------------------------------------------------------------------------- */

/*
 * lichen_native_handle_rx — parse and dispatch an incoming host frame.
 *
 * Call this from the rx_cb you pass to lichen_native_init(), or use it
 * directly as the callback.
 */
void lichen_native_handle_rx(uint8_t msg_type, const uint8_t *buf, size_t len)
{
	ARG_UNUSED(buf); ARG_UNUSED(len);

	switch (msg_type) {
	case LN_TYPE_HELLO:
		/* Host connected — reply with our hello + node_info */
		LOG_INF("host connected");
		lichen_native_send_hello();
		break;

	case LN_TYPE_LOG_SUBSCRIBE: {
		/*
		 * Minimal parse: key 1 is a bool (enable).
		 * Full CBOR parse: find key 0x01 in the map, read bool.
		 * For now, toggle based on key 1 value.
		 */
		bool enable = false;
		/* Walk map: skip type key, look for key 1 */
		size_t pos = 0;
		if (pos < len && (buf[pos] & 0xe0u) == 0xa0u) {
			pos++;
		}
		while (pos + 1 < len) {
			uint8_t k = buf[pos++];
			if (k == 0x01u) { /* key 1 */
				enable = (pos < len && buf[pos] == 0xf5u);
				break;
			}
			/* skip the value — only handles simple types */
			if (pos < len) { pos++; }
		}
		s_log_subscribed = enable;
		LOG_INF("log streaming %s", enable ? "enabled" : "disabled");
		break;
	}

	default:
		LOG_DBG("unhandled msg type 0x%02x", msg_type);
		break;
	}
}
