/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/*
 * Legacy LICHEN Native CBOR protocol — USB CDC-ACM transport + framing.
 *
 * This implements the historical spec/lichen-native draft. It is not the
 * current LCI app contract; current LCI transports carry IPv6 packets and use
 * CoAP resources from spec/11-lci.md.
 *
 * Framing (spec/lichen-native/01-framing.md):
 *   [0xC1][LEN_HI][LEN_LO][CBOR payload of LEN bytes]
 *
 * Transport: the board's HAL serial-local device.  Board overlays may expose
 * lichen,native-uart, zephyr,uart-pipe, zephyr,slip-uart, shell UART, or
 * console UART according to the HAL serial-local precedence policy.
 */

#include <lichen/hal.h>
#include <lichen/native.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/init.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/reboot.h>
#if IS_ENABLED(CONFIG_USB_DEVICE_STACK)
#include <zephyr/usb/usb_device.h>
#if IS_ENABLED(CONFIG_STATS)
#include <zephyr/stats/stats.h>
#endif
#elif IS_ENABLED(CONFIG_USB_DEVICE_STACK_NEXT)
#include <zephyr/usb/usbd.h>
#endif
/* nRF GPREGRET (DFU-touch reboot) — needed for both USB stacks on nRF. */
#if defined(CONFIG_SOC_FAMILY_NORDIC_NRF)
#include <nrfx_power.h>
#endif
#include <zcbor_decode.h>
#include <string.h>

LOG_MODULE_REGISTER(lichen_native, LOG_LEVEL_INF);

/*
 * Watchdog heartbeat hook. The app (e.g. puck main.c) provides a strong
 * definition that refreshes the WDT-feed timestamp; this weak fallback lets
 * the native lib link in apps that don't. Called during the byte-at-a-time
 * CDC writes below: uart_poll_out() blocks while the host drains the TX ring,
 * and native TX runs on the main loop, so without pumping this the heartbeat
 * goes stale and the watchdog resets the SoC ~8 s after a host attaches.
 */
__attribute__((weak)) void lichen_radio_progress(void) { }

#if IS_ENABLED(CONFIG_USB_DEVICE_STACK)
/*
 * USB bus-health monitoring + wedge recovery (lora_ipv6_mesh-1jqj).
 *
 * Opening/closing/DTR-churning the CDC port can wedge the nRF USBD: the host
 * loops on "device descriptor read, error -110" and, until now, only a
 * physical replug recovered. The firmware keeps running throughout, so a
 * low-priority monitor thread can detect the wedge (a bus-reset storm with no
 * successful configure) and reset the USBD peripheral via usb_disable() +
 * usb_enable() — the software equivalent of the VBUS cycle a replug provides.
 *
 * Counters are exported as a Zephyr STATS group ("usb"), readable over the
 * SMP transport (if02) so the USB state can be observed without opening the
 * native port that triggers the wedge.
 */
#if IS_ENABLED(CONFIG_STATS)
STATS_SECT_START(lichen_usb_stats)
STATS_SECT_ENTRY32(reset)
STATS_SECT_ENTRY32(configured)
STATS_SECT_ENTRY32(suspend)
STATS_SECT_ENTRY32(error)
STATS_SECT_ENTRY32(disconnect)
STATS_SECT_ENTRY32(recovery)
STATS_SECT_END;

STATS_NAME_START(lichen_usb_stats)
STATS_NAME(lichen_usb_stats, reset)
STATS_NAME(lichen_usb_stats, configured)
STATS_NAME(lichen_usb_stats, suspend)
STATS_NAME(lichen_usb_stats, error)
STATS_NAME(lichen_usb_stats, disconnect)
STATS_NAME(lichen_usb_stats, recovery)
STATS_NAME_END(lichen_usb_stats);

STATS_SECT_DECL(lichen_usb_stats) lichen_usb_stats;
#define USB_STAT_INC(field) STATS_INC(lichen_usb_stats, field)
#else
#define USB_STAT_INC(field) do { } while (0)
#endif /* CONFIG_STATS */

static atomic_t s_usb_resets_since_cfg;
static atomic_t s_usb_last_cfg_ms;

static void lichen_usb_status_cb(enum usb_dc_status_code status,
				 const uint8_t *param)
{
	ARG_UNUSED(param);

	switch (status) {
	case USB_DC_CONFIGURED:
		atomic_set(&s_usb_resets_since_cfg, 0);
		atomic_set(&s_usb_last_cfg_ms, (atomic_val_t)k_uptime_get());
		USB_STAT_INC(configured);
		break;
	case USB_DC_RESET:
		atomic_inc(&s_usb_resets_since_cfg);
		USB_STAT_INC(reset);
		break;
	case USB_DC_SUSPEND:
		USB_STAT_INC(suspend);
		break;
	case USB_DC_ERROR:
		USB_STAT_INC(error);
		break;
	case USB_DC_DISCONNECTED:
		USB_STAT_INC(disconnect);
		break;
	default:
		break;
	}
}

/*
 * Wedge = many bus resets with no successful configure for a while. BOTH
 * thresholds must trip, so normal enumeration (1-2 resets then configure)
 * and a headless node (no host -> no resets) never trigger a spurious reset.
 */
#define USB_WEDGE_RESET_THRESHOLD 8
#define USB_WEDGE_QUIET_MS        3000
#define USB_MONITOR_PERIOD_MS     1000

static void lichen_usb_monitor_fn(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	while (true) {
		k_sleep(K_MSEC(USB_MONITOR_PERIOD_MS));

		int32_t resets = (int32_t)atomic_get(&s_usb_resets_since_cfg);

		if (resets < USB_WEDGE_RESET_THRESHOLD) {
			continue;
		}

		int64_t since_cfg =
			k_uptime_get() - (int64_t)atomic_get(&s_usb_last_cfg_ms);

		if (since_cfg < USB_WEDGE_QUIET_MS) {
			continue;
		}

		LOG_WRN("USB wedge (%d resets, %lld ms since configure); "
			"resetting USBD peripheral", resets, (long long)since_cfg);
		USB_STAT_INC(recovery);

		(void)usb_disable();
		k_sleep(K_MSEC(100));
		(void)usb_enable(lichen_usb_status_cb);

		atomic_set(&s_usb_resets_since_cfg, 0);
		atomic_set(&s_usb_last_cfg_ms, (atomic_val_t)k_uptime_get());
	}
}

K_THREAD_DEFINE(lichen_usb_monitor, 1024, lichen_usb_monitor_fn, NULL, NULL,
		NULL, K_LOWEST_APPLICATION_THREAD_PRIO, 0, 0);

/* Enable USB early so CDC-ACM enumerates before peripheral drivers start,
 * allowing console output even if LoRa/GNSS init fails. */
static int lichen_usb_early_init(void)
{
#if IS_ENABLED(CONFIG_STATS)
	(void)STATS_INIT_AND_REG(lichen_usb_stats, STATS_SIZE_32, "usb");
#endif
	int ret = usb_enable(lichen_usb_status_cb);

	return (ret == -EALREADY) ? 0 : ret;
}
SYS_INIT(lichen_usb_early_init, APPLICATION, 0);

#elif IS_ENABLED(CONFIG_USB_DEVICE_STACK_NEXT)


USBD_DEVICE_DEFINE(lichen_usbd,
		   DEVICE_DT_GET(DT_NODELABEL(zephyr_udc0)),
		   0x2FE3, 0x0100);

USBD_DESC_LANG_DEFINE(lichen_lang);
USBD_DESC_MANUFACTURER_DEFINE(lichen_mfr, "LICHEN Project");
USBD_DESC_PRODUCT_DEFINE(lichen_product, "LICHEN Node");
USBD_DESC_SERIAL_NUMBER_DEFINE(lichen_sn);

USBD_CONFIGURATION_DEFINE(lichen_fs_config, 0, 100);

static void lichen_usbd_msg_cb(struct usbd_context *const ctx,
			       const struct usbd_msg *msg)
{
	if (usbd_can_detect_vbus(ctx)) {
		if (msg->type == USBD_MSG_VBUS_READY) {
			usbd_enable(ctx);
		} else if (msg->type == USBD_MSG_VBUS_REMOVED) {
			usbd_disable(ctx);
		}
	}
}


static int lichen_usb_early_init(void)
{
	int ret;

	ret = usbd_add_descriptor(&lichen_usbd, &lichen_lang);
	if (ret) { return ret; }
	ret = usbd_add_descriptor(&lichen_usbd, &lichen_mfr);
	if (ret) { return ret; }
	ret = usbd_add_descriptor(&lichen_usbd, &lichen_product);
	if (ret) { return ret; }
	ret = usbd_add_descriptor(&lichen_usbd, &lichen_sn);
	if (ret) { return ret; }

	ret = usbd_add_configuration(&lichen_usbd, USBD_SPEED_FS, &lichen_fs_config);
	if (ret) { return ret; }

	ret = usbd_register_all_classes(&lichen_usbd, USBD_SPEED_FS, 1);
	if (ret) { return ret; }

	/* IAD triple required for multi-interface CDC-ACM (two instances) */
	usbd_device_set_code_triple(&lichen_usbd, USBD_SPEED_FS,
				    USB_BCC_MISCELLANEOUS, 0x02, 0x01);

	ret = usbd_msg_register_cb(&lichen_usbd, lichen_usbd_msg_cb);
	if (ret) { return ret; }

	ret = usbd_init(&lichen_usbd);
	if (ret) { return ret; }

	/* The VBUS_READY callback may have fired during usbd_init() (ghost
	 * event from the UF2 bootloader) before the INITIALIZED state flag
	 * was set, causing usbd_enable() to fail silently.  Check VBUS now
	 * that init is complete and enable directly if VBUS is present.
	 * Hot-plug after boot is handled by lichen_usbd_msg_cb.
	 * -EALREADY: callback fired again after init completed and already
	 * enabled; not an error. */
	if (nrfx_power_usbstatus_get() != NRFX_POWER_USB_STATE_DISCONNECTED) {
		ret = usbd_enable(&lichen_usbd);
		if (ret == -EALREADY) { ret = 0; }
	}

	return ret;
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

#define LN_FRAME_SYNC_BYTE 0xC1u

static const struct device *s_uart;
static K_MUTEX_DEFINE(s_tx_mutex);
static uint8_t s_tx_buf[TX_BUF_SIZE];

static bool s_log_subscribed;
static lichen_native_rx_cb_t s_rx_cb;
static bool s_initialized;
static atomic_t s_rx_shutdown = ATOMIC_INIT(0);
static K_MUTEX_DEFINE(s_init_mutex);

static const uint8_t s_default_supported_types[] = {
	LN_TYPE_HELLO,
	LN_TYPE_MESSAGE_RECEIVED,
	LN_TYPE_NODE_INFO,
	LN_TYPE_LOG_ENTRY,
	LN_TYPE_LOG_SUBSCRIBE,
};

#ifdef LICHEN_NATIVE_TEST_TX
#define TEST_TX_CAPTURE_SIZE 8192U
static K_MUTEX_DEFINE(s_test_tx_mutex);
static uint8_t s_test_tx_capture[TEST_TX_CAPTURE_SIZE];
static size_t s_test_tx_len;
static bool s_test_tx_overflow;

void lichen_native_test_tx_clear(void)
{
	k_mutex_lock(&s_test_tx_mutex, K_FOREVER);
	s_test_tx_len = 0;
	s_test_tx_overflow = false;
	k_mutex_unlock(&s_test_tx_mutex);
}

size_t lichen_native_test_tx_snapshot(uint8_t *buf, size_t cap, bool *overflow)
{
	size_t len;

	k_mutex_lock(&s_test_tx_mutex, K_FOREVER);
	len = MIN(s_test_tx_len, cap);
	memcpy(buf, s_test_tx_capture, len);
	if (overflow != NULL) {
		*overflow = s_test_tx_overflow;
	}
	k_mutex_unlock(&s_test_tx_mutex);

	return len;
}

static void test_tx_byte(uint8_t byte)
{
	k_mutex_lock(&s_test_tx_mutex, K_FOREVER);
	if (s_test_tx_len < sizeof(s_test_tx_capture)) {
		s_test_tx_capture[s_test_tx_len++] = byte;
	} else {
		s_test_tx_overflow = true;
	}
	k_mutex_unlock(&s_test_tx_mutex);
	k_yield();
}
#endif

/* Write a complete frame: [0xC1][LEN_HI][LEN_LO][payload].
 * Caller must hold s_tx_mutex so shared encode buffers cannot be modified
 * while their frame is being emitted.
 */
static int native_send_frame_locked(const uint8_t *payload, uint16_t len)
{
	int ret = 0;

#ifdef LICHEN_NATIVE_TEST_TX
	test_tx_byte(LN_FRAME_SYNC_BYTE);
	test_tx_byte((uint8_t)(len >> 8));
	test_tx_byte((uint8_t)len);
	for (uint16_t i = 0; i < len; i++) {
		test_tx_byte(payload[i]);
	}

	return ret;
#else
	if (!s_uart || !device_is_ready(s_uart)) {
		return -ENODEV;
	}

	/*
	 * Pump the watchdog heartbeat around each blocking write. uart_poll_out()
	 * stalls while the host drains the 1 KB CDC TX ring, and native TX runs on
	 * the main loop (the only other progress source is the radio poll, which we
	 * are not in here). Without this, a slow/attached host stalls the loop and
	 * the WDT-feed timer withholds → SoC reset ~8 s after a host opens the port.
	 */
	lichen_radio_progress();
	uart_poll_out(s_uart, LN_FRAME_SYNC_BYTE);
	uart_poll_out(s_uart, (uint8_t)(len >> 8));
	uart_poll_out(s_uart, (uint8_t)len);
	for (uint16_t i = 0; i < len; i++) {
		lichen_radio_progress();
		uart_poll_out(s_uart, payload[i]);
	}

	return ret;
#endif
}

/* Send payload already encoded into s_tx_buf. Caller must hold s_tx_mutex. */
static int send_payload_locked(int pos)
{
	if (pos < 0 || pos > TX_BUF_SIZE) {
		return -ENOMEM;
	}
	return native_send_frame_locked(s_tx_buf, (uint16_t)pos);
}

static int finish_tx_locked(int pos)
{
	int ret = send_payload_locked(pos);

	k_mutex_unlock(&s_tx_mutex);
	if (ret == -ENOMEM) {
		LOG_ERR("CBOR encode overflow");
	}
	return ret;
}

static int encode_hello(uint8_t *buf, int cap, const uint8_t *supported,
			size_t supported_len)
{
	int pos = 0;

#if IS_ENABLED(CONFIG_GNSS_AG3335)
	const bool has_gps = true;
#else
	const bool has_gps = false;
#endif

	if (buf == NULL || supported == NULL || supported_len > 23) {
		return -EINVAL;
	}

	/*
	 * hello map has 5 top-level keys:
	 *   0:type  1:version  2:[types]  3:fw  7:{4:has_gps}
	 */
	pos = cbor_map(buf, pos, cap, 5);
	/* 0: type = hello */
	pos = cbor_uint(buf, pos, cap, 0);
	pos = cbor_uint(buf, pos, cap, LN_TYPE_HELLO);
	/* 1: protocol version = 1 */
	pos = cbor_uint(buf, pos, cap, 1);
	pos = cbor_uint(buf, pos, cap, 1);
	/* 2: supported types array */
	pos = cbor_uint(buf, pos, cap, 2);
	pos = cbor_array(buf, pos, cap, supported_len);
	for (size_t i = 0; i < supported_len; i++) {
		pos = cbor_uint(buf, pos, cap, supported[i]);
	}
	/* 3: firmware string */
	pos = cbor_uint(buf, pos, cap, 3);
	pos = cbor_tstr(buf, pos, cap, "lichen-fw-0.1.0");
	/* 7: features {4: has_gps} */
	pos = cbor_uint(buf, pos, cap, 7);
	pos = cbor_map(buf, pos, cap, 1);
	pos = cbor_uint(buf, pos, cap, 4);
	pos = cbor_bool(buf, pos, cap, has_gps);

	return pos;
}

#ifdef LICHEN_NATIVE_TEST_PARSE
int lichen_native_encode_hello_for_test(uint8_t *buf, size_t len)
{
	return encode_hello(buf, (int)len, s_default_supported_types,
			    ARRAY_SIZE(s_default_supported_types));
}
#endif

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
#define LN_MSG_TYPE_KEY 0u
#define LN_LOG_SUBSCRIBE_ENABLE_KEY 1u

#ifdef LICHEN_NATIVE_TEST_PARSE
int lichen_native_parse_msg_type_for_test(const uint8_t *buf, size_t len);
int lichen_native_parse_log_subscribe_for_test(const uint8_t *buf, size_t len,
					       bool *enable);
#define PARSE_MSG_TYPE_LINKAGE
#else
#define PARSE_MSG_TYPE_LINKAGE static
#endif

PARSE_MSG_TYPE_LINKAGE int parse_msg_type(const uint8_t *buf, size_t len)
{
	uint32_t key = LN_MSG_TYPE_KEY;
	uint32_t type = 0;
	bool found_type = false;

	if (buf == NULL || len == 0) {
		return -1;
	}

	ZCBOR_STATE_D(zsd, 2, buf, len, 1, 0);

	if (!zcbor_map_start_decode(zsd)) {
		return -1;
	}

	while (!zcbor_array_at_end(zsd)) {
		zcbor_state_t key_state = *zsd;

		if (zcbor_uint32_decode(zsd, &key) && key == LN_MSG_TYPE_KEY) {
			if (!zcbor_uint32_decode(zsd, &type) || type > UINT8_MAX) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -1;
			}
			found_type = true;
			continue;
		}

		(void)zcbor_pop_error(zsd);
		*zsd = key_state;

		if (!zcbor_any_skip(zsd, NULL) || !zcbor_any_skip(zsd, NULL)) {
			(void)zcbor_list_map_end_force_decode(zsd);
			return -1;
		}
	}

	if (!zcbor_map_end_decode(zsd)) {
		(void)zcbor_list_map_end_force_decode(zsd);
		return -1;
	}

	return found_type ? (int)type : -1;
}

#ifdef LICHEN_NATIVE_TEST_PARSE
int lichen_native_parse_msg_type_for_test(const uint8_t *buf, size_t len)
{
	return parse_msg_type(buf, len);
}
#endif

static int parse_log_subscribe_enable(const uint8_t *buf, size_t len, bool *enable)
{
	uint32_t key = 0;
	bool decoded_enable = false;
	bool found_enable = false;

	if (buf == NULL || len == 0 || enable == NULL) {
		return -EINVAL;
	}

	ZCBOR_STATE_D(zsd, 2, buf, len, 1, 0);

	if (!zcbor_map_start_decode(zsd)) {
		return -EINVAL;
	}

	while (!zcbor_array_at_end(zsd)) {
		zcbor_state_t key_state = *zsd;

		if (zcbor_uint32_decode(zsd, &key) &&
		    key == LN_LOG_SUBSCRIBE_ENABLE_KEY) {
			if (!zcbor_bool_decode(zsd, &decoded_enable)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			found_enable = true;
			continue;
		}

		(void)zcbor_pop_error(zsd);
		*zsd = key_state;

		if (!zcbor_any_skip(zsd, NULL) || !zcbor_any_skip(zsd, NULL)) {
			(void)zcbor_list_map_end_force_decode(zsd);
			return -EINVAL;
		}
	}

	if (!zcbor_map_end_decode(zsd) || !found_enable) {
		(void)zcbor_list_map_end_force_decode(zsd);
		return -EINVAL;
	}

	*enable = decoded_enable;
	return 0;
}

#ifdef LICHEN_NATIVE_TEST_PARSE
int lichen_native_parse_log_subscribe_for_test(const uint8_t *buf, size_t len,
					       bool *enable)
{
	return parse_log_subscribe_enable(buf, len, enable);
}
#endif

static void rx_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1); ARG_UNUSED(p2); ARG_UNUSED(p3);

	enum { S_SYNC, S_LEN_HI, S_LEN_LO, S_PAYLOAD } state = S_SYNC;
	uint16_t expected_len = 0;
	uint16_t rx_pos = 0;
	uint8_t byte;

	while (true) {
		k_msgq_get(&s_rx_msgq, &byte, K_FOREVER);

		if (atomic_get(&s_rx_shutdown)) {
			break;
		}

		switch (state) {
		case S_SYNC:
			if (byte == LN_FRAME_SYNC_BYTE) {
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
				} else {
					lichen_native_rx_cb_t rx_cb;

					k_mutex_lock(&s_init_mutex, K_FOREVER);
					rx_cb = s_rx_cb;
					k_mutex_unlock(&s_init_mutex);

					if (rx_cb) {
						rx_cb((uint8_t)type, s_rx_payload, expected_len);
					}
				}
				state = S_SYNC;
			}
			break;
		}
	}
}

/* --------------------------------------------------------------------------
 * Platform helpers — buzzer + 1200-bps DFU touch (nRF, stack-agnostic)
 *
 * These are gated by board features, NOT the USB stack, so they work with
 * either USB_DEVICE_STACK (old) or USB_DEVICE_STACK_NEXT.
 * -------------------------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LICHEN_NATIVE_BUZZER)
/*
 * T1000-E buzzer: P0.25 (signal) + P1.05 (enable, active-high).
 * 2 kHz square wave, n beeps of 150 ms each separated by 200 ms gaps.
 */
static void buzz_n(int n)
{
	const struct device *gpio0_dev = DEVICE_DT_GET(DT_NODELABEL(gpio0));
	const struct device *gpio1_dev = DEVICE_DT_GET(DT_NODELABEL(gpio1));

	if (!device_is_ready(gpio0_dev) || !device_is_ready(gpio1_dev)) {
		return;
	}
	/* P1.05 = BUZZER_EN — power the buzzer */
	gpio_pin_configure(gpio1_dev, 5, GPIO_OUTPUT_ACTIVE);
	/* P0.25 = PIN_BUZZER — audio signal */
	gpio_pin_configure(gpio0_dev, 25, GPIO_OUTPUT_INACTIVE);

	for (int b = 0; b < n; b++) {
		if (b > 0) {
			k_busy_wait(200000); /* 200 ms gap between beeps */
		}
		for (int i = 0; i < 300; i++) { /* 300 × 500 µs = 150 ms */
			gpio_pin_set_raw(gpio0_dev, 25, 1);
			k_busy_wait(250);
			gpio_pin_set_raw(gpio0_dev, 25, 0);
			k_busy_wait(250);
		}
	}

	gpio_pin_configure(gpio0_dev, 25, GPIO_INPUT);
	gpio_pin_configure(gpio1_dev, 5, GPIO_OUTPUT_INACTIVE); /* disable */
}
#endif /* CONFIG_LICHEN_NATIVE_BUZZER */

/*
 * 1200-bps touch reset (Adafruit/Arduino convention).
 *
 * When a host opens the CDC-ACM port at 1200 baud with DTR de-asserted, write
 * the Adafruit UF2 bootloader magic to GPREGRET and cold-reboot. The bootloader
 * checks GPREGRET on startup: 0x57 → enter UF2 DFU mode. This lets
 * `adafruit-nrfutil --touch 1200` trigger a headless reflash. nRF-only
 * (GPREGRET); works with either USB stack.
 */
#if defined(CONFIG_SOC_FAMILY_NORDIC_NRF) && IS_ENABLED(CONFIG_UART_LINE_CTRL)
#define LICHEN_DFU_TOUCH 1
#define DFU_MAGIC_UF2_RESET 0x57u

static void dfu_reset_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	NRF_POWER->GPREGRET = DFU_MAGIC_UF2_RESET;
	sys_reboot(SYS_REBOOT_COLD);
}
static K_WORK_DEFINE(s_dfu_reset_work, dfu_reset_work_fn);

static void dfu_touch_poll_fn(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(s_dfu_touch_poll, dfu_touch_poll_fn);

static void dfu_touch_poll_fn(struct k_work *work)
{
	if (s_uart && device_is_ready(s_uart)) {
		uint32_t baud = 0, dtr = 1;

		uart_line_ctrl_get(s_uart, UART_LINE_CTRL_BAUD_RATE, &baud);
		uart_line_ctrl_get(s_uart, UART_LINE_CTRL_DTR, &dtr);
		if (baud == 1200 && !dtr) {
			k_work_submit(&s_dfu_reset_work);
			return; /* don't reschedule — reboot incoming */
		}
	}
	k_work_reschedule(&s_dfu_touch_poll, K_MSEC(100));
}
#endif /* nRF + UART_LINE_CTRL */

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int lichen_native_init(lichen_native_rx_cb_t rx_cb)
{
	k_mutex_lock(&s_init_mutex, K_FOREVER);

	if (s_initialized) {
		s_rx_cb = rx_cb;
		k_mutex_unlock(&s_init_mutex);
		return 0;
	}

#if IS_ENABLED(CONFIG_LICHEN_NATIVE_BUZZER)
	buzz_n(2); /* 2 beeps: LoRa/GNSS passed, native transport initializing */
#endif
	s_rx_cb = rx_cb;
	s_log_subscribed = false;

#if IS_ENABLED(CONFIG_USB_DEVICE_STACK)
	int usb_ret = usb_enable(NULL);
	if (usb_ret && usb_ret != -EALREADY) {
		LOG_ERR("USB enable failed: %d", usb_ret);
	}
#endif

	int ret = lichen_hal_serial_device_get(&s_uart);

	if (ret < 0) {
		LOG_ERR("native serial-local device unavailable: %d", ret);
		k_mutex_unlock(&s_init_mutex);
		return ret;
	}

	uart_irq_callback_set(s_uart, uart_rx_isr);
	uart_irq_rx_enable(s_uart);

	k_thread_create(&s_rx_thread, s_rx_stack, RX_STACK_SIZE,
			rx_thread_fn, NULL, NULL, NULL,
			K_PRIO_COOP(7), 0, K_NO_WAIT);
	k_thread_name_set(&s_rx_thread, "native_rx");

#if defined(LICHEN_DFU_TOUCH)
	k_work_schedule(&s_dfu_touch_poll, K_MSEC(100));
#endif

	s_initialized = true;
	k_mutex_unlock(&s_init_mutex);
	return 0;
}

int lichen_native_deinit(void)
{
	k_mutex_lock(&s_init_mutex, K_FOREVER);

	if (!s_initialized) {
		k_mutex_unlock(&s_init_mutex);
		return 0;
	}

	atomic_set(&s_rx_shutdown, 1);

	if (s_uart && device_is_ready(s_uart)) {
		uart_irq_rx_disable(s_uart);
	}

	uint8_t poison = 0xFF;
	k_msgq_put(&s_rx_msgq, &poison, K_NO_WAIT);

	int join_ret = k_thread_join(&s_rx_thread, K_MSEC(500));
	if (join_ret != 0) {
		LOG_WRN("native_rx join timeout (%d), aborting", join_ret);
		k_thread_abort(&s_rx_thread);
		k_thread_join(&s_rx_thread, K_FOREVER);
	}

	s_initialized = false;
	s_rx_cb = NULL;
	atomic_clear(&s_rx_shutdown);

	k_mutex_unlock(&s_init_mutex);
	LOG_INF("native deinit complete");
	return 0;
}

int lichen_native_send_hello(void)
{
	const int cap = TX_BUF_SIZE;
	int pos;

	k_mutex_lock(&s_tx_mutex, K_FOREVER);
	pos = encode_hello(s_tx_buf, cap, s_default_supported_types,
			   ARRAY_SIZE(s_default_supported_types));

	return finish_tx_locked(pos);
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

	k_mutex_lock(&s_tx_mutex, K_FOREVER);

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

	return finish_tx_locked(pos);
}

int lichen_native_send_message_received(const uint8_t src_iid[8],
					const uint8_t *payload, size_t len,
					int16_t rssi, int8_t snr)
{
	int pos = 0;
	const int cap = TX_BUF_SIZE;

	k_mutex_lock(&s_tx_mutex, K_FOREVER);

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

	return finish_tx_locked(pos);
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

	k_mutex_lock(&s_tx_mutex, K_FOREVER);

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

	return finish_tx_locked(pos);
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
	switch (msg_type) {
	case LN_TYPE_HELLO:
		/* Host connected — reply with our hello + node_info */
		LOG_INF("host connected");
		lichen_native_send_hello();
		break;

	case LN_TYPE_LOG_SUBSCRIBE: {
		bool enable = false;

		if (parse_log_subscribe_enable(buf, len, &enable) < 0) {
			LOG_WRN("invalid log_subscribe frame");
			break;
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
