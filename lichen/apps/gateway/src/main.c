/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap_service.h>

#ifdef CONFIG_LORA_LICHEN_BLE
#include "ble_uart.h"
#endif

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
#include <lichen/native.h>
#endif

LOG_MODULE_REGISTER(lichen_gateway, LOG_LEVEL_INF);

/* LoRa parameters per LICHEN spec: SF10 / 125 kHz / CR4-5.
 * Frequency is region-dependent; 868 MHz (EU) is the default.
 * Override per board via a board-specific Kconfig once that lands. */
#define LORA_FREQ_HZ     868000000U
#define LORA_MAX_FRAME   255
#define LORA_RX_STACKSZ  1024
#define LORA_RX_PRIORITY 7

/* Set by main() after lora_config() succeeds; read by the RX thread. */
static const struct device *s_lora_dev;
static K_SEM_DEFINE(s_radio_ready, 0, 1);

/* CBOR content-format code (RFC 7252 §12.3 / IANA CoAP Content-Formats) */
#define CBOR_CONTENT_FORMAT 60

/* Mutable gateway config — written by PUT /config */
static int8_t s_tx_power_dbm = 14;

/* --------------------------------------------------------------------------
 * CBOR helpers
 * -------------------------------------------------------------------------- */

/*
 * Build a minimal CoAP response and send it.
 * Pass payload=NULL / payload_len=0 for responses with no body.
 */
static int coap_respond(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len,
			uint8_t resp_code,
			const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
		       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int r;

	r = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1,
			     type, tkl, token, resp_code,
			     coap_header_get_id(request));
	if (r < 0) {
		return r;
	}

	if (payload && payload_len > 0) {
		r = coap_append_option_int(&resp, COAP_OPTION_CONTENT_FORMAT,
					   CBOR_CONTENT_FORMAT);
		if (r < 0) {
			return r;
		}
		r = coap_packet_append_payload_marker(&resp);
		if (r < 0) {
			return r;
		}
		r = coap_packet_append_payload(&resp, payload, payload_len);
		if (r < 0) {
			return r;
		}
	}

	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}

/* --------------------------------------------------------------------------
 * /status
 * -------------------------------------------------------------------------- */

/*
 * Pre-encoded CBOR: {"rank": 256, "role": "root"}
 *   a2              -- map(2)
 *   64 "rank"       -- tstr(4)
 *   19 01 00        -- uint(256)
 *   64 "role"       -- tstr(4)
 *   64 "root"       -- tstr(4)
 */
static const uint8_t cbor_status[] = {
	0xa2,
	0x64, 'r', 'a', 'n', 'k',
	0x19, 0x01, 0x00,
	0x64, 'r', 'o', 'l', 'e',
	0x64, 'r', 'o', 'o', 't',
};

static int status_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT,
			    cbor_status, sizeof(cbor_status));
}

static const char * const status_path[] = { "status", NULL };
COAP_RESOURCE_DEFINE(status, lichen_coap, {
	.get  = status_get,
	.path = status_path,
});

/* --------------------------------------------------------------------------
 * /neighbors
 * -------------------------------------------------------------------------- */

/* Pre-encoded CBOR: []  (0x80 = array(0)) */
static const uint8_t cbor_neighbors[] = { 0x80 };

static int neighbors_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT,
			    cbor_neighbors, sizeof(cbor_neighbors));
}

static const char * const neighbors_path[] = { "neighbors", NULL };
COAP_RESOURCE_DEFINE(neighbors, lichen_coap, {
	.get  = neighbors_get,
	.path = neighbors_path,
});

/* --------------------------------------------------------------------------
 * /config
 * -------------------------------------------------------------------------- */

/*
 * Build CBOR {"tx_power_dbm": <val>} into buf (must be >= 15 bytes).
 *   a1              -- map(1)
 *   6c "tx_power_dbm" -- tstr(12)
 *   <val>           -- uint or negative int (fits in one CBOR byte: -24..23)
 *
 * Returns encoded byte count.
 */
static size_t encode_config_cbor(uint8_t *buf, size_t buf_size)
{
	if (buf_size < 15) {
		return 0;
	}
	buf[0] = 0xa1;
	buf[1] = 0x6c;
	(void)memcpy(&buf[2], "tx_power_dbm", 12);
	if (s_tx_power_dbm >= 0) {
		buf[14] = (uint8_t)s_tx_power_dbm;
	} else {
		buf[14] = (uint8_t)(0x20u | (uint8_t)(-s_tx_power_dbm - 1));
	}
	return 15;
}

static int config_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[16];
	size_t len = encode_config_cbor(cbor_buf, sizeof(cbor_buf));

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

static int config_put(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	/* CBOR body parsing deferred; accept unconditionally */
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CHANGED, NULL, 0);
}

static const char * const config_path[] = { "config", NULL };
COAP_RESOURCE_DEFINE(config, lichen_coap, {
	.get  = config_get,
	.put  = config_put,
	.path = config_path,
});

/* --------------------------------------------------------------------------
 * CoAP service (AUTOSTART — no explicit start call needed)
 * -------------------------------------------------------------------------- */

static const uint16_t coap_port = 5683;
COAP_SERVICE_DEFINE(lichen_coap, NULL, &coap_port, COAP_SERVICE_AUTOSTART);

/* --------------------------------------------------------------------------
 * LoRa RX thread — runs continuously, logs every received frame.
 * -------------------------------------------------------------------------- */

static void lora_rx_entry(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);

	k_sem_take(&s_radio_ready, K_FOREVER);

	uint8_t buf[LORA_MAX_FRAME];
	int16_t rssi;
	int8_t  snr;

	while (1) {
		int len = lora_recv(s_lora_dev, buf, sizeof(buf),
				    K_FOREVER, &rssi, &snr);
		if (len > 0) {
			LOG_INF("RX %d B rssi=%d snr=%d [%02x%s]",
				len, rssi, snr, buf[0],
				len > 1 ? " ..." : "");
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
			static const uint8_t unknown_iid[8];
			lichen_native_send_message_received(unknown_iid,
							    buf, len,
							    rssi, snr);
#endif
		} else if (len < 0) {
			LOG_WRN("lora_recv err: %d", len);
			k_sleep(K_MSEC(100));
		}
	}
}

K_THREAD_DEFINE(lora_rx, LORA_RX_STACKSZ,
		lora_rx_entry, NULL, NULL, NULL,
		LORA_RX_PRIORITY, 0, 0);

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(void)
{
	LOG_INF("LICHEN gateway starting");

	/* LoRa radio init.  The sim driver ignores RF parameters and returns 0;
	 * on hardware this configures the SX126x transceiver. */
	s_lora_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_lora));

	if (!device_is_ready(s_lora_dev)) {
		/* Expected in CI (no sim server); gateway still serves CoAP. */
		LOG_WRN("LoRa radio not ready — CoAP-only mode");
	} else {
		struct lora_modem_config lora_cfg = {
			.frequency    = LORA_FREQ_HZ,
			.bandwidth    = BW_125_KHZ,
			.datarate     = SF_10,
			.coding_rate  = CR_4_5,
			.preamble_len = 8,
			.tx_power     = s_tx_power_dbm,
			.tx           = false,       /* start in receive mode */
			.public_network = false,
		};
		int ret = lora_config(s_lora_dev, &lora_cfg);

		if (ret < 0) {
			LOG_ERR("LoRa config failed: %d", ret);
		} else {
			LOG_INF("LoRa SF10/125kHz/CR4-5 @ %u Hz", LORA_FREQ_HZ);
			k_sem_give(&s_radio_ready);
		}
	}

	/* LICHEN Native over USB CDC-ACM */
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
	if (lichen_native_init(lichen_native_handle_rx) == 0) {
		LOG_INF("LICHEN Native ready");
		lichen_native_send_hello();
	}
#endif

	/* SLIP bridge: enabled by Kconfig on hardware (CONFIG_SLIP +
	 * CONFIG_NET_SLIP_TAP).  native_sim uses the lichen-sim driver
	 * instead.  No app-level init required in either case. */

	/* BLE UART (NUS) — optional, enabled on boards with a BLE radio */
#ifdef CONFIG_LORA_LICHEN_BLE
	if (ble_uart_init() < 0) {
		LOG_WRN("BLE UART init failed — BLE unavailable");
	}
#endif

	/* RPL DODAG root: Zephyr has no RPL subsystem.  This gateway acts as
	 * the mesh coordinator; RPL signalling is deferred until the C RPL
	 * layer lands. */
	LOG_INF("CoAP server on port %u (AUTOSTART)", coap_port);

	return 0;
}
