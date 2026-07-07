/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/sys/util.h>
#if IS_ENABLED(CONFIG_LORA)
#include <zephyr/drivers/lora.h>
#endif
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap_service.h>

#include <lichen/hal.h>

#include "config_apply.h"
#include "config_cbor.h"
#include "status_cbor.h"

#ifdef CONFIG_LORA_LICHEN_BLE
#include "ble_uart.h"
#endif

#ifdef CONFIG_LORA_LICHEN_MESHTASTIC_BLE
#include "ble_meshtastic.h"
#include "message_contract.h"
#include "meshtastic_adapter.h"
#endif

#ifdef CONFIG_LORA_LICHEN_MESHCORE_BLE
#include "ble_meshcore.h"
#include "gateway_identity.h"
#include "message_contract.h"
#include "meshcore_adapter.h"
#endif

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
#include <lichen/native.h>
#endif

LOG_MODULE_REGISTER(lichen_gateway, LOG_LEVEL_INF);

#define LICHEN_GATEWAY_HAS_LORA \
	IS_ENABLED(CONFIG_LICHEN_HAS_LORA)

/*
 * Manual LoRa handling (non-L2 mode).
 *
 * When CONFIG_LICHEN_L2 is enabled, the L2 layer handles all LoRa
 * initialization and RX via its own thread. These definitions are only
 * needed for direct LoRa testing without the full network stack.
 */
#if !IS_ENABLED(CONFIG_LICHEN_L2) && LICHEN_GATEWAY_HAS_LORA
/* LoRa parameters per LICHEN spec: SF10 / 125 kHz / CR4-5.
 * Frequency is region-dependent; 915 MHz (US915) is the default.
 * Override per board via a board-specific Kconfig once that lands. */
#define LORA_FREQ_HZ     915000000U
#define LORA_MAX_FRAME   255
#define LORA_RX_STACKSZ  1024
#define LORA_RX_PRIORITY 7

/* Set by main() after lora_config() succeeds; read by the RX thread. */
static const struct device *s_lora_dev;
static K_SEM_DEFINE(s_radio_ready, 0, 1);
#endif /* !CONFIG_LICHEN_L2 && LICHEN_GATEWAY_HAS_LORA */

/* CBOR content-format code (RFC 7252 §12.3 / IANA CoAP Content-Formats) */
#define CBOR_CONTENT_FORMAT 60
#define LICHEN_GATEWAY_STATUS_COAP_OVERHEAD 64U

BUILD_ASSERT(CONFIG_COAP_SERVER_MESSAGE_SIZE >=
	     LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE +
	     LICHEN_GATEWAY_STATUS_COAP_OVERHEAD,
	     "gateway status CoAP buffer must fit CBOR body plus options");

#if IS_ENABLED(CONFIG_LORA_LICHEN_GATEWAY_RPL_ROOT)
#define LICHEN_GATEWAY_STATUS_ROLE "root"
#define LICHEN_GATEWAY_STATUS_RPL_CAPABLE true
#define LICHEN_GATEWAY_STATUS_RANK 256
#else
#define LICHEN_GATEWAY_STATUS_ROLE "gateway"
#define LICHEN_GATEWAY_STATUS_RPL_CAPABLE false
#define LICHEN_GATEWAY_STATUS_RANK 0xffff
#endif

/* Mutable gateway config — written by PUT /config */
static int8_t s_tx_power_dbm = 14;
static struct lichen_gateway_manual_location_config s_manual_location;
static bool s_has_manual_location;

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
 * /status (Observable)
 * -------------------------------------------------------------------------- */

/*
 * Build CBOR status with explicit power-provider availability and only valid
 * measured power fields. Returns encoded byte count.
 */
static size_t encode_status_cbor(uint8_t *buf, size_t buf_size, uint16_t rank,
				 const char *role, bool rpl_capable)
{
	struct lichen_hal_power_snapshot power;
	struct lichen_hal_location_time_snapshot location_time;
	struct lichen_hal_time_snapshot time;
	uint32_t uptime_ms = k_uptime_get_32();

	(void)lichen_hal_power_snapshot_get(&power);
	(void)lichen_hal_location_time_snapshot_get(&location_time);
	(void)lichen_hal_time_snapshot_get(&time);
	return lichen_gateway_encode_status_cbor(
		buf, buf_size, rank, role, rpl_capable, uptime_ms, &power,
		&location_time, &time);
}

/* Gateway status state (observable) */
static uint16_t s_rank = LICHEN_GATEWAY_STATUS_RANK;

static int status_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	size_t len = encode_status_cbor(cbor_buf, sizeof(cbor_buf), s_rank,
					LICHEN_GATEWAY_STATUS_ROLE,
					LICHEN_GATEWAY_STATUS_RPL_CAPABLE);

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

/*
 * Notify callback for Observe (RFC 7641).
 * Called by coap_resource_notify() when we want to push updates to observers.
 */
static void status_notify(struct coap_resource *resource,
			  struct coap_observer *observer)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t cbor_buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct coap_packet notif;
	size_t cbor_len;
	int r;

	cbor_len = encode_status_cbor(cbor_buf, sizeof(cbor_buf), s_rank,
				      LICHEN_GATEWAY_STATUS_ROLE,
				      LICHEN_GATEWAY_STATUS_RPL_CAPABLE);
	if (cbor_len == 0) {
		return;
	}

	r = coap_packet_init(&notif, buf, sizeof(buf), COAP_VERSION_1,
			     COAP_TYPE_NON_CON,
			     observer->tkl, observer->token,
			     COAP_RESPONSE_CODE_CONTENT, 0);
	if (r < 0) {
		return;
	}

	/* Add Observe option with the resource age */
	r = coap_append_option_int(&notif, COAP_OPTION_OBSERVE, resource->age);
	if (r < 0) {
		return;
	}

	r = coap_append_option_int(&notif, COAP_OPTION_CONTENT_FORMAT,
				   CBOR_CONTENT_FORMAT);
	if (r < 0) {
		return;
	}

	r = coap_packet_append_payload_marker(&notif);
	if (r < 0) {
		return;
	}

	r = coap_packet_append_payload(&notif, cbor_buf, cbor_len);
	if (r < 0) {
		return;
	}

	(void)coap_resource_send(resource, &notif,
				 &observer->addr, sizeof(observer->addr), NULL);
}

static const char * const status_path[] = { "status", NULL };
COAP_RESOURCE_DEFINE(status, lichen_coap, {
	.get    = status_get,
	.notify = status_notify,
	.path   = status_path,
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

static int config_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[160];
	size_t len = lichen_gateway_encode_config_update_cbor(
		cbor_buf, sizeof(cbor_buf), s_tx_power_dbm,
		s_has_manual_location ? &s_manual_location : NULL);

	if (len == 0U) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

static int config_put(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	struct lichen_gateway_config_update update;

	if (payload == NULL ||
	    lichen_gateway_decode_config_cbor(payload, payload_len,
					      &update) < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	if (lichen_gateway_apply_config_update(&update, &s_tx_power_dbm,
					       &s_manual_location,
					       &s_has_manual_location) < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}
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
 *
 * When CONFIG_LICHEN_L2 is enabled, the L2 layer handles LoRa RX via its own
 * thread and routes packets through the IPv6 stack. This manual RX thread is
 * only used for direct LoRa testing without the full network stack.
 * -------------------------------------------------------------------------- */

#if !IS_ENABLED(CONFIG_LICHEN_L2) && LICHEN_GATEWAY_HAS_LORA
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
#endif /* !CONFIG_LICHEN_L2 && LICHEN_GATEWAY_HAS_LORA */

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(void)
{
	LOG_INF("LICHEN gateway starting");

#if IS_ENABLED(CONFIG_LICHEN_L2)
	/*
	 * When LICHEN L2 is enabled, the L2 layer handles LoRa initialization
	 * and RX automatically via NET_DEVICE_INIT. The L2 interface will be
	 * available to the IPv6 stack for sending/receiving packets over LoRa.
	 */
	LOG_INF("LICHEN L2 enabled - LoRa handled by network stack");
#elif LICHEN_GATEWAY_HAS_LORA
	int ret;

	/* LoRa radio init.  The sim driver ignores RF parameters and returns 0;
	 * on hardware this configures the SX126x transceiver. */
	ret = lichen_hal_lora_device_get(&s_lora_dev);
	if (ret < 0) {
		/* Expected in CI (no sim server); gateway still serves CoAP. */
		LOG_WRN("LoRa radio unavailable (%d) — CoAP-only mode", ret);
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
		ret = lora_config(s_lora_dev, &lora_cfg);

		if (ret < 0) {
			LOG_ERR("LoRa config failed: %d", ret);
		} else {
			LOG_INF("LoRa SF10/125kHz/CR4-5 @ %u Hz", LORA_FREQ_HZ);
			k_sem_give(&s_radio_ready);
		}
	}
#else
	LOG_INF("No LoRa radio configured - CoAP/local-client only");
#endif

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

	/* Meshtastic-compatible BLE GATT — optional app compatibility surface */
#ifdef CONFIG_LORA_LICHEN_MESHTASTIC_BLE
	if (gateway_message_contract_init() < 0) {
		LOG_WRN("Message contract init failed — Meshtastic app unavailable");
	} else if (ble_meshtastic_init() < 0) {
		LOG_WRN("Meshtastic BLE init failed — Meshtastic app unavailable");
	} else if (gateway_meshtastic_adapter_init() < 0) {
		LOG_WRN("Meshtastic adapter init failed — Meshtastic app unavailable");
	}
#endif

	/* MeshCore-compatible BLE GATT — local app compatibility only */
#ifdef CONFIG_LORA_LICHEN_MESHCORE_BLE
	if (IS_ENABLED(CONFIG_LICHEN_L2) &&
	    gateway_identity_publish_self() < 0) {
		LOG_WRN("MeshCore app identity using degraded SELF_INFO until key is published");
	}
	if (gateway_message_contract_init() < 0) {
		LOG_WRN("Message contract init failed — MeshCore app unavailable");
	} else if (ble_meshcore_init() < 0) {
		LOG_WRN("MeshCore BLE init failed — MeshCore app unavailable");
	} else if (gateway_meshcore_adapter_init() < 0) {
		LOG_WRN("MeshCore adapter init failed — MeshCore app unavailable");
	}
#endif

#if IS_ENABLED(CONFIG_LORA_LICHEN_GATEWAY_RPL_ROOT)
	LOG_INF("RPL root signalling enabled");
#else
	LOG_WRN("RPL root signalling disabled - advertising /status rpl=false");
#endif
	LOG_INF("CoAP server on port %u (AUTOSTART)", coap_port);

	return 0;
}
