/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/*
 * Legacy LICHEN Native CBOR protocol — device-side library.
 *
 * This API implements the historical spec/lichen-native draft. It is retained
 * for prototype compatibility and parser coverage. New LCI app surfaces use
 * IPv6 + CoAP resources from spec/11-lci.md, not this CBOR framing.
 *
 * Wire format: [0xC1][LEN_HI][LEN_LO][CBOR payload]
 * Transport:   USB CDC-ACM (zephyr,cdc-acm-uart chosen alias "native-uart")
 *
 * Usage:
 *   1. lichen_native_init(rx_cb)  — once at boot, starts RX thread
 *   2. lichen_native_send_hello() — after USB line goes active
 *   3. lichen_native_send_node_info(...) — on connect and periodically
 *   4. lichen_native_send_message_received(...) — on LoRa RX
 */

#ifndef LICHEN_NATIVE_H
#define LICHEN_NATIVE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Legacy message type codes (from spec/lichen-native/02-common.md) */
#define LN_TYPE_HELLO            0x01
#define LN_TYPE_CONFIG_GET       0x10
#define LN_TYPE_CONFIG_SET       0x11
#define LN_TYPE_CONFIG_RESULT    0x12
#define LN_TYPE_SEND_MESSAGE     0x20
#define LN_TYPE_MESSAGE_RECEIVED 0x21
#define LN_TYPE_MESH_STATE       0x30
#define LN_TYPE_NODE_INFO        0x31
#define LN_TYPE_LOG_ENTRY        0x40
#define LN_TYPE_LOG_SUBSCRIBE    0x41
#define LN_TYPE_OTA_BEGIN        0x50
#define LN_TYPE_OTA_CHUNK        0x51
#define LN_TYPE_OTA_FINISH       0x52
#define LN_TYPE_OTA_STATUS       0x53
#define LN_TYPE_RAW_TX           0x60
#define LN_TYPE_RAW_RX           0x61

struct ln_gps_info {
	int32_t  lat_udeg;  /* latitude in microdegrees */
	int32_t  lon_udeg;  /* longitude in microdegrees */
	int32_t  alt_cm;    /* altitude in cm above sea level */
	uint32_t satellites;
	bool     valid;
};

struct ln_radio_stats {
	uint32_t tx_pkts;
	uint32_t rx_pkts;
};

/*
 * Callback invoked on the RX thread when a complete frame arrives.
 * buf/len is the raw CBOR payload (NOT the 3-byte header).
 * msg_type is key 0 from the CBOR map (pre-parsed).
 */
typedef void (*lichen_native_rx_cb_t)(uint8_t msg_type, const uint8_t *buf, size_t len);

/*
 * lichen_native_init — initialise the library and start the RX thread.
 *
 * Call at application start after USB is ready. Repeated calls are allowed:
 * they update rx_cb and do not restart the RX thread or reset runtime state.
 * rx_cb is called on the native RX thread for every received frame.
 * Returns 0 on success, negative errno on failure.
 */
int lichen_native_init(lichen_native_rx_cb_t rx_cb);

/*
 * lichen_native_deinit — stop RX thread and release resources.
 *
 * Must be called before re-init or module unload. Wakes blocked RX thread
 * via poison message + IRQ disable + join/abort. Idempotent.
 */
int lichen_native_deinit(void);

/*
 * lichen_native_send_hello — transmit a hello frame to the host.
 *
 * Announces the default device-side message types implemented by this library
 * and device capabilities.
 */
int lichen_native_send_hello(void);

/*
 * lichen_native_send_node_info — transmit device status to the host.
 */
int lichen_native_send_node_info(const char *name,
				 const char *fw_version,
				 const char *hw_model,
				 uint64_t uptime_ms,
				 const uint8_t iid[8],
				 const struct ln_gps_info *gps,
				 const struct ln_radio_stats *radio);

/*
 * lichen_native_send_message_received — forward a LoRa RX packet to host.
 *
 * src_iid: 8-byte source IID
 * payload/len: application payload
 * rssi, snr: link-layer signal quality
 */
int lichen_native_send_message_received(const uint8_t src_iid[8],
					const uint8_t *payload, size_t len,
					int16_t rssi, int8_t snr);

/*
 * lichen_native_log_is_subscribed — true if host has enabled log streaming.
 */
bool lichen_native_log_is_subscribed(void);

/*
 * lichen_native_send_log_entry — send a log entry to the host.
 *
 * level: 1=error 2=warn 3=info 4=debug
 */
int lichen_native_send_log_entry(uint8_t level, const char *module, const char *msg);

/*
 * lichen_native_handle_rx — default dispatcher for incoming host frames.
 *
 * Handles hello (replies with hello) and log_subscribe (toggles streaming).
 * Applications pass this as rx_cb, or call it from their own callback after
 * handling app-specific message types.
 */
void lichen_native_handle_rx(uint8_t msg_type, const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_NATIVE_H */
