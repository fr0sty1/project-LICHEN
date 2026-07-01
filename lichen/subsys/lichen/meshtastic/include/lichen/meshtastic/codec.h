/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_MESHTASTIC_CODEC_H_
#define LICHEN_MESHTASTIC_CODEC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_MESHTASTIC_PROTOBUF_COMMIT \
	"032b7dfd68e875c4323e6ac67590c6fc616b1714"

#ifdef CONFIG_LICHEN_MESHTASTIC_MAX_TO_RADIO
#define LICHEN_MESHTASTIC_TO_RADIO_MAX CONFIG_LICHEN_MESHTASTIC_MAX_TO_RADIO
#else
#define LICHEN_MESHTASTIC_TO_RADIO_MAX 504U
#endif

#ifdef CONFIG_LICHEN_MESHTASTIC_MAX_FROM_RADIO
#define LICHEN_MESHTASTIC_FROM_RADIO_MAX CONFIG_LICHEN_MESHTASTIC_MAX_FROM_RADIO
#else
#define LICHEN_MESHTASTIC_FROM_RADIO_MAX 510U
#endif

#define LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX 200U

enum lichen_meshtastic_to_radio_type {
	LICHEN_MESHTASTIC_TO_RADIO_UNSET = 0,
	LICHEN_MESHTASTIC_TO_RADIO_PACKET,
	LICHEN_MESHTASTIC_TO_RADIO_WANT_CONFIG_ID,
	LICHEN_MESHTASTIC_TO_RADIO_DISCONNECT,
	LICHEN_MESHTASTIC_TO_RADIO_HEARTBEAT,
};

struct lichen_meshtastic_to_radio {
	enum lichen_meshtastic_to_radio_type type;
	union {
		struct {
			const uint8_t *data;
			size_t len;
		} packet;
		uint32_t want_config_id;
		bool disconnect;
	} value;
};

struct lichen_meshtastic_queue_status {
	uint32_t res;
	uint32_t free;
	uint32_t maxlen;
	uint32_t mesh_packet_id;
	bool has_res;
	bool has_mesh_packet_id;
};

struct lichen_meshtastic_text_packet {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t channel;
	const uint8_t *payload;
	size_t payload_len;
	bool has_channel;
	bool want_ack;
};

struct lichen_meshtastic_routing_packet {
	uint32_t from;
	uint32_t to;
	uint32_t id;
	uint32_t request_id;
	uint32_t error_reason;
	bool has_error_reason;
};

struct lichen_meshtastic_local_info {
	uint32_t node_num;
	uint32_t reboot_count;
	uint32_t min_app_version;
	uint32_t nodedb_count;
	uint32_t uptime_seconds;
	int32_t tx_power_dbm;
	const char *long_name;
	const char *short_name;
	const char *firmware_version;
	const char *pio_env;
	const uint8_t *device_id;
	size_t device_id_len;
	bool has_bluetooth;
	bool has_battery;
	bool has_gnss;
	bool has_lora;
	bool has_tx_power_dbm;
	uint16_t battery_voltage_mv;
	uint8_t battery_percent;
	bool has_battery_percent;
	bool has_battery_voltage_mv;
	bool has_charging;
	bool charging;
	bool has_external_power;
	bool external_power;
};

enum lichen_meshtastic_config_section {
	LICHEN_MESHTASTIC_CONFIG_DEVICE,
	LICHEN_MESHTASTIC_CONFIG_POSITION,
	LICHEN_MESHTASTIC_CONFIG_POWER,
	LICHEN_MESHTASTIC_CONFIG_NETWORK,
	LICHEN_MESHTASTIC_CONFIG_DISPLAY,
	LICHEN_MESHTASTIC_CONFIG_LORA,
	LICHEN_MESHTASTIC_CONFIG_BLUETOOTH,
	LICHEN_MESHTASTIC_CONFIG_SECURITY,
	LICHEN_MESHTASTIC_CONFIG_DEVICE_UI,
};

enum lichen_meshtastic_from_radio_message {
	LICHEN_MESHTASTIC_FROM_RADIO_MY_INFO = 3,
	LICHEN_MESHTASTIC_FROM_RADIO_NODE_INFO = 4,
	LICHEN_MESHTASTIC_FROM_RADIO_CONFIG = 5,
	LICHEN_MESHTASTIC_FROM_RADIO_MODULE_CONFIG = 9,
	LICHEN_MESHTASTIC_FROM_RADIO_CHANNEL = 10,
	LICHEN_MESHTASTIC_FROM_RADIO_METADATA = 13,
	LICHEN_MESHTASTIC_FROM_RADIO_CLIENT_NOTIFICATION = 16,
	LICHEN_MESHTASTIC_FROM_RADIO_REGION_PRESETS = 19,
};

int lichen_meshtastic_decode_to_radio(const uint8_t *buf, size_t len,
				      struct lichen_meshtastic_to_radio *out);

int lichen_meshtastic_encode_from_radio_config_complete(uint32_t nonce,
							uint8_t *buf,
							size_t buflen);

int lichen_meshtastic_encode_from_radio_queue_status(
	const struct lichen_meshtastic_queue_status *status,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_from_radio_packet(uint32_t from_radio_id,
					       const uint8_t *packet,
					       size_t packet_len,
					       uint8_t *buf,
					       size_t buflen);

int lichen_meshtastic_encode_from_radio_message(
	enum lichen_meshtastic_from_radio_message message,
	const uint8_t *payload, size_t payload_len,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_text_packet(
	const struct lichen_meshtastic_text_packet *packet,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_routing_packet(
	const struct lichen_meshtastic_routing_packet *packet,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_my_info_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_metadata_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_config_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_config_section_payload(
	enum lichen_meshtastic_config_section section,
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_module_config_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_channel_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_region_presets_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen);

int lichen_meshtastic_encode_node_info_payload(
	const struct lichen_meshtastic_local_info *info,
	uint8_t *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_MESHTASTIC_CODEC_H_ */
