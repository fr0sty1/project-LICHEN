/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "meshtastic_pb.h"

BUILD_ASSERT(LICHEN_MESHTASTIC_FROM_RADIO_MAX <= INT_MAX,
	     "max must fit in int");

bool from_radio_len_field_supported(uint32_t field)
{
	switch (field) {
	case FROMRADIO_MY_INFO_FIELD:
	case FROMRADIO_NODE_INFO_FIELD:
	case FROMRADIO_CONFIG_FIELD:
	case FROMRADIO_MODULE_CONFIG_FIELD:
	case FROMRADIO_CHANNEL_FIELD:
	case FROMRADIO_METADATA_FIELD:
	case FROMRADIO_CLIENT_NOTIFICATION_FIELD:
	case FROMRADIO_REGION_PRESETS_FIELD:
		return true;
	default:
		return false;
	}
}

int lichen_meshtastic_decode_to_radio(const uint8_t *buf, size_t len,
				      struct lichen_meshtastic_to_radio *out)
{
	struct pb_cursor cur = { .buf = buf, .len = len };

	if (buf == NULL || out == NULL) {
		return -EINVAL;
	}
	if (len > LICHEN_MESHTASTIC_TO_RADIO_MAX) {
		return -EMSGSIZE;
	}

	memset(out, 0, sizeof(*out));

	while (cur.pos < cur.len) {
		uint32_t field;
		uint32_t wt;
		uint64_t v;
		const uint8_t *data;
		size_t data_len;
		enum lichen_meshtastic_to_radio_type type =
			LICHEN_MESHTASTIC_TO_RADIO_UNSET;

		if (pb_read_key(&cur, &field, &wt) < 0) {
			return -EINVAL;
		}

		switch (field) {
		case TORADIO_PACKET_FIELD:
			if (wt != PB_WT_LEN ||
			    pb_read_len_value(&cur, &data, &data_len) < 0) {
				return -EINVAL;
			}
			type = LICHEN_MESHTASTIC_TO_RADIO_PACKET;
			out->value.packet.data = data;
			out->value.packet.len = data_len;
			break;
		case TORADIO_WANT_CONFIG_ID_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0 ||
			    v > UINT32_MAX) {
				return -EINVAL;
			}
			type = LICHEN_MESHTASTIC_TO_RADIO_WANT_CONFIG_ID;
			out->value.want_config_id = (uint32_t)v;
			break;
		case TORADIO_DISCONNECT_FIELD:
			if (wt != PB_WT_VARINT || pb_read_varint(&cur, &v) < 0) {
				return -EINVAL;
			}
			type = LICHEN_MESHTASTIC_TO_RADIO_DISCONNECT;
			out->value.disconnect = (v != 0U);
			break;
		case TORADIO_HEARTBEAT_FIELD:
			if (wt != PB_WT_LEN ||
			    pb_read_len_value(&cur, &data, &data_len) < 0) {
				return -EINVAL;
			}
			type = LICHEN_MESHTASTIC_TO_RADIO_HEARTBEAT;
			break;
		default:
			if (pb_skip_value(&cur, wt) < 0) {
				return -EINVAL;
			}
			continue;
		}

		out->type = type;
	}

	return out->type != LICHEN_MESHTASTIC_TO_RADIO_UNSET ? 0 : -ENODATA;
}
