/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <limits.h>

#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include <lichen/meshcore/codec.h>

BUILD_ASSERT(CONFIG_LICHEN_MESHCORE_MAX_SERIAL_PAYLOAD <= UINT16_MAX,
	     "Serial payload cannot exceed 16-bit length field");
BUILD_ASSERT(CONFIG_LICHEN_MESHCORE_MAX_SERIAL_PAYLOAD <= LICHEN_MESHCORE_BLE_FRAME_MAX,
	     "Exceeds MeshCore BLE frame maximum");
BUILD_ASSERT(CONFIG_LICHEN_MESHCORE_MAX_SERIAL_PAYLOAD <= INT_MAX - 3,
	     "Serial payload too large for int return");

int lichen_meshcore_decode_frame(const uint8_t *frame, size_t len,
				 struct lichen_meshcore_frame_view *view)
{
	if (frame == NULL || view == NULL || len == 0U ||
	    len > LICHEN_MESHCORE_FRAME_MAX) {
		return -EINVAL;
	}

	view->type = frame[0];
	view->payload = (len > 1U) ? &frame[1] : NULL;
	view->payload_len = len - 1U;
	return 0;
}

bool lichen_meshcore_command_known(uint8_t cmd)
{
	return cmd >= 0x01U && cmd <= 0x41U;
}

int lichen_meshcore_encode_error(uint8_t err, uint8_t *out, size_t out_len)
{
	if (out == NULL || out_len < 2U) {
		return -ENOMEM;
	}

	out[0] = LICHEN_MESHCORE_RESP_ERR;
	out[1] = err;
	return 2;
}

int lichen_meshcore_encode_ok(uint8_t *out, size_t out_len)
{
	if (out == NULL || out_len < 1U) {
		return -ENOMEM;
	}

	out[0] = LICHEN_MESHCORE_RESP_OK;
	return 1;
}

int lichen_meshcore_encode_serial_frame(uint8_t marker, const uint8_t *payload,
					size_t payload_len, uint8_t *out,
					size_t out_len)
{
	if ((marker != LICHEN_MESHCORE_SERIAL_APP_TO_DEVICE &&
	     marker != LICHEN_MESHCORE_SERIAL_DEVICE_TO_APP) ||
	    payload_len == 0U || (payload == NULL && payload_len > 0U) ||
	    payload_len > CONFIG_LICHEN_MESHCORE_MAX_SERIAL_PAYLOAD ||
	    out == NULL || out_len < 3U || payload_len > out_len - 3U) {
		return -EINVAL;
	}

	out[0] = marker;
	sys_put_le16((uint16_t)payload_len, &out[1]);
	if (payload_len > 0U) {
		memcpy(&out[3], payload, payload_len);
	}
	return (int)(payload_len + 3U);
}
