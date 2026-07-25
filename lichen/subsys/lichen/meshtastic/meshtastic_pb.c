/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "meshtastic_pb.h"

BUILD_ASSERT(sizeof(float) == sizeof(uint32_t),
	     "float must be 32-bit (IEEE 754 binary32 assumed for float32_bits)");

int pb_read_varint(struct pb_cursor *cur, uint64_t *value)
{
	uint64_t out = 0U;
	uint8_t shift = 0U;

	if (cur == NULL || value == NULL) {
		return -EINVAL;
	}

	while (cur->pos < cur->len && shift < 64U) {
		uint8_t byte = cur->buf[cur->pos++];

		if (shift == 63U && (byte & 0x7eU) != 0U) {
			return -EINVAL;
		}
		out |= ((uint64_t)(byte & 0x7fU)) << shift;
		if ((byte & 0x80U) == 0U) {
			*value = out;
			return 0;
		}
		shift += 7U;
	}

	return -EINVAL;
}

int pb_read_key(struct pb_cursor *cur, uint32_t *field, uint32_t *wire_type)
{
	uint64_t key;
	uint64_t field64;
	int ret = pb_read_varint(cur, &key);

	if (ret < 0) {
		return ret;
	}

	field64 = key >> 3;
	*wire_type = (uint32_t)(key & 0x07U);
	if (field64 == 0U || field64 > PB_MAX_FIELD_NUMBER) {
		return -EINVAL;
	}
	*field = (uint32_t)field64;

	return 0;
}

int pb_skip_value(struct pb_cursor *cur, uint32_t wire_type)
{
	uint64_t len;

	switch (wire_type) {
	case PB_WT_VARINT:
		return pb_read_varint(cur, &len);
	case PB_WT_LEN:
		if (pb_read_varint(cur, &len) < 0 || len > SIZE_MAX - cur->pos ||
		    cur->pos + (size_t)len > cur->len) {
			return -EINVAL;
		}
		cur->pos += (size_t)len;
		return 0;
	case PB_WT_64BIT:
		if (cur->len - cur->pos < 8U) {
			return -EINVAL;
		}
		cur->pos += 8U;
		return 0;
	case PB_WT_32BIT:
		if (cur->len - cur->pos < 4U) {
			return -EINVAL;
		}
		cur->pos += 4U;
		return 0;
	case PB_WT_SGROUP:
	case PB_WT_EGROUP:
		/*
		 * SECURITY: Deprecated proto2 group markers. Groups were removed
		 * in proto3 and have no length prefix, making them impossible to
		 * skip without schema knowledge. Reject to prevent parse confusion.
		 */
		return -EINVAL;
	default:
		/*
		 * SECURITY: Wire types 6 and 7 are reserved/undefined per the
		 * protobuf spec. Reject unknown wire types to prevent undefined
		 * behavior from malformed or malicious input.
		 */
		return -EINVAL;
	}
}

int pb_read_len_value(struct pb_cursor *cur, const uint8_t **data, size_t *len)
{
	uint64_t n;

	if (pb_read_varint(cur, &n) < 0 || n > SIZE_MAX - cur->pos ||
	    cur->pos + (size_t)n > cur->len) {
		return -EINVAL;
	}

	*data = &cur->buf[cur->pos];
	*len = (size_t)n;
	cur->pos += (size_t)n;
	return 0;
}

int pb_put_byte(uint8_t *buf, size_t buflen, size_t *pos, uint8_t byte)
{
	if (*pos >= buflen) {
		return -ENOMEM;
	}
	buf[(*pos)++] = byte;
	return 0;
}

size_t pb_varint_size(uint64_t value)
{
	size_t len = 1U;

	while (value > 0x7fU) {
		value >>= 7;
		len++;
	}

	return len;
}

size_t pb_key_size(uint32_t field, uint32_t wire_type)
{
	return pb_varint_size(((uint64_t)field << 3) | wire_type);
}

int pb_write_varint_raw(uint8_t *buf, size_t buflen, size_t *pos,
			uint64_t value)
{
	do {
		uint8_t byte = (uint8_t)(value & 0x7fU);

		value >>= 7;
		if (value != 0U) {
			byte |= 0x80U;
		}
		if (pb_put_byte(buf, buflen, pos, byte) < 0) {
			return -ENOMEM;
		}
	} while (value != 0U);

	return 0;
}

int pb_write_key(uint8_t *buf, size_t buflen, size_t *pos,
		 uint32_t field, uint32_t wire_type)
{
	return pb_write_varint_raw(buf, buflen, pos,
				   ((uint64_t)field << 3) | wire_type);
}

int pb_write_varint_field(uint8_t *buf, size_t buflen, size_t *pos,
			  uint32_t field, uint64_t value)
{
	if (pb_write_key(buf, buflen, pos, field, PB_WT_VARINT) < 0) {
		return -ENOMEM;
	}
	return pb_write_varint_raw(buf, buflen, pos, value);
}

int pb_write_fixed32_field(uint8_t *buf, size_t buflen, size_t *pos,
			   uint32_t field, uint32_t value)
{
	if (pb_write_key(buf, buflen, pos, field, PB_WT_32BIT) < 0 ||
	    buflen - *pos < sizeof(uint32_t)) {
		return -ENOMEM;
	}

	buf[(*pos)++] = (uint8_t)(value & 0xffU);
	buf[(*pos)++] = (uint8_t)((value >> 8) & 0xffU);
	buf[(*pos)++] = (uint8_t)((value >> 16) & 0xffU);
	buf[(*pos)++] = (uint8_t)((value >> 24) & 0xffU);
	return 0;
}

uint32_t float32_bits(float value)
{
	/* Returns the IEEE 754 binary32 bit pattern (as uint32_t) of `value`.
	 * The BUILD_ASSERT above and Zephyr target support (ARM/RISC-V/x86)
	 * guarantee the memcpy type-pun is valid. No NaN/inf special cases
	 * are needed for battery voltage encoding.
	 */
	uint32_t bits;

	memcpy(&bits, &value, sizeof(bits));
	return bits;
}

int pb_write_len_field(uint8_t *buf, size_t buflen, size_t *pos,
		       uint32_t field, const uint8_t *data, size_t len)
{
	if (data == NULL && len > 0U) {
		return -EINVAL;
	}
	if (pb_write_key(buf, buflen, pos, field, PB_WT_LEN) < 0 ||
	    pb_write_varint_raw(buf, buflen, pos, len) < 0) {
		return -ENOMEM;
	}
	if (buflen - *pos < len) {
		return -ENOMEM;
	}
	if (len > 0U) {
		memcpy(&buf[*pos], data, len);
	}
	*pos += len;
	return 0;
}

int pb_write_string_field(uint8_t *buf, size_t buflen, size_t *pos,
			  uint32_t field, const char *value)
{
	if (value == NULL) {
		value = "";
	}
	return pb_write_len_field(buf, buflen, pos, field,
				  (const uint8_t *)value, strlen(value));
}

int copy_tmp_payload(const uint8_t *tmp, size_t len,
		     uint8_t *buf, size_t buflen)
{
	if (buf == NULL) {
		return -EINVAL;
	}
	if (len > LICHEN_MESHTASTIC_FROM_RADIO_MAX) {
		return -EMSGSIZE;
	}
	if (buflen < len) {
		return -ENOMEM;
	}
	if (len > 0U) {
		memcpy(buf, tmp, len);
	}
	return (int)len;
}
