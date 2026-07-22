/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_MESHTASTIC_PB_INTERNAL_H_
#define LICHEN_MESHTASTIC_PB_INTERNAL_H_

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zephyr/sys/byteorder.h>

#define PB_WT_VARINT 0U
#define PB_WT_64BIT 1U
#define PB_WT_LEN 2U
#define PB_WT_SGROUP 3U
#define PB_WT_EGROUP 4U
#define PB_WT_32BIT 5U
#define PB_MAX_FIELD_NUMBER 536870911ULL

struct pb_cursor {
	const uint8_t *buf;
	size_t len;
	size_t pos;
};

static inline int pb_read_varint(struct pb_cursor *cur, uint64_t *value)
{
	if (cur == NULL || value == NULL) {
		return -EINVAL;
	}
	uint64_t out = 0U;
	uint8_t shift = 0U;

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

static inline int pb_read_key(struct pb_cursor *cur, uint32_t *field, uint32_t *wire_type)
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

static inline int pb_skip_value(struct pb_cursor *cur, uint32_t wire_type)
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
		return -EINVAL;
	default:
		return -EINVAL;
	}
}

static inline int pb_read_len_value(struct pb_cursor *cur, const uint8_t **data, size_t *len)
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

static inline int pb_put_byte(uint8_t *buf, size_t buflen, size_t *pos, uint8_t byte)
{
	if (*pos >= buflen) {
		return -EMSGSIZE;
	}
	buf[(*pos)++] = byte;
	return 0;
}

static inline size_t pb_varint_size(uint64_t value)
{
	size_t len = 1U;

	while (value > 0x7fU) {
		value >>= 7;
		len++;
	}

	return len;
}

static inline size_t pb_key_size(uint32_t field, uint32_t wire_type)
{
	return pb_varint_size(((uint64_t)field << 3) | wire_type);
}

static inline int pb_write_varint(uint8_t *buf, size_t buflen, size_t *pos,
				  uint64_t value)
{
	do {
		uint8_t byte = (uint8_t)(value & 0x7fU);

		value >>= 7;
		if (value != 0U) {
			byte |= 0x80U;
		}
		if (pb_put_byte(buf, buflen, pos, byte) < 0) {
			return -EMSGSIZE;
		}
	} while (value != 0U);

	return 0;
}

static inline int pb_write_key(uint8_t *buf, size_t buflen, size_t *pos,
			       uint32_t field, uint32_t wire_type)
{
	return pb_write_varint(buf, buflen, pos,
			       ((uint64_t)field << 3) | (uint64_t)wire_type);
}

static inline int pb_write_varint_field(uint8_t *buf, size_t buflen, size_t *pos,
					uint32_t field, uint64_t value)
{
	if (pb_write_key(buf, buflen, pos, field, PB_WT_VARINT) < 0) {
		return -EMSGSIZE;
	}
	return pb_write_varint(buf, buflen, pos, value);
}

static inline int pb_write_fixed32_field(uint8_t *buf, size_t buflen, size_t *pos,
				  uint32_t field, uint32_t value)
{
	if (pb_write_key(buf, buflen, pos, field, PB_WT_32BIT) < 0 ||
	    buflen - *pos < sizeof(uint32_t)) {
		return -EMSGSIZE;
	}
	sys_put_le32(value, &buf[*pos]);
	*pos += sizeof(uint32_t);
	return 0;
}

static inline int pb_write_len_field(uint8_t *buf, size_t buflen, size_t *pos,
			      uint32_t field, const uint8_t *data, size_t len)
{
	if (data == NULL && len > 0U) {
		return -EINVAL;
	}
	if (pb_write_key(buf, buflen, pos, field, PB_WT_LEN) < 0 ||
	    pb_write_varint(buf, buflen, pos, len) < 0 ||
	    len > buflen - *pos) {
		return -EMSGSIZE;
	}
	if (len > 0U) {
		memcpy(&buf[*pos], data, len);
	}
	*pos += len;
	return 0;
}

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_MESHTASTIC_PB_INTERNAL_H_ */
