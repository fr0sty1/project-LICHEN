/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/coap_codec.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define COAP_HEADER_LEN 4U
#define COAP_EXTENDED_MAX (269U + UINT16_MAX)

static int decode_field(uint8_t nibble, const uint8_t *wire, size_t wire_len,
			size_t *offset, size_t *value)
{
	if (nibble < 13U) {
		*value = nibble;
		return 0;
	}
	if (nibble == 13U) {
		if (*offset >= wire_len) {
			return -EBADMSG;
		}
		*value = 13U + wire[*offset];
		(*offset)++;
		return 0;
	}
	if (nibble == 14U) {
		if (wire_len - *offset < 2U) {
			return -EBADMSG;
		}
		*value = 269U + ((size_t)wire[*offset] << 8) + wire[*offset + 1U];
		*offset += 2U;
		return 0;
	}
	return -EBADMSG;
}

int lichen_coap_parse(const uint8_t *wire, size_t wire_len,
		      struct lichen_coap_packet *packet)
{
	struct lichen_coap_packet parsed = { 0 };
	size_t offset;
	uint32_t current_option = 0U;

	if (wire == NULL || packet == NULL) {
		return -EINVAL;
	}
	if (wire_len < COAP_HEADER_LEN) {
		return -EBADMSG;
	}
	if ((wire[0] >> 6) != LICHEN_COAP_VERSION) {
		return -EBADMSG;
	}

	parsed.type = (enum lichen_coap_type)((wire[0] >> 4) & 0x03U);
	parsed.token_len = wire[0] & 0x0fU;
	if (parsed.token_len > LICHEN_COAP_TOKEN_MAX ||
	    parsed.token_len > wire_len - COAP_HEADER_LEN) {
		return -EBADMSG;
	}
	parsed.code = wire[1];
	parsed.message_id = (uint16_t)(((uint16_t)wire[2] << 8) | wire[3]);
	parsed.token = &wire[COAP_HEADER_LEN];
	offset = COAP_HEADER_LEN + parsed.token_len;

	while (offset < wire_len) {
		uint8_t header;
		size_t delta;
		size_t length;
		uint32_t next_option;
		int ret;

		if (wire[offset] == LICHEN_COAP_PAYLOAD_MARKER) {
			if (offset + 1U >= wire_len) {
				return -EBADMSG;
			}
			parsed.payload = &wire[offset + 1U];
			parsed.payload_len = wire_len - offset - 1U;
			offset = wire_len;
			break;
		}

		header = wire[offset++];
		ret = decode_field(header >> 4, wire, wire_len, &offset, &delta);
		if (ret < 0) {
			return ret;
		}
		ret = decode_field(header & 0x0fU, wire, wire_len, &offset, &length);
		if (ret < 0) {
			return ret;
		}
		next_option = current_option + (uint32_t)delta;
		if (next_option > UINT16_MAX) {
			return -EOVERFLOW;
		}
		if (length > wire_len - offset) {
			return -EBADMSG;
		}
		if (parsed.option_count >= LICHEN_COAP_OPTIONS_MAX) {
			return -E2BIG;
		}

		parsed.options[parsed.option_count].number = (uint16_t)next_option;
		parsed.options[parsed.option_count].value = &wire[offset];
		parsed.options[parsed.option_count].length = length;
		parsed.option_count++;
		current_option = next_option;
		offset += length;
	}

	if (parsed.code == 0U &&
	    (parsed.token_len != 0U || parsed.option_count != 0U ||
	     parsed.payload_len != 0U)) {
		return -EBADMSG;
	}

	*packet = parsed;
	return 0;
}

static int field_encoding(size_t value, uint8_t *nibble, uint8_t ext[2],
			  size_t *ext_len)
{
	if (value < 13U) {
		*nibble = (uint8_t)value;
		*ext_len = 0U;
		return 0;
	}
	if (value < 269U) {
		*nibble = 13U;
		ext[0] = (uint8_t)(value - 13U);
		*ext_len = 1U;
		return 0;
	}
	if (value <= COAP_EXTENDED_MAX) {
		size_t encoded = value - 269U;

		*nibble = 14U;
		ext[0] = (uint8_t)(encoded >> 8);
		ext[1] = (uint8_t)encoded;
		*ext_len = 2U;
		return 0;
	}
	return -EMSGSIZE;
}

static int add_size(size_t *total, size_t amount)
{
	if (amount > SIZE_MAX - *total) {
		return -EOVERFLOW;
	}
	*total += amount;
	return 0;
}

int lichen_coap_serialize(const struct lichen_coap_packet *packet,
			 uint8_t *out, size_t *out_len)
{
	uint8_t delta_nibbles[LICHEN_COAP_OPTIONS_MAX];
	uint8_t length_nibbles[LICHEN_COAP_OPTIONS_MAX];
	uint8_t delta_ext[LICHEN_COAP_OPTIONS_MAX][2];
	uint8_t length_ext[LICHEN_COAP_OPTIONS_MAX][2];
	size_t delta_ext_len[LICHEN_COAP_OPTIONS_MAX];
	size_t length_ext_len[LICHEN_COAP_OPTIONS_MAX];
	size_t needed;
	size_t offset;
	uint16_t previous = 0U;

	if (packet == NULL || out == NULL || out_len == NULL) {
		return -EINVAL;
	}
	if ((unsigned int)packet->type > LICHEN_COAP_TYPE_RST ||
	    packet->token_len > LICHEN_COAP_TOKEN_MAX ||
	    packet->option_count > LICHEN_COAP_OPTIONS_MAX ||
	    (packet->token_len > 0U && packet->token == NULL) ||
	    (packet->payload_len > 0U && packet->payload == NULL)) {
		return -EINVAL;
	}
	if (packet->code == 0U &&
	    (packet->token_len != 0U || packet->option_count != 0U ||
	     packet->payload_len != 0U)) {
		return -EINVAL;
	}

	needed = COAP_HEADER_LEN;
	if (add_size(&needed, packet->token_len) < 0) {
		return -EOVERFLOW;
	}
	for (size_t i = 0U; i < packet->option_count; i++) {
		size_t delta;
		int ret;

		if (packet->options[i].number < previous ||
		    (packet->options[i].length > 0U &&
		     packet->options[i].value == NULL)) {
			return -EINVAL;
		}
		delta = packet->options[i].number - previous;
		ret = field_encoding(delta, &delta_nibbles[i], delta_ext[i],
				     &delta_ext_len[i]);
		if (ret < 0) {
			return ret;
		}
		ret = field_encoding(packet->options[i].length, &length_nibbles[i],
				     length_ext[i], &length_ext_len[i]);
		if (ret < 0) {
			return ret;
		}
		if (add_size(&needed, 1U + delta_ext_len[i] + length_ext_len[i]) < 0 ||
		    add_size(&needed, packet->options[i].length) < 0) {
			return -EOVERFLOW;
		}
		previous = packet->options[i].number;
	}
	if (packet->payload_len > 0U) {
		if (add_size(&needed, 1U) < 0 ||
		    add_size(&needed, packet->payload_len) < 0) {
			return -EOVERFLOW;
		}
	}
	if (*out_len < needed) {
		return -ENOMEM;
	}

	/* All validation and sizing is complete; no failure is possible below. */
	out[0] = (uint8_t)((LICHEN_COAP_VERSION << 6) |
			   ((uint8_t)packet->type << 4) |
			   (uint8_t)packet->token_len);
	out[1] = packet->code;
	out[2] = (uint8_t)(packet->message_id >> 8);
	out[3] = (uint8_t)packet->message_id;
	offset = COAP_HEADER_LEN;
	if (packet->token_len > 0U) {
		memcpy(&out[offset], packet->token, packet->token_len);
		offset += packet->token_len;
	}
	for (size_t i = 0U; i < packet->option_count; i++) {
		out[offset++] = (uint8_t)((delta_nibbles[i] << 4) |
					  length_nibbles[i]);
		if (delta_ext_len[i] > 0U) {
			memcpy(&out[offset], delta_ext[i], delta_ext_len[i]);
			offset += delta_ext_len[i];
		}
		if (length_ext_len[i] > 0U) {
			memcpy(&out[offset], length_ext[i], length_ext_len[i]);
			offset += length_ext_len[i];
		}
		if (packet->options[i].length > 0U) {
			memcpy(&out[offset], packet->options[i].value,
			       packet->options[i].length);
			offset += packet->options[i].length;
		}
	}
	if (packet->payload_len > 0U) {
		out[offset++] = LICHEN_COAP_PAYLOAD_MARKER;
		memcpy(&out[offset], packet->payload, packet->payload_len);
		offset += packet->payload_len;
	}

	*out_len = offset;
	return 0;
}
