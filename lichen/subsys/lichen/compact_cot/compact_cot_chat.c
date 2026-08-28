/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/compact_cot_chat.h>

#include <errno.h>
#include <stdbool.h>
#include <string.h>

static bool continuation(uint8_t byte)
{
	return (byte & 0xc0U) == 0x80U;
}

/* RFC 3629, including shortest-form, surrogate, and U+10FFFF checks. */
static bool valid_utf8(const uint8_t *text, size_t length)
{
	size_t offset = 0U;

	while (offset < length) {
		uint8_t lead = text[offset];

		if (lead < 0x80U) {
			offset++;
		} else if (lead >= 0xc2U && lead <= 0xdfU) {
			if (offset + 1U >= length || !continuation(text[offset + 1U])) {
				return false;
			}
			offset += 2U;
		} else if (lead == 0xe0U) {
			if (offset + 2U >= length || text[offset + 1U] < 0xa0U ||
			    text[offset + 1U] > 0xbfU ||
			    !continuation(text[offset + 2U])) {
				return false;
			}
			offset += 3U;
		} else if ((lead >= 0xe1U && lead <= 0xecU) ||
			   (lead >= 0xeeU && lead <= 0xefU)) {
			if (offset + 2U >= length || !continuation(text[offset + 1U]) ||
			    !continuation(text[offset + 2U])) {
				return false;
			}
			offset += 3U;
		} else if (lead == 0xedU) {
			if (offset + 2U >= length || text[offset + 1U] < 0x80U ||
			    text[offset + 1U] > 0x9fU ||
			    !continuation(text[offset + 2U])) {
				return false;
			}
			offset += 3U;
		} else if (lead == 0xf0U) {
			if (offset + 3U >= length || text[offset + 1U] < 0x90U ||
			    text[offset + 1U] > 0xbfU ||
			    !continuation(text[offset + 2U]) ||
			    !continuation(text[offset + 3U])) {
				return false;
			}
			offset += 4U;
		} else if (lead >= 0xf1U && lead <= 0xf3U) {
			if (offset + 3U >= length || !continuation(text[offset + 1U]) ||
			    !continuation(text[offset + 2U]) ||
			    !continuation(text[offset + 3U])) {
				return false;
			}
			offset += 4U;
		} else if (lead == 0xf4U) {
			if (offset + 3U >= length || text[offset + 1U] < 0x80U ||
			    text[offset + 1U] > 0x8fU ||
			    !continuation(text[offset + 2U]) ||
			    !continuation(text[offset + 3U])) {
				return false;
			}
			offset += 4U;
		} else {
			return false;
		}
	}

	return true;
}

static size_t destination_size(uint8_t destination_type)
{
	switch (destination_type) {
	case LICHEN_COMPACT_COT_CHAT_BROADCAST:
		return 0U;
	case LICHEN_COMPACT_COT_CHAT_TEAM:
		return 1U;
	case LICHEN_COMPACT_COT_CHAT_DIRECT:
		return 16U;
	default:
		return SIZE_MAX;
	}
}

static int validate_chat(const struct lichen_compact_cot_chat *chat)
{
	if (destination_size(chat->destination_type) == SIZE_MAX) {
		return -EINVAL;
	}
	if (chat->destination_type == LICHEN_COMPACT_COT_CHAT_TEAM &&
	    (chat->destination.team < LICHEN_COMPACT_COT_TEAM_MIN ||
	     chat->destination.team > LICHEN_COMPACT_COT_TEAM_MAX)) {
		return -EINVAL;
	}
	if (!valid_utf8(chat->message, chat->message_length)) {
		return -EINVAL;
	}

	return 0;
}

int lichen_compact_cot_chat_encode(const struct lichen_compact_cot_chat *chat,
				   uint8_t *output, size_t output_size)
{
	uint8_t encoded[LICHEN_COMPACT_COT_CHAT_MAX_ENCODED_SIZE];
	size_t destination_length;
	size_t message_offset;
	size_t encoded_size;
	int ret;

	if (chat == NULL || output == NULL) {
		return -EINVAL;
	}

	ret = validate_chat(chat);
	if (ret < 0) {
		return ret;
	}

	destination_length = destination_size(chat->destination_type);
	message_offset = 3U + destination_length;
	encoded_size = message_offset + chat->message_length;
	if (output_size < encoded_size) {
		return -EMSGSIZE;
	}

	encoded[0] = LICHEN_COMPACT_COT_CHAT_SUBTYPE;
	encoded[1] = chat->destination_type;
	if (chat->destination_type == LICHEN_COMPACT_COT_CHAT_TEAM) {
		encoded[2] = chat->destination.team;
	} else if (chat->destination_type == LICHEN_COMPACT_COT_CHAT_DIRECT) {
		memcpy(&encoded[2], chat->destination.address,
		       sizeof(chat->destination.address));
	}
	encoded[2U + destination_length] = chat->message_length;
	memcpy(&encoded[message_offset], chat->message, chat->message_length);

	memcpy(output, encoded, encoded_size);
	return (int)encoded_size;
}

int lichen_compact_cot_chat_decode(const uint8_t *input, size_t input_size,
				   struct lichen_compact_cot_chat *chat)
{
	struct lichen_compact_cot_chat decoded = {0};
	size_t destination_length;
	size_t message_offset;
	size_t encoded_size;
	int ret;

	if (input == NULL || chat == NULL) {
		return -EINVAL;
	}
	if (input_size < 3U) {
		return -EMSGSIZE;
	}
	if (input[0] != LICHEN_COMPACT_COT_CHAT_SUBTYPE) {
		return -EINVAL;
	}

	decoded.destination_type = input[1];
	destination_length = destination_size(decoded.destination_type);
	if (destination_length == SIZE_MAX) {
		return -EINVAL;
	}
	message_offset = 3U + destination_length;
	if (input_size < message_offset) {
		return -EMSGSIZE;
	}

	if (decoded.destination_type == LICHEN_COMPACT_COT_CHAT_TEAM) {
		decoded.destination.team = input[2];
	} else if (decoded.destination_type == LICHEN_COMPACT_COT_CHAT_DIRECT) {
		memcpy(decoded.destination.address, &input[2],
		       sizeof(decoded.destination.address));
	}
	decoded.message_length = input[2U + destination_length];
	encoded_size = message_offset + decoded.message_length;
	if (input_size != encoded_size) {
		return -EMSGSIZE;
	}
	memcpy(decoded.message, &input[message_offset], decoded.message_length);

	ret = validate_chat(&decoded);
	if (ret < 0) {
		return ret;
	}

	*chat = decoded;
	return 0;
}
