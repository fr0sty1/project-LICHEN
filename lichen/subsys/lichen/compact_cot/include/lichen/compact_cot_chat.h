/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_COMPACT_COT_CHAT_H_
#define LICHEN_COMPACT_COT_CHAT_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_COMPACT_COT_CHAT_SUBTYPE 0x01U
#define LICHEN_COMPACT_COT_CHAT_MAX_MESSAGE_SIZE 255U
#define LICHEN_COMPACT_COT_CHAT_MAX_ENCODED_SIZE 274U
#define LICHEN_COMPACT_COT_TEAM_MIN 0x01U
#define LICHEN_COMPACT_COT_TEAM_MAX 0x0aU

enum lichen_compact_cot_chat_destination_type {
	LICHEN_COMPACT_COT_CHAT_BROADCAST = 0x00,
	LICHEN_COMPACT_COT_CHAT_TEAM = 0x01,
	LICHEN_COMPACT_COT_CHAT_DIRECT = 0x02,
};

union lichen_compact_cot_chat_destination {
	uint8_t team;
	uint8_t address[16];
};

/** Owned, bounded Compact CoT chat message. */
struct lichen_compact_cot_chat {
	uint8_t destination_type;
	union lichen_compact_cot_chat_destination destination;
	uint8_t message_length;
	uint8_t message[LICHEN_COMPACT_COT_CHAT_MAX_MESSAGE_SIZE];
};

/**
 * Encode one canonical Compact CoT chat datagram.
 *
 * The output is not modified on error and may overlap @p chat.
 *
 * @return encoded size (3..274) on success, -EINVAL for NULL, invalid
 *         destination/team, or invalid UTF-8, and -EMSGSIZE for a short
 *         output buffer.
 */
int lichen_compact_cot_chat_encode(const struct lichen_compact_cot_chat *chat,
				   uint8_t *output, size_t output_size);

/**
 * Decode one complete Compact CoT chat datagram.
 *
 * The owned output is not modified on error and may overlap @p input.
 * Trailing data, truncated headers/messages, reserved destination types,
 * invalid team values, non-chat subtypes, and invalid UTF-8 are rejected.
 *
 * @return 0 on success, -EINVAL for invalid content, or -EMSGSIZE for a
 *         truncated datagram or trailing data.
 */
int lichen_compact_cot_chat_decode(const uint8_t *input, size_t input_size,
				   struct lichen_compact_cot_chat *chat);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COMPACT_COT_CHAT_H_ */
