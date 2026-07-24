/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <schc/schc.h>

#include <stdbool.h>
#include <limits.h>
#include <string.h>

#define SCHC_DEFAULT_WINDOW_BITS 1
#define SCHC_DEFAULT_FCN_BITS 6
#define SCHC_DEFAULT_DTAG_BITS 0
#define SCHC_WINDOW_SIZE 32
#define SCHC_FRAGMENT_RULE_ID_LEN 1
#define SCHC_FRAGMENT_CONTROL_LEN 1
#define SCHC_FRAGMENT_MIC_LEN 4
#define SCHC_ACK_BASE_LEN 3
#define SCHC_FRAGMENT_MAX_TRACKED_TILES 64

enum sender_phase {
	SENDER_INITIAL,
	SENDER_WAITING,
	SENDER_RETRANSMIT,
	SENDER_ACK_REQUEST,
	SENDER_ABORT,
	SENDER_NONE,
};

enum receiver_pending {
	RECEIVER_PENDING_NONE,
	RECEIVER_PENDING_ACK,
	RECEIVER_PENDING_COMPLETE,
	RECEIVER_PENDING_ABORT,
};

static bool valid_fragment_rule(uint8_t rule_id)
{
	return rule_id == SCHC_FRAGMENT_RULE_A_TO_B ||
	       rule_id == SCHC_FRAGMENT_RULE_B_TO_A;
}

static uint32_t crc32_iso_hdlc(const uint8_t *data, size_t len)
{
	uint32_t crc = 0xffffffffu;

	for (size_t i = 0; i < len; i++) {
		crc ^= data[i];
		for (uint8_t bit = 0; bit < 8; bit++) {
			uint32_t mask = 0u - (crc & 1u);

			crc = (crc >> 1) ^ (0xedb88320u & mask);
		}
	}
	return ~crc;
}

static uint32_t packet_rcs(const uint8_t *packet, size_t packet_len)
{
	uint32_t crc = ~crc32_iso_hdlc(packet, packet_len);

	for (uint8_t bit = 0; bit < 8; bit++) {
		uint32_t mask = 0u - (crc & 1u);

		crc = (crc >> 1) ^ (0xedb88320u & mask);
	}
	return ~crc;
}

static void write_be32(uint8_t *out, uint32_t value)
{
	out[0] = (uint8_t)(value >> 24);
	out[1] = (uint8_t)(value >> 16);
	out[2] = (uint8_t)(value >> 8);
	out[3] = (uint8_t)value;
}

static const struct schc_rule *find_rule(const struct schc_profile *profile,
					 uint8_t rule_id)
{
	for (size_t i = 0; i < profile->rule_count; i++) {
		if (profile->rules[i].rule_id == rule_id) {
			return &profile->rules[i];
		}
	}
	return NULL;
}

int schc_compress(const struct schc_profile *profile,
		  const uint8_t *packet, size_t packet_len,
		  uint8_t *out, size_t out_len)
{
	if (profile == NULL ||
	    (profile->rule_count > 0 && profile->rules == NULL)) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (packet == NULL) {
		return SCHC_ERR_TOO_SHORT;
	}
	if (out == NULL) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	for (size_t i = 0; i < profile->rule_count; i++) {
		const struct schc_rule *rule = &profile->rules[i];

		if (rule->compress == NULL) {
			continue;
		}
		int ret = rule->compress(rule, packet, packet_len, out, out_len);
		if (ret > 0) {
			return ret;
		}
		if (ret != SCHC_ERR_NO_MATCHING_RULE) {
			return ret;
		}
	}
	if (!profile->use_uncompressed_fallback) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}
	if (packet_len > (size_t)INT_MAX - 1u) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	size_t needed = 1 + packet_len;
	if (out_len < needed) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = profile->uncompressed_rule_id;
	memcpy(&out[1], packet, packet_len);
	return (int)needed;
}

int schc_decompress(const struct schc_profile *profile,
		    const uint8_t *data, size_t data_len,
		    uint8_t *out, size_t out_len)
{
	if (profile == NULL ||
	    (profile->rule_count > 0 && profile->rules == NULL)) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (data == NULL) {
		return SCHC_ERR_TOO_SHORT;
	}
	if (out == NULL) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	if (data_len == 0) {
		return SCHC_ERR_TOO_SHORT;
	}
	uint8_t id = data[0];
	if (profile->use_uncompressed_fallback &&
	    id == profile->uncompressed_rule_id) {
		const uint8_t *payload = &data[1];
		size_t payload_len = data_len - 1;

		if (payload_len > (size_t)INT_MAX) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
		if (out_len < payload_len) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
		memcpy(out, payload, payload_len);
		return (int)payload_len;
	}
	const struct schc_rule *rule = find_rule(profile, id);
	if (rule == NULL || rule->decompress == NULL) {
		return SCHC_ERR_UNKNOWN_RULE_ID;
	}
	return rule->decompress(rule, data, data_len, out, out_len);
}

static void set_bit(uint8_t *bytes, size_t bit)
{
	if (fragmenter == NULL || config == NULL || packet == NULL ||
	    config->tile_size == 0 || config->mtu == 0) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (packet_len > SCHC_MAX_PACKET) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	uint8_t window_bits = fragment_window_bits(config);
	uint8_t fcn_bits = fragment_fcn_bits(config);
	int ret = validate_fragment_bits(config->dtag_bits, window_bits,
					 fcn_bits);

	if (ret < 0) {
		return ret;
	}
	ret = validate_dtag(config->dtag, config->dtag_bits);
	if (ret < 0) {
		return ret;
	}

	fragmenter->config = *config;
	fragmenter->packet = packet;
	fragmenter->packet_len = packet_len;
	fragmenter->offset = 0;
	return SCHC_OK;
}

static bool get_bit(const uint8_t *bytes, size_t bit)
{
	return (bytes[bit / 8u] & (uint8_t)(1u << (7u - bit % 8u))) != 0;
}

int schc_fragment_encode(const struct schc_fragment *fragment,
			 uint8_t *out, size_t out_len)
{
	if (fragment == NULL || out == NULL || fragment->tile == NULL ||
	    !valid_fragment_rule(fragment->rule_id) || fragment->window > 1u ||
	    fragment->fcn > SCHC_ALL_1) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	bool all1 = fragment->fcn == SCHC_ALL_1;
	if ((all1 && (fragment->tile_len == 0u ||
		     fragment->tile_len > SCHC_FRAGMENT_TILE_SIZE)) ||
	    (!all1 && fragment->tile_len != SCHC_FRAGMENT_TILE_SIZE) ||
	    (!all1 && fragment->window == 1u && fragment->fcn == 0u) ||
	    (!all1 && (fragment->rcs[0] != 0u || fragment->rcs[1] != 0u ||
			 fragment->rcs[2] != 0u || fragment->rcs[3] != 0u))) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	size_t content_len = fragment->tile_len + (all1 ? 4u : 0u);
	size_t needed = content_len + 2u;
	if (out_len < needed) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	memset(out, 0, needed);
	out[0] = fragment->rule_id;
	out[1] = (uint8_t)((fragment->window << 7) | (fragment->fcn << 1));
	size_t index = 0;
	if (all1) {
		for (size_t i = 0; i < 4u; i++, index++) {
			out[1u + index] |= fragment->rcs[i] >> 7;
			out[2u + index] = (uint8_t)(fragment->rcs[i] << 1);
		}
	}
	for (size_t i = 0; i < fragment->tile_len; i++, index++) {
		out[1u + index] |= fragment->tile[i] >> 7;
		out[2u + index] = (uint8_t)(fragment->tile[i] << 1);
	}
	return (int)needed;
}

int schc_fragment_decode(struct schc_fragment *fragment,
			 const uint8_t *data, size_t data_len,
			 uint8_t *tile, size_t tile_len)
{
	if (fragment == NULL || data == NULL || tile == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (data_len < 2u) {
		return SCHC_ERR_TOO_SHORT;
	}
	if (!valid_fragment_rule(data[0])) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if ((data[data_len - 1u] & 1u) != 0u) {
		return SCHC_ERR_FRAGMENT_PADDING;
	}
	uint8_t fcn = (data[1] >> 1) & SCHC_ALL_1;
	uint8_t window = data[1] >> 7;
	bool all1 = fcn == SCHC_ALL_1;
	size_t content_len = data_len - 2u;
	size_t payload_len;
	if (all1) {
		if (content_len < 5u || content_len > 4u + SCHC_FRAGMENT_TILE_SIZE) {
			return SCHC_ERR_FRAGMENT_LENGTH;
		}
		payload_len = content_len - 4u;
	} else {
		if (data_len != SCHC_FRAGMENT_TILE_SIZE + 2u) {
			return SCHC_ERR_FRAGMENT_LENGTH;
		}
		if (window == 1u && fcn == 0u) {
			return SCHC_ERR_FRAGMENT_FCN;
		}
		payload_len = SCHC_FRAGMENT_TILE_SIZE;
	}
	if (tile_len < payload_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	memset(fragment, 0, sizeof(*fragment));
	fragment->rule_id = data[0];
	fragment->window = window;
	fragment->fcn = fcn;
	fragment->tile = tile;
	fragment->tile_len = payload_len;
	if (all1) {
		for (size_t i = 0; i < 4u; i++) {
			fragment->rcs[i] = (uint8_t)((data[1u + i] << 7) |
						      (data[2u + i] >> 1));
		}
	}
	size_t skip = all1 ? 4u : 0u;
	for (size_t i = 0; i < payload_len; i++) {
		tile[i] = (uint8_t)((data[1u + skip + i] << 7) |
				    (data[2u + skip + i] >> 1));
	}
	return (int)data_len;
}

int schc_ack_encode(const struct schc_ack *ack, uint8_t *out, size_t out_len)
{
	if (ack == NULL || out == NULL || !valid_fragment_rule(ack->rule_id) ||
	    ack->window > 1u || (ack->complete && ack->bitmap != 0u)) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (ack->complete) {
		if (out_len < 2u) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
		out[0] = ack->rule_id;
		out[1] = (uint8_t)((ack->window << 7) | 0x40u);
		return 2;
	}
	uint64_t bitmap = ack->bitmap & SCHC_BITMAP_MASK;
	size_t trailing = 0;
	while (trailing < SCHC_FRAGMENT_WINDOW_SIZE &&
	       (bitmap & (UINT64_C(1) << trailing)) != 0u) {
		trailing++;
	}
	size_t kept = SCHC_FRAGMENT_WINDOW_SIZE;
	size_t restored = 0;
	size_t padding = 7u;
	if (trailing != 0u) {
		kept -= trailing;
		restored = (8u - ((2u + kept) % 8u)) % 8u;
		padding = 0;
	}
	size_t needed = 1u + (2u + kept + restored + padding) / 8u;
	if (out_len < needed) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	memset(out, 0, needed);
	out[0] = ack->rule_id;
	if (ack->window != 0u) {
		set_bit(&out[1], 0);
	}
	for (size_t position = 0; position < kept; position++) {
		if ((bitmap & (UINT64_C(1) << (62u - position))) != 0u) {
			set_bit(&out[1], 2u + position);
		}
	}
	for (size_t position = 0; position < restored; position++) {
		set_bit(&out[1], 2u + kept + position);
	}
	return (int)needed;
}

int schc_ack_decode(struct schc_ack *ack, uint64_t assigned_bitmap,
		    bool check_assigned, const uint8_t *data, size_t data_len)
{
	if (ack == NULL || data == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (data_len < 2u) {
		return SCHC_ERR_TOO_SHORT;
	}
	if (data_len > 10u || !valid_fragment_rule(data[0])) {
		return SCHC_ERR_ACK_MALFORMED;
	}
	struct schc_ack decoded = {
		.rule_id = data[0],
		.window = data[1] >> 7,
		.complete = (data[1] & 0x40u) != 0u,
	};
	if (decoded.complete) {
		if (data_len != 2u || (data[1] & SCHC_ALL_1) != 0u) {
			return SCHC_ERR_ACK_MALFORMED;
		}
		*ack = decoded;
		return 2;
	}
	size_t bit_count = (data_len - 1u) * 8u - 2u;
	if (bit_count >= SCHC_FRAGMENT_WINDOW_SIZE) {
		size_t padding = bit_count - SCHC_FRAGMENT_WINDOW_SIZE;
		if (padding > 7u) {
			return SCHC_ERR_ACK_MALFORMED;
		}
		for (size_t i = 0; i < padding; i++) {
			if (get_bit(&data[1], 2u + SCHC_FRAGMENT_WINDOW_SIZE + i)) {
				return SCHC_ERR_ACK_MALFORMED;
			}
		}
		for (size_t position = 0; position < SCHC_FRAGMENT_WINDOW_SIZE; position++) {
			if (get_bit(&data[1], 2u + position)) {
				decoded.bitmap |= UINT64_C(1) << (62u - position);
			}
		}
	} else {
		for (size_t position = 0; position < bit_count; position++) {
			if (get_bit(&data[1], 2u + position)) {
				decoded.bitmap |= UINT64_C(1) << (62u - position);
			}
		}
		for (size_t position = bit_count; position < SCHC_FRAGMENT_WINDOW_SIZE;
		     position++) {
			decoded.bitmap |= UINT64_C(1) << (62u - position);
		}
	}
	uint8_t canonical[10];
	int canonical_len = schc_ack_encode(&decoded, canonical, sizeof(canonical));
	if (canonical_len < 0 || (size_t)canonical_len != data_len ||
	    memcmp(canonical, data, data_len) != 0) {
		return SCHC_ERR_ACK_NONCANONICAL;
	}
	if (check_assigned &&
	    (decoded.bitmap & ~(assigned_bitmap & SCHC_BITMAP_MASK)) != 0u) {
		return SCHC_ERR_ACK_UNASSIGNED;
	}
	*ack = decoded;
	return (int)data_len;
}

int schc_control_encode(enum schc_fragment_control control, uint8_t rule_id,
			uint8_t window, uint8_t *out, size_t out_len)
{
	if (control != SCHC_CONTROL_ACK_REQUEST &&
	    control != SCHC_CONTROL_SENDER_ABORT &&
	    control != SCHC_CONTROL_RECEIVER_ABORT) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (!valid_fragment_rule(rule_id) || window > 1u || out == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	size_t needed = control == SCHC_CONTROL_RECEIVER_ABORT ? 3u : 2u;
	if (out_len < needed) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = rule_id;
	switch (control) {
	case SCHC_CONTROL_ACK_REQUEST:
		out[1] = (uint8_t)(window << 7);
		break;
	case SCHC_CONTROL_SENDER_ABORT:
		out[1] = 0xfeu;
		break;
	case SCHC_CONTROL_RECEIVER_ABORT:
		out[1] = 0xffu;
		out[2] = 0xffu;
		break;
	default:
		break;
	}
	return (int)needed;
}

static uint8_t sender_final_window(const struct schc_fragmenter *fragmenter)
{
	return (uint8_t)((fragmenter->fragment_count - 1u) /
			 SCHC_FRAGMENT_WINDOW_SIZE);
}

static void sender_terminal(struct schc_fragmenter *fragmenter,
			    enum schc_sender_status status, uint8_t phase)
{
	fragmenter->packet = NULL;
	fragmenter->packet_len = 0;
	fragmenter->fragment_count = 0;
	fragmenter->next_fragment = 0;
	fragmenter->missing = 0;
	fragmenter->status = status;
	fragmenter->phase = phase;
}

static uint64_t sender_assigned(const struct schc_fragmenter *fragmenter,
				uint8_t window)
{
	uint64_t assigned = 0;
	for (size_t index = 0; index < fragmenter->fragment_count; index++) {
		if (index / SCHC_FRAGMENT_WINDOW_SIZE == window) {
			bool final = index + 1u == fragmenter->fragment_count;
			uint8_t fcn = final ? 0u :
				(uint8_t)(62u - index % SCHC_FRAGMENT_WINDOW_SIZE);
			assigned |= UINT64_C(1) << fcn;
		}
	}
	return assigned;
}

static int sender_fragment(const struct schc_fragmenter *fragmenter, size_t index,
			   uint8_t *out, size_t out_len)
{
	size_t offset = index * SCHC_FRAGMENT_TILE_SIZE;
	size_t remaining = fragmenter->packet_len - offset;
	bool final = index + 1u == fragmenter->fragment_count;
	struct schc_fragment fragment = {
		.tile = &fragmenter->packet[offset],
		.tile_len = remaining < SCHC_FRAGMENT_TILE_SIZE ? remaining :
			    SCHC_FRAGMENT_TILE_SIZE,
		.rule_id = fragmenter->rule_id,
		.window = (uint8_t)(index / SCHC_FRAGMENT_WINDOW_SIZE),
		.fcn = final ? SCHC_ALL_1 :
		       (uint8_t)(62u - index % SCHC_FRAGMENT_WINDOW_SIZE),
	};
	if (final) {
		write_be32(fragment.rcs, packet_rcs(fragmenter->packet,
						    fragmenter->packet_len));
	}
	return schc_fragment_encode(&fragment, out, out_len);
}

int schc_fragmenter_init(struct schc_fragmenter *fragmenter, uint8_t rule_id,
			 const uint8_t *packet, size_t packet_len,
			 size_t receiver_limit)
{
	if (fragmenter == NULL || packet == NULL || !valid_fragment_rule(rule_id) ||
	    receiver_limit == 0u || receiver_limit > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (packet_len == 0u) {
		return SCHC_ERR_TOO_SHORT;
	}
	if (packet_len > receiver_limit) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	memset(fragmenter, 0, sizeof(*fragmenter));
	fragmenter->packet = packet;
	fragmenter->packet_len = packet_len;
	fragmenter->fragment_count =
		(packet_len + SCHC_FRAGMENT_TILE_SIZE - 1u) / SCHC_FRAGMENT_TILE_SIZE;
	fragmenter->rule_id = rule_id;
	fragmenter->phase = SENDER_INITIAL;
	fragmenter->status = SCHC_SENDER_READY;
	return SCHC_OK;
}

int schc_fragmenter_next(struct schc_fragmenter *fragmenter,
			 uint8_t *out, size_t out_len)
{
	if (fragmenter == NULL || out == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (fragmenter->phase == SENDER_INITIAL) {
		int ret = sender_fragment(fragmenter, fragmenter->next_fragment,
					  out, out_len);
		if (ret < 0) {
			return ret;
		}
		fragmenter->status = SCHC_SENDER_ACTIVE;
		fragmenter->next_fragment++;
		if (fragmenter->next_fragment == fragmenter->fragment_count) {
			fragmenter->attempts++;
			fragmenter->phase = SENDER_WAITING;
		}
		return ret;
	}
	if (fragmenter->phase == SENDER_RETRANSMIT) {
		uint8_t position = fragmenter->retransmit_position;
		while (position < SCHC_FRAGMENT_WINDOW_SIZE) {
			uint8_t bit = (uint8_t)(62u - position);
			if ((fragmenter->missing & (UINT64_C(1) << bit)) == 0u) {
				position++;
				continue;
			}
			size_t index = (size_t)fragmenter->retransmit_window *
				       SCHC_FRAGMENT_WINDOW_SIZE + position;
			if (bit == 0u && fragmenter->retransmit_window ==
					 sender_final_window(fragmenter)) {
				index = fragmenter->fragment_count - 1u;
			}
			int ret = sender_fragment(fragmenter, index, out, out_len);
			if (ret < 0) {
				return ret;
			}
			fragmenter->retransmit_position = position + 1u;
			if (index + 1u == fragmenter->fragment_count) {
				fragmenter->attempts++;
				fragmenter->phase = SENDER_WAITING;
			}
			return ret;
		}
		fragmenter->phase = SENDER_ACK_REQUEST;
	}
	if (fragmenter->phase == SENDER_ACK_REQUEST) {
		if (fragmenter->attempts >= SCHC_FRAGMENT_MAX_ATTEMPTS) {
			sender_terminal(fragmenter, SCHC_SENDER_ABORTED, SENDER_ABORT);
		} else {
			int ret = schc_control_encode(SCHC_CONTROL_ACK_REQUEST,
						      fragmenter->rule_id,
						      sender_final_window(fragmenter),
						      out, out_len);
			if (ret < 0) {
				return ret;
			}
			fragmenter->attempts++;
			fragmenter->phase = SENDER_WAITING;
			return ret;
		}
	}
	if (fragmenter->phase == SENDER_ABORT) {
		int ret = schc_control_encode(SCHC_CONTROL_SENDER_ABORT,
					      fragmenter->rule_id, 0, out, out_len);
		if (ret < 0) {
			return ret;
		}
		fragmenter->phase = SENDER_NONE;
		return ret;
	}
	return SCHC_ERR_DONE;
}

int schc_fragmenter_input(struct schc_fragmenter *fragmenter,
			  const uint8_t *message, size_t message_len)
{
	if (fragmenter == NULL || message == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (fragmenter->status != SCHC_SENDER_ACTIVE || message_len == 0u ||
	    message[0] != fragmenter->rule_id) {
		return SCHC_OK;
	}
	uint8_t abort[3];
	int abort_len = schc_control_encode(SCHC_CONTROL_RECEIVER_ABORT,
					    fragmenter->rule_id, 0,
					    abort, sizeof(abort));
	if (abort_len > 0 && message_len == (size_t)abort_len &&
	    memcmp(message, abort, message_len) == 0) {
		sender_terminal(fragmenter, SCHC_SENDER_ABORTED, SENDER_NONE);
		return SCHC_OK;
	}
	if (fragmenter->phase != SENDER_WAITING) {
		return SCHC_OK;
	}
	struct schc_ack ack;
	int ret = schc_ack_decode(&ack, 0, false, message, message_len);
	if (ret < 0) {
		return ret;
	}
	uint8_t final_window = sender_final_window(fragmenter);
	if (ack.complete) {
		if (ack.window == final_window) {
			sender_terminal(fragmenter, SCHC_SENDER_SUCCEEDED, SENDER_NONE);
		}
		return SCHC_OK;
	}
	if (ack.window > final_window) {
		return SCHC_OK;
	}
	uint64_t assigned = sender_assigned(fragmenter, ack.window);
	ret = schc_ack_decode(&ack, assigned, true, message, message_len);
	if (ret < 0) {
		return ret;
	}
	uint64_t missing = assigned & ~ack.bitmap;
	if (missing == 0u) {
		if (ack.window == final_window) {
			sender_terminal(fragmenter, SCHC_SENDER_ABORTED, SENDER_ABORT);
		}
		return SCHC_OK;
	}
	if (fragmenter->attempts >= SCHC_FRAGMENT_MAX_ATTEMPTS) {
		sender_terminal(fragmenter, SCHC_SENDER_ABORTED, SENDER_ABORT);
		return SCHC_OK;
	}
	fragmenter->missing = missing;
	fragmenter->retransmit_window = ack.window;
	fragmenter->retransmit_position = 0;
	fragmenter->phase = SENDER_RETRANSMIT;
	return SCHC_OK;
}

int schc_fragmenter_timeout(struct schc_fragmenter *fragmenter)
{
	if (fragmenter == NULL || fragmenter->status != SCHC_SENDER_ACTIVE ||
	    fragmenter->phase != SENDER_WAITING) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (fragmenter->attempts >= SCHC_FRAGMENT_MAX_ATTEMPTS) {
		sender_terminal(fragmenter, SCHC_SENDER_ABORTED, SENDER_ABORT);
	} else {
		fragmenter->phase = SENDER_ACK_REQUEST;
	}
	return SCHC_OK;
}

static void receiver_reset(struct schc_reassembler *reassembler)
{
	reassembler->final_len = 0;
	reassembler->final_staging = 0;
	reassembler->complete_len = 0;
	reassembler->bitmap[0] = 0;
	reassembler->bitmap[1] = 0;
	memset(reassembler->rcs, 0, sizeof(reassembler->rcs));
	memset(&reassembler->pending_ack, 0, sizeof(reassembler->pending_ack));
	reassembler->rule_id = 0;
	reassembler->final_window = 0;
	reassembler->attempts = 0;
	reassembler->pending = RECEIVER_PENDING_NONE;
	reassembler->active = false;
	reassembler->have_all1 = false;
	reassembler->delivered = false;
}

int schc_reassembler_init(struct schc_reassembler *reassembler,
			  uint8_t *packet, size_t capacity, size_t limit)
{
	if (reassembler == NULL || packet == NULL || limit == 0u ||
	    limit > capacity || limit > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	memset(reassembler, 0, sizeof(*reassembler));
	reassembler->packet = packet;
	reassembler->capacity = capacity;
	reassembler->limit = limit;
	return SCHC_OK;
}

void schc_reassembler_release(struct schc_reassembler *reassembler)
{
	if (reassembler != NULL) {
		receiver_reset(reassembler);
	}
}

static void receiver_queue_abort(struct schc_reassembler *reassembler,
				 uint8_t rule_id)
{
	reassembler->rule_id = rule_id;
	reassembler->pending = RECEIVER_PENDING_ABORT;
}

static void receiver_queue_ack(struct schc_reassembler *reassembler,
			       uint8_t window, uint64_t bitmap, bool complete)
{
	if (reassembler->attempts >= SCHC_FRAGMENT_MAX_ATTEMPTS) {
		receiver_queue_abort(reassembler, reassembler->rule_id);
		return;
	}
	reassembler->pending_ack.rule_id = reassembler->rule_id;
	reassembler->pending_ack.window = window;
	reassembler->pending_ack.bitmap = complete ? 0u : bitmap;
	reassembler->pending_ack.complete = complete;
	reassembler->pending = complete ? RECEIVER_PENDING_COMPLETE :
			       RECEIVER_PENDING_ACK;
}

static unsigned trailing_zeros63(uint64_t value)
{
	unsigned count = 0;
	while (count < SCHC_FRAGMENT_WINDOW_SIZE &&
	       (value & (UINT64_C(1) << count)) == 0u) {
		count++;
	}
	return count;
}

static void receiver_finalize(struct schc_reassembler *reassembler,
			      struct schc_reassembly_result *result)
{
	if (reassembler->final_window == 1u &&
	    reassembler->bitmap[0] != SCHC_BITMAP_MASK) {
		receiver_queue_ack(reassembler, 0, reassembler->bitmap[0], false);
		result->aborted = reassembler->pending == RECEIVER_PENDING_ABORT;
		return;
	}
	uint64_t bitmap = reassembler->bitmap[reassembler->final_window];
	size_t regular_count = bitmap == 0u ? 0u :
		SCHC_FRAGMENT_WINDOW_SIZE - trailing_zeros63(bitmap);
	uint64_t required = regular_count == 0u ? 0u :
		SCHC_BITMAP_MASK & ~(SCHC_BITMAP_MASK >> regular_count);
	if ((bitmap & required) != required) {
		receiver_queue_ack(reassembler, reassembler->final_window,
				   bitmap | 1u, false);
		result->aborted = reassembler->pending == RECEIVER_PENDING_ABORT;
		return;
	}
	size_t final_ordinal = (size_t)reassembler->final_window *
			       SCHC_FRAGMENT_WINDOW_SIZE + regular_count;
	size_t final_offset = final_ordinal * SCHC_FRAGMENT_TILE_SIZE;
	size_t packet_len = final_offset + reassembler->final_len;
	if (packet_len > reassembler->limit || final_offset > reassembler->final_staging) {
		receiver_queue_abort(reassembler, reassembler->rule_id);
		result->aborted = true;
		return;
	}
	memmove(&reassembler->packet[final_offset],
		&reassembler->packet[reassembler->final_staging],
		reassembler->final_len);
	reassembler->final_staging = final_offset;
	result->rcs_checked = true;
	uint8_t expected[4];
	write_be32(expected, packet_rcs(reassembler->packet, packet_len));
	if (memcmp(expected, reassembler->rcs, sizeof(expected)) == 0) {
		reassembler->complete_len = packet_len;
		result->rcs_ok = true;
		receiver_queue_ack(reassembler, reassembler->final_window, 0, true);
	} else {
		result->rcs_ok = false;
		receiver_queue_ack(reassembler, reassembler->final_window,
				   bitmap | 1u, false);
		result->aborted = reassembler->pending == RECEIVER_PENDING_ABORT;
	}
}

static bool exact_control(const uint8_t *message, size_t message_len,
			  enum schc_fragment_control control)
{
	uint8_t expected[3];
	int length = schc_control_encode(control, message[0], message[1] >> 7,
					 expected, sizeof(expected));
	return length > 0 && message_len == (size_t)length &&
	       memcmp(message, expected, message_len) == 0;
}

int schc_reassembler_input(struct schc_reassembler *reassembler,
			   const uint8_t *message, size_t message_len,
			   struct schc_reassembly_result *result)
{
	if (reassembler == NULL || message == NULL || result == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	memset(result, 0, sizeof(*result));
	if (message_len == 0u) {
		return SCHC_ERR_TOO_SHORT;
	}
	if (!valid_fragment_rule(message[0])) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	uint8_t rule_id = message[0];
	bool has_context = reassembler->active || reassembler->delivered ||
			   reassembler->pending != RECEIVER_PENDING_NONE;
	if (has_context && valid_fragment_rule(reassembler->rule_id) &&
	    reassembler->rule_id != rule_id) {
		return SCHC_OK;
	}
	if (message_len < 2u) {
		if (reassembler->delivered) {
			return SCHC_ERR_TOO_SHORT;
		}
	}

	if (tile_index >= SCHC_FRAGMENT_MAX_TRACKED_TILES ||
	    (reassembler->config.tile_size > 0 && tile_index > reassembler->packet_max_len / reassembler->config.tile_size)) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	if (offset >= reassembler->packet_max_len ||
	    tile_len > reassembler->packet_max_len - offset) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	if (fcn == all_1 && mic_len != 0) {
		size_t candidate_len = offset + tile_len;
		uint32_t observed = read_be32(&tile[tile_len]);

		memcpy(&reassembler->packet[offset], tile, tile_len);
		tile_copied = true;

		uint32_t expected = schc_crc32_ieee(reassembler->packet,
						   candidate_len);

		if (expected != observed) {
			*complete = false;
			return SCHC_ERR_MIC_MISMATCH;
		}
		receiver_queue_abort(reassembler, rule_id);
		result->aborted = true;
		return SCHC_OK;
	}
	if (exact_control(message, message_len, SCHC_CONTROL_SENDER_ABORT) ||
	    exact_control(message, message_len, SCHC_CONTROL_RECEIVER_ABORT)) {
		receiver_reset(reassembler);
		result->aborted = true;
		return SCHC_OK;
	}
	bool ack_request = exact_control(message, message_len,
					 SCHC_CONTROL_ACK_REQUEST);
	if (reassembler->delivered) {
		if (!ack_request) {
			struct schc_fragment probe;
			int probe_len = schc_fragment_decode(&probe, message, message_len,
							     reassembler->decode_tile,
							     sizeof(reassembler->decode_tile));
			if (probe_len < 0) {
				return probe_len;
			}
		}
		receiver_reset(reassembler);
	}
	if (reassembler->pending != RECEIVER_PENDING_NONE) {
		if (reassembler->pending == RECEIVER_PENDING_ABORT ||
		    !reassembler->have_all1) {
			return SCHC_ERR_INVALID_ARGUMENT;
		}
		struct schc_fragment repeated;
		int repeated_len = schc_fragment_decode(&repeated, message, message_len,
							 reassembler->decode_tile,
							 sizeof(reassembler->decode_tile));
		if (repeated_len < 0 || repeated.fcn != SCHC_ALL_1) {
			return SCHC_ERR_INVALID_ARGUMENT;
		}
		bool same = reassembler->final_window == repeated.window &&
			    reassembler->final_len == repeated.tile_len &&
			    memcmp(reassembler->rcs, repeated.rcs, 4u) == 0 &&
			    memcmp(&reassembler->packet[reassembler->final_staging],
				   repeated.tile, repeated.tile_len) == 0;
		if (!same) {
			receiver_queue_abort(reassembler, rule_id);
			result->aborted = true;
			return SCHC_OK;
		}
		receiver_finalize(reassembler, result);
		return SCHC_OK;
	}
	if (ack_request) {
		if (!reassembler->active) {
			reassembler->active = true;
			reassembler->rule_id = rule_id;
		}
		if (reassembler->have_all1) {
			receiver_finalize(reassembler, result);
		} else {
			uint8_t window = reassembler->bitmap[0] == SCHC_BITMAP_MASK ? 1u : 0u;
			receiver_queue_ack(reassembler, window,
					   reassembler->bitmap[window], false);
		}
		result->aborted = reassembler->pending == RECEIVER_PENDING_ABORT;
		return SCHC_OK;
	}
	struct schc_fragment fragment;
	int ret = schc_fragment_decode(&fragment, message, message_len,
				       reassembler->decode_tile,
				       sizeof(reassembler->decode_tile));
	if (ret < 0) {
		receiver_queue_abort(reassembler, rule_id);
		result->aborted = true;
		return SCHC_OK;
	}
	if (!reassembler->active) {
		reassembler->active = true;
		reassembler->rule_id = rule_id;
	}
	if (fragment.fcn == SCHC_ALL_1) {
		if ((reassembler->bitmap[fragment.window] & 1u) != 0u) {
			receiver_queue_abort(reassembler, rule_id);
			result->aborted = true;
			return SCHC_OK;
		}
		if (reassembler->have_all1) {
			bool same = reassembler->final_window == fragment.window &&
				    reassembler->final_len == fragment.tile_len &&
				    memcmp(reassembler->rcs, fragment.rcs, 4u) == 0 &&
				    memcmp(&reassembler->packet[reassembler->final_staging],
					   fragment.tile, fragment.tile_len) == 0;
			if (!same) {
				receiver_queue_abort(reassembler, rule_id);
				result->aborted = true;
				return SCHC_OK;
			}
			receiver_finalize(reassembler, result);
			return SCHC_OK;
		}
		if (fragment.window == 0u && reassembler->bitmap[1] != 0u) {
			receiver_queue_abort(reassembler, rule_id);
			result->aborted = true;
			return SCHC_OK;
		}
		size_t retained = fragment.tile_len;
		for (size_t window = 0; window < 2u; window++) {
			uint64_t bits = reassembler->bitmap[window];
			while (bits != 0u) {
				retained += SCHC_FRAGMENT_TILE_SIZE;
				bits &= bits - 1u;
			}
		}
		if (retained > reassembler->limit) {
			receiver_queue_abort(reassembler, rule_id);
			result->aborted = true;
			return SCHC_OK;
		}
		reassembler->final_staging = reassembler->limit - fragment.tile_len;
		memcpy(&reassembler->packet[reassembler->final_staging], fragment.tile,
		       fragment.tile_len);
		reassembler->final_len = fragment.tile_len;
		reassembler->final_window = fragment.window;
		memcpy(reassembler->rcs, fragment.rcs, 4u);
		reassembler->have_all1 = true;
		receiver_finalize(reassembler, result);
		return SCHC_OK;
	}
	if (reassembler->have_all1 &&
	    (fragment.window > reassembler->final_window ||
	     (fragment.window == reassembler->final_window && fragment.fcn == 0u))) {
		receiver_queue_abort(reassembler, rule_id);
		result->aborted = true;
		return SCHC_OK;
	}
	size_t ordinal = (size_t)fragment.window * SCHC_FRAGMENT_WINDOW_SIZE +
			 62u - fragment.fcn;
	size_t offset = ordinal * SCHC_FRAGMENT_TILE_SIZE;
	size_t end = offset + SCHC_FRAGMENT_TILE_SIZE;
	if (end > reassembler->limit) {
		receiver_queue_abort(reassembler, rule_id);
		result->aborted = true;
		return SCHC_OK;
	}
	if (reassembler->have_all1 &&
	    offset < reassembler->final_staging + reassembler->final_len &&
	    end > reassembler->final_staging) {
		size_t tail = reassembler->limit - reassembler->final_len;

		if (end > tail) {
			receiver_queue_abort(reassembler, rule_id);
			result->aborted = true;
			return SCHC_OK;
		}
		memmove(&reassembler->packet[tail],
			&reassembler->packet[reassembler->final_staging],
			reassembler->final_len);
		reassembler->final_staging = tail;
	}
	if (reassembler->have_all1 && end > reassembler->final_staging) {
		receiver_queue_abort(reassembler, rule_id);
		result->aborted = true;
		return SCHC_OK;
	}
	uint64_t bit = UINT64_C(1) << fragment.fcn;
	if ((reassembler->bitmap[fragment.window] & bit) != 0u) {
		if (memcmp(&reassembler->packet[offset], fragment.tile,
			   SCHC_FRAGMENT_TILE_SIZE) != 0) {
			receiver_queue_abort(reassembler, rule_id);
			result->aborted = true;
		}
		return SCHC_OK;
	}
	memcpy(&reassembler->packet[offset], fragment.tile, SCHC_FRAGMENT_TILE_SIZE);
	reassembler->bitmap[fragment.window] |= bit;
	return SCHC_OK;
}

int schc_reassembler_next(struct schc_reassembler *reassembler,
			  uint8_t *out, size_t out_len,
			  struct schc_reassembly_result *result)
{
	if (reassembler == NULL || out == NULL || result == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	memset(result, 0, sizeof(*result));
	if (reassembler->pending == RECEIVER_PENDING_NONE) {
		return SCHC_ERR_DONE;
	}
	int ret;
	if (reassembler->pending == RECEIVER_PENDING_ABORT) {
		ret = schc_control_encode(SCHC_CONTROL_RECEIVER_ABORT,
					  reassembler->rule_id, 0, out, out_len);
	} else {
		ret = schc_ack_encode(&reassembler->pending_ack, out, out_len);
	}
	if (ret < 0) {
		return ret;
	}
	uint8_t pending = reassembler->pending;
	reassembler->pending = RECEIVER_PENDING_NONE;
	if (pending == RECEIVER_PENDING_ABORT) {
		result->aborted = true;
		receiver_reset(reassembler);
	} else if (pending == RECEIVER_PENDING_COMPLETE) {
		reassembler->active = false;
		reassembler->delivered = true;
		result->complete = true;
		result->rcs_checked = true;
		result->rcs_ok = true;
		result->packet_len = reassembler->complete_len;
	} else {
		reassembler->attempts++;
	}
	return ret;
}

int schc_reassembler_packet(const struct schc_reassembler *reassembler,
			    const uint8_t **packet, size_t *packet_len)
{
	if (reassembler == NULL || packet == NULL || packet_len == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (!reassembler->delivered) {
		return SCHC_ERR_DONE;
	}
	*packet = reassembler->packet;
	*packet_len = reassembler->complete_len;
	return SCHC_OK;
}

int schc_reassembler_expire(struct schc_reassembler *reassembler)
{
	if (reassembler == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (reassembler->delivered ||
	    (!reassembler->active && reassembler->pending == RECEIVER_PENDING_NONE)) {
		return SCHC_ERR_DONE;
	}
	if (reassembler->pending == RECEIVER_PENDING_COMPLETE) {
		return SCHC_ERR_DONE;
	}
	receiver_queue_abort(reassembler, reassembler->rule_id);
	return SCHC_OK;
}

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct schc_fragmenter) <= 80u,
	       "SCHC sender context unexpectedly large");
_Static_assert(sizeof(struct schc_reassembler) <= 320u,
	       "SCHC receiver context unexpectedly large");
#endif
