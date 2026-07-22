/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <schc/schc.h>

#include <stdbool.h>
#include <string.h>

#define SCHC_DEFAULT_WINDOW_BITS 2
#define SCHC_DEFAULT_FCN_BITS 6
#define SCHC_FRAGMENT_RULE_ID_LEN 1
#define SCHC_FRAGMENT_CONTROL_LEN 1
#define SCHC_FRAGMENT_MIC_LEN 4
#define SCHC_ACK_BASE_LEN 3
#define SCHC_FRAGMENT_MAX_TRACKED_TILES 64

static uint8_t fragment_window_bits(const struct schc_fragmenter_config *config)
{
	return (config->window_bits != 0) ? config->window_bits :
					   SCHC_DEFAULT_WINDOW_BITS;
}

static uint8_t fragment_fcn_bits(const struct schc_fragmenter_config *config)
{
	return (config->fcn_bits != 0) ? config->fcn_bits :
					SCHC_DEFAULT_FCN_BITS;
}

static bool fragment_mode_uses_mic(enum schc_fragment_mode mode)
{
	return mode == SCHC_FRAGMENT_ACK_ALWAYS ||
	       mode == SCHC_FRAGMENT_ACK_ON_ERROR;
}

static uint8_t fragment_all_1(uint8_t fcn_bits)
{
	return (uint8_t)((1u << fcn_bits) - 1u);
}

static int validate_fragment_bits(uint8_t dtag_bits, uint8_t window_bits,
				  uint8_t fcn_bits)
{
	if (dtag_bits > 7 ||
	    window_bits == 0 || window_bits > 7 ||
	    fcn_bits == 0 || fcn_bits > 7 ||
	    dtag_bits + window_bits + fcn_bits > 8) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	return SCHC_OK;
}

static int validate_dtag(uint8_t dtag, uint8_t dtag_bits)
{
	if (dtag_bits == 0) {
		return (dtag == 0) ? SCHC_OK : SCHC_ERR_INVALID_ARGUMENT;
	}

	return (dtag < (1u << dtag_bits)) ? SCHC_OK :
					    SCHC_ERR_INVALID_ARGUMENT;
}

static uint8_t fragment_control(uint8_t dtag, uint8_t window, uint8_t fcn,
				uint8_t window_bits, uint8_t fcn_bits)
{
	return (uint8_t)((dtag << (window_bits + fcn_bits)) |
			 (window << fcn_bits) | fcn);
}

static uint8_t fragment_control_dtag(uint8_t control, uint8_t dtag_bits,
				     uint8_t window_bits, uint8_t fcn_bits)
{
	(void)fcn_bits;

	if (dtag_bits == 0) {
		return 0;
	}

	return (uint8_t)(control >> (window_bits + fcn_bits));
}

static uint8_t fragment_control_window(uint8_t control, uint8_t window_bits,
				       uint8_t fcn_bits)
{
	uint8_t mask = (uint8_t)((1u << window_bits) - 1u);

	return (uint8_t)((control >> fcn_bits) & mask);
}

static uint32_t schc_crc32_ieee(const uint8_t *data, size_t len)
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

static void write_be32(uint8_t *out, uint32_t value)
{
	out[0] = (uint8_t)(value >> 24);
	out[1] = (uint8_t)(value >> 16);
	out[2] = (uint8_t)(value >> 8);
	out[3] = (uint8_t)value;
}

static uint32_t read_be32(const uint8_t *data)
{
	return ((uint32_t)data[0] << 24) |
	       ((uint32_t)data[1] << 16) |
	       ((uint32_t)data[2] << 8) |
	       (uint32_t)data[3];
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

int schc_fragmenter_init(struct schc_fragmenter *fragmenter,
			 const struct schc_fragmenter_config *config,
			 const uint8_t *packet, size_t packet_len)
{
	if (fragmenter == NULL || config == NULL || packet == NULL ||
	    config->tile_size == 0 || config->mtu == 0) {
		return SCHC_ERR_INVALID_ARGUMENT;
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

size_t schc_fragment_header_len(const struct schc_fragmenter_config *config)
{
	(void)config;

	return SCHC_FRAGMENT_RULE_ID_LEN + SCHC_FRAGMENT_CONTROL_LEN;
}

int schc_fragmenter_next(struct schc_fragmenter *fragmenter,
			 uint8_t *out, size_t out_len)
{
	if (fragmenter == NULL || out == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	if (fragmenter->offset >= fragmenter->packet_len) {
		return SCHC_ERR_DONE;
	}

	uint8_t window_bits = fragment_window_bits(&fragmenter->config);
	uint8_t fcn_bits = fragment_fcn_bits(&fragmenter->config);

	int ret = validate_fragment_bits(fragmenter->config.dtag_bits,
					 window_bits, fcn_bits);
	if (ret < 0) {
		return ret;
	}

	size_t header_len = schc_fragment_header_len(&fragmenter->config);
	if (fragmenter->config.mtu < header_len || out_len < header_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	size_t max_payload = fragmenter->config.mtu - header_len;
	if (max_payload > out_len - header_len) {
		max_payload = out_len - header_len;
	}
	if (max_payload == 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	size_t tile_len = fragmenter->config.tile_size;
	size_t remaining = fragmenter->packet_len - fragmenter->offset;
	bool is_last = remaining <= tile_len;
	if (is_last) {
		tile_len = remaining;
	}
	size_t mic_len = is_last && fragment_mode_uses_mic(fragmenter->config.mode) ?
			 SCHC_FRAGMENT_MIC_LEN : 0;

	if (tile_len > max_payload ||
	    mic_len > max_payload || tile_len > max_payload - mic_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	uint8_t all_1 = fragment_all_1(fcn_bits);
	size_t tiles_per_window = all_1;
	size_t tile_index = fragmenter->offset / fragmenter->config.tile_size;
	size_t window = tile_index / tiles_per_window;
	size_t pos_in_window = tile_index % tiles_per_window;

	if (window >= (1u << window_bits)) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	uint8_t fcn = is_last ? all_1 : (uint8_t)(all_1 - 1u - pos_in_window);

	out[0] = fragmenter->config.rule_id;
	out[1] = fragment_control(fragmenter->config.dtag, (uint8_t)window,
				  fcn, window_bits, fcn_bits);
	memcpy(&out[header_len], &fragmenter->packet[fragmenter->offset], tile_len);
	if (mic_len != 0) {
		write_be32(&out[header_len + tile_len],
			   schc_crc32_ieee(fragmenter->packet,
					   fragmenter->packet_len));
	}
	fragmenter->offset += tile_len;

	return (int)(header_len + tile_len + mic_len);
}

int schc_fragmenter_retransmit(const struct schc_fragmenter *fragmenter,
			       const struct schc_ack *ack,
			       uint8_t *out, size_t out_len)
{
	if (fragmenter == NULL || ack == NULL || out == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (ack->complete) {
		return SCHC_ERR_DONE;
	}
	if (ack->rule_id != fragmenter->config.rule_id ||
	    ack->dtag != fragmenter->config.dtag) {
		return SCHC_ERR_UNKNOWN_RULE_ID;
	}

	uint8_t window_bits = fragment_window_bits(&fragmenter->config);
	uint8_t fcn_bits = fragment_fcn_bits(&fragmenter->config);
	int ret = validate_fragment_bits(fragmenter->config.dtag_bits,
					 window_bits, fcn_bits);

	if (ret < 0) {
		return ret;
	}
	if (ack->window >= (1u << window_bits)) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	uint8_t all_1 = fragment_all_1(fcn_bits);

	if (all_1 > 63) {
		return SCHC_ERR_NOT_SUPPORTED;
	}

	size_t tiles_per_window = all_1;
	size_t header_len = schc_fragment_header_len(&fragmenter->config);

	if (fragmenter->config.mtu < header_len ||
	    out_len < header_len + fragmenter->config.tile_size) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	for (uint8_t pos = 0; pos < ack->bitmap_bits && pos < all_1; pos++) {
		if ((ack->bitmap & (1ULL << pos)) != 0) {
			continue;
		}

		size_t tile_index = (size_t)ack->window * tiles_per_window + pos;
		size_t offset = tile_index * fragmenter->config.tile_size;

		if (offset >= fragmenter->packet_len) {
			return SCHC_ERR_DONE;
		}

		size_t remaining = fragmenter->packet_len - offset;
		size_t tile_len = remaining < fragmenter->config.tile_size ?
				  remaining : fragmenter->config.tile_size;

		if (tile_len != fragmenter->config.tile_size) {
			return SCHC_ERR_NOT_SUPPORTED;
		}

		uint8_t fcn = (uint8_t)(all_1 - 1u - pos);

		out[0] = fragmenter->config.rule_id;
		out[1] = fragment_control(fragmenter->config.dtag, ack->window,
					  fcn, window_bits, fcn_bits);
		memcpy(&out[header_len], &fragmenter->packet[offset], tile_len);
		return (int)(header_len + tile_len);
	}

	return SCHC_ERR_DONE;
}

size_t schc_ack_len(const struct schc_ack *ack)
{
	if (ack == NULL) {
		return 0;
	}

	return SCHC_ACK_BASE_LEN + ((ack->bitmap_bits + 7u) / 8u);
}

int schc_ack_encode(const struct schc_ack *ack, uint8_t *out, size_t out_len)
{
	if (ack == NULL || out == NULL || ack->bitmap_bits > 63 ||
	    ack->dtag_bits > 7 || ack->window_bits == 0 ||
	    ack->window_bits > 7 || ack->dtag_bits + ack->window_bits > 8 ||
	    validate_dtag(ack->dtag, ack->dtag_bits) < 0 ||
	    ack->window >= (1u << ack->window_bits)) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	size_t needed = schc_ack_len(ack);

	if (out_len < needed) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	out[0] = ack->rule_id;
	out[1] = (uint8_t)((ack->dtag << ack->window_bits) | ack->window);
	out[2] = ack->complete ? 1u : 0u;

	size_t bitmap_len = needed - SCHC_ACK_BASE_LEN;
	for (size_t i = 0; i < bitmap_len; i++) {
		out[SCHC_ACK_BASE_LEN + i] =
			(uint8_t)(ack->bitmap >> (8u * (bitmap_len - 1u - i)));
	}

	return (int)needed;
}

int schc_ack_decode(struct schc_ack *ack, uint8_t dtag_bits,
		    uint8_t window_bits, uint8_t bitmap_bits,
		    const uint8_t *data, size_t data_len)
{
	if (ack == NULL || data == NULL || bitmap_bits > 63 ||
	    dtag_bits > 7 || window_bits == 0 || window_bits > 7 ||
	    dtag_bits + window_bits > 8) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	if (data_len < SCHC_ACK_BASE_LEN) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_ack decoded = {
		.rule_id = data[0],
		.dtag = dtag_bits == 0 ? 0 :
			(uint8_t)(data[1] >> window_bits),
		.dtag_bits = dtag_bits,
		.window = (uint8_t)(data[1] & ((1u << window_bits) - 1u)),
		.window_bits = window_bits,
		.complete = data[2] != 0,
		.bitmap_bits = bitmap_bits,
		.bitmap = 0,
	};
	size_t needed = schc_ack_len(&decoded);

	if (data_len < needed) {
		return SCHC_ERR_TOO_SHORT;
	}
	if ((dtag_bits == 0 && decoded.dtag != 0) ||
	    (dtag_bits != 0 && decoded.dtag >= (1u << dtag_bits)) ||
	    decoded.window >= (1u << window_bits)) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	size_t bitmap_len = needed - SCHC_ACK_BASE_LEN;
	for (size_t i = 0; i < bitmap_len; i++) {
		decoded.bitmap <<= 8;
		decoded.bitmap |= data[SCHC_ACK_BASE_LEN + i];
	}

	if (bitmap_bits < 64) {
		uint64_t valid_mask = (1ULL << bitmap_bits) - 1ULL;

		decoded.bitmap &= valid_mask;
	}

	*ack = decoded;
	return (int)needed;
}

static uint8_t reassembler_window_bits(const struct schc_reassembler_config *config)
{
	return (config->window_bits != 0) ? config->window_bits :
					   SCHC_DEFAULT_WINDOW_BITS;
}

static uint8_t reassembler_fcn_bits(const struct schc_reassembler_config *config)
{
	return (config->fcn_bits != 0) ? config->fcn_bits :
					SCHC_DEFAULT_FCN_BITS;
}

size_t schc_reassembler_header_len(const struct schc_reassembler_config *config)
{
	(void)config;

	return SCHC_FRAGMENT_RULE_ID_LEN + SCHC_FRAGMENT_CONTROL_LEN;
}

int schc_reassembler_init(struct schc_reassembler *reassembler,
			  const struct schc_reassembler_config *config,
			  uint8_t *packet, size_t packet_max_len)
{
	if (reassembler == NULL || config == NULL || packet == NULL ||
	    config->tile_size == 0 || packet_max_len == 0) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	uint8_t window_bits = reassembler_window_bits(config);
	uint8_t fcn_bits = reassembler_fcn_bits(config);
	int ret = validate_fragment_bits(config->dtag_bits, window_bits,
					 fcn_bits);

	if (ret < 0) {
		return ret;
	}
	ret = validate_dtag(config->dtag, config->dtag_bits);
	if (ret < 0) {
		return ret;
	}

	reassembler->config = *config;
	reassembler->packet = packet;
	reassembler->packet_max_len = packet_max_len;
	reassembler->packet_len = 0;
	reassembler->complete = false;
	reassembler->received_tiles = 0;
	reassembler->received_tile_count = 0;
	reassembler->contiguous_tile_count = 0;
	reassembler->last_window = 0;
	return SCHC_OK;
}

int schc_reassembler_input(struct schc_reassembler *reassembler,
			   const uint8_t *fragment, size_t fragment_len,
			   bool *complete)
{
	if (reassembler == NULL || fragment == NULL || complete == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	if (reassembler->complete) {
		*complete = true;
		return (int)reassembler->packet_len;
	}

	size_t header_len = schc_reassembler_header_len(&reassembler->config);
	if (fragment_len < header_len) {
		return SCHC_ERR_TOO_SHORT;
	}

	if (fragment[0] != reassembler->config.rule_id) {
		return SCHC_ERR_UNKNOWN_RULE_ID;
	}

	uint8_t window_bits = reassembler_window_bits(&reassembler->config);
	uint8_t fcn_bits = reassembler_fcn_bits(&reassembler->config);
	int ret = validate_fragment_bits(reassembler->config.dtag_bits,
					 window_bits, fcn_bits);

	if (ret < 0) {
		return ret;
	}

	uint8_t all_1 = fragment_all_1(fcn_bits);
	uint8_t fcn_mask = all_1;
	uint8_t control = fragment[1];
	uint8_t dtag = fragment_control_dtag(control, reassembler->config.dtag_bits,
					     window_bits, fcn_bits);
	size_t window = fragment_control_window(control, window_bits, fcn_bits);
	uint8_t fcn = control & fcn_mask;
	const uint8_t *tile = &fragment[header_len];
	size_t tile_len = fragment_len - header_len;
	size_t mic_len = fcn == all_1 &&
			 fragment_mode_uses_mic(reassembler->config.mode) ?
			 SCHC_FRAGMENT_MIC_LEN : 0;

	if (dtag != reassembler->config.dtag) {
		return SCHC_ERR_UNKNOWN_RULE_ID;
	}
	if (tile_len <= mic_len) {
		return SCHC_ERR_TOO_SHORT;
	}
	tile_len -= mic_len;
	if (tile_len == 0 || tile_len > reassembler->config.tile_size) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t tiles_per_window = all_1;
	size_t offset;
	size_t tile_index;
	bool tile_copied = false;

	if (fcn == all_1) {
		if (reassembler->received_tile_count !=
		    reassembler->contiguous_tile_count) {
			*complete = false;
			return SCHC_ERR_NO_MATCHING_RULE;
		}
		tile_index = reassembler->contiguous_tile_count;
		offset = tile_index * reassembler->config.tile_size;
	} else {
		size_t pos_in_window = (size_t)(all_1 - 1u - fcn);

		tile_index = window * tiles_per_window + pos_in_window;
		offset = tile_index * reassembler->config.tile_size;
		if (tile_len != reassembler->config.tile_size) {
			return SCHC_ERR_TOO_SHORT;
		}
	}

	if (tile_index >= SCHC_FRAGMENT_MAX_TRACKED_TILES ||
	    (reassembler->config.tile_size > 0 && tile_index > reassembler->packet_max_len / reassembler->config.tile_size)) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	if (offset + tile_len > reassembler->packet_max_len) {
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
	}

	if (!tile_copied) {
		memcpy(&reassembler->packet[offset], tile, tile_len);
	}
	if ((reassembler->received_tiles & (1ULL << tile_index)) == 0) {
		reassembler->received_tiles |= 1ULL << tile_index;
		reassembler->received_tile_count++;
	}
	while (reassembler->contiguous_tile_count < SCHC_FRAGMENT_MAX_TRACKED_TILES &&
	       (reassembler->received_tiles &
		(1ULL << reassembler->contiguous_tile_count)) != 0) {
		reassembler->contiguous_tile_count++;
	}
	if (reassembler->packet_len < offset + tile_len) {
		reassembler->packet_len = offset + tile_len;
	}
	reassembler->last_window = (uint8_t)window;

	if (fcn == all_1) {
		uint64_t required = (tile_index == 63) ? UINT64_MAX :
				    ((1ULL << (tile_index + 1u)) - 1ULL);

		if ((reassembler->received_tiles & required) != required) {
			*complete = false;
			return SCHC_OK;
		}

		reassembler->complete = true;
		*complete = true;
		return (int)reassembler->packet_len;
	}

	*complete = false;
	return SCHC_OK;
}

int schc_reassembler_ack(const struct schc_reassembler *reassembler,
			 struct schc_ack *ack)
{
	if (reassembler == NULL || ack == NULL) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	uint8_t window_bits = reassembler_window_bits(&reassembler->config);
	uint8_t fcn_bits = reassembler_fcn_bits(&reassembler->config);
	int ret = validate_fragment_bits(reassembler->config.dtag_bits,
					 window_bits, fcn_bits);

	if (ret < 0) {
		return ret;
	}

	uint8_t all_1 = fragment_all_1(fcn_bits);

	if (all_1 > 63) {
		return SCHC_ERR_NOT_SUPPORTED;
	}

	uint64_t bitmap = 0;
	size_t first_tile = (size_t)reassembler->last_window * all_1;

	for (uint8_t pos = 0; pos < all_1; pos++) {
		size_t tile_index = first_tile + pos;

		if (tile_index >= SCHC_FRAGMENT_MAX_TRACKED_TILES) {
			break;
		}
		if ((reassembler->received_tiles & (1ULL << tile_index)) != 0) {
			bitmap |= 1ULL << pos;
		}
	}

	ack->rule_id = reassembler->config.rule_id;
	ack->dtag = reassembler->config.dtag;
	ack->dtag_bits = reassembler->config.dtag_bits;
	ack->window = reassembler->last_window;
	ack->window_bits = window_bits;
	ack->complete = reassembler->complete;
	ack->bitmap_bits = all_1;
	ack->bitmap = bitmap;
	return SCHC_OK;
}
