/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <schc/schc.h>

#include <stdbool.h>
#include <string.h>

#define SCHC_DEFAULT_WINDOW_BITS 2
#define SCHC_DEFAULT_FCN_BITS 6
#define SCHC_FRAGMENT_RULE_ID_LEN 1
#define SCHC_FRAGMENT_CONTROL_LEN 1

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

static uint8_t fragment_all_1(uint8_t fcn_bits)
{
	return (uint8_t)((1u << fcn_bits) - 1u);
}

static int validate_fragment_bits(uint8_t window_bits, uint8_t fcn_bits)
{
	if (window_bits == 0 || window_bits > 7 ||
	    fcn_bits == 0 || fcn_bits > 7 ||
	    window_bits + fcn_bits > 8) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	return SCHC_OK;
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

	int ret = validate_fragment_bits(window_bits, fcn_bits);
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
	if (tile_len > max_payload) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	size_t remaining = fragmenter->packet_len - fragmenter->offset;
	bool is_last = remaining <= tile_len;
	if (is_last) {
		tile_len = remaining;
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
	out[1] = (uint8_t)((window << fcn_bits) | fcn);
	memcpy(&out[header_len], &fragmenter->packet[fragmenter->offset], tile_len);
	fragmenter->offset += tile_len;

	return (int)(header_len + tile_len);
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
	int ret = validate_fragment_bits(window_bits, fcn_bits);

	if (ret < 0) {
		return ret;
	}

	reassembler->config = *config;
	reassembler->packet = packet;
	reassembler->packet_max_len = packet_max_len;
	reassembler->packet_len = 0;
	reassembler->complete = false;
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
	int ret = validate_fragment_bits(window_bits, fcn_bits);

	if (ret < 0) {
		return ret;
	}

	uint8_t all_1 = fragment_all_1(fcn_bits);
	uint8_t fcn_mask = all_1;
	uint8_t control = fragment[1];
	size_t window = control >> fcn_bits;
	uint8_t fcn = control & fcn_mask;
	const uint8_t *tile = &fragment[header_len];
	size_t tile_len = fragment_len - header_len;

	if (tile_len == 0 || tile_len > reassembler->config.tile_size) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t tiles_per_window = all_1;
	size_t offset;

	if (fcn == all_1) {
		offset = reassembler->packet_len;
	} else {
		size_t pos_in_window = (size_t)(all_1 - 1u - fcn);
		size_t tile_index = window * tiles_per_window + pos_in_window;

		offset = tile_index * reassembler->config.tile_size;
		if (tile_len != reassembler->config.tile_size) {
			return SCHC_ERR_TOO_SHORT;
		}
		if (offset != reassembler->packet_len) {
			return SCHC_ERR_NO_MATCHING_RULE;
		}
	}

	if (offset + tile_len > reassembler->packet_max_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	memcpy(&reassembler->packet[offset], tile, tile_len);
	reassembler->packet_len = offset + tile_len;

	if (fcn == all_1) {
		reassembler->complete = true;
		*complete = true;
		return (int)reassembler->packet_len;
	}

	*complete = false;
	return SCHC_OK;
}
