/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/** @file rpl_dis.c Authenticated DIS solicitation admission. */

#include <lichen/rpl_dis.h>

#include <limits.h>
#include <stddef.h>
#include <string.h>

static bool before_deadline(uint32_t now, uint32_t deadline)
{
	return !lichen_trickle_time_reached(now, deadline);
}

static bool solicited_matches(const struct lichen_rpl_solicited_info *info,
			      const struct lichen_rpl_dis_context *context)
{
	return ((info->flags & LICHEN_RPL_SOLICITED_INSTANCE_PREDICATE) == 0U ||
		info->rpl_instance_id == context->rpl_instance_id) &&
	       ((info->flags & LICHEN_RPL_SOLICITED_DODAG_PREDICATE) == 0U ||
		memcmp(info->dodag_id, context->dodag_id,
		       sizeof(info->dodag_id)) == 0) &&
	       ((info->flags & LICHEN_RPL_SOLICITED_VERSION_PREDICATE) == 0U ||
		info->version == context->version);
}

static int find_solicited_information(
	const uint8_t *wire, size_t wire_len,
	struct lichen_rpl_solicited_info *info, bool *present)
{
	struct lichen_rpl_opt_iter it;
	struct lichen_rpl_raw_opt option;
	const uint8_t *options = lichen_rpl_dis_options(wire, wire_len);
	size_t options_len = wire_len > LICHEN_RPL_DIS_BASE_LEN ?
		wire_len - LICHEN_RPL_DIS_BASE_LEN : 0U;
	int ret;

	*present = false;
	lichen_rpl_opt_iter_init(&it, options, options_len);
	while ((ret = lichen_rpl_opt_iter_next(&it, &option)) == LICHEN_RPL_OK) {
		if (option.opt_type != LICHEN_RPL_OPT_SOLICITED_INFO) {
			continue;
		}
		ret = lichen_rpl_solicited_info_parse(info, option.data,
						       option.data_len);
		if (ret != LICHEN_RPL_OK) {
			return ret;
		}
		*present = true;
	}
	return ret == 1 ? LICHEN_RPL_OK : ret;
}

int lichen_rpl_dis_handler_init(struct lichen_rpl_dis_handler *handler,
				uint32_t response_interval_ms)
{
	if (handler == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (response_interval_ms == 0U || response_interval_ms > INT32_MAX) {
		return LICHEN_RPL_ERR_INVALID;
	}

	memset(handler, 0, sizeof(*handler));
	handler->response_interval_ms = response_interval_ms;
	handler->initialized = true;
	return LICHEN_RPL_OK;
}

int lichen_rpl_dis_handle(
	struct lichen_rpl_dis_handler *handler,
	const uint8_t *wire, size_t wire_len,
	bool destination_is_multicast,
	const struct lichen_rpl_dis_context *context,
	const uint8_t *sender_addr,
	bool authenticated, bool replay_admitted,
	struct lichen_trickle *trickle,
	uint32_t now, uint32_t rand_offset)
{
	struct lichen_rpl_solicited_info solicited;
	struct lichen_rpl_dis parsed;
	bool have_solicited;
	int ret;

	if (handler == NULL || wire == NULL || context == NULL ||
	    sender_addr == NULL || trickle == NULL || !handler->initialized) {
		return LICHEN_RPL_ERR_INVALID;
	}
	/* Authentication and replay admission are prerequisite link-layer gates.
	 * Fail silently and do not expose parse results for rejected traffic. */
	if (!authenticated || !replay_admitted) {
		return LICHEN_RPL_DIS_IGNORE;
	}

	ret = lichen_rpl_dis_parse(&parsed, wire, wire_len);
	if (ret != LICHEN_RPL_OK) {
		return ret;
	}
	ret = find_solicited_information(wire, wire_len, &solicited,
					 &have_solicited);
	if (ret != LICHEN_RPL_OK) {
		return ret;
	}
	if (have_solicited && !solicited_matches(&solicited, context)) {
		return LICHEN_RPL_DIS_IGNORE;
	}

	if (destination_is_multicast) {
		if (handler->multicast_window_active &&
		    before_deadline(now, handler->multicast_not_before)) {
			return LICHEN_RPL_DIS_COALESCED;
		}

		struct lichen_trickle staged_trickle = *trickle;
		struct lichen_rpl_dis_handler staged_handler = *handler;
		if (!lichen_trickle_reset(&staged_trickle, now, rand_offset)) {
			return LICHEN_RPL_ERR_INVALID;
		}
		staged_handler.multicast_window_active = true;
		staged_handler.multicast_not_before =
			now + staged_handler.response_interval_ms;
		*trickle = staged_trickle;
		*handler = staged_handler;
		return LICHEN_RPL_DIS_RESET_TRICKLE;
	}

	if (handler->unicast_window_active &&
	    before_deadline(now, handler->unicast_not_before)) {
		return memcmp(handler->unicast_peer, sender_addr,
			      sizeof(handler->unicast_peer)) == 0 ?
			LICHEN_RPL_DIS_COALESCED : LICHEN_RPL_DIS_RATE_LIMITED;
	}

	struct lichen_rpl_dis_handler staged_handler = *handler;
	staged_handler.unicast_window_active = true;
	staged_handler.unicast_not_before = now + staged_handler.response_interval_ms;
	memcpy(staged_handler.unicast_peer, sender_addr,
	       sizeof(staged_handler.unicast_peer));
	*handler = staged_handler;
	return LICHEN_RPL_DIS_UNICAST_DIO_WITH_CONFIG;
}
