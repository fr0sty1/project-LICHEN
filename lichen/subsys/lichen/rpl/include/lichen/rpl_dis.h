/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/rpl_dis.h
 * @brief Authenticated DIS solicitation admission (RFC 6550 Section 8.3)
 */

#ifndef LICHEN_RPL_DIS_H_
#define LICHEN_RPL_DIS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/rpl_messages.h>
#include <lichen/rpl_trickle.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Action selected for an admitted DIS. */
enum lichen_rpl_dis_action {
	/** Reject or ignore without producing traffic. */
	LICHEN_RPL_DIS_IGNORE = 0,
	/** Matching multicast solicitation reset the DIO Trickle timer. */
	LICHEN_RPL_DIS_RESET_TRICKLE = 1,
	/** Matching unicast solicitation requests a configured unicast DIO. */
	LICHEN_RPL_DIS_UNICAST_DIO_WITH_CONFIG = 2,
	/** An equivalent admitted request was already acted on in this window. */
	LICHEN_RPL_DIS_COALESCED = 3,
	/** Another peer already consumed the bounded unicast response window. */
	LICHEN_RPL_DIS_RATE_LIMITED = 4,
};

/** Local DODAG values evaluated by Solicited Information predicates. */
struct lichen_rpl_dis_context {
	uint8_t rpl_instance_id;
	uint8_t dodag_id[16];
	uint8_t version;
};

/**
 * Bounded per-DODAG solicitation state.
 *
 * No allocation or peer table is required. Multicast resets share one window;
 * unicast replies share another, while repeated requests by the selected peer
 * are explicitly coalesced.
 */
struct lichen_rpl_dis_handler {
	uint32_t response_interval_ms;
	uint32_t multicast_not_before;
	uint32_t unicast_not_before;
	uint8_t unicast_peer[16];
	bool multicast_window_active;
	bool unicast_window_active;
	bool initialized;
};

/**
 * Initialize solicitation rate limiting.
 *
 * @param response_interval_ms Minimum interval between equivalent actions.
 *        Must be in [1, INT32_MAX] for wrap-safe 32-bit clock comparison.
 */
int lichen_rpl_dis_handler_init(
	struct lichen_rpl_dis_handler *_Nullable handler,
	uint32_t response_interval_ms);

/**
 * Admit and handle one DIS after link verification.
 *
 * @param authenticated Link signature verification succeeded.
 * @param replay_admitted Link replay protection admitted this exact frame.
 * @param destination_is_multicast Whether the received IPv6 destination was
 *        multicast. Matching multicast requests reset Trickle; matching
 *        unicast requests return UNICAST_DIO_WITH_CONFIG.
 * @param sender_addr Authenticated sender IPv6 address (16 bytes).
 * @param rand_offset Caller-provided Trickle offset used only for a reset.
 *
 * Unauthenticated or replay-rejected messages are silently ignored before
 * parsing. Authenticated malformed messages return a negative LICHEN_RPL_ERR_*
 * value. The handler and Trickle state are unchanged on every ignored,
 * coalesced, rate-limited, or error result. Solicited Information predicates
 * scope a request to the supplied context; an absent option or no enabled
 * predicates is a wildcard.
 */
int lichen_rpl_dis_handle(
	struct lichen_rpl_dis_handler *_Nullable handler,
	const uint8_t *_Nullable wire, size_t wire_len,
	bool destination_is_multicast,
	const struct lichen_rpl_dis_context *_Nullable context,
	const uint8_t *_Nullable sender_addr,
	bool authenticated, bool replay_admitted,
	struct lichen_trickle *_Nullable trickle,
	uint32_t now, uint32_t rand_offset);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_DIS_H_ */
