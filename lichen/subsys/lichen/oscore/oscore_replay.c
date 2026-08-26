/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file oscore_replay.c
 * @brief OSCORE replay window protection
 *
 * Implements replay window tracking for incoming OSCORE messages.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <lichen/oscore.h>
#include "oscore_internal.h"

LOG_MODULE_DECLARE(oscore, CONFIG_LICHEN_OSCORE_LOG_LEVEL);

/*
 * Replay window implementation uses a 32-bit bitmap. The configurable
 * window size must not exceed what can be tracked in uint32_t.
 * (Fixes python-ano.55)
 */
#if CONFIG_LICHEN_OSCORE_REPLAY_WINDOW > 32
#error "CONFIG_LICHEN_OSCORE_REPLAY_WINDOW exceeds 32-bit bitmap capacity"
#endif

#define OSCORE_REPLAY_PENDING_MAX \
	(CONFIG_LICHEN_OSCORE_MAX_CONTEXTS * CONFIG_LICHEN_OSCORE_REPLAY_WINDOW)

struct oscore_replay_pending {
	bool active;
	int ctx_idx;
	uint64_t seq;
};

static struct oscore_replay_pending s_replay_pending[OSCORE_REPLAY_PENDING_MAX];

/*
 * Check if sequence number would be acceptable (without updating state).
 * Returns true if acceptable, false if replay or too old.
 */
bool replay_check_acceptable(const struct oscore_ctx *ctx, uint64_t seq)
{
	uint32_t window_size = CONFIG_LICHEN_OSCORE_REPLAY_WINDOW;

	if (seq > ctx->recipient_seq) {
		/* New highest seq - always acceptable */
		return true;
	}

	/* seq <= recipient_seq: check if within window */
	uint32_t diff = ctx->recipient_seq - seq;
	if (diff >= window_size) {
		/* Too old */
		return false;
	}

	/* Check if already seen */
	uint32_t mask = 1U << diff;
	if (ctx->replay_window & mask) {
		/* Replay detected */
		return false;
	}

	return true;
}

/*
 * Reserve an acceptable sequence while authentication runs without the replay
 * mutex. The committed replay window is not advanced until authentication
 * succeeds, so forged packets cannot poison replay state.
 *
 * Caller must hold s_ctx_mutex.
 */
int replay_reserve_pending_locked(const struct oscore_ctx *ctx, int ctx_idx, uint64_t seq)
{
	int free_idx = -1;

	if (!replay_check_acceptable(ctx, seq)) {
		return OSCORE_ERR_REPLAY;
	}

	for (int i = 0; i < OSCORE_REPLAY_PENDING_MAX; i++) {
		if (!s_replay_pending[i].active) {
			if (free_idx < 0) {
				free_idx = i;
			}
			continue;
		}

		if (s_replay_pending[i].ctx_idx == ctx_idx && s_replay_pending[i].seq == seq) {
			return OSCORE_ERR_REPLAY;
		}
	}

	if (free_idx < 0) {
		return OSCORE_ERR_NO_MEMORY;
	}

	s_replay_pending[free_idx].active = true;
	s_replay_pending[free_idx].ctx_idx = ctx_idx;
	s_replay_pending[free_idx].seq = seq;
	return OSCORE_OK;
}

/*
 * Clear a pending reservation. Caller must hold s_ctx_mutex.
 */
void replay_clear_pending_locked(int ctx_idx, uint64_t seq)
{
	for (int i = 0; i < OSCORE_REPLAY_PENDING_MAX; i++) {
		if (s_replay_pending[i].active &&
		    s_replay_pending[i].ctx_idx == ctx_idx &&
		    s_replay_pending[i].seq == seq) {
			s_replay_pending[i].active = false;
			return;
		}
	}
}

/*
 * Clear all pending reservations for a context slot. Caller must hold
 * s_ctx_mutex.
 */
void replay_clear_pending_context_locked(int ctx_idx)
{
	for (int i = 0; i < OSCORE_REPLAY_PENDING_MAX; i++) {
		if (s_replay_pending[i].active && s_replay_pending[i].ctx_idx == ctx_idx) {
			s_replay_pending[i].active = false;
		}
	}
}

/*
 * Update replay window after successful decryption.
 * Must be called ONLY after decryption succeeds (caller holds mutex).
 *
 * Returns true if update succeeded, false if seq is no longer acceptable:
 * - Another thread may have advanced the window during decryption
 * - The sequence may have fallen outside the replay window
 * - The sequence may already be marked (duplicate delivery attempt)
 *
 * SECURITY: We reject sequences that fell outside the window during
 * processing, even though decryption succeeded. This is conservative
 * but necessary to avoid gaps in replay protection.
 */
bool replay_update_window(struct oscore_ctx *ctx, uint64_t seq)
{
	if (seq > ctx->recipient_seq) {
		/* New highest seq - shift window */
		uint32_t shift = seq - ctx->recipient_seq;
		if (shift >= 32) {
			ctx->replay_window = 0;
		} else {
			ctx->replay_window <<= shift;
		}
		ctx->replay_window |= 1; /* Mark current as seen */
		ctx->recipient_seq = seq;
		return true;
	}

	/* seq <= recipient_seq: check if still within window */
	uint32_t diff = ctx->recipient_seq - seq;
	if (diff >= CONFIG_LICHEN_OSCORE_REPLAY_WINDOW) {
		/*
		 * SECURITY: Seq fell outside window while we were decrypting -
		 * another thread advanced recipient_seq significantly.
		 *
		 * We REJECT this packet even though decryption succeeded.
		 * Rationale: if we cannot mark the sequence in the replay
		 * window, we cannot guarantee it wasn't already delivered.
		 * The conservative choice is to reject packets we cannot
		 * track rather than risk replay gaps.
		 *
		 * This may drop legitimate packets under extreme concurrent
		 * load, but that is preferable to gaps in replay protection.
		 */
		return false;
	}

	/* Check if already marked by another thread */
	uint32_t mask = 1U << diff;
	if (ctx->replay_window & mask) {
		return false;
	}

	/* Mark as seen */
	ctx->replay_window |= mask;
	return true;
}
