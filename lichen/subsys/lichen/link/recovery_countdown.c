/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file recovery_countdown.c
 * @brief CCP desync recovery countdown timers (spec §2a.6, CCP-13a)
 *
 * Implements recovery countdown timers for T_DRIFT_MAX and T_GIVE_UP using
 * Zephyr hardware timers (k_timer).
 */

#include <lichen/recovery_countdown.h>
#include <lichen/errno.h>

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lichen_recovery_countdown, CONFIG_LICHEN_LINK_LOG_LEVEL);
#else
#include <stdio.h>
#define LOG_DBG(...) ((void)0)
#define LOG_INF(...) ((void)0)
#define LOG_WRN(...) ((void)0)
#define LOG_ERR(...) ((void)0)
#endif

/* Superframe duration in milliseconds for timer calculation */
#ifndef LICHEN_SUPERFRAME_MS
#define LICHEN_SUPERFRAME_MS (LICHEN_TDMA_SLOT_MS * 8)
#endif

#ifdef __ZEPHYR__

/**
 * @brief Drift timer expiration handler
 *
 * Called from timer context when T_DRIFT_MAX expires.
 */
static void drift_timer_handler(struct k_timer *timer)
{
	struct lichen_recovery_countdown *ctx =
		CONTAINER_OF(timer, struct lichen_recovery_countdown, drift_timer);

	if (ctx == NULL) {
		return;
	}

	LOG_INF("T_DRIFT_MAX expired after %u superframes", ctx->drift_count);

	ctx->in_drift = false;
	ctx->drift_count = ctx->drift_max_threshold;

	if (ctx->on_drift_max != NULL) {
		ctx->on_drift_max(ctx->user_data);
	}
}

/**
 * @brief Recover timer expiration handler
 *
 * Called from timer context when T_GIVE_UP expires.
 */
static void recover_timer_handler(struct k_timer *timer)
{
	struct lichen_recovery_countdown *ctx =
		CONTAINER_OF(timer, struct lichen_recovery_countdown, recover_timer);

	if (ctx == NULL) {
		return;
	}

	LOG_WRN("T_GIVE_UP expired after %u superframes - abandoning recovery",
		ctx->recover_count);

	ctx->in_recover = false;
	ctx->recover_count = ctx->give_up_threshold;

	if (ctx->on_give_up != NULL) {
		ctx->on_give_up(ctx->user_data);
	}
}

#endif /* __ZEPHYR__ */

int lichen_recovery_countdown_init(struct lichen_recovery_countdown *ctx,
				   uint16_t drift_max_sf,
				   uint16_t give_up_sf,
				   lichen_recovery_cb_t on_drift_max,
				   lichen_recovery_cb_t on_give_up,
				   void *user_data)
{
	if (ctx == NULL) {
		return -EINVAL;
	}

	ctx->drift_max_threshold = drift_max_sf;
	ctx->give_up_threshold = give_up_sf;
	ctx->drift_count = 0;
	ctx->recover_count = 0;
	ctx->in_drift = false;
	ctx->in_recover = false;
	ctx->on_drift_max = on_drift_max;
	ctx->on_give_up = on_give_up;
	ctx->user_data = user_data;

#ifdef __ZEPHYR__
	k_timer_init(&ctx->drift_timer, drift_timer_handler, NULL);
	k_timer_init(&ctx->recover_timer, recover_timer_handler, NULL);
#endif

	LOG_DBG("Recovery countdown initialized: drift_max=%u, give_up=%u superframes",
		drift_max_sf, give_up_sf);

	return 0;
}

int lichen_recovery_countdown_init_default(struct lichen_recovery_countdown *ctx,
					   lichen_recovery_cb_t on_drift_max,
					   lichen_recovery_cb_t on_give_up,
					   void *user_data)
{
	return lichen_recovery_countdown_init(ctx,
					      LICHEN_T_DRIFT_MAX_SUPERFRAMES,
					      LICHEN_T_GIVE_UP_SUPERFRAMES,
					      on_drift_max,
					      on_give_up,
					      user_data);
}

int lichen_recovery_countdown_enter_drift(struct lichen_recovery_countdown *ctx)
{
	if (ctx == NULL) {
		return -EINVAL;
	}

#ifdef __ZEPHYR__
	/* Stop any existing timers */
	k_timer_stop(&ctx->drift_timer);
	k_timer_stop(&ctx->recover_timer);
#endif

	ctx->drift_count = 0;
	ctx->recover_count = 0;
	ctx->in_drift = true;
	ctx->in_recover = false;

#ifdef __ZEPHYR__
	/* Start hardware timer for T_DRIFT_MAX */
	uint32_t timeout_ms = (uint32_t)ctx->drift_max_threshold * LICHEN_SUPERFRAME_MS;
	k_timer_start(&ctx->drift_timer, K_MSEC(timeout_ms), K_NO_WAIT);
	LOG_INF("Entered DRIFT state, T_DRIFT_MAX timer started (%u ms)", timeout_ms);
#endif

	return 0;
}

int lichen_recovery_countdown_enter_recover(struct lichen_recovery_countdown *ctx)
{
	if (ctx == NULL) {
		return -EINVAL;
	}

#ifdef __ZEPHYR__
	/* Stop drift timer */
	k_timer_stop(&ctx->drift_timer);
	k_timer_stop(&ctx->recover_timer);
#endif

	ctx->drift_count = 0;
	ctx->recover_count = 0;
	ctx->in_drift = false;
	ctx->in_recover = true;

#ifdef __ZEPHYR__
	/* Start hardware timer for T_GIVE_UP */
	uint32_t timeout_ms = (uint32_t)ctx->give_up_threshold * LICHEN_SUPERFRAME_MS;
	k_timer_start(&ctx->recover_timer, K_MSEC(timeout_ms), K_NO_WAIT);
	LOG_INF("Entered RECOVER state, T_GIVE_UP timer started (%u ms)", timeout_ms);
#endif

	return 0;
}

int lichen_recovery_countdown_reset(struct lichen_recovery_countdown *ctx)
{
	if (ctx == NULL) {
		return -EINVAL;
	}

#ifdef __ZEPHYR__
	k_timer_stop(&ctx->drift_timer);
	k_timer_stop(&ctx->recover_timer);
#endif

	ctx->drift_count = 0;
	ctx->recover_count = 0;
	ctx->in_drift = false;
	ctx->in_recover = false;

	LOG_DBG("Recovery countdown reset");

	return 0;
}

bool lichen_recovery_countdown_tick_drift(struct lichen_recovery_countdown *ctx)
{
	if (ctx == NULL || !ctx->in_drift) {
		return false;
	}

	ctx->drift_count++;

	if (ctx->drift_count >= ctx->drift_max_threshold) {
		LOG_INF("T_DRIFT_MAX expired (tick-based) after %u superframes",
			ctx->drift_count);
		ctx->in_drift = false;

		if (ctx->on_drift_max != NULL) {
			ctx->on_drift_max(ctx->user_data);
		}

		return true;
	}

	return false;
}

bool lichen_recovery_countdown_tick_recover(struct lichen_recovery_countdown *ctx)
{
	if (ctx == NULL || !ctx->in_recover) {
		return false;
	}

	ctx->recover_count++;

	if (ctx->recover_count >= ctx->give_up_threshold) {
		LOG_WRN("T_GIVE_UP expired (tick-based) after %u superframes",
			ctx->recover_count);
		ctx->in_recover = false;

		if (ctx->on_give_up != NULL) {
			ctx->on_give_up(ctx->user_data);
		}

		return true;
	}

	return false;
}

uint16_t lichen_recovery_countdown_drift_remaining(
	const struct lichen_recovery_countdown *ctx)
{
	if (ctx == NULL || !ctx->in_drift) {
		return 0;
	}

	if (ctx->drift_count >= ctx->drift_max_threshold) {
		return 0;
	}

	return ctx->drift_max_threshold - ctx->drift_count;
}

uint16_t lichen_recovery_countdown_recover_remaining(
	const struct lichen_recovery_countdown *ctx)
{
	if (ctx == NULL || !ctx->in_recover) {
		return 0;
	}

	if (ctx->recover_count >= ctx->give_up_threshold) {
		return 0;
	}

	return ctx->give_up_threshold - ctx->recover_count;
}

bool lichen_recovery_countdown_is_drifting(
	const struct lichen_recovery_countdown *ctx)
{
	if (ctx == NULL) {
		return false;
	}

	return ctx->in_drift;
}

bool lichen_recovery_countdown_is_recovering(
	const struct lichen_recovery_countdown *ctx)
{
	if (ctx == NULL) {
		return false;
	}

	return ctx->in_recover;
}
