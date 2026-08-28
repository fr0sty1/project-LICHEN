/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/duty_cycle.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

#ifdef CONFIG_LICHEN_DUTY_CYCLE

static uint64_t saturating_end(uint64_t start, uint32_t duration)
{
	return start > UINT64_MAX - duration ? UINT64_MAX : start + duration;
}

static uint64_t saturating_add(uint64_t left, uint64_t right)
{
	return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

static void reset_context(struct lichen_duty_cycle_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	atomic_flag_clear_explicit(&ctx->lock, memory_order_release);
}

static bool try_lock(struct lichen_duty_cycle_ctx *ctx)
{
	return !atomic_flag_test_and_set_explicit(&ctx->lock,
						 memory_order_acquire);
}

static void unlock(struct lichen_duty_cycle_ctx *ctx)
{
	atomic_flag_clear_explicit(&ctx->lock, memory_order_release);
}

static bool observe_time_locked(struct lichen_duty_cycle_ctx *ctx,
				 uint64_t now_ms)
{
	if (ctx->has_observed_time && now_ms < ctx->last_observed_ms) {
		return false;
	}
	ctx->last_observed_ms = now_ms;
	ctx->has_observed_time = true;
	return true;
}

int lichen_duty_cycle_limit_for_region(enum lichen_duty_cycle_region region,
				       struct lichen_duty_cycle_limit *limit)
{
	if (limit == NULL) {
		return -EINVAL;
	}

	struct lichen_duty_cycle_limit candidate;
	switch (region) {
	case LICHEN_DUTY_CYCLE_REGION_EU868:
		candidate = (struct lichen_duty_cycle_limit) {
			.duty_permille = LICHEN_EU868_DUTY_PERMILLE,
		};
		break;
	case LICHEN_DUTY_CYCLE_REGION_US915:
		candidate = (struct lichen_duty_cycle_limit) {
			.duty_permille = LICHEN_US915_DUTY_PERMILLE,
			.max_dwell_time_ms = LICHEN_US915_FCC_MAX_DWELL_MS,
			.has_dwell_time = true,
		};
		break;
	default:
		return -EINVAL;
	}

	*limit = candidate;
	return 0;
}

int lichen_duty_cycle_init_region(struct lichen_duty_cycle_ctx *ctx,
				  enum lichen_duty_cycle_region region)
{
	if (ctx == NULL) {
		return -EINVAL;
	}

	reset_context(ctx);
	struct lichen_duty_cycle_limit limit;
	int ret = lichen_duty_cycle_limit_for_region(region, &limit);
	if (ret < 0) {
		return ret;
	}
	ctx->duty_permille = limit.duty_permille;
	ctx->max_dwell_time_ms = limit.max_dwell_time_ms;
	ctx->has_dwell_time = limit.has_dwell_time;
	ctx->configured = true;
	return 0;
}

void lichen_duty_cycle_init(struct lichen_duty_cycle_ctx *ctx, uint16_t permille)
{
	if (ctx == NULL) {
		return;
	}
	reset_context(ctx);
	if (permille == 0u || permille > 1000u) {
		return;
	}
	ctx->duty_permille = permille;
	ctx->configured = true;
}

static void prune_locked(struct lichen_duty_cycle_ctx *ctx, uint64_t now_ms)
{
	uint64_t window_start = now_ms > LICHEN_DUTY_CYCLE_WINDOW_MS ?
		now_ms - LICHEN_DUTY_CYCLE_WINDOW_MS : 0u;
	while (ctx->len > 0u) {
		uint8_t index = ctx->head;
		if (saturating_end(ctx->records[index], ctx->durations[index]) >
		    window_start) {
			break;
		}
		ctx->head = (uint8_t)((ctx->head + 1u) %
					LICHEN_DUTY_CYCLE_RECORD_CAPACITY);
		ctx->len--;
	}
}

static uint32_t total_tx(const struct lichen_duty_cycle_ctx *ctx,
			 uint64_t now_ms)
{
	uint64_t window_start = now_ms > LICHEN_DUTY_CYCLE_WINDOW_MS ?
		now_ms - LICHEN_DUTY_CYCLE_WINDOW_MS : 0u;
	uint32_t total = 0u;
	for (uint8_t i = 0u; i < ctx->len; i++) {
		uint8_t index = (uint8_t)((ctx->head + i) %
					  LICHEN_DUTY_CYCLE_RECORD_CAPACITY);
		uint64_t start = ctx->records[index];
		uint32_t duration = ctx->durations[index];
		uint64_t end = saturating_end(start, duration);
		uint32_t overlap = 0u;
		if (start >= window_start) {
			overlap = duration;
		} else if (end > window_start) {
			uint64_t partial = end - window_start;
			overlap = partial > UINT32_MAX ? UINT32_MAX :
				  (uint32_t)partial;
		}
		total = total > UINT32_MAX - overlap ? UINT32_MAX :
			total + overlap;
	}
	return total;
}

static uint32_t max_tx_ms(const struct lichen_duty_cycle_ctx *ctx)
{
	return (uint32_t)((LICHEN_DUTY_CYCLE_WINDOW_MS / 1000u) *
			  ctx->duty_permille);
}

bool lichen_duty_cycle_record_tx(struct lichen_duty_cycle_ctx *ctx,
				 uint64_t timestamp_ms, uint32_t duration_ms)
{
	if (ctx == NULL || !ctx->configured || duration_ms == 0u ||
	    !try_lock(ctx)) {
		return false;
	}
	if (!observe_time_locked(ctx, timestamp_ms)) {
		unlock(ctx);
		return false;
	}
	prune_locked(ctx, timestamp_ms);
	if (ctx->len == LICHEN_DUTY_CYCLE_RECORD_CAPACITY) {
		unlock(ctx);
		return false;
	}
	uint8_t index = (uint8_t)((ctx->head + ctx->len) %
				  LICHEN_DUTY_CYCLE_RECORD_CAPACITY);
	ctx->records[index] = timestamp_ms;
	ctx->durations[index] = duration_ms;
	ctx->len++;
	unlock(ctx);
	return true;
}

bool lichen_duty_cycle_try_record_tx(struct lichen_duty_cycle_ctx *ctx,
				     uint64_t timestamp_ms,
				     uint32_t duration_ms)
{
	if (ctx == NULL || !ctx->configured || duration_ms == 0u ||
	    !try_lock(ctx)) {
		return false;
	}
	if (!observe_time_locked(ctx, timestamp_ms)) {
		unlock(ctx);
		return false;
	}
	prune_locked(ctx, timestamp_ms);
	uint32_t maximum = max_tx_ms(ctx);
	uint32_t used = total_tx(ctx, timestamp_ms);
	if ((ctx->has_dwell_time && duration_ms > ctx->max_dwell_time_ms) ||
	    duration_ms > maximum ||
	    (uint64_t)used + duration_ms > maximum ||
	    ctx->len == LICHEN_DUTY_CYCLE_RECORD_CAPACITY) {
		unlock(ctx);
		return false;
	}

	uint8_t index = (uint8_t)((ctx->head + ctx->len) %
				  LICHEN_DUTY_CYCLE_RECORD_CAPACITY);
	ctx->records[index] = timestamp_ms;
	ctx->durations[index] = duration_ms;
	ctx->len++;
	unlock(ctx);
	return true;
}

uint32_t lichen_duty_cycle_remaining_ms(struct lichen_duty_cycle_ctx *ctx,
					uint64_t now_ms)
{
	if (ctx == NULL || !ctx->configured || !try_lock(ctx)) {
		return 0u;
	}
	if (!observe_time_locked(ctx, now_ms)) {
		unlock(ctx);
		return 0u;
	}
	prune_locked(ctx, now_ms);
	uint32_t maximum = max_tx_ms(ctx);
	uint32_t used = total_tx(ctx, now_ms);
	uint32_t remaining = maximum > used ? maximum - used : 0u;
	unlock(ctx);
	return remaining;
}

uint16_t lichen_duty_cycle_usage_permille(struct lichen_duty_cycle_ctx *ctx,
					  uint64_t now_ms)
{
	if (ctx == NULL || !ctx->configured) {
		return 0u;
	}
	if (!try_lock(ctx)) {
		return UINT16_MAX;
	}
	if (!observe_time_locked(ctx, now_ms)) {
		unlock(ctx);
		return UINT16_MAX;
	}
	prune_locked(ctx, now_ms);
	uint64_t usage = (uint64_t)total_tx(ctx, now_ms) * 1000u /
			 LICHEN_DUTY_CYCLE_WINDOW_MS;
	uint16_t result = usage > UINT16_MAX ? UINT16_MAX : (uint16_t)usage;
	unlock(ctx);
	return result;
}

uint64_t lichen_duty_cycle_next_tx_available_ms(
	struct lichen_duty_cycle_ctx *ctx, uint64_t now_ms, uint32_t duration_ms)
{
	if (ctx == NULL || !ctx->configured || duration_ms == 0u ||
	    !try_lock(ctx)) {
		return UINT64_MAX;
	}
	if (!observe_time_locked(ctx, now_ms) ||
	    (ctx->has_dwell_time && duration_ms > ctx->max_dwell_time_ms)) {
		unlock(ctx);
		return UINT64_MAX;
	}
	prune_locked(ctx, now_ms);
	uint32_t maximum = max_tx_ms(ctx);
	uint32_t used = total_tx(ctx, now_ms);
	if ((uint64_t)used + duration_ms <= maximum) {
		unlock(ctx);
		return now_ms;
	}
	if (duration_ms > maximum) {
		unlock(ctx);
		return UINT64_MAX;
	}

	uint32_t needed = (uint32_t)((uint64_t)used + duration_ms - maximum);
	uint32_t freed = 0u;
	for (uint8_t i = 0u; i < ctx->len; i++) {
		uint8_t index = (uint8_t)((ctx->head + i) %
					  LICHEN_DUTY_CYCLE_RECORD_CAPACITY);
		freed = freed > UINT32_MAX - ctx->durations[index] ? UINT32_MAX :
			freed + ctx->durations[index];
		if (freed >= needed) {
			uint64_t available = saturating_add(
				saturating_end(ctx->records[index],
					       ctx->durations[index]),
				LICHEN_DUTY_CYCLE_WINDOW_MS);
			unlock(ctx);
			return available;
		}
	}
	unlock(ctx);
	return UINT64_MAX;
}

bool lichen_duty_cycle_can_transmit(struct lichen_duty_cycle_ctx *ctx,
				    uint64_t now_ms, uint32_t duration_ms)
{
	if (ctx == NULL || !ctx->configured || duration_ms == 0u ||
	    !try_lock(ctx)) {
		return false;
	}
	if (!observe_time_locked(ctx, now_ms) ||
	    (ctx->has_dwell_time && duration_ms > ctx->max_dwell_time_ms)) {
		unlock(ctx);
		return false;
	}
	prune_locked(ctx, now_ms);
	uint32_t maximum = max_tx_ms(ctx);
	uint32_t used = total_tx(ctx, now_ms);
	bool allowed = duration_ms <= maximum &&
		       (uint64_t)used + duration_ms <= maximum;
	unlock(ctx);
	return allowed;
}

#endif /* CONFIG_LICHEN_DUTY_CYCLE */
