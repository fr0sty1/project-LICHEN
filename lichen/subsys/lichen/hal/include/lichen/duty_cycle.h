/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_DUTY_CYCLE_H_
#define LICHEN_DUTY_CYCLE_H_

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_DUTY_CYCLE_WINDOW_MS UINT64_C(3600000)
#define LICHEN_DUTY_CYCLE_RECORD_CAPACITY 32u
#define LICHEN_EU868_DUTY_PERMILLE 10u
#define LICHEN_US915_DUTY_PERMILLE 1000u
#define LICHEN_US915_FCC_MAX_DWELL_MS 400u

enum lichen_duty_cycle_region {
	LICHEN_DUTY_CYCLE_REGION_EU868 = 0,
	LICHEN_DUTY_CYCLE_REGION_US915 = 1,
};

struct lichen_duty_cycle_limit {
	uint16_t duty_permille;
	uint32_t max_dwell_time_ms;
	bool has_dwell_time;
};

struct lichen_duty_cycle_ctx {
	uint64_t records[LICHEN_DUTY_CYCLE_RECORD_CAPACITY];
	uint32_t durations[LICHEN_DUTY_CYCLE_RECORD_CAPACITY];
	uint8_t head;
	uint8_t len;
	uint16_t duty_permille;
	uint32_t max_dwell_time_ms;
	uint64_t last_observed_ms;
	atomic_flag lock;
	bool has_dwell_time;
	bool has_observed_time;
	bool configured;
};

/** Resolve the immutable regulatory limits for a supported region. */
int lichen_duty_cycle_limit_for_region(
	enum lichen_duty_cycle_region region,
	struct lichen_duty_cycle_limit *limit);
/** Reset and configure a tracker for a supported regulatory region. */
int lichen_duty_cycle_init_region(struct lichen_duty_cycle_ctx *ctx,
				  enum lichen_duty_cycle_region region);
/** Reset and configure a tracker with a custom rolling-window limit. */
void lichen_duty_cycle_init(struct lichen_duty_cycle_ctx *ctx,
			    uint16_t permille);
/** Record a completed transmission; rejected transmissions are never added. */
bool lichen_duty_cycle_record_tx(struct lichen_duty_cycle_ctx *ctx,
				 uint64_t timestamp_ms, uint32_t duration_ms);
/** Atomically admit and record a transmission only when the budget permits. */
bool lichen_duty_cycle_try_record_tx(struct lichen_duty_cycle_ctx *ctx,
				     uint64_t timestamp_ms,
				     uint32_t duration_ms);
/** Return remaining rolling-window airtime, or zero for invalid state. */
uint32_t lichen_duty_cycle_remaining_ms(struct lichen_duty_cycle_ctx *ctx,
					uint64_t now_ms);
/** Return observed rolling-window usage in permille. */
uint16_t lichen_duty_cycle_usage_permille(struct lichen_duty_cycle_ctx *ctx,
					  uint64_t now_ms);
/** Return the earliest possible transmit time, or UINT64_MAX on failure. */
uint64_t lichen_duty_cycle_next_tx_available_ms(
	struct lichen_duty_cycle_ctx *ctx, uint64_t now_ms, uint32_t duration_ms);
/** Check both rolling-window and per-transmission dwell limits. */
bool lichen_duty_cycle_can_transmit(struct lichen_duty_cycle_ctx *ctx,
				    uint64_t now_ms, uint32_t duration_ms);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_DUTY_CYCLE_H_ */
