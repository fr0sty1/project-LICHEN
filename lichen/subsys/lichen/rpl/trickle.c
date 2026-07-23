/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file trickle.c
 * @brief Trickle timer (RFC 6206) implementation matching pseudocode in §4.2.
 *
 * Reset guard aligned for cross-impl determinism (project-LICHEN-vsph).
 * Used by lichen_rpl_dodag for DIO pacing per LICHEN RPL profile.
 */

#include <lichen/rpl_trickle.h>
#include <stddef.h>

/* Saturating add - clamp at UINT32_MAX on overflow */
static uint32_t sat_add_u32(uint32_t a, uint32_t b)
{
	uint32_t result = a + b;
	/* Overflow if result < either operand */
	return (result < a) ? UINT32_MAX : result;
}

/* Saturating multiply - clamp at UINT32_MAX on overflow */
static uint32_t sat_mul_u32(uint32_t a, uint32_t b)
{
	uint64_t result = (uint64_t)a * b;
	return result > UINT32_MAX ? UINT32_MAX : (uint32_t)result;
}

/* Internal: begin a new interval (RFC 6206 §4.1: t uniform in [I/2, I)) */
static void begin_interval(struct lichen_trickle *t,
			   uint32_t now,
			   uint32_t rand_offset)
{
	t->interval_start = now;
	t->counter = 0;
	t->transmitted = false;

	/* Per RFC 6206 §4.2: t uniform in [I/2, I). Use (interval+1)/2 to avoid
	 * off-by-one bias (Worker23/project-LICHEN-verh); shift form avoids
	 * u32 overflow at saturated UINT32_MAX (project-LICHEN-jufb merge-conflict). */
	uint32_t half = (t->interval >> 1) + (t->interval & 1u);
	uint32_t range = t->interval - half;
	uint32_t offset = (range > 0) ? (rand_offset % range) : 0;
	t->transmit_time = sat_add_u32(sat_add_u32(now, half), offset);
}

void lichen_trickle_init(struct lichen_trickle *t,
			 uint32_t imin_ms,
			 uint32_t imax_doublings,
			 uint32_t k)
{
	if (t == NULL) {
		return;
	}
	if (imin_ms == 0) {
		imin_ms = 1;
	}
	t->imin = imin_ms;

	if (imax_doublings == 0) {
		t->max_interval = imin_ms;
	} else if (imax_doublings >= 32 ||
		   (imin_ms >> (32 - imax_doublings)) > 0) {
		t->max_interval = UINT32_MAX;
	} else {
		t->max_interval = imin_ms << imax_doublings;
	}

	t->k = k;
	t->interval = 0;
	t->counter = 0;
	t->interval_start = 0;
	t->transmit_time = 0;
	t->transmitted = false;
}

void lichen_trickle_start(struct lichen_trickle *t,
			  uint32_t now,
			  uint32_t rand_offset)
{
	if (t == NULL) {
		return;
	}
	t->interval = t->imin;
	begin_interval(t, now, rand_offset);
}

bool lichen_trickle_fire_transmit(struct lichen_trickle *t)
{
	if (t == NULL) {
		return false;
	}
	t->transmitted = true;
	return lichen_trickle_should_transmit(t);
}

void lichen_trickle_expire(struct lichen_trickle *t,
			   uint32_t now,
			   uint32_t rand_offset)
{
	if (t == NULL) {
		return;
	}
	uint32_t doubled = sat_mul_u32(t->interval, 2);
	t->interval = (doubled < t->max_interval) ? doubled : t->max_interval;
	begin_interval(t, now, rand_offset);
}
void lichen_trickle_reset(struct lichen_trickle *t,
			  uint32_t now,
			  uint32_t rand_offset)
{
	if (t == NULL) {
		return;
	}
	/* interval == 0 is sentinel for "not yet started" (set in init).
	 * Matches Rust/Python proxies for cross-impl determinism on
	 * edge cases (time=0, init, u32 wrap). See rpl_trickle.h. */
	if (t->interval == 0 || t->interval > t->imin) {
		t->interval = t->imin;
		begin_interval(t, now, rand_offset);
	}
}


void lichen_trickle_next_event(const struct lichen_trickle *t,
			       struct lichen_trickle_event *out)
{
	if (t == NULL || out == NULL) {
		return;
	}
	if (!t->transmitted) {
		out->type = LICHEN_TRICKLE_TRANSMIT;
		out->at_ms = t->transmit_time;
	} else {
		out->type = LICHEN_TRICKLE_EXPIRE;
		out->at_ms = lichen_trickle_interval_end(t);
	}
}
