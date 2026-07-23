/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file trickle.c
 * @brief Trickle timer (RFC 6206) implementation
 *
 * Ported from rust/lichen-rpl/src/trickle.rs
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

/* Internal: begin a new interval */
static void begin_interval(struct lichen_trickle *t,
			   uint32_t now,
			   uint32_t rand_offset)
{
	t->interval_start = now;
	t->counter = 0;
	t->transmitted = false;

	uint32_t half = t->interval / 2;
	/* transmit_time is uniform in [now + half, now + interval) */
	uint32_t offset = (half > 0) ? (rand_offset % half) : 0;
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

	/* Trickle Imin must be > 0 (RFC 6206); 0 causes infinite busy-loop
	 * on transmit/expire (see bead project-LICHEN-p00p). Defensive default. */
	if (imin_ms == 0) {
		imin_ms = 1;
	}
	t->imin = imin_ms;

	/* Calculate max_interval = imin << doublings, clamped at UINT32_MAX.
	 * Overflow occurs if any of the top `doublings` bits are set in imin,
	 * since those bits would be shifted out. Check before shifting.
	 * Special case: doublings=0 means no shift, so no overflow possible. */
	if (imax_doublings == 0) {
		t->max_interval = imin_ms;
	} else if (imax_doublings >= 32 ||
		   (imin_ms >> (32 - imax_doublings)) > 0) {
		t->max_interval = UINT32_MAX;
	} else {
		t->max_interval = imin_ms << imax_doublings;
	}

	t->k = k;
	t->interval = imin_ms;
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

	/* Double interval, capped at max_interval */
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

	/* RFC 6206 §4.2: no-op if already at imin *and running*.
	 * transmit_time==0 proxies for Stopped state (see Rust TrickleState,
	 * worker1 version, and reset_from_stopped_starts_timer test). */
	if (t->transmit_time == 0 || t->interval != t->imin) {
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
