/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file trickle.c
 * @brief Trickle timer (RFC 6206) implementation
 *
 * Absolute deadlines deliberately use uint32_t modular arithmetic to match
 * Zephyr's k_uptime_get_32().
 */

#include <lichen/rpl_trickle.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

/* Internal: begin a new interval (RFC 6206 §4.1: t uniform in [I/2, I)) */
static bool begin_interval(struct lichen_trickle *t, uint32_t interval,
			   uint32_t now, uint32_t rand_offset)
{
	/* ceil(I/2) is the first representable millisecond in [I/2, I). */
	uint32_t half = (interval >> 1) + (interval & 1u);
	uint32_t range = interval - half;

	if (!t->initialized || range == 0 || rand_offset >= range) {
		return false;
	}

	t->interval = interval;
	t->interval_start = now;
	t->counter = 0;
	t->active = true;
	t->transmitted = false;
	t->transmit_time = now + half + rand_offset;
	return true;
}

int lichen_trickle_init(struct lichen_trickle *t, uint32_t imin_ms,
			uint32_t imax_doublings, uint32_t k)
{
	uint64_t max_interval;

	if (t == NULL) {
		return -EINVAL;
	}
	memset(t, 0, sizeof(*t));
	if (imin_ms < 2 || k == 0) {
		return -EINVAL;
	}
	if (imax_doublings >= 32) {
		return -ERANGE;
	}
	max_interval = (uint64_t)imin_ms << imax_doublings;
	/* Signed-difference deadline ordering requires delays <= INT32_MAX. */
	if (max_interval > INT32_MAX) {
		return -ERANGE;
	}

	t->imin = imin_ms;
	t->max_interval = (uint32_t)max_interval;

	t->k = k;
	t->initialized = true;
	return 0;
}

bool lichen_trickle_start(struct lichen_trickle *t, uint32_t now,
			 uint32_t rand_offset)
{
	if (t == NULL) {
		return false;
	}
	return begin_interval(t, t->imin, now, rand_offset);
}

bool lichen_trickle_fire_transmit(struct lichen_trickle *t)
{
	if (t == NULL || !t->active || t->transmitted) {
		return false;
	}
	bool send = lichen_trickle_should_transmit(t);
	t->transmitted = true;
	return send;
}

bool lichen_trickle_expire(struct lichen_trickle *t, uint32_t now,
			  uint32_t rand_offset)
{
	uint32_t next;

	if (t == NULL || !t->active || !t->transmitted) {
		return false;
	}
	next = (t->interval > t->max_interval / 2) ? t->max_interval
						     : t->interval * 2;
	return begin_interval(t, next, now, rand_offset);
}

bool lichen_trickle_reset(struct lichen_trickle *t, uint32_t now,
			 uint32_t rand_offset)
{
	if (t == NULL) {
		return false;
	}
	return begin_interval(t, t->imin, now, rand_offset);
}

bool lichen_trickle_next_event(const struct lichen_trickle *t,
			      struct lichen_trickle_event *out)
{
	if (t == NULL || out == NULL || !t->active) {
		return false;
	}
	if (!t->transmitted) {
		out->type = LICHEN_TRICKLE_TRANSMIT;
		out->at_ms = t->transmit_time;
	} else {
		out->type = LICHEN_TRICKLE_EXPIRE;
		out->at_ms = lichen_trickle_interval_end(t);
	}
	return true;
}
