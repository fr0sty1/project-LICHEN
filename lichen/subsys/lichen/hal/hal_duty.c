/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdint.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/hal.h>

#ifdef CONFIG_LICHEN_DUTY_CYCLE
#define LICHEN_DUTY_CYCLE_WINDOW_MS 3600000ULL

static void prune(struct lichen_duty_cycle_ctx *t, uint64_t now) {
	uint64_t ws = now > LICHEN_DUTY_CYCLE_WINDOW_MS ? now - LICHEN_DUTY_CYCLE_WINDOW_MS : 0ULL;
	while (t->len > 0) {
		uint8_t idx = t->head;
		uint64_t e = t->records[idx] + (uint64_t)t->durations[idx];
		if (e <= ws) {
			t->head = (t->head + 1U) % 32U;
			t->len--;
		} else break;
	}
}

static uint32_t total_tx(const struct lichen_duty_cycle_ctx *t, uint64_t now) {
	uint64_t ws = now > LICHEN_DUTY_CYCLE_WINDOW_MS ? now - LICHEN_DUTY_CYCLE_WINDOW_MS : 0ULL;
	uint32_t tot = 0;
	for (uint8_t i = 0; i < t->len; i++) {
		uint8_t k = (t->head + i) % 32U;
		uint64_t ts = t->records[k];
		uint32_t d = t->durations[k];
		if (ts >= ws) {
			if (tot > UINT32_MAX - d) tot = UINT32_MAX; else tot += d;
		} else {
			uint64_t e = ts + (uint64_t)d;
			if (e > ws) {
				uint32_t o = (uint32_t)(e - ws);
				if (tot > UINT32_MAX - o) tot = UINT32_MAX; else tot += o;
			}
		}
	}
	return tot;
}

void lichen_duty_cycle_init(struct lichen_duty_cycle_ctx *t, uint16_t permille) {
	t->head = 0;
	t->len = 0;
	t->duty_permille = (permille == 0 || permille > 1000) ? LICHEN_DUTY_CYCLE_DEFAULT_PERMILLE : permille;
}

bool lichen_duty_cycle_record_tx(struct lichen_duty_cycle_ctx *t, uint64_t ts, uint32_t dur) {
	prune(t, ts);
	if (t->len == 32) return false;
	uint8_t idx = (t->head + t->len) % 32U;
	t->records[idx] = ts;
	t->durations[idx] = dur;
	t->len++;
	return true;
}

uint32_t lichen_duty_cycle_remaining_ms(struct lichen_duty_cycle_ctx *t, uint64_t now) {
	prune(t, now);
	uint32_t m = (LICHEN_DUTY_CYCLE_WINDOW_MS / 1000ULL) * t->duty_permille;
	uint32_t u = total_tx(t, now);
	return m > u ? m - u : 0;
}

uint16_t lichen_duty_cycle_usage_permille(struct lichen_duty_cycle_ctx *t, uint64_t now) {
	prune(t, now);
	uint32_t u = total_tx(t, now);
	return (uint16_t)((uint64_t)u * 1000ULL / LICHEN_DUTY_CYCLE_WINDOW_MS);
}

uint64_t lichen_duty_cycle_next_tx_available_ms(struct lichen_duty_cycle_ctx *t, uint64_t now, uint32_t dur) {
	prune(t, now);
	uint32_t m = (LICHEN_DUTY_CYCLE_WINDOW_MS / 1000ULL) * t->duty_permille;
	uint32_t u = total_tx(t, now);
	if ((uint64_t)u + (uint64_t)dur <= (uint64_t)m) return now;
	uint32_t need = (uint32_t)((uint64_t)u + (uint64_t)dur - (uint64_t)m);
	uint32_t f = 0;
	for (uint8_t i = 0; i < t->len; i++) {
		uint8_t k = (t->head + i) % 32U;
		uint32_t d = t->durations[k];
		if (f > UINT32_MAX - d) f = UINT32_MAX; else f += d;
		if (f >= need) return t->records[k] + LICHEN_DUTY_CYCLE_WINDOW_MS;
	}
	return (uint64_t)-1;
}

bool lichen_duty_cycle_can_transmit(struct lichen_duty_cycle_ctx *t, uint64_t now, uint32_t dur) {
	return lichen_duty_cycle_remaining_ms(t, now) >= dur;
}
#endif
