/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/hal.h>
#include <zephyr/kernel.h>

#define DUTY_CYCLE_N 32

struct duty_cycle_tracker {
	uint32_t tx_times[DUTY_CYCLE_N];
	uint8_t head;
	uint8_t count;
	uint32_t window_ms;
	uint16_t limit_permille;
};

void duty_cycle_init(struct duty_cycle_tracker *t, uint32_t window_ms, uint16_t limit_permille)
{
	t->window_ms = window_ms;
	t->limit_permille = limit_permille;
	t->head = 0;
	t->count = 0;
	for (int i = 0; i < DUTY_CYCLE_N; i++) {
		t->tx_times[i] = 0;
	}
}

static void evict_stale(struct duty_cycle_tracker *t, uint32_t now_ms)
{
	while (t->count > 0) {
		uint8_t idx = (t->head + DUTY_CYCLE_N - t->count) % DUTY_CYCLE_N;
		if (now_ms - t->tx_times[idx] >= t->window_ms) {
			t->count--;
		} else {
			break;
		}
	}
}

static uint32_t total_tx_in_window(struct duty_cycle_tracker *t, uint32_t now_ms, uint32_t tx_ms)
{
	evict_stale(t, now_ms);
	uint32_t total = 0;
	for (uint8_t i = 0; i < t->count; i++) {
		uint8_t idx = (t->head + DUTY_CYCLE_N - 1 - i) % DUTY_CYCLE_N;
		uint32_t tx_time = t->tx_times[idx];
		if (tx_time + tx_ms > now_ms - t->window_ms) {
			uint32_t overlap = tx_time + tx_ms - (now_ms - t->window_ms);
			if (overlap > tx_ms) overlap = tx_ms;
			total += overlap;
		}
	}
	return total;
}

uint16_t duty_cycle_usage_permille(struct duty_cycle_tracker *t, uint32_t now_ms)
{
	uint32_t used = total_tx_in_window(t, now_ms, 0);
	return (uint16_t)((used * 1000ULL) / t->window_ms);
}

uint32_t duty_cycle_remaining_ms(struct duty_cycle_tracker *t, uint32_t now_ms)
{
	uint16_t usage = duty_cycle_usage_permille(t, now_ms);
	uint32_t limit_ms = (uint32_t)t->limit_permille * t->window_ms / 1000;
	if (usage >= t->limit_permille) return 0;
	return limit_ms - (usage * t->window_ms / 1000);
}

bool duty_cycle_can_transmit(struct duty_cycle_tracker *t, uint32_t now_ms, uint32_t duration_ms)
{
	uint32_t remaining = duty_cycle_remaining_ms(t, now_ms);
	return remaining >= duration_ms;
}

void duty_cycle_record_tx(struct duty_cycle_tracker *t, uint32_t now_ms, uint32_t duration_ms)
{
	evict_stale(t, now_ms);
	if (t->count < DUTY_CYCLE_N) {
		t->tx_times[t->head] = now_ms;
		t->head = (t->head + 1) % DUTY_CYCLE_N;
		t->count++;
	}
}
