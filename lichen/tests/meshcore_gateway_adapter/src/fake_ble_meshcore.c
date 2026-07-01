/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "fake_ble_meshcore.h"

#include "ble_meshcore.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/meshcore/limits.h>

#define FAKE_QUEUE_DEPTH 4U

struct fake_slot {
	uint8_t data[LICHEN_MESHCORE_FRAME_MAX];
	size_t len;
	uint32_t epoch;
};

static struct fake_slot s_rx[FAKE_QUEUE_DEPTH];
static struct fake_slot s_tx[FAKE_QUEUE_DEPTH];
static size_t s_rx_count;
static size_t s_tx_count;
static uint32_t s_epoch = 1U;
static uint32_t s_tx_cap = FAKE_QUEUE_DEPTH;
static bool s_connected = true;
static bool s_disconnect_on_next_enqueue;
static K_MUTEX_DEFINE(s_fake_mutex);

void fake_ble_meshcore_reset(uint32_t tx_cap)
{
	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	memset(s_rx, 0, sizeof(s_rx));
	memset(s_tx, 0, sizeof(s_tx));
	s_rx_count = 0U;
	s_tx_count = 0U;
	s_epoch = 1U;
	s_tx_cap = MIN(tx_cap, FAKE_QUEUE_DEPTH);
	s_connected = true;
	s_disconnect_on_next_enqueue = false;
	k_mutex_unlock(&s_fake_mutex);
}

void fake_ble_meshcore_set_epoch(uint32_t session_epoch)
{
	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	s_epoch = session_epoch;
	k_mutex_unlock(&s_fake_mutex);
}

void fake_ble_meshcore_disconnect_on_next_enqueue(void)
{
	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	s_disconnect_on_next_enqueue = true;
	k_mutex_unlock(&s_fake_mutex);
}

void fake_ble_meshcore_set_connected(bool connected)
{
	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (s_connected != connected) {
		s_epoch++;
	}
	s_connected = connected;
	if (!s_connected) {
		s_tx_count = 0U;
	}
	k_mutex_unlock(&s_fake_mutex);
}

int fake_ble_meshcore_push_rx(const uint8_t *frame, size_t len,
			      uint32_t session_epoch)
{
	if (frame == NULL || len == 0U || len > LICHEN_MESHCORE_FRAME_MAX) {
		return -EINVAL;
	}

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (s_rx_count == ARRAY_SIZE(s_rx)) {
		k_mutex_unlock(&s_fake_mutex);
		return -ENOMEM;
	}

	memcpy(s_rx[s_rx_count].data, frame, len);
	s_rx[s_rx_count].len = len;
	s_rx[s_rx_count].epoch = session_epoch;
	s_rx_count++;
	k_mutex_unlock(&s_fake_mutex);
	return 0;
}

size_t fake_ble_meshcore_tx_count(void)
{
	size_t count;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	count = s_tx_count;
	k_mutex_unlock(&s_fake_mutex);
	return count;
}

const uint8_t *fake_ble_meshcore_tx(size_t index, size_t *len)
{
	if (len == NULL) {
		return NULL;
	}

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (index >= s_tx_count) {
		k_mutex_unlock(&s_fake_mutex);
		return NULL;
	}

	*len = s_tx[index].len;
	k_mutex_unlock(&s_fake_mutex);
	return s_tx[index].data;
}

int ble_meshcore_dequeue_rx(uint8_t *frame, size_t buflen, size_t *out_len,
			    uint32_t *out_session_epoch)
{
	if (frame == NULL || out_len == NULL || out_session_epoch == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (s_rx_count == 0U) {
		k_mutex_unlock(&s_fake_mutex);
		return 0;
	}
	if (buflen < s_rx[0].len) {
		k_mutex_unlock(&s_fake_mutex);
		return -ENOMEM;
	}

	memcpy(frame, s_rx[0].data, s_rx[0].len);
	*out_len = s_rx[0].len;
	*out_session_epoch = s_rx[0].epoch;
	for (size_t i = 1U; i < s_rx_count; i++) {
		s_rx[i - 1U] = s_rx[i];
	}
	s_rx_count--;
	k_mutex_unlock(&s_fake_mutex);
	return 1;
}

int ble_meshcore_enqueue_tx_if_session(uint32_t session_epoch,
				       const uint8_t *frame, size_t len)
{
	if (frame == NULL || len == 0U || len > LICHEN_MESHCORE_FRAME_MAX) {
		return -EINVAL;
	}

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (!s_connected) {
		k_mutex_unlock(&s_fake_mutex);
		return -ENOTCONN;
	}
	if (session_epoch != s_epoch) {
		k_mutex_unlock(&s_fake_mutex);
		return -ESTALE;
	}
	if (s_disconnect_on_next_enqueue) {
		s_disconnect_on_next_enqueue = false;
		s_connected = false;
		s_epoch++;
		s_tx_count = 0U;
		k_mutex_unlock(&s_fake_mutex);
		return -ENOTCONN;
	}
	if (s_tx_count >= s_tx_cap) {
		k_mutex_unlock(&s_fake_mutex);
		return -ENOMEM;
	}

	memcpy(s_tx[s_tx_count].data, frame, len);
	s_tx[s_tx_count].len = len;
	s_tx[s_tx_count].epoch = session_epoch;
	s_tx_count++;
	k_mutex_unlock(&s_fake_mutex);
	return 0;
}

uint32_t ble_meshcore_tx_free(void)
{
	uint32_t free_slots;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	free_slots = s_tx_count >= s_tx_cap ? 0U : s_tx_cap - s_tx_count;
	k_mutex_unlock(&s_fake_mutex);
	return free_slots;
}

bool ble_meshcore_session_epoch_current(uint32_t session_epoch)
{
	bool current;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	current = session_epoch == s_epoch;
	k_mutex_unlock(&s_fake_mutex);
	return current;
}

uint32_t ble_meshcore_session_epoch(void)
{
	uint32_t epoch;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	epoch = s_epoch;
	k_mutex_unlock(&s_fake_mutex);
	return epoch;
}

bool ble_meshcore_session_active(void)
{
	bool connected;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	connected = s_connected;
	k_mutex_unlock(&s_fake_mutex);
	return connected;
}
