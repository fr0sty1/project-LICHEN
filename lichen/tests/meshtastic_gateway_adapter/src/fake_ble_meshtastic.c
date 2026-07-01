/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/kernel.h>

#include <lichen/meshtastic/codec.h>

#include "ble_meshtastic.h"
#include "fake_ble_meshtastic.h"

#define FAKE_FROM_RADIO_CAPACITY 4U
#define FAKE_TO_RADIO_CAPACITY 2U

static uint8_t s_from_radio[FAKE_FROM_RADIO_CAPACITY][LICHEN_MESHTASTIC_FROM_RADIO_MAX];
static size_t s_from_radio_len[FAKE_FROM_RADIO_CAPACITY];
static size_t s_from_radio_count;
static size_t s_from_radio_cap = FAKE_FROM_RADIO_CAPACITY;
static uint8_t s_to_radio[FAKE_TO_RADIO_CAPACITY][LICHEN_MESHTASTIC_TO_RADIO_MAX];
static size_t s_to_radio_len[FAKE_TO_RADIO_CAPACITY];
static uint32_t s_to_radio_epoch[FAKE_TO_RADIO_CAPACITY];
static size_t s_to_radio_head;
static size_t s_to_radio_count;
static uint32_t s_session_epoch;
static bool s_connected;
static bool s_disconnect_on_next_enqueue;
static K_MUTEX_DEFINE(s_fake_mutex);

void fake_ble_meshtastic_reset(size_t from_radio_cap)
{
	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	memset(s_from_radio, 0, sizeof(s_from_radio));
	memset(s_from_radio_len, 0, sizeof(s_from_radio_len));
	memset(s_to_radio, 0, sizeof(s_to_radio));
	memset(s_to_radio_len, 0, sizeof(s_to_radio_len));
	memset(s_to_radio_epoch, 0, sizeof(s_to_radio_epoch));
	s_from_radio_count = 0U;
	s_to_radio_head = 0U;
	s_to_radio_count = 0U;
	s_from_radio_cap = from_radio_cap;
	if (s_from_radio_cap > FAKE_FROM_RADIO_CAPACITY) {
		s_from_radio_cap = FAKE_FROM_RADIO_CAPACITY;
	}
	s_session_epoch++;
	s_connected = true;
	s_disconnect_on_next_enqueue = false;
	k_mutex_unlock(&s_fake_mutex);
}

void fake_ble_meshtastic_set_connected(bool connected)
{
	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (s_connected != connected) {
		s_session_epoch++;
	}
	s_connected = connected;
	if (!s_connected) {
		memset(s_from_radio, 0, sizeof(s_from_radio));
		memset(s_from_radio_len, 0, sizeof(s_from_radio_len));
		memset(s_to_radio, 0, sizeof(s_to_radio));
		memset(s_to_radio_len, 0, sizeof(s_to_radio_len));
		memset(s_to_radio_epoch, 0, sizeof(s_to_radio_epoch));
		s_from_radio_count = 0U;
		s_to_radio_head = 0U;
		s_to_radio_count = 0U;
	}
	k_mutex_unlock(&s_fake_mutex);
}

void fake_ble_meshtastic_disconnect_on_next_enqueue(void)
{
	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	s_disconnect_on_next_enqueue = true;
	k_mutex_unlock(&s_fake_mutex);
}

size_t fake_ble_meshtastic_from_radio_count(void)
{
	size_t count;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	count = s_from_radio_count;
	k_mutex_unlock(&s_fake_mutex);
	return count;
}

const uint8_t *fake_ble_meshtastic_from_radio(size_t index, size_t *len)
{
	if (len == NULL) {
		return NULL;
	}

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (index >= s_from_radio_count) {
		k_mutex_unlock(&s_fake_mutex);
		return NULL;
	}

	*len = s_from_radio_len[index];
	k_mutex_unlock(&s_fake_mutex);
	return s_from_radio[index];
}

int fake_ble_meshtastic_push_to_radio(const uint8_t *to_radio, size_t len)
{
	size_t tail;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (!s_connected) {
		k_mutex_unlock(&s_fake_mutex);
		return -ENOTCONN;
	}
	if (to_radio == NULL && len > 0U) {
		k_mutex_unlock(&s_fake_mutex);
		return -EINVAL;
	}
	if (len > LICHEN_MESHTASTIC_TO_RADIO_MAX) {
		k_mutex_unlock(&s_fake_mutex);
		return -EMSGSIZE;
	}
	if (s_to_radio_count == FAKE_TO_RADIO_CAPACITY) {
		k_mutex_unlock(&s_fake_mutex);
		return -ENOMEM;
	}

	tail = (s_to_radio_head + s_to_radio_count) % FAKE_TO_RADIO_CAPACITY;
	if (len > 0U) {
		memcpy(s_to_radio[tail], to_radio, len);
	}
	s_to_radio_len[tail] = len;
	s_to_radio_epoch[tail] = s_session_epoch;
	s_to_radio_count++;
	k_mutex_unlock(&s_fake_mutex);
	return 0;
}

int ble_meshtastic_enqueue_from_radio(const uint8_t *from_radio, size_t len)
{
	return ble_meshtastic_enqueue_from_radio_if_session(
		ble_meshtastic_session_epoch(),
							   from_radio, len);
}

int ble_meshtastic_enqueue_from_radio_if_session(uint32_t session_epoch,
						 const uint8_t *from_radio,
						 size_t len)
{
	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (session_epoch != s_session_epoch) {
		k_mutex_unlock(&s_fake_mutex);
		return -ESTALE;
	}
	if (!s_connected) {
		k_mutex_unlock(&s_fake_mutex);
		return -ENOTCONN;
	}
	if (s_disconnect_on_next_enqueue) {
		s_disconnect_on_next_enqueue = false;
		memset(s_from_radio, 0, sizeof(s_from_radio));
		memset(s_from_radio_len, 0, sizeof(s_from_radio_len));
		memset(s_to_radio, 0, sizeof(s_to_radio));
		memset(s_to_radio_len, 0, sizeof(s_to_radio_len));
		memset(s_to_radio_epoch, 0, sizeof(s_to_radio_epoch));
		s_from_radio_count = 0U;
		s_to_radio_head = 0U;
		s_to_radio_count = 0U;
		s_connected = false;
		s_session_epoch++;
		k_mutex_unlock(&s_fake_mutex);
		return -ENOTCONN;
	}
	if (from_radio == NULL && len > 0U) {
		k_mutex_unlock(&s_fake_mutex);
		return -EINVAL;
	}
	if (len > LICHEN_MESHTASTIC_FROM_RADIO_MAX) {
		k_mutex_unlock(&s_fake_mutex);
		return -EMSGSIZE;
	}
	if (s_from_radio_count == s_from_radio_cap) {
		k_mutex_unlock(&s_fake_mutex);
		return -ENOMEM;
	}

	if (len > 0U) {
		memcpy(s_from_radio[s_from_radio_count], from_radio, len);
	}
	s_from_radio_len[s_from_radio_count] = len;
	s_from_radio_count++;
	k_mutex_unlock(&s_fake_mutex);
	return 0;
}

int ble_meshtastic_dequeue_to_radio(uint8_t *to_radio, size_t buflen,
				    size_t *out_len,
				    uint32_t *out_session_epoch)
{
	if (out_len == NULL || out_session_epoch == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (!s_connected) {
		k_mutex_unlock(&s_fake_mutex);
		return -ENOTCONN;
	}
	if (s_to_radio_count == 0U) {
		*out_len = 0U;
		*out_session_epoch = s_session_epoch;
		k_mutex_unlock(&s_fake_mutex);
		return 0;
	}
	if (to_radio == NULL || buflen < s_to_radio_len[s_to_radio_head]) {
		k_mutex_unlock(&s_fake_mutex);
		return -ENOMEM;
	}
	memcpy(to_radio, s_to_radio[s_to_radio_head],
	       s_to_radio_len[s_to_radio_head]);
	*out_len = s_to_radio_len[s_to_radio_head];
	*out_session_epoch = s_to_radio_epoch[s_to_radio_head];
	memset(s_to_radio[s_to_radio_head], 0, sizeof(s_to_radio[s_to_radio_head]));
	s_to_radio_len[s_to_radio_head] = 0U;
	s_to_radio_epoch[s_to_radio_head] = 0U;
	s_to_radio_head = (s_to_radio_head + 1U) % FAKE_TO_RADIO_CAPACITY;
	s_to_radio_count--;
	k_mutex_unlock(&s_fake_mutex);
	return 1;
}

void ble_meshtastic_reset_session(void)
{
	fake_ble_meshtastic_reset(s_from_radio_cap);
}

int ble_meshtastic_reset_session_if_epoch(uint32_t session_epoch)
{
	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	if (session_epoch != s_session_epoch) {
		k_mutex_unlock(&s_fake_mutex);
		return -ESTALE;
	}
	memset(s_from_radio, 0, sizeof(s_from_radio));
	memset(s_from_radio_len, 0, sizeof(s_from_radio_len));
	memset(s_to_radio, 0, sizeof(s_to_radio));
	memset(s_to_radio_len, 0, sizeof(s_to_radio_len));
	memset(s_to_radio_epoch, 0, sizeof(s_to_radio_epoch));
	s_from_radio_count = 0U;
	s_to_radio_head = 0U;
	s_to_radio_count = 0U;
	s_session_epoch++;
	k_mutex_unlock(&s_fake_mutex);
	return 0;
}

uint32_t ble_meshtastic_session_epoch(void)
{
	uint32_t epoch;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	epoch = s_session_epoch;
	k_mutex_unlock(&s_fake_mutex);
	return epoch;
}

bool ble_meshtastic_session_active(void)
{
	bool connected;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	connected = s_connected;
	k_mutex_unlock(&s_fake_mutex);
	return connected;
}

bool ble_meshtastic_session_epoch_current(uint32_t session_epoch)
{
	bool current;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	current = session_epoch == s_session_epoch;
	k_mutex_unlock(&s_fake_mutex);
	return current;
}

uint32_t ble_meshtastic_from_radio_free(void)
{
	uint32_t free_slots;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	free_slots = (uint32_t)(s_from_radio_cap - s_from_radio_count);
	k_mutex_unlock(&s_fake_mutex);
	return free_slots;
}

uint32_t ble_meshtastic_from_radio_capacity(void)
{
	uint32_t capacity;

	k_mutex_lock(&s_fake_mutex, K_FOREVER);
	capacity = (uint32_t)s_from_radio_cap;
	k_mutex_unlock(&s_fake_mutex);
	return capacity;
}
