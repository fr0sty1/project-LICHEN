/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

static K_SEM_DEFINE(s_send_sem, 0, 1);
static K_MUTEX_DEFINE(s_state_mutex);
static uint8_t s_last_ipv6[1280];
static size_t s_last_len;
static uint32_t s_send_count;
static int s_return_value;

void ble_uart_stub_reset(int return_value)
{
	k_sem_reset(&s_send_sem);
	k_mutex_lock(&s_state_mutex, K_FOREVER);
	memset(s_last_ipv6, 0, sizeof(s_last_ipv6));
	s_last_len = 0U;
	s_send_count = 0U;
	s_return_value = return_value;
	k_mutex_unlock(&s_state_mutex);
}

int ble_uart_stub_wait(void)
{
	return k_sem_take(&s_send_sem, K_SECONDS(2));
}

uint32_t ble_uart_stub_send_count(void)
{
	uint32_t count;

	k_mutex_lock(&s_state_mutex, K_FOREVER);
	count = s_send_count;
	k_mutex_unlock(&s_state_mutex);
	return count;
}

size_t ble_uart_stub_last_len(void)
{
	size_t len;

	k_mutex_lock(&s_state_mutex, K_FOREVER);
	len = s_last_len;
	k_mutex_unlock(&s_state_mutex);
	return len;
}

int ble_uart_stub_copy_last(uint8_t *buf, size_t cap)
{
	if (buf == NULL && cap > 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&s_state_mutex, K_FOREVER);
	if (cap < s_last_len) {
		k_mutex_unlock(&s_state_mutex);
		return -ENOMEM;
	}
	memcpy(buf, s_last_ipv6, s_last_len);
	k_mutex_unlock(&s_state_mutex);
	return 0;
}

int ble_uart_send_slip(const uint8_t *ipv6, size_t len)
{
	if (ipv6 == NULL && len > 0U) {
		return -EINVAL;
	}

	k_mutex_lock(&s_state_mutex, K_FOREVER);
	s_send_count++;
	s_last_len = MIN(len, sizeof(s_last_ipv6));
	if (s_last_len > 0U) {
		memcpy(s_last_ipv6, ipv6, s_last_len);
	}
	k_mutex_unlock(&s_state_mutex);
	k_sem_give(&s_send_sem);
	return s_return_value;
}
