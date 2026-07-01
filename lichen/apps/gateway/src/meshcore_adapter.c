/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "meshcore_adapter.h"

#include "ble_meshcore.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <lichen/meshcore/adapter.h>
#include <lichen/meshcore/limits.h>

LOG_MODULE_REGISTER(gateway_meshcore_adapter, LOG_LEVEL_INF);

#define ADAPTER_STACK_SIZE 2048
#define ADAPTER_PRIORITY 7
#define ADAPTER_IDLE_SLEEP K_MSEC(20)

static struct lichen_meshcore_adapter s_adapter;
static uint8_t s_rx_frame[LICHEN_MESHCORE_FRAME_MAX];
static struct k_thread s_thread;
static K_THREAD_STACK_DEFINE(s_stack, ADAPTER_STACK_SIZE);
static K_MUTEX_DEFINE(s_init_mutex);
static K_MUTEX_DEFINE(s_adapter_mutex);
static bool s_started;
static uint32_t s_dispatch_epoch;

static int enqueue_tx(const uint8_t *frame, size_t len, void *user_data)
{
	ARG_UNUSED(user_data);

	return ble_meshcore_enqueue_tx_if_session(s_dispatch_epoch, frame, len);
}

static uint32_t tx_free(void *user_data)
{
	ARG_UNUSED(user_data);

	return ble_meshcore_tx_free();
}

static struct lichen_meshcore_adapter_ops adapter_ops(void)
{
	return (struct lichen_meshcore_adapter_ops){
		.enqueue_tx = enqueue_tx,
		.tx_free = tx_free,
	};
}

#ifdef CONFIG_ZTEST
void gateway_meshcore_adapter_test_reset(void)
{
	struct lichen_meshcore_adapter_ops ops = adapter_ops();

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	s_dispatch_epoch = 0U;
	lichen_meshcore_adapter_init(&s_adapter, &ops);
	k_mutex_unlock(&s_adapter_mutex);
}

int gateway_meshcore_adapter_test_process_once(void)
{
	size_t frame_len = 0U;
	uint32_t session_epoch = 0U;
	int ret = ble_meshcore_dequeue_rx(s_rx_frame, sizeof(s_rx_frame),
					  &frame_len, &session_epoch);

	if (ret <= 0) {
		return ret;
	}

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	s_dispatch_epoch = session_epoch;
	if (!ble_meshcore_session_epoch_current(session_epoch)) {
		lichen_meshcore_adapter_reset(&s_adapter);
		k_mutex_unlock(&s_adapter_mutex);
		return -ESTALE;
	}

	ret = lichen_meshcore_adapter_process_raw(&s_adapter, s_rx_frame,
						  frame_len);
	k_mutex_unlock(&s_adapter_mutex);
	return ret;
}
#endif

static void adapter_thread(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	for (;;) {
		size_t frame_len = 0U;
		uint32_t session_epoch = 0U;
		int ret = ble_meshcore_dequeue_rx(s_rx_frame, sizeof(s_rx_frame),
						  &frame_len, &session_epoch);

		if (ret == 0) {
			k_sleep(ADAPTER_IDLE_SLEEP);
			continue;
		}
		if (ret < 0) {
			LOG_WRN("MeshCore RX dequeue failed: %d", ret);
			k_sleep(ADAPTER_IDLE_SLEEP);
			continue;
		}

		k_mutex_lock(&s_adapter_mutex, K_FOREVER);
		s_dispatch_epoch = session_epoch;
		if (!ble_meshcore_session_epoch_current(session_epoch)) {
			lichen_meshcore_adapter_reset(&s_adapter);
			k_mutex_unlock(&s_adapter_mutex);
			continue;
		}

		ret = lichen_meshcore_adapter_process_raw(&s_adapter,
							  s_rx_frame,
							  frame_len);
		if (ret < 0) {
			LOG_WRN("MeshCore command dispatch failed: %d", ret);
		}
		k_mutex_unlock(&s_adapter_mutex);
	}
}

int gateway_meshcore_adapter_init(void)
{
	struct lichen_meshcore_adapter_ops ops = adapter_ops();

	k_mutex_lock(&s_init_mutex, K_FOREVER);
	if (s_started) {
		k_mutex_unlock(&s_init_mutex);
		return 0;
	}

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	lichen_meshcore_adapter_init(&s_adapter, &ops);
	k_mutex_unlock(&s_adapter_mutex);

	k_thread_create(&s_thread, s_stack, K_THREAD_STACK_SIZEOF(s_stack),
			adapter_thread, NULL, NULL, NULL,
			ADAPTER_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&s_thread, "meshcore");
	s_started = true;
	k_mutex_unlock(&s_init_mutex);
	LOG_INF("MeshCore app adapter ready");

	return 0;
}
