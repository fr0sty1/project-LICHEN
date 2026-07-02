/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "meshcore_adapter.h"

#include "ble_meshcore.h"
#include "gateway_identity.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <lichen/app_interface/app_interface.h>
#include <lichen/meshcore/adapter.h>
#include <lichen/meshcore/limits.h>

#ifndef ENOKEY
#define ENOKEY ENOENT
#endif

LOG_MODULE_REGISTER(gateway_meshcore_adapter, LOG_LEVEL_INF);

#define ADAPTER_STACK_SIZE 2048
#define ADAPTER_PRIORITY 7
#define ADAPTER_IDLE_SLEEP K_MSEC(20)

static struct lichen_meshcore_adapter s_adapter;
static struct lichen_meshcore_compat_settings s_compat_settings;
static uint8_t s_rx_frame[LICHEN_MESHCORE_FRAME_MAX];
static struct k_thread s_thread;
static K_THREAD_STACK_DEFINE(s_stack, ADAPTER_STACK_SIZE);
static K_MUTEX_DEFINE(s_init_mutex);
static K_MUTEX_DEFINE(s_adapter_mutex);
static K_MUTEX_DEFINE(s_sink_mutex);
static bool s_started;
static bool s_sink_registered;
static uint8_t s_sink_id;
static uint32_t s_dispatch_epoch;
static uint32_t s_adapter_epoch;
static bool s_command_dispatching;
static k_tid_t s_command_dispatch_thread;

static int lock_adapter_for_egress(void)
{
	if (s_command_dispatching &&
	    s_command_dispatch_thread == k_current_get()) {
		return -EBUSY;
	}

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	return 0;
}

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

static int submit_text(uint8_t channel, uint8_t text_type,
		       const uint8_t *payload, size_t payload_len,
		       void *user_data)
{
	const struct lichen_app_text_event event = {
		.from = 0U,
		.to = UINT32_MAX,
		.payload = payload,
		.payload_len = payload_len,
	};

	ARG_UNUSED(channel);
	ARG_UNUSED(text_type);
	ARG_UNUSED(user_data);

	return lichen_app_interface_submit_text(&event);
}

static int apply_pin(uint32_t pin, void *user_data)
{
	ARG_UNUSED(user_data);

	return ble_meshcore_set_passkey(pin);
}

static struct lichen_meshcore_adapter_ops adapter_ops(void)
{
	return (struct lichen_meshcore_adapter_ops){
		.enqueue_tx = enqueue_tx,
		.tx_free = tx_free,
		.submit_text = submit_text,
		.apply_pin = apply_pin,
		.compat_settings = &s_compat_settings,
	};
}

static uint32_t sync_adapter_session_locked(void)
{
	uint32_t current_epoch = ble_meshcore_session_epoch();

	if (s_adapter_epoch != current_epoch) {
		lichen_meshcore_adapter_reset(&s_adapter);
		s_adapter_epoch = current_epoch;
	}
	return current_epoch;
}

static int meshcore_text_sink(const struct lichen_app_text_event *event,
			      void *user_data)
{
	struct lichen_meshcore_incoming_text meshcore_event;
	int ret;

	ARG_UNUSED(user_data);

	if (event == NULL) {
		return -EINVAL;
	}
	if (!ble_meshcore_session_active()) {
		return -ENOTCONN;
	}

	meshcore_event = (struct lichen_meshcore_incoming_text){
		.from = event->from,
		.to = event->to,
		.id = event->id,
		.payload = event->payload,
		.payload_len = event->payload_len,
		.has_id = event->has_id,
	};

	ret = lock_adapter_for_egress();
	if (ret < 0) {
		return ret;
	}
	s_dispatch_epoch = sync_adapter_session_locked();
	ret = lichen_meshcore_adapter_emit_text(&s_adapter, &meshcore_event);
	k_mutex_unlock(&s_adapter_mutex);
	return ret;
}

static int meshcore_status_sink(const struct lichen_app_status_event *event,
				void *user_data)
{
	struct lichen_meshcore_incoming_status meshcore_event;
	int ret;

	ARG_UNUSED(user_data);

	if (event == NULL) {
		return -EINVAL;
	}
	if (!ble_meshcore_session_active()) {
		return -ENOTCONN;
	}

	meshcore_event = (struct lichen_meshcore_incoming_status){
		.from = event->from,
		.to = event->to,
		.id = event->id,
		.request_id = event->request_id,
		.error_reason = event->error_reason,
		.has_id = event->has_id,
		.has_error_reason = event->has_error_reason,
	};

	ret = lock_adapter_for_egress();
	if (ret < 0) {
		return ret;
	}
	s_dispatch_epoch = sync_adapter_session_locked();
	ret = lichen_meshcore_adapter_emit_status(&s_adapter, &meshcore_event);
	k_mutex_unlock(&s_adapter_mutex);
	return ret;
}

static int ensure_app_sink(void)
{
	const struct lichen_app_interface_sink sink = {
		.emit_text = meshcore_text_sink,
		.emit_status = meshcore_status_sink,
	};
	int ret = 0;

	k_mutex_lock(&s_sink_mutex, K_FOREVER);
	if (!s_sink_registered) {
		ret = lichen_app_interface_register_sink(&sink, &s_sink_id);
		if (ret == 0) {
			s_sink_registered = true;
		}
	}
	k_mutex_unlock(&s_sink_mutex);
	return ret;
}

static void try_publish_self_identity(void)
{
	int ret = gateway_identity_publish_self();

	if (ret < 0 && ret != -ENOTSUP && ret != -ENOKEY &&
	    ret != -EAGAIN) {
		LOG_WRN("MeshCore self identity publication retry failed: %d",
			ret);
	}
}

static void seed_default_compat_pin(void)
{
#if defined(CONFIG_LORA_LICHEN_MESHCORE_BLE_PASSKEY)
	uint32_t pin = CONFIG_LORA_LICHEN_MESHCORE_BLE_PASSKEY;
#elif defined(CONFIG_ZTEST)
	uint32_t pin = 123456U;
#else
	uint32_t pin = 0U;
#endif

	if (pin == 0U || (pin >= 100000U && pin <= 999999U)) {
		s_compat_settings.device_pin = pin;
		s_compat_settings.device_pin_valid = true;
	}
}

#ifdef CONFIG_ZTEST
void gateway_meshcore_adapter_test_reset(void)
{
	struct lichen_meshcore_adapter_ops ops = adapter_ops();

	k_mutex_lock(&s_sink_mutex, K_FOREVER);
	s_sink_registered = false;
	k_mutex_unlock(&s_sink_mutex);

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	s_dispatch_epoch = 0U;
	s_adapter_epoch = ble_meshcore_session_epoch();
	s_command_dispatching = false;
	s_command_dispatch_thread = NULL;
	lichen_meshcore_compat_settings_reset(&s_compat_settings);
	seed_default_compat_pin();
	lichen_meshcore_adapter_init(&s_adapter, &ops);
	k_mutex_unlock(&s_adapter_mutex);
	(void)ensure_app_sink();
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

	try_publish_self_identity();
	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	s_adapter_epoch = sync_adapter_session_locked();
	s_dispatch_epoch = session_epoch;
	if (!ble_meshcore_session_epoch_current(session_epoch)) {
		lichen_meshcore_adapter_reset(&s_adapter);
		k_mutex_unlock(&s_adapter_mutex);
		return -ESTALE;
	}

	s_command_dispatching = true;
	s_command_dispatch_thread = k_current_get();
	ret = lichen_meshcore_adapter_process_raw(&s_adapter, s_rx_frame,
						  frame_len);
	s_command_dispatching = false;
	s_command_dispatch_thread = NULL;
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

		try_publish_self_identity();
		k_mutex_lock(&s_adapter_mutex, K_FOREVER);
		s_adapter_epoch = sync_adapter_session_locked();
		s_dispatch_epoch = session_epoch;
		if (!ble_meshcore_session_epoch_current(session_epoch)) {
			lichen_meshcore_adapter_reset(&s_adapter);
			k_mutex_unlock(&s_adapter_mutex);
			continue;
		}

		s_command_dispatching = true;
		s_command_dispatch_thread = k_current_get();
		ret = lichen_meshcore_adapter_process_raw(&s_adapter,
							  s_rx_frame,
							  frame_len);
		s_command_dispatching = false;
		s_command_dispatch_thread = NULL;
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
	s_adapter_epoch = ble_meshcore_session_epoch();
	seed_default_compat_pin();
	lichen_meshcore_adapter_init(&s_adapter, &ops);
	k_mutex_unlock(&s_adapter_mutex);
	try_publish_self_identity();
	if (ensure_app_sink() < 0) {
		k_mutex_unlock(&s_init_mutex);
		return -EIO;
	}

	k_thread_create(&s_thread, s_stack, K_THREAD_STACK_SIZEOF(s_stack),
			adapter_thread, NULL, NULL, NULL,
			ADAPTER_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&s_thread, "meshcore");
	s_started = true;
	k_mutex_unlock(&s_init_mutex);
	LOG_INF("MeshCore app adapter ready");

	return 0;
}
