/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "meshcore_adapter.h"

#include "ble_meshcore.h"
#include "gateway_identity.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#if IS_ENABLED(CONFIG_LORA_LICHEN_MESHCORE_COMPAT_SETTINGS_PERSISTENCE)
#include <zephyr/settings/settings.h>
#include <zephyr/sys/crc.h>
#endif

#include <lichen/app_identity/app_identity.h>
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
#define COMPAT_SETTINGS_MAGIC 0x4d435043U
#define COMPAT_SETTINGS_VERSION 1U

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
#if IS_ENABLED(CONFIG_LORA_LICHEN_MESHCORE_COMPAT_SETTINGS_PERSISTENCE)
static bool s_settings_registered;

struct meshcore_compat_settings_record {
	uint32_t magic;
	uint16_t version;
	uint16_t settings_size;
	struct lichen_meshcore_compat_settings settings;
	uint32_t crc32;
};
#endif
#ifdef CONFIG_ZTEST
static int s_test_reset_status;
#endif

#if IS_ENABLED(CONFIG_LORA_LICHEN_MESHCORE_COMPAT_SETTINGS_PERSISTENCE)
static uint32_t compat_settings_record_crc(
	const struct meshcore_compat_settings_record *record)
{
	return crc32_ieee((const uint8_t *)record,
			  offsetof(struct meshcore_compat_settings_record,
				   crc32));
}

static void compat_settings_record_prepare(
	struct meshcore_compat_settings_record *record,
	const struct lichen_meshcore_compat_settings *settings)
{
	memset(record, 0, sizeof(*record));
	record->magic = COMPAT_SETTINGS_MAGIC;
	record->version = COMPAT_SETTINGS_VERSION;
	record->settings_size = sizeof(record->settings);
	record->settings = *settings;
	record->crc32 = compat_settings_record_crc(record);
}

static bool compat_settings_record_valid(
	const struct meshcore_compat_settings_record *record)
{
	return record->magic == COMPAT_SETTINGS_MAGIC &&
	       record->version == COMPAT_SETTINGS_VERSION &&
	       record->settings_size == sizeof(record->settings) &&
	       record->crc32 == compat_settings_record_crc(record);
}

static bool compat_valid_utf8(const uint8_t *payload, size_t payload_len)
{
	size_t i = 0U;

	while (i < payload_len) {
		uint8_t c = payload[i];

		if (c < 0x80U) {
			i++;
		} else if (c >= 0xc2U && c <= 0xdfU) {
			if (i + 1U >= payload_len ||
			    (payload[i + 1U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 2U;
		} else if (c == 0xe0U) {
			if (i + 2U >= payload_len ||
			    payload[i + 1U] < 0xa0U ||
			    payload[i + 1U] > 0xbfU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 3U;
		} else if ((c >= 0xe1U && c <= 0xecU) ||
			   (c >= 0xeeU && c <= 0xefU)) {
			if (i + 2U >= payload_len ||
			    (payload[i + 1U] & 0xc0U) != 0x80U ||
			    (payload[i + 2U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 3U;
		} else if (c == 0xedU) {
			if (i + 2U >= payload_len ||
			    payload[i + 1U] < 0x80U ||
			    payload[i + 1U] > 0x9fU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 3U;
		} else if (c == 0xf0U) {
			if (i + 3U >= payload_len ||
			    payload[i + 1U] < 0x90U ||
			    payload[i + 1U] > 0xbfU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U ||
			    (payload[i + 3U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 4U;
		} else if (c >= 0xf1U && c <= 0xf3U) {
			if (i + 3U >= payload_len ||
			    (payload[i + 1U] & 0xc0U) != 0x80U ||
			    (payload[i + 2U] & 0xc0U) != 0x80U ||
			    (payload[i + 3U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 4U;
		} else if (c == 0xf4U) {
			if (i + 3U >= payload_len ||
			    payload[i + 1U] < 0x80U ||
			    payload[i + 1U] > 0x8fU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U ||
			    (payload[i + 3U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 4U;
		} else {
			return false;
		}
	}
	return true;
}

static bool compat_valid_name(const char *name, size_t len, size_t cap)
{
	if (len == 0U || len >= cap ||
	    !compat_valid_utf8((const uint8_t *)name, len)) {
		return false;
	}
	for (size_t i = 0U; i < len; i++) {
		if (name[i] == '\0') {
			return false;
		}
	}
	for (size_t i = len; i < cap; i++) {
		if (name[i] != '\0') {
			return false;
		}
	}
	return true;
}

static bool compat_channel_has_secret(const uint8_t *body)
{
	for (size_t i = 33U; i < LICHEN_MESHCORE_CHANNEL_BODY_LEN; i++) {
		if (body[i] != 0U) {
			return true;
		}
	}
	return false;
}

static bool compat_default_flood_name_valid(const uint8_t *name)
{
	const uint8_t *nul = memchr(name, 0,
				    LICHEN_MESHCORE_DEFAULT_FLOOD_NAME_LEN);
	size_t len;

	if (nul == NULL || nul == name) {
		return false;
	}
	len = (size_t)(nul - name);
	return len <= 30U && compat_valid_utf8(name, len);
}

static bool compat_settings_semantic_valid(
	const struct lichen_meshcore_compat_settings *settings)
{
	if (settings->advert_name_valid &&
	    !compat_valid_name(settings->advert_name,
			       settings->advert_name_len,
			       sizeof(settings->advert_name))) {
		return false;
	}
	if (!settings->advert_name_valid &&
	    settings->advert_name_len != 0U) {
		return false;
	}
	if (settings->channel0_valid &&
	    (settings->channel0_body[0] != 0U ||
	     compat_channel_has_secret(settings->channel0_body))) {
		return false;
	}
	if (settings->default_flood_scope_valid &&
	    !compat_default_flood_name_valid(settings->default_flood_name)) {
		return false;
	}
	if (settings->device_pin_valid &&
	    settings->device_pin != 0U &&
	    (settings->device_pin < 100000U ||
	     settings->device_pin > 999999U)) {
		return false;
	}
	return true;
}

static int meshcore_settings_set(const char *name, size_t len,
				 settings_read_cb read_cb, void *cb_arg)
{
	const char *next;
	struct meshcore_compat_settings_record record;
	int ret;

	if (!settings_name_steq(name, "compat", &next) || next != NULL) {
		return -ENOENT;
	}
	if (len != sizeof(record)) {
		lichen_meshcore_compat_settings_reset(&s_compat_settings);
		return 0;
	}

	ret = read_cb(cb_arg, &record, sizeof(record));
	if (ret < 0) {
		return ret;
	}
	if (ret != sizeof(record) || !compat_settings_record_valid(&record) ||
	    !compat_settings_semantic_valid(&record.settings)) {
		lichen_meshcore_compat_settings_reset(&s_compat_settings);
		return 0;
	}

	s_compat_settings = record.settings;
	return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(meshcore_compat_settings, "meshcore", NULL,
			       meshcore_settings_set, NULL, NULL);

static int persist_compat_settings(
	const struct lichen_meshcore_compat_settings *settings, void *user_data)
{
	struct meshcore_compat_settings_record record;

	ARG_UNUSED(user_data);

	if (settings == NULL) {
		return -EINVAL;
	}

	compat_settings_record_prepare(&record, settings);
	return settings_save_one("meshcore/compat", &record, sizeof(record));
}

static int ensure_compat_settings_loaded(void)
{
	int ret;

	if (!s_settings_registered) {
		ret = settings_subsys_init();
		if (ret < 0) {
			return ret;
		}
		s_settings_registered = true;
	}

	lichen_meshcore_compat_settings_reset(&s_compat_settings);
	return settings_load_subtree("meshcore");
}

static int clear_persisted_compat_settings(void)
{
	int ret = settings_subsys_init();

	if (ret < 0) {
		return ret;
	}
	return settings_delete("meshcore/compat");
}

static int corrupt_persisted_compat_settings(void)
{
	const uint8_t bad[] = { 0x4d, 0x43, 0x50, 0x43, 0x00 };
	int ret = settings_subsys_init();

	if (ret < 0) {
		return ret;
	}
	return settings_save_one("meshcore/compat", bad, sizeof(bad));
}

static int write_invalid_semantic_compat_settings(void)
{
	struct meshcore_compat_settings_record record;
	struct lichen_meshcore_compat_settings settings = {
		.device_pin_valid = true,
		.device_pin = 42U,
	};
	int ret = settings_subsys_init();

	if (ret < 0) {
		return ret;
	}
	compat_settings_record_prepare(&record, &settings);
	return settings_save_one("meshcore/compat", &record, sizeof(record));
}
#else
static int persist_compat_settings(
	const struct lichen_meshcore_compat_settings *settings, void *user_data)
{
	ARG_UNUSED(settings);
	ARG_UNUSED(user_data);

	return 0;
}

static int ensure_compat_settings_loaded(void)
{
	lichen_meshcore_compat_settings_reset(&s_compat_settings);
	return 0;
}

static int clear_persisted_compat_settings(void)
{
	return 0;
}

static int corrupt_persisted_compat_settings(void)
{
	return -ENOTSUP;
}

static int write_invalid_semantic_compat_settings(void)
{
	return -ENOTSUP;
}
#endif

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
		       const uint8_t *to_iid, const uint8_t *payload,
		       size_t payload_len,
		       void *user_data)
{
	const struct lichen_app_text_event event = {
		.from = 0U,
		.to = UINT32_MAX,
		.has_to_iid = to_iid != NULL,
		.payload = payload,
		.payload_len = payload_len,
	};

	ARG_UNUSED(channel);
	ARG_UNUSED(text_type);
	ARG_UNUSED(user_data);

	if (to_iid != NULL) {
		struct lichen_app_text_event direct_event = event;

		memcpy(direct_event.to_iid, to_iid,
		       sizeof(direct_event.to_iid));
		return lichen_app_interface_submit_text(&direct_event);
	}
	return lichen_app_interface_submit_text(&event);
}

static int apply_pin(uint32_t pin, void *user_data)
{
	ARG_UNUSED(user_data);

	return ble_meshcore_set_passkey(pin);
}

static int resolve_peer_prefix(const uint8_t prefix[6], uint8_t to_iid[8],
			       void *user_data)
{
#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
	struct lichen_app_identity_peer
		peers[CONFIG_LICHEN_APP_IDENTITY_MAX_PEERS];
	size_t count;
	size_t matches = 0U;

	ARG_UNUSED(user_data);
	if (prefix == NULL || to_iid == NULL) {
		return -EINVAL;
	}

	count = lichen_app_identity_copy_peers(peers, ARRAY_SIZE(peers));
	for (size_t i = 0U; i < count; i++) {
		if (!peers[i].has_public_key ||
		    memcmp(peers[i].public_key, prefix, 6U) != 0) {
			continue;
		}
		memcpy(to_iid, peers[i].iid, sizeof(peers[i].iid));
		matches++;
	}
	return matches == 1U ? 0 : -ENOENT;
#else
	ARG_UNUSED(prefix);
	ARG_UNUSED(to_iid);
	ARG_UNUSED(user_data);
	return -ENOENT;
#endif
}

static struct lichen_meshcore_adapter_ops adapter_ops(void)
{
	struct lichen_meshcore_adapter_ops ops = {
		.enqueue_tx = enqueue_tx,
		.tx_free = tx_free,
		.submit_text = submit_text,
		.apply_pin = apply_pin,
		.resolve_peer_prefix = resolve_peer_prefix,
		.compat_settings = &s_compat_settings,
	};

	if (IS_ENABLED(CONFIG_LORA_LICHEN_MESHCORE_COMPAT_SETTINGS_PERSISTENCE)) {
		ops.persist_settings = persist_compat_settings;
	}
	return ops;
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

	if (!s_compat_settings.device_pin_valid &&
	    (pin == 0U || (pin >= 100000U && pin <= 999999U))) {
		s_compat_settings.device_pin = pin;
		s_compat_settings.device_pin_valid = true;
	}
}

static int apply_compat_pin(void)
{
	if (s_compat_settings.device_pin_valid) {
		return apply_pin(s_compat_settings.device_pin, NULL);
	}
	return 0;
}

#ifdef CONFIG_ZTEST
void gateway_meshcore_adapter_test_reset(void)
{
	struct lichen_meshcore_adapter_ops ops = adapter_ops();
	int ret;

	k_mutex_lock(&s_sink_mutex, K_FOREVER);
	s_sink_registered = false;
	k_mutex_unlock(&s_sink_mutex);

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	s_dispatch_epoch = 0U;
	s_adapter_epoch = ble_meshcore_session_epoch();
	s_command_dispatching = false;
	s_command_dispatch_thread = NULL;
	ret = clear_persisted_compat_settings();
	if (ret == 0) {
		ret = ensure_compat_settings_loaded();
	}
	s_test_reset_status = ret;
	if (ret == 0) {
		seed_default_compat_pin();
		ret = apply_compat_pin();
		s_test_reset_status = ret;
		if (ret == 0) {
			lichen_meshcore_adapter_init(&s_adapter, &ops);
		}
	}
	k_mutex_unlock(&s_adapter_mutex);
	if (ret == 0) {
		s_test_reset_status = ensure_app_sink();
	}
}

int gateway_meshcore_adapter_test_reset_status(void)
{
	return s_test_reset_status;
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

int gateway_meshcore_adapter_test_reload_compat_settings(void)
{
	struct lichen_meshcore_adapter_ops ops = adapter_ops();
	int ret;

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	ret = ensure_compat_settings_loaded();
	if (ret == 0) {
		seed_default_compat_pin();
		ret = apply_compat_pin();
		if (ret == 0) {
			lichen_meshcore_adapter_init(&s_adapter, &ops);
			s_adapter_epoch = ble_meshcore_session_epoch();
		}
	}
	k_mutex_unlock(&s_adapter_mutex);
	return ret;
}

int gateway_meshcore_adapter_test_corrupt_compat_settings(void)
{
	return corrupt_persisted_compat_settings();
}

int gateway_meshcore_adapter_test_write_invalid_compat_settings(void)
{
	return write_invalid_semantic_compat_settings();
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
	int ret;

	k_mutex_lock(&s_init_mutex, K_FOREVER);
	if (s_started) {
		k_mutex_unlock(&s_init_mutex);
		return 0;
	}

	k_mutex_lock(&s_adapter_mutex, K_FOREVER);
	s_adapter_epoch = ble_meshcore_session_epoch();
	ret = ensure_compat_settings_loaded();
	if (ret < 0) {
		k_mutex_unlock(&s_adapter_mutex);
		k_mutex_unlock(&s_init_mutex);
		return ret;
	}
	seed_default_compat_pin();
	ret = apply_compat_pin();
	if (ret < 0) {
		k_mutex_unlock(&s_adapter_mutex);
		k_mutex_unlock(&s_init_mutex);
		return ret;
	}
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
