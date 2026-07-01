/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "inbound_events.h"

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/app_interface/app_interface.h>

#if IS_ENABLED(CONFIG_LICHEN_MESHTASTIC_ADAPTER)
#include "meshtastic_adapter.h"
#endif

#if IS_ENABLED(CONFIG_LICHEN_MESHTASTIC_ADAPTER)
static K_MUTEX_DEFINE(s_sink_mutex);
static bool s_sink_registered;
static uint8_t s_sink_id;

static int meshtastic_text_sink(const struct lichen_app_text_event *event,
				void *user_data)
{
	struct lichen_meshtastic_incoming_text meshtastic_event;

	ARG_UNUSED(user_data);

	meshtastic_event = (struct lichen_meshtastic_incoming_text){
		.from = event->from,
		.to = event->to,
		.id = event->id,
		.payload = event->payload,
		.payload_len = event->payload_len,
		.has_id = event->has_id,
	};

	return gateway_meshtastic_adapter_emit_text(&meshtastic_event);
}

static int meshtastic_status_sink(const struct lichen_app_status_event *event,
				  void *user_data)
{
	struct lichen_meshtastic_incoming_status meshtastic_event;

	ARG_UNUSED(user_data);

	meshtastic_event = (struct lichen_meshtastic_incoming_status){
		.from = event->from,
		.to = event->to,
		.id = event->id,
		.request_id = event->request_id,
		.error_reason = event->error_reason,
		.has_id = event->has_id,
		.has_error_reason = event->has_error_reason,
	};

	return gateway_meshtastic_adapter_emit_status(&meshtastic_event);
}

static int ensure_meshtastic_sink(void)
{
	const struct lichen_app_interface_sink sink = {
		.emit_text = meshtastic_text_sink,
		.emit_status = meshtastic_status_sink,
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

#ifdef CONFIG_ZTEST
void gateway_inbound_events_test_reset(void)
{
	k_mutex_lock(&s_sink_mutex, K_FOREVER);
	if (s_sink_registered) {
		(void)lichen_app_interface_unregister_sink(s_sink_id);
		s_sink_registered = false;
	}
	k_mutex_unlock(&s_sink_mutex);
}
#endif
#else
static int ensure_meshtastic_sink(void)
{
	return 0;
}

#ifdef CONFIG_ZTEST
void gateway_inbound_events_test_reset(void)
{
}
#endif
#endif

int gateway_inbound_emit_text(const struct gateway_inbound_text_event *event)
{
	struct lichen_app_text_event app_event;
	int ret;

	if (event == NULL) {
		return -EINVAL;
	}

	ret = ensure_meshtastic_sink();
	if (ret < 0) {
		return ret;
	}

	app_event = (struct lichen_app_text_event){
		.from = event->from,
		.to = event->to,
		.id = event->id,
		.payload = event->payload,
		.payload_len = event->payload_len,
		.has_id = event->has_id,
	};

	return lichen_app_interface_emit_text(&app_event);
}

int gateway_inbound_emit_status(const struct gateway_inbound_status_event *event)
{
	struct lichen_app_status_event app_event;
	int ret;

	if (event == NULL) {
		return -EINVAL;
	}

	ret = ensure_meshtastic_sink();
	if (ret < 0) {
		return ret;
	}

	app_event = (struct lichen_app_status_event){
		.from = event->from,
		.to = event->to,
		.id = event->id,
		.request_id = event->request_id,
		.error_reason = event->error_reason,
		.has_id = event->has_id,
		.has_error_reason = event->has_error_reason,
	};

	return lichen_app_interface_emit_status(&app_event);
}
