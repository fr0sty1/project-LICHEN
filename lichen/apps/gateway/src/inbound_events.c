/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "inbound_events.h"

#include <errno.h>

#include <zephyr/sys/util.h>

#if IS_ENABLED(CONFIG_LICHEN_MESHTASTIC_ADAPTER)
#include "meshtastic_adapter.h"
#endif

int gateway_inbound_emit_text(const struct gateway_inbound_text_event *event)
{
	if (event == NULL) {
		return -EINVAL;
	}

#if IS_ENABLED(CONFIG_LICHEN_MESHTASTIC_ADAPTER)
	struct lichen_meshtastic_incoming_text meshtastic_event;

	meshtastic_event = (struct lichen_meshtastic_incoming_text){
		.from = event->from,
		.to = event->to,
		.id = event->id,
		.payload = event->payload,
		.payload_len = event->payload_len,
		.has_id = event->has_id,
	};

	return gateway_meshtastic_adapter_emit_text(&meshtastic_event);
#else
	ARG_UNUSED(event);
	return -ENOTSUP;
#endif
}

int gateway_inbound_emit_status(const struct gateway_inbound_status_event *event)
{
	if (event == NULL) {
		return -EINVAL;
	}

#if IS_ENABLED(CONFIG_LICHEN_MESHTASTIC_ADAPTER)
	struct lichen_meshtastic_incoming_status meshtastic_event;

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
#else
	ARG_UNUSED(event);
	return -ENOTSUP;
#endif
}
