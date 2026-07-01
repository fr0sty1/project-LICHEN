/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "inbound_coap.h"

#include <errno.h>
#include <stdint.h>

#include <zephyr/sys/util.h>

#include "inbound_events.h"

static uint8_t inbound_result_code(int ret)
{
	switch (ret) {
	case 0:
		return COAP_RESPONSE_CODE_CHANGED;
	case -EINVAL:
	case -EMSGSIZE:
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	case -ENOMEM:
	case -ENOTCONN:
	case -ENOTSUP:
		return COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE;
	default:
		return COAP_RESPONSE_CODE_INTERNAL_ERROR;
	}
}

int gateway_inbound_text_post(struct coap_resource *resource,
			      struct coap_packet *request,
			      struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	struct gateway_inbound_text_event event = {
		.from = 0U,
		.to = UINT32_MAX,
		.payload = payload,
		.payload_len = payload_len,
	};

	ARG_UNUSED(resource);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);

	return inbound_result_code(gateway_inbound_emit_text(&event));
}

static uint32_t inbound_read_be32(const uint8_t payload[4])
{
	return ((uint32_t)payload[0] << 24) |
	       ((uint32_t)payload[1] << 16) |
	       ((uint32_t)payload[2] << 8) |
	       (uint32_t)payload[3];
}

int gateway_inbound_status_post(struct coap_resource *resource,
				struct coap_packet *request,
				struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	struct gateway_inbound_status_event event = {
		.from = 0U,
		.to = UINT32_MAX,
	};

	ARG_UNUSED(resource);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);

	if (payload == NULL || payload_len != sizeof(uint32_t)) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}

	event.request_id = inbound_read_be32(payload);
	return inbound_result_code(gateway_inbound_emit_status(&event));
}

#ifdef CONFIG_LORA_LICHEN_MESHTASTIC_BLE
#include <zephyr/net/coap_service.h>

static const char * const inbound_text_path[] = { "inbound", "text", NULL };
COAP_RESOURCE_DEFINE(inbound_text, lichen_coap, {
	.post = gateway_inbound_text_post,
	.path = inbound_text_path,
});

static const char * const inbound_status_path[] = { "inbound", "status", NULL };
COAP_RESOURCE_DEFINE(inbound_status, lichen_coap, {
	.post = gateway_inbound_status_post,
	.path = inbound_status_path,
});
#endif /* CONFIG_LORA_LICHEN_MESHTASTIC_BLE */
