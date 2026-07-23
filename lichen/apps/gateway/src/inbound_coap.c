/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "inbound_coap.h"

#include <errno.h>
#include <stdint.h>

#include <zephyr/net/net_ip.h>
#include <zephyr/sys/util.h>

#include <lichen/app_interface/app_interface.h>

#if IS_ENABLED(CONFIG_LICHEN_HAL)
#include <lichen/app_interface/hal_bridge.h>
#endif

#if IS_ENABLED(CONFIG_LORA_LICHEN_BLE) || \
	IS_ENABLED(CONFIG_LICHEN_INBOUND_LOCATION_TEST_SURFACE)
#include "ble_lci_netif.h"
#endif

#include "inbound_events.h"

#define INBOUND_LOCATION_PAYLOAD_VERSION 1U
#define INBOUND_LOCATION_FLAG_ALTITUDE BIT(0)
#define INBOUND_LOCATION_FLAG_FIX_TIME BIT(1)
#define INBOUND_LOCATION_FLAG_SATELLITES BIT(2)
#define INBOUND_LOCATION_FLAG_HORIZONTAL_ACCURACY BIT(3)
#define INBOUND_LOCATION_FLAG_VERTICAL_ACCURACY BIT(4)
#define INBOUND_LOCATION_FLAG_AGE_SECONDS BIT(5)
#define INBOUND_LOCATION_KNOWN_FLAGS \
	(INBOUND_LOCATION_FLAG_ALTITUDE | INBOUND_LOCATION_FLAG_FIX_TIME | \
	 INBOUND_LOCATION_FLAG_SATELLITES | \
	 INBOUND_LOCATION_FLAG_HORIZONTAL_ACCURACY | \
	 INBOUND_LOCATION_FLAG_VERTICAL_ACCURACY | INBOUND_LOCATION_FLAG_AGE_SECONDS)
#define INBOUND_LOCATION_BASE_LEN 10U

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

static int32_t inbound_read_be_i32_twos_complement(const uint8_t payload[4])
{
	uint32_t raw = inbound_read_be32(payload);

	if ((raw & BIT(31)) == 0U) {
		return (int32_t)raw;
	}

	return -1 - (int32_t)(UINT32_MAX - raw);
}

static bool inbound_source_is_local_client(const struct sockaddr *addr,
					   socklen_t addr_len)
{
	const struct sockaddr_in6 *in6;

	if (addr == NULL) {
		return IS_ENABLED(CONFIG_ZTEST);
	}
	if (addr_len < sizeof(struct sockaddr_in6) ||
	    addr->sa_family != AF_INET6) {
		return false;
	}

	in6 = (const struct sockaddr_in6 *)addr;
	if (net_ipv6_is_addr_loopback((struct in6_addr *)&in6->sin6_addr)) {
		return true;
	}
#if IS_ENABLED(CONFIG_LORA_LICHEN_BLE) || \
	IS_ENABLED(CONFIG_LICHEN_INBOUND_LOCATION_TEST_SURFACE)
	if (net_ipv6_is_ll_addr(&in6->sin6_addr)) {
		struct net_if *iface = ble_lci_netif_get();

		return iface != NULL &&
		       in6->sin6_scope_id == net_if_get_by_iface(iface);
	}
#endif

	return false;
}

static int inbound_location_read_u32(const uint8_t *payload,
				     uint16_t payload_len, uint16_t *pos,
				     uint32_t *out)
{
	if (*pos > payload_len || payload_len - *pos < sizeof(uint32_t)) {
		return -EINVAL;
	}

	*out = inbound_read_be32(&payload[*pos]);
	*pos += sizeof(uint32_t);
	return 0;
}

static int inbound_location_read_i32(const uint8_t *payload,
				     uint16_t payload_len, uint16_t *pos,
				     int32_t *out)
{
	if (*pos > payload_len || payload_len - *pos < sizeof(uint32_t)) {
		return -EINVAL;
	}

	*out = inbound_read_be_i32_twos_complement(&payload[*pos]);
	*pos += sizeof(uint32_t);
	return 0;
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

int gateway_inbound_location_post(struct coap_resource *resource,
				  struct coap_packet *request,
				  struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len = 0;
	uint16_t pos = 0U;
	uint8_t flags;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	struct lichen_app_location_time_snapshot location = {
		.source_class_valid = true,
		.source_class = LICHEN_APP_LOCATION_SOURCE_LOCAL_CLIENT,
		.fix_state_valid = true,
	};
	int ret;

	ARG_UNUSED(resource);

	if (payload == NULL || payload_len < INBOUND_LOCATION_BASE_LEN ||
	    payload[0] != INBOUND_LOCATION_PAYLOAD_VERSION) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}
	if (!inbound_source_is_local_client(addr, addr_len)) {
		return COAP_RESPONSE_CODE_FORBIDDEN;
	}

	flags = payload[1];
	if ((flags & ~INBOUND_LOCATION_KNOWN_FLAGS) != 0U) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}
	location.fix_state = (enum lichen_app_location_fix_state)payload[2];
	if (payload[3] != 0U) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}
	pos = 4U;

	location.latitude_e7_valid = true;
	ret = inbound_location_read_i32(payload, payload_len, &pos,
					&location.latitude_e7);
	if (ret < 0) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}
	location.longitude_e7_valid = true;
	ret = inbound_location_read_i32(payload, payload_len, &pos,
					&location.longitude_e7);
	if (ret < 0) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}

	if ((flags & INBOUND_LOCATION_FLAG_ALTITUDE) != 0U) {
		location.altitude_m_valid = true;
		ret = inbound_location_read_i32(payload, payload_len, &pos,
						&location.altitude_m);
		if (ret < 0) {
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
	}
	if ((flags & INBOUND_LOCATION_FLAG_FIX_TIME) != 0U) {
		uint32_t fix_time_unix;

		location.fix_time_unix_valid = true;
		ret = inbound_location_read_u32(payload, payload_len, &pos,
						&fix_time_unix);
		if (ret < 0) {
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
		location.fix_time_unix = fix_time_unix;
	}
	if ((flags & INBOUND_LOCATION_FLAG_SATELLITES) != 0U) {
		if (pos >= payload_len) {
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
		location.satellites_valid = true;
		location.satellites = payload[pos++];
	}
	if ((flags & INBOUND_LOCATION_FLAG_HORIZONTAL_ACCURACY) != 0U) {
		location.horizontal_accuracy_mm_valid = true;
		ret = inbound_location_read_u32(
			payload, payload_len, &pos,
			&location.horizontal_accuracy_mm);
		if (ret < 0) {
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
	}
	if ((flags & INBOUND_LOCATION_FLAG_VERTICAL_ACCURACY) != 0U) {
		location.vertical_accuracy_mm_valid = true;
		ret = inbound_location_read_u32(payload, payload_len, &pos,
						&location.vertical_accuracy_mm);
		if (ret < 0) {
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
	}
	if ((flags & INBOUND_LOCATION_FLAG_AGE_SECONDS) != 0U) {
		location.age_seconds_valid = true;
		ret = inbound_location_read_u32(payload, payload_len, &pos,
						&location.age_seconds);
		if (ret < 0) {
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
	}
	if (pos != payload_len) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}

#if IS_ENABLED(CONFIG_LICHEN_HAL)
	return inbound_result_code(lichen_app_location_submit_to_hal(&location));
#else
	return COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE;
#endif
}

#if IS_ENABLED(CONFIG_LORA_LICHEN_MESHTASTIC_BLE) || \
	IS_ENABLED(CONFIG_LICHEN_MESHTASTIC_GATEWAY_ADAPTER_TEST_SURFACE)
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
#endif

#if IS_ENABLED(CONFIG_LICHEN_INBOUND_LOCATION_TEST_SURFACE) || \
	IS_ENABLED(CONFIG_LICHEN_MESHTASTIC_GATEWAY_ADAPTER_TEST_SURFACE)
#include <zephyr/net/coap_service.h>

static const char * const inbound_location_path[] = {
	"inbound", "location", NULL
};
COAP_RESOURCE_DEFINE(inbound_location, lichen_coap, {
	.post = gateway_inbound_location_post,
	.path = inbound_location_path,
});
#endif
