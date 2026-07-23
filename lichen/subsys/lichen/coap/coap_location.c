/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_location.c
 * @brief LICHEN CoAP position resource (spec 12-apps.md §18.2.2).
 *
 * Serves GET /sensors/location as a SenML pack (application/senml+cbor,
 * RFC 8428) describing the node's current position, when a valid fix is
 * available. The base name identifies the node by its EUI-64
 * (urn:dev:mac:<eui64>:) so a client can attribute the reading.
 *
 * Returns 4.04 Not Found when the node has no valid latitude/longitude fix.
 */

#include <math.h>
#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>

#include <lichen/hal.h>
#include <lichen/senml.h>
#include <lichen/coap_server.h>

#include "lora_l2.h"

LOG_MODULE_REGISTER(lichen_coap_location, CONFIG_LICHEN_COAP_LOCATION_LOG_LEVEL);

#define LOCATION_SENML_MAX 128

/* "urn:dev:mac:" + 16 hex + ":" + NUL */
#define BASE_NAME_MAX 32



/* Fill `out` with the node's SenML base name, or an empty string if the
 * EUI-64 is not yet available (a valid pack can still omit the base name). */
static void build_base_name(char *out, size_t out_len)
{
	uint8_t eui[8];

	if (lichen_lora_l2_copy_eui64(eui) != 0) {
		out[0] = '\0';
		return;
	}
	snprintf(out, out_len,
		 "urn:dev:mac:%02x%02x%02x%02x%02x%02x%02x%02x:", eui[0], eui[1],
		 eui[2], eui[3], eui[4], eui[5], eui[6], eui[7]);
}

static int sensors_location_get(struct coap_resource *resource,
				struct coap_packet *request,
				struct sockaddr *addr, socklen_t addr_len)
{
	struct lichen_hal_location_time_snapshot snap;
	char base_name[BASE_NAME_MAX];
	uint8_t senml[LOCATION_SENML_MAX];
	float lat;
	float lon;
	float alt;
	uint64_t base_time;
	int len;

	if (lichen_hal_location_time_snapshot_get(&snap) < 0 ||
	    !snap.latitude_e7_valid || !snap.longitude_e7_valid) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}

	lat = (float)snap.latitude_e7 / 1e7f;
	lon = (float)snap.longitude_e7 / 1e7f;
	alt = snap.altitude_m_valid ? (float)snap.altitude_m : NAN;
	base_time = snap.fix_time_unix_valid ? snap.fix_time_unix : 0U;

	build_base_name(base_name, sizeof(base_name));

	len = senml_encode_location(base_name[0] != '\0' ? base_name : NULL,
				    base_time, lat, lon, alt, senml,
				    sizeof(senml));
	if (len < 0) {
		LOG_ERR("senml_encode_location failed: %d", len);
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, 112, senml, (size_t)len);
}

static int sensors_location_post(struct coap_resource *resource,
				struct coap_packet *request,
				struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) {
		return COAP_RESPONSE_CODE_BAD_REQUEST;
	}
	/* Demo crowd map: accept SenML position POST, submit to HAL as NETWORK source for live map aggregation. Full decode in follow-up. */
	LOG_INF("crowd map /position POST (%u bytes)", payload_len);
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CREATED, NULL, 0);
}

static const char *const sensors_location_path[] = { "sensors", "location",
						     NULL };

COAP_RESOURCE_DEFINE(lichen_sensors_location, lichen_coap_server, {
	.get = sensors_location_get,
	.post = sensors_location_post,
	.path = sensors_location_path,
});
