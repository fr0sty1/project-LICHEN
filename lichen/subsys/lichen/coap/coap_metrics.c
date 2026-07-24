/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>

#include <lichen/senml.h>
#include <lichen/coap_server.h>
#include <lichen/lora_l2.h>
#include <lichen/lichen_l2.h>

LOG_MODULE_REGISTER(lichen_coap_metrics, CONFIG_LICHEN_COAP_METRICS_LOG_LEVEL);

#define METRICS_SENML_MAX 256
#define BASE_NAME_MAX 32

static int64_t s_start_time_ms;

static void metrics_init_time(void)
{
	if (s_start_time_ms == 0) {
		s_start_time_ms = k_uptime_get();
	}
}

static int metrics_get(struct coap_resource *resource,
		       struct coap_packet *request,
		       struct sockaddr *addr, socklen_t addr_len)
{
	char base_name[BASE_NAME_MAX];
	uint8_t senml[METRICS_SENML_MAX];
	uint32_t tx_attempts, tx_errors, rx_frames, rx_accepted;
	int tx_last_err, rx_last_err;
	uint8_t eui[8];
	int64_t uptime_ms;
	float uptime_s;
	int len, ret;

	metrics_init_time();

	uptime_ms = k_uptime_delta(&s_start_time_ms);
	s_start_time_ms = k_uptime_get();
	uptime_s = uptime_ms > 0 ? (float)(uptime_ms) / 1000.0f : 1.0f;

	lichen_l2_get_tx_stats(&tx_attempts, &tx_errors, &tx_last_err);
	lichen_l2_get_rx_stats(&rx_frames, &rx_accepted, &rx_last_err);

	(void)tx_last_err;
	(void)rx_last_err;

	base_name[0] = '\0';
	if (lichen_lora_l2_copy_eui64(eui) == 0) {
		snprintf(base_name, sizeof(base_name),
			 "urn:dev:mac:%02x%02x%02x%02x%02x%02x%02x%02x:",
			 eui[0], eui[1], eui[2], eui[3],
			 eui[4], eui[5], eui[6], eui[7]);
	}

	struct senml_pack pack;
	ret = senml_pack_init(&pack,
			      base_name[0] != '\0' ? base_name : NULL,
			      k_uptime_get() / 1000U);
	if (ret < 0) {
		LOG_ERR("senml_pack_init failed: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	ret = senml_add_float(&pack, "pkt_tx", NULL, (float)tx_attempts);
	if (ret < 0) goto encode_err;

	ret = senml_add_float(&pack, "pkt_rx", NULL, (float)rx_frames);
	if (ret < 0) goto encode_err;

	ret = senml_add_float(&pack, "tx_fail", NULL, (float)tx_errors);
	if (ret < 0) goto encode_err;

	ret = senml_add_float(&pack, "rx_accepted", NULL, (float)rx_accepted);
	if (ret < 0) goto encode_err;

	ret = senml_add_float(&pack, "rx_dropped", NULL,
			      (float)(rx_frames - rx_accepted));
	if (ret < 0) goto encode_err;

	float pkt_rate = (float)(tx_attempts + rx_frames) / uptime_s;
	ret = senml_add_float(&pack, "pkt_rate", NULL, pkt_rate);
	if (ret < 0) goto encode_err;

	ret = senml_add_float(&pack, "uptime_s", "s", k_uptime_get() / 1000.0f);
	if (ret < 0) goto encode_err;

	ret = senml_add_float(&pack, "total_packets", NULL,
			      (float)(tx_attempts + rx_frames));
	if (ret < 0) goto encode_err;

	len = senml_encode_cbor(&pack, senml, sizeof(senml));
	if (len < 0) {
		LOG_ERR("senml_encode_cbor failed: %d", len);
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, SENML_CBOR_CONTENT_FORMAT,
			    senml, (size_t)len);

encode_err:
	LOG_ERR("senml_add_float failed: %d", ret);
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
}

static const char *const metrics_path[] = { "metrics", NULL };

COAP_RESOURCE_DEFINE(lichen_metrics, lichen_coap_server, {
	.get = metrics_get,
	.path = metrics_path,
});
