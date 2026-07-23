/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/sys/util.h>
#if IS_ENABLED(CONFIG_LORA)
#include <zephyr/drivers/lora.h>
#endif
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap_service.h>

#include <lichen/hal.h>
#if IS_ENABLED(CONFIG_LORA_LICHEN_GATEWAY_RPL_ROOT)
#include "rpl_root.h"
#include <lichen/l2/ipv6_addr.h>
#include <lichen/l2/lora_l2.h>
#include <zephyr/net/net_if.h>
#endif

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
#include "lora_l2.h"
#endif

#if IS_ENABLED(CONFIG_LICHEN_L2)
#include "lichen_l2.h"
#include <lichen/coap_client.h>
#endif

#include "config_apply.h"
#include "config_cbor.h"
#include "status_cbor.h"

#ifdef CONFIG_LORA_LICHEN_BLE
#include "ble_uart.h"
#endif

#ifdef CONFIG_LORA_LICHEN_MESHTASTIC_BLE
#include "ble_meshtastic.h"
#include "message_contract.h"
#include "meshtastic_adapter.h"
#endif

#ifdef CONFIG_LORA_LICHEN_MESHCORE_BLE
#include "ble_meshcore.h"
#include "gateway_identity.h"
#include "message_contract.h"
#include "meshcore_adapter.h"
#endif

#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
#include <lichen/native.h>
#endif

#if IS_ENABLED(CONFIG_LICHEN_GATEWAY_PREFIX_DELEGATION)
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_event.h>
#endif

LOG_MODULE_REGISTER(lichen_gateway, LOG_LEVEL_INF);

#define LICHEN_GATEWAY_HAS_LORA \
	IS_ENABLED(CONFIG_LICHEN_HAS_LORA)

/*
 * Manual LoRa handling (non-L2 mode).
 *
 * When CONFIG_LICHEN_L2 is enabled, the L2 layer handles all LoRa
 * initialization and RX via its own thread. These definitions are only
 * needed for direct LoRa testing without the full network stack.
 */
#if !IS_ENABLED(CONFIG_LICHEN_L2) && LICHEN_GATEWAY_HAS_LORA
/* LoRa parameters per LICHEN spec: SF10 / 125 kHz / CR4-5.
 * Frequency is region-dependent; 915 MHz (US915) is the default.
 * Override per board via a board-specific Kconfig once that lands. */
#define LORA_FREQ_HZ     915000000U
#define LORA_MAX_FRAME   255
#define LORA_RX_STACKSZ  1024
#define LORA_RX_PRIORITY 7

/* Set by main() after lora_config() succeeds; read by the RX thread. */
static const struct device *s_lora_dev;
static K_SEM_DEFINE(s_radio_ready, 0, 1);
#endif /* !CONFIG_LICHEN_L2 && LICHEN_GATEWAY_HAS_LORA */

/* CBOR content-format code (RFC 7252 §12.3 / IANA CoAP Content-Formats) */
#define CBOR_CONTENT_FORMAT 60
#define LICHEN_GATEWAY_STATUS_COAP_OVERHEAD 64U

BUILD_ASSERT(CONFIG_COAP_SERVER_MESSAGE_SIZE >=
	     LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE +
	     LICHEN_GATEWAY_STATUS_COAP_OVERHEAD,
	     "gateway status CoAP buffer must fit CBOR body plus options");

#if IS_ENABLED(CONFIG_LORA_LICHEN_GATEWAY_RPL_ROOT)
#define LICHEN_GATEWAY_STATUS_ROLE "root"
#define LICHEN_GATEWAY_STATUS_RPL_CAPABLE true
#define LICHEN_GATEWAY_STATUS_RANK 256
#else
#define LICHEN_GATEWAY_STATUS_ROLE "gateway"
#define LICHEN_GATEWAY_STATUS_RPL_CAPABLE false
#define LICHEN_GATEWAY_STATUS_RANK 0xffff
#endif

/* Mutable gateway config — written by PUT /config */
static int8_t s_tx_power_dbm = 14;
static struct lichen_gateway_manual_location_config s_manual_location;
static bool s_has_manual_location;

#if IS_ENABLED(CONFIG_LORA_LICHEN_GATEWAY_RPL_ROOT)
static struct lichen_rpl_root s_rpl_root;
static struct k_work_delayable s_rpl_tick_work;

static void rpl_tick_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	lichen_rpl_root_tick(&s_rpl_root, k_uptime_get_32());
	k_work_schedule(&s_rpl_tick_work, K_MSEC(CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS / 4));
}
#endif

#if IS_ENABLED(CONFIG_LICHEN_GATEWAY_PREFIX_DELEGATION)
static bool s_backhaul_connected = false;
static struct net_mgmt_event_callback s_wifi_mgmt_cb;
#endif

static int gateway_rpl_init(void) {
	int ret = 0;
#if IS_ENABLED(CONFIG_LORA_LICHEN_GATEWAY_RPL_ROOT)
	uint8_t dodag_id[16] = {0};
	uint8_t self_eui64[8];
	uint8_t iid[8];
	struct in6_addr ll_addr;

	if (IS_ENABLED(CONFIG_LICHEN_GATEWAY_PREFIX_DELEGATION)) {
		dodag_id[0] = 0xfd;
		dodag_id[1] = 0x00;
	} else {
		dodag_id[0] = 0xfd;
	}
	dodag_id[15] = 0x01;

	ret = lichen_lora_l2_copy_eui64(self_eui64);
	if (ret != 0) {
		LOG_ERR("failed to read self EUI64: %d", ret);
		return ret;
	}
	ret = lichen_eui64_to_iid(self_eui64, iid);
	if (ret != 0) {
		return ret;
	}
	ret = lichen_make_link_local(iid, &ll_addr);
	if (ret != 0) {
		return ret;
	}

	struct lichen_rpl_root *rp = lichen_rpl_root_init(
		&s_rpl_root, net_if_get_default(), dodag_id, ll_addr.s6_addr);
	if (rp == NULL) {
		LOG_ERR("lichen_rpl_root_init failed");
		return -EINVAL;
	}
	LOG_INF("RPL DODAG root initialized (rank=%u, role=ROOT)", s_rpl_root.dodag.rank);

	k_work_init_delayable(&s_rpl_tick_work, rpl_tick_handler);
	k_work_schedule(&s_rpl_tick_work, K_MSEC(CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS / 4));
#endif
	return ret;
}

#if IS_ENABLED(CONFIG_LICHEN_GATEWAY_PREFIX_DELEGATION)
/*
 * WiFi station backhaul event handler per Kconfig and AGENTS.md.
 * Registers early, handles connect result and IPv6 addr add for prefix
 * delegation to RPL DODAG root. Updates observable status on change.
 */
static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb,
				    uint32_t mgmt_event, struct net_if *iface)
{
	ARG_UNUSED(iface);

	if (mgmt_event == NET_EVENT_WIFI_CONNECT_RESULT) {
		const struct wifi_status *status =
			(const struct wifi_status *)cb->info;
		if (status->status == 0) {  /* success per Zephyr wifi_mgmt */
			s_backhaul_connected = true;
			LOG_INF("WiFi backhaul connected to %s", CONFIG_LICHEN_GATEWAY_WIFI_SSID);
		} else {
			s_backhaul_connected = false;
			LOG_ERR("WiFi connect failed: status=%d", status->status);
		}
	} else if (mgmt_event == NET_EVENT_IPV6_ADDR_ADD) {
		s_backhaul_connected = true;
		LOG_INF("IPv6 address added on backhaul - prefix delegation to RPL active");
		/* TODO: extract prefix from iface and call lichen_rpl_root_set_prefix(&s_dodag, ...) */
	}

	/* Status observable will reflect s_backhaul_connected on next GET/notify */
}

static void gateway_backhaul_init(void)
{
	net_mgmt_init_event_callback(&s_wifi_mgmt_cb, wifi_mgmt_event_handler,
		NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_IPV6_ADDR_ADD);
	net_mgmt_add_event_callback(&s_wifi_mgmt_cb);

	struct net_if *iface = net_if_get_wifi_sta();
	if (iface == NULL) {
		LOG_WRN("No WiFi STA interface - backhaul unavailable");
		return;
	}

	if (net_if_is_up(iface) == false) {
		net_if_up(iface);
	}

	struct wifi_connect_req_params params = {
		.ssid = CONFIG_LICHEN_GATEWAY_WIFI_SSID,
		.ssid_length = strlen(CONFIG_LICHEN_GATEWAY_WIFI_SSID),
		.psk = CONFIG_LICHEN_GATEWAY_WIFI_PSK,
		.psk_length = strlen(CONFIG_LICHEN_GATEWAY_WIFI_PSK),
		.security = (strlen(CONFIG_LICHEN_GATEWAY_WIFI_PSK) > 0)
				? WIFI_SECURITY_TYPE_PSK : WIFI_SECURITY_TYPE_NONE,
		.channel = WIFI_CHANNEL_ANY,
		.mfp = WIFI_MFP_OPTIONAL,
	};

	int ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &params, sizeof(params));
	if (ret < 0) {
		LOG_ERR("WiFi connect request failed: %d", ret);
	} else {
		LOG_INF("WiFi station mode requested for SSID %s (prefix delegation enabled)", CONFIG_LICHEN_GATEWAY_WIFI_SSID);
	}
}
#endif /* CONFIG_LICHEN_GATEWAY_PREFIX_DELEGATION */

 /* --------------------------------------------------------------------------
 * CBOR helpers
 * -------------------------------------------------------------------------- */


/*
 * Build a minimal CoAP response and send it.
 * Pass payload=NULL / payload_len=0 for responses with no body.
 */
static int coap_respond(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len,
			uint8_t resp_code,
			const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
		       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int r;

	r = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1,
			     type, tkl, token, resp_code,
			     coap_header_get_id(request));
	if (r < 0) {
		return r;
	}

	if (payload && payload_len > 0) {
		r = coap_append_option_int(&resp, COAP_OPTION_CONTENT_FORMAT,
					   CBOR_CONTENT_FORMAT);
		if (r < 0) {
			return r;
		}
		r = coap_packet_append_payload_marker(&resp);
		if (r < 0) {
			return r;
		}
		r = coap_packet_append_payload(&resp, payload, payload_len);
		if (r < 0) {
			return r;
		}
	}

	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}

/* --------------------------------------------------------------------------
 * /status (Observable)
 * -------------------------------------------------------------------------- */

/*
 * Build CBOR status with explicit power-provider availability and only valid
 * measured power fields. Returns encoded byte count.
 */
static size_t encode_status_cbor(uint8_t *buf, size_t buf_size, uint16_t rank,
				 const char *role, bool rpl_capable)
{
	struct lichen_hal_power_snapshot power;
	struct lichen_hal_location_time_snapshot location_time;
	struct lichen_hal_time_snapshot time;
	uint32_t uptime_ms = k_uptime_get_32();

	(void)lichen_hal_power_snapshot_get(&power);
	(void)lichen_hal_location_time_snapshot_get(&location_time);
	(void)lichen_hal_time_snapshot_get(&time);
	return lichen_gateway_encode_status_cbor(
		buf, buf_size, rank, role, rpl_capable, uptime_ms, &power,
		&location_time, &time);
}

/* Gateway status state (observable) */
static uint16_t s_rank = LICHEN_GATEWAY_STATUS_RANK;

/*
 * Respond with Block2 slicing (RFC 7959) when the payload will not fit a
 * single LICHEN L2 frame. 128-byte blocks keep each response packet well
 * under the 240-byte L2 MTU after CoAP/UDP/IPv6 headers; small payloads
 * still go out as one plain response.
 */
#define COAP_BLOCK2_SINGLE_MAX 128U

static int coap_respond_block2(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len,
			       const uint8_t *payload, size_t payload_len)
{
	struct coap_block_context ctx;
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
		       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int block2 = coap_get_option_int(request, COAP_OPTION_BLOCK2);
	size_t chunk;
	int r;

	if (block2 < 0 && payload_len <= COAP_BLOCK2_SINGLE_MAX) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_CONTENT,
				    payload, payload_len);
	}

	enum coap_block_size blk = COAP_BLOCK_128;

	if (block2 >= 0 && GET_BLOCK_SIZE(block2) < (int)blk) {
		/* Serve at the client's (smaller) block size so its block
		 * numbering stays aligned (RFC 7959 §2.4). Anything <= 128
		 * fits the L2 MTU. */
		blk = (enum coap_block_size)GET_BLOCK_SIZE(block2);
	}
	coap_block_transfer_init(&ctx, blk, payload_len);
	if (block2 >= 0) {
		ctx.current = GET_BLOCK_NUM(block2) *
			      coap_block_size_to_bytes(blk);
	}
	if (ctx.current >= payload_len) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_OPTION, NULL, 0);
	}

	r = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1,
			     type, tkl, token, COAP_RESPONSE_CODE_CONTENT,
			     coap_header_get_id(request));
	if (r < 0) {
		return r;
	}
	r = coap_append_option_int(&resp, COAP_OPTION_CONTENT_FORMAT,
				   CBOR_CONTENT_FORMAT);
	if (r < 0) {
		return r;
	}
	r = coap_append_block2_option(&resp, &ctx);
	if (r < 0) {
		return r;
	}
	r = coap_packet_append_payload_marker(&resp);
	if (r < 0) {
		return r;
	}
	chunk = MIN((size_t)coap_block_size_to_bytes(blk),
		    payload_len - ctx.current);
	r = coap_packet_append_payload(&resp, payload + ctx.current, chunk);
	if (r < 0) {
		return r;
	}

	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}

static int status_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	size_t len = encode_status_cbor(cbor_buf, sizeof(cbor_buf), s_rank,
					LICHEN_GATEWAY_STATUS_ROLE,
					LICHEN_GATEWAY_STATUS_RPL_CAPABLE);

	/*
	 * RX1-style response delay (lora_ipv6_mesh-fe1z). The requesting puck is
	 * a half-duplex node switching its radio from TX (the GET it just sent)
	 * to RX. The gateway answers within <1 ms, so without a gap the reply
	 * lands during the puck's TX->RX turnaround and is missed — confirmed on
	 * the T1000-E (LR1110), which never received its own replies. Wait, like
	 * LoRaWAN Class-A RX1, so the reply arrives after the puck is listening.
	 * The T-Echo (SX1262) turns around fast enough not to need it, but the
	 * delay is harmless for it.
	 */
	/* Compile-time guard: with the default 0, K_MSEC(0) -> MAX(0, 0) trips
	 * bugprone-branch-clone, so drop the call entirely when disabled. */
#if CONFIG_LICHEN_GATEWAY_RX1_DELAY_MS > 0
	k_sleep(K_MSEC(CONFIG_LICHEN_GATEWAY_RX1_DELAY_MS));
#endif

	/* Diagnostic (lora_ipv6_mesh-fe1z): which peer's GET reached the server,
	 * and did the response send succeed? IID last 2 bytes = EUI tail
	 * (..2c:ab = T1000-E, ..2c:10 = T-Echo). */
	int _rr = coap_respond_block2(resource, request, addr, addr_len,
				      cbor_buf, len);
	if (addr != NULL && addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *_a6 = (const struct sockaddr_in6 *)addr;

		LOG_INF("status GET from ..%02x:%02x -> respond %zu B ret=%d",
			_a6->sin6_addr.s6_addr[14], _a6->sin6_addr.s6_addr[15],
			len, _rr);
	}
	return _rr;
}

/*
 * Notify callback for Observe (RFC 7641).
 * Called by coap_resource_notify() when we want to push updates to observers.
 */
static void status_notify(struct coap_resource *resource,
			  struct coap_observer *observer)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t cbor_buf[LICHEN_GATEWAY_STATUS_CBOR_MAX_SIZE];
	struct coap_packet notif;
	size_t cbor_len;
	int r;

	cbor_len = encode_status_cbor(cbor_buf, sizeof(cbor_buf), s_rank,
				      LICHEN_GATEWAY_STATUS_ROLE,
				      LICHEN_GATEWAY_STATUS_RPL_CAPABLE);
	if (cbor_len == 0) {
		return;
	}

	r = coap_packet_init(&notif, buf, sizeof(buf), COAP_VERSION_1,
			     COAP_TYPE_NON_CON,
			     observer->tkl, observer->token,
			     COAP_RESPONSE_CODE_CONTENT, 0);
	if (r < 0) {
		return;
	}

	/* Add Observe option with the resource age */
	r = coap_append_option_int(&notif, COAP_OPTION_OBSERVE, resource->age);
	if (r < 0) {
		return;
	}

	r = coap_append_option_int(&notif, COAP_OPTION_CONTENT_FORMAT,
				   CBOR_CONTENT_FORMAT);
	if (r < 0) {
		return;
	}

	r = coap_packet_append_payload_marker(&notif);
	if (r < 0) {
		return;
	}

	r = coap_packet_append_payload(&notif, cbor_buf, cbor_len);
	if (r < 0) {
		return;
	}

	(void)coap_resource_send(resource, &notif,
				 &observer->addr, sizeof(observer->addr), NULL);
}

static const char * const status_path[] = { "status", NULL };
COAP_RESOURCE_DEFINE(status, lichen_coap, {
	.get    = status_get,
	.notify = status_notify,
	.path   = status_path,
});

/* --------------------------------------------------------------------------
 * /status/queues (Observable)
 * -------------------------------------------------------------------------- */

/*
 * Get queue statistics from the L2 TX queue.
 * Converts from tx_queue_stats to lichen_gateway_queue_stats.
 */
static void get_queue_stats(struct lichen_gateway_queue_stats *stats)
{
	memset(stats, 0, sizeof(*stats));

#if IS_ENABLED(CONFIG_LICHEN_LORA_L2)
	struct tx_queue_stats tx_stats;

	if (lichen_lora_l2_queue_stats_get(&tx_stats) == 0) {
		stats->packets_queued = tx_stats.packets_queued;
		stats->packets_dropped_deadline = tx_stats.packets_dropped_deadline;
		stats->packets_dropped_full = tx_stats.packets_dropped_full;
		stats->max_latency_ms = tx_stats.max_latency_ms;
		/*
		 * avg_latency_ms is not tracked by tx_queue - would require
		 * storing enqueue timestamps and computing exponential average.
		 * Left as 0 for now; can be added to tx_queue if needed.
		 */
		stats->avg_latency_ms = 0;
	}
#endif
}

static int queues_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[LICHEN_GATEWAY_QUEUES_CBOR_MAX_SIZE];
	struct lichen_gateway_queue_stats stats;
	size_t len;

	get_queue_stats(&stats);
	len = lichen_gateway_encode_queues_cbor(cbor_buf, sizeof(cbor_buf),
						&stats);
	if (len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

static void queues_notify(struct coap_resource *resource,
			  struct coap_observer *observer)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t cbor_buf[LICHEN_GATEWAY_QUEUES_CBOR_MAX_SIZE];
	struct coap_packet notif;
	struct lichen_gateway_queue_stats stats;
	size_t cbor_len;
	int r;

	get_queue_stats(&stats);
	cbor_len = lichen_gateway_encode_queues_cbor(cbor_buf, sizeof(cbor_buf),
						     &stats);
	if (cbor_len == 0) {
		return;
	}

	r = coap_packet_init(&notif, buf, sizeof(buf), COAP_VERSION_1,
			     COAP_TYPE_NON_CON,
			     observer->tkl, observer->token,
			     COAP_RESPONSE_CODE_CONTENT, 0);
	if (r < 0) {
		return;
	}

	r = coap_append_option_int(&notif, COAP_OPTION_OBSERVE, resource->age);
	if (r < 0) {
		return;
	}

	r = coap_append_option_int(&notif, COAP_OPTION_CONTENT_FORMAT,
				   CBOR_CONTENT_FORMAT);
	if (r < 0) {
		return;
	}

	r = coap_packet_append_payload_marker(&notif);
	if (r < 0) {
		return;
	}

	r = coap_packet_append_payload(&notif, cbor_buf, cbor_len);
	if (r < 0) {
		return;
	}

	(void)coap_resource_send(resource, &notif,
				 &observer->addr, sizeof(observer->addr), NULL);
}

static const char * const queues_path[] = { "status", "queues", NULL };
COAP_RESOURCE_DEFINE(queues, lichen_coap, {
	.get    = queues_get,
	.notify = queues_notify,
	.path   = queues_path,
});

/* --------------------------------------------------------------------------
 * /neighbors
 * -------------------------------------------------------------------------- */

/* Pre-encoded CBOR: []  (0x80 = array(0)) */
static const uint8_t cbor_neighbors[] = { 0x80 };

static int neighbors_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT,
			    cbor_neighbors, sizeof(cbor_neighbors));
}

static const char * const neighbors_path[] = { "neighbors", NULL };
COAP_RESOURCE_DEFINE(neighbors, lichen_coap, {
	.get  = neighbors_get,
	.path = neighbors_path,
});

/* --------------------------------------------------------------------------
 * /config
 * -------------------------------------------------------------------------- */

static int config_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[160];
	size_t len = lichen_gateway_encode_config_update_cbor(
		cbor_buf, sizeof(cbor_buf), s_tx_power_dbm,
		s_has_manual_location ? &s_manual_location : NULL);

	if (len == 0U) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

static int config_put(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	struct lichen_gateway_config_update update;

	if (payload == NULL ||
	    lichen_gateway_decode_config_cbor(payload, payload_len,
					      &update) < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	if (lichen_gateway_apply_config_update(&update, &s_tx_power_dbm,
					       &s_manual_location,
					       &s_has_manual_location) < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CHANGED, NULL, 0);
}

static const char * const config_path[] = { "config", NULL };
COAP_RESOURCE_DEFINE(config, lichen_coap, {
	.get  = config_get,
	.put  = config_put,
	.path = config_path,
});

/* --------------------------------------------------------------------------
 * CoAP service (AUTOSTART — no explicit start call needed)
 * -------------------------------------------------------------------------- */

static const uint16_t coap_port = 5683;
COAP_SERVICE_DEFINE(lichen_coap, NULL, &coap_port, COAP_SERVICE_AUTOSTART);

/* --------------------------------------------------------------------------
 * LoRa RX thread — runs continuously, logs every received frame.
 *
 * When CONFIG_LICHEN_L2 is enabled, the L2 layer handles LoRa RX via its own
 * thread and routes packets through the IPv6 stack. This manual RX thread is
 * only used for direct LoRa testing without the full network stack.
 * -------------------------------------------------------------------------- */

#if !IS_ENABLED(CONFIG_LICHEN_L2) && LICHEN_GATEWAY_HAS_LORA
static void lora_rx_entry(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);

	k_sem_take(&s_radio_ready, K_FOREVER);

	uint8_t buf[LORA_MAX_FRAME];
	int16_t rssi;
	int8_t  snr;

	while (1) {
		int len = lora_recv(s_lora_dev, buf, sizeof(buf),
				    K_FOREVER, &rssi, &snr);
		if (len > 0) {
			LOG_INF("RX %d B rssi=%d snr=%d [%02x%s]",
				len, rssi, snr, buf[0],
				len > 1 ? " ..." : "");
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
			static const uint8_t unknown_iid[8];
			lichen_native_send_message_received(unknown_iid,
							    buf, len,
							    rssi, snr);
#endif
		} else if (len < 0) {
			LOG_WRN("lora_recv err: %d", len);
			k_sleep(K_MSEC(100));
		}
	}
}

K_THREAD_DEFINE(lora_rx, LORA_RX_STACKSZ,
		lora_rx_entry, NULL, NULL, NULL,
		LORA_RX_PRIORITY, 0, 0);
#endif /* !CONFIG_LICHEN_L2 && LICHEN_GATEWAY_HAS_LORA */

/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(void)
{
	LOG_INF("LICHEN gateway starting");

#if IS_ENABLED(CONFIG_LICHEN_L2)
	LOG_INF("LICHEN L2 enabled - LoRa handled by network stack");

#if IS_ENABLED(CONFIG_LICHEN_L2_DEV_PROVISIONING)
	int prov = -EAGAIN;
	for (int i = 0; i < 50 && prov == -EAGAIN; i++) {
		prov = lichen_l2_dev_provision(NULL);
		if (prov == -EAGAIN) {
			k_sleep(K_MSEC(100));
		}
	}
	if (prov != 0) {
		LOG_ERR("L2 dev provisioning failed: %d", prov);
	}
#endif
	lichen_l2_publish_app_identity("gateway", NULL);
	lichen_coap_client_init();
#elif LICHEN_GATEWAY_HAS_LORA
	int ret;

	/* LoRa radio init.  The sim driver ignores RF parameters and returns 0;
	 * on hardware this configures the SX126x transceiver. */
	ret = lichen_hal_lora_device_get(&s_lora_dev);
	if (ret < 0) {
		/* Expected in CI (no sim server); gateway still serves CoAP. */
		LOG_WRN("LoRa radio unavailable (%d) — CoAP-only mode", ret);
	} else {
		struct lora_modem_config lora_cfg = {
			.frequency    = LORA_FREQ_HZ,
			.bandwidth    = BW_125_KHZ,
			.datarate     = SF_10,
			.coding_rate  = CR_4_5,
			.preamble_len = 8,
			.tx_power     = s_tx_power_dbm,
			.tx           = false,       /* start in receive mode */
			.public_network = false,
		};
		ret = lora_config(s_lora_dev, &lora_cfg);

		if (ret < 0) {
			LOG_ERR("LoRa config failed: %d", ret);
		} else {
			LOG_INF("LoRa SF10/125kHz/CR4-5 @ %u Hz", LORA_FREQ_HZ);
			k_sem_give(&s_radio_ready);
		}
	}
#else
	LOG_INF("No LoRa radio configured - CoAP/local-client only");
#endif

	/* LICHEN Native over USB CDC-ACM */
#if IS_ENABLED(CONFIG_LICHEN_NATIVE)
	if (lichen_native_init(lichen_native_handle_rx) == 0) {
		LOG_INF("LICHEN Native ready");
		lichen_native_send_hello();
	}
#endif

	/* SLIP bridge: enabled by Kconfig on hardware (CONFIG_SLIP +
	 * CONFIG_NET_SLIP_TAP).  native_sim uses the lichen-sim driver
	 * instead.  No app-level init required in either case. */

	/* Common message contract for BLE adapters (idempotent) */
#if defined(CONFIG_LORA_LICHEN_MESHTASTIC_BLE) || defined(CONFIG_LORA_LICHEN_MESHCORE_BLE)
	if (gateway_message_contract_init() < 0) {
		LOG_WRN("Message contract init failed — BLE apps unavailable");
	}
#endif

	/* BLE UART (NUS) — optional, enabled on boards with a BLE radio */
#ifdef CONFIG_LORA_LICHEN_BLE
	if (ble_uart_init() < 0) {
		LOG_WRN("BLE UART init failed — BLE unavailable");
	}
#endif

	/* Meshtastic-compatible BLE GATT — optional app compatibility surface */
#ifdef CONFIG_LORA_LICHEN_MESHTASTIC_BLE
	if (ble_meshtastic_init() < 0) {
		LOG_WRN("Meshtastic BLE init failed — Meshtastic app unavailable");
	} else if (gateway_meshtastic_adapter_init() < 0) {
		LOG_WRN("Meshtastic adapter init failed — Meshtastic app unavailable");
	}
#endif

	/* MeshCore-compatible BLE GATT — local app compatibility only */
#ifdef CONFIG_LORA_LICHEN_MESHCORE_BLE
	if (IS_ENABLED(CONFIG_LICHEN_L2) &&
	    gateway_identity_publish_self() < 0) {
		LOG_WRN("MeshCore app identity using degraded SELF_INFO until key is published");
	}
	if (ble_meshcore_init() < 0) {
		LOG_WRN("MeshCore BLE init failed — MeshCore app unavailable");
	} else if (gateway_meshcore_adapter_init() < 0) {
		LOG_WRN("MeshCore adapter init failed — MeshCore app unavailable");
	}
#endif

#if IS_ENABLED(CONFIG_LICHEN_GATEWAY_PREFIX_DELEGATION)
	gateway_backhaul_init();  /* registers handlers early, follows AGENTS.md init order before RPL */
#endif

	if (gateway_rpl_init() < 0) {
		LOG_WRN("RPL root init failed - continuing without full DODAG support");
	} else if (IS_ENABLED(CONFIG_LORA_LICHEN_GATEWAY_RPL_ROOT)) {
		LOG_INF("RPL root signalling enabled (DODAG root active, Trickle Imin=%ums)",
			CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS);
	}

#if !IS_ENABLED(CONFIG_LORA_LICHEN_GATEWAY_RPL_ROOT)
	LOG_WRN("RPL root signalling disabled - advertising /status rpl=false");
#endif

#if IS_ENABLED(CONFIG_LICHEN_GATEWAY_PREFIX_DELEGATION)
	LOG_INF("Prefix delegation enabled - WiFi station backhaul active");
#endif

	LOG_INF("CoAP server on port %u (AUTOSTART)", coap_port);

	return 0;
}
