/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_status.c
 * @brief LCI /status resource handlers (RFC 7641 Observable)
 *
 * Implements /status, /status/neighbors, /status/routes per LCI spec 17.5.3.
 * CCP-17 capacity validation for CBOR encoders (BUILD_ASSERT + runtime checks).
 */

#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>

#include <lichen/coap_status.h>

LOG_MODULE_REGISTER(lichen_coap_status, CONFIG_LICHEN_COAP_STATUS_LOG_LEVEL);

/* CBOR content-format code (RFC 7252 / IANA) */
#define CBOR_CONTENT_FORMAT 60

/* ── Static state ─────────────────────────────────────────────────────────── */

static struct lichen_coap_status_config s_config;
static bool s_initialized;

/* ── CBOR encoding context with bounds checking ────────────────────────────── */

/**
 * @brief CBOR encoding context for bounds-checked writes
 *
 * SECURITY: All CBOR writes go through this context to prevent buffer overflow.
 * If any write would exceed buf_size, the overflow flag is set and subsequent
 * writes become no-ops. Callers must check ctx->overflow after encoding.
 */
struct cbor_ctx {
	uint8_t *buf;
	size_t off;
	size_t size;
	bool overflow;
};

static void cbor_ctx_init(struct cbor_ctx *ctx, uint8_t *buf, size_t size)
{
	ctx->buf = buf;
	ctx->off = 0;
	ctx->size = size;
	ctx->overflow = false;
}

/* SECURITY: Check bounds before writing n bytes */
static inline bool cbor_check_space(struct cbor_ctx *ctx, size_t n)
{
	if (ctx->overflow || ctx->off + n > ctx->size) {
		ctx->overflow = true;
		return false;
	}
	return true;
}

static void cbor_put_map_header(struct cbor_ctx *ctx, uint16_t count)
{
	if (count > 0xff) {
		ctx->overflow = true;
		return;
	}
	uint8_t c = (uint8_t)count;
	if (c < 24U) {
		if (!cbor_check_space(ctx, 1)) {
			return;
		}
		ctx->buf[ctx->off++] = 0xa0U | c;
	} else {
		if (!cbor_check_space(ctx, 2)) {
			return;
		}
		ctx->buf[ctx->off++] = 0xb8;
		ctx->buf[ctx->off++] = c;
	}
}

static void cbor_put_array_header(struct cbor_ctx *ctx, uint16_t count)
{
	if (count > 0xff) {
		ctx->overflow = true;
		return;
	}
	uint8_t c = (uint8_t)count;
	if (c < 24U) {
		if (!cbor_check_space(ctx, 1)) {
			return;
		}
		ctx->buf[ctx->off++] = 0x80U | c;
	} else {
		if (!cbor_check_space(ctx, 2)) {
			return;
		}
		ctx->buf[ctx->off++] = 0x98;
		ctx->buf[ctx->off++] = c;
	}
}

static void cbor_put_tstr(struct cbor_ctx *ctx, const char *value)
{
	size_t len = value ? strlen(value) : 0;
	size_t header_len;
	if (len < 24U) {
		header_len = 1;
	} else if (len <= UINT8_MAX) {
		header_len = 2;
	} else if (len <= UINT16_MAX) {
		header_len = 3;
	} else {
		header_len = 5;
	}
	if (!cbor_check_space(ctx, header_len + len)) {
		return;
	}
	if (len < 24U) {
		ctx->buf[ctx->off++] = 0x60U | (uint8_t)len;
	} else if (len <= UINT8_MAX) {
		ctx->buf[ctx->off++] = 0x78;
		ctx->buf[ctx->off++] = (uint8_t)len;
	} else if (len <= UINT16_MAX) {
		ctx->buf[ctx->off++] = 0x79;
		ctx->buf[ctx->off++] = (uint8_t)(len >> 8);
		ctx->buf[ctx->off++] = (uint8_t)(len & 0xffU);
	} else {
		ctx->buf[ctx->off++] = 0x7a;
		ctx->buf[ctx->off++] = (uint8_t)(len >> 24);
		ctx->buf[ctx->off++] = (uint8_t)(len >> 16);
		ctx->buf[ctx->off++] = (uint8_t)(len >> 8);
		ctx->buf[ctx->off++] = (uint8_t)(len & 0xffU);
	}
	if (len > 0) {
		memcpy(&ctx->buf[ctx->off], value, len);
		ctx->off += len;
	}
}

static void cbor_put_key(struct cbor_ctx *ctx, const char *key)
{
	cbor_put_tstr(ctx, key);
}

static void cbor_put_bool(struct cbor_ctx *ctx, bool value)
{
	if (!cbor_check_space(ctx, 1)) {
		return;
	}
	ctx->buf[ctx->off++] = value ? 0xf5 : 0xf4;
}

static void cbor_put_uint(struct cbor_ctx *ctx, uint32_t value)
{
	size_t needed;

	if (value < 24U) {
		needed = 1;
	} else if (value <= UINT8_MAX) {
		needed = 2;
	} else if (value <= UINT16_MAX) {
		needed = 3;
	} else {
		needed = 5;
	}

	if (!cbor_check_space(ctx, needed)) {
		return;
	}

	if (value < 24U) {
		ctx->buf[ctx->off++] = (uint8_t)value;
	} else if (value <= UINT8_MAX) {
		ctx->buf[ctx->off++] = 0x18;
		ctx->buf[ctx->off++] = (uint8_t)value;
	} else if (value <= UINT16_MAX) {
		ctx->buf[ctx->off++] = 0x19;
		ctx->buf[ctx->off++] = (uint8_t)(value >> 8);
		ctx->buf[ctx->off++] = (uint8_t)(value & 0xffU);
	} else {
		ctx->buf[ctx->off++] = 0x1a;
		ctx->buf[ctx->off++] = (uint8_t)(value >> 24);
		ctx->buf[ctx->off++] = (uint8_t)(value >> 16);
		ctx->buf[ctx->off++] = (uint8_t)(value >> 8);
		ctx->buf[ctx->off++] = (uint8_t)(value & 0xffU);
	}
}

static void cbor_put_int(struct cbor_ctx *ctx, int32_t value)
{
	uint32_t encoded;
	size_t needed;

	if (value >= 0) {
		cbor_put_uint(ctx, (uint32_t)value);
		return;
	}

	encoded = (uint32_t)(-1LL - (int64_t)value);

	if (encoded < 24U) {
		needed = 1;
	} else if (encoded <= 0xffU) {
		needed = 2;
	} else if (encoded <= 0xffffU) {
		needed = 3;
	} else {
		needed = 5;
	}

	if (!cbor_check_space(ctx, needed)) {
		return;
	}

	if (encoded < 24U) {
		ctx->buf[ctx->off++] = 0x20U | (uint8_t)encoded;
	} else if (encoded <= 0xffU) {
		ctx->buf[ctx->off++] = 0x38;
		ctx->buf[ctx->off++] = (uint8_t)encoded;
	} else if (encoded <= 0xffffU) {
		ctx->buf[ctx->off++] = 0x39;
		ctx->buf[ctx->off++] = (uint8_t)(encoded >> 8);
		ctx->buf[ctx->off++] = (uint8_t)(encoded & 0xffU);
	} else {
		ctx->buf[ctx->off++] = 0x3a;
		ctx->buf[ctx->off++] = (uint8_t)(encoded >> 24);
		ctx->buf[ctx->off++] = (uint8_t)(encoded >> 16);
		ctx->buf[ctx->off++] = (uint8_t)(encoded >> 8);
		ctx->buf[ctx->off++] = (uint8_t)(encoded & 0xffU);
	}
}

/* Format IPv6 address as string (fe80::1234:5678:9abc:def0) */
static int format_ipv6(const uint8_t addr[16], char *buf, size_t buf_size)
{
	struct in6_addr in6;
	memcpy(in6.s6_addr, addr, 16);
	if (net_addr_ntop(AF_INET6, &in6, buf, buf_size) == NULL) {
		return -EINVAL;
	}
	return 0;
}

static const char *trust_level_str(enum lichen_coap_trust_level trust)
{
	switch (trust) {
	case LICHEN_COAP_TRUST_TOFU:
		return "tofu";
	case LICHEN_COAP_TRUST_DANE:
		return "dane";
	case LICHEN_COAP_TRUST_VERIFIED:
		return "verified";
	default:
		return "unknown";
	}
}

/* ── CBOR encoders ─────────────────────────────────────────────────────────── */

size_t lichen_coap_encode_status_cbor(uint8_t *buf, size_t buf_size,
				      const struct lichen_coap_node_status *status)
{
	struct cbor_ctx ctx;
	char ipv6_buf[40];
	if (buf == NULL || status == NULL || buf_size == 0) {
		return 0;
	}
	if (status->txq_used > status->txq_cap || status->fwd_used > status->fwd_cap) {
		return 0;
	}
	cbor_ctx_init(&ctx, buf, buf_size);
	uint16_t map_count = 9;
	map_count += status->battery_pct_valid ? 1 : 0;
	map_count += status->battery_mv_valid ? 1 : 0;
	if (map_count > 0xff) {
		ctx.overflow = true;
	}
	cbor_put_map_header(&ctx, map_count);
	cbor_put_key(&ctx, "uptime_s");
	cbor_put_uint(&ctx, status->uptime_s);
	if (status->battery_pct_valid) {
		cbor_put_key(&ctx, "battery_pct");
		cbor_put_uint(&ctx, status->battery_pct);
	}
	if (status->battery_mv_valid) {
		cbor_put_key(&ctx, "battery_mv");
		cbor_put_uint(&ctx, status->battery_mv);
	}
	cbor_put_key(&ctx, "mem_free_kb");
	cbor_put_uint(&ctx, status->mem_free_kb);
	cbor_put_key(&ctx, "time");
	uint8_t time_count = 2;
	if (status->time.wall_clock_valid) time_count += 1;
	if (status->time.source_class) time_count += 1;
	if (status->time.source_name) time_count += 1;
	cbor_put_map_header(&ctx, time_count);
	cbor_put_key(&ctx, "wall_clock_valid");
	cbor_put_bool(&ctx, status->time.wall_clock_valid);
	if (status->time.wall_clock_valid) {
		cbor_put_key(&ctx, "unix_time");
		cbor_put_uint(&ctx, status->time.unix_time);
	}
	if (status->time.source_class) {
		cbor_put_key(&ctx, "source_class");
		cbor_put_tstr(&ctx, status->time.source_class);
	}
	if (status->time.source_name) {
		cbor_put_key(&ctx, "source_name");
		cbor_put_tstr(&ctx, status->time.source_name);
	}
	cbor_put_key(&ctx, "age_s");
	cbor_put_uint(&ctx, status->time.age_s);
	cbor_put_key(&ctx, "dodag");
	uint8_t dodag_count = 2;
	if (status->dodag.has_parent) dodag_count += 1;
	if (status->dodag.has_root) dodag_count += 1;
	cbor_put_map_header(&ctx, dodag_count);
	cbor_put_key(&ctx, "joined");
	cbor_put_bool(&ctx, status->dodag.joined);
	cbor_put_key(&ctx, "rank");
	cbor_put_uint(&ctx, status->dodag.rank);
	if (status->dodag.has_parent) {
		cbor_put_key(&ctx, "parent");
		format_ipv6(status->dodag.parent, ipv6_buf, sizeof(ipv6_buf));
		cbor_put_tstr(&ctx, ipv6_buf);
	}
	if (status->dodag.has_root) {
		cbor_put_key(&ctx, "root");
		format_ipv6(status->dodag.root, ipv6_buf, sizeof(ipv6_buf));
		cbor_put_tstr(&ctx, ipv6_buf);
	}
	cbor_put_key(&ctx, "radio");
	cbor_put_map_header(&ctx, 4);
	cbor_put_key(&ctx, "rx_packets");
	cbor_put_uint(&ctx, status->radio.rx_packets);
	cbor_put_key(&ctx, "tx_packets");
	cbor_put_uint(&ctx, status->radio.tx_packets);
	cbor_put_key(&ctx, "rx_errors");
	cbor_put_uint(&ctx, status->radio.rx_errors);
	cbor_put_key(&ctx, "duty_cycle_pct");
	cbor_put_uint(&ctx, status->radio.duty_cycle_pct_x10);
	cbor_put_key(&ctx, "txq_cap");
	cbor_put_uint(&ctx, status->txq_cap);
	cbor_put_key(&ctx, "txq_used");
	cbor_put_uint(&ctx, status->txq_used);
	cbor_put_key(&ctx, "fwd_cap");
	cbor_put_uint(&ctx, status->fwd_cap);
	cbor_put_key(&ctx, "fwd_used");
	cbor_put_uint(&ctx, status->fwd_used);
	if (ctx.overflow) {
		return 0;
	}
	return ctx.off;
}

size_t lichen_coap_encode_neighbors_cbor(uint8_t *buf, size_t buf_size,
					 const struct lichen_coap_neighbor *neighbors,
					 size_t count)
{
	struct cbor_ctx ctx;
	char ipv6_buf[40];

	if (buf == NULL || buf_size == 0) {
		return 0;
	}

	cbor_ctx_init(&ctx, buf, buf_size);

	/* Root map with "neighbors" array */
	cbor_put_map_header(&ctx, 1);
	cbor_put_key(&ctx, "neighbors");

	if (neighbors == NULL || count == 0) {
		cbor_put_array_header(&ctx, 0);
		/* SECURITY: Return 0 if buffer overflow would have occurred */
		return ctx.overflow ? 0 : ctx.off;
	}

	cbor_put_array_header(&ctx, (uint8_t)count);

	for (size_t i = 0; i < count; i++) {
		const struct lichen_coap_neighbor *n = &neighbors[i];

		cbor_put_map_header(&ctx, 6);

		cbor_put_key(&ctx, "addr");
		format_ipv6(n->addr, ipv6_buf, sizeof(ipv6_buf));
		cbor_put_tstr(&ctx, ipv6_buf);

		cbor_put_key(&ctx, "rssi_dbm");
		cbor_put_int(&ctx, n->rssi_dbm);

		/* snr_db as scaled integer (7.5 dB -> 75) */
		cbor_put_key(&ctx, "snr_db");
		cbor_put_int(&ctx, n->snr_db_x10);

		/* etx as scaled integer (1.2 -> 12) */
		cbor_put_key(&ctx, "etx");
		cbor_put_uint(&ctx, n->etx_x10);

		cbor_put_key(&ctx, "last_seen_s");
		cbor_put_uint(&ctx, n->last_seen_s);

		cbor_put_key(&ctx, "trust");
		cbor_put_tstr(&ctx, trust_level_str(n->trust));
	}

	/* SECURITY: Return 0 if buffer overflow would have occurred */
	if (ctx.overflow) {
		return 0;
	}

	return ctx.off;
}

size_t lichen_coap_encode_routes_cbor(uint8_t *buf, size_t buf_size,
				      const struct lichen_coap_route *routes,
				      size_t count,
				      const uint8_t *default_route)
{
	struct cbor_ctx ctx;
	char ipv6_buf[40];
	char prefix_buf[48]; /* IPv6/prefix_len */
	uint8_t map_count = 1; /* routes array */

	if (buf == NULL || buf_size == 0) {
		return 0;
	}

	cbor_ctx_init(&ctx, buf, buf_size);

	map_count += default_route ? 1 : 0;

	cbor_put_map_header(&ctx, map_count);

	/* routes array */
	cbor_put_key(&ctx, "routes");

	if (routes == NULL || count == 0) {
		cbor_put_array_header(&ctx, 0);
	} else {
		cbor_put_array_header(&ctx, (uint8_t)count);

		for (size_t i = 0; i < count; i++) {
			const struct lichen_coap_route *r = &routes[i];

			cbor_put_map_header(&ctx, 4);

			/* prefix with length */
			cbor_put_key(&ctx, "prefix");
			format_ipv6(r->prefix, ipv6_buf, sizeof(ipv6_buf));
			(void)snprintf(prefix_buf, sizeof(prefix_buf), "%s/%u",
				       ipv6_buf, r->prefix_len);
			cbor_put_tstr(&ctx, prefix_buf);

			cbor_put_key(&ctx, "via");
			format_ipv6(r->via, ipv6_buf, sizeof(ipv6_buf));
			cbor_put_tstr(&ctx, ipv6_buf);

			cbor_put_key(&ctx, "metric");
			cbor_put_uint(&ctx, r->metric);

			cbor_put_key(&ctx, "lifetime_s");
			cbor_put_uint(&ctx, r->lifetime_s);
		}
	}

	/* default_route */
	if (default_route) {
		cbor_put_key(&ctx, "default_route");
		format_ipv6(default_route, ipv6_buf, sizeof(ipv6_buf));
		cbor_put_tstr(&ctx, ipv6_buf);
	}

	/* SECURITY: Return 0 if buffer overflow would have occurred */
	if (ctx.overflow) {
		return 0;
	}

	return ctx.off;
}

/* ── CoAP response helpers ─────────────────────────────────────────────────── */

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

/* ── /status handlers ──────────────────────────────────────────────────────── */

static int status_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[LICHEN_COAP_STATUS_CBOR_MAX_SIZE];
	struct lichen_coap_node_status status = {0};
	size_t len;
	int r;

	/* Handle Observe registration */
	r = coap_resource_parse_observe(resource, request, addr);
	if (r < 0 && r != -ENOENT) {
		LOG_WRN("Observe parse failed: %d", r);
	}

	if (!s_initialized || !s_config.status_get) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	r = s_config.status_get(&status);
	if (r < 0) {
		LOG_WRN("status_get callback failed: %d", r);
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	len = lichen_coap_encode_status_cbor(cbor_buf, sizeof(cbor_buf), &status);
	if (len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

static void status_notify(struct coap_resource *resource,
			  struct coap_observer *observer)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t cbor_buf[LICHEN_COAP_STATUS_CBOR_MAX_SIZE];
	struct coap_packet notif;
	struct lichen_coap_node_status status = {0};
	size_t cbor_len;
	int r;

	if (!s_initialized || !s_config.status_get) {
		return;
	}

	r = s_config.status_get(&status);
	if (r < 0) {
		return;
	}

	cbor_len = lichen_coap_encode_status_cbor(cbor_buf, sizeof(cbor_buf), &status);
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

/* ── /status/neighbors handlers ────────────────────────────────────────────── */

static int neighbors_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[LICHEN_COAP_NEIGHBORS_CBOR_MAX_SIZE];
	struct lichen_coap_neighbor neighbors[CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS];
	size_t len;
	int count;
	int r;

	/* Handle Observe registration */
	r = coap_resource_parse_observe(resource, request, addr);
	if (r < 0 && r != -ENOENT) {
		LOG_WRN("Observe parse failed: %d", r);
	}

	if (!s_initialized || !s_config.neighbors_get) {
		/* Return empty array if no callback */
		len = lichen_coap_encode_neighbors_cbor(cbor_buf, sizeof(cbor_buf),
							NULL, 0);
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
	}

	count = s_config.neighbors_get(neighbors, ARRAY_SIZE(neighbors));
	if (count < 0 || count > CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	len = lichen_coap_encode_neighbors_cbor(cbor_buf, sizeof(cbor_buf),
						neighbors, (size_t)count);
	if (len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

static void neighbors_notify(struct coap_resource *resource,
			     struct coap_observer *observer)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t cbor_buf[LICHEN_COAP_NEIGHBORS_CBOR_MAX_SIZE];
	struct coap_packet notif;
	struct lichen_coap_neighbor neighbors[CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS];
	size_t cbor_len;
	int count;
	int r;

	if (!s_initialized || !s_config.neighbors_get) {
		return;
	}

	count = s_config.neighbors_get(neighbors, ARRAY_SIZE(neighbors));
	if (count < 0) {
		count = 0;
	}

	cbor_len = lichen_coap_encode_neighbors_cbor(cbor_buf, sizeof(cbor_buf),
						     neighbors, (size_t)count);
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

/* ── /status/routes handlers ───────────────────────────────────────────────── */

static int routes_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[LICHEN_COAP_ROUTES_CBOR_MAX_SIZE];
	struct lichen_coap_route routes[CONFIG_LICHEN_COAP_STATUS_MAX_ROUTES];
	uint8_t default_route[16];
	bool has_default = false;
	size_t len;
	int count;

	if (!s_initialized || !s_config.routes_get) {
		/* Return empty routes if no callback */
		len = lichen_coap_encode_routes_cbor(cbor_buf, sizeof(cbor_buf),
						     NULL, 0, NULL);
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
	}

	count = s_config.routes_get(routes, ARRAY_SIZE(routes), default_route);
	if (count < 0) {
		LOG_WRN("routes_get callback failed: %d", count);
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	/* Check if default_route was set (non-zero) */
	for (int i = 0; i < 16; i++) {
		if (default_route[i] != 0) {
			has_default = true;
			break;
		}
	}

	len = lichen_coap_encode_routes_cbor(cbor_buf, sizeof(cbor_buf),
					     routes, (size_t)count,
					     has_default ? default_route : NULL);
	if (len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

/* ── Resource definitions ──────────────────────────────────────────────────── */

static const char * const status_path[] = { "status", NULL };
static const char * const neighbors_path[] = { "status", "neighbors", NULL };
static const char * const routes_path[] = { "status", "routes", NULL };

/*
 * Resources are defined but must be registered with a CoAP service.
 * The application must call COAP_RESOURCE_DEFINE or manually add these
 * to its service.
 */

/* Exported resource descriptors for applications to use */
const struct coap_resource lichen_coap_status_resource = {
	.get    = status_get,
	.notify = status_notify,
	.path   = status_path,
};

const struct coap_resource lichen_coap_neighbors_resource = {
	.get    = neighbors_get,
	.notify = neighbors_notify,
	.path   = neighbors_path,
};

const struct coap_resource lichen_coap_routes_resource = {
	.get  = routes_get,
	.path = routes_path,
};

/* ── Public API ────────────────────────────────────────────────────────────── */

int lichen_coap_status_init(const struct lichen_coap_status_config *config)
{
	if (config == NULL) {
		return -EINVAL;
	}

	/* status_get is required, others are optional */
	if (config->status_get == NULL) {
		return -EINVAL;
	}

	memcpy(&s_config, config, sizeof(s_config));
	s_initialized = true;

	LOG_INF("CoAP status handlers initialized");
	return 0;
}

void lichen_coap_status_notify(void)
{
	coap_resource_notify((struct coap_resource *)&lichen_coap_status_resource);
}

void lichen_coap_status_neighbors_notify(void)
{
	coap_resource_notify((struct coap_resource *)&lichen_coap_status_resource);
}
