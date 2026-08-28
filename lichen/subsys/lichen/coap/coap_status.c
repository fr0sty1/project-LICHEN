/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>

#include <lichen/coap_status.h>
#include <lichen/coap_config.h>
#include <lichen/coap_server.h>

LOG_MODULE_REGISTER(lichen_coap_status, CONFIG_LICHEN_COAP_STATUS_LOG_LEVEL);

#define CBOR_CONTENT_FORMAT 60
#define CBOR_MAP_BASE 0xa0U
#define CBOR_ARRAY_BASE 0x80U
#define CBOR_TEXT_BASE 0x60U
#define CBOR_TRUE 0xf5U
#define CBOR_FALSE 0xf4U
#define CBOR_NULL 0xf6U
#define CBOR_FLOAT64 0xfbU
#define CBOR_UINT8 0x18U
#define CBOR_UINT16 0x19U
#define CBOR_UINT32 0x1aU
#define STATUS_OBSERVE_FIRST_SEQUENCE 2U

BUILD_ASSERT(LICHEN_COAP_STATUS_CBOR_MAX_SIZE >= 320U,
	     "CCP-17: status CBOR buffer insufficient for worst-case (runtime overflow checks)");
BUILD_ASSERT(CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS <= 16U,
	     "CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS exceeds CBOR array header + buffer");
BUILD_ASSERT(CONFIG_LICHEN_COAP_STATUS_MAX_ROUTES <= 16U,
	     "CONFIG_LICHEN_COAP_STATUS_MAX_ROUTES exceeds CBOR array header + buffer");
BUILD_ASSERT(CONFIG_LICHEN_COAP_STATUS_MAX_TXQ <= 255U,
	     "CONFIG_LICHEN_COAP_STATUS_MAX_TXQ exceeds uint8_t range");
BUILD_ASSERT(CONFIG_LICHEN_COAP_STATUS_MAX_FWD <= 255U,
	     "CONFIG_LICHEN_COAP_STATUS_MAX_FWD exceeds uint8_t range");
BUILD_ASSERT(LICHEN_COAP_STATUS_CBOR_MAX_SIZE <= CONFIG_COAP_SERVER_MESSAGE_SIZE,
	     "LICHEN_COAP_STATUS_CBOR_MAX_SIZE must fit in CONFIG_COAP_SERVER_MESSAGE_SIZE");
BUILD_ASSERT(LICHEN_COAP_NEIGHBORS_CBOR_MAX_SIZE <= CONFIG_COAP_SERVER_MESSAGE_SIZE,
	     "LICHEN_COAP_NEIGHBORS_CBOR_MAX_SIZE must fit in CONFIG_COAP_SERVER_MESSAGE_SIZE");
BUILD_ASSERT(LICHEN_COAP_ROUTES_CBOR_MAX_SIZE <= CONFIG_COAP_SERVER_MESSAGE_SIZE,
	     "LICHEN_COAP_ROUTES_CBOR_MAX_SIZE must fit in CONFIG_COAP_SERVER_MESSAGE_SIZE");
BUILD_ASSERT(LICHEN_CONFIG_ADDR_MAX_LEN >= INET6_ADDRSTRLEN,
	     "LICHEN_CONFIG_ADDR_MAX_LEN below INET6_ADDRSTRLEN: net_addr_ntop ignores buf_size and would overflow caller buffers");

static struct lichen_coap_status_config s_config;
static bool s_initialized;
static K_MUTEX_DEFINE(s_mutex);

struct status_observer_slot {
	struct coap_observer observer;
	socklen_t addr_len;
	int64_t last_refresh_ms;
	int64_t retry_at_ms;
	uint8_t retries;
	bool active;
	bool pending;
};

struct status_observe_state {
	struct status_observer_slot slots[CONFIG_LICHEN_COAP_STATUS_MAX_OBSERVERS];
	struct lichen_coap_status_observe_stats stats;
	uint8_t payload[LICHEN_COAP_STATUS_CBOR_MAX_SIZE];
	size_t payload_len;
	int64_t last_notify_ms;
	int64_t last_poll_ms;
	bool have_payload;
	bool have_last_poll;
};

static struct status_observe_state s_observe;
static K_MUTEX_DEFINE(s_observe_mutex);
extern struct coap_resource lichen_coap_status_resource;

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

static inline bool cbor_check_space(struct cbor_ctx *ctx, size_t n)
{
	if (ctx->overflow || ctx->off + n > ctx->size) {
		ctx->overflow = true;
		return false;
	}
	return true;
}

static void cbor_put_map_header(struct cbor_ctx *ctx, size_t count)
{
	if (count > 65535) {
		ctx->overflow = true;
		return;
	}
	if (count < 24U) {
		if (!cbor_check_space(ctx, 1)) {
			return;
		}
		ctx->buf[ctx->off++] = CBOR_MAP_BASE | (uint8_t)count;
	} else if (count <= 255) {
		if (!cbor_check_space(ctx, 2)) {
			return;
		}
		ctx->buf[ctx->off++] = 0xb8;
		ctx->buf[ctx->off++] = (uint8_t)count;
	} else {
		if (!cbor_check_space(ctx, 3)) {
			return;
		}
		ctx->buf[ctx->off++] = 0xb9;
		ctx->buf[ctx->off++] = (uint8_t)(count >> 8);
		ctx->buf[ctx->off++] = (uint8_t)(count & 0xffU);
	}
}

static void cbor_put_array_header(struct cbor_ctx *ctx, size_t count)
{
	if (count > 65535) {
		ctx->overflow = true;
		return;
	}
	if (count < 24U) {
		if (!cbor_check_space(ctx, 1)) {
			return;
		}
		ctx->buf[ctx->off++] = CBOR_ARRAY_BASE | (uint8_t)count;
	} else if (count <= 255) {
		if (!cbor_check_space(ctx, 2)) {
			return;
		}
		ctx->buf[ctx->off++] = 0x98;
		ctx->buf[ctx->off++] = (uint8_t)count;
	} else {
		if (!cbor_check_space(ctx, 3)) {
			return;
		}
		ctx->buf[ctx->off++] = 0x99;
		ctx->buf[ctx->off++] = (uint8_t)(count >> 8);
		ctx->buf[ctx->off++] = (uint8_t)(count & 0xffU);
	}
}

static void cbor_put_tstr(struct cbor_ctx *ctx, const char *value)
{
	size_t len = value ? strlen(value) : 0;
	if (len > 0xffffffffU) {
		ctx->overflow = true;
		return;
	}
	size_t header_len;

	if (len < 24U) {
		header_len = 1;
	} else if (len <= UINT8_MAX) {
		header_len = 2;
	} else if (len <= 0xffffU) {
		header_len = 3;
	} else {
		header_len = 5;
	}
	if (len > (size_t)-1 - header_len) {
		ctx->overflow = true;
		return;
	}

	if (!cbor_check_space(ctx, header_len + len)) {
		return;
	}

	if (len < 24U) {
		ctx->buf[ctx->off++] = CBOR_TEXT_BASE | (uint8_t)len;
	} else if (len <= UINT8_MAX) {
		ctx->buf[ctx->off++] = 0x78;
		ctx->buf[ctx->off++] = (uint8_t)len;
	} else if (len <= 0xffffU) {
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
	ctx->buf[ctx->off++] = value ? CBOR_TRUE : CBOR_FALSE;
}

static void cbor_put_null(struct cbor_ctx *ctx)
{
	if (cbor_check_space(ctx, 1U)) {
		ctx->buf[ctx->off++] = CBOR_NULL;
	}
}

static void cbor_put_double(struct cbor_ctx *ctx, double value)
{
	uint64_t bits;

	if (!cbor_check_space(ctx, 9U)) {
		return;
	}
	memcpy(&bits, &value, sizeof(bits));
	ctx->buf[ctx->off++] = CBOR_FLOAT64;
	for (int shift = 56; shift >= 0; shift -= 8) {
		ctx->buf[ctx->off++] = (uint8_t)(bits >> shift);
	}
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

int lichen_coap_format_ipv6(const uint8_t *addr, char *buf, size_t buf_size)
{
	struct in6_addr in6;

	if (addr == NULL || buf == NULL || buf_size < LICHEN_CONFIG_ADDR_MAX_LEN) {
		return -ENOBUFS;
	}

	memcpy(in6.s6_addr, addr, 16);
	if (net_addr_ntop(AF_INET6, &in6, buf, buf_size) == NULL) {
		return -ENOBUFS;
	}
	return 0;
}

static int format_dodag_root(const uint8_t addr[16], char *buf, size_t buf_size)
{
	int ret = lichen_coap_format_ipv6(addr, buf, buf_size);

	if (ret < 0) {
		return ret;
	}
	/* LCI 17.5.3 presents the reserved native DODAG prefix as 0200::/8.
	 * Preserve that one leading zero instead of inet_ntop's RFC 5952
	 * shortening so the embedded response matches the shared wire corpus. */
	if (addr[0] == 0x02U && addr[1] == 0x00U &&
	    strncmp(buf, "200:", sizeof("200:") - 1U) == 0) {
		size_t len = strlen(buf);

		if (len + 2U > buf_size) {
			return -ENOBUFS;
		}
		memmove(buf + 1, buf, len + 1U);
		buf[0] = '0';
	}
	return 0;
}

static bool status_observer_addr_equal(const struct sockaddr *a,
				       const struct sockaddr *b)
{
	if (a->sa_family != b->sa_family) {
		return false;
	}
	if (a->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;

		return a6->sin6_port == b6->sin6_port &&
		       a6->sin6_scope_id == b6->sin6_scope_id &&
		       net_ipv6_addr_cmp(&a6->sin6_addr, &b6->sin6_addr);
	}
#if defined(CONFIG_NET_IPV4)
	if (a->sa_family == AF_INET) {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
		const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;

		return a4->sin_port == b4->sin_port &&
		       net_ipv4_addr_cmp(&a4->sin_addr, &b4->sin_addr);
	}
#endif
	return false;
}

static struct status_observer_slot *find_status_observer_locked(
	const struct sockaddr *addr, const uint8_t *token, uint8_t token_len)
{
	for (size_t i = 0U; i < ARRAY_SIZE(s_observe.slots); i++) {
		struct status_observer_slot *slot = &s_observe.slots[i];

		if (slot->active && slot->observer.tkl == token_len &&
		    memcmp(slot->observer.token, token, token_len) == 0 &&
		    status_observer_addr_equal(&slot->observer.addr, addr)) {
			return slot;
		}
	}
	return NULL;
}

static struct status_observer_slot *free_status_observer_locked(void)
{
	for (size_t i = 0U; i < ARRAY_SIZE(s_observe.slots); i++) {
		if (!s_observe.slots[i].active) {
			return &s_observe.slots[i];
		}
	}
	return NULL;
}

static uint8_t status_observer_count_locked(void)
{
	uint8_t count = 0U;

	for (size_t i = 0U; i < ARRAY_SIZE(s_observe.slots); i++) {
		count += s_observe.slots[i].active ? 1U : 0U;
	}
	return count;
}

static void remove_status_observer_locked(struct status_observer_slot *slot)
{
	uint8_t count;

	if (slot->active) {
		(void)coap_remove_observer(&lichen_coap_status_resource,
					   &slot->observer);
	}
	memset(slot, 0, sizeof(*slot));
	count = status_observer_count_locked();
	s_observe.stats.observers = count;
	if (count == 0U) {
		s_observe.have_payload = false;
		s_observe.payload_len = 0U;
	}
}

static int64_t status_deadline_after(int64_t now_ms, uint32_t delay_ms)
{
	return now_ms > INT64_MAX - (int64_t)delay_ms
		       ? INT64_MAX
		       : now_ms + (int64_t)delay_ms;
}

static bool status_transient_send_error(int ret)
{
	return ret == -EAGAIN || ret == -ENOMEM || ret == -ENOBUFS ||
	       ret == -ENETDOWN;
}

static uint32_t status_next_sequence(uint32_t current)
{
	return current >= COAP_OBSERVE_MAX_AGE
		       ? STATUS_OBSERVE_FIRST_SEQUENCE
		       : current + 1U;
}

static void expire_status_observers_locked(int64_t now_ms)
{
	for (size_t i = 0U; i < ARRAY_SIZE(s_observe.slots); i++) {
		struct status_observer_slot *slot = &s_observe.slots[i];

		if (slot->active && now_ms >= slot->last_refresh_ms &&
		    (uint64_t)(now_ms - slot->last_refresh_ms) >=
			    LICHEN_COAP_STATUS_OBSERVER_TTL_MS) {
			remove_status_observer_locked(slot);
			s_observe.stats.expired++;
		}
	}
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

static bool status_snapshot_valid(const struct lichen_coap_node_status *status)
{
	if (status->battery_pct_valid && status->battery_pct > 100U) {
		return false;
	}
	if (status->time.valid &&
	    (strnlen(status->time.source_class,
		     sizeof(status->time.source_class)) >=
		     sizeof(status->time.source_class) ||
	     strnlen(status->time.source_name, sizeof(status->time.source_name)) >=
		     sizeof(status->time.source_name))) {
		return false;
	}
	if (status->dodag.valid &&
	    ((!status->dodag.joined &&
	      (status->dodag.rank != UINT16_MAX || status->dodag.has_parent ||
	       status->dodag.has_root)) ||
	     (status->dodag.joined && status->dodag.rank == UINT16_MAX))) {
		return false;
	}
	if (status->radio.valid && status->radio.duty_cycle_pct_x10 > 1000U) {
		return false;
	}
	if (status->capacity_valid &&
	    (status->txq_cap > CONFIG_LICHEN_COAP_STATUS_MAX_TXQ ||
	     status->fwd_cap > CONFIG_LICHEN_COAP_STATUS_MAX_FWD ||
	     status->txq_used > status->txq_cap ||
	     status->fwd_used > status->fwd_cap)) {
		return false;
	}
	return true;
}

ssize_t lichen_coap_encode_status_cbor(uint8_t *buf, size_t buf_size,
				       const struct lichen_coap_node_status *status)
{
	struct cbor_ctx ctx;
	char ipv6_buf[LICHEN_CONFIG_ADDR_MAX_LEN];
	uint8_t map_count;

	if (buf == NULL || status == NULL || buf_size == 0U) {
		return -ENOBUFS;
	}
	if (!status_snapshot_valid(status)) {
		return -EINVAL;
	}

	map_count = (status->uptime_valid ? 1U : 0U) +
		    (status->battery_pct_valid ? 1U : 0U) +
		    (status->battery_mv_valid ? 1U : 0U) +
		    (status->mem_free_kb_valid ? 1U : 0U) +
		    (status->time.valid ? 1U : 0U) +
		    (status->dodag.valid ? 1U : 0U) +
		    (status->radio.valid ? 1U : 0U) +
		    (status->ccp.valid ? 1U : 0U);
	cbor_ctx_init(&ctx, buf, buf_size);
	cbor_put_map_header(&ctx, map_count);

	if (status->uptime_valid) {
		cbor_put_key(&ctx, "uptime_s");
		cbor_put_uint(&ctx, status->uptime_s);
	}
	if (status->battery_pct_valid) {
		cbor_put_key(&ctx, "battery_pct");
		cbor_put_uint(&ctx, status->battery_pct);
	}
	if (status->battery_mv_valid) {
		cbor_put_key(&ctx, "battery_mv");
		cbor_put_uint(&ctx, status->battery_mv);
	}
	if (status->mem_free_kb_valid) {
		cbor_put_key(&ctx, "mem_free_kb");
		cbor_put_uint(&ctx, status->mem_free_kb);
	}

	if (status->time.valid) {
		uint8_t time_fields = 1U +
			(status->time.wall_clock_valid ? 1U : 0U) +
			(status->time.source_class[0] != '\0' ? 1U : 0U) +
			(status->time.source_name[0] != '\0' ? 1U : 0U) +
			(status->time.age_valid ? 1U : 0U);

		cbor_put_key(&ctx, "time");
		cbor_put_map_header(&ctx, time_fields);
		cbor_put_key(&ctx, "wall_clock_valid");
		cbor_put_bool(&ctx, status->time.wall_clock_valid);
		if (status->time.wall_clock_valid) {
			cbor_put_key(&ctx, "unix_time");
			cbor_put_uint(&ctx, status->time.unix_time);
		}
		if (status->time.source_class[0] != '\0') {
			cbor_put_key(&ctx, "source_class");
			cbor_put_tstr(&ctx, status->time.source_class);
		}
		if (status->time.source_name[0] != '\0') {
			cbor_put_key(&ctx, "source_name");
			cbor_put_tstr(&ctx, status->time.source_name);
		}
		if (status->time.age_valid) {
			cbor_put_key(&ctx, "age_s");
			cbor_put_uint(&ctx, status->time.age_s);
		}
	}

	if (status->dodag.valid) {
		cbor_put_key(&ctx, "dodag");
		cbor_put_map_header(&ctx, 4U);
		cbor_put_key(&ctx, "joined");
		cbor_put_bool(&ctx, status->dodag.joined);
		cbor_put_key(&ctx, "rank");
		cbor_put_uint(&ctx, status->dodag.rank);
		cbor_put_key(&ctx, "parent");
		if (status->dodag.has_parent) {
			if (lichen_coap_format_ipv6(status->dodag.parent, ipv6_buf,
						     sizeof(ipv6_buf)) < 0) {
				return -EINVAL;
			}
			cbor_put_tstr(&ctx, ipv6_buf);
		} else {
			cbor_put_null(&ctx);
		}
		cbor_put_key(&ctx, "root");
		if (status->dodag.has_root) {
			if (format_dodag_root(status->dodag.root, ipv6_buf,
					      sizeof(ipv6_buf)) < 0) {
				return -EINVAL;
			}
			cbor_put_tstr(&ctx, ipv6_buf);
		} else {
			cbor_put_null(&ctx);
		}
	}

	if (status->radio.valid) {
		cbor_put_key(&ctx, "radio");
		cbor_put_map_header(&ctx, status->capacity_valid ? 5U : 4U);
		cbor_put_key(&ctx, "rx_packets");
		cbor_put_uint(&ctx, status->radio.rx_packets);
		cbor_put_key(&ctx, "tx_packets");
		cbor_put_uint(&ctx, status->radio.tx_packets);
		cbor_put_key(&ctx, "rx_errors");
		cbor_put_uint(&ctx, status->radio.rx_errors);
		cbor_put_key(&ctx, "duty_cycle_pct");
		cbor_put_double(&ctx,
				(double)status->radio.duty_cycle_pct_x10 / 10.0);

		if (status->capacity_valid) {
			cbor_put_key(&ctx, "capacity");
			cbor_put_map_header(&ctx, 4U);
			cbor_put_key(&ctx, "txq_used");
			cbor_put_uint(&ctx, status->txq_used);
			cbor_put_key(&ctx, "txq_cap");
			cbor_put_uint(&ctx, status->txq_cap);
			cbor_put_key(&ctx, "fwd_used");
			cbor_put_uint(&ctx, status->fwd_used);
			cbor_put_key(&ctx, "fwd_cap");
			cbor_put_uint(&ctx, status->fwd_cap);
		}
	}

	if (status->ccp.valid) {
		cbor_put_key(&ctx, "ccp");
		cbor_put_map_header(&ctx, 3U);
		cbor_put_key(&ctx, "rx_channel");
		cbor_put_uint(&ctx, status->ccp.rx_channel);
		cbor_put_key(&ctx, "scheduler_active");
		cbor_put_bool(&ctx, status->ccp.scheduler_active);
		cbor_put_key(&ctx, "preferred_rx_valid_until_sfn");
		cbor_put_uint(&ctx, status->ccp.preferred_rx_valid_until_sfn);
	}

	return ctx.overflow ? -ENOBUFS : (ssize_t)ctx.off;
}

ssize_t lichen_coap_encode_neighbors_cbor(uint8_t *buf, size_t buf_size,
					  const struct lichen_coap_neighbor *neighbors,
					  size_t count)
{
	struct cbor_ctx ctx;
	char ipv6_buf[LICHEN_CONFIG_ADDR_MAX_LEN];

	if (buf == NULL || buf_size == 0) {
		return -ENOBUFS;
	}

	if (count > 16U) {
		return -ENOBUFS;
	}

	if (buf_size < 2) {
		return -ENOBUFS;
	}

	cbor_ctx_init(&ctx, buf, buf_size);
	cbor_put_map_header(&ctx, 1u);
	cbor_put_key(&ctx, "neighbors");

	if (neighbors == NULL || count == 0) {
		cbor_put_array_header(&ctx, 0u);
		return ctx.overflow ? -ENOBUFS : (ssize_t)ctx.off;
	}

	cbor_put_array_header(&ctx, count);

	for (size_t i = 0; i < count; i++) {
		const struct lichen_coap_neighbor *n = &neighbors[i];

		cbor_put_map_header(&ctx, 6);

		cbor_put_key(&ctx, "addr");
		if (lichen_coap_format_ipv6(n->addr, ipv6_buf, sizeof(ipv6_buf)) < 0) {
			ctx.overflow = true;
			return -ENOBUFS;
		}
		cbor_put_tstr(&ctx, ipv6_buf);

		cbor_put_key(&ctx, "rssi_dbm");
		cbor_put_int(&ctx, n->rssi_dbm);

		cbor_put_key(&ctx, "snr_db");
		cbor_put_int(&ctx, n->snr_db_x10);

		cbor_put_key(&ctx, "etx");
		cbor_put_uint(&ctx, n->etx_x10);

		cbor_put_key(&ctx, "last_seen_s");
		cbor_put_uint(&ctx, n->last_seen_s);

		cbor_put_key(&ctx, "trust");
		cbor_put_tstr(&ctx, trust_level_str(n->trust));
	}

	if (ctx.overflow) {
		return -ENOBUFS;
	}

	return (ssize_t)ctx.off;
}

ssize_t lichen_coap_encode_routes_cbor(uint8_t *buf, size_t buf_size,
				       const struct lichen_coap_route *routes,
				       size_t count,
				       const uint8_t *default_route)
{
	struct cbor_ctx ctx;
	char ipv6_buf[LICHEN_CONFIG_ADDR_MAX_LEN];
	char prefix_buf[LICHEN_CONFIG_ADDR_MAX_LEN + 6U];

	if (buf == NULL || buf_size == 0) {
		return -ENOBUFS;
	}

	if (count > 16U) {
		return -ENOBUFS;
	}

	uint16_t map_count = 1U + (default_route ? 1U : 0U);
	if (map_count > 255 || buf_size < 2) {
		return -ENOBUFS;
	}

	cbor_ctx_init(&ctx, buf, buf_size);
	cbor_put_map_header(&ctx, map_count);

	cbor_put_key(&ctx, "routes");

	if (routes == NULL || count == 0) {
		cbor_put_array_header(&ctx, 0u);
	} else {
		cbor_put_array_header(&ctx, count);

		for (size_t i = 0; i < count; i++) {
			const struct lichen_coap_route *r = &routes[i];

			cbor_put_map_header(&ctx, 4);

			cbor_put_key(&ctx, "prefix");
			if (lichen_coap_format_ipv6(r->prefix, ipv6_buf, sizeof(ipv6_buf)) < 0) {
				ctx.overflow = true;
				return -ENOBUFS;
			}
			int pr = snprintf(prefix_buf, sizeof(prefix_buf), "%s/%u", ipv6_buf, r->prefix_len);
			if (pr < 0 || (size_t)pr >= sizeof(prefix_buf)) {
				ctx.overflow = true;
				return -ENOBUFS;
			}
			cbor_put_tstr(&ctx, prefix_buf);

			cbor_put_key(&ctx, "via");
			if (lichen_coap_format_ipv6(r->via, ipv6_buf, sizeof(ipv6_buf)) < 0) {
				ctx.overflow = true;
				return -ENOBUFS;
			}
			cbor_put_tstr(&ctx, ipv6_buf);

			cbor_put_key(&ctx, "metric");
			cbor_put_uint(&ctx, r->metric);

			cbor_put_key(&ctx, "lifetime_s");
			cbor_put_uint(&ctx, r->lifetime_s);
		}
	}

	if (default_route) {
		cbor_put_key(&ctx, "default_route");
		if (lichen_coap_format_ipv6(default_route, ipv6_buf, sizeof(ipv6_buf)) < 0) {
			ctx.overflow = true;
			return -ENOBUFS;
		}
		cbor_put_tstr(&ctx, ipv6_buf);
	}

	if (ctx.overflow) {
		return -ENOBUFS;
	}

	return (ssize_t)ctx.off;
}


__weak int lichen_coap_status_observe_send(
	const struct sockaddr *addr, socklen_t addr_len,
	const uint8_t *token, uint8_t token_len, uint32_t sequence,
	const uint8_t *payload, size_t payload_len, bool initial,
	uint8_t request_type, uint16_t request_id)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet response;
	uint8_t type = initial && request_type == COAP_TYPE_CON
			       ? COAP_TYPE_ACK
			       : COAP_TYPE_NON_CON;
	uint16_t id = initial ? request_id : coap_next_id();
	int ret;

	if (addr == NULL || token == NULL || token_len == 0U ||
	    token_len > COAP_TOKEN_MAX_LEN || payload == NULL ||
	    payload_len > UINT16_MAX || sequence > COAP_OBSERVE_MAX_AGE) {
		return -EINVAL;
	}
	ret = coap_packet_init(&response, buf, sizeof(buf), COAP_VERSION_1,
			       type, token_len, token, COAP_RESPONSE_CODE_CONTENT,
			       id);
	if (ret < 0) {
		return ret;
	}
	ret = coap_append_option_int(&response, COAP_OPTION_OBSERVE, sequence);
	if (ret < 0) {
		return ret;
	}
	ret = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT,
				     CBOR_CONTENT_FORMAT);
	if (ret < 0) {
		return ret;
	}
	ret = coap_packet_append_payload_marker(&response);
	if (ret < 0) {
		return ret;
	}
	ret = coap_packet_append_payload(&response, payload,
					 (uint16_t)payload_len);
	if (ret < 0) {
		return ret;
	}
	return coap_resource_send(&lichen_coap_status_resource, &response, addr,
				  addr_len, NULL);
}

static int send_status_slot_locked(struct status_observer_slot *slot,
				   bool initial, uint8_t request_type,
				   uint16_t request_id)
{
	return lichen_coap_status_observe_send(
		&slot->observer.addr, slot->addr_len,
		slot->observer.token, slot->observer.tkl,
		s_observe.stats.sequence, s_observe.payload,
		s_observe.payload_len, initial, request_type, request_id);
}

static bool retry_status_observers_locked(int64_t now_ms)
{
	bool pending = false;

	for (size_t i = 0U; i < ARRAY_SIZE(s_observe.slots); i++) {
		struct status_observer_slot *slot = &s_observe.slots[i];
		int ret;

		if (!slot->active || !slot->pending) {
			continue;
		}
		if (now_ms < slot->retry_at_ms) {
			pending = true;
			continue;
		}
		ret = send_status_slot_locked(slot, false, COAP_TYPE_NON_CON, 0U);
		if (ret == 0) {
			slot->pending = false;
			slot->retries = 0U;
			s_observe.stats.notifications++;
			continue;
		}
		s_observe.stats.last_error = ret;
		if (status_transient_send_error(ret) &&
		    ++slot->retries < LICHEN_COAP_STATUS_OBSERVE_MAX_RETRIES) {
			slot->retry_at_ms = status_deadline_after(
				now_ms, LICHEN_COAP_STATUS_OBSERVE_RETRY_MS);
			s_observe.stats.backpressure++;
			pending = true;
			continue;
		}
		s_observe.stats.failures++;
		remove_status_observer_locked(slot);
	}
	return pending;
}

static int status_observe_request(struct coap_resource *resource,
				  struct coap_packet *request,
				  struct sockaddr *addr, socklen_t addr_len,
				  const uint8_t *payload, size_t payload_len,
				  int observe)
{
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t token_len = coap_header_get_token(request, token);
	struct status_observer_slot *slot;
	int64_t now_ms = k_uptime_get();
	int ret;

	if (addr == NULL || addr_len < sizeof(sa_family_t) ||
	    addr_len > sizeof(struct sockaddr_storage) || token_len == 0U ||
	    (observe != 0 && observe != 1)) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST, 0,
					   NULL, 0U);
	}

	k_mutex_lock(&s_observe_mutex, K_FOREVER);
	expire_status_observers_locked(now_ms);
	slot = find_status_observer_locked(addr, token, token_len);
	if (observe == 1) {
		if (slot != NULL) {
			remove_status_observer_locked(slot);
		}
		k_mutex_unlock(&s_observe_mutex);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_CONTENT,
					   CBOR_CONTENT_FORMAT, payload,
					   payload_len);
	}

	if (slot == NULL) {
		slot = free_status_observer_locked();
		if (slot == NULL) {
			k_mutex_unlock(&s_observe_mutex);
			return lichen_coap_respond(
				resource, request, addr, addr_len,
				COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0, NULL, 0U);
		}
		memset(slot, 0, sizeof(*slot));
		coap_observer_init(&slot->observer, request, addr);
		slot->addr_len = addr_len;
		slot->active = true;
		(void)coap_register_observer(resource, &slot->observer);
	}
	slot->addr_len = addr_len;
	slot->last_refresh_ms = now_ms;
	slot->pending = false;
	slot->retries = 0U;
	if (s_observe.stats.sequence == 0U) {
		s_observe.stats.sequence = STATUS_OBSERVE_FIRST_SEQUENCE;
		resource->age = STATUS_OBSERVE_FIRST_SEQUENCE;
	}
	/* All observers of one resource must share one immutable representation
	 * for an Observe value. A refresh/new subscriber therefore receives the
	 * sampled cache; provider changes are admitted only by the poll policy. */
	if (!s_observe.have_payload) {
		memcpy(s_observe.payload, payload, payload_len);
		s_observe.payload_len = payload_len;
		s_observe.have_payload = true;
		s_observe.last_notify_ms = now_ms;
	}
	s_observe.stats.observers = status_observer_count_locked();
	ret = send_status_slot_locked(slot, true, coap_header_get_type(request),
				      coap_header_get_id(request));
	if (ret < 0) {
		s_observe.stats.last_error = ret;
		s_observe.stats.failures++;
		remove_status_observer_locked(slot);
	} else {
		s_observe.stats.notifications++;
	}
	k_mutex_unlock(&s_observe_mutex);
	return ret;
}

static int status_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[LICHEN_COAP_STATUS_CBOR_MAX_SIZE];
	struct lichen_coap_node_status status = {0};
	ssize_t len;
	int r;

	if (!s_initialized || !s_config.status_get) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}

	r = s_config.status_get(&status);
	if (r < 0) {
		LOG_WRN("status_get callback failed: %d", r);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	len = lichen_coap_encode_status_cbor(cbor_buf, sizeof(cbor_buf), &status);
	if (len < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	{
		struct coap_option observe_options[2];
		int option_count = coap_find_options(request, COAP_OPTION_OBSERVE,
						     observe_options,
						     ARRAY_SIZE(observe_options));

		if (option_count < 0 || option_count > 1) {
			return lichen_coap_respond(resource, request, addr, addr_len,
						   COAP_RESPONSE_CODE_BAD_REQUEST,
						   0, NULL, 0U);
		}
	}
	r = coap_get_option_int(request, COAP_OPTION_OBSERVE);
	if (r >= 0) {
		return status_observe_request(resource, request, addr, addr_len,
					      cbor_buf, (size_t)len, r);
	}
	if (r != -ENOENT) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST, 0,
					   NULL, 0U);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, (size_t)len);
}

static void status_notify(struct coap_resource *resource,
			  struct coap_observer *observer)
{
	struct status_observer_slot *slot;

	ARG_UNUSED(resource);
	k_mutex_lock(&s_observe_mutex, K_FOREVER);
	slot = CONTAINER_OF(observer, struct status_observer_slot, observer);
	if (slot->active && s_observe.have_payload) {
		(void)send_status_slot_locked(slot, false, COAP_TYPE_NON_CON, 0U);
	}
	k_mutex_unlock(&s_observe_mutex);
}

static int neighbors_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[LICHEN_COAP_NEIGHBORS_CBOR_MAX_SIZE];
	struct lichen_coap_neighbor neighbors[CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS];
	ssize_t len;
	int count;
	int r;

	r = coap_resource_parse_observe(resource, request, addr);
	if (r < 0 && r != -ENOENT) {
		LOG_WRN("Observe parse failed: %d", r);
	}

	if (!s_initialized || !s_config.neighbors_get) {
		len = lichen_coap_encode_neighbors_cbor(cbor_buf, sizeof(cbor_buf),
							NULL, 0);
		if (len < 0) {
			return lichen_coap_respond(resource, request, addr, addr_len,
						   COAP_RESPONSE_CODE_TOO_MANY_REQUESTS, 0, NULL, 0);
		}

		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, (size_t)len);
	}

	count = s_config.neighbors_get(neighbors, ARRAY_SIZE(neighbors));
	if (count < 0) {
		LOG_WRN("neighbors_get callback failed: %d", count);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}
	if (count > (int)ARRAY_SIZE(neighbors)) {
		LOG_ERR("neighbors_get returned too many entries: %d > %zu",
			count, ARRAY_SIZE(neighbors));
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	len = lichen_coap_encode_neighbors_cbor(cbor_buf, sizeof(cbor_buf),
						neighbors, (size_t)count);
	if (len < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_TOO_MANY_REQUESTS, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, (size_t)len);
}

static void neighbors_notify(struct coap_resource *resource,
			     struct coap_observer *observer)
{
	static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t cbor_buf[LICHEN_COAP_NEIGHBORS_CBOR_MAX_SIZE];
	struct coap_packet notif;
	struct lichen_coap_neighbor neighbors[CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS];
	ssize_t cbor_len;
	int count;
	int r;

	if (!s_initialized || !s_config.neighbors_get) {
		return;
	}

	count = s_config.neighbors_get(neighbors, ARRAY_SIZE(neighbors));
	if (count < 0) {
		count = 0;
	}
	if (count > (int)ARRAY_SIZE(neighbors)) {
		count = (int)ARRAY_SIZE(neighbors);
	}

	cbor_len = lichen_coap_encode_neighbors_cbor(cbor_buf, sizeof(cbor_buf),
						     neighbors, (size_t)count);
	if (cbor_len < 0) {
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

	r = coap_packet_append_payload(&notif, cbor_buf, (uint16_t)cbor_len);
	if (r < 0) {
		return;
	}

	(void)coap_resource_send(resource, &notif,
				 &observer->addr, sizeof(observer->addr), NULL);
}

static void routes_notify(struct coap_resource *resource,
			  struct coap_observer *observer)
{
	static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t cbor_buf[LICHEN_COAP_ROUTES_CBOR_MAX_SIZE];
	struct coap_packet notif;
	struct lichen_coap_route routes[CONFIG_LICHEN_COAP_STATUS_MAX_ROUTES];
	uint8_t default_route[16];
	bool has_default = false;
	ssize_t cbor_len;
	int count;
	int r;

	if (!s_initialized || !s_config.routes_get) {
		return;
	}

	count = s_config.routes_get(routes, ARRAY_SIZE(routes), default_route, &has_default);
	if (count < 0) {
		count = 0;
	}
	if (count > (int)ARRAY_SIZE(routes)) {
		count = (int)ARRAY_SIZE(routes);
	}

	cbor_len = lichen_coap_encode_routes_cbor(cbor_buf, sizeof(cbor_buf),
						  routes, (size_t)count,
						  has_default ? default_route : NULL);
	if (cbor_len <= 0) {
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

	r = coap_packet_append_payload(&notif, cbor_buf, (uint16_t)cbor_len);
	if (r < 0) {
		return;
	}

	(void)coap_resource_send(resource, &notif,
				 &observer->addr, sizeof(observer->addr), NULL);
}

static int routes_get(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[LICHEN_COAP_ROUTES_CBOR_MAX_SIZE];
	struct lichen_coap_route routes[CONFIG_LICHEN_COAP_STATUS_MAX_ROUTES];
	uint8_t default_route[16];
	bool has_default = false;
	ssize_t len;
	int count;
	int r;

	r = coap_resource_parse_observe(resource, request, addr);
	if (r < 0 && r != -ENOENT) {
		LOG_WRN("Observe parse failed: %d", r);
	}

	if (!s_initialized || !s_config.routes_get) {
		len = lichen_coap_encode_routes_cbor(cbor_buf, sizeof(cbor_buf),
						     NULL, 0, NULL);
		if (len < 0) {
			return lichen_coap_respond(resource, request, addr, addr_len,
						   COAP_RESPONSE_CODE_TOO_MANY_REQUESTS, 0, NULL, 0);
		}

		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, (size_t)len);
	}

	count = s_config.routes_get(routes, ARRAY_SIZE(routes), default_route, &has_default);
	if (count < 0) {
		LOG_WRN("routes_get callback failed: %d", count);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}
	if (count > (int)ARRAY_SIZE(routes)) {
		LOG_ERR("routes_get returned too many entries: %d > %zu",
			count, ARRAY_SIZE(routes));
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	len = lichen_coap_encode_routes_cbor(cbor_buf, sizeof(cbor_buf),
					     routes, (size_t)count,
					     has_default ? default_route : NULL);
	if (len < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_TOO_MANY_REQUESTS, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, (size_t)len);
}

static const char * const status_path[] = { "status", NULL };
static const char * const neighbors_path[] = { "status", "neighbors", NULL };
static const char * const routes_path[] = { "status", "routes", NULL };

struct coap_resource lichen_coap_status_resource = {
	.get    = status_get,
	.notify = status_notify,
	.path   = status_path,
};

struct coap_resource lichen_coap_neighbors_resource = {
	.get    = neighbors_get,
	.notify = neighbors_notify,
	.path   = neighbors_path,
};

struct coap_resource lichen_coap_routes_resource = {
	.get    = routes_get,
	.notify = routes_notify,
	.path   = routes_path,
};

int lichen_coap_status_observe_poll(int64_t now_ms)
{
	uint8_t payload[LICHEN_COAP_STATUS_CBOR_MAX_SIZE];
	struct lichen_coap_node_status status = {0};
	bool changed;
	bool refresh;
	ssize_t payload_len;
	int ret;

	if (now_ms < 0) {
		return -EINVAL;
	}
	k_mutex_lock(&s_observe_mutex, K_FOREVER);
	if (s_observe.have_last_poll && now_ms < s_observe.last_poll_ms) {
		k_mutex_unlock(&s_observe_mutex);
		return -EINVAL;
	}
	s_observe.have_last_poll = true;
	s_observe.last_poll_ms = now_ms;
	expire_status_observers_locked(now_ms);
	if (retry_status_observers_locked(now_ms)) {
		k_mutex_unlock(&s_observe_mutex);
		return LICHEN_COAP_STATUS_OBSERVE_DEFERRED;
	}
	if (status_observer_count_locked() == 0U) {
		k_mutex_unlock(&s_observe_mutex);
		return LICHEN_COAP_STATUS_OBSERVE_IDLE;
	}
	k_mutex_unlock(&s_observe_mutex);

	if (!s_initialized || s_config.status_get == NULL) {
		return -ENOENT;
	}
	ret = s_config.status_get(&status);
	if (ret < 0) {
		k_mutex_lock(&s_observe_mutex, K_FOREVER);
		s_observe.stats.last_error = ret;
		s_observe.stats.failures++;
		k_mutex_unlock(&s_observe_mutex);
		return ret;
	}
	payload_len = lichen_coap_encode_status_cbor(payload, sizeof(payload),
						      &status);
	if (payload_len < 0) {
		k_mutex_lock(&s_observe_mutex, K_FOREVER);
		s_observe.stats.last_error = (int)payload_len;
		s_observe.stats.failures++;
		k_mutex_unlock(&s_observe_mutex);
		return (int)payload_len;
	}

	k_mutex_lock(&s_observe_mutex, K_FOREVER);
	expire_status_observers_locked(now_ms);
	if (status_observer_count_locked() == 0U) {
		k_mutex_unlock(&s_observe_mutex);
		return LICHEN_COAP_STATUS_OBSERVE_IDLE;
	}
	changed = !s_observe.have_payload ||
		  s_observe.payload_len != (size_t)payload_len ||
		  memcmp(s_observe.payload, payload, (size_t)payload_len) != 0;
	refresh = s_observe.have_payload && now_ms >= s_observe.last_notify_ms &&
		  (uint64_t)(now_ms - s_observe.last_notify_ms) >=
			  LICHEN_COAP_STATUS_OBSERVE_MAX_INTERVAL_MS;
	if (!changed && !refresh) {
		k_mutex_unlock(&s_observe_mutex);
		return LICHEN_COAP_STATUS_OBSERVE_IDLE;
	}
	if (changed && s_observe.have_payload &&
	    now_ms >= s_observe.last_notify_ms &&
	    (uint64_t)(now_ms - s_observe.last_notify_ms) <
		    LICHEN_COAP_STATUS_OBSERVE_MIN_INTERVAL_MS) {
		k_mutex_unlock(&s_observe_mutex);
		return LICHEN_COAP_STATUS_OBSERVE_DEFERRED;
	}

	s_observe.stats.sequence = status_next_sequence(s_observe.stats.sequence);
	lichen_coap_status_resource.age = s_observe.stats.sequence;
	memcpy(s_observe.payload, payload, (size_t)payload_len);
	s_observe.payload_len = (size_t)payload_len;
	s_observe.have_payload = true;
	s_observe.last_notify_ms = now_ms;
	for (size_t i = 0U; i < ARRAY_SIZE(s_observe.slots); i++) {
		struct status_observer_slot *slot = &s_observe.slots[i];

		if (!slot->active) {
			continue;
		}
		ret = send_status_slot_locked(slot, false, COAP_TYPE_NON_CON, 0U);
		if (ret == 0) {
			s_observe.stats.notifications++;
			continue;
		}
		s_observe.stats.last_error = ret;
		if (status_transient_send_error(ret)) {
			slot->pending = true;
			slot->retries = 0U;
			slot->retry_at_ms = status_deadline_after(
				now_ms, LICHEN_COAP_STATUS_OBSERVE_RETRY_MS);
			s_observe.stats.backpressure++;
			continue;
		}
		s_observe.stats.failures++;
		remove_status_observer_locked(slot);
	}
	k_mutex_unlock(&s_observe_mutex);
	return LICHEN_COAP_STATUS_OBSERVE_NOTIFIED;
}

void lichen_coap_status_observe_reset(void)
{
	k_mutex_lock(&s_observe_mutex, K_FOREVER);
	for (size_t i = 0U; i < ARRAY_SIZE(s_observe.slots); i++) {
		remove_status_observer_locked(&s_observe.slots[i]);
	}
	memset(&s_observe, 0, sizeof(s_observe));
	lichen_coap_status_resource.age = 0U;
	k_mutex_unlock(&s_observe_mutex);
}

int lichen_coap_status_observe_get_stats(
	struct lichen_coap_status_observe_stats *stats)
{
	if (stats == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&s_observe_mutex, K_FOREVER);
	s_observe.stats.observers = status_observer_count_locked();
	*stats = s_observe.stats;
	k_mutex_unlock(&s_observe_mutex);
	return 0;
}

#if defined(CONFIG_ZTEST)
int lichen_coap_status_observe_set_sequence_for_test(uint32_t sequence)
{
	if (sequence > COAP_OBSERVE_MAX_AGE) {
		return -EINVAL;
	}
	k_mutex_lock(&s_observe_mutex, K_FOREVER);
	s_observe.stats.sequence = sequence;
	lichen_coap_status_resource.age = sequence;
	k_mutex_unlock(&s_observe_mutex);
	return 0;
}
#endif

int lichen_coap_status_init(const struct lichen_coap_status_config *config)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	if (s_initialized) {
		k_mutex_unlock(&s_mutex);
		return 0;
	}
	if (config == NULL || config->status_get == NULL) {
		k_mutex_unlock(&s_mutex);
		return -EINVAL;
	}
	memcpy(&s_config, config, sizeof(s_config));
	s_initialized = true;
	k_mutex_unlock(&s_mutex);
	LOG_INF("CoAP status handlers initialized");
	return 0;
}

void lichen_coap_status_notify(void)
{
	if (!s_initialized || !s_config.status_get) {
		return;
	}
	(void)lichen_coap_status_observe_poll(k_uptime_get());
}

void lichen_coap_status_neighbors_notify(void)
{
	if (!s_initialized || !s_config.neighbors_get) {
		return;
	}
	coap_resource_notify(&lichen_coap_neighbors_resource);
}

void lichen_coap_status_routes_notify(void)
{
	if (!s_initialized || !s_config.routes_get) {
		return;
	}
	coap_resource_notify(&lichen_coap_routes_resource);
}
