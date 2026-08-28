/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_rangetest.c
 * @brief CoAP range testing resources (spec/12-apps.md section 18.7)
 *
 * Implements /diag/rangetest (extended and continuous range test) and
 * /diag/traceroute. Wire bytes are the canonical SenML/CBOR encodings
 * verified against test/vectors/rangetest.json.
 */

#include <lichen/coap_rangetest.h>

#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_link_format.h>
#include <zephyr/net/coap_service.h>

#include <lichen/coap_oscore.h>

#define RANGETEST_SENML_CBOR_MAX 192U
/* Traceroute worst case: map(1) + "hops"(5) + array(1) + 8 x 83 bytes per
 * max-length hop (map(1) + "addr"(5) + 2+45 addr + "rssi"(5) + f64(9) +
 * "rtt_ms"(7) + f64(9)) + "total_hops"(11) + uint(1) + "total_rtt_ms"(13) +
 * f64(9) = 41 + 8*83 = 705; 720 leaves headroom. */
#define RANGETEST_TRACE_CBOR_MAX 720U
#define RANGETEST_DECODE_MAX_ENTRIES 32U
#define RANGETEST_SKIP_MAX_DEPTH 8U
/* Floor for a continuous-test interval (spec 18.7): anything shorter
 * floods the radio once a scheduler consumes it. The valid vector uses
 * exactly 1000, so the floor is inclusive. */
#define RANGETEST_INTERVAL_MIN_MS 1000U

static struct lichen_rangetest_config s_config;
static uint8_t s_eui64[LICHEN_RANGETEST_EUI64_LEN];
static uint32_t s_seq;
static uint32_t s_interval_ms = LICHEN_RANGETEST_DEFAULT_INTERVAL_MS;
static K_MUTEX_DEFINE(s_mutex);

#if IS_ENABLED(CONFIG_LICHEN_COAP_RANGETEST)
#include <zephyr/version.h>
/* COAP_RESOURCE_DEFINE names the symbol coap_resource_<name> on Zephyr 3.x
 * and plain <name> on 4.x (see coap_service.h). <zephyr/version.h> resolves
 * to the generated header defining KERNEL_VERSION_NUMBER (0x040100 = 4.1.0). */
#if KERNEL_VERSION_NUMBER >= 0x040000
extern struct coap_resource rangetest;
#define RANGETEST_RESOURCE_PTR (&rangetest)
#else
extern struct coap_resource coap_resource_rangetest;
#define RANGETEST_RESOURCE_PTR (&coap_resource_rangetest)
#endif
#endif

/* --------------------------------------------------------------------------
 * CBOR encoding helpers (bounds checked; ok=false marks a truncated encode)
 * -------------------------------------------------------------------------- */

struct cbor_enc {
	uint8_t *buf;
	size_t size;
	size_t off;
	bool ok;
};

static void enc_put(struct cbor_enc *e, uint8_t byte)
{
	if (e->off < e->size) {
		e->buf[e->off++] = byte;
	} else {
		e->ok = false;
	}
}

static void enc_bytes(struct cbor_enc *e, const uint8_t *data, size_t len)
{
	if (len <= e->size - e->off) {
		memcpy(&e->buf[e->off], data, len);
		e->off += len;
	} else {
		e->ok = false;
	}
}

static void enc_tstr(struct cbor_enc *e, const char *value, size_t len)
{
	if (len < 24U) {
		enc_put(e, 0x60U | (uint8_t)len);
	} else if (len <= UINT8_MAX) {
		enc_put(e, 0x78U);
		enc_put(e, (uint8_t)len);
	} else {
		e->ok = false;
		return;
	}
	enc_bytes(e, (const uint8_t *)value, len);
}

static void enc_key(struct cbor_enc *e, const char *key)
{
	enc_tstr(e, key, strlen(key));
}

static void enc_uint(struct cbor_enc *e, uint64_t value)
{
	if (value < 24U) {
		enc_put(e, (uint8_t)value);
	} else if (value <= UINT8_MAX) {
		enc_put(e, 0x18U);
		enc_put(e, (uint8_t)value);
	} else if (value <= UINT16_MAX) {
		enc_put(e, 0x19U);
		enc_put(e, (uint8_t)(value >> 8));
		enc_put(e, (uint8_t)value);
	} else if (value <= UINT32_MAX) {
		enc_put(e, 0x1aU);
		for (unsigned int shift = 24U; shift != 0U; shift -= 8U) {
			enc_put(e, (uint8_t)(value >> shift));
		}
		enc_put(e, (uint8_t)value);
	} else {
		enc_put(e, 0x1bU);
		for (unsigned int shift = 56U; shift != 0U; shift -= 8U) {
			enc_put(e, (uint8_t)(value >> shift));
		}
		enc_put(e, (uint8_t)value);
	}
}

/* Encodes the negative integer -(value+1); only -2/-3 (bn/bt) are needed. */
static void enc_small_nint(struct cbor_enc *e, uint64_t value)
{
	if (value >= 24U) {
		e->ok = false;
		return;
	}
	enc_put(e, (uint8_t)(0x20U | value));
}

static void enc_map(struct cbor_enc *e, size_t count)
{
	if (count < 24U) {
		enc_put(e, 0xa0U | (uint8_t)count);
	} else if (count <= UINT8_MAX) {
		enc_put(e, 0xb8U);
		enc_put(e, (uint8_t)count);
	} else {
		e->ok = false;
	}
}

static void enc_array(struct cbor_enc *e, size_t count)
{
	if (count < 24U) {
		enc_put(e, 0x80U | (uint8_t)count);
	} else {
		e->ok = false;
	}
}

static void enc_f64(struct cbor_enc *e, double value)
{
	union {
		double d;
		uint64_t u;
	} conv;

	conv.d = value;
	enc_put(e, 0xfbU);
	for (unsigned int shift = 56U; shift != 0U; shift -= 8U) {
		enc_put(e, (uint8_t)(conv.u >> shift));
	}
	enc_put(e, (uint8_t)conv.u);
}

/* --------------------------------------------------------------------------
 * Strict CBOR decoding helpers (whole-input, map of text keys only)
 * -------------------------------------------------------------------------- */

struct cbor_cursor {
	const uint8_t *buf;
	size_t len;
	size_t off;
};

static bool cur_read_head(struct cbor_cursor *c, uint8_t *major,
			  uint64_t *argument)
{
	uint8_t initial;
	uint8_t additional;
	uint64_t decoded = 0U;
	size_t width;

	if (c->off >= c->len) {
		return false;
	}
	initial = c->buf[c->off++];
	*major = initial & 0xe0U;
	additional = initial & 0x1fU;
	if (additional < 24U) {
		*argument = additional;
		return true;
	}
	switch (additional) {
	case 24U:
		width = 1U;
		break;
	case 25U:
		width = 2U;
		break;
	case 26U:
		width = 4U;
		break;
	case 27U:
		width = 8U;
		break;
	default:
		return false;
	}
	if (width > c->len - c->off) {
		return false;
	}
	for (size_t i = 0U; i < width; i++) {
		decoded = (decoded << 8) | c->buf[c->off++];
	}
	*argument = decoded;
	return true;
}

/**
 * Skips one data item of any type without interpreting it. Iterative with a
 * bounded container stack (no recursion; oversized nesting is rejected).
 */
static bool cur_skip_item(struct cbor_cursor *c)
{
	uint64_t counts[RANGETEST_SKIP_MAX_DEPTH];
	size_t depth = 0U;

	for (;;) {
		uint8_t major;
		uint64_t argument;

		if (!cur_read_head(c, &major, &argument)) {
			return false;
		}
		if (major == 0x40U || major == 0x60U) {
			if (argument > (uint64_t)(c->len - c->off)) {
				return false;
			}
			c->off += (size_t)argument;
		} else if (major == 0x80U || major == 0xa0U) {
			uint64_t slots;

			if (major == 0xa0U) {
				/* Reject arguments whose doubling would
				 * wrap; a wrapped slot count makes the
				 * container look empty and re-aligns the
				 * parse on untrusted input. */
				if (argument > UINT64_MAX / 2U) {
					return false;
				}
				slots = argument * 2U;
			} else {
				slots = argument;
			}
			if (slots == 0U) {
				/* fall through to the unwind below */
			} else if (depth >= RANGETEST_SKIP_MAX_DEPTH) {
				return false;
			} else {
				counts[depth++] = slots;
				continue;
			}
		} else if (major == 0xc0U) {
			/* Tag: the tagged item follows as the next item. */
			continue;
		}
		/* uint, nint, simple/float, or a completed empty container. */
		while (depth > 0U) {
			if (counts[depth - 1U] > 1U) {
				counts[depth - 1U]--;
				break;
			}
			depth--;
		}
		if (depth == 0U) {
			return true;
		}
	}
}

static bool cur_read_key(struct cbor_cursor *c, const uint8_t **key,
			 size_t *key_len)
{
	uint8_t major;
	uint64_t argument;

	if (!cur_read_head(c, &major, &argument) || major != 0x60U ||
	    argument > (uint64_t)(c->len - c->off)) {
		return false;
	}
	*key = &c->buf[c->off];
	*key_len = (size_t)argument;
	c->off += (size_t)argument;
	return true;
}

static bool cur_read_uint(struct cbor_cursor *c, uint32_t *value)
{
	uint8_t major;
	uint64_t argument;

	if (!cur_read_head(c, &major, &argument) || major != 0x00U ||
	    argument > UINT32_MAX) {
		return false;
	}
	*value = (uint32_t)argument;
	return true;
}

static bool cur_read_map_count(struct cbor_cursor *c, size_t *count)
{
	uint8_t major;
	uint64_t argument;

	if (!cur_read_head(c, &major, &argument) || major != 0xa0U ||
	    argument > RANGETEST_DECODE_MAX_ENTRIES) {
		return false;
	}
	*count = (size_t)argument;
	return true;
}

/**
 * Shared body decoder: requires a single top-level map, feeds each key to
 * @p handle (which must consume the value; return 1 to skip an unknown
 * entry), and rejects trailing bytes. Atomic: @p ctx is only updated once
 * the whole body parsed cleanly.
 */
static int decode_entries(const uint8_t *buf, size_t len,
			  int (*handle)(const uint8_t *key, size_t key_len,
					struct cbor_cursor *c, void *ctx),
			  void *ctx)
{
	struct cbor_cursor c = {.buf = buf, .len = len};
	size_t count;

	if (buf == NULL) {
		return -EINVAL;
	}
	if (!cur_read_map_count(&c, &count)) {
		return -EBADMSG;
	}
	for (size_t i = 0U; i < count; i++) {
		const uint8_t *key;
		size_t key_len;
		int ret;

		if (!cur_read_key(&c, &key, &key_len)) {
			return -EBADMSG;
		}
		ret = handle(key, key_len, &c, ctx);
		if (ret < 0) {
			return ret;
		}
	}
	if (c.off != c.len) {
		return -EBADMSG;
	}
	return 0;
}

/* --------------------------------------------------------------------------
 * SenML / traceroute encoding
 * -------------------------------------------------------------------------- */

int lichen_rangetest_senml_encode(uint8_t *buf, size_t buf_size,
				  const char *base_name, uint32_t base_time,
				  uint32_t seq,
				  const struct lichen_rangetest_metrics *metrics)
{
	struct cbor_enc e = {.buf = buf, .size = buf_size, .ok = true};
	size_t bn_len;

	if (buf == NULL || base_name == NULL || metrics == NULL ||
	    !isfinite(metrics->rssi) || !isfinite(metrics->snr) ||
	    !isfinite(metrics->freq)) {
		return -EINVAL;
	}
	bn_len = strlen(base_name);
	if (bn_len == 0U || bn_len > LICHEN_RANGETEST_BN_MAX - 1U) {
		return -EINVAL;
	}

	enc_array(&e, 6U);

	/* Base record: bn (-2) then bt (-3) per the canonical vectors. */
	enc_map(&e, 2U);
	enc_small_nint(&e, 1U);
	enc_tstr(&e, base_name, bn_len);
	enc_small_nint(&e, 2U);
	enc_uint(&e, base_time);

	/* seq */
	enc_map(&e, 2U);
	enc_put(&e, 0U);
	enc_key(&e, "seq");
	enc_put(&e, 2U);
	enc_uint(&e, seq);

	/* rssi */
	enc_map(&e, 3U);
	enc_put(&e, 0U);
	enc_key(&e, "rssi");
	enc_put(&e, 1U);
	enc_key(&e, "dBm");
	enc_put(&e, 2U);
	enc_f64(&e, metrics->rssi);

	/* snr */
	enc_map(&e, 3U);
	enc_put(&e, 0U);
	enc_key(&e, "snr");
	enc_put(&e, 1U);
	enc_key(&e, "dB");
	enc_put(&e, 2U);
	enc_f64(&e, metrics->snr);

	/* sf */
	enc_map(&e, 2U);
	enc_put(&e, 0U);
	enc_key(&e, "sf");
	enc_put(&e, 2U);
	enc_uint(&e, metrics->sf);

	/* freq */
	enc_map(&e, 3U);
	enc_put(&e, 0U);
	enc_key(&e, "freq");
	enc_put(&e, 1U);
	enc_key(&e, "MHz");
	enc_put(&e, 2U);
	enc_f64(&e, metrics->freq);

	return e.ok ? (int)e.off : -ENOBUFS;
}

int lichen_traceroute_encode(uint8_t *buf, size_t buf_size,
			     const struct lichen_rangetest_hop *hops,
			     size_t hop_count)
{
	struct cbor_enc e = {.buf = buf, .size = buf_size, .ok = true};

	if (buf == NULL || (hops == NULL && hop_count > 0U)) {
		return -EINVAL;
	}

	enc_map(&e, 3U);
	enc_key(&e, "hops");
	enc_array(&e, hop_count);
	for (size_t i = 0U; i < hop_count; i++) {
		size_t addr_len = strnlen(hops[i].addr, sizeof(hops[i].addr));

		if (!isfinite(hops[i].rssi) || !isfinite(hops[i].rtt_ms) ||
		    addr_len == 0U || addr_len >= sizeof(hops[i].addr)) {
			return -EINVAL;
		}
		enc_map(&e, 3U);
		enc_key(&e, "addr");
		enc_tstr(&e, hops[i].addr, addr_len);
		enc_key(&e, "rssi");
		enc_f64(&e, hops[i].rssi);
		enc_key(&e, "rtt_ms");
		enc_f64(&e, hops[i].rtt_ms);
	}
	enc_key(&e, "total_hops");
	enc_uint(&e, hop_count);
	enc_key(&e, "total_rtt_ms");
	enc_f64(&e, hop_count > 0U ? hops[hop_count - 1U].rtt_ms : 0.0);

	return e.ok ? (int)e.off : -ENOBUFS;
}

/* --------------------------------------------------------------------------
 * Request body decoding
 * -------------------------------------------------------------------------- */

struct request_fields {
	bool has_seq;
	uint32_t seq;
	bool has_payload_len;
	uint32_t payload_len;
	bool has_count;
	uint32_t count;
};

static int request_handle_key(const uint8_t *key, size_t key_len,
			      struct cbor_cursor *c, void *ctx)
{
	struct request_fields *fields = ctx;

	if (key_len == 3U && memcmp(key, "seq", 3U) == 0) {
		if (fields->has_seq || !cur_read_uint(c, &fields->seq)) {
			return -EBADMSG;
		}
		fields->has_seq = true;
	} else if (key_len == 11U && memcmp(key, "payload_len", 11U) == 0) {
		if (fields->has_payload_len ||
		    !cur_read_uint(c, &fields->payload_len) ||
		    fields->payload_len > LICHEN_RANGETEST_MAX_PAYLOAD_LEN) {
			return -EBADMSG;
		}
		fields->has_payload_len = true;
	} else if (key_len == 5U && memcmp(key, "count", 5U) == 0) {
		if (fields->has_count || !cur_read_uint(c, &fields->count) ||
		    fields->count < 1U ||
		    fields->count > LICHEN_RANGETEST_MAX_COUNT) {
			return -EBADMSG;
		}
		fields->has_count = true;
	} else if (!cur_skip_item(c)) {
		return -EBADMSG;
	}
	return 0;
}

int lichen_rangetest_request_decode(const uint8_t *buf, size_t len,
				    struct lichen_rangetest_request *req)
{
	struct request_fields fields = {0};
	int ret;

	if (req == NULL) {
		return -EINVAL;
	}
	if (len > 0U) {
		ret = decode_entries(buf, len, request_handle_key, &fields);
		if (ret < 0) {
			return ret;
		}
	}
	memset(req, 0, sizeof(*req));
	req->has_seq = fields.has_seq;
	req->seq = fields.seq;
	req->has_payload_len = fields.has_payload_len;
	req->payload_len = fields.payload_len;
	req->has_count = fields.has_count;
	req->count = fields.count;
	return 0;
}

static int interval_handle_key(const uint8_t *key, size_t key_len,
			       struct cbor_cursor *c, void *ctx)
{
	struct lichen_rangetest_interval *out = ctx;
	uint32_t value;

	if (key_len == 11U && memcmp(key, "interval_ms", 11U) == 0) {
		if (out->has_interval_ms || !cur_read_uint(c, &value) ||
		    value == 0U || value < RANGETEST_INTERVAL_MIN_MS) {
			return -EBADMSG;
		}
		out->has_interval_ms = true;
		out->interval_ms = value;
	} else if (!cur_skip_item(c)) {
		return -EBADMSG;
	}
	return 0;
}

int lichen_rangetest_interval_decode(const uint8_t *buf, size_t len,
				     struct lichen_rangetest_interval *out)
{
	struct lichen_rangetest_interval decoded = {0};
	int ret;

	if (out == NULL) {
		return -EINVAL;
	}
	if (len > 0U) {
		ret = decode_entries(buf, len, interval_handle_key, &decoded);
		if (ret < 0) {
			return ret;
		}
	}
	*out = decoded;
	return 0;
}

/* --------------------------------------------------------------------------
 * Provider plumbing
 * -------------------------------------------------------------------------- */

static void metrics_get(struct lichen_rangetest_metrics *metrics)
{
	static const struct lichen_rangetest_metrics defaults = {
		.rssi = -85.0,
		.snr = 7.5,
		.sf = 9U,
		.freq = 906.875,
	};

	if (s_config.get_metrics != NULL) {
		s_config.get_metrics(metrics);
		if (!isfinite(metrics->rssi) || !isfinite(metrics->snr) ||
		    !isfinite(metrics->freq)) {
			*metrics = defaults;
		}
	} else {
		*metrics = defaults;
	}
}

static size_t hops_get(struct lichen_rangetest_hop *hops)
{
	if (s_config.get_hops == NULL) {
		return 0U;
	}
	{
		size_t count = s_config.get_hops(hops, LICHEN_RANGETEST_MAX_HOPS);

		return count > LICHEN_RANGETEST_MAX_HOPS ? LICHEN_RANGETEST_MAX_HOPS
							 : count;
	}
}

static uint32_t time_now(void)
{
	return s_config.now != NULL ? s_config.now() : 0U;
}

static void build_base_name(char *base_name, size_t size)
{
	static const char hex[] = "0123456789abcdef";
	const char prefix[] = "urn:dev:mac:";
	size_t off = 0U;

	if (size < LICHEN_RANGETEST_BN_MAX) {
		if (size > 0U) {
			base_name[0] = '\0';
		}
		return;
	}
	memcpy(base_name, prefix, sizeof(prefix) - 1U);
	off = sizeof(prefix) - 1U;
	for (size_t i = 0U; i < sizeof(s_eui64); i++) {
		base_name[off++] = hex[s_eui64[i] >> 4];
		base_name[off++] = hex[s_eui64[i] & 0x0fU];
	}
	base_name[off++] = ':';
	base_name[off] = '\0';
}

static int build_senml(uint8_t *buf, size_t buf_size, uint32_t seq)
{
	char base_name[LICHEN_RANGETEST_BN_MAX];
	struct lichen_rangetest_metrics metrics;

	build_base_name(base_name, sizeof(base_name));
	metrics_get(&metrics);
	return lichen_rangetest_senml_encode(buf, buf_size, base_name,
					     time_now(), seq, &metrics);
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

int lichen_rangetest_init(const struct lichen_rangetest_config *config)
{
	if (config == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	s_config = *config;
	if (config->eui64 != NULL) {
		memcpy(s_eui64, config->eui64, sizeof(s_eui64));
	} else {
		memset(s_eui64, 0, sizeof(s_eui64));
	}
	s_config.eui64 = s_eui64;
	s_seq = 0U;
	s_interval_ms = LICHEN_RANGETEST_DEFAULT_INTERVAL_MS;
	k_mutex_unlock(&s_mutex);
	return 0;
}

uint32_t lichen_rangetest_seq(void)
{
	uint32_t seq;

	k_mutex_lock(&s_mutex, K_FOREVER);
	seq = s_seq;
	k_mutex_unlock(&s_mutex);
	return seq;
}

uint32_t lichen_rangetest_interval_ms(void)
{
	uint32_t interval;

	k_mutex_lock(&s_mutex, K_FOREVER);
	interval = s_interval_ms;
	k_mutex_unlock(&s_mutex);
	return interval;
}

void lichen_rangetest_update(void)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	s_seq = s_seq == UINT32_MAX ? 0U : s_seq + 1U;
	k_mutex_unlock(&s_mutex);
#if IS_ENABLED(CONFIG_LICHEN_COAP_RANGETEST)
	(void)coap_resource_notify(RANGETEST_RESOURCE_PTR);
#endif
}

/* --------------------------------------------------------------------------
 * CoAP resource handlers
 * -------------------------------------------------------------------------- */

int lichen_rangetest_post_handler(struct coap_resource *resource,
				  struct coap_packet *request,
				  struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct lichen_rangetest_request req;
	uint8_t cbor[RANGETEST_SENML_CBOR_MAX];
	uint32_t seq;
	int len;
	int ret;

	ret = coap_oscore_unprotect_resource_request(
		resource, request, addr, addr_len, COAP_METHOD_POST, &oscore);
	if (ret != 0) {
		return ret;
	}
	ret = lichen_rangetest_request_decode(oscore.payload,
					      oscore.payload_len, &req);
	if (ret < 0) {
		return coap_oscore_respond_resource(
			resource, request, addr, addr_len, &oscore,
			COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	seq = req.has_seq ? req.seq : 0U;
	len = build_senml(cbor, sizeof(cbor), seq);
	if (len < 0) {
		return coap_oscore_respond_resource(
			resource, request, addr, addr_len, &oscore,
			COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0, NULL, 0);
	}
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CONTENT,
					    LICHEN_RANGETEST_CF_SENML_CBOR,
					    cbor, (size_t)len);
}

int lichen_rangetest_get_handler(struct coap_resource *resource,
				 struct coap_packet *request,
				 struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct coap_option observe_options[2];
	struct lichen_rangetest_interval interval;
	uint8_t cbor[RANGETEST_SENML_CBOR_MAX];
	uint32_t seq;
	int observe_count;
	int len;
	int ret;

	ret = coap_oscore_unprotect_resource_request(
		resource, request, addr, addr_len, COAP_METHOD_GET, &oscore);
	if (ret != 0) {
		return ret;
	}
	observe_count = coap_find_options(request, COAP_OPTION_OBSERVE,
					  observe_options,
					  ARRAY_SIZE(observe_options));
	if (observe_count < 0 || observe_count > 1) {
		return coap_oscore_respond_resource(
			resource, request, addr, addr_len, &oscore,
			COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	ret = lichen_rangetest_interval_decode(oscore.payload,
					       oscore.payload_len, &interval);
	if (ret < 0) {
		return coap_oscore_respond_resource(
			resource, request, addr, addr_len, &oscore,
			COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	if (interval.has_interval_ms) {
		k_mutex_lock(&s_mutex, K_FOREVER);
		s_interval_ms = interval.interval_ms;
		k_mutex_unlock(&s_mutex);
	}
	k_mutex_lock(&s_mutex, K_FOREVER);
	seq = s_seq;
	k_mutex_unlock(&s_mutex);
	len = build_senml(cbor, sizeof(cbor), seq);
	if (len < 0) {
		return coap_oscore_respond_resource(
			resource, request, addr, addr_len, &oscore,
			COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0, NULL, 0);
	}
	/* RFC 7641: only register the observer once the request is fully
	 * validated and the response is guaranteed; a 4.00/5.03 must not
	 * consume an observer slot. */
	if (observe_count == 1) {
		ret = coap_resource_parse_observe(resource, request, addr);
		if (ret < 0) {
			return coap_oscore_respond_resource(
				resource, request, addr, addr_len, &oscore,
				COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0,
				NULL, 0);
		}
	}
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CONTENT,
					    LICHEN_RANGETEST_CF_SENML_CBOR,
					    cbor, (size_t)len);
}

int lichen_traceroute_get_handler(struct coap_resource *resource,
				  struct coap_packet *request,
				  struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct lichen_rangetest_hop hops[LICHEN_RANGETEST_MAX_HOPS];
	uint8_t cbor[RANGETEST_TRACE_CBOR_MAX];
	size_t hop_count;
	int len;
	int ret;

	ret = coap_oscore_unprotect_resource_request(
		resource, request, addr, addr_len, COAP_METHOD_GET, &oscore);
	if (ret != 0) {
		return ret;
	}
	hop_count = hops_get(hops);
	len = lichen_traceroute_encode(cbor, sizeof(cbor), hops, hop_count);
	if (len < 0) {
		return coap_oscore_respond_resource(
			resource, request, addr, addr_len, &oscore,
			COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0, NULL, 0);
	}
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CONTENT,
					    LICHEN_RANGETEST_CF_CBOR, cbor,
					    (size_t)len);
}

void lichen_rangetest_notify_cb(struct coap_resource *resource,
				struct coap_observer *observer)
{
	uint8_t packet_buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t cbor[RANGETEST_SENML_CBOR_MAX];
	struct coap_packet packet;
	uint32_t seq;
	int len;
	int ret;

	k_mutex_lock(&s_mutex, K_FOREVER);
	seq = s_seq;
	k_mutex_unlock(&s_mutex);
	len = build_senml(cbor, sizeof(cbor), seq);
	if (len < 0) {
		return;
	}
	ret = coap_packet_init(&packet, packet_buf, sizeof(packet_buf),
			       COAP_VERSION_1, COAP_TYPE_NON_CON,
			       observer->tkl, observer->token,
			       COAP_RESPONSE_CODE_CONTENT, coap_next_id());
	if (ret == 0) {
		ret = coap_append_option_int(&packet, COAP_OPTION_OBSERVE,
					     (uint32_t)resource->age);
	}
	if (ret == 0) {
		ret = coap_append_option_int(&packet,
					     COAP_OPTION_CONTENT_FORMAT,
					     LICHEN_RANGETEST_CF_SENML_CBOR);
	}
	if (ret == 0) {
		ret = coap_packet_append_payload_marker(&packet);
	}
	if (ret == 0) {
		ret = coap_packet_append_payload(&packet, cbor, (uint16_t)len);
	}
	if (ret == 0) {
		(void)coap_resource_send(resource, &packet, &observer->addr,
					 sizeof(observer->addr), NULL);
	}
}

/* --------------------------------------------------------------------------
 * Resource registration (lichen_coap_server service, coap_server.c)
 * -------------------------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LICHEN_COAP_RANGETEST)

static const char *const rangetest_path[] = {"diag", "rangetest", NULL};
static const char *const rangetest_attrs[] = {
	"rt=\"rangetest\"",
	"ct=\"112\"",
	"obs",
	NULL,
};

COAP_RESOURCE_DEFINE(rangetest, lichen_coap_server,
		     {
			     .get = lichen_rangetest_get_handler,
			     .post = lichen_rangetest_post_handler,
			     .notify = lichen_rangetest_notify_cb,
			     .path = rangetest_path,
			     .user_data = &((struct coap_core_metadata){
				     .attributes = rangetest_attrs,
			     }),
		     });

static const char *const traceroute_path[] = {"diag", "traceroute", NULL};
static const char *const traceroute_attrs[] = {
	"rt=\"traceroute\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(traceroute, lichen_coap_server,
		     {
			     .get = lichen_traceroute_get_handler,
			     .path = traceroute_path,
			     .user_data = &((struct coap_core_metadata){
				     .attributes = traceroute_attrs,
			     }),
		     });

#endif /* CONFIG_LICHEN_COAP_RANGETEST */
