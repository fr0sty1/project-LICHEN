/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <math.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/ztest.h>

#include <lichen/coap_oscore.h>
#include <lichen/coap_rangetest.h>

static uint16_t coap_port = 5683U;
COAP_SERVICE_DEFINE(lichen_coap_server, NULL, &coap_port, 0);

#include "rangetest_vectors.inc"

/* Large enough for the largest canonical SenML pack in the vectors. */
#define TEST_SENML_BUF_MAX 192U

/* Mock OSCORE adapter: passes the vector body through unprotected. */
static const uint8_t *request_payload;
static size_t request_payload_len;
static uint8_t response_code;
static uint16_t response_cf;
static uint8_t response_payload[1024];
static size_t response_payload_len;

int coap_oscore_unprotect_resource_request(
	struct coap_resource *resource, struct coap_packet *request,
	struct sockaddr *addr, socklen_t addr_len, uint8_t expected_method,
	struct coap_oscore_unprotect_result *result)
{
	ARG_UNUSED(resource);
	ARG_UNUSED(request);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	ARG_UNUSED(expected_method);
	memset(result, 0, sizeof(*result));
	result->payload = (uint8_t *)request_payload;
	result->payload_len = (uint16_t)request_payload_len;
	return 0;
}

int coap_oscore_respond_resource(
	struct coap_resource *resource, struct coap_packet *request,
	struct sockaddr *addr, socklen_t addr_len,
	const struct coap_oscore_unprotect_result *result, uint8_t code,
	uint16_t content_format, const uint8_t *payload, size_t payload_len)
{
	ARG_UNUSED(resource);
	ARG_UNUSED(request);
	ARG_UNUSED(addr);
	ARG_UNUSED(addr_len);
	ARG_UNUSED(result);
	response_code = code;
	response_cf = content_format;
	response_payload_len = payload_len;
	if (payload_len > 0U) {
		zassert_true(payload_len <= sizeof(response_payload));
		memcpy(response_payload, payload, payload_len);
	}
	return 0;
}

/* Provider wired to the values the canonical vectors were derived from. */
static uint32_t test_now;
static const struct lichen_rangetest_hop *prov_hops;
static size_t prov_hop_count;

static void metrics_provider(struct lichen_rangetest_metrics *metrics)
{
	metrics->rssi = VEC_RSSI;
	metrics->snr = VEC_SNR;
	metrics->sf = (uint8_t)VEC_SF;
	metrics->freq = VEC_FREQ;
}

static size_t hops_provider(struct lichen_rangetest_hop *hops, size_t max_hops)
{
	size_t count = prov_hop_count < max_hops ? prov_hop_count : max_hops;

	for (size_t i = 0U; i < count; i++) {
		hops[i] = prov_hops[i];
	}
	return count;
}

static uint32_t now_provider(void)
{
	return test_now;
}

static void init_provider(void)
{
	static const struct lichen_rangetest_config config = {
		.eui64 = vec_eui64,
		.now = now_provider,
		.get_metrics = metrics_provider,
		.get_hops = hops_provider,
	};

	test_now = VEC_BT;
	prov_hops = NULL;
	prov_hop_count = 0U;
	response_code = 0U;
	response_cf = 0U;
	response_payload_len = 0U;
	zassert_ok(lichen_rangetest_init(&config));
}

static const struct rangetest_vector *find_vector(const char *name)
{
	for (size_t i = 0U; i < ARRAY_SIZE(rangetest_vectors); i++) {
		if (strcmp(rangetest_vectors[i].name, name) == 0) {
			return &rangetest_vectors[i];
		}
	}
	zassert_true(false, "vector %s not found", name);
	return NULL;
}

static void arm_vector(const struct rangetest_vector *vector)
{
	request_payload = vector->body;
	request_payload_len = vector->body_len;
	prov_hops = vector->hops;
	prov_hop_count = vector->hop_count;
}

static void invoke_vector(const struct rangetest_vector *vector,
			  struct coap_resource *resource,
			  struct coap_packet *request,
			  const struct sockaddr *addr)
{
	int ret;

	switch (vector->kind) {
	case 0:
		ret = lichen_rangetest_post_handler(resource, request,
						    (struct sockaddr *)addr,
						    sizeof(struct sockaddr_in6));
		break;
	case 1:
		ret = lichen_rangetest_get_handler(resource, request,
						   (struct sockaddr *)addr,
						   sizeof(struct sockaddr_in6));
		break;
	default:
		ret = lichen_traceroute_get_handler(
			resource, request, (struct sockaddr *)addr,
			sizeof(struct sockaddr_in6));
		break;
	}
	zassert_ok(ret, "%s: handler", vector->name);
}

ZTEST(coap_rangetest, test_all_vectors_byte_exact) {
	struct coap_resource resource = {0};
	struct coap_packet request = {0};
	struct sockaddr_in6 peer = {.sin6_family = AF_INET6};

	for (size_t i = 0U; i < ARRAY_SIZE(rangetest_vectors); i++) {
		const struct rangetest_vector *vector = &rangetest_vectors[i];
		uint8_t want_code = (uint8_t)((vector->code_class << 5) |
					      vector->code_detail);

		init_provider();
		arm_vector(vector);
		invoke_vector(vector, &resource, &request,
			      (const struct sockaddr *)&peer);
		zassert_equal(response_code, want_code,
			      "%s: response code got=0x%02x want=0x%02x",
			      vector->name, response_code, want_code);
		if (vector->cf == 0U) {
			zassert_equal(response_payload_len, 0U, "%s: no payload",
				      vector->name);
			continue;
		}
		zassert_equal(response_cf, vector->cf, "%s: content format",
			      vector->name);
		zassert_equal(response_payload_len, vector->payload_len,
			      "%s: payload length", vector->name);
		zassert_mem_equal(response_payload, vector->payload,
				  vector->payload_len, "%s: payload bytes",
				  vector->name);
	}
}

ZTEST(coap_rangetest, test_post_vectors_do_not_mutate_state) {
	struct coap_resource resource = {0};
	struct coap_packet request = {0};
	struct sockaddr_in6 peer = {.sin6_family = AF_INET6};

	init_provider();
	for (size_t i = 0U; i < ARRAY_SIZE(rangetest_vectors); i++) {
		const struct rangetest_vector *vector = &rangetest_vectors[i];

		if (vector->kind != 0) {
			continue;
		}
		arm_vector(vector);
		invoke_vector(vector, &resource, &request,
			      (const struct sockaddr *)&peer);
		zassert_equal(lichen_rangetest_seq(), 0U,
			      "%s: POST must not advance state seq",
			      vector->name);
	}
}

ZTEST(coap_rangetest, test_request_decode_matches_oracle_verdicts) {
	for (size_t i = 0U; i < ARRAY_SIZE(rangetest_vectors); i++) {
		const struct rangetest_vector *vector = &rangetest_vectors[i];
		bool should_succeed = vector->code_class == 2U;

		if (vector->kind == 2) {
			continue;
		}
		if (vector->kind == 0) {
			struct lichen_rangetest_request decoded = {
				.has_seq = true,
				.seq = 0xdeadbeefU,
			};

			if (should_succeed) {
				zassert_ok(
					lichen_rangetest_request_decode(
						vector->body, vector->body_len,
						&decoded),
					"%s: decode", vector->name);
				if (decoded.has_seq) {
					zassert_equal(decoded.seq,
						      vector->expected_seq,
						      "%s: echoed seq",
						      vector->name);
				}
			} else {
				zassert_true(
					lichen_rangetest_request_decode(
						vector->body, vector->body_len,
						&decoded) < 0,
					"%s: must be rejected", vector->name);
				zassert_true(decoded.has_seq,
					     "%s: decode must be atomic",
					     vector->name);
				zassert_equal(decoded.seq, 0xdeadbeefU,
					      "%s: decode must be atomic",
					      vector->name);
			}
		} else {
			struct lichen_rangetest_interval decoded = {
				.has_interval_ms = true,
				.interval_ms = 0xcafeU,
			};

			if (should_succeed) {
				zassert_ok(
					lichen_rangetest_interval_decode(
						vector->body, vector->body_len,
						&decoded),
					"%s: decode", vector->name);
			} else {
				zassert_true(
					lichen_rangetest_interval_decode(
						vector->body, vector->body_len,
						&decoded) < 0,
					"%s: must be rejected", vector->name);
				zassert_true(decoded.has_interval_ms,
					     "%s: decode must be atomic",
					     vector->name);
				zassert_equal(decoded.interval_ms, 0xcafeU,
					      "%s: decode must be atomic",
					      vector->name);
			}
		}
	}
}

ZTEST(coap_rangetest, test_interval_state_semantics) {
	struct coap_resource resource = {0};
	struct coap_packet request = {0};
	struct sockaddr_in6 peer = {.sin6_family = AF_INET6};
	const struct rangetest_vector *valid = find_vector(
		"rangetest_get_interval_valid");
	const struct rangetest_vector *zero = find_vector(
		"rangetest_get_interval_min_boundary");

	init_provider();
	zassert_equal(lichen_rangetest_interval_ms(),
		      LICHEN_RANGETEST_DEFAULT_INTERVAL_MS);
	zassert_equal(lichen_rangetest_seq(), 0U);

	arm_vector(valid);
	invoke_vector(valid, &resource, &request,
		      (const struct sockaddr *)&peer);
	zassert_equal(response_code, COAP_RESPONSE_CODE_CONTENT);
	zassert_equal(lichen_rangetest_interval_ms(), 1000U,
		      "interval_ms body 0x1903e8 must set the interval");

	arm_vector(zero);
	invoke_vector(zero, &resource, &request,
		      (const struct sockaddr *)&peer);
	zassert_equal(response_code, COAP_RESPONSE_CODE_BAD_REQUEST);
	zassert_equal(lichen_rangetest_interval_ms(), 1000U,
		      "rejected body must not change the interval");
}

ZTEST(coap_rangetest, test_update_advances_seq_and_get_reflects_it) {
	struct coap_resource resource = {0};
	struct coap_packet request = {0};
	struct sockaddr_in6 peer = {.sin6_family = AF_INET6};
	const struct rangetest_vector *get_default = find_vector(
		"rangetest_get_default");

	init_provider();
	lichen_rangetest_update();
	lichen_rangetest_update();
	zassert_equal(lichen_rangetest_seq(), 2U);

	arm_vector(get_default);
	prov_hops = NULL;
	prov_hop_count = 0U;
	invoke_vector(get_default, &resource, &request,
		      (const struct sockaddr *)&peer);
	zassert_equal(response_code, COAP_RESPONSE_CODE_CONTENT);
	zassert_equal(response_cf, LICHEN_RANGETEST_CF_SENML_CBOR);
	zassert_equal(response_payload_len, get_default->payload_len);
	/* GET reports the internal seq (2), not the vector's echo of 0: the
	 * packs differ only in the seq v-field byte. */
	zassert_true(memcmp(response_payload, get_default->payload,
			    response_payload_len) != 0,
		     "GET must report the advanced seq");
	zassert_equal(response_payload[47], 0x02U, "seq v field encodes 2");
}

ZTEST(coap_rangetest, test_codec_contract_edges) {
	struct lichen_rangetest_metrics metrics = {
		.rssi = VEC_RSSI,
		.snr = VEC_SNR,
		.sf = (uint8_t)VEC_SF,
		.freq = VEC_FREQ,
	};
	struct lichen_rangetest_hop hop = {
		.addr = "fe80::1111",
		.rssi = -65.0,
		.rtt_ms = 120.0,
	};
	uint8_t small[8];
	uint8_t buf[TEST_SENML_BUF_MAX];
	int len;

	zassert_equal(lichen_rangetest_init(NULL), -EINVAL);

	len = lichen_rangetest_senml_encode(small, sizeof(small),
					    "urn:dev:mac:0102030405060708:",
					    VEC_BT, 0U, &metrics);
	zassert_equal(len, -ENOBUFS);

	len = lichen_rangetest_senml_encode(buf, sizeof(buf), NULL, VEC_BT, 0U,
					    &metrics);
	zassert_equal(len, -EINVAL);
	len = lichen_rangetest_senml_encode(buf, sizeof(buf), "", VEC_BT, 0U,
					    &metrics);
	zassert_equal(len, -EINVAL);

	metrics.rssi = NAN;
	len = lichen_rangetest_senml_encode(buf, sizeof(buf),
					    "urn:dev:mac:0102030405060708:",
					    VEC_BT, 0U, &metrics);
	zassert_equal(len, -EINVAL);

	zassert_equal(lichen_traceroute_encode(buf, sizeof(buf), NULL, 1U),
		      -EINVAL);
	zassert_equal(lichen_traceroute_encode(small, sizeof(small), &hop, 1U),
		      -ENOBUFS);
	hop.rtt_ms = NAN;
	zassert_equal(lichen_traceroute_encode(buf, sizeof(buf), &hop, 1U),
		      -EINVAL);
}

ZTEST(coap_rangetest, test_traceroute_max_hops_encode) {
	/* 720 mirrors RANGETEST_TRACE_CBOR_MAX in coap_rangetest.c. */
	uint8_t sized[720U];
	uint8_t tight[704U];
	struct lichen_rangetest_hop hops[LICHEN_RANGETEST_MAX_HOPS];
	int len;

	/* 45 chars is the longest IPv6 text form (INET6_ADDRSTRLEN - 1),
	 * which encodes with the 0x78 two-byte string header. */
	for (size_t i = 0U; i < LICHEN_RANGETEST_MAX_HOPS; i++) {
		memset(hops[i].addr, 'f', LICHEN_RANGETEST_ADDR_MAX - 1U);
		hops[i].addr[LICHEN_RANGETEST_ADDR_MAX - 1U] = '\0';
		hops[i].rssi = -65.0 - (double)i;
		hops[i].rtt_ms = 100.0 + (double)i;
		zassert_equal(strnlen(hops[i].addr, sizeof(hops[i].addr)),
			      LICHEN_RANGETEST_ADDR_MAX - 1U, "addr len");
	}

	len = lichen_traceroute_encode(sized, sizeof(sized), hops,
				       LICHEN_RANGETEST_MAX_HOPS);
	zassert_equal(len, 705, "canonical max-hop length");

	/* 704 cannot hold the 705-byte document (the old 640 buffer could
	 * not either); the encoder must report the overflow, not truncate. */
	len = lichen_traceroute_encode(tight, sizeof(tight), hops,
				       LICHEN_RANGETEST_MAX_HOPS);
	zassert_equal(len, -ENOBUFS, "bound must be exact");
}

static void *suite_setup(void)
{
	return NULL;
}

ZTEST_SUITE(coap_rangetest, NULL, suite_setup, NULL, NULL, NULL);
