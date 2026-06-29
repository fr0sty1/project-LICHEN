/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdint.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/socket.h>
#include <zephyr/ztest.h>

#include <lichen/coap_client.h>

#define COAP_MAX_VALID_TIMEOUT_MS (UINT32_MAX / 2U)

static const char * const valid_path[] = { "status", NULL };
static const uint8_t cbor_payload[] = { 0xa0 };

static struct sockaddr_in6 test_addr(void)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(5683),
	};

	addr.sin6_addr.s6_addr[0] = 0xfe;
	addr.sin6_addr.s6_addr[1] = 0x80;
	addr.sin6_addr.s6_addr[15] = 0x01;

	return addr;
}

static struct lichen_coap_request valid_request(void)
{
	struct lichen_coap_request req = {
		.addr = test_addr(),
		.path = valid_path,
		.method = COAP_METHOD_GET,
		.content_format = LICHEN_COAP_FMT_UNSET,
		.confirmable = true,
		.timeout_ms = LICHEN_COAP_TIMEOUT_MS,
	};

	return req;
}

ZTEST(coap_client_api, test_request_rejects_null_request)
{
	zassert_equal(lichen_coap_request(NULL), LICHEN_COAP_ERR_INVALID_PARAM);
}

ZTEST(coap_client_api, test_request_rejects_null_payload_with_nonzero_length)
{
	struct lichen_coap_request req = valid_request();

	req.method = COAP_METHOD_POST;
	req.payload = NULL;
	req.payload_len = 1;

	zassert_equal(lichen_coap_request(&req), LICHEN_COAP_ERR_INVALID_PARAM);
}

ZTEST(coap_client_api, test_request_rejects_invalid_path_arrays)
{
	const char * const unterminated_path[LICHEN_COAP_MAX_PATH_COMPONENTS] = {
		"a", "b", "c", "d", "e", "f", "g", "h",
	};
	struct lichen_coap_request req = valid_request();

	req.path = NULL;
	zassert_equal(lichen_coap_request(&req), LICHEN_COAP_ERR_INVALID_PARAM);

	req = valid_request();
	req.path = unterminated_path;
	zassert_equal(lichen_coap_request(&req), LICHEN_COAP_ERR_INVALID_PARAM);
}

ZTEST(coap_client_api, test_request_rejects_timeout_that_would_overflow_fallback)
{
	struct lichen_coap_request req = valid_request();

	req.timeout_ms = COAP_MAX_VALID_TIMEOUT_MS + 1U;

	zassert_equal(lichen_coap_request(&req), LICHEN_COAP_ERR_INVALID_PARAM);
}

ZTEST(coap_client_api, test_post_cbor_rejects_invalid_parameters)
{
	struct sockaddr_in6 addr = test_addr();

	zassert_equal(lichen_coap_post_cbor(NULL, valid_path, cbor_payload,
					    sizeof(cbor_payload), NULL, NULL),
		      LICHEN_COAP_ERR_INVALID_PARAM);
	zassert_equal(lichen_coap_post_cbor(&addr, NULL, cbor_payload,
					    sizeof(cbor_payload), NULL, NULL),
		      LICHEN_COAP_ERR_INVALID_PARAM);
	zassert_equal(lichen_coap_post_cbor(&addr, valid_path, NULL, 1, NULL, NULL),
		      LICHEN_COAP_ERR_INVALID_PARAM);
}

ZTEST_SUITE(coap_client_api, NULL, NULL, NULL, NULL, NULL);
