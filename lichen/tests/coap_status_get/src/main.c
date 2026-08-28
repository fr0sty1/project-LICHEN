/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/ztest.h>

#include <lichen/coap_server.h>
#include <lichen/coap_status.h>

#define TEST_CBOR_MAX_SIZE LICHEN_COAP_STATUS_CBOR_MAX_SIZE

extern struct coap_resource lichen_coap_status_resource;

static struct lichen_coap_node_status test_status;
static int status_get_result;
static unsigned int status_get_calls;
static bool mutate_after_get;

static struct {
  int result;
  unsigned int calls;
  uint32_t sequence;
  uint8_t token[COAP_TOKEN_MAX_LEN];
  uint8_t token_len;
  uint8_t payload[TEST_CBOR_MAX_SIZE];
  size_t payload_len;
  bool initial;
  uint8_t request_type;
  uint16_t request_id;
} observe_send;

static struct {
  uint8_t code;
  uint16_t content_format;
  uint8_t payload[TEST_CBOR_MAX_SIZE];
  size_t payload_len;
} response;

static int test_status_get(struct lichen_coap_node_status *status) {
  status_get_calls++;
  if (status_get_result < 0) {
    return status_get_result;
  }
  *status = test_status;
  if (mutate_after_get) {
    memset(&test_status, 0xa5, sizeof(test_status));
  }
  return 0;
}

static const struct lichen_coap_status_config config = {
    .status_get = test_status_get,
};

int lichen_coap_respond(struct coap_resource *resource,
                        struct coap_packet *request, struct sockaddr *addr,
                        socklen_t addr_len, uint8_t resp_code,
                        uint16_t content_format, const uint8_t *payload,
                        size_t payload_len) {
  ARG_UNUSED(resource);
  ARG_UNUSED(request);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);

  response.code = resp_code;
  response.content_format = content_format;
  response.payload_len = payload_len;
  if (payload_len > sizeof(response.payload)) {
    return -EMSGSIZE;
  }
  if (payload_len > 0U) {
    memcpy(response.payload, payload, payload_len);
  }
  return 0;
}

int lichen_coap_status_observe_send(
    const struct sockaddr *addr, socklen_t addr_len, const uint8_t *token,
    uint8_t token_len, uint32_t sequence, const uint8_t *payload,
    size_t payload_len, bool initial, uint8_t request_type,
    uint16_t request_id) {
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);

  observe_send.calls++;
  observe_send.sequence = sequence;
  observe_send.token_len = token_len;
  memcpy(observe_send.token, token, token_len);
  observe_send.payload_len = payload_len;
  memcpy(observe_send.payload, payload, payload_len);
  observe_send.initial = initial;
  observe_send.request_type = request_type;
  observe_send.request_id = request_id;
  return observe_send.result;
}

static void init_request(struct coap_packet *request, uint8_t *buf,
                         size_t buf_size, const uint8_t *token,
                         uint8_t token_len, int observe) {
  zassert_ok(coap_packet_init(request, buf, (uint16_t)buf_size, COAP_VERSION_1,
                              COAP_TYPE_CON, token_len, token,
                              COAP_METHOD_GET, 0x1234U));
  if (observe >= 0) {
    zassert_ok(coap_append_option_int(request, COAP_OPTION_OBSERVE,
                                      (unsigned int)observe));
  }

  /* Handlers receive parsed datagrams, whose max_len is the received length.
   * coap_packet_init instead keeps the output buffer capacity. */
  request->max_len = request->offset;
}

static void init_addr(struct sockaddr_in6 *addr, uint16_t port,
                      uint8_t suffix) {
  memset(addr, 0, sizeof(*addr));
  addr->sin6_family = AF_INET6;
  addr->sin6_port = htons(port);
  addr->sin6_addr.s6_addr[0] = 0xfeU;
  addr->sin6_addr.s6_addr[1] = 0x80U;
  addr->sin6_addr.s6_addr[15] = suffix;
}

static int call_status_get(struct coap_packet *request,
                           struct sockaddr_in6 *addr) {
  return lichen_coap_status_resource.get(
      &lichen_coap_status_resource, request, (struct sockaddr *)addr,
      sizeof(*addr));
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -EINVAL;
}

static size_t decode_hex(const char *hex, uint8_t *out, size_t out_size) {
  size_t hex_len = strlen(hex);

  if ((hex_len % 2U) != 0U || out_size < hex_len / 2U) {
    return 0U;
  }
  for (size_t i = 0U; i < hex_len / 2U; i++) {
    int high = hex_nibble(hex[i * 2U]);
    int low = hex_nibble(hex[i * 2U + 1U]);

    if (high < 0 || low < 0) {
      return 0U;
    }
    out[i] = (uint8_t)((high << 4) | low);
  }
  return hex_len / 2U;
}

static bool contains_bytes(const uint8_t *haystack, size_t haystack_len,
                           const uint8_t *needle, size_t needle_len) {
  if (needle_len == 0U || haystack_len < needle_len) {
    return false;
  }
  for (size_t i = 0U; i <= haystack_len - needle_len; i++) {
    if (memcmp(haystack + i, needle, needle_len) == 0) {
      return true;
    }
  }
  return false;
}

static void assert_encoding(const struct lichen_coap_node_status *status,
                            const char *expected_hex) {
  uint8_t expected[TEST_CBOR_MAX_SIZE];
  uint8_t encoded[TEST_CBOR_MAX_SIZE];
  size_t expected_len = decode_hex(expected_hex, expected, sizeof(expected));
  ssize_t encoded_len =
      lichen_coap_encode_status_cbor(encoded, sizeof(encoded), status);

  zassert_true(expected_len > 0U, "invalid test vector");
  zassert_equal(encoded_len, (ssize_t)expected_len, "actual %zd expected %zu",
                encoded_len, expected_len);
  zassert_mem_equal(encoded, expected, expected_len,
                    "status output differs from shared vector");
}

static void set_full_status(void) {
  memset(&test_status, 0, sizeof(test_status));
  test_status.uptime_s = 3600U;
  test_status.uptime_valid = true;
  test_status.battery_pct = 87U;
  test_status.battery_pct_valid = true;
  test_status.battery_mv = 3950U;
  test_status.battery_mv_valid = true;
  test_status.mem_free_kb = 42U;
  test_status.mem_free_kb_valid = true;
  test_status.time.valid = true;
  test_status.time.wall_clock_valid = true;
  test_status.time.unix_time = 1716742800U;
  (void)strcpy(test_status.time.source_class, "gnss");
  (void)strcpy(test_status.time.source_name, "onboard-gnss");
  test_status.time.age_s = 120U;
  test_status.time.age_valid = true;
  test_status.dodag.valid = true;
  test_status.dodag.joined = true;
  test_status.dodag.rank = 512U;
  test_status.dodag.has_parent = true;
  test_status.dodag.has_root = true;
  zassert_ok(net_addr_pton(AF_INET6, "fe80::1234:5678:9abc:def0",
                           test_status.dodag.parent));
  zassert_ok(net_addr_pton(AF_INET6, "0200:1234:5678:9abc::1",
                           test_status.dodag.root));
  test_status.radio.valid = true;
  test_status.radio.rx_packets = 1234U;
  test_status.radio.tx_packets = 567U;
  test_status.radio.rx_errors = 12U;
  test_status.radio.duty_cycle_pct_x10 = 23U;
  test_status.ccp.valid = true;
  test_status.ccp.rx_channel = 5U;
  test_status.ccp.scheduler_active = true;
  test_status.ccp.preferred_rx_valid_until_sfn = 12350U;
}

static void before(void *fixture) {
  ARG_UNUSED(fixture);
  memset(&response, 0, sizeof(response));
  set_full_status();
  status_get_result = 0;
  status_get_calls = 0U;
  mutate_after_get = false;
  memset(&observe_send, 0, sizeof(observe_send));
  lichen_coap_status_observe_reset();
}

ZTEST_SUITE(coap_status_get, NULL, NULL, before, NULL, NULL);

ZTEST(coap_status_get, test_00_handler_policy_snapshot_and_errors) {
  static const char full_hex[] =
      "a868757074696d655f73190e106b626174746572795f70637418576a6261747465"
      "72795f6d76190f6e6b6d656d5f667265655f6b62182a6474696d65a57077616c"
      "6c5f636c6f636b5f76616c6964f569756e69785f74696d651a66536a906c736f"
      "757263655f636c61737364676e73736b736f757263655f6e616d656c6f6e626f"
      "6172642d676e7373656167655f73187865646f646167a4666a6f696e6564f564"
      "72616e6b19020066706172656e747819666538303a3a313233343a353637383a39"
      "6162633a6465663064726f6f7476303230303a313233343a353637383a39616263"
      "3a3a3165726164696fa46a72785f7061636b6574731904d26a74785f7061636b"
      "6574731902376972785f6572726f72730c6e647574795f6379636c655f706374"
      "fb400266666666666663636370a36a72785f6368616e6e656c05707363686564"
      "756c65725f616374697665f5781c7072656665727265645f72785f76616c6964"
      "5f756e74696c5f73666e19303e";
  static const char *const sensitive[] = {"seed", "private", "privkey",
                                          "secret"};
  struct coap_packet request;
  struct sockaddr_in6 addr;
  uint8_t request_buf[32];
  uint8_t expected[TEST_CBOR_MAX_SIZE];
  size_t expected_len = decode_hex(full_hex, expected, sizeof(expected));

  init_request(&request, request_buf, sizeof(request_buf), NULL, 0U, -1);
  init_addr(&addr, 5683U, 1U);

  zassert_equal(strcmp(lichen_coap_status_resource.path[0], "status"), 0);
  zassert_is_null(lichen_coap_status_resource.path[1]);
  zassert_not_null(lichen_coap_status_resource.get);
  zassert_is_null(lichen_coap_status_resource.post, "status must be read-only");
  zassert_is_null(lichen_coap_status_resource.put, "status must be read-only");
  zassert_is_null(lichen_coap_status_resource.del, "status must be read-only");

  zassert_ok(call_status_get(&request, &addr));
  zassert_equal(response.code, COAP_RESPONSE_CODE_NOT_FOUND);
  zassert_equal(response.payload_len, 0U);

  zassert_ok(lichen_coap_status_init(&config));
  mutate_after_get = true;
  memset(&response, 0, sizeof(response));
  zassert_ok(call_status_get(&request, &addr));
  zassert_equal(status_get_calls, 1U, "provider must be read exactly once");
  zassert_equal(response.code, COAP_RESPONSE_CODE_CONTENT);
  zassert_equal(response.content_format, 60U);
  zassert_equal(response.payload_len, expected_len, "actual %zu expected %zu",
                response.payload_len, expected_len);
  zassert_mem_equal(response.payload, expected, expected_len,
                    "GET response differs from shared status vector");
  for (size_t i = 0U; i < ARRAY_SIZE(sensitive); i++) {
    zassert_false(contains_bytes(response.payload, response.payload_len,
                                 (const uint8_t *)sensitive[i],
                                 strlen(sensitive[i])),
                  "sensitive field leaked: %s", sensitive[i]);
  }

  mutate_after_get = false;
  status_get_result = -EIO;
  memset(&response, 0, sizeof(response));
  zassert_ok(call_status_get(&request, &addr));
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR);

  status_get_result = 0;
  set_full_status();
  test_status.battery_pct = 101U;
  memset(&response, 0, sizeof(response));
  zassert_ok(call_status_get(&request, &addr));
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR,
                "invalid provider snapshot must fail closed");
}

ZTEST(coap_status_get, test_all_shared_status_vector_shapes) {
  static const char minimal_hex[] =
      "a368757074696d655f7318786b626174746572795f70637418406a626174746572"
      "795f6d76190e74";
  static const char invalid_clock_hex[] =
      "a468757074696d655f73185a6b626174746572795f7063740c6474696d65a170"
      "77616c6c5f636c6f636b5f76616c6964f465646f646167a4666a6f696e6564f4"
      "6472616e6b19ffff66706172656e74f664726f6f74f6";
  struct lichen_coap_node_status status = {0};

  assert_encoding(&status, "a0");

  status.uptime_valid = true;
  status.uptime_s = 120U;
  status.battery_pct_valid = true;
  status.battery_pct = 64U;
  status.battery_mv_valid = true;
  status.battery_mv = 3700U;
  assert_encoding(&status, minimal_hex);

  memset(&status, 0, sizeof(status));
  status.uptime_valid = true;
  status.uptime_s = 90U;
  status.battery_pct_valid = true;
  status.battery_pct = 12U;
  status.time.valid = true;
  status.time.wall_clock_valid = false;
  status.dodag.valid = true;
  status.dodag.joined = false;
  status.dodag.rank = UINT16_MAX;
  assert_encoding(&status, invalid_clock_hex);
}

ZTEST(coap_status_get, test_encoder_boundaries_and_invalid_unknowns) {
  uint8_t encoded[TEST_CBOR_MAX_SIZE];
  struct lichen_coap_node_status status = {0};

  zassert_equal(lichen_coap_encode_status_cbor(encoded, 1U, &status), 1,
                "empty unknown snapshot must fit in one byte");
  zassert_equal(encoded[0], 0xa0U);
  zassert_equal(lichen_coap_encode_status_cbor(encoded, 0U, &status), -ENOBUFS);

  status.battery_pct_valid = true;
  status.battery_pct = 0U;
  zassert_true(
      lichen_coap_encode_status_cbor(encoded, sizeof(encoded), &status) > 0);
  status.battery_pct = 100U;
  zassert_true(
      lichen_coap_encode_status_cbor(encoded, sizeof(encoded), &status) > 0);
  status.battery_pct = 101U;
  zassert_equal(
      lichen_coap_encode_status_cbor(encoded, sizeof(encoded), &status),
      -EINVAL);

  set_full_status();
  test_status.radio.duty_cycle_pct_x10 = 1001U;
  zassert_equal(
      lichen_coap_encode_status_cbor(encoded, sizeof(encoded), &test_status),
      -EINVAL);
  set_full_status();
  test_status.capacity_valid = true;
  test_status.txq_cap = 2U;
  test_status.txq_used = 3U;
  zassert_equal(
      lichen_coap_encode_status_cbor(encoded, sizeof(encoded), &test_status),
      -EINVAL);
  set_full_status();
  memset(test_status.time.source_name, 'x',
         sizeof(test_status.time.source_name));
  zassert_equal(
      lichen_coap_encode_status_cbor(encoded, sizeof(encoded), &test_status),
      -EINVAL, "unterminated provider string must fail closed");
}

ZTEST(coap_status_get, test_observe_register_refresh_cancel_and_validation) {
  struct lichen_coap_status_observe_stats stats;
  struct sockaddr_in6 addr;
  struct sockaddr_in6 second_addr;
  struct coap_packet request;
  const uint8_t token[] = {0x10U, 0x20U, 0x30U};
  const uint8_t second_token = 0x31U;
  uint8_t request_buf[48];
  uint8_t cached[TEST_CBOR_MAX_SIZE];
  size_t cached_len;

  zassert_ok(lichen_coap_status_init(&config));
  init_addr(&addr, 5683U, 7U);
  init_request(&request, request_buf, sizeof(request_buf), token,
               sizeof(token), 0);
  zassert_ok(call_status_get(&request, &addr));
  zassert_equal(observe_send.calls, 1U, "initial send calls %u",
                observe_send.calls);
  zassert_true(observe_send.initial);
  zassert_equal(observe_send.request_type, COAP_TYPE_CON);
  zassert_equal(observe_send.request_id, 0x1234U);
  zassert_equal(observe_send.sequence, 2U);
  zassert_mem_equal(observe_send.token, token, sizeof(token));
  cached_len = observe_send.payload_len;
  memcpy(cached, observe_send.payload, cached_len);
  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_equal(stats.observers, 1U);

  /* A subscriber arriving between samples receives the same immutable
   * representation and Observe value as existing observers. */
  test_status.uptime_s++;
  init_addr(&second_addr, 5684U, 8U);
  init_request(&request, request_buf, sizeof(request_buf), &second_token, 1U,
               0);
  zassert_ok(call_status_get(&request, &second_addr));
  zassert_equal(observe_send.sequence, 2U);
  zassert_equal(observe_send.payload_len, cached_len);
  zassert_mem_equal(observe_send.payload, cached, cached_len);
  init_request(&request, request_buf, sizeof(request_buf), &second_token, 1U,
               1);
  zassert_ok(call_status_get(&request, &second_addr));
  test_status.uptime_s--;

  init_request(&request, request_buf, sizeof(request_buf), token,
               sizeof(token), 0);
  zassert_ok(call_status_get(&request, &addr));
  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_equal(stats.observers, 1U, "refresh must not duplicate observer");

  init_request(&request, request_buf, sizeof(request_buf), token,
               sizeof(token), 1);
  zassert_ok(call_status_get(&request, &addr));
  zassert_equal(response.code, COAP_RESPONSE_CODE_CONTENT);
  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_equal(stats.observers, 0U);

  init_request(&request, request_buf, sizeof(request_buf), token,
               sizeof(token), 2);
  zassert_ok(call_status_get(&request, &addr));
  zassert_equal(response.code, COAP_RESPONSE_CODE_BAD_REQUEST);

  init_request(&request, request_buf, sizeof(request_buf), NULL, 0U, 0);
  zassert_ok(call_status_get(&request, &addr));
  zassert_equal(response.code, COAP_RESPONSE_CODE_BAD_REQUEST);

  init_request(&request, request_buf, sizeof(request_buf), token,
               sizeof(token), 0);
  request.max_len = sizeof(request_buf);
  zassert_ok(coap_append_option_int(&request, COAP_OPTION_OBSERVE, 0U));
  request.max_len = request.offset;
  zassert_ok(call_status_get(&request, &addr));
  zassert_equal(response.code, COAP_RESPONSE_CODE_BAD_REQUEST,
                "duplicate Observe must be rejected");
}

ZTEST(coap_status_get, test_observe_capacity_and_expiry) {
  struct lichen_coap_status_observe_stats stats;
  struct sockaddr_in6 addr;
  struct coap_packet request;
  uint8_t request_buf[48];
  uint8_t token;
  int64_t base;

  zassert_ok(lichen_coap_status_init(&config));
  for (uint8_t i = 0U; i < CONFIG_LICHEN_COAP_STATUS_MAX_OBSERVERS; i++) {
    token = (uint8_t)(0x40U + i);
    init_addr(&addr, (uint16_t)(5683U + i), (uint8_t)(10U + i));
    init_request(&request, request_buf, sizeof(request_buf), &token, 1U, 0);
    zassert_ok(call_status_get(&request, &addr));
  }
  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_equal(stats.observers, CONFIG_LICHEN_COAP_STATUS_MAX_OBSERVERS);

  token = 0x7fU;
  init_addr(&addr, 5700U, 31U);
  init_request(&request, request_buf, sizeof(request_buf), &token, 1U, 0);
  zassert_ok(call_status_get(&request, &addr));
  zassert_equal(response.code, COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE);
  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_equal(stats.observers, CONFIG_LICHEN_COAP_STATUS_MAX_OBSERVERS);

  base = k_uptime_get();
  zassert_equal(lichen_coap_status_observe_poll(
                    base + LICHEN_COAP_STATUS_OBSERVER_TTL_MS + 1),
                LICHEN_COAP_STATUS_OBSERVE_IDLE);
  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_equal(stats.observers, 0U);
  zassert_equal(stats.expired, CONFIG_LICHEN_COAP_STATUS_MAX_OBSERVERS);
}

ZTEST(coap_status_get, test_observe_change_sampling_refresh_and_wrap) {
  struct lichen_coap_status_observe_stats stats;
  struct sockaddr_in6 addr;
  struct coap_packet request;
  const uint8_t token = 0x55U;
  uint8_t request_buf[48];
  int64_t base;

  zassert_ok(lichen_coap_status_init(&config));
  init_addr(&addr, 5683U, 20U);
  init_request(&request, request_buf, sizeof(request_buf), &token, 1U, 0);
  zassert_ok(call_status_get(&request, &addr));
  base = k_uptime_get();

  zassert_equal(lichen_coap_status_observe_poll(base + 100),
                LICHEN_COAP_STATUS_OBSERVE_IDLE,
                "unchanged snapshot must not notify");
  test_status.uptime_s++;
  zassert_equal(lichen_coap_status_observe_poll(base + 200),
                LICHEN_COAP_STATUS_OBSERVE_DEFERRED,
                "change must be rate-limited");
  zassert_equal(lichen_coap_status_observe_poll(
                    base + LICHEN_COAP_STATUS_OBSERVE_MIN_INTERVAL_MS),
                LICHEN_COAP_STATUS_OBSERVE_NOTIFIED);
  zassert_equal(observe_send.sequence, 3U);
  zassert_false(observe_send.initial);

  zassert_ok(lichen_coap_status_observe_set_sequence_for_test(
      COAP_OBSERVE_MAX_AGE));
  test_status.uptime_s++;
  zassert_equal(lichen_coap_status_observe_poll(
                    base + 2 * LICHEN_COAP_STATUS_OBSERVE_MIN_INTERVAL_MS),
                LICHEN_COAP_STATUS_OBSERVE_NOTIFIED);
  zassert_equal(observe_send.sequence, 2U, "24-bit sequence must wrap to 2");

  zassert_equal(lichen_coap_status_observe_poll(
                    base + 2 * LICHEN_COAP_STATUS_OBSERVE_MIN_INTERVAL_MS +
                    LICHEN_COAP_STATUS_OBSERVE_MAX_INTERVAL_MS),
                LICHEN_COAP_STATUS_OBSERVE_NOTIFIED,
                "unchanged snapshot needs maximum-age refresh");
  zassert_equal(observe_send.sequence, 3U);
  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_equal(stats.notifications, 4U,
                "initial plus three notifications expected");
  zassert_equal(lichen_coap_status_observe_poll(-1), -EINVAL);
}

ZTEST(coap_status_get, test_observe_backpressure_cached_retry_and_errors) {
  struct lichen_coap_status_observe_stats stats;
  struct sockaddr_in6 addr;
  struct coap_packet request;
  const uint8_t token = 0x66U;
  uint8_t request_buf[48];
  uint8_t cached[TEST_CBOR_MAX_SIZE];
  size_t cached_len;
  int64_t base;
  int poll_result;
  uint8_t changed_payload[TEST_CBOR_MAX_SIZE];
  ssize_t changed_len;

  zassert_ok(lichen_coap_status_init(&config));
  init_addr(&addr, 5683U, 21U);
  init_request(&request, request_buf, sizeof(request_buf), &token, 1U, 0);
  zassert_ok(call_status_get(&request, &addr));
  base = k_uptime_get();

  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_equal(stats.observers, 1U);

  test_status.uptime_s++;
  changed_len = lichen_coap_encode_status_cbor(
      changed_payload, sizeof(changed_payload), &test_status);
  zassert_true(changed_len > 0);
  zassert_false(changed_len == (ssize_t)observe_send.payload_len &&
                    memcmp(changed_payload, observe_send.payload,
                           observe_send.payload_len) == 0,
                "test mutation must alter canonical snapshot");
  observe_send.result = -EAGAIN;
  poll_result = lichen_coap_status_observe_poll(
      base + LICHEN_COAP_STATUS_OBSERVE_MIN_INTERVAL_MS);
  zassert_equal(poll_result, LICHEN_COAP_STATUS_OBSERVE_NOTIFIED,
                "unexpected poll result %d", poll_result);
  cached_len = observe_send.payload_len;
  memcpy(cached, observe_send.payload, cached_len);
  test_status.uptime_s++;
  observe_send.result = 0;
  zassert_equal(lichen_coap_status_observe_poll(
                    base + LICHEN_COAP_STATUS_OBSERVE_MIN_INTERVAL_MS +
                    LICHEN_COAP_STATUS_OBSERVE_RETRY_MS),
                LICHEN_COAP_STATUS_OBSERVE_DEFERRED);
  zassert_mem_equal(observe_send.payload, cached, cached_len,
                    "retry must reuse immutable cached representation");
  zassert_equal(lichen_coap_status_observe_poll(
                    base + 2 * LICHEN_COAP_STATUS_OBSERVE_MIN_INTERVAL_MS),
                LICHEN_COAP_STATUS_OBSERVE_NOTIFIED,
                "latest provider state must follow cached retry");
  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_true(stats.backpressure > 0U);
  zassert_equal(stats.observers, 1U);

  status_get_result = -EIO;
  zassert_equal(lichen_coap_status_observe_poll(
                    base + 3 * LICHEN_COAP_STATUS_OBSERVE_MIN_INTERVAL_MS),
                -EIO);
  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_equal(stats.last_error, -EIO);
}

ZTEST(coap_status_get, test_observe_repeated_backpressure_evicts_observer) {
  struct lichen_coap_status_observe_stats stats;
  struct sockaddr_in6 addr;
  struct coap_packet request;
  const uint8_t token = 0x77U;
  uint8_t request_buf[48];
  int64_t base;

  zassert_ok(lichen_coap_status_init(&config));
  init_addr(&addr, 5683U, 22U);
  init_request(&request, request_buf, sizeof(request_buf), &token, 1U, 0);
  zassert_ok(call_status_get(&request, &addr));
  base = k_uptime_get();
  test_status.uptime_s++;
  observe_send.result = -ENOBUFS;
  zassert_equal(lichen_coap_status_observe_poll(
                    base + LICHEN_COAP_STATUS_OBSERVE_MIN_INTERVAL_MS),
                LICHEN_COAP_STATUS_OBSERVE_NOTIFIED);
  for (uint8_t retry = 1U;
       retry <= LICHEN_COAP_STATUS_OBSERVE_MAX_RETRIES; retry++) {
    (void)lichen_coap_status_observe_poll(
        base + LICHEN_COAP_STATUS_OBSERVE_MIN_INTERVAL_MS +
        retry * LICHEN_COAP_STATUS_OBSERVE_RETRY_MS);
  }
  zassert_ok(lichen_coap_status_observe_get_stats(&stats));
  zassert_equal(stats.observers, 0U);
  zassert_equal(stats.failures, 1U);
}
