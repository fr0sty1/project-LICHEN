/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/ztest.h>

#include <lichen/coap_msg.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>

#define TEST_PACKET_SIZE 512U
#define TEST_SENT_POST_MAX 288U

static bool request_is_protected;
static bool local_admin;
static int unprotect_result;
static int request_content_format;
static const uint8_t *request_payload;
static size_t request_payload_len;
static uint8_t response_code;
static uint16_t response_format;
static uint8_t response_payload[TEST_PACKET_SIZE];
static size_t response_payload_len;
static char response_location[64];

static const uint8_t peer_a[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

int lichen_coap_respond(struct coap_resource *resource,
                        struct coap_packet *request, struct sockaddr *addr,
                        socklen_t addr_len, uint8_t code,
                        uint16_t content_format, const uint8_t *payload,
                        size_t payload_len) {
  ARG_UNUSED(resource);
  ARG_UNUSED(request);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  response_code = code;
  response_format = content_format;
  response_payload_len = MIN(payload_len, sizeof(response_payload));
  if (response_payload_len > 0U) {
    memcpy(response_payload, payload, response_payload_len);
  }
  return 0;
}

bool lichen_coap_is_local_admin(const struct sockaddr *addr,
                                socklen_t addr_len) {
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  return local_admin;
}

int coap_oscore_unprotect_resource_request(
    struct coap_resource *resource, struct coap_packet *request,
    struct sockaddr *addr, socklen_t addr_len, uint8_t expected_method,
    struct coap_oscore_unprotect_result *result) {
  ARG_UNUSED(resource);
  ARG_UNUSED(request);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  zassert_true(expected_method == COAP_METHOD_POST ||
               expected_method == COAP_METHOD_GET);
  if (unprotect_result != 0) {
    return unprotect_result;
  }
  memset(result, 0, sizeof(*result));
  result->is_protected = request_is_protected;
  result->payload = (uint8_t *)request_payload;
  result->payload_len = request_payload_len;
  return 0;
}

int coap_oscore_respond_resource(
    struct coap_resource *resource, struct coap_packet *request,
    struct sockaddr *addr, socklen_t addr_len,
    const struct coap_oscore_unprotect_result *result, uint8_t code,
    uint16_t content_format, const uint8_t *payload, size_t payload_len) {
  ARG_UNUSED(result);
  return lichen_coap_respond(resource, request, addr, addr_len, code,
                             content_format, payload, payload_len);
}

int lichen_coap_format_ipv6(const uint8_t addr[16], char *buf, size_t buf_len) {
  if (net_addr_ntop(AF_INET6, addr, buf, buf_len) == NULL) {
    return -EINVAL;
  }
  return (int)strlen(buf);
}

int __wrap_coap_resource_send(
    const struct coap_resource *resource, const struct coap_packet *packet,
    const struct sockaddr *addr, socklen_t addr_len,
    const struct coap_transmission_parameters *params) {
  struct coap_option options[3];
  struct coap_packet parsed = *packet;
  int count;
  size_t off = 0U;

  ARG_UNUSED(resource);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  ARG_UNUSED(params);
  response_code = coap_header_get_code(packet);
  parsed.max_len = parsed.offset;
  count = coap_find_options(&parsed, COAP_OPTION_LOCATION_PATH, options,
                            ARRAY_SIZE(options));
  for (int i = 0; i < count && i < (int)ARRAY_SIZE(options); i++) {
    if (i > 0 && off + 1U < sizeof(response_location)) {
      response_location[off++] = '/';
    }
    size_t copy_len = MIN(options[i].len, sizeof(response_location) - off - 1U);
    memcpy(&response_location[off], options[i].value, copy_len);
    off += copy_len;
  }
  response_location[off] = '\0';
  return 0;
}

static size_t put_uint(uint8_t *buf, size_t off, uint64_t value) {
  if (value < 24U) {
    buf[off++] = (uint8_t)value;
  } else if (value <= UINT8_MAX) {
    buf[off++] = 0x18U;
    buf[off++] = (uint8_t)value;
  } else if (value <= UINT16_MAX) {
    buf[off++] = 0x19U;
    buf[off++] = (uint8_t)(value >> 8);
    buf[off++] = (uint8_t)value;
  } else if (value <= UINT32_MAX) {
    buf[off++] = 0x1aU;
    for (int shift = 24; shift >= 0; shift -= 8) {
      buf[off++] = (uint8_t)(value >> shift);
    }
  } else {
    buf[off++] = 0x1bU;
    for (int shift = 56; shift >= 0; shift -= 8) {
      buf[off++] = (uint8_t)(value >> shift);
    }
  }
  return off;
}

static size_t put_tstr(uint8_t *buf, size_t off, const uint8_t *value,
                       size_t len) {
  if (len < 24U) {
    buf[off++] = 0x60U | (uint8_t)len;
  } else {
    zassert_true(len <= UINT8_MAX);
    buf[off++] = 0x78U;
    buf[off++] = (uint8_t)len;
  }
  memcpy(&buf[off], value, len);
  return off + len;
}

static size_t make_sent(uint8_t *buf, const char *to, const uint8_t *body,
                        size_t body_len, bool ack, bool explicit_id,
                        uint64_t id) {
  size_t off = 0U;
  size_t count = explicit_id ? 4U : 3U;

  buf[off++] = 0xa0U | (uint8_t)count;
  if (explicit_id) {
    off = put_tstr(buf, off, (const uint8_t *)"id", 2U);
    off = put_uint(buf, off, id);
  }
  off = put_tstr(buf, off, (const uint8_t *)"to", 2U);
  off = put_tstr(buf, off, (const uint8_t *)to, strlen(to));
  off = put_tstr(buf, off, (const uint8_t *)"ack", 3U);
  buf[off++] = ack ? 0xf5U : 0xf4U;
  off = put_tstr(buf, off, (const uint8_t *)"body", 4U);
  return put_tstr(buf, off, body, body_len);
}

static void init_packet(struct coap_packet *packet, uint8_t *buf,
                        uint8_t method) {
  zassert_ok(coap_packet_init(packet, buf, TEST_PACKET_SIZE, COAP_VERSION_1,
                              COAP_TYPE_CON, 0U, NULL, method, 7U));
}

static int post_sent(const uint8_t *payload, size_t payload_len) {
  uint8_t packet_buf[TEST_PACKET_SIZE];
  struct coap_packet packet;
  struct coap_resource resource = {0};
  struct sockaddr_in6 addr = {0};

  init_packet(&packet, packet_buf, COAP_METHOD_POST);
  if (request_content_format >= 0) {
    zassert_ok(coap_append_option_int(&packet, COAP_OPTION_CONTENT_FORMAT,
                                      (unsigned int)request_content_format));
  }
  packet.max_len = packet.offset;
  addr.sin6_family = AF_INET6;
  memcpy(addr.sin6_addr.s6_addr, peer_a, sizeof(peer_a));
  request_payload = payload;
  request_payload_len = payload_len;
  response_code = 0U;
  response_location[0] = '\0';
  int ret = lichen_msg_sent_post(&resource, &packet,
                                 (struct sockaddr *)&addr, sizeof(addr));
  return ret == 0 ? response_code : ret;
}

static int get_sent(const char *id, bool extra_path) {
  uint8_t packet_buf[TEST_PACKET_SIZE];
  struct coap_packet packet;
  struct coap_resource resource = {0};
  struct sockaddr_in6 addr = {0};

  init_packet(&packet, packet_buf, COAP_METHOD_GET);
  zassert_ok(coap_packet_append_option(&packet, COAP_OPTION_URI_PATH, "msg", 3U));
  zassert_ok(coap_packet_append_option(&packet, COAP_OPTION_URI_PATH, "sent", 4U));
  zassert_ok(coap_packet_append_option(&packet, COAP_OPTION_URI_PATH, id,
                                       strlen(id)));
  if (extra_path) {
    zassert_ok(coap_packet_append_option(&packet, COAP_OPTION_URI_PATH,
                                         "extra", 5U));
  }
  packet.max_len = packet.offset;
  addr.sin6_family = AF_INET6;
  memcpy(addr.sin6_addr.s6_addr, peer_a, sizeof(peer_a));
  request_payload = NULL;
  request_payload_len = 0U;
  response_code = 0U;
  response_payload_len = 0U;
  int ret = lichen_msg_sent_id_get(&resource, &packet,
                                   (struct sockaddr *)&addr, sizeof(addr));
  return ret == 0 ? response_code : ret;
}

static uint64_t location_id(void) {
  static const char prefix[] = "msg/sent/";
  char *end;

  zassert_true(strncmp(response_location, prefix, sizeof(prefix) - 1U) == 0);
  errno = 0;
  unsigned long long id = strtoull(response_location + sizeof(prefix) - 1U,
                                   &end, 10);
  zassert_equal(errno, 0);
  zassert_equal(*end, '\0');
  return (uint64_t)id;
}

static void reset_request(void) {
  request_is_protected = false;
  local_admin = true;
  unprotect_result = 0;
  request_content_format = -1;
  request_payload = NULL;
  request_payload_len = 0U;
  response_code = 0U;
  response_format = 0U;
  response_payload_len = 0U;
  response_location[0] = '\0';
}

ZTEST(coap_msg_sent, test_auto_id_location_and_record) {
  uint8_t payload[TEST_PACKET_SIZE];
  struct lichen_msg msg;
  size_t len = make_sent(payload, "2001:db8::1", (const uint8_t *)"hello",
                         5U, true, false, 0U);

  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_CREATED);
  uint64_t id = location_id();
  zassert_ok(lichen_msg_sent_get(id, &msg));
  zassert_equal(msg.id, id);
  zassert_equal(msg.body_len, 5U);
  zassert_mem_equal(msg.body, "hello", 5U);
  zassert_true(msg.ack_requested);
}

ZTEST(coap_msg_sent, test_explicit_id_is_idempotent_and_conflicts_atomically) {
  uint8_t payload[TEST_PACKET_SIZE];
  struct lichen_msg before;
  struct lichen_msg after;
  size_t len = make_sent(payload, "2001:db8::1", (const uint8_t *)"same",
                         4U, false, true, 4242U);

  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_CREATED);
  zassert_equal(location_id(), 4242U);
  zassert_ok(lichen_msg_sent_get(4242U, &before));
  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_CREATED);
  zassert_equal(location_id(), 4242U);

  len = make_sent(payload, "2001:db8::1", (const uint8_t *)"changed",
                  7U, false, true, 4242U);
  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_CONFLICT);
  zassert_ok(lichen_msg_sent_get(4242U, &after));
  zassert_mem_equal(&after, &before, sizeof(after));
}

ZTEST(coap_msg_sent, test_full_store_evicts_oldest_atomically) {
  uint8_t payload[TEST_PACKET_SIZE];

  for (uint64_t id = 5000U; id <= 5008U; id++) {
    size_t len = make_sent(payload, "ff02::1", (const uint8_t *)"broadcast",
                           9U, false, true, id);
    zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_CREATED);
  }
  struct lichen_msg msg;
  zassert_equal(lichen_msg_sent_get(5000U, &msg), -ENOENT);
  zassert_ok(lichen_msg_sent_get(5008U, &msg));
  zassert_mem_equal(msg.body, "broadcast", 9U);
}

ZTEST(coap_msg_sent, test_get_is_private_and_paths_are_canonical) {
  uint8_t payload[TEST_PACKET_SIZE];
  size_t len = make_sent(payload, "2001:db8::1", (const uint8_t *)"private",
                         7U, true, true, 7000U);

  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_CREATED);
  struct lichen_msg stored;
  zassert_ok(lichen_msg_sent_get(7000U, &stored));
  local_admin = false;
  request_is_protected = true;
  zassert_equal(get_sent("7000", false), COAP_RESPONSE_CODE_UNAUTHORIZED);
  local_admin = true;
  int code = get_sent("7000", false);
  zassert_equal(code, COAP_RESPONSE_CODE_CONTENT, "code=%d", code);
  zassert_equal(response_format, 60U);
  zassert_true(response_payload_len > 0U);
  zassert_equal(response_payload[0], 0xa5U);

  zassert_equal(get_sent("07000", false), COAP_RESPONSE_CODE_NOT_FOUND);
  zassert_equal(get_sent("18446744073709551616", false),
                COAP_RESPONSE_CODE_NOT_FOUND);
  zassert_equal(get_sent("7000", true), COAP_RESPONSE_CODE_NOT_FOUND);
  zassert_equal(get_sent("999999", false), COAP_RESPONSE_CODE_NOT_FOUND);
}

ZTEST(coap_msg_sent, test_mesh_post_and_unprotect_failure_do_not_mutate) {
  uint8_t payload[TEST_PACKET_SIZE];
  struct lichen_msg msg;
  size_t len = make_sent(payload, "2001:db8::1", (const uint8_t *)"forged",
                         6U, false, true, 8000U);

  local_admin = false;
  request_is_protected = true;
  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_UNAUTHORIZED);
  zassert_equal(lichen_msg_sent_get(8000U, &msg), -ENOENT);

  local_admin = true;
  unprotect_result = COAP_RESPONSE_CODE_UNAUTHORIZED;
  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_UNAUTHORIZED);
  zassert_equal(lichen_msg_sent_get(8000U, &msg), -ENOENT);
}

ZTEST(coap_msg_sent, test_strict_schema_destination_and_content) {
  uint8_t payload[TEST_PACKET_SIZE];
  struct lichen_msg msg;
  static const uint8_t invalid_utf8[] = {0xc0U, 0xafU};
  size_t len = make_sent(payload, "::", (const uint8_t *)"bad", 3U,
                         false, true, 9000U);

  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_BAD_REQUEST);
  len = make_sent(payload, "2001:db8::1", (const uint8_t *)"wrong format",
                  12U, false, true, 8999U);
  request_content_format = 0;
  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_BAD_REQUEST);
  request_content_format = -1;
  zassert_equal(lichen_msg_sent_get(8999U, &msg), -ENOENT);
  len = make_sent(payload, "2001:db8::1", invalid_utf8,
                  sizeof(invalid_utf8), false, true, 9000U);
  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_BAD_REQUEST);
  len = make_sent(payload, "2001:db8::1", (const uint8_t *)"", 0U,
                  false, true, 9000U);
  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_BAD_REQUEST);

  len = make_sent(payload, "2001:db8::1", (const uint8_t *)"valid", 5U,
                  false, true, 9000U);
  payload[len++] = 0U;
  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_BAD_REQUEST);

  len = make_sent(payload, "2001:db8::1", (const uint8_t *)"valid", 5U,
                  false, true, 9000U);
  payload[0] = 0xa5U;
  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_BAD_REQUEST);
  memset(payload, 0, sizeof(payload));
  zassert_equal(post_sent(payload, TEST_SENT_POST_MAX + 1U),
                COAP_RESPONSE_CODE_REQUEST_TOO_LARGE);
  zassert_equal(lichen_msg_sent_get(9000U, &msg), -ENOENT);
}

ZTEST(coap_msg_sent, test_duplicate_unknown_and_wrong_type_rejected) {
  static const uint8_t duplicate_to[] = {
      0xa3, 0x62, 't', 'o', 0x63, ':', ':', '1',
      0x62, 't', 'o', 0x63, ':', ':', '1',
      0x64, 'b', 'o', 'd', 'y', 0x61, 'x'};
  static const uint8_t unknown[] = {
      0xa3, 0x62, 't', 'o', 0x63, ':', ':', '1',
      0x64, 'b', 'o', 'd', 'y', 0x61, 'x',
      0x61, 'x', 0x01};
  static const uint8_t wrong_ack[] = {
      0xa3, 0x62, 't', 'o', 0x63, ':', ':', '1',
      0x63, 'a', 'c', 'k', 0x01,
      0x64, 'b', 'o', 'd', 'y', 0x61, 'x'};

  zassert_equal(post_sent(duplicate_to, sizeof(duplicate_to)),
                COAP_RESPONSE_CODE_BAD_REQUEST);
  zassert_equal(post_sent(unknown, sizeof(unknown)),
                COAP_RESPONSE_CODE_BAD_REQUEST);
  zassert_equal(post_sent(wrong_ack, sizeof(wrong_ack)),
                COAP_RESPONSE_CODE_BAD_REQUEST);
}

ZTEST(coap_msg_sent, test_z_uint64_max_exhausts_generated_ids_cleanly) {
  uint8_t payload[TEST_PACKET_SIZE];
  struct lichen_msg msg;
  size_t len = make_sent(payload, "2001:db8::1", (const uint8_t *)"max",
                         3U, false, true, UINT64_MAX);

  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_CREATED);
  zassert_true(strncmp(response_location, "msg/sent/", 9U) == 0,
               "location='%s' code=%u", response_location, response_code);
  zassert_equal(location_id(), UINT64_MAX);
  zassert_ok(lichen_msg_sent_get(UINT64_MAX, &msg));
  len = make_sent(payload, "2001:db8::1", (const uint8_t *)"auto", 4U,
                  false, false, 0U);
  zassert_equal(post_sent(payload, len), COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE);
}

static void *suite_setup(void) {
  zassert_ok(lichen_msg_init());
  return NULL;
}

static void before_each(void *fixture) {
  ARG_UNUSED(fixture);
  reset_request();
}

ZTEST_SUITE(coap_msg_sent, NULL, suite_setup, before_each, NULL, NULL);
