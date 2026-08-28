/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/ztest.h>

#include <lichen/coap_msg.h>
#include <lichen/coap_oscore.h>

#define PACKET_SIZE 512U

static bool local_admin = true;
static uint8_t response_code;
static uint16_t response_format;
static uint8_t response_payload[PACKET_SIZE];
static size_t response_payload_len;
static int observe_send_result;
static unsigned int observe_sends;
static uint32_t last_sequence;
static uint8_t last_observe_payload[PACKET_SIZE];
static size_t last_observe_payload_len;

static const uint8_t peer[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

bool lichen_coap_is_local_admin(const struct sockaddr *addr,
                                socklen_t addr_len) {
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  return local_admin;
}

int lichen_coap_format_ipv6(const uint8_t addr[16], char *buf, size_t buf_len) {
  return net_addr_ntop(AF_INET6, addr, buf, buf_len) == NULL
             ? -ENOBUFS
             : (int)strlen(buf);
}

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

int coap_oscore_unprotect_resource_request(
    struct coap_resource *resource, struct coap_packet *request,
    struct sockaddr *addr, socklen_t addr_len, uint8_t expected_method,
    struct coap_oscore_unprotect_result *result) {
  ARG_UNUSED(resource);
  ARG_UNUSED(request);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  zassert_equal(expected_method, COAP_METHOD_GET);
  memset(result, 0, sizeof(*result));
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

int lichen_msg_inbox_observe_send(
    struct coap_resource *resource, const struct sockaddr *addr,
    socklen_t addr_len, const uint8_t *token, uint8_t token_len,
    uint32_t sequence, const uint8_t *payload, size_t payload_len,
    bool initial, uint8_t request_type, uint16_t request_id) {
  ARG_UNUSED(resource);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  ARG_UNUSED(token);
  ARG_UNUSED(token_len);
  ARG_UNUSED(initial);
  ARG_UNUSED(request_type);
  ARG_UNUSED(request_id);
  observe_sends++;
  last_sequence = sequence;
  last_observe_payload_len = MIN(payload_len, sizeof(last_observe_payload));
  memcpy(last_observe_payload, payload, last_observe_payload_len);
  return observe_send_result;
}

static void init_resource(struct coap_resource *resource) {
  memset(resource, 0, sizeof(*resource));
  sys_slist_init(&resource->observers);
  resource->notify = lichen_msg_inbox_notify_cb;
}

static void init_request(struct coap_packet *request, uint8_t *buf,
                         uint8_t token, int observe, const char *query) {
  zassert_ok(coap_packet_init(request, buf, PACKET_SIZE, COAP_VERSION_1,
                              COAP_TYPE_CON, 1U, &token, COAP_METHOD_GET, 9U));
  if (observe >= 0) {
    zassert_ok(coap_append_option_int(request, COAP_OPTION_OBSERVE,
                                      (unsigned int)observe));
  }
  if (query != NULL) {
    zassert_ok(coap_packet_append_option(request, COAP_OPTION_URI_QUERY, query,
                                         strlen(query)));
  }
  request->max_len = request->offset;
}

static int collection_get(struct coap_resource *resource, uint8_t token,
                          int observe, const char *query, uint16_t port) {
  uint8_t buf[PACKET_SIZE];
  struct coap_packet request;
  struct sockaddr_in6 addr = {.sin6_family = AF_INET6,
                              .sin6_port = htons(port)};

  memcpy(addr.sin6_addr.s6_addr, peer, sizeof(peer));
  init_request(&request, buf, token, observe, query);
  response_code = 0U;
  int ret = lichen_msg_inbox_get_handler(
      resource, &request, (struct sockaddr *)&addr, sizeof(addr));
  return ret == 0 ? response_code : ret;
}

static int detail_get(struct coap_resource *resource, const char *id) {
  uint8_t buf[PACKET_SIZE];
  uint8_t token = 0x71U;
  struct coap_packet request;
  struct sockaddr_in6 addr = {.sin6_family = AF_INET6};

  memcpy(addr.sin6_addr.s6_addr, peer, sizeof(peer));
  init_request(&request, buf, token, -1, NULL);
  request.max_len = PACKET_SIZE;
  zassert_ok(coap_packet_append_option(&request, COAP_OPTION_URI_PATH, "msg", 3U));
  zassert_ok(coap_packet_append_option(&request, COAP_OPTION_URI_PATH, "inbox", 5U));
  zassert_ok(coap_packet_append_option(&request, COAP_OPTION_URI_PATH, id,
                                       strlen(id)));
  request.max_len = request.offset;
  response_code = 0U;
  int ret = lichen_msg_inbox_id_get(
      resource, &request, (struct sockaddr *)&addr, sizeof(addr));
  return ret == 0 ? response_code : ret;
}

static uint64_t read_uint(const uint8_t *buf, size_t len, size_t *off) {
  zassert_true(*off < len);
  uint8_t head = buf[(*off)++];
  if (head < 24U) {
    return head;
  }
  zassert_equal(head, 0x18U);
  zassert_true(*off < len);
  return buf[(*off)++];
}

static bool contains_bytes(const uint8_t *buf, size_t len,
                           const char *needle, size_t needle_len) {
  if (needle_len > len) {
    return false;
  }
  for (size_t i = 0U; i <= len - needle_len; i++) {
    if (memcmp(&buf[i], needle, needle_len) == 0) {
      return true;
    }
  }
  return false;
}

static void decode_page_header(size_t *next, size_t *unread,
                               size_t *messages) {
  size_t off = 0U;
  zassert_equal(response_payload[off++], 0xa3U);
  zassert_equal(response_payload[off++], 0x64U);
  zassert_mem_equal(&response_payload[off], "next", 4U);
  off += 4U;
  *next = (size_t)read_uint(response_payload, response_payload_len, &off);
  zassert_equal(response_payload[off++], 0x66U);
  zassert_mem_equal(&response_payload[off], "unread", 6U);
  off += 6U;
  *unread = (size_t)read_uint(response_payload, response_payload_len, &off);
  zassert_equal(response_payload[off++], 0x68U);
  zassert_mem_equal(&response_payload[off], "messages", 8U);
  off += 8U;
  zassert_true((response_payload[off] & 0xf8U) == 0x80U);
  *messages = response_payload[off] & 0x07U;
}

ZTEST(coap_msg_inbox, test_empty_private_and_strict_pagination) {
  struct coap_resource resource;
  size_t next;
  size_t unread;
  size_t messages;

  init_resource(&resource);
  zassert_equal(collection_get(&resource, 1U, -1, NULL, 1001U),
                COAP_RESPONSE_CODE_CONTENT);
  zassert_equal(response_format, 60U);
  decode_page_header(&next, &unread, &messages);
  zassert_equal(next, 0U);
  zassert_equal(unread, 0U);
  zassert_equal(messages, 0U);
  local_admin = false;
  zassert_equal(collection_get(&resource, 1U, -1, NULL, 1001U),
                COAP_RESPONSE_CODE_UNAUTHORIZED);
  local_admin = true;
  zassert_equal(collection_get(&resource, 1U, -1, "limit=0", 1001U),
                COAP_RESPONSE_CODE_BAD_REQUEST);
  zassert_equal(collection_get(&resource, 1U, -1, "unknown=1", 1001U),
                COAP_RESPONSE_CODE_BAD_REQUEST);
}

ZTEST(coap_msg_inbox, test_listing_detail_and_read_transition) {
  struct coap_resource resource;
  struct lichen_msg msg;
  size_t next;
  size_t unread;
  size_t messages;
  char id[24];

  init_resource(&resource);
  zassert_ok(lichen_msg_receive(peer, "first", 5U, 100U));
  zassert_ok(lichen_msg_receive(peer, "second", 6U, 101U));
  zassert_equal(collection_get(&resource, 2U, -1, "limit=1", 1002U),
                COAP_RESPONSE_CODE_CONTENT);
  decode_page_header(&next, &unread, &messages);
  zassert_equal(next, 1U);
  zassert_equal(unread, 2U);
  zassert_equal(messages, 1U);
  zassert_ok(lichen_msg_inbox_get(0U, &msg));
  snprintk(id, sizeof(id), "%llu", (unsigned long long)msg.id);
  zassert_equal(detail_get(&resource, id), COAP_RESPONSE_CODE_CONTENT);
  zassert_true(contains_bytes(response_payload, response_payload_len,
                              "read", 4U));
  zassert_ok(lichen_msg_inbox_get(0U, &msg));
  zassert_equal(msg.status, LICHEN_MSG_STATUS_READ);
  zassert_equal(collection_get(&resource, 2U, -1, NULL, 1002U),
                COAP_RESPONSE_CODE_CONTENT);
  decode_page_header(&next, &unread, &messages);
  zassert_equal(unread, 1U);
  zassert_equal(detail_get(&resource, id), COAP_RESPONSE_CODE_CONTENT);
  zassert_true(contains_bytes(response_payload, response_payload_len,
                              "read", 4U));
  zassert_equal(detail_get(&resource, "01"), COAP_RESPONSE_CODE_NOT_FOUND);
  zassert_equal(detail_get(&resource, "18446744073709551616"),
                COAP_RESPONSE_CODE_NOT_FOUND);
}

ZTEST(coap_msg_inbox, test_observe_change_no_change_cancel_and_capacity) {
  struct coap_resource resources[5];

  for (size_t i = 0U; i < ARRAY_SIZE(resources); i++) {
    init_resource(&resources[i]);
  }
  observe_sends = 0U;
  zassert_equal(collection_get(&resources[0], 10U, 0, NULL, 2000U), 0);
  zassert_equal(observe_sends, 1U);
  uint32_t initial_sequence = last_sequence;
  zassert_ok(lichen_msg_receive(peer, "notify", 6U, 200U));
  zassert_ok(coap_resource_notify(&resources[0]));
  zassert_equal(observe_sends, 2U);
  zassert_true(last_sequence != initial_sequence);
  zassert_true(last_observe_payload_len > 0U);
  zassert_ok(coap_resource_notify(&resources[0]));
  zassert_equal(observe_sends, 2U, "unchanged representation must not resend");
  zassert_equal(collection_get(&resources[0], 10U, 1, NULL, 2000U),
                COAP_RESPONSE_CODE_CONTENT);
  zassert_ok(lichen_msg_receive(peer, "after cancel", 12U, 201U));
  zassert_ok(coap_resource_notify(&resources[0]));
  zassert_equal(observe_sends, 2U);

  for (size_t i = 0U; i < 4U; i++) {
    zassert_equal(collection_get(&resources[i], (uint8_t)(20U + i), 0, NULL,
                                 (uint16_t)(2100U + i)), 0);
  }
  zassert_equal(collection_get(&resources[4], 30U, 0, NULL, 2200U),
                COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE);
  for (size_t i = 0U; i < 4U; i++) {
    zassert_equal(collection_get(&resources[i], (uint8_t)(20U + i), 1, NULL,
                                 (uint16_t)(2100U + i)),
                  COAP_RESPONSE_CODE_CONTENT);
  }
}

ZTEST(coap_msg_inbox, test_transient_backpressure_retries_then_releases_slot) {
  struct coap_resource resource;

  init_resource(&resource);
  observe_send_result = 0;
  zassert_equal(collection_get(&resource, 40U, 0, NULL, 3000U), 0);
  observe_send_result = -EAGAIN;
  zassert_ok(lichen_msg_receive(peer, "retry", 5U, 300U));
  zassert_ok(coap_resource_notify(&resource));
  zassert_ok(coap_resource_notify(&resource));
  zassert_ok(coap_resource_notify(&resource));
  observe_send_result = 0;
  zassert_ok(coap_resource_notify(&resource));
  zassert_equal(collection_get(&resource, 41U, 0, NULL, 3001U), 0,
                "failed observer slot must be reusable");
  zassert_equal(collection_get(&resource, 41U, 1, NULL, 3001U),
                COAP_RESPONSE_CODE_CONTENT);
}

ZTEST(coap_msg_inbox, test_z_full_queue_evicts_oldest) {
  struct lichen_msg before;
  struct lichen_msg after;

  zassert_ok(lichen_msg_inbox_get(0U, &before));
  for (size_t i = 0U; i < LICHEN_MSG_INBOX_MAX + 1U; i++) {
    zassert_ok(lichen_msg_receive(peer, "fill", 4U, (uint32_t)(400U + i)));
  }
  zassert_equal(lichen_msg_inbox_count(), LICHEN_MSG_INBOX_MAX);
  zassert_ok(lichen_msg_inbox_get(0U, &after));
  zassert_true(after.id > before.id);
}

static void *setup(void) {
  zassert_ok(lichen_msg_init());
  return NULL;
}

static void before(void *fixture) {
  ARG_UNUSED(fixture);
  local_admin = true;
  response_code = 0U;
  response_format = 0U;
  response_payload_len = 0U;
  observe_send_result = 0;
}

ZTEST_SUITE(coap_msg_inbox, NULL, setup, before, NULL, NULL);
