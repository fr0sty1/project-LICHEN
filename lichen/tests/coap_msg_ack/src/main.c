/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/ztest.h>

#include <lichen/coap_msg.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>

#define TEST_CBOR_MAX 128U
#define TEST_ACK_MAX_CBOR 96U

static bool request_is_protected;
static bool local_admin;
static int unprotect_result;
static const uint8_t *request_payload;
static size_t request_payload_len;
static uint8_t response_code;
static unsigned int status_change_count;
static uint64_t changed_id;
static enum lichen_msg_status changed_status;
static uint32_t changed_timestamp;

static const uint8_t peer_a[16] = {
    0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
static const uint8_t peer_b[16] = {
    0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01};

void lichen_msg_status_changed(uint64_t msg_id,
                               enum lichen_msg_status status,
                               uint32_t timestamp) {
  status_change_count++;
  changed_id = msg_id;
  changed_status = status;
  changed_timestamp = timestamp;
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
  ARG_UNUSED(content_format);
  ARG_UNUSED(payload);
  ARG_UNUSED(payload_len);
  response_code = code;
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
  zassert_equal(expected_method, COAP_METHOD_POST);
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
  ARG_UNUSED(addr);
  if (buf_len < 4U) {
    return -ENOMEM;
  }
  memcpy(buf, "::1", 4U);
  return 3;
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

static size_t make_receipt(uint8_t *buf, uint64_t id, const char *status,
                           uint64_t timestamp) {
  size_t off = 0U;
  size_t status_len = strlen(status);

  buf[off++] = 0xa3U;
  buf[off++] = 0x62U;
  memcpy(&buf[off], "id", 2U);
  off += 2U;
  off = put_uint(buf, off, id);
  buf[off++] = 0x66U;
  memcpy(&buf[off], "status", 6U);
  off += 6U;
  buf[off++] = 0x60U | (uint8_t)status_len;
  memcpy(&buf[off], status, status_len);
  off += status_len;
  buf[off++] = 0x62U;
  memcpy(&buf[off], "ts", 2U);
  off += 2U;
  return put_uint(buf, off, timestamp);
}

static uint64_t queue_message(const uint8_t peer[16], bool ack) {
  uint64_t id = 0U;

  zassert_ok(lichen_msg_send(peer, "hello", 5U, ack, &id));
  return id;
}

static int post_receipt(const uint8_t *payload, size_t payload_len,
                        const uint8_t source[16]) {
  struct coap_resource resource = {0};
  struct coap_packet request = {0};
  struct sockaddr_in6 addr = {0};

  addr.sin6_family = AF_INET6;
  memcpy(addr.sin6_addr.s6_addr, source, 16U);
  request_payload = payload;
  request_payload_len = payload_len;
  response_code = 0U;
  int ret = lichen_msg_ack_post(&resource, &request,
                                (struct sockaddr *)&addr, sizeof(addr));
  return ret == 0 ? response_code : ret;
}

static void reset_request(void) {
  request_is_protected = true;
  local_admin = false;
  unprotect_result = 0;
  request_payload = NULL;
  request_payload_len = 0U;
  response_code = 0U;
}

ZTEST(coap_msg_ack, test_valid_duplicate_and_read_transition) {
  uint8_t payload[TEST_CBOR_MAX];
  struct lichen_msg msg;
  uint64_t id = queue_message(peer_a, true);
  size_t len = make_receipt(payload, id, "delivered", 1716742900U);

  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_CHANGED);
  zassert_ok(lichen_msg_sent_get(id, &msg));
  zassert_equal(msg.status, LICHEN_MSG_STATUS_DELIVERED);
  zassert_equal(msg.receipt_timestamp, 1716742900U);
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_CHANGED,
                "exact duplicate must be idempotent");

  len = make_receipt(payload, id, "read", 1716742901U);
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_CHANGED);
  zassert_ok(lichen_msg_sent_get(id, &msg));
  zassert_equal(msg.status, LICHEN_MSG_STATUS_READ);
}

ZTEST(coap_msg_ack, test_local_sent_failed_propagation_is_monotonic) {
  struct lichen_msg before;
  struct lichen_msg after;
  uint64_t id = queue_message(peer_a, true);
  uint32_t sent_at = UINT32_MAX - 2U;

  status_change_count = 0U;
  zassert_ok(lichen_msg_sent_status_update(id, LICHEN_MSG_STATUS_SENT, sent_at));
  zassert_equal(status_change_count, 1U);
  zassert_equal(changed_id, id);
  zassert_equal(changed_status, LICHEN_MSG_STATUS_SENT);
  zassert_equal(changed_timestamp, sent_at);
  zassert_ok(lichen_msg_sent_status_update(id, LICHEN_MSG_STATUS_SENT, sent_at),
             "exact transition replay is idempotent");
  zassert_equal(status_change_count, 1U);
  zassert_ok(lichen_msg_sent_get(id, &before));
  zassert_equal(lichen_msg_sent_status_update(id, LICHEN_MSG_STATUS_SENT,
                                              sent_at + 1U),
                -EALREADY);
  zassert_equal(lichen_msg_sent_status_update(id, LICHEN_MSG_STATUS_FAILED,
                                              sent_at - 1U),
                -EALREADY);
  zassert_ok(lichen_msg_sent_get(id, &after));
  zassert_mem_equal(&after, &before, sizeof(after));
  zassert_ok(lichen_msg_sent_status_update(id, LICHEN_MSG_STATUS_FAILED,
                                           sent_at + 1U));
  zassert_equal(status_change_count, 2U);
  zassert_equal(changed_status, LICHEN_MSG_STATUS_FAILED);
  zassert_equal(lichen_msg_sent_status_update(id, LICHEN_MSG_STATUS_SENT,
                                              UINT32_MAX),
                -EALREADY);
}

ZTEST(coap_msg_ack, test_read_before_delivery_is_rejected_atomically) {
  uint8_t payload[TEST_CBOR_MAX];
  struct lichen_msg before;
  struct lichen_msg after;
  uint64_t id = queue_message(peer_a, true);
  size_t len = make_receipt(payload, id, "read", 500U);

  zassert_ok(lichen_msg_sent_get(id, &before));
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_CONFLICT);
  zassert_ok(lichen_msg_sent_get(id, &after));
  zassert_mem_equal(&after, &before, sizeof(after));
}

ZTEST(coap_msg_ack, test_replay_conflict_is_atomic) {
  uint8_t payload[TEST_CBOR_MAX];
  struct lichen_msg before;
  struct lichen_msg after;
  uint64_t id = queue_message(peer_a, true);
  size_t len = make_receipt(payload, id, "delivered", 200U);

  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_CHANGED);
  zassert_ok(lichen_msg_sent_get(id, &before));
  len = make_receipt(payload, id, "failed", 199U);
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_CONFLICT);
  zassert_ok(lichen_msg_sent_get(id, &after));
  zassert_mem_equal(&after, &before, sizeof(after));
}

ZTEST(coap_msg_ack, test_failed_receipt_is_terminal) {
  uint8_t payload[TEST_CBOR_MAX];
  struct lichen_msg before;
  struct lichen_msg after;
  uint64_t id = queue_message(peer_a, true);
  size_t len = make_receipt(payload, id, "failed", 300U);

  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_CHANGED);
  zassert_ok(lichen_msg_sent_get(id, &before));
  zassert_equal(before.status, LICHEN_MSG_STATUS_FAILED);
  zassert_true(before.acknowledged);
  len = make_receipt(payload, id, "delivered", 301U);
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_CONFLICT);
  zassert_ok(lichen_msg_sent_get(id, &after));
  zassert_mem_equal(&after, &before, sizeof(after));
}

ZTEST(coap_msg_ack, test_forged_unknown_and_unrequested_receipts) {
  uint8_t payload[TEST_CBOR_MAX];
  struct lichen_msg before;
  struct lichen_msg after;
  uint64_t id = queue_message(peer_a, true);
  size_t len = make_receipt(payload, id, "delivered", 1U);

  zassert_ok(lichen_msg_sent_get(id, &before));
  zassert_equal(post_receipt(payload, len, peer_b), COAP_RESPONSE_CODE_FORBIDDEN);
  zassert_ok(lichen_msg_sent_get(id, &after));
  zassert_mem_equal(&after, &before, sizeof(after));

  len = make_receipt(payload, UINT64_MAX, "delivered", UINT32_MAX);
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_NOT_FOUND,
                "max-width valid types must reach identity lookup");

  id = queue_message(peer_a, false);
  len = make_receipt(payload, id, "delivered", 1U);
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_FORBIDDEN);
}

ZTEST(coap_msg_ack, test_authentication_policy) {
  uint8_t payload[TEST_CBOR_MAX];
  uint64_t id = queue_message(peer_a, true);
  size_t len = make_receipt(payload, id, "delivered", 3U);

  request_is_protected = false;
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_UNAUTHORIZED);
  local_admin = true;
  zassert_equal(post_receipt(payload, len, peer_b), COAP_RESPONSE_CODE_CHANGED);

  unprotect_result = COAP_RESPONSE_CODE_UNAUTHORIZED;
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_UNAUTHORIZED);
}

ZTEST(coap_msg_ack, test_strict_schema_and_canonical_integers) {
  uint8_t payload[TEST_CBOR_MAX];
  uint64_t id = queue_message(peer_a, true);
  size_t len = make_receipt(payload, id, "bogus", 1U);

  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_BAD_REQUEST);

  len = make_receipt(payload, id, "delivered", 1U);
  payload[len++] = 0U;
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_BAD_REQUEST,
                "trailing data must be rejected");

  len = make_receipt(payload, id, "delivered", (uint64_t)UINT32_MAX + 1U);
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_BAD_REQUEST);

  len = make_receipt(payload, id, "delivered", 1U);
  payload[0] = 0xa2U;
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_BAD_REQUEST);

  memset(payload, 0, sizeof(payload));
  zassert_equal(post_receipt(payload, TEST_ACK_MAX_CBOR + 1U, peer_a),
                COAP_RESPONSE_CODE_REQUEST_TOO_LARGE);
}

ZTEST(coap_msg_ack, test_duplicate_unknown_and_noncanonical_fields) {
  static const uint8_t duplicate_id[] = {
      0xa3, 0x62, 'i', 'd', 0x01, 0x62, 'i', 'd', 0x01,
      0x62, 't', 's', 0x01};
  static const uint8_t unknown_key[] = {
      0xa3, 0x62, 'i', 'd', 0x01, 0x61, 'x', 0x01,
      0x62, 't', 's', 0x01};
  static const uint8_t negative_id[] = {
      0xa3, 0x62, 'i', 'd', 0x20, 0x66, 's', 't', 'a', 't', 'u', 's',
      0x69, 'd', 'e', 'l', 'i', 'v', 'e', 'r', 'e', 'd',
      0x62, 't', 's', 0x01};
  static const uint8_t noncanonical_id[] = {
      0xa3, 0x62, 'i', 'd', 0x18, 0x01,
      0x66, 's', 't', 'a', 't', 'u', 's',
      0x69, 'd', 'e', 'l', 'i', 'v', 'e', 'r', 'e', 'd',
      0x62, 't', 's', 0x01};

  zassert_equal(post_receipt(duplicate_id, sizeof(duplicate_id), peer_a),
                COAP_RESPONSE_CODE_BAD_REQUEST);
  zassert_equal(post_receipt(unknown_key, sizeof(unknown_key), peer_a),
                COAP_RESPONSE_CODE_BAD_REQUEST);
  zassert_equal(post_receipt(negative_id, sizeof(negative_id), peer_a),
                COAP_RESPONSE_CODE_BAD_REQUEST);
  zassert_equal(post_receipt(noncanonical_id, sizeof(noncanonical_id), peer_a),
                COAP_RESPONSE_CODE_BAD_REQUEST);
}

ZTEST(coap_msg_ack, test_sent_capacity_eviction_and_latest_receipt) {
  uint8_t payload[TEST_CBOR_MAX];
  uint64_t ids[LICHEN_MSG_SENT_MAX + 1U];

  for (size_t i = 0U; i < ARRAY_SIZE(ids); i++) {
    ids[i] = queue_message(peer_a, true);
  }
  size_t len = make_receipt(payload, ids[0], "delivered", 1U);
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_NOT_FOUND);
  len = make_receipt(payload, ids[ARRAY_SIZE(ids) - 1U], "delivered", 1U);
  zassert_equal(post_receipt(payload, len, peer_a), COAP_RESPONSE_CODE_CHANGED);
}

static void *suite_setup(void) {
  zassert_ok(lichen_msg_init());
  return NULL;
}

static void before_each(void *fixture) {
  ARG_UNUSED(fixture);
  reset_request();
}

ZTEST_SUITE(coap_msg_ack, NULL, suite_setup, before_each, NULL, NULL);
