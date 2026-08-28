/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/ztest.h>

#include <lichen/coap_client.h>
#include <lichen/coap_location.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>
#include <lichen/hal.h>
#include <lichen/senml.h>

static uint16_t coap_port = 5683;
COAP_SERVICE_DEFINE(lichen_coap_server, NULL, &coap_port, 0);

struct tx_capture {
  int ret;
  uint32_t calls;
  size_t payload_len;
  uint8_t payload[LICHEN_POSITION_BEACON_PAYLOAD_MAX];
};

static struct tx_capture tx;
static struct lichen_hal_location_time_snapshot snapshot;
static int snapshot_ret;
static struct lichen_coap_request default_request;
static uint8_t default_payload[LICHEN_POSITION_BEACON_PAYLOAD_MAX];
static uint32_t default_request_calls;
static char encoded_base_name[40];
static uint64_t encoded_base_time;
static float encoded_latitude;
static float encoded_longitude;
static float encoded_altitude;
static float encoded_hacc;
static float encoded_vacc;
static uint8_t response_code;
static uint16_t response_format;
static uint8_t response_payload[LICHEN_POSITION_CACHE_PAYLOAD_MAX];
static size_t response_payload_len;
static int observe_tx_ret;
static uint32_t observe_tx_calls;
static uint32_t observe_sequence;
static bool observe_initial;
static uint8_t observe_token[COAP_TOKEN_MAX_LEN];
static uint8_t observe_token_len;
static uint8_t observe_payload[LICHEN_POSITION_BEACON_PAYLOAD_MAX];
static size_t observe_payload_len;

extern struct coap_resource lichen_position_cache;
extern struct coap_resource lichen_sensors_location;

static void set_fix(int32_t latitude_e7, int32_t longitude_e7) {
  snapshot = (struct lichen_hal_location_time_snapshot){
      .location_provider_available = true,
      .latitude_e7_valid = true,
      .latitude_e7 = latitude_e7,
      .longitude_e7_valid = true,
      .longitude_e7 = longitude_e7,
      .altitude_m_valid = true,
      .altitude_m = 42,
      .fix_time_unix_valid = true,
      .fix_time_unix = 1710000000U,
      .horizontal_accuracy_mm_valid = true,
      .horizontal_accuracy_mm = 1250U,
      .vertical_accuracy_mm_valid = true,
      .vertical_accuracy_mm = 2500U,
  };
  snapshot_ret = 0;
}

static int capture_tx(const uint8_t *payload, size_t payload_len,
                      void *user_data) {
  struct tx_capture *capture = user_data;

  capture->calls++;
  capture->payload_len = payload_len;
  zassert_true(payload_len <= sizeof(capture->payload));
  memcpy(capture->payload, payload, payload_len);
  return capture->ret;
}

int lichen_position_observe_send(
    const struct coap_resource *resource, const struct sockaddr *addr,
    socklen_t addr_len, const uint8_t *token, uint8_t token_len,
    uint32_t sequence, const uint8_t *payload, size_t payload_len, bool initial,
    uint8_t request_type, uint16_t request_id) {
  ARG_UNUSED(resource);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  ARG_UNUSED(request_type);
  ARG_UNUSED(request_id);
  zassert_true(token_len <= sizeof(observe_token));
  zassert_true(payload_len <= sizeof(observe_payload));
  observe_tx_calls++;
  observe_sequence = sequence;
  observe_initial = initial;
  observe_token_len = token_len;
  memcpy(observe_token, token, token_len);
  observe_payload_len = payload_len;
  memcpy(observe_payload, payload, payload_len);
  return observe_tx_ret;
}

int lichen_hal_location_time_snapshot_get(
    struct lichen_hal_location_time_snapshot *out) {
  if (out == NULL) {
    return -EINVAL;
  }
  if (snapshot_ret < 0) {
    return snapshot_ret;
  }
  *out = snapshot;
  return 0;
}

int lichen_lora_l2_copy_eui64(uint8_t eui64[8]) {
  static const uint8_t expected[8] = {
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  };

  memcpy(eui64, expected, sizeof(expected));
  return 0;
}

int senml_encode_location_full(const char *base_name, uint64_t base_time,
                               float latitude, float longitude, float altitude,
                               float speed, float heading,
                               float horizontal_accuracy,
                               float vertical_accuracy, uint8_t *buf,
                               size_t buf_len) {
  static const uint8_t encoded[] = {
      0x82, 0xa1, 0x00, 0x63, 0x6c, 0x61, 0x74,
  };

  zassert_not_null(base_name);
  zassert_equal(buf_len, LICHEN_POSITION_BEACON_PAYLOAD_MAX);
  zassert_true(isnan(speed));
  zassert_true(isnan(heading));
  strncpy(encoded_base_name, base_name, sizeof(encoded_base_name) - 1U);
  encoded_base_time = base_time;
  encoded_latitude = latitude;
  encoded_longitude = longitude;
  encoded_altitude = altitude;
  encoded_hacc = horizontal_accuracy;
  encoded_vacc = vertical_accuracy;
  if (buf_len < sizeof(encoded)) {
    return -ENOBUFS;
  }
  memcpy(buf, encoded, sizeof(encoded));
  return sizeof(encoded);
}

int lichen_coap_request(const struct lichen_coap_request *request) {
  default_request = *request;
  default_request_calls++;
  zassert_true(request->payload_len <= sizeof(default_payload));
  memcpy(default_payload, request->payload, request->payload_len);
  return LICHEN_COAP_OK;
}

int lichen_coap_respond(struct coap_resource *resource,
                        struct coap_packet *request, struct sockaddr *addr,
                        socklen_t addr_len, uint8_t resp_code,
                        uint16_t content_format, const uint8_t *payload,
                        size_t payload_len) {
  ARG_UNUSED(resource);
  ARG_UNUSED(request);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  response_code = resp_code;
  response_format = content_format;
  response_payload_len = payload_len;
  zassert_true(payload_len <= sizeof(response_payload));
  if (payload_len > 0U) {
    zassert_not_null(payload);
    memcpy(response_payload, payload, payload_len);
  }
  return 0;
}

bool lichen_coap_is_local_admin(const struct sockaddr *addr,
                                socklen_t addr_len) {
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  return false;
}

int coap_oscore_unprotect_resource_request(
    struct coap_resource *resource, struct coap_packet *request,
    struct sockaddr *addr, socklen_t addr_len, uint8_t expected_method,
    struct coap_oscore_unprotect_result *result) {
  ARG_UNUSED(resource);
  ARG_UNUSED(request);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  ARG_UNUSED(expected_method);
  ARG_UNUSED(result);
  return -ENOTSUP;
}

int coap_oscore_respond_resource(
    struct coap_resource *resource, struct coap_packet *request,
    struct sockaddr *addr, socklen_t addr_len,
    const struct coap_oscore_unprotect_result *result, uint8_t response_code,
    uint16_t content_format, const uint8_t *payload, size_t payload_len) {
  ARG_UNUSED(resource);
  ARG_UNUSED(request);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  ARG_UNUSED(result);
  ARG_UNUSED(response_code);
  ARG_UNUSED(content_format);
  ARG_UNUSED(payload);
  ARG_UNUSED(payload_len);
  return -ENOTSUP;
}

static void reset_state(void) {
  lichen_position_beacon_stop();
  lichen_position_observe_reset();
  lichen_position_cache_reset();
  memset(&tx, 0, sizeof(tx));
  memset(&default_request, 0, sizeof(default_request));
  memset(default_payload, 0, sizeof(default_payload));
  default_request_calls = 0U;
  memset(encoded_base_name, 0, sizeof(encoded_base_name));
  response_code = 0U;
  response_format = 0U;
  response_payload_len = 0U;
  memset(response_payload, 0, sizeof(response_payload));
  observe_tx_ret = 0;
  observe_tx_calls = 0U;
  observe_sequence = 0U;
  observe_initial = false;
  observe_token_len = 0U;
  observe_payload_len = 0U;
  memset(observe_token, 0, sizeof(observe_token));
  memset(observe_payload, 0, sizeof(observe_payload));
  snapshot_ret = 0;
  set_fix(476206130, -1223493000);
}

static struct lichen_position_beacon_config test_config(void) {
  return (struct lichen_position_beacon_config){
      .moving_interval_ms = 60U,
      .stationary_interval_ms = 300U,
      .retry_interval_ms = 5U,
      .moving_threshold_cm = 1000U,
      .stationary_threshold_cm = 300U,
      .stationary_hysteresis_samples = 2U,
      .max_retries = 3U,
      .tx_fn = capture_tx,
      .tx_user_data = &tx,
  };
}

static struct lichen_position_cache_update cache_update(uint16_t suffix,
                                                         int64_t observed_ms,
                                                         uint64_t timestamp) {
  struct lichen_position_cache_update update = {
      .latitude_e7 = 377749290,
      .longitude_e7 = -1224194160,
      .altitude_cm = 1050,
      .timestamp_unix = timestamp,
      .observed_monotonic_ms = observed_ms,
      .privacy = LICHEN_POSITION_PRIVACY_PUBLIC,
      .provenance = LICHEN_POSITION_PROVENANCE_LINK_SIGNED,
      .altitude_valid = true,
      .authenticated = true,
  };

  update.node[0] = 0x02U;
  update.node[14] = (uint8_t)(suffix >> 8);
  update.node[15] = (uint8_t)suffix;
  memcpy(update.authenticated_node, update.node, sizeof(update.node));
  return update;
}

static int observe_request(uint8_t token_value, uint32_t observe_value) {
  uint8_t request_buf[64];
  struct coap_packet request;
  struct sockaddr_in6 addr = {
      .sin6_family = AF_INET6,
      .sin6_port = htons(5683U),
  };
  int ret;

  addr.sin6_addr.s6_addr[0] = 0x02U;
  addr.sin6_addr.s6_addr[15] = token_value;
  ret = coap_packet_init(&request, request_buf, sizeof(request_buf),
                         COAP_VERSION_1, COAP_TYPE_CON, 1U, &token_value,
                         COAP_METHOD_GET, token_value);
  zassert_ok(ret);
  ret = coap_append_option_int(&request, COAP_OPTION_OBSERVE, observe_value);
  zassert_ok(ret);
  return lichen_sensors_location.get(
      &lichen_sensors_location, &request, (struct sockaddr *)&addr,
      sizeof(addr));
}

ZTEST(coap_location_beacon,
      test_stationary_and_moving_intervals_with_hysteresis) {
  struct lichen_position_beacon_config config = test_config();
  struct lichen_position_beacon_stats stats;

  reset_state();
  zassert_ok(lichen_position_beacon_configure(&config, 0));
  zassert_equal(lichen_position_beacon_poll(0), LICHEN_POSITION_BEACON_SENT);
  zassert_ok(lichen_position_beacon_get_stats(&stats));
  zassert_false(stats.moving);
  zassert_equal(stats.next_due_ms, 300);

  set_fix(476208130, -1223493000);
  zassert_equal(lichen_position_beacon_poll(60), LICHEN_POSITION_BEACON_SENT);
  zassert_ok(lichen_position_beacon_get_stats(&stats));
  zassert_true(stats.moving);
  zassert_equal(stats.next_due_ms, 120);
  zassert_equal(lichen_position_beacon_poll(119), LICHEN_POSITION_BEACON_IDLE);
  zassert_equal(lichen_position_beacon_poll(120), LICHEN_POSITION_BEACON_SENT);

  zassert_equal(lichen_position_beacon_poll(180), LICHEN_POSITION_BEACON_SENT);
  zassert_ok(lichen_position_beacon_get_stats(&stats));
  zassert_false(stats.moving);
  zassert_equal(stats.next_due_ms, 480);
}

ZTEST(coap_location_beacon, test_payload_fields_are_bounded_and_canonical) {
  struct lichen_position_beacon_config config = test_config();

  reset_state();
  zassert_ok(lichen_position_beacon_configure(&config, 10));
  zassert_equal(lichen_position_beacon_poll(10), LICHEN_POSITION_BEACON_SENT);
  zassert_equal(tx.calls, 1U);
  zassert_true(tx.payload_len <= LICHEN_POSITION_BEACON_PAYLOAD_MAX);
  zassert_str_equal(encoded_base_name, "urn:dev:mac:0011223344556677:");
  zassert_equal(encoded_base_time, 1710000000U);
  zassert_within(encoded_latitude, 47.620613f, 0.000001f);
  zassert_within(encoded_longitude, -122.3493f, 0.00001f);
  zassert_within(encoded_altitude, 42.0f, 0.001f);
  zassert_within(encoded_hacc, 1.25f, 0.001f);
  zassert_within(encoded_vacc, 2.5f, 0.001f);
}

ZTEST(coap_location_beacon, test_no_fix_and_privacy_modes_never_transmit) {
  struct lichen_position_beacon_config config = test_config();
  struct lichen_position_beacon_stats stats;

  reset_state();
  zassert_ok(lichen_position_beacon_configure(&config, 0));
  snapshot.latitude_e7_valid = false;
  zassert_equal(lichen_position_beacon_poll(0), LICHEN_POSITION_BEACON_NO_FIX);
  zassert_equal(tx.calls, 0U);
  zassert_ok(lichen_position_beacon_get_stats(&stats));
  zassert_equal(stats.next_due_ms, 60);

  set_fix(476206130, -1223493000);
  for (enum lichen_position_privacy_mode mode = LICHEN_POSITION_PRIVACY_GROUP;
       mode <= LICHEN_POSITION_PRIVACY_OFF; mode++) {
    zassert_ok(lichen_position_beacon_set_privacy(mode));
    zassert_equal(lichen_position_beacon_poll(stats.next_due_ms),
                  LICHEN_POSITION_BEACON_SUPPRESSED);
    zassert_ok(lichen_position_beacon_get_stats(&stats));
  }
  zassert_equal(tx.calls, 0U);
  zassert_ok(
      lichen_position_beacon_set_privacy(LICHEN_POSITION_PRIVACY_PUBLIC));
  zassert_equal(lichen_position_beacon_poll(1000), LICHEN_POSITION_BEACON_SENT);
  zassert_equal(tx.calls, 1U);
}

ZTEST(coap_location_beacon, test_backpressure_retries_are_bounded) {
  struct lichen_position_beacon_config config = test_config();
  struct lichen_position_beacon_stats stats;

  reset_state();
  tx.ret = -ENOBUFS;
  zassert_ok(lichen_position_beacon_configure(&config, 0));
  for (int64_t now = 0; now <= 15; now += 5) {
    zassert_equal(lichen_position_beacon_poll(now), -ENOBUFS);
  }
  zassert_ok(lichen_position_beacon_get_stats(&stats));
  zassert_equal(stats.backpressure, 4U);
  zassert_equal(stats.failures, 1U);
  zassert_equal(stats.retry_count, 0U);
  zassert_equal(stats.next_due_ms, 315);
  zassert_equal(lichen_position_beacon_poll(314), LICHEN_POSITION_BEACON_IDLE);
  tx.ret = 0;
  zassert_equal(lichen_position_beacon_poll(315), LICHEN_POSITION_BEACON_SENT);
}

ZTEST(coap_location_beacon,
      test_default_transport_is_nonconfirmable_multicast_put) {
  struct lichen_position_beacon_config config = test_config();

  reset_state();
  config.tx_fn = NULL;
  config.tx_user_data = NULL;
  config.interface_index = 7U;
  zassert_ok(lichen_position_beacon_configure(&config, 0));
  zassert_equal(lichen_position_beacon_poll(0), LICHEN_POSITION_BEACON_SENT);
  zassert_equal(default_request_calls, 1U);
  zassert_equal(default_request.method, COAP_METHOD_PUT);
  zassert_false(default_request.confirmable);
  zassert_equal(default_request.content_format, SENML_CBOR_CONTENT_FORMAT);
  zassert_equal(default_request.addr.sin6_family, AF_INET6);
  zassert_equal(ntohs(default_request.addr.sin6_port), 5683U);
  zassert_equal(default_request.addr.sin6_scope_id, 7U);
  zassert_equal(default_request.addr.sin6_addr.s6_addr[0], 0xffU);
  zassert_equal(default_request.addr.sin6_addr.s6_addr[1], 0x02U);
  zassert_equal(default_request.addr.sin6_addr.s6_addr[15], 0x01U);
  zassert_str_equal(default_request.path[0], "pos");
  zassert_is_null(default_request.path[1]);
  zassert_equal(default_request.payload_len, 7U);
}

ZTEST(coap_location_beacon,
      test_invalid_configuration_and_deadline_saturation) {
  struct lichen_position_beacon_config config = test_config();
  struct lichen_position_beacon_stats stats;

  reset_state();
  zassert_equal(lichen_position_beacon_configure(&config, -1), -EINVAL);
  config.stationary_interval_ms = 59U;
  zassert_equal(lichen_position_beacon_configure(&config, 0), -EINVAL);
  config = test_config();
  config.stationary_threshold_cm = config.moving_threshold_cm;
  zassert_equal(lichen_position_beacon_configure(&config, 0), -EINVAL);
  config = test_config();
  zassert_ok(lichen_position_beacon_configure(&config, INT64_MAX - 1));
  zassert_equal(lichen_position_beacon_poll(INT64_MAX - 2), -ERANGE);
  zassert_equal(lichen_position_beacon_poll(INT64_MAX - 1),
                LICHEN_POSITION_BEACON_SENT);
  zassert_ok(lichen_position_beacon_get_stats(&stats));
  zassert_equal(stats.next_due_ms, INT64_MAX);
  zassert_equal(
      lichen_position_beacon_set_privacy((enum lichen_position_privacy_mode)99),
      -EINVAL);
  zassert_equal(lichen_position_beacon_get_stats(NULL), -EINVAL);
}

ZTEST(coap_location_beacon, test_cache_empty_age_and_atomic_bounds) {
  static const uint8_t empty_cache[] = {
      0xa1, 0x69, 'p', 'o', 's', 'i', 't', 'i', 'o', 'n', 's', 0x80,
  };
  static const uint8_t age_45[] = {
      0x65, 'a', 'g', 'e', '_', 's', 0x18, 0x2d,
  };
  struct lichen_position_cache_update update =
      cache_update(0x1111U, 1000, 1716742800U);
  uint8_t encoded[LICHEN_POSITION_CACHE_PAYLOAD_MAX];
  int len;
  bool found_age = false;

  reset_state();
  len = lichen_position_cache_encode(0, encoded, sizeof(encoded));
  zassert_equal(len, sizeof(empty_cache));
  zassert_mem_equal(encoded, empty_cache, sizeof(empty_cache));

  zassert_ok(lichen_position_cache_update(&update));
  len = lichen_position_cache_encode(46000, encoded, sizeof(encoded));
  zassert_true(len > (int)sizeof(empty_cache));
  zassert_equal(encoded[11], 0x81U);
  for (size_t i = 0; i + sizeof(age_45) <= (size_t)len; i++) {
    if (memcmp(&encoded[i], age_45, sizeof(age_45)) == 0) {
      found_age = true;
      break;
    }
  }
  zassert_true(found_age);
  zassert_equal(lichen_position_cache_encode(45999, encoded, sizeof(encoded)),
                -ERANGE);
  memset(encoded, 0xa5, sizeof(encoded));
  zassert_equal(lichen_position_cache_encode(46000, encoded, 1U), -ENOBUFS);
  zassert_equal(encoded[0], 0xa5U);
}

ZTEST(coap_location_beacon, test_cache_auth_privacy_and_replay) {
  struct lichen_position_cache_update update =
      cache_update(0x2222U, 1000, 100U);
  uint8_t encoded[LICHEN_POSITION_CACHE_PAYLOAD_MAX];

  reset_state();
  update.authenticated = false;
  zassert_equal(lichen_position_cache_update(&update), -EINVAL);
  update.authenticated = true;
  update.authenticated_node[15] ^= 1U;
  zassert_equal(lichen_position_cache_update(&update), -EINVAL);
  memcpy(update.authenticated_node, update.node, sizeof(update.node));
  update.privacy = LICHEN_POSITION_PRIVACY_PRIVATE;
  zassert_equal(lichen_position_cache_update(&update), -EINVAL);
  update.privacy = LICHEN_POSITION_PRIVACY_GROUP;
  zassert_equal(lichen_position_cache_update(&update), -EINVAL);
  update.provenance = LICHEN_POSITION_PROVENANCE_GROUP_OSCORE;
  zassert_ok(lichen_position_cache_update(&update));
  update.observed_monotonic_ms = 2000;
  zassert_equal(lichen_position_cache_update(&update), -EALREADY);

  zassert_ok(
      lichen_position_cache_set_privacy(LICHEN_POSITION_PRIVACY_PRIVATE));
  zassert_equal(lichen_position_cache_encode(2000, encoded, sizeof(encoded)),
                -EACCES);
  zassert_ok(
      lichen_position_cache_set_privacy(LICHEN_POSITION_PRIVACY_PUBLIC));
  zassert_true(lichen_position_cache_encode(2000, encoded, sizeof(encoded)) > 0);
  zassert_equal(encoded[11], 0x80U);
  update = cache_update(0x3333U, 2000, 101U);
  zassert_ok(lichen_position_cache_update(&update));
  zassert_true(lichen_position_cache_encode(2000, encoded, sizeof(encoded)) > 0);
  zassert_equal(encoded[11], 0x81U);
}

ZTEST(coap_location_beacon, test_cache_bound_eviction_and_expiry) {
  uint8_t encoded[LICHEN_POSITION_CACHE_PAYLOAD_MAX];
  int len;

  reset_state();
  for (uint16_t i = 1U; i <= 5U; i++) {
    struct lichen_position_cache_update update =
        cache_update(i, (int64_t)i * 1000, i);

    zassert_ok(lichen_position_cache_update(&update));
  }
  len = lichen_position_cache_encode(6000, encoded, sizeof(encoded));
  zassert_true(len > 12);
  zassert_equal(encoded[11], 0x84U);

  lichen_position_cache_reset();
  struct lichen_position_cache_update boundary =
      cache_update(6U, 5000, 6U);
  zassert_ok(lichen_position_cache_update(&boundary));
  zassert_equal(lichen_position_cache_purge(
                    5000 + LICHEN_POSITION_CACHE_EXPIRY_MS,
                    LICHEN_POSITION_CACHE_EXPIRY_MS),
                0U);
  zassert_equal(lichen_position_cache_purge(
                    5001 + LICHEN_POSITION_CACHE_EXPIRY_MS,
                    LICHEN_POSITION_CACHE_EXPIRY_MS),
                1U);
}

ZTEST(coap_location_beacon, test_cache_resource_response) {
  reset_state();
  zassert_ok(lichen_position_cache.get(&lichen_position_cache, NULL, NULL, 0));
  zassert_equal(response_code, COAP_RESPONSE_CODE_CONTENT);
  zassert_equal(response_format, 60U);
  zassert_true(response_payload_len > 0U);

  zassert_ok(
      lichen_position_cache_set_privacy(LICHEN_POSITION_PRIVACY_PRIVATE));
  zassert_ok(lichen_position_cache.get(&lichen_position_cache, NULL, NULL, 0));
  zassert_equal(response_code, COAP_RESPONSE_CODE_UNAUTHORIZED);
  zassert_equal(response_payload_len, 0U);
}

ZTEST(coap_location_beacon, test_observe_registry_cancel_and_sequence) {
  struct lichen_position_observe_stats stats;

  reset_state();
  zassert_ok(observe_request(1U, 0U));
  zassert_true(observe_initial);
  zassert_equal(observe_sequence, 2U);
  zassert_equal(observe_token_len, 1U);
  zassert_equal(observe_token[0], 1U);
  zassert_true(observe_payload_len > 0U);
  zassert_ok(observe_request(2U, 0U));
  zassert_ok(observe_request(3U, 0U));
  zassert_ok(lichen_position_observe_get_stats(&stats));
  zassert_equal(stats.observers, LICHEN_POSITION_OBSERVER_MAX);

  response_code = 0U;
  zassert_ok(observe_request(4U, 0U));
  zassert_equal(response_code, COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE);
  zassert_ok(lichen_position_observe_get_stats(&stats));
  zassert_equal(stats.observers, LICHEN_POSITION_OBSERVER_MAX);

  zassert_ok(observe_request(2U, 1U));
  zassert_ok(lichen_position_observe_get_stats(&stats));
  zassert_equal(stats.observers, LICHEN_POSITION_OBSERVER_MAX - 1U);
  response_code = 0U;
  zassert_ok(observe_request(5U, 2U));
  zassert_equal(response_code, COAP_RESPONSE_CODE_BAD_REQUEST);
}

ZTEST(coap_location_beacon, test_observe_change_triggers_and_wrap) {
  struct lichen_position_observe_stats stats;

  reset_state();
  zassert_ok(observe_request(1U, 0U));
  observe_tx_calls = 0U;
  snapshot.source_class_valid = true;
  snapshot.source_class = LICHEN_HAL_LOCATION_SOURCE_ONBOARD_HARDWARE;
  snapshot.fix_state_valid = true;
  snapshot.fix_state = LICHEN_HAL_LOCATION_FIX_3D;
  strcpy(snapshot.source_name, "gnss");

  zassert_equal(lichen_position_observe_poll(0),
                LICHEN_POSITION_OBSERVE_NOTIFIED);
  zassert_equal(observe_tx_calls, 1U);
  zassert_false(observe_initial);
  zassert_equal(observe_sequence, 3U);
  snapshot.latitude_e7 += 100;
  zassert_equal(lichen_position_observe_poll(1000),
                LICHEN_POSITION_OBSERVE_IDLE);
  zassert_equal(observe_tx_calls, 1U);

  strcpy(snapshot.source_name, "external-gnss");
  zassert_equal(lichen_position_observe_poll(2000),
                LICHEN_POSITION_OBSERVE_NOTIFIED);
  snapshot.latitude_e7 += 5000;
  zassert_equal(lichen_position_observe_poll(3000),
                LICHEN_POSITION_OBSERVE_NOTIFIED);
  snapshot.fix_state = LICHEN_HAL_LOCATION_FIX_STALE;
  zassert_equal(lichen_position_observe_poll(4000),
                LICHEN_POSITION_OBSERVE_NO_FIX);
  zassert_equal(observe_tx_calls, 3U);

  snapshot.fix_state = LICHEN_HAL_LOCATION_FIX_3D;
  snapshot.age_seconds_valid = true;
  snapshot.age_seconds = 1U;
  zassert_equal(lichen_position_observe_poll(5000),
                LICHEN_POSITION_OBSERVE_NOTIFIED);
  lichen_sensors_location.age = COAP_OBSERVE_MAX_AGE;
  strcpy(snapshot.source_name, "replacement-gnss");
  zassert_equal(lichen_position_observe_poll(6000),
                LICHEN_POSITION_OBSERVE_NOTIFIED);
  zassert_equal(observe_sequence, 2U);
  zassert_equal(lichen_position_observe_poll(
                    6000 + LICHEN_POSITION_OBSERVE_INTERVAL_MS),
                LICHEN_POSITION_OBSERVE_NOTIFIED);
  zassert_equal(observe_sequence, 3U);
  zassert_ok(lichen_position_observe_get_stats(&stats));
  zassert_equal(stats.sequence, 3U);
  zassert_equal(stats.notifications, 6U);
}

ZTEST(coap_location_beacon, test_observe_backpressure_retry_and_drop) {
  struct lichen_position_observe_stats stats;

  reset_state();
  zassert_ok(observe_request(1U, 0U));
  observe_tx_calls = 0U;
  observe_tx_ret = -ENOBUFS;
  zassert_equal(lichen_position_observe_poll(0),
                LICHEN_POSITION_OBSERVE_NOTIFIED);
  zassert_equal(observe_tx_calls, 1U);
  zassert_equal(lichen_position_observe_poll(4999),
                LICHEN_POSITION_OBSERVE_IDLE);
  zassert_equal(observe_tx_calls, 1U);
  zassert_equal(lichen_position_observe_poll(5000),
                LICHEN_POSITION_OBSERVE_IDLE);
  zassert_equal(lichen_position_observe_poll(10000),
                LICHEN_POSITION_OBSERVE_IDLE);
  zassert_equal(lichen_position_observe_poll(15000),
                LICHEN_POSITION_OBSERVE_IDLE);
  zassert_equal(observe_tx_calls, 4U);
  zassert_ok(lichen_position_observe_get_stats(&stats));
  zassert_equal(stats.backpressure, 4U);
  zassert_equal(stats.failures, 1U);
  zassert_equal(stats.observers, 0U);
}

ZTEST(coap_location_beacon, test_observe_privacy_cancels_and_suppresses) {
  struct lichen_position_beacon_config config = test_config();
  struct lichen_position_observe_stats stats;

  reset_state();
  zassert_ok(lichen_position_beacon_configure(&config, 0));
  zassert_ok(observe_request(1U, 0U));
  zassert_ok(lichen_position_beacon_set_privacy(
      LICHEN_POSITION_PRIVACY_PRIVATE));
  zassert_ok(lichen_position_observe_get_stats(&stats));
  zassert_equal(stats.observers, 0U);
  observe_tx_calls = 0U;
  zassert_equal(lichen_position_observe_poll(0),
                LICHEN_POSITION_OBSERVE_SUPPRESSED);
  zassert_equal(observe_tx_calls, 0U);
}

ZTEST_SUITE(coap_location_beacon, NULL, NULL, NULL, NULL, NULL);
