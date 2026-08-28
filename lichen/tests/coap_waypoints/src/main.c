/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/ztest.h>

#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>
#include <lichen/coap_waypoints.h>

static uint16_t coap_port = 5683U;
COAP_SERVICE_DEFINE(lichen_coap_server, NULL, &coap_port, 0);

static const uint8_t minimal_vector[] = {
    0xa6, 0x62, 0x69, 0x64, 0x67, 0x77, 0x70, 0x74, 0x2d, 0x30, 0x30, 0x31,
    0x64, 0x6e, 0x61, 0x6d, 0x65, 0x71, 0x52, 0x61, 0x6c, 0x6c, 0x79, 0x20,
    0x50, 0x6f, 0x69, 0x6e, 0x74, 0x20, 0x41, 0x6c, 0x70, 0x68, 0x61, 0x63,
    0x6c, 0x61, 0x74, 0xfb, 0x40, 0x42, 0xe3, 0x30, 0xdf, 0x9b, 0xdc, 0x6a,
    0x63, 0x6c, 0x6f, 0x6e, 0xfb, 0xc0, 0x5e, 0x9a, 0xd7, 0xb6, 0x34, 0xda,
    0xd3, 0x67, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x1a, 0x66, 0x53,
    0x6a, 0x90, 0x67, 0x63, 0x72, 0x65, 0x61, 0x74, 0x6f, 0x72, 0x6a, 0x30,
    0x32, 0x30, 0x30, 0x3a, 0x3a, 0x31, 0x31, 0x31, 0x31,
};

static const uint8_t all_fields_vector[] = {
    0xab, 0x62, 0x69, 0x64, 0x67, 0x77, 0x70, 0x74, 0x2d, 0x30, 0x30, 0x32,
    0x64, 0x6e, 0x61, 0x6d, 0x65, 0x6c, 0x57, 0x61, 0x74, 0x65, 0x72, 0x20,
    0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x63, 0x6c, 0x61, 0x74, 0xfb, 0x40,
    0x42, 0xe3, 0xd7, 0x0a, 0x3d, 0x70, 0xa4, 0x63, 0x6c, 0x6f, 0x6e, 0xfb,
    0xc0, 0x5e, 0x9a, 0xe1, 0x47, 0xae, 0x14, 0x7b, 0x63, 0x61, 0x6c, 0x74,
    0xfb, 0x40, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x69, 0x63,
    0x6f, 0x6e, 0x65, 0x77, 0x61, 0x74, 0x65, 0x72, 0x65, 0x63, 0x6f, 0x6c,
    0x6f, 0x72, 0x67, 0x23, 0x30, 0x30, 0x30, 0x30, 0x46, 0x46, 0x65, 0x6e,
    0x6f, 0x74, 0x65, 0x73, 0x77, 0x50, 0x6f, 0x74, 0x61, 0x62, 0x6c, 0x65,
    0x20, 0x77, 0x61, 0x74, 0x65, 0x72, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6c,
    0x61, 0x62, 0x6c, 0x65, 0x67, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
    0x1a, 0x66, 0x53, 0x6a, 0x90, 0x67, 0x63, 0x72, 0x65, 0x61, 0x74, 0x6f,
    0x72, 0x6a, 0x30, 0x32, 0x30, 0x30, 0x3a, 0x3a, 0x32, 0x32, 0x32, 0x32,
    0x67, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x1a, 0x66, 0x54, 0xbc,
    0x10,
};

struct waypoint_wire_vector {
  const char *name;
  const uint8_t *wire;
  size_t wire_len;
};

#include "waypoint_vectors.inc"

static struct lichen_waypoint_store_image persisted;
static bool persisted_valid;
static bool save_fails;
static bool local_admin;
static bool protected_request;
static const uint8_t *request_payload;
static size_t request_payload_len;
static uint8_t response_code;
static uint8_t response_payload[1024];
static size_t response_payload_len;
static uint64_t test_now = 1716742800U;
static uint8_t last_expected_method;

static int save_image(const struct lichen_waypoint_store_image *image) {
  if (save_fails) {
    return -EIO;
  }
  persisted = *image;
  persisted_valid = true;
  return 0;
}

static int load_image(struct lichen_waypoint_store_image *image) {
  if (!persisted_valid) {
    return -ENOENT;
  }
  *image = persisted;
  return 0;
}

static uint64_t now_seconds(void) { return test_now; }

static void init_store(void) {
  const struct lichen_waypoint_config config = {
      .local_creator = "0200::local",
      .now = now_seconds,
      .load = load_image,
      .save = save_image,
  };

  persisted_valid = false;
  save_fails = false;
  local_admin = true;
  protected_request = false;
  request_payload = NULL;
  request_payload_len = 0U;
  response_code = 0U;
  response_payload_len = 0U;
  last_expected_method = 0U;
  zassert_ok(lichen_waypoints_init(&config));
}

static struct lichen_waypoint candidate(const char *name, double lat,
                                        double lon) {
  struct lichen_waypoint value = {.lat = lat, .lon = lon};

  strncpy(value.name, name, sizeof(value.name) - 1U);
  return value;
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
  response_code = code;
  response_payload_len = payload_len;
  if (payload_len > 0U) {
    zassert_true(payload_len <= sizeof(response_payload));
    memcpy(response_payload, payload, payload_len);
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
  last_expected_method = expected_method;
  memset(result, 0, sizeof(*result));
  result->is_protected = protected_request;
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

ZTEST(coap_waypoints, test_shared_vector_exact_and_strict_decode) {
  struct lichen_waypoint waypoint;
  struct lichen_waypoint unchanged = {.lat = 77.0};
  uint8_t encoded[256];
  int len;

  zassert_ok(lichen_waypoint_decode(minimal_vector, sizeof(minimal_vector),
                                    &waypoint));
  zassert_equal(strcmp(waypoint.id, "wpt-001"), 0);
  zassert_equal(strcmp(waypoint.creator, "0200::1111"), 0);
  len = lichen_waypoint_encode(&waypoint, encoded, sizeof(encoded));
  zassert_equal(len, sizeof(minimal_vector));
  zassert_mem_equal(encoded, minimal_vector, sizeof(minimal_vector));
  zassert_ok(lichen_waypoint_decode(all_fields_vector,
                                    sizeof(all_fields_vector), &waypoint));
  zassert_true(waypoint.has_alt && waypoint.has_icon && waypoint.has_color &&
               waypoint.has_notes && waypoint.has_expires);
  len = lichen_waypoint_encode(&waypoint, encoded, sizeof(encoded));
  zassert_equal(len, sizeof(all_fields_vector));
  zassert_mem_equal(encoded, all_fields_vector, sizeof(all_fields_vector));
  zassert_equal(lichen_waypoint_decode(minimal_vector,
                                       sizeof(minimal_vector) - 1U, &unchanged),
                -EBADMSG);
  zassert_equal(unchanged.lat, 77.0, "decode must be atomic");
  memcpy(encoded, minimal_vector, sizeof(minimal_vector));
  encoded[3] = 'x';
  zassert_equal(
      lichen_waypoint_decode(encoded, sizeof(minimal_vector), &unchanged),
      -EBADMSG, "unknown keys must be rejected");
  encoded[0] = 0x55;
  zassert_equal(lichen_waypoint_encode(&waypoint, encoded, 8U), -ENOBUFS);
  zassert_equal(encoded[0], 0x55, "encode must be atomic");
}

ZTEST(coap_waypoints, test_all_shared_vectors_round_trip_byte_exactly) {
  uint8_t encoded[512];

  for (size_t i = 0U; i < ARRAY_SIZE(waypoint_valid_vectors); i++) {
    const struct waypoint_wire_vector *vector = &waypoint_valid_vectors[i];
    struct lichen_waypoint waypoint;
    int len;

    zassert_ok(lichen_waypoint_decode(vector->wire, vector->wire_len, &waypoint),
               "%s: decode", vector->name);
    len = lichen_waypoint_encode(&waypoint, encoded, sizeof(encoded));
    zassert_equal(len, vector->wire_len, "%s: encoded length", vector->name);
    zassert_mem_equal(encoded, vector->wire, vector->wire_len,
                      "%s: encoded bytes", vector->name);
  }

  for (size_t i = 0U; i < ARRAY_SIZE(waypoint_reject_vectors); i++) {
    const struct waypoint_wire_vector *vector = &waypoint_reject_vectors[i];
    struct lichen_waypoint unchanged = {.lat = 77.0, .version = 42U};

    zassert_equal(lichen_waypoint_decode(vector->wire, vector->wire_len,
                                         &unchanged),
                  -EBADMSG, "%s: reject", vector->name);
    zassert_equal(unchanged.lat, 77.0, "%s: atomic latitude", vector->name);
    zassert_equal(unchanged.version, 42U, "%s: atomic version", vector->name);
  }
}

ZTEST(coap_waypoints, test_transactional_crud_auth_and_capacity) {
  struct lichen_waypoint made;
  struct lichen_waypoint value;
  struct lichen_waypoint replacement;

  init_store();
  value = candidate("alpha", 90.0, -180.0);
  zassert_ok(lichen_waypoints_create(&value, &made));
  zassert_equal(strcmp(made.id, "wpt-001"), 0);
  zassert_equal(strcmp(made.creator, "0200::local"), 0);
  zassert_equal(made.created, test_now);
  value = candidate("duplicate", 1.0, 2.0);
  strncpy(value.id, made.id, sizeof(value.id) - 1U);
  zassert_equal(lichen_waypoints_create(&value, &replacement), -EEXIST);
  replacement = candidate("updated", -90.0, 180.0);
  zassert_equal(
      lichen_waypoints_update(made.id, &replacement, "0200::forged", false),
      -EACCES);
  zassert_ok(
      lichen_waypoints_update(made.id, &replacement, "0200::local", false));
  zassert_ok(lichen_waypoints_find(made.id, &value));
  zassert_equal(value.version, 2U);
  zassert_equal(strcmp(value.name, "updated"), 0);

  save_fails = true;
  replacement = candidate("not-committed", 1.0, 2.0);
  zassert_equal(
      lichen_waypoints_update(made.id, &replacement, "0200::local", false),
      -EIO);
  zassert_ok(lichen_waypoints_find(made.id, &value));
  zassert_equal(strcmp(value.name, "updated"), 0);
  zassert_equal(lichen_waypoints_delete(made.id, "0200::local", false), -EIO);
  zassert_equal(lichen_waypoints_count(), 1U);
  save_fails = false;
  zassert_ok(lichen_waypoints_delete(made.id, "0200::local", false));

  for (size_t i = 0U; i < LICHEN_WAYPOINT_MAX; i++) {
    char name[16];
    snprintk(name, sizeof(name), "point-%u", (unsigned int)i);
    value = candidate(name, 0.0, 0.0);
    zassert_ok(lichen_waypoints_create(&value, &made));
  }
  value = candidate("overflow", 0.0, 0.0);
  zassert_equal(lichen_waypoints_create(&value, &made), -ENOSPC);
}

ZTEST(coap_waypoints, test_reboot_and_corruption_are_atomic) {
  const struct lichen_waypoint_config config = {
      .local_creator = "0200::local",
      .now = now_seconds,
      .load = load_image,
      .save = save_image,
  };
  struct lichen_waypoint value = candidate("persisted", 1.0, 2.0);
  struct lichen_waypoint made;

  init_store();
  zassert_ok(lichen_waypoints_create(&value, &made));
  zassert_ok(lichen_waypoints_init(&config));
  zassert_equal(lichen_waypoints_count(), 1U);
  persisted.entries[1] = persisted.entries[0];
  persisted.count = 2U;
  zassert_equal(lichen_waypoints_init(&config), -EBADMSG);
  zassert_equal(lichen_waypoints_count(), 1U,
                "failed load must leave live store intact");
}

ZTEST(coap_waypoints, test_validation_and_handler_policy) {
  struct coap_resource resource = {0};
  struct coap_packet request = {0};
  struct sockaddr_in6 peer = {.sin6_family = AF_INET6};
  struct lichen_waypoint value = candidate("bad", 91.0, 0.0);
  struct lichen_waypoint made;
  uint8_t expected_collection[sizeof(minimal_vector) + 12U] = {
      0xa1, 0x69, 'w', 'a', 'y', 'p', 'o', 'i', 'n', 't', 's', 0x81,
  };
  uint8_t packet_buf[256];

  init_store();
  zassert_equal(lichen_waypoints_create(&value, &made), -EINVAL);
  value = candidate("bad", 0.0, 181.0);
  zassert_equal(lichen_waypoints_create(&value, &made), -EINVAL);
  memcpy(peer.sin6_addr.s6_addr,
         (uint8_t[]){0xfe, 0x80, 0, 0, 0, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7},
         16U);
  request_payload = minimal_vector;
  request_payload_len = sizeof(minimal_vector);
  local_admin = false;
  protected_request = false;
  zassert_ok(lichen_waypoints_post_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_UNAUTHORIZED);
  protected_request = true;
  zassert_ok(lichen_waypoints_post_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_FORBIDDEN,
                "remote peer must not forge creator");

  /* Local LCI may import an explicitly attributed shared waypoint. */
  local_admin = true;
  protected_request = false;
  zassert_ok(coap_packet_init(&request, packet_buf, sizeof(packet_buf),
                              COAP_VERSION_1, COAP_TYPE_CON, 0, NULL,
                              COAP_METHOD_POST, 123U));
  /* The isolated resource is not registered with a live server, so the final
   * send may report no endpoint.  The transaction itself must still commit. */
  (void)lichen_waypoints_post_handler(&resource, &request,
                                      (struct sockaddr *)&peer, sizeof(peer));
  zassert_equal(lichen_waypoints_count(), 1U);

  memset(&request, 0, sizeof(request));
  zassert_ok(lichen_waypoints_get_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_CONTENT);
  memcpy(&expected_collection[12], minimal_vector, sizeof(minimal_vector));
  zassert_equal(response_payload_len, sizeof(expected_collection));
  zassert_mem_equal(response_payload, expected_collection,
                    sizeof(expected_collection));
}

ZTEST(coap_waypoints, test_receive_authenticated_shared_waypoint) {
  struct coap_resource resource = {0};
  struct coap_packet request;
  struct sockaddr_in6 peer = {.sin6_family = AF_INET6};
  struct lichen_waypoint stored;
  uint8_t packet_buf[256];

  /* The canonical minimal vector names 0200::1111 as its creator.  Bind the
   * authenticated request to that same IPv6 source so the receiver can retain
   * the origin without accepting a forged creator claim. */
  memcpy(
      peer.sin6_addr.s6_addr,
      (uint8_t[]){0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11},
      16U);
  init_store();
  local_admin = false;
  protected_request = true;
  request_payload = minimal_vector;
  request_payload_len = sizeof(minimal_vector);
  zassert_ok(coap_packet_init(&request, packet_buf, sizeof(packet_buf),
                              COAP_VERSION_1, COAP_TYPE_CON, 0, NULL,
                              COAP_METHOD_POST, 124U));

  /* The isolated resource has no live endpoint, so sending the 2.01 may fail
   * after the durable transaction.  Receipt and storage are the behavior
   * under test here. */
  (void)lichen_waypoints_post_handler(&resource, &request,
                                      (struct sockaddr *)&peer, sizeof(peer));
  zassert_equal(last_expected_method, COAP_METHOD_POST);
  zassert_equal(lichen_waypoints_count(), 1U);
  zassert_ok(lichen_waypoints_find("wpt-001", &stored));
  zassert_equal(strcmp(stored.name, "Rally Point Alpha"), 0);
  zassert_equal(strcmp(stored.creator, "0200::1111"), 0);
  zassert_equal(stored.created, 1716742800U);
  zassert_true(persisted_valid, "accepted share must be durable before reply");
  zassert_equal(persisted.count, 1U);

  /* Replaying the same semantic create cannot duplicate or mutate the store. */
  zassert_ok(lichen_waypoints_post_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_CONFLICT);
  zassert_equal(lichen_waypoints_count(), 1U);
  zassert_equal(persisted.count, 1U);
}

static void make_detail_request(struct coap_packet *request, uint8_t *buf,
                                size_t size, uint8_t method, const char *id,
                                bool trailing) {
  zassert_ok(coap_packet_init(request, buf, size, COAP_VERSION_1, COAP_TYPE_CON,
                              0, NULL, method, 321U));
  zassert_ok(coap_packet_append_option(request, COAP_OPTION_URI_PATH,
                                       "waypoints", 9U));
  zassert_ok(
      coap_packet_append_option(request, COAP_OPTION_URI_PATH, id, strlen(id)));
  if (trailing) {
    zassert_ok(
        coap_packet_append_option(request, COAP_OPTION_URI_PATH, "x", 1U));
  }
  request->max_len = request->offset;
}

ZTEST(coap_waypoints, test_detail_get_is_vector_exact_and_routes_strictly) {
  static const char *const aliases[] = {"wpt-1",    "wpt-01",   "wpt-000",
                                        "wpt-0001", "+wpt-001", "wpt-001-"};
  struct coap_resource resource = {0};
  struct coap_packet request;
  struct sockaddr_in6 peer = {.sin6_family = AF_INET6};
  struct lichen_waypoint waypoint;
  struct lichen_waypoint created;
  uint8_t packet_buf[256];

  init_store();
  zassert_ok(lichen_waypoint_decode(minimal_vector, sizeof(minimal_vector),
                                    &waypoint));
  zassert_ok(lichen_waypoints_create(&waypoint, &created));
  local_admin = false;
  protected_request = false;
  make_detail_request(&request, packet_buf, sizeof(packet_buf), COAP_METHOD_GET,
                      "wpt-001", false);
  zassert_ok(lichen_waypoint_detail_get_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(last_expected_method, COAP_METHOD_GET);
  zassert_equal(response_code, COAP_RESPONSE_CODE_CONTENT);
  zassert_equal(response_payload_len, sizeof(minimal_vector));
  zassert_mem_equal(response_payload, minimal_vector, sizeof(minimal_vector));

  for (size_t i = 0U; i < ARRAY_SIZE(aliases); i++) {
    make_detail_request(&request, packet_buf, sizeof(packet_buf),
                        COAP_METHOD_GET, aliases[i], false);
    zassert_ok(lichen_waypoint_detail_get_handler(
        &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
    zassert_equal(response_code, COAP_RESPONSE_CODE_NOT_FOUND,
                  "noncanonical alias accepted: %s", aliases[i]);
  }
  make_detail_request(&request, packet_buf, sizeof(packet_buf), COAP_METHOD_GET,
                      "wpt-001", true);
  zassert_ok(lichen_waypoint_detail_get_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_NOT_FOUND);
}

ZTEST(coap_waypoints, test_detail_delete_auth_rollback_and_idempotence) {
  struct coap_resource resource = {0};
  struct coap_packet request;
  struct sockaddr_in6 peer = {.sin6_family = AF_INET6};
  struct lichen_waypoint waypoint;
  struct lichen_waypoint created;
  uint8_t packet_buf[256];

  memcpy(peer.sin6_addr.s6_addr,
         (uint8_t[]){0xfe, 0x80, 0, 0, 0, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7},
         16U);
  init_store();
  zassert_ok(lichen_waypoint_decode(minimal_vector, sizeof(minimal_vector),
                                    &waypoint));
  zassert_ok(lichen_waypoints_create(&waypoint, &created));
  make_detail_request(&request, packet_buf, sizeof(packet_buf),
                      COAP_METHOD_DELETE, "wpt-001", false);

  local_admin = false;
  protected_request = false;
  zassert_ok(lichen_waypoint_detail_delete_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_UNAUTHORIZED);
  zassert_equal(lichen_waypoints_count(), 1U);

  protected_request = true;
  zassert_ok(lichen_waypoint_detail_delete_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_FORBIDDEN);
  zassert_equal(lichen_waypoints_count(), 1U);

  local_admin = true;
  protected_request = false;
  save_fails = true;
  zassert_ok(lichen_waypoint_detail_delete_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE);
  zassert_equal(lichen_waypoints_count(), 1U, "failed save mutated store");
  save_fails = false;
  zassert_ok(lichen_waypoint_detail_delete_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_DELETED);
  zassert_equal(lichen_waypoints_count(), 0U);
  zassert_ok(lichen_waypoint_detail_delete_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_NOT_FOUND,
                "repeat delete must retain the absent state");

  init_store();
  waypoint = candidate("peer-owned", 1.0, 2.0);
  strcpy(waypoint.id, "wpt-001");
  strcpy(waypoint.creator, "fe80::201:203:405:607");
  zassert_ok(lichen_waypoints_create(&waypoint, &created));
  make_detail_request(&request, packet_buf, sizeof(packet_buf),
                      COAP_METHOD_DELETE, "wpt-001", false);
  local_admin = false;
  protected_request = true;
  zassert_ok(lichen_waypoint_detail_delete_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(response_code, COAP_RESPONSE_CODE_DELETED,
                "authenticated creator must be allowed to delete");
}

ZTEST(coap_waypoints, test_detail_put_is_explicitly_not_allowed) {
  struct coap_resource resource = {0};
  struct coap_packet request;
  struct sockaddr_in6 peer = {.sin6_family = AF_INET6};
  uint8_t packet_buf[256];

  init_store();
  make_detail_request(&request, packet_buf, sizeof(packet_buf), COAP_METHOD_PUT,
                      "wpt-001", false);
  zassert_ok(lichen_waypoint_detail_put_handler(
      &resource, &request, (struct sockaddr *)&peer, sizeof(peer)));
  zassert_equal(last_expected_method, COAP_METHOD_PUT);
  zassert_equal(response_code, COAP_RESPONSE_CODE_NOT_ALLOWED);
}

static void *suite_setup(void) {
  init_store();
  return NULL;
}

ZTEST_SUITE(coap_waypoints, NULL, suite_setup, NULL, NULL, NULL);
