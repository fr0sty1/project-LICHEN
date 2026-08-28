/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/ztest.h>

#include <zcbor_decode.h>

#include <lichen/coap_config.h>
#include <lichen/coap_keys.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>

#define TEST_CBOR_MAX_SIZE 256U

extern struct coap_resource lichen_config;
extern struct coap_resource lichen_config_radio;
extern struct coap_resource lichen_config_identity;

static struct lichen_config_node test_node;
static struct lichen_config_radio test_radio;
static struct lichen_config_identity test_identity;
static int node_get_result;
static int node_set_result;
static int radio_get_result;
static int radio_set_result;
static int identity_get_result;
static int fingerprint_result;
static unsigned int node_get_calls;
static unsigned int node_set_calls;
static unsigned int radio_get_calls;
static unsigned int radio_set_calls;
static unsigned int identity_get_calls;
static unsigned int fingerprint_calls;
static unsigned int admin_calls;
static unsigned int oscore_calls;
static bool mutate_after_get;
static bool mutate_radio_after_get;
static bool mutate_identity_after_get;
static bool fingerprint_malformed;
static bool admin_result;
static bool request_is_protected;
static int oscore_result;
static const uint8_t *request_payload;
static size_t request_payload_len;

static struct {
  uint8_t code;
  uint16_t content_format;
  uint8_t payload[TEST_CBOR_MAX_SIZE];
  size_t payload_len;
} response;

static int test_node_get(struct lichen_config_node *config) {
  node_get_calls++;
  if (node_get_result < 0) {
    return node_get_result;
  }
  *config = test_node;
  if (mutate_after_get) {
    /* A later provider change must not alter this response snapshot. */
    (void)strcpy(test_node.name, "changed-after-snapshot");
    test_node.role = LICHEN_CONFIG_ROLE_LEAF;
  }
  return 0;
}

static int test_node_set(const struct lichen_config_node *config) {
  node_set_calls++;
  if (node_set_result < 0) {
    return node_set_result;
  }
  test_node = *config;
  return 0;
}

static int test_radio_get(struct lichen_config_radio *config) {
  radio_get_calls++;
  if (radio_get_result < 0) {
    return radio_get_result;
  }
  *config = test_radio;
  if (mutate_radio_after_get) {
    memset(&test_radio, 0, sizeof(test_radio));
  }
  return 0;
}

static int test_radio_set(const struct lichen_config_radio *config) {
  radio_set_calls++;
  if (radio_set_result < 0) {
    return radio_set_result;
  }
  test_radio = *config;
  return 0;
}

static int test_identity_get(struct lichen_config_identity *identity) {
  identity_get_calls++;
  if (identity_get_result < 0) {
    return identity_get_result;
  }
  *identity = test_identity;
  if (mutate_identity_after_get) {
    memset(&test_identity, 0xa5, sizeof(test_identity));
  }
  return 0;
}

static const struct lichen_config_provider provider = {
    .node_get = test_node_get,
    .node_set = test_node_set,
    .radio_get = test_radio_get,
    .radio_set = test_radio_set,
    .identity_get = test_identity_get,
};

static const struct lichen_config_provider missing_get_provider;

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

bool lichen_coap_is_local_admin(const struct sockaddr *addr,
                                socklen_t addr_len) {
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  admin_calls++;
  return admin_result;
}

int coap_oscore_unprotect_resource_request(
    struct coap_resource *resource, struct coap_packet *request,
    struct sockaddr *addr, socklen_t addr_len, uint8_t expected_method,
    struct coap_oscore_unprotect_result *result) {
  ARG_UNUSED(resource);
  ARG_UNUSED(request);
  ARG_UNUSED(addr);
  ARG_UNUSED(addr_len);
  oscore_calls++;
  zassert_equal(expected_method, COAP_METHOD_PUT);
  if (oscore_result != 0) {
    return oscore_result;
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
    const struct coap_oscore_unprotect_result *result, uint8_t resp_code,
    uint16_t content_format, const uint8_t *payload, size_t payload_len) {
  ARG_UNUSED(result);
  return lichen_coap_respond(resource, request, addr, addr_len, resp_code,
                             content_format, payload, payload_len);
}

int lichen_key_pubkey_fingerprint(const uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN],
                                  char *out, size_t out_len) {
  ARG_UNUSED(pubkey);
  static const char fingerprint[] =
      "SHA256:Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw=";

  fingerprint_calls++;
  if (fingerprint_result < 0) {
    return fingerprint_result;
  }
  if (out == NULL || out_len < sizeof(fingerprint)) {
    return -ENOMEM;
  }
  memcpy(out, fingerprint, sizeof(fingerprint));
  if (fingerprint_malformed) {
    out[sizeof(fingerprint) - 2U] = '!';
  }
  return (int)(sizeof(fingerprint) - 1U);
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

static void
assert_identity_encoding(const struct lichen_config_identity *identity,
                         const char *expected_hex) {
  uint8_t expected[TEST_CBOR_MAX_SIZE];
  uint8_t encoded[TEST_CBOR_MAX_SIZE];
  size_t expected_len = decode_hex(expected_hex, expected, sizeof(expected));
  size_t encoded_len =
      lichen_config_encode_identity_cbor(encoded, sizeof(encoded), identity);

  zassert_true(expected_len > 0U, "invalid test vector");
  zassert_equal(encoded_len, expected_len, "actual %zu expected %zu",
                encoded_len, expected_len);
  zassert_mem_equal(encoded, expected, expected_len,
                    "identity output differs from shared vector");
}

static bool decode_node_payload(struct lichen_config_node *node, char radio[20],
                                char identity[24]) {
  ZCBOR_STATE_D(state, 2, response.payload, response.payload_len, 1, 0);
  bool have_name = false;
  bool have_role = false;
  bool have_radio = false;
  bool have_identity = false;

  if (!zcbor_map_start_decode(state)) {
    return false;
  }
  while (!zcbor_array_at_end(state)) {
    struct zcbor_string key;
    struct zcbor_string value;

    if (!zcbor_tstr_decode(state, &key) || !zcbor_tstr_decode(state, &value)) {
      return false;
    }
    if (key.len == 4U && memcmp(key.value, "name", 4U) == 0) {
      if (value.len >= sizeof(node->name)) {
        return false;
      }
      memcpy(node->name, value.value, value.len);
      node->name[value.len] = '\0';
      have_name = true;
    } else if (key.len == 4U && memcmp(key.value, "role", 4U) == 0) {
      if (value.len == 6U && memcmp(value.value, "router", 6U) == 0) {
        node->role = LICHEN_CONFIG_ROLE_ROUTER;
      } else {
        return false;
      }
      have_role = true;
    } else if (key.len == 5U && memcmp(key.value, "radio", 5U) == 0) {
      if (value.len >= 20U) {
        return false;
      }
      memcpy(radio, value.value, value.len);
      radio[value.len] = '\0';
      have_radio = true;
    } else if (key.len == 8U && memcmp(key.value, "identity", 8U) == 0) {
      if (value.len >= 24U) {
        return false;
      }
      memcpy(identity, value.value, value.len);
      identity[value.len] = '\0';
      have_identity = true;
    } else {
      return false;
    }
  }
  return zcbor_map_end_decode(state) && have_name && have_role && have_radio &&
         have_identity;
}

static void before(void *fixture) {
  ARG_UNUSED(fixture);
  memset(&response, 0, sizeof(response));
  memset(&test_node, 0, sizeof(test_node));
  memset(&test_radio, 0, sizeof(test_radio));
  memset(&test_identity, 0, sizeof(test_identity));
  (void)strcpy(test_node.name, "my-node");
  test_node.role = LICHEN_CONFIG_ROLE_ROUTER;
  test_radio.freq_khz = 906875U;
  test_radio.bw_khz = 125U;
  test_radio.sf = 9U;
  test_radio.cr = LICHEN_CONFIG_CR_4_5;
  test_radio.tx_power_dbm = 20;
  test_radio.sync_word = 0x34U;
  static const uint8_t pubkey[] = {
      0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe, 0x1d, 0x70, 0xdd,
      0x18, 0xe7, 0x4b, 0xc0, 0x99, 0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5,
      0x0d, 0x5f, 0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
  };
  static const uint8_t eui64[] = {0x00, 0x11, 0x22, 0x33,
                                  0x44, 0x55, 0x66, 0x77};
  memcpy(test_identity.eui64, eui64, sizeof(eui64));
  test_identity.eui64_valid = true;
  memcpy(test_identity.pubkey, pubkey, sizeof(pubkey));
  test_identity.pubkey_valid = true;
  (void)strcpy(test_identity.link_local, "fe80::ed42:42ea:d4ac:6948");
  (void)strcpy(test_identity.primary, "2ed:4242:ead4:ac69:ed42:42ea:d4ac:6948");
  node_get_result = 0;
  node_set_result = 0;
  radio_get_result = 0;
  radio_set_result = 0;
  identity_get_result = 0;
  fingerprint_result = 0;
  node_get_calls = 0U;
  node_set_calls = 0U;
  radio_get_calls = 0U;
  radio_set_calls = 0U;
  identity_get_calls = 0U;
  fingerprint_calls = 0U;
  admin_calls = 0U;
  oscore_calls = 0U;
  mutate_after_get = false;
  mutate_radio_after_get = false;
  mutate_identity_after_get = false;
  fingerprint_malformed = false;
  admin_result = false;
  request_is_protected = false;
  oscore_result = 0;
  request_payload = NULL;
  request_payload_len = 0U;
}

ZTEST_SUITE(coap_config, NULL, NULL, before, NULL, NULL);

ZTEST(coap_config, test_get_returns_complete_public_snapshot) {
  struct lichen_config_node decoded = {0};
  struct coap_packet request = {0};
  struct sockaddr addr = {0};
  char radio[20] = {0};
  char identity[24] = {0};

  zassert_ok(lichen_coap_config_register(&provider));
  mutate_after_get = true;
  zassert_not_null(lichen_config.get, "GET handler missing");
  zassert_equal(strcmp(lichen_config.path[0], "config"), 0,
                "wrong resource path");
  zassert_is_null(lichen_config.path[1], "resource path must be exact");
  zassert_ok(lichen_config.get(&lichen_config, &request, &addr, sizeof(addr)));

  zassert_equal(node_get_calls, 1U, "provider snapshot must be read once");
  zassert_equal(response.code, COAP_RESPONSE_CODE_CONTENT);
  zassert_equal(response.content_format, 60U, "application/cbor is ct=60");
  zassert_true(response.payload_len > 0U &&
                   response.payload_len <= TEST_CBOR_MAX_SIZE,
               "bounded response payload");
  zassert_true(decode_node_payload(&decoded, radio, identity),
               "response schema must contain exactly the four LCI fields");
  zassert_equal(strcmp(decoded.name, "my-node"), 0,
                "snapshot changed during encoding");
  zassert_equal(decoded.role, LICHEN_CONFIG_ROLE_ROUTER);
  zassert_equal(strcmp(radio, "/config/radio"), 0);
  zassert_equal(strcmp(identity, "/config/identity"), 0);
  zassert_equal(admin_calls, 0U, "non-sensitive GET must be public");
  zassert_equal(oscore_calls, 0U, "public GET must not require OSCORE");
}

ZTEST(coap_config, test_get_error_mapping) {
  struct coap_packet request = {0};
  struct sockaddr addr = {0};

  zassert_ok(lichen_coap_config_register(&missing_get_provider));
  zassert_ok(lichen_config.get(&lichen_config, &request, &addr, sizeof(addr)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_NOT_FOUND);
  zassert_equal(response.payload_len, 0U);

  memset(&response, 0, sizeof(response));
  node_get_result = -EIO;
  zassert_ok(lichen_coap_config_register(&provider));
  zassert_ok(lichen_config.get(&lichen_config, &request, &addr, sizeof(addr)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR);
  zassert_equal(response.payload_len, 0U);
}

static int invoke_identity_get(void) {
  struct coap_packet request = {0};
  struct sockaddr addr = {0};

  zassert_not_null(lichen_config_identity.get, "identity GET handler missing");
  return lichen_config_identity.get(&lichen_config_identity, &request, &addr,
                                    sizeof(addr));
}

ZTEST(coap_config, test_identity_get_emits_exact_public_snapshot) {
  static const char expected_hex[] =
      "a465657569363472307830303131323233333434353536363737667075626b6579"
      "784030336131303762666633636531306265316437306464313865373462633039"
      "393637653464363330396261353064356631646463383636343132353533316238"
      "727075626b65795f66696e6765727072696e74775348413235363a353634373561"
      "61373534363334373463656164647273a26a6c696e6b5f6c6f63616c78196665"
      "38303a3a656434323a343265613a643461633a36393438677072696d6172797826"
      "3265643a343234323a656164343a616336393a656434323a343265613a64346163"
      "3a36393438";
  static const uint8_t private_seed[] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  static const char *const forbidden[] = {"private", "privkey", "seed"};
  uint8_t expected[TEST_CBOR_MAX_SIZE];
  size_t expected_len = decode_hex(expected_hex, expected, sizeof(expected));

  zassert_ok(lichen_coap_config_register(&provider));
  mutate_identity_after_get = true;
  zassert_equal(strcmp(lichen_config_identity.path[0], "config"), 0);
  zassert_equal(strcmp(lichen_config_identity.path[1], "identity"), 0);
  zassert_is_null(lichen_config_identity.path[2],
                  "resource path must be exact");
  zassert_is_null(lichen_config_identity.post, "identity must be read-only");
  zassert_is_null(lichen_config_identity.put, "identity must be read-only");
  zassert_is_null(lichen_config_identity.del, "identity must be read-only");
  zassert_ok(invoke_identity_get());

  zassert_equal(identity_get_calls, 1U, "provider snapshot must be read once");
  zassert_equal(fingerprint_calls, 1U);
  zassert_equal(response.code, COAP_RESPONSE_CODE_CONTENT);
  zassert_equal(response.content_format, 60U, "application/cbor is ct=60");
  zassert_equal(response.payload_len, expected_len);
  zassert_mem_equal(response.payload, expected, expected_len,
                    "GET response differs from shared identity vector");
  zassert_equal(admin_calls, 0U, "public identity GET must not require admin");
  zassert_equal(oscore_calls, 0U,
                "public identity GET must not require OSCORE");
  zassert_false(contains_bytes(response.payload, response.payload_len,
                               private_seed, sizeof(private_seed)),
                "private seed leaked into identity response");
  for (size_t i = 0U; i < ARRAY_SIZE(forbidden); i++) {
    zassert_false(contains_bytes(response.payload, response.payload_len,
                                 (const uint8_t *)forbidden[i],
                                 strlen(forbidden[i])),
                  "private field name leaked: %s", forbidden[i]);
  }
}

ZTEST(coap_config, test_identity_encoder_consumes_optional_shared_vectors) {
  static const char minimal_hex[] =
      "a165657569363472307830303131323233333434353536363737";
  static const char addrs_hex[] =
      "a1656164647273a26a6c696e6b5f6c6f63616c7819666538303a3a656434323a"
      "343265613a643461633a36393438677072696d61727978263265643a343234323a"
      "656164343a616336393a656434323a343265613a643461633a36393438";
  struct lichen_config_identity identity = test_identity;

  identity.pubkey_valid = false;
  identity.link_local[0] = '\0';
  identity.primary[0] = '\0';
  assert_identity_encoding(&identity, minimal_hex);

  identity = test_identity;
  identity.eui64_valid = false;
  identity.pubkey_valid = false;
  assert_identity_encoding(&identity, addrs_hex);

  memset(&identity, 0, sizeof(identity));
  assert_identity_encoding(&identity, "a0");
  zassert_equal(fingerprint_calls, 0U,
                "absent public key must not invoke fingerprinting");
}

ZTEST(coap_config, test_identity_get_error_mapping_and_bounds) {
  uint8_t encoded[TEST_CBOR_MAX_SIZE];
  struct lichen_config_identity invalid = test_identity;

  zassert_ok(lichen_coap_config_register(&missing_get_provider));
  zassert_ok(invoke_identity_get());
  zassert_equal(response.code, COAP_RESPONSE_CODE_NOT_FOUND);
  zassert_equal(response.payload_len, 0U);

  identity_get_result = -EIO;
  memset(&response, 0, sizeof(response));
  zassert_ok(lichen_coap_config_register(&provider));
  zassert_ok(invoke_identity_get());
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR);

  identity_get_result = 0;
  fingerprint_result = -EIO;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_identity_get());
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR);
  zassert_equal(response.payload_len, 0U);

  fingerprint_result = 0;
  fingerprint_malformed = true;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_identity_get());
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR,
                "malformed fingerprint must fail closed");

  fingerprint_malformed = false;
  memset(invalid.link_local, 'x', sizeof(invalid.link_local));
  zassert_equal(
      lichen_config_encode_identity_cbor(encoded, sizeof(encoded), &invalid),
      0U, "unterminated provider address must fail closed");
  zassert_equal(lichen_config_encode_identity_cbor(encoded, 1U, &test_identity),
                0U, "undersized output must fail closed");
}

static int invoke_radio_get(void) {
  struct coap_packet request = {0};
  struct sockaddr addr = {0};

  zassert_not_null(lichen_config_radio.get, "radio GET handler missing");
  return lichen_config_radio.get(&lichen_config_radio, &request, &addr,
                                 sizeof(addr));
}

ZTEST(coap_config, test_radio_get_emits_exact_public_snapshot) {
  static const uint8_t expected[] = {
      0xa6, 0x68, 0x66, 0x72, 0x65, 0x71, 0x5f, 0x6d, 0x68, 0x7a, 0xfb, 0x40,
      0x8c, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x62, 0x77, 0x5f, 0x6b,
      0x68, 0x7a, 0x18, 0x7d, 0x62, 0x73, 0x66, 0x09, 0x62, 0x63, 0x72, 0x63,
      0x34, 0x2f, 0x35, 0x6c, 0x74, 0x78, 0x5f, 0x70, 0x6f, 0x77, 0x65, 0x72,
      0x5f, 0x64, 0x62, 0x6d, 0x14, 0x69, 0x73, 0x79, 0x6e, 0x63, 0x5f, 0x77,
      0x6f, 0x72, 0x64, 0x64, 0x30, 0x78, 0x33, 0x34};
  struct lichen_config_radio decoded = {
      .freq_khz = 906875U,
      .bw_khz = 125U,
      .sf = 9U,
      .cr = LICHEN_CONFIG_CR_4_5,
      .tx_power_dbm = 20,
      .sync_word = 0x34U,
  };

  zassert_ok(lichen_coap_config_register(&provider));
  mutate_radio_after_get = true;
  zassert_equal(strcmp(lichen_config_radio.path[0], "config"), 0);
  zassert_equal(strcmp(lichen_config_radio.path[1], "radio"), 0);
  zassert_is_null(lichen_config_radio.path[2], "resource path must be exact");
  zassert_ok(invoke_radio_get());

  zassert_equal(radio_get_calls, 1U, "provider snapshot must be read once");
  zassert_equal(response.code, COAP_RESPONSE_CODE_CONTENT);
  zassert_equal(response.content_format, 60U, "application/cbor is ct=60");
  zassert_equal(response.payload_len, sizeof(expected),
                "actual %zu expected %zu", response.payload_len,
                sizeof(expected));
  zassert_mem_equal(response.payload, expected, sizeof(expected),
                    "spec vector must be byte-exact, including float64");
  zassert_ok(lichen_config_decode_radio_cbor(response.payload,
                                             response.payload_len, &decoded));
  zassert_equal(decoded.freq_khz, 906875U);
  zassert_equal(decoded.bw_khz, 125U);
  zassert_equal(decoded.sf, 9U);
  zassert_equal(decoded.cr, LICHEN_CONFIG_CR_4_5);
  zassert_equal(decoded.tx_power_dbm, 20);
  zassert_equal(decoded.sync_word, 0x34U);
  zassert_equal(admin_calls, 0U, "radio GET must be public");
  zassert_equal(oscore_calls, 0U, "radio GET must not require OSCORE");
}

ZTEST(coap_config, test_radio_encoder_accepts_documented_boundaries) {
  uint8_t output[TEST_CBOR_MAX_SIZE];
  struct lichen_config_radio boundary = {
      .freq_khz = 1U,
      .bw_khz = 1U,
      .sf = 7U,
      .cr = LICHEN_CONFIG_CR_4_5,
      .tx_power_dbm = -20,
      .sync_word = 0U,
  };
  struct lichen_config_radio decoded = boundary;
  size_t encoded_len =
      lichen_config_encode_radio_cbor(output, sizeof(output), &boundary);

  zassert_true(encoded_len > 0U && encoded_len <= sizeof(output));
  zassert_ok(lichen_config_decode_radio_cbor(output, encoded_len, &decoded));
  zassert_equal(decoded.freq_khz, boundary.freq_khz);
  zassert_equal(decoded.bw_khz, boundary.bw_khz);
  zassert_equal(decoded.sf, boundary.sf);
  zassert_equal(decoded.cr, boundary.cr);
  zassert_equal(decoded.tx_power_dbm, boundary.tx_power_dbm);
  zassert_equal(decoded.sync_word, boundary.sync_word);

  boundary.freq_khz = 10000000U;
  boundary.bw_khz = 5000U;
  boundary.sf = 12U;
  boundary.cr = LICHEN_CONFIG_CR_4_8;
  boundary.tx_power_dbm = 30;
  boundary.sync_word = UINT16_MAX;
  encoded_len =
      lichen_config_encode_radio_cbor(output, sizeof(output), &boundary);
  zassert_true(encoded_len > 0U && encoded_len <= sizeof(output));
  decoded = boundary;
  zassert_ok(lichen_config_decode_radio_cbor(output, encoded_len, &decoded));
  zassert_equal(decoded.freq_khz, boundary.freq_khz);
  zassert_equal(decoded.bw_khz, boundary.bw_khz);
  zassert_equal(decoded.sf, boundary.sf);
  zassert_equal(decoded.cr, boundary.cr);
  zassert_equal(decoded.tx_power_dbm, boundary.tx_power_dbm);
  zassert_equal(decoded.sync_word, boundary.sync_word);
  zassert_equal(lichen_config_encode_radio_cbor(output, 8U, &boundary), 0U,
                "undersized output must fail closed");
}

ZTEST(coap_config, test_radio_get_rejects_invalid_provider_snapshots) {
  struct lichen_config_radio invalid[9];

  for (size_t i = 0U; i < ARRAY_SIZE(invalid); i++) {
    invalid[i] = test_radio;
  }
  invalid[0].freq_khz = 0U;
  invalid[1].freq_khz = 10000001U;
  invalid[2].bw_khz = 0U;
  invalid[3].bw_khz = 5001U;
  invalid[4].sf = 6U;
  invalid[5].sf = 13U;
  invalid[6].cr = (enum lichen_config_coding_rate)99;
  invalid[7].tx_power_dbm = -21;
  invalid[8].tx_power_dbm = 31;

  zassert_ok(lichen_coap_config_register(&provider));
  for (size_t i = 0U; i < ARRAY_SIZE(invalid); i++) {
    test_radio = invalid[i];
    memset(&response, 0, sizeof(response));
    zassert_ok(invoke_radio_get(), "invalid boundary %zu", i);
    zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR,
                  "invalid boundary %zu was exposed", i);
    zassert_equal(response.payload_len, 0U);
  }
}

ZTEST(coap_config, test_radio_get_error_mapping) {
  zassert_ok(lichen_coap_config_register(&missing_get_provider));
  zassert_ok(invoke_radio_get());
  zassert_equal(response.code, COAP_RESPONSE_CODE_NOT_FOUND);
  zassert_equal(response.payload_len, 0U);

  radio_get_result = -EIO;
  memset(&response, 0, sizeof(response));
  zassert_ok(lichen_coap_config_register(&provider));
  zassert_ok(invoke_radio_get());
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR);
  zassert_equal(response.payload_len, 0U);
}

static int invoke_radio_put(const uint8_t *payload, size_t payload_len) {
  struct coap_packet request = {0};
  struct sockaddr addr = {0};

  request_payload = payload;
  request_payload_len = payload_len;
  zassert_not_null(lichen_config_radio.put, "radio PUT handler missing");
  return lichen_config_radio.put(&lichen_config_radio, &request, &addr,
                                 sizeof(addr));
}

ZTEST(coap_config, test_radio_put_partial_update_is_atomic_and_changed) {
  static const uint8_t update[] = {0xa2, 0x62, 's', 'f', 0x0a, 0x6c, 't',
                                   'x',  '_',  'p', 'o', 'w',  'e',  'r',
                                   '_',  'd',  'b', 'm', 0x11};

  zassert_ok(lichen_coap_config_register(&provider));
  admin_result = true;
  zassert_ok(invoke_radio_put(update, sizeof(update)));

  zassert_equal(oscore_calls, 1U);
  zassert_equal(admin_calls, 1U);
  zassert_equal(radio_get_calls, 1U);
  zassert_equal(radio_set_calls, 1U);
  zassert_equal(test_radio.freq_khz, 906875U);
  zassert_equal(test_radio.bw_khz, 125U);
  zassert_equal(test_radio.sf, 10U);
  zassert_equal(test_radio.cr, LICHEN_CONFIG_CR_4_5);
  zassert_equal(test_radio.tx_power_dbm, 17);
  zassert_equal(test_radio.sync_word, 0x34U);
  zassert_equal(response.code, COAP_RESPONSE_CODE_CHANGED);
  zassert_equal(response.content_format, 0U);
  zassert_equal(response.payload_len, 0U);
}

ZTEST(coap_config, test_radio_put_protected_or_local_admin_policy) {
  static const uint8_t update[] = {0xa1, 0x62, 's', 'f', 0x0c};

  zassert_ok(lichen_coap_config_register(&provider));
  request_is_protected = true;
  zassert_ok(invoke_radio_put(update, sizeof(update)));
  zassert_equal(admin_calls, 0U);
  zassert_equal(radio_set_calls, 1U);
  zassert_equal(test_radio.sf, 12U);
  zassert_equal(response.code, COAP_RESPONSE_CODE_CHANGED);

  request_is_protected = false;
  admin_result = false;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_radio_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_UNAUTHORIZED);
  zassert_equal(radio_set_calls, 1U, "unauthorized request reached provider");
}

struct radio_invalid_update {
  const uint8_t *payload;
  size_t payload_len;
  const char *description;
};

ZTEST(coap_config, test_radio_put_strict_rejections_do_not_mutate) {
  static const uint8_t empty_map[] = {0xa0};
  static const uint8_t non_map[] = {0x64, 's', 'f', '1', '0'};
  static const uint8_t unknown[] = {0xa1, 0x6d, 'b', 'a',  'n', 'd',
                                    'w',  'i',  'd', 't',  'h', '_',
                                    'k',  'h',  'z', 0x18, 0xfa};
  static const uint8_t duplicate[] = {0xa2, 0x62, 's', 'f', 0x09,
                                      0x62, 's',  'f', 0x0a};
  static const uint8_t tagged[] = {0xa1, 0x62, 's', 'f', 0xd8, 0x1d, 0x0a};
  static const uint8_t trailing[] = {0xa1, 0x62, 's', 'f', 0x0a, 0x00};
  static const uint8_t indefinite[] = {0xbf, 0x62, 's', 'f', 0x0a, 0xff};
  static const uint8_t noncanonical_int[] = {0xa1, 0x62, 's', 'f', 0x18, 0x0a};
  static const uint8_t wrong_type[] = {0xa1, 0x62, 's', 'f', 0x61, 'x'};
  static const uint8_t sf_too_low[] = {0xa1, 0x62, 's', 'f', 0x06};
  static const uint8_t sf_too_high[] = {0xa1, 0x62, 's', 'f', 0x0d};
  static const uint8_t bw_zero[] = {0xa1, 0x66, 'b', 'w', '_',
                                    'k',  'h',  'z', 0x00};
  static const uint8_t bw_too_high[] = {0xa1, 0x66, 'b',  'w',  '_', 'k',
                                        'h',  'z',  0x19, 0x13, 0x89};
  static const uint8_t tx_too_low[] = {0xa1, 0x6c, 't', 'x', '_', 'p', 'o', 'w',
                                       'e',  'r',  '_', 'd', 'b', 'm', 0x34};
  static const uint8_t tx_too_high[] = {0xa1, 0x6c, 't',  'x', '_', 'p',
                                        'o',  'w',  'e',  'r', '_', 'd',
                                        'b',  'm',  0x18, 0x1f};
  static const uint8_t invalid_cr[] = {0xa1, 0x62, 'c', 'r',
                                       0x63, '4',  '/', '9'};
  static const uint8_t invalid_sync[] = {0xa1, 0x69, 's', 'y', 'n', 'c',
                                         '_',  'w',  'o', 'r', 'd', 0x64,
                                         '0',  'x',  'g', '1'};
  static const uint8_t nan_frequency[] = {
      0xa1, 0x68, 'f',  'r',  'e',  'q',  '_',  'm',  'h', 'z',
      0xfb, 0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  static const struct radio_invalid_update cases[] = {
      {NULL, 0U, "empty payload"},
      {empty_map, sizeof(empty_map), "empty map"},
      {non_map, sizeof(non_map), "non-map"},
      {unknown, sizeof(unknown), "unknown field"},
      {duplicate, sizeof(duplicate), "duplicate field"},
      {tagged, sizeof(tagged), "tagged value"},
      {trailing, sizeof(trailing), "trailing byte"},
      {indefinite, sizeof(indefinite), "indefinite map"},
      {noncanonical_int, sizeof(noncanonical_int), "noncanonical integer"},
      {wrong_type, sizeof(wrong_type), "wrong type"},
      {sf_too_low, sizeof(sf_too_low), "SF below 7"},
      {sf_too_high, sizeof(sf_too_high), "SF above 12"},
      {bw_zero, sizeof(bw_zero), "zero bandwidth"},
      {bw_too_high, sizeof(bw_too_high), "bandwidth above bound"},
      {tx_too_low, sizeof(tx_too_low), "TX power below bound"},
      {tx_too_high, sizeof(tx_too_high), "TX power above bound"},
      {invalid_cr, sizeof(invalid_cr), "invalid coding rate"},
      {invalid_sync, sizeof(invalid_sync), "invalid sync word"},
      {nan_frequency, sizeof(nan_frequency), "NaN frequency"},
  };

  zassert_ok(lichen_coap_config_register(&provider));
  admin_result = true;
  for (size_t i = 0U; i < ARRAY_SIZE(cases); i++) {
    struct lichen_config_radio before_update = test_radio;
    unsigned int set_calls_before = radio_set_calls;

    memset(&response, 0, sizeof(response));
    zassert_ok(invoke_radio_put(cases[i].payload, cases[i].payload_len), "%s",
               cases[i].description);
    zassert_equal(response.code, COAP_RESPONSE_CODE_BAD_REQUEST, "%s",
                  cases[i].description);
    zassert_equal(radio_set_calls, set_calls_before, "%s reached provider",
                  cases[i].description);
    zassert_mem_equal(&test_radio, &before_update, sizeof(test_radio),
                      "%s partially mutated radio state", cases[i].description);
  }
}

ZTEST(coap_config, test_radio_put_provider_error_mapping_and_rollback) {
  static const uint8_t update[] = {0xa1, 0x62, 's', 'f', 0x0a};
  struct lichen_config_radio initial = test_radio;

  admin_result = true;

  zassert_ok(lichen_coap_config_register(&missing_get_provider));
  zassert_ok(invoke_radio_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_NOT_FOUND);

  memset(&response, 0, sizeof(response));
  zassert_ok(lichen_coap_config_register(&provider));

  radio_get_result = -EIO;
  zassert_ok(invoke_radio_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR);
  zassert_equal(radio_set_calls, 0U);

  radio_get_result = 0;
  test_radio.sf = 6U;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_radio_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR,
                "invalid provider snapshot must be a server error");
  zassert_equal(radio_set_calls, 0U);
  test_radio = initial;

  radio_set_result = -EINVAL;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_radio_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_BAD_REQUEST);
  zassert_mem_equal(&test_radio, &initial, sizeof(initial));

  radio_set_result = -ERANGE;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_radio_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_BAD_REQUEST,
                "regional limit rejection must be 4.00");
  zassert_mem_equal(&test_radio, &initial, sizeof(initial));

  radio_set_result = -EACCES;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_radio_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_FORBIDDEN);
  zassert_mem_equal(&test_radio, &initial, sizeof(initial));

  radio_set_result = -EIO;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_radio_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR,
                "persistence failure must be 5.00");
  zassert_mem_equal(&test_radio, &initial, sizeof(initial));
}

ZTEST(coap_config, test_encoder_rejects_unbounded_or_invalid_snapshot) {
  uint8_t output[TEST_CBOR_MAX_SIZE];
  struct lichen_config_node invalid;

  memset(&invalid, 'x', sizeof(invalid));
  invalid.role = LICHEN_CONFIG_ROLE_ROUTER;
  zassert_equal(
      lichen_config_encode_node_cbor(output, sizeof(output), &invalid), 0U,
      "non-terminated provider name must be rejected");

  memset(&invalid, 0, sizeof(invalid));
  (void)strcpy(invalid.name, "valid-name");
  invalid.role = (enum lichen_config_role)99;
  zassert_equal(
      lichen_config_encode_node_cbor(output, sizeof(output), &invalid), 0U,
      "invalid role must not silently become leaf");

  invalid.role = LICHEN_CONFIG_ROLE_BORDER_ROUTER;
  zassert_equal(lichen_config_encode_node_cbor(output, 8U, &invalid), 0U,
                "undersized response buffer must fail closed");
}

static int invoke_put(const uint8_t *payload, size_t payload_len) {
  struct coap_packet request = {0};
  struct sockaddr addr = {0};

  request_payload = payload;
  request_payload_len = payload_len;
  zassert_not_null(lichen_config.put, "PUT handler missing");
  return lichen_config.put(&lichen_config, &request, &addr, sizeof(addr));
}

ZTEST(coap_config, test_put_partial_update_is_atomic_and_changed) {
  static const uint8_t name_update[] = {0xa1, 0x64, 'n', 'a', 'm',
                                        'e',  0x68, 'n', 'e', 'w',
                                        '-',  'n',  'a', 'm', 'e'};

  zassert_ok(lichen_coap_config_register(&provider));
  admin_result = true;
  zassert_ok(invoke_put(name_update, sizeof(name_update)));

  zassert_equal(oscore_calls, 1U);
  zassert_equal(admin_calls, 1U);
  zassert_equal(node_get_calls, 1U);
  zassert_equal(node_set_calls, 1U);
  zassert_equal(strcmp(test_node.name, "new-name"), 0);
  zassert_equal(test_node.role, LICHEN_CONFIG_ROLE_ROUTER,
                "partial update must retain the current role");
  zassert_equal(response.code, COAP_RESPONSE_CODE_CHANGED);
  zassert_equal(response.content_format, 0U);
  zassert_equal(response.payload_len, 0U);
}

ZTEST(coap_config, test_put_protected_request_does_not_require_local_admin) {
  static const uint8_t role_update[] = {0xa1, 0x64, 'r', 'o', 'l', 'e', 0x6d,
                                        'b',  'o',  'r', 'd', 'e', 'r', '-',
                                        'r',  'o',  'u', 't', 'e', 'r'};

  zassert_ok(lichen_coap_config_register(&provider));
  request_is_protected = true;
  zassert_ok(invoke_put(role_update, sizeof(role_update)));

  zassert_equal(admin_calls, 0U);
  zassert_equal(node_set_calls, 1U);
  zassert_equal(test_node.role, LICHEN_CONFIG_ROLE_BORDER_ROUTER);
  zassert_equal(response.code, COAP_RESPONSE_CODE_CHANGED);
}

ZTEST(coap_config, test_put_unauthorized_is_rejected_before_provider) {
  static const uint8_t update[] = {0xa1, 0x64, 'n', 'a', 'm', 'e', 0x61, 'x'};

  zassert_ok(lichen_coap_config_register(&provider));
  zassert_ok(invoke_put(update, sizeof(update)));

  zassert_equal(response.code, COAP_RESPONSE_CODE_UNAUTHORIZED);
  zassert_equal(node_get_calls, 0U);
  zassert_equal(node_set_calls, 0U);
  zassert_equal(strcmp(test_node.name, "my-node"), 0);
}

struct invalid_update {
  const uint8_t *payload;
  size_t payload_len;
  const char *description;
};

ZTEST(coap_config, test_put_strict_rejections_do_not_mutate) {
  static const uint8_t malformed[] = {0xff, 0xfe, 0xfd};
  static const uint8_t non_map[] = {0x83, 0x01, 0x02, 0x03};
  static const uint8_t unknown_after_name[] = {
      0xa2, 0x64, 'n', 'a', 'm', 'e', 0x62, 'v', '3',
      0x67, 'u',  'n', 'k', 'n', 'o', 'w',  'n', 0x01};
  static const uint8_t trailing[] = {0xa1, 0x64, 'n', 'a', 'm',
                                     'e',  0x61, 'x', 0x00};
  static const uint8_t duplicate[] = {
      0xa2, 0x64, 'n', 'a', 'm', 'e',  0x65, 'f', 'i', 'r', 's', 't',
      0x64, 'n',  'a', 'm', 'e', 0x66, 's',  'e', 'c', 'o', 'n', 'd'};
  static const uint8_t tagged[] = {0xa1, 0x64, 'n',  'a', 'm', 'e',
                                   0xd8, 0x1d, 0x63, 'a', 'b', 'c'};
  static const uint8_t wrong_type[] = {0xa1, 0x64, 'n', 'a', 'm', 'e', 0x01};
  static const uint8_t invalid_role[] = {0xa1, 0x64, 'r', 'o', 'l', 'e', 0x67,
                                         'g',  'a',  't', 'e', 'w', 'a', 'y'};
  static const uint8_t too_long_name[] = {
      0xa1, 0x64, 'n', 'a', 'm', 'e', 0x78, 0x20, 'x', 'x', 'x', 'x', 'x', 'x',
      'x',  'x',  'x', 'x', 'x', 'x', 'x',  'x',  'x', 'x', 'x', 'x', 'x', 'x',
      'x',  'x',  'x', 'x', 'x', 'x', 'x',  'x',  'x', 'x', 'x', 'x'};
  static const struct invalid_update cases[] = {
      {NULL, 0U, "empty"},
      {malformed, sizeof(malformed), "malformed"},
      {non_map, sizeof(non_map), "non-map"},
      {unknown_after_name, sizeof(unknown_after_name), "unknown field"},
      {trailing, sizeof(trailing), "trailing bytes"},
      {duplicate, sizeof(duplicate), "duplicate field"},
      {tagged, sizeof(tagged), "tagged value"},
      {wrong_type, sizeof(wrong_type), "wrong type"},
      {invalid_role, sizeof(invalid_role), "invalid role"},
      {too_long_name, sizeof(too_long_name), "oversized name"},
  };

  zassert_ok(lichen_coap_config_register(&provider));
  admin_result = true;
  for (size_t i = 0U; i < ARRAY_SIZE(cases); i++) {
    struct lichen_config_node before_update = test_node;
    unsigned int set_calls_before = node_set_calls;

    memset(&response, 0, sizeof(response));
    zassert_ok(invoke_put(cases[i].payload, cases[i].payload_len), "%s",
               cases[i].description);
    zassert_equal(response.code, COAP_RESPONSE_CODE_BAD_REQUEST, "%s",
                  cases[i].description);
    zassert_equal(node_set_calls, set_calls_before, "%s reached provider",
                  cases[i].description);
    zassert_mem_equal(&test_node, &before_update, sizeof(test_node),
                      "%s partially mutated state", cases[i].description);
  }
}

ZTEST(coap_config, test_decoder_rejection_is_atomic) {
  static const uint8_t update_then_unknown[] = {
      0xa2, 0x64, 'n', 'a', 'm', 'e', 0x62, 'v', '3',
      0x67, 'u',  'n', 'k', 'n', 'o', 'w',  'n', 0x01};
  struct lichen_config_node candidate = test_node;
  struct lichen_config_node original = candidate;

  zassert_equal(lichen_config_decode_node_cbor(update_then_unknown,
                                               sizeof(update_then_unknown),
                                               &candidate),
                -EINVAL);
  zassert_mem_equal(&candidate, &original, sizeof(candidate));
}

ZTEST(coap_config, test_put_provider_errors_are_mapped_without_mutation) {
  static const uint8_t update[] = {0xa1, 0x64, 'n', 'a', 'm', 'e', 0x61, 'x'};
  struct lichen_config_node initial;

  zassert_ok(lichen_coap_config_register(&provider));
  admin_result = true;
  initial = test_node;

  node_get_result = -EIO;
  zassert_ok(invoke_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR);
  zassert_equal(node_set_calls, 0U);
  zassert_mem_equal(&test_node, &initial, sizeof(initial));

  node_get_result = 0;
  node_set_result = -EINVAL;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_BAD_REQUEST);
  zassert_mem_equal(&test_node, &initial, sizeof(initial));

  node_set_result = -EACCES;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_FORBIDDEN);
  zassert_mem_equal(&test_node, &initial, sizeof(initial));

  node_set_result = -EIO;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR,
                "persistence failure must be a server error");
  zassert_mem_equal(&test_node, &initial, sizeof(initial));

  node_set_result = 0;
  test_node.role = (enum lichen_config_role)99;
  memset(&response, 0, sizeof(response));
  zassert_ok(invoke_put(update, sizeof(update)));
  zassert_equal(response.code, COAP_RESPONSE_CODE_INTERNAL_ERROR,
                "invalid provider snapshot must be a server error");
}
