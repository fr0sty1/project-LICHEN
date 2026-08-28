/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/net/coap.h>
#include <zephyr/ztest.h>

#include <lichen/coap_blockwise.h>

struct option_vector {
  uint32_t num;
  bool more;
  uint8_t szx;
  uint8_t encoded[3];
  uint8_t len;
};

static const struct option_vector option_vectors[] = {
    {0, false, 0, {0x00}, 1},
    {0, true, 0, {0x08}, 1},
    {0, false, 3, {0x03}, 1},
    {0, true, 2, {0x0a}, 1},
    {1, false, 0, {0x10}, 1},
    {2, true, 3, {0x2b}, 1},
    {15, false, 6, {0xf6}, 1},
    {16, false, 0, {0x01, 0x00}, 2},
    {255, true, 4, {0x0f, 0xfc}, 2},
    {4095, true, 0, {0xff, 0xf8}, 2},
    {4096, false, 2, {0x01, 0x00, 0x02}, 3},
    {0xfffff, false, 6, {0xff, 0xff, 0xf6}, 3},
};

static uint8_t upload[LICHEN_COAP_BLOCK_MAX_BODY];
static uint8_t download[LICHEN_COAP_BLOCK_MAX_BODY];
static uint8_t source[LICHEN_COAP_BLOCK_MAX_BODY + 1U];

static struct lichen_coap_block_key key(uint8_t peer, uint8_t token,
                                        bool protected_message) {
  struct lichen_coap_block_key value = {
      .peer_id = {peer},
      .peer_id_len = 1U,
      .token = {token},
      .token_len = 1U,
      .resource_id = 0x12345678U,
      .oscore_context_id = protected_message ? 7U : 0U,
      .protected_message = protected_message,
  };

  return value;
}

ZTEST(coap_blockwise, test_shared_option_vectors_and_rejections) {
  uint8_t encoded[3];
  struct lichen_coap_block block;

  for (size_t i = 0U; i < ARRAY_SIZE(option_vectors); i++) {
    const struct option_vector *v = &option_vectors[i];

    zassert_ok(lichen_coap_block_decode(v->encoded, v->len, &block));
    zassert_equal(block.num, v->num);
    zassert_equal(block.more, v->more);
    zassert_equal(block.szx, v->szx);
    zassert_equal(lichen_coap_block_size(&block), (size_t)1U << (v->szx + 4U));
    zassert_equal(lichen_coap_block_encode(&block, encoded), v->len);
    zassert_mem_equal(encoded, v->encoded, v->len);
  }
  zassert_equal(lichen_coap_block_decode(NULL, 0U, &block), -EBADMSG);
  zassert_equal(lichen_coap_block_decode((uint8_t[]){0x07}, 1U, &block),
                -EBADMSG);
  zassert_equal(lichen_coap_block_decode((uint8_t[]){0, 0}, 2U, &block),
                -EBADMSG);
  zassert_equal(lichen_coap_block_decode((uint8_t[]){0, 0, 0, 0}, 4U, &block),
                -EBADMSG);
}

ZTEST(coap_blockwise, test_shared_wire_messages_parse_options) {
  static const uint8_t get_status[] = {0x40, 0x01, 0x12, 0x34, 0xb6, 's', 't',
                                       'a',  't',  'u',  's',  0xc1, 0x03};
  static const uint8_t put_ota[] = {0x40, 0x03, 0x00, 0x02, 0xb3, 'o', 't',
                                    'a',  0xd1, 0x03, 0x08, 0xff, 'a', 'a',
                                    'a',  'a',  'a',  'a',  'a',  'a', 'a',
                                    'a',  'a',  'a',  'a',  'a',  'a', 'a'};
  static const uint8_t response[] = {0x60, 0x45, 0x00, 0x01, 0xd1, 0x0a, 0x10,
                                     0xff, 'h',  'e',  'l',  'l',  'o'};
  struct coap_option options[8];
  struct coap_packet packet;
  struct lichen_coap_block block;

  zassert_ok(coap_packet_parse(&packet, (uint8_t *)get_status,
                               sizeof(get_status), options,
                               ARRAY_SIZE(options)));
  zassert_ok(lichen_coap_block_get_option(&packet, COAP_OPTION_BLOCK2, &block));
  zassert_equal(block.num, 0U);
  zassert_equal(block.szx, 3U);
  zassert_ok(coap_packet_parse(&packet, (uint8_t *)put_ota, sizeof(put_ota),
                               options, ARRAY_SIZE(options)));
  zassert_ok(lichen_coap_block_get_option(&packet, COAP_OPTION_BLOCK1, &block));
  zassert_true(block.more);
  zassert_ok(coap_packet_parse(&packet, (uint8_t *)response, sizeof(response),
                               options, ARRAY_SIZE(options)));
  zassert_ok(lichen_coap_block_get_option(&packet, COAP_OPTION_BLOCK2, &block));
  zassert_equal(block.num, 1U);
  zassert_false(block.more);
}

ZTEST(coap_blockwise, test_packet_append_size_and_duplicate_options) {
  struct lichen_coap_block expected = {.num = 16U, .more = true, .szx = 2U};
  struct lichen_coap_block decoded;
  struct coap_option option;
  struct coap_packet packet;
  uint8_t packet_buf[64];
  size_t size;

  zassert_ok(coap_packet_init(&packet, packet_buf, sizeof(packet_buf),
                              COAP_VERSION_1, COAP_TYPE_CON, 0, NULL,
                              COAP_METHOD_GET, 1U));
  zassert_ok(
      lichen_coap_block_append_option(&packet, COAP_OPTION_BLOCK2, &expected));
  zassert_ok(lichen_coap_block_append_size(&packet, COAP_OPTION_SIZE2, 4096U));
  packet.max_len = packet.offset;
  zassert_ok(
      lichen_coap_block_get_option(&packet, COAP_OPTION_BLOCK2, &decoded));
  zassert_equal(decoded.num, expected.num);
  zassert_equal(decoded.more, expected.more);
  zassert_equal(decoded.szx, expected.szx);
  zassert_equal(coap_find_options(&packet, COAP_OPTION_SIZE2, &option, 1), 1);
  zassert_ok(lichen_coap_block_decode_size(option.value, option.len, &size));
  zassert_equal(size, 4096U);
  zassert_ok(lichen_coap_block_decode_size(NULL, 0U, &size));
  zassert_equal(size, 0U);
  zassert_equal(lichen_coap_block_decode_size((uint8_t[]){0, 1}, 2U, &size),
                -EBADMSG);

  zassert_ok(coap_packet_init(&packet, packet_buf, sizeof(packet_buf),
                              COAP_VERSION_1, COAP_TYPE_CON, 0, NULL,
                              COAP_METHOD_GET, 2U));
  zassert_ok(
      lichen_coap_block_append_option(&packet, COAP_OPTION_BLOCK2, &expected));
  zassert_ok(
      lichen_coap_block_append_option(&packet, COAP_OPTION_BLOCK2, &expected));
  packet.max_len = packet.offset;
  zassert_equal(
      lichen_coap_block_get_option(&packet, COAP_OPTION_BLOCK2, &decoded),
      -EBADMSG);
}

ZTEST(coap_blockwise, test_block1_exact_assembly_resize_and_duplicates) {
  struct lichen_coap_block1_receiver receiver;
  struct lichen_coap_block_key transfer = key(1U, 2U, true);
  enum lichen_coap_block_result result;
  struct lichen_coap_block block = {.num = 0U, .more = true, .szx = 2U};

  for (size_t i = 0U; i < 160U; i++) {
    source[i] = (uint8_t)i;
  }
  zassert_ok(lichen_coap_block1_init(&receiver, upload, sizeof(upload), 100U));
  zassert_ok(lichen_coap_block1_receive(&receiver, 0U, &transfer, &block, true,
                                        160U, source, 64U, &result));
  zassert_equal(result, LICHEN_COAP_BLOCK_ACCEPTED);
  zassert_ok(lichen_coap_block1_receive(&receiver, 1U, &transfer, &block, true,
                                        160U, source, 64U, &result));
  zassert_equal(result, LICHEN_COAP_BLOCK_DUPLICATE);

  /* The client may reduce SZX while preserving the absolute offset. */
  block = (struct lichen_coap_block){.num = 2U, .more = true, .szx = 1U};
  zassert_ok(lichen_coap_block1_receive(&receiver, 2U, &transfer, &block, true,
                                        160U, &source[64], 32U, &result));
  block.num = 3U;
  zassert_ok(lichen_coap_block1_receive(&receiver, 3U, &transfer, &block, true,
                                        160U, &source[96], 32U, &result));
  block.num = 4U;
  block.more = false;
  zassert_ok(lichen_coap_block1_receive(&receiver, 4U, &transfer, &block, true,
                                        160U, &source[128], 32U, &result));
  zassert_equal(result, LICHEN_COAP_BLOCK_COMPLETE);
  zassert_equal(receiver.length, 160U);
  zassert_mem_equal(receiver.body, source, 160U);
  zassert_ok(lichen_coap_block1_receive(&receiver, 4U, &transfer, &block, true,
                                        160U, &source[128], 32U, &result));
  zassert_equal(result, LICHEN_COAP_BLOCK_DUPLICATE);
}

ZTEST(coap_blockwise, test_block1_rejects_without_partial_mutation) {
  struct lichen_coap_block1_receiver receiver;
  struct lichen_coap_block_key transfer = key(1U, 2U, false);
  struct lichen_coap_block_key attacker = key(9U, 2U, false);
  struct lichen_coap_block_key wrong_security = key(1U, 2U, true);
  enum lichen_coap_block_result result;
  struct lichen_coap_block block = {.num = 1U, .more = true, .szx = 2U};

  memset(upload, 0x5a, sizeof(upload));
  memset(source, 0x11, 128U);
  zassert_ok(lichen_coap_block1_init(&receiver, upload, 128U, 10U));
  zassert_equal(lichen_coap_block1_receive(&receiver, 0U, &transfer, &block,
                                           true, 128U, source, 64U, &result),
                -EAGAIN);
  zassert_equal(receiver.length, 0U);
  block.num = 0U;
  zassert_equal(lichen_coap_block1_receive(&receiver, 0U, &transfer, &block,
                                           true, 129U, source, 64U, &result),
                -EMSGSIZE);
  zassert_false(receiver.active);
  zassert_ok(lichen_coap_block1_receive(&receiver, 0U, &transfer, &block, true,
                                        128U, source, 64U, &result));
  zassert_equal(lichen_coap_block1_receive(&receiver, 1U, &wrong_security,
                                           &block, true, 128U, source, 64U,
                                           &result),
                -EACCES);
  zassert_equal(lichen_coap_block1_receive(&receiver, 1U, &attacker, &block,
                                           true, 128U, source, 64U, &result),
                -EACCES);
  source[0] ^= 0xffU;
  zassert_equal(lichen_coap_block1_receive(&receiver, 1U, &transfer, &block,
                                           true, 128U, source, 64U, &result),
                -EEXIST);
  zassert_equal(receiver.length, 64U);
  zassert_true(lichen_coap_block1_expire(&receiver, 10U));
  block.num = 1U;
  zassert_equal(lichen_coap_block1_receive(&receiver, 11U, &transfer, &block,
                                           true, 128U, source, 64U, &result),
                -EAGAIN);
  zassert_equal(receiver.length, 0U);
}

ZTEST(coap_blockwise, test_block2_snapshot_negotiation_binding_and_timeout) {
  struct lichen_coap_block2_sender sender;
  struct lichen_coap_block_key transfer = key(3U, 4U, true);
  struct lichen_coap_block_key attacker = key(3U, 5U, true);
  struct lichen_coap_block request = {.num = 0U, .more = false, .szx = 6U};
  struct lichen_coap_block2_view view;

  for (size_t i = 0U; i < 200U; i++) {
    source[i] = (uint8_t)(255U - i);
  }
  zassert_ok(
      lichen_coap_block2_init(&sender, download, sizeof(download), 2U, 10U));
  zassert_ok(lichen_coap_block2_start(&sender, 0U, &transfer, source, 200U));
  zassert_ok(lichen_coap_block2_start(&sender, 1U, &transfer, source, 200U));
  source[0] ^= 0xffU;
  zassert_equal(lichen_coap_block2_start(&sender, 1U, &transfer, source, 200U),
                -EEXIST);
  source[0] ^= 0xffU;
  memset(source, 0U, 200U);
  zassert_ok(lichen_coap_block2_get(&sender, 1U, &transfer, &request, &view));
  zassert_equal(view.block.szx, 2U);
  zassert_equal(view.block.num, 0U);
  zassert_true(view.block.more);
  zassert_equal(view.payload_len, 64U);
  zassert_equal(view.payload[0], 255U, "response was not a stable snapshot");

  request = (struct lichen_coap_block){.num = 1U, .szx = 3U};
  zassert_ok(lichen_coap_block2_get(&sender, 2U, &transfer, &request, &view));
  zassert_equal(view.block.num, 2U, "128-byte offset maps to 64-byte block 2");
  zassert_equal(view.payload_len, 64U);
  zassert_equal(lichen_coap_block2_get(&sender, 3U, &attacker, &request, &view),
                -EACCES);
  request = (struct lichen_coap_block){.num = 4U, .szx = 2U};
  zassert_equal(lichen_coap_block2_get(&sender, 3U, &transfer, &request, &view),
                -ERANGE);
  zassert_true(lichen_coap_block2_expire(&sender, 12U));
  zassert_equal(lichen_coap_block2_get(&sender, 12U, &transfer, NULL, &view),
                -ETIMEDOUT);
}

ZTEST(coap_blockwise, test_payload_ceiling_and_error_mapping) {
  struct lichen_coap_block2_sender sender;
  struct lichen_coap_block_key transfer = key(1U, 1U, false);

  zassert_ok(
      lichen_coap_block2_init(&sender, download, sizeof(download), 6U, 100U));
  zassert_equal(
      lichen_coap_block2_start(&sender, 0U, &transfer, source, sizeof(source)),
      -EMSGSIZE);
  zassert_false(sender.active);
  zassert_equal(lichen_coap_block_error_response(-EMSGSIZE),
                COAP_RESPONSE_CODE_REQUEST_TOO_LARGE);
  zassert_equal(lichen_coap_block_error_response(-EAGAIN),
                COAP_RESPONSE_CODE_INCOMPLETE);
  zassert_equal(lichen_coap_block_error_response(-EEXIST),
                COAP_RESPONSE_CODE_CONFLICT);
  zassert_equal(lichen_coap_block_error_response(-EBADMSG),
                COAP_RESPONSE_CODE_BAD_OPTION);
}

ZTEST_SUITE(coap_blockwise, NULL, NULL, NULL, NULL, NULL);
