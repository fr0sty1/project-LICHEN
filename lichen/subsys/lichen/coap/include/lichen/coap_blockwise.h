/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_COAP_BLOCKWISE_H_
#define LICHEN_COAP_BLOCKWISE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <zephyr/net/coap.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_COAP_BLOCK_MAX_NUM 0xfffffU
#define LICHEN_COAP_BLOCK_MIN_SIZE 16U
#define LICHEN_COAP_BLOCK_MAX_SIZE 1024U
#define LICHEN_COAP_BLOCK_MAX_BODY 4096U
#define LICHEN_COAP_BLOCK_TOKEN_MAX 8U
#define LICHEN_COAP_BLOCK_PEER_ID_MAX 16U

struct lichen_coap_block {
  uint32_t num;
  uint8_t szx;
  bool more;
};

struct lichen_coap_block_key {
  uint8_t peer_id[LICHEN_COAP_BLOCK_PEER_ID_MAX];
  uint8_t peer_id_len;
  uint8_t token[LICHEN_COAP_BLOCK_TOKEN_MAX];
  uint8_t token_len;
  uint32_t resource_id;
  uint32_t oscore_context_id;
  bool protected_message;
};

/* OSCORE boundary: callers pass plaintext from one independently unprotected
 * block and independently protect each returned block. Never concatenate
 * ciphertext. The protection flag and context ID bind continuations to the
 * authenticated context that opened the transfer. */

enum lichen_coap_block_result {
  LICHEN_COAP_BLOCK_ACCEPTED = 0,
  LICHEN_COAP_BLOCK_DUPLICATE = 1,
  LICHEN_COAP_BLOCK_COMPLETE = 2,
};

struct lichen_coap_block1_receiver {
  uint8_t *body;
  size_t capacity;
  size_t length;
  size_t expected_size;
  uint64_t deadline_ms;
  uint32_t timeout_ms;
  uint8_t largest_szx;
  struct lichen_coap_block_key key;
  bool has_expected_size;
  bool active;
  bool complete;
};

struct lichen_coap_block2_sender {
  uint8_t *snapshot;
  size_t capacity;
  size_t length;
  uint64_t deadline_ms;
  uint32_t timeout_ms;
  uint8_t max_szx;
  struct lichen_coap_block_key key;
  bool active;
};

struct lichen_coap_block2_view {
  const uint8_t *payload;
  size_t payload_len;
  size_t size2;
  struct lichen_coap_block block;
};

size_t lichen_coap_block_size(const struct lichen_coap_block *block);
int lichen_coap_block_offset(const struct lichen_coap_block *block,
                             size_t *offset);
int lichen_coap_block_decode(const uint8_t *value, size_t value_len,
                             struct lichen_coap_block *block);
int lichen_coap_block_encode(const struct lichen_coap_block *block,
                             uint8_t value[3]);
int lichen_coap_block_get_option(const struct coap_packet *packet,
                                 uint16_t option_number,
                                 struct lichen_coap_block *block);
int lichen_coap_block_append_option(struct coap_packet *packet,
                                    uint16_t option_number,
                                    const struct lichen_coap_block *block);
int lichen_coap_block_decode_size(const uint8_t *value, size_t value_len,
                                  size_t *size);
int lichen_coap_block_append_size(struct coap_packet *packet,
                                  uint16_t option_number, size_t size);

int lichen_coap_block1_init(struct lichen_coap_block1_receiver *receiver,
                            uint8_t *body, size_t capacity,
                            uint32_t timeout_ms);
void lichen_coap_block1_reset(struct lichen_coap_block1_receiver *receiver);
bool lichen_coap_block1_expire(struct lichen_coap_block1_receiver *receiver,
                               uint64_t now_ms);
int lichen_coap_block1_receive(struct lichen_coap_block1_receiver *receiver,
                               uint64_t now_ms,
                               const struct lichen_coap_block_key *key,
                               const struct lichen_coap_block *block,
                               bool has_size1, size_t size1,
                               const uint8_t *payload, size_t payload_len,
                               enum lichen_coap_block_result *result);

int lichen_coap_block2_init(struct lichen_coap_block2_sender *sender,
                            uint8_t *snapshot, size_t capacity, uint8_t max_szx,
                            uint32_t timeout_ms);
void lichen_coap_block2_reset(struct lichen_coap_block2_sender *sender);
bool lichen_coap_block2_expire(struct lichen_coap_block2_sender *sender,
                               uint64_t now_ms);
int lichen_coap_block2_start(struct lichen_coap_block2_sender *sender,
                             uint64_t now_ms,
                             const struct lichen_coap_block_key *key,
                             const uint8_t *payload, size_t payload_len);
int lichen_coap_block2_get(struct lichen_coap_block2_sender *sender,
                           uint64_t now_ms,
                           const struct lichen_coap_block_key *key,
                           const struct lichen_coap_block *request,
                           struct lichen_coap_block2_view *view);

uint8_t lichen_coap_block_error_response(int error);

#ifdef __cplusplus
}
#endif

#endif
