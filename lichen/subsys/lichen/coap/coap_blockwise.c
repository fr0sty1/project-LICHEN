/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/coap_blockwise.h>

#include <errno.h>
#include <string.h>

static bool block_valid(const struct lichen_coap_block *block) {
  return block != NULL && block->szx <= 6U &&
         block->num <= LICHEN_COAP_BLOCK_MAX_NUM;
}

static bool option_number_valid(uint16_t option_number) {
  return option_number == COAP_OPTION_BLOCK1 ||
         option_number == COAP_OPTION_BLOCK2;
}

static bool size_option_number_valid(uint16_t option_number) {
  return option_number == COAP_OPTION_SIZE1 ||
         option_number == COAP_OPTION_SIZE2;
}

static bool key_valid(const struct lichen_coap_block_key *key) {
  return key != NULL && key->peer_id_len > 0U &&
         key->peer_id_len <= sizeof(key->peer_id) &&
         key->token_len <= sizeof(key->token) &&
         (!key->protected_message || key->oscore_context_id != 0U);
}

static bool key_equal(const struct lichen_coap_block_key *a,
                      const struct lichen_coap_block_key *b) {
  return a->peer_id_len == b->peer_id_len && a->token_len == b->token_len &&
         a->resource_id == b->resource_id &&
         a->oscore_context_id == b->oscore_context_id &&
         a->protected_message == b->protected_message &&
         memcmp(a->peer_id, b->peer_id, a->peer_id_len) == 0 &&
         memcmp(a->token, b->token, a->token_len) == 0;
}

static uint64_t deadline(uint64_t now_ms, uint32_t timeout_ms) {
  return UINT64_MAX - now_ms < timeout_ms ? UINT64_MAX : now_ms + timeout_ms;
}

size_t lichen_coap_block_size(const struct lichen_coap_block *block) {
  return block_valid(block) ? ((size_t)1U << (block->szx + 4U)) : 0U;
}

int lichen_coap_block_offset(const struct lichen_coap_block *block,
                             size_t *offset) {
  size_t block_size = lichen_coap_block_size(block);

  if (offset == NULL || block_size == 0U ||
      block->num > SIZE_MAX / block_size) {
    return -EINVAL;
  }
  *offset = (size_t)block->num * block_size;
  return 0;
}

int lichen_coap_block_decode(const uint8_t *value, size_t value_len,
                             struct lichen_coap_block *block) {
  uint32_t packed = 0U;

  if (value == NULL || block == NULL || value_len == 0U || value_len > 3U) {
    return -EBADMSG;
  }
  if (value_len > 1U && value[0] == 0U) {
    return -EBADMSG;
  }
  for (size_t i = 0U; i < value_len; i++) {
    packed = (packed << 8) | value[i];
  }
  block->szx = (uint8_t)(packed & 0x07U);
  block->more = (packed & 0x08U) != 0U;
  block->num = packed >> 4;
  return block_valid(block) ? 0 : -EBADMSG;
}

int lichen_coap_block_encode(const struct lichen_coap_block *block,
                             uint8_t value[3]) {
  uint32_t packed;

  if (!block_valid(block) || value == NULL) {
    return -EINVAL;
  }
  packed = (block->num << 4) | ((uint32_t)block->more << 3) | block->szx;
  if (packed <= UINT8_MAX) {
    value[0] = (uint8_t)packed;
    return 1;
  }
  if (packed <= UINT16_MAX) {
    value[0] = (uint8_t)(packed >> 8);
    value[1] = (uint8_t)packed;
    return 2;
  }
  value[0] = (uint8_t)(packed >> 16);
  value[1] = (uint8_t)(packed >> 8);
  value[2] = (uint8_t)packed;
  return 3;
}

int lichen_coap_block_get_option(const struct coap_packet *packet,
                                 uint16_t option_number,
                                 struct lichen_coap_block *block) {
  struct coap_option options[2];
  int count;

  if (packet == NULL || block == NULL || !option_number_valid(option_number)) {
    return -EINVAL;
  }
  count =
      coap_find_options(packet, option_number, options, ARRAY_SIZE(options));
  if (count == 0) {
    return -ENOENT;
  }
  if (count != 1) {
    return -EBADMSG;
  }
  return lichen_coap_block_decode(options[0].value, options[0].len, block);
}

int lichen_coap_block_append_option(struct coap_packet *packet,
                                    uint16_t option_number,
                                    const struct lichen_coap_block *block) {
  uint8_t value[3];
  int len;

  if (packet == NULL || !option_number_valid(option_number)) {
    return -EINVAL;
  }
  len = lichen_coap_block_encode(block, value);
  return len < 0 ? len
                 : coap_packet_append_option(packet, option_number, value,
                                             (uint16_t)len);
}

int lichen_coap_block_decode_size(const uint8_t *value, size_t value_len,
                                  size_t *size) {
  uint32_t decoded = 0U;

  if (size == NULL || value_len > 4U || (value_len > 0U && value == NULL) ||
      (value_len > 1U && value[0] == 0U)) {
    return -EBADMSG;
  }
  for (size_t i = 0U; i < value_len; i++) {
    decoded = (decoded << 8) | value[i];
  }
  *size = decoded;
  return 0;
}

int lichen_coap_block_append_size(struct coap_packet *packet,
                                  uint16_t option_number, size_t size) {
  uint8_t bytes[4] = {0};
  size_t len;

  if (packet == NULL || !size_option_number_valid(option_number) ||
      size > UINT32_MAX) {
    return -EINVAL;
  }
  if (size == 0U) {
    len = 0U;
  } else if (size <= UINT8_MAX) {
    len = 1U;
  } else if (size <= UINT16_MAX) {
    len = 2U;
  } else if (size <= 0xffffffU) {
    len = 3U;
  } else {
    len = 4U;
  }
  for (size_t i = 0U; i < len; i++) {
    bytes[i] = (uint8_t)(size >> (8U * (len - i - 1U)));
  }
  return coap_packet_append_option(packet, option_number, bytes, len);
}

int lichen_coap_block1_init(struct lichen_coap_block1_receiver *receiver,
                            uint8_t *body, size_t capacity,
                            uint32_t timeout_ms) {
  if (receiver == NULL || body == NULL || capacity == 0U ||
      capacity > LICHEN_COAP_BLOCK_MAX_BODY || timeout_ms == 0U) {
    return -EINVAL;
  }
  memset(receiver, 0, sizeof(*receiver));
  receiver->body = body;
  receiver->capacity = capacity;
  receiver->timeout_ms = timeout_ms;
  return 0;
}

void lichen_coap_block1_reset(struct lichen_coap_block1_receiver *receiver) {
  if (receiver == NULL) {
    return;
  }
  receiver->length = 0U;
  receiver->expected_size = 0U;
  receiver->deadline_ms = 0U;
  receiver->largest_szx = 0U;
  memset(&receiver->key, 0, sizeof(receiver->key));
  receiver->has_expected_size = false;
  receiver->active = false;
  receiver->complete = false;
}

bool lichen_coap_block1_expire(struct lichen_coap_block1_receiver *receiver,
                               uint64_t now_ms) {
  if (receiver == NULL || !receiver->active || now_ms < receiver->deadline_ms) {
    return false;
  }
  lichen_coap_block1_reset(receiver);
  return true;
}

int lichen_coap_block1_receive(struct lichen_coap_block1_receiver *receiver,
                               uint64_t now_ms,
                               const struct lichen_coap_block_key *key,
                               const struct lichen_coap_block *block,
                               bool has_size1, size_t size1,
                               const uint8_t *payload, size_t payload_len,
                               enum lichen_coap_block_result *result) {
  size_t block_size;
  size_t offset;
  bool expired;

  if (receiver == NULL || result == NULL || !key_valid(key) ||
      !block_valid(block) || (payload == NULL && payload_len > 0U)) {
    return -EINVAL;
  }
  block_size = lichen_coap_block_size(block);
  if ((block->more && payload_len != block_size) || payload_len > block_size ||
      lichen_coap_block_offset(block, &offset) < 0) {
    return -EBADMSG;
  }
  expired = lichen_coap_block1_expire(receiver, now_ms);
  if (!receiver->active) {
    if (block->num != 0U) {
      return expired ? -ETIMEDOUT : -EAGAIN;
    }
    if ((has_size1 && size1 > receiver->capacity) ||
        (has_size1 && size1 < payload_len) ||
        payload_len > receiver->capacity ||
        (has_size1 && !block->more && size1 != payload_len)) {
      return has_size1 && size1 > receiver->capacity ? -EMSGSIZE : -EBADMSG;
    }
    receiver->key = *key;
    receiver->largest_szx = block->szx;
    receiver->has_expected_size = has_size1;
    receiver->expected_size = size1;
    receiver->active = true;
  } else {
    if (!key_equal(&receiver->key, key)) {
      return -EACCES;
    }
    if (block->szx > receiver->largest_szx ||
        (has_size1 && receiver->has_expected_size &&
         size1 != receiver->expected_size) ||
        (has_size1 && !receiver->has_expected_size)) {
      return -EEXIST;
    }
  }
  if (offset < receiver->length) {
    bool original_more =
        offset + payload_len < receiver->length || !receiver->complete;

    if (payload_len > receiver->length - offset ||
        (payload_len > 0U &&
         memcmp(receiver->body + offset, payload, payload_len) != 0) ||
        block->more != original_more) {
      return -EEXIST;
    }
    receiver->deadline_ms = deadline(now_ms, receiver->timeout_ms);
    *result = LICHEN_COAP_BLOCK_DUPLICATE;
    return 0;
  }
  if (offset > receiver->length || receiver->complete) {
    return -EAGAIN;
  }
  if (payload_len > receiver->capacity - receiver->length) {
    return -EMSGSIZE;
  }
  if (receiver->has_expected_size &&
      receiver->length + payload_len > receiver->expected_size) {
    return -EBADMSG;
  }
  if (!block->more && receiver->has_expected_size &&
      receiver->length + payload_len != receiver->expected_size) {
    return -EBADMSG;
  }
  if (payload_len > 0U) {
    memcpy(receiver->body + receiver->length, payload, payload_len);
  }
  receiver->length += payload_len;
  receiver->deadline_ms = deadline(now_ms, receiver->timeout_ms);
  receiver->complete = !block->more;
  *result = receiver->complete ? LICHEN_COAP_BLOCK_COMPLETE
                               : LICHEN_COAP_BLOCK_ACCEPTED;
  return 0;
}

int lichen_coap_block2_init(struct lichen_coap_block2_sender *sender,
                            uint8_t *snapshot, size_t capacity, uint8_t max_szx,
                            uint32_t timeout_ms) {
  if (sender == NULL || snapshot == NULL || capacity == 0U ||
      capacity > LICHEN_COAP_BLOCK_MAX_BODY || max_szx > 6U ||
      timeout_ms == 0U) {
    return -EINVAL;
  }
  memset(sender, 0, sizeof(*sender));
  sender->snapshot = snapshot;
  sender->capacity = capacity;
  sender->max_szx = max_szx;
  sender->timeout_ms = timeout_ms;
  return 0;
}

void lichen_coap_block2_reset(struct lichen_coap_block2_sender *sender) {
  if (sender == NULL) {
    return;
  }
  sender->length = 0U;
  sender->deadline_ms = 0U;
  memset(&sender->key, 0, sizeof(sender->key));
  sender->active = false;
}

bool lichen_coap_block2_expire(struct lichen_coap_block2_sender *sender,
                               uint64_t now_ms) {
  if (sender == NULL || !sender->active || now_ms < sender->deadline_ms) {
    return false;
  }
  lichen_coap_block2_reset(sender);
  return true;
}

int lichen_coap_block2_start(struct lichen_coap_block2_sender *sender,
                             uint64_t now_ms,
                             const struct lichen_coap_block_key *key,
                             const uint8_t *payload, size_t payload_len) {
  if (sender == NULL || !key_valid(key) ||
      (payload == NULL && payload_len > 0U)) {
    return -EINVAL;
  }
  if (payload_len > sender->capacity) {
    return -EMSGSIZE;
  }
  if (sender->active && !lichen_coap_block2_expire(sender, now_ms)) {
    if (!key_equal(&sender->key, key)) {
      return -EBUSY;
    }
    if (sender->length != payload_len ||
        (payload_len > 0U &&
         memcmp(sender->snapshot, payload, payload_len) != 0)) {
      return -EEXIST;
    }
    sender->deadline_ms = deadline(now_ms, sender->timeout_ms);
    return 0;
  }
  if (payload_len > 0U) {
    memcpy(sender->snapshot, payload, payload_len);
  }
  sender->length = payload_len;
  sender->key = *key;
  sender->deadline_ms = deadline(now_ms, sender->timeout_ms);
  sender->active = true;
  return 0;
}

int lichen_coap_block2_get(struct lichen_coap_block2_sender *sender,
                           uint64_t now_ms,
                           const struct lichen_coap_block_key *key,
                           const struct lichen_coap_block *request,
                           struct lichen_coap_block2_view *view) {
  struct lichen_coap_block wanted = {0};
  size_t requested_offset;
  size_t response_size;
  size_t end;

  if (sender == NULL || view == NULL || !key_valid(key) ||
      (request != NULL && !block_valid(request))) {
    return -EINVAL;
  }
  if (lichen_coap_block2_expire(sender, now_ms) || !sender->active) {
    return -ETIMEDOUT;
  }
  if (!key_equal(&sender->key, key)) {
    return -EACCES;
  }
  if (request != NULL) {
    if (request->more) {
      return -EBADMSG;
    }
    wanted = *request;
  } else {
    wanted.szx = sender->max_szx;
  }
  if (lichen_coap_block_offset(&wanted, &requested_offset) < 0) {
    return -ERANGE;
  }
  wanted.szx = MIN(wanted.szx, sender->max_szx);
  response_size = lichen_coap_block_size(&wanted);
  if (requested_offset > sender->length ||
      (sender->length > 0U && requested_offset == sender->length)) {
    return -ERANGE;
  }
  wanted.num = (uint32_t)(requested_offset / response_size);
  end = MIN(requested_offset + response_size, sender->length);
  wanted.more = end < sender->length;
  view->payload = sender->snapshot + requested_offset;
  view->payload_len = end - requested_offset;
  view->size2 = sender->length;
  view->block = wanted;
  sender->deadline_ms = deadline(now_ms, sender->timeout_ms);
  return 0;
}

uint8_t lichen_coap_block_error_response(int error) {
  switch (error) {
  case -EACCES:
    return COAP_RESPONSE_CODE_UNAUTHORIZED;
  case -EAGAIN:
  case -ETIMEDOUT:
    return COAP_RESPONSE_CODE_INCOMPLETE;
  case -EEXIST:
  case -EALREADY:
  case -EBUSY:
    return COAP_RESPONSE_CODE_CONFLICT;
  case -EMSGSIZE:
    return COAP_RESPONSE_CODE_REQUEST_TOO_LARGE;
  case -ENOMEM:
    return COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE;
  default:
    return COAP_RESPONSE_CODE_BAD_OPTION;
  }
}
