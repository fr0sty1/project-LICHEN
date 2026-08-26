/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_keys_internal.h
 * @brief Internal declarations for coap_keys split implementation
 */

#ifndef COAP_KEYS_INTERNAL_H_
#define COAP_KEYS_INTERNAL_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <zephyr/kernel.h>
#include <lichen/coap_keys.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum keys to store */
#ifndef CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES
#define CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES 16
#endif

#ifndef CONFIG_LICHEN_COAP_KEYS_MAX_GROUPS
#define CONFIG_LICHEN_COAP_KEYS_MAX_GROUPS 4
#endif

/* CBOR content-format code */
#define CBOR_CONTENT_FORMAT 60

/* String keys for LCI key CBOR (per spec section 17.5.5) */
#define KEY_IID "iid"
#define KEY_PUBKEY "pubkey"
#define KEY_PUBKEY_FP "pubkey_fp"
#define KEY_TRUST "trust"
#define KEY_FIRST_SEEN "first_seen"
#define KEY_LAST_SEEN "last_seen"
#define KEY_KEYS "keys"

/* Max CBOR size for responses */
#define KEYS_LIST_CBOR_MAX_SIZE 512
#define KEY_SINGLE_CBOR_MAX_SIZE 256
#define KEY_LIST_ENTRY_CBOR_MAX_SIZE 192

/* --------------------------------------------------------------------------
 * CBOR context for overflow-safe encoding
 * -------------------------------------------------------------------------- */

struct cbor_ctx {
	uint8_t *buf;
	size_t off;
	size_t size;
	bool overflow;
};

void cbor_ctx_init(struct cbor_ctx *ctx, uint8_t *buf, size_t size);
bool cbor_check_space(struct cbor_ctx *ctx, size_t n);
void cbor_put_map_header(struct cbor_ctx *ctx, uint8_t count);
void cbor_put_tstr(struct cbor_ctx *ctx, const char *value);
void cbor_put_key(struct cbor_ctx *ctx, const char *key);

/* --------------------------------------------------------------------------
 * Format helpers (coap_keys_format.c)
 * -------------------------------------------------------------------------- */

extern const char hex_chars[];

size_t base64_encode(const uint8_t *data, size_t len, char *out, size_t out_len);
int base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_len);
const char *trust_to_str(enum lichen_key_trust trust);
enum lichen_key_trust str_to_trust(const char *str, size_t len);

/* --------------------------------------------------------------------------
 * CBOR encoding/decoding (coap_keys_cbor.c)
 * -------------------------------------------------------------------------- */

size_t encode_iso8601_timestamp(uint32_t unix_time, char *buf, size_t buf_len);
size_t encode_keys_list_cbor(uint8_t *buf, size_t buf_size);
size_t encode_key_single_cbor(const struct lichen_key_entry *entry,
			      uint8_t *buf, size_t buf_size);
int decode_key_put_cbor(const uint8_t *payload, size_t payload_len,
			uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
			enum lichen_key_trust *_Nonnull trust);

/* --------------------------------------------------------------------------
 * Key store internals (coap_keys_store.c)
 * -------------------------------------------------------------------------- */

extern struct lichen_key_entry s_keys[];
extern struct k_mutex s_mutex;

int find_key_locked(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN]);
int find_free_slot_locked(void);
uint32_t get_unix_time(void);

#ifdef __cplusplus
}
#endif

#endif /* COAP_KEYS_INTERNAL_H_ */
