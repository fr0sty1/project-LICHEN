/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_keys_format.c
 * @brief IID/fingerprint formatting, base64, trust level conversion
 */

#include <errno.h>
#include <string.h>

#include <lichen/coap_keys.h>
#include "coap_keys_internal.h"
#include <monocypher.h>
#include <monocypher-ed25519.h>

#ifdef CONFIG_TINYCRYPT_SHA256
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#endif

/* --------------------------------------------------------------------------
 * Hex and base64 encoding tables
 * -------------------------------------------------------------------------- */

const char hex_chars[] = "0123456789abcdef";

static const char base64_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* --------------------------------------------------------------------------
 * IID formatting
 * -------------------------------------------------------------------------- */

int lichen_key_iid_to_str(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
			  char *_Nonnull buf, size_t buf_len)
{
	if (iid == NULL || buf == NULL || buf_len < LICHEN_KEY_IID_STR_LEN) {
		return -EINVAL;
	}

	/* Format: xxxx:xxxx:xxxx:xxxx */
	size_t pos = 0;

	for (size_t i = 0; i < LICHEN_KEY_IID_LEN; i++) {
		if (i > 0 && (i % 2) == 0) {
			buf[pos++] = ':';
		}
		buf[pos++] = hex_chars[(iid[i] >> 4) & 0x0f];
		buf[pos++] = hex_chars[iid[i] & 0x0f];
	}
	buf[pos] = '\0';

	return (int)pos;
}

static int hex_char_to_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

int lichen_key_str_to_iid(const char *_Nonnull str, uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN])
{
	if (str == NULL || iid == NULL) {
		return -EINVAL;
	}

	size_t str_len = strlen(str);

	if (str_len != LICHEN_KEY_IID_STR_LEN - 1) {
		return -EINVAL;
	}

	size_t byte_idx = 0;
	size_t str_idx = 0;

	while (byte_idx < LICHEN_KEY_IID_LEN && str_idx < str_len) {
		/* Expect colon every 4 hex chars (2 bytes) */
		if (byte_idx > 0 && (byte_idx % 2) == 0) {
			if (str[str_idx] != ':') {
				return -EINVAL;
			}
			str_idx++;
		}

		int hi = hex_char_to_nibble(str[str_idx++]);
		int lo = hex_char_to_nibble(str[str_idx++]);

		if (hi < 0 || lo < 0) {
			return -EINVAL;
		}

		iid[byte_idx++] = (uint8_t)((hi << 4) | lo);
	}

	if (byte_idx != LICHEN_KEY_IID_LEN) {
		return -EINVAL;
	}

	return 0;
}

/* --------------------------------------------------------------------------
 * Base64 encoding/decoding
 * -------------------------------------------------------------------------- */

size_t base64_encode(const uint8_t *data, size_t len, char *out, size_t out_len)
{
	size_t out_idx = 0;
	size_t i;

	for (i = 0; i + 2 < len; i += 3) {
		if (out_idx + 4 > out_len) {
			return 0;
		}
		out[out_idx++] = base64_chars[(data[i] >> 2) & 0x3f];
		out[out_idx++] = base64_chars[((data[i] & 0x03) << 4) | ((data[i + 1] >> 4) & 0x0f)];
		out[out_idx++] = base64_chars[((data[i + 1] & 0x0f) << 2) | ((data[i + 2] >> 6) & 0x03)];
		out[out_idx++] = base64_chars[data[i + 2] & 0x3f];
	}

	if (i < len) {
		if (out_idx + 4 > out_len) {
			return 0;
		}
		out[out_idx++] = base64_chars[(data[i] >> 2) & 0x3f];
		if (i + 1 < len) {
			out[out_idx++] = base64_chars[((data[i] & 0x03) << 4) |
						      ((data[i + 1] >> 4) & 0x0f)];
			out[out_idx++] = base64_chars[((data[i + 1] & 0x0f) << 2)];
		} else {
			out[out_idx++] = base64_chars[((data[i] & 0x03) << 4)];
			out[out_idx++] = '=';
		}
		out[out_idx++] = '=';
	}

	out[out_idx] = '\0';
	return out_idx;
}

static int base64_decode_char(char c)
{
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	if (c == '+') {
		return 62;
	}
	if (c == '/') {
		return 63;
	}
	if (c == '=') {
		return -2; /* padding */
	}
	return -1;
}

int base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_len)
{
	if (in_len % 4 != 0) {
		return -EINVAL;
	}

	size_t out_idx = 0;

	for (size_t i = 0; i < in_len; i += 4) {
		int v0 = base64_decode_char(in[i]);
		int v1 = base64_decode_char(in[i + 1]);
		int v2 = base64_decode_char(in[i + 2]);
		int v3 = base64_decode_char(in[i + 3]);

		if (v0 < 0 || v1 < 0) {
			return -EINVAL;
		}

		if (out_idx >= out_len) {
			return -ENOMEM;
		}
		out[out_idx++] = (uint8_t)((v0 << 2) | (v1 >> 4));

		if (v2 >= 0) {
			if (out_idx >= out_len) {
				return -ENOMEM;
			}
			out[out_idx++] = (uint8_t)((v1 << 4) | (v2 >> 2));

			if (v3 >= 0) {
				if (out_idx >= out_len) {
					return -ENOMEM;
				}
				out[out_idx++] = (uint8_t)((v2 << 6) | v3);
			}
		}
	}

	return (int)out_idx;
}

/* --------------------------------------------------------------------------
 * Public key fingerprint
 * -------------------------------------------------------------------------- */

int lichen_key_pubkey_fingerprint(const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
				  char *_Nonnull buf, size_t buf_len)
{
	if (pubkey == NULL || buf == NULL || buf_len < LICHEN_KEY_FINGERPRINT_STR_LEN) {
		return -EINVAL;
	}

#ifdef CONFIG_TINYCRYPT_SHA256
	struct tc_sha256_state_struct sha_state;
	uint8_t hash[32];

	if (tc_sha256_init(&sha_state) != TC_CRYPTO_SUCCESS) {
		return -EIO;
	}
	if (tc_sha256_update(&sha_state, pubkey, LICHEN_KEY_PUBKEY_LEN) != TC_CRYPTO_SUCCESS) {
		return -EIO;
	}
	if (tc_sha256_final(hash, &sha_state) != TC_CRYPTO_SUCCESS) {
		return -EIO;
	}

	/* Format: "SHA256:<base64>" */
	memcpy(buf, "SHA256:", 7);
	size_t b64_len = base64_encode(hash, sizeof(hash), buf + 7, buf_len - 7);

	if (b64_len == 0) {
		memset(hash, 0, sizeof(hash));
		return -ENOMEM;
	}

	memset(hash, 0, sizeof(hash));
	return 7 + (int)b64_len;
#else
	memcpy(buf, "SHA256:", 7);
	size_t pos = 7;

	for (int i = 0; i < 8 && pos + 2 < buf_len; i++) {
		buf[pos++] = hex_chars[(pubkey[i] >> 4) & 0x0f];
		buf[pos++] = hex_chars[pubkey[i] & 0x0f];
	}
	buf[pos++] = '.';
	buf[pos++] = '.';
	buf[pos++] = '.';
	buf[pos] = '\0';
	return (int)pos;
#endif
}

/*
 * lichen_key_pubkey_to_iid() is defined in link/identity_addr.c (always
 * built); see the move note there for the CONFIG_LICHEN_IPV6 /
 * CONFIG_LICHEN_COAP_KEYS decoupling rationale.
 */

/* --------------------------------------------------------------------------
 * Trust level conversion
 * -------------------------------------------------------------------------- */

const char *trust_to_str(enum lichen_key_trust trust)
{
	switch (trust) {
	case LICHEN_KEY_TRUST_UNKNOWN:
		return "unknown";
	case LICHEN_KEY_TRUST_TOFU:
		return "tofu";
	case LICHEN_KEY_TRUST_VERIFIED:
		return "verified";
	case LICHEN_KEY_TRUST_DANE:
		return "dane";
	default:
		return "unknown";
	}
}

enum lichen_key_trust str_to_trust(const char *str, size_t len)
{
	if (len == 4 && memcmp(str, "tofu", 4) == 0) {
		return LICHEN_KEY_TRUST_TOFU;
	}
	if (len == 8 && memcmp(str, "verified", 8) == 0) {
		return LICHEN_KEY_TRUST_VERIFIED;
	}
	if (len == 4 && memcmp(str, "dane", 4) == 0) {
		return LICHEN_KEY_TRUST_DANE;
	}
	return LICHEN_KEY_TRUST_UNKNOWN;
}
