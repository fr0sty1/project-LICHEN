/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_keys.c
 * @brief LCI /keys CoAP resource handlers
 *
 * Implements the key store resource per LCI spec section 17.5.5.
 * Keys are stored in memory with trust levels and timestamps.
 *
 * SECURITY: Write operations (PUT/DELETE) require local admin access.
 * The access check verifies the request comes from a local client
 * (loopback or SLIP LCI interface only - NOT the LoRa mesh interface).
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zcbor_decode.h>

#include <lichen/coap_keys.h>
#include <lichen/coap_server.h>
#include <lichen/transport/slip_transport.h>
#include <lichen/oscore.h>
#include <lichen/coap_oscore.h>
#include <lichen/l2/ipv6_addr.h>

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
#include <lichen/oscore.h>
#include <lichen/coap_oscore.h>
#include <lichen/l2/ipv6_addr.h>
#endif

#ifdef CONFIG_TINYCRYPT_SHA256
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#endif

LOG_MODULE_REGISTER(lichen_coap_keys, CONFIG_LICHEN_COAP_KEYS_LOG_LEVEL);

/* Maximum keys to store */
#ifndef CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES
#define CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES 16
#endif
BUILD_ASSERT(CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES <= 16, "CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES >16 risks stack overflow in encode_keys_list_cbor [p0wq]");

/* CBOR content-format code */
#define CBOR_CONTENT_FORMAT 60

/* String keys for LCI key CBOR (per spec section 17.5.5) - consistent with coap_config.c */
#define KEY_IID "iid"
#define KEY_PUBKEY "pubkey"
#define KEY_PUBKEY_FP "pubkey_fp"
#define KEY_TRUST "trust"
#define KEY_FIRST_SEEN "first_seen"
#define KEY_LAST_SEEN "last_seen"
#define KEY_KEYS "keys"

/* Key store */
static struct lichen_key_entry s_keys[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES];
static K_MUTEX_DEFINE(s_mutex);

/* --------------------------------------------------------------------------
 * CBOR helpers (string-keyed encoding per spec)
 * -------------------------------------------------------------------------- */

static void cbor_put_map_header(uint8_t *buf, size_t *off, uint8_t count)
{
	if (count < 24U) {
		buf[(*off)++] = 0xa0U | count;
	} else {
		buf[(*off)++] = 0xb8;
		buf[(*off)++] = count;
	}
}

static void cbor_put_tstr(uint8_t *buf, size_t *off, const char *value)
{
	size_t len = value ? strlen(value) : 0;
	if (len > 0xffffffffU) {
		len = 0xffffffffU;
	}
	if (len < 24U) {
		buf[(*off)++] = 0x60U | (uint8_t)len;
	} else if (len <= UINT8_MAX) {
		buf[(*off)++] = 0x78;
		buf[(*off)++] = (uint8_t)len;
	} else if (len <= 0xffffU) {
		buf[(*off)++] = 0x79;
		buf[(*off)++] = (uint8_t)(len >> 8);
		buf[(*off)++] = (uint8_t)(len & 0xffU);
	} else {
		buf[(*off)++] = 0x7a;
		buf[(*off)++] = (uint8_t)(len >> 24);
		buf[(*off)++] = (uint8_t)(len >> 16);
		buf[(*off)++] = (uint8_t)(len >> 8);
		buf[(*off)++] = (uint8_t)(len & 0xffU);
	}
	memcpy(&buf[*off], value, len);
	*off += len;
}

static void cbor_put_key(uint8_t *buf, size_t *off, const char *key)
{
	cbor_put_tstr(buf, off, key);
}

/* --------------------------------------------------------------------------
 * IID and fingerprint formatting
 * -------------------------------------------------------------------------- */

static const char hex_chars[] = "0123456789abcdef";

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

/* Base64 encoding table */
static const char base64_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const uint8_t *data, size_t len, char *out, size_t out_len)
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

static int base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_len)
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

int lichen_key_pubkey_to_iid(const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
			     uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN])
{
	if (pubkey == NULL || iid == NULL) {
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

	/* IID = SHA-256(pubkey)[0:8] with U/L bit cleared (bit 1 = 0x02)
	 * per RFC 4291 (locally-administered) and LICHEN spec.
	 * Matches _pubkey_to_iid() in Python and lichen_pubkey_to_iid() in ipv6_addr.c.
	 * This enables unified identity across LCI, mesh, and backbone.
	 */
	memcpy(iid, hash, LICHEN_KEY_IID_LEN);
	iid[0] &= ~0x02U;  /* Clear U/L bit */
	memset(hash, 0, sizeof(hash));  /* scrub sensitive material */

	return 0;
#else
	/* Fallback without crypto (insecure, test-only) */
		memcpy(iid, pubkey, LICHEN_KEY_IID_LEN);
		iid[0] &= ~0x02U;
		return 0;
#endif

}

static int key_ct_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
	volatile uint8_t diff = 0U;
	for (size_t i = 0; i < len; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff;
}

/* --------------------------------------------------------------------------
 * Key store implementation
 * -------------------------------------------------------------------------- */

static int find_key_locked(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN])
{
	for (int i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; i++) {
		if (s_keys[i].valid &&
		    key_ct_compare(s_keys[i].iid, iid, LICHEN_KEY_IID_LEN) == 0) {
			return i;
		}
	}
	return -ENOENT;
}

static int find_free_slot_locked(void)
{
	for (int i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; i++) {
		if (!s_keys[i].valid) {
			return i;
		}
	}
	return -ENOSPC;
}

static uint32_t get_unix_time(void)
{
	/* Return uptime as a fallback if no wall clock is available */
	return (uint32_t)(k_uptime_get() / 1000);
}

int lichen_key_store_put(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
			 const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
			 enum lichen_key_trust trust)
{
	int slot;
	uint32_t now = get_unix_time();

	if (iid == NULL || pubkey == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);

	slot = find_key_locked(iid);
	if (slot >= 0) {
		/*
		 * SECURITY: TOFU key pinning - existing keys cannot have their
		 * pubkey changed. Reject if pubkey differs.
		 */
		if (key_ct_compare(s_keys[slot].pubkey, pubkey, LICHEN_KEY_PUBKEY_LEN) != 0) {
			k_mutex_unlock(&s_mutex);
			LOG_WRN("Key update rejected: pubkey mismatch (TOFU violation)");
			return -EEXIST;
		}
		/* Update trust level and last_seen */
		s_keys[slot].trust = trust;
		s_keys[slot].last_seen = now;
		k_mutex_unlock(&s_mutex);
		return 0;
	}

	/* New key */
	slot = find_free_slot_locked();
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOSPC;
	}

	memcpy(s_keys[slot].iid, iid, LICHEN_KEY_IID_LEN);
	memcpy(s_keys[slot].pubkey, pubkey, LICHEN_KEY_PUBKEY_LEN);
	s_keys[slot].trust = trust;
	s_keys[slot].first_seen = now;
	s_keys[slot].last_seen = now;
	s_keys[slot].valid = true;

	k_mutex_unlock(&s_mutex);
	return 0;
}

int lichen_key_store_get(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
			 struct lichen_key_entry *_Nonnull entry)
{
	int slot;

	if (iid == NULL || entry == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);

	slot = find_key_locked(iid);
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}

	*entry = s_keys[slot];
	k_mutex_unlock(&s_mutex);
	return 0;
}

int lichen_key_store_delete(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN])
{
	int slot;

	if (iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);

	slot = find_key_locked(iid);
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}

	memset(&s_keys[slot], 0, sizeof(s_keys[slot]));
	k_mutex_unlock(&s_mutex);
	return 0;
}

size_t lichen_key_store_count(void)
{
	size_t count = 0;

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (int i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; i++) {
		if (s_keys[i].valid) {
			count++;
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

size_t lichen_key_store_list(struct lichen_key_entry *_Nonnull entries,
			     size_t max_entries)
{
	size_t count = 0;

	if (entries == NULL || max_entries == 0) {
		return 0;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (int i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES && count < max_entries; i++) {
		if (s_keys[i].valid) {
			entries[count++] = s_keys[i];
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

int lichen_key_store_touch(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN], uint32_t unix_time)
{
	int slot;

	if (iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);

	slot = find_key_locked(iid);
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}

	s_keys[slot].last_seen = unix_time;
	k_mutex_unlock(&s_mutex);
	return 0;
}

#ifdef CONFIG_LICHEN_COAP_KEYS_TEST_HOOKS
void lichen_key_store_test_reset(void)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	memset(s_keys, 0, sizeof(s_keys));
	k_mutex_unlock(&s_mutex);
}
#endif

/* --------------------------------------------------------------------------
 * Trust level string conversion
 * -------------------------------------------------------------------------- */

static const char *trust_to_str(enum lichen_key_trust trust)
{
	switch (trust) {
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

static enum lichen_key_trust str_to_trust(const char *str, size_t len)
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

/* --------------------------------------------------------------------------
 * CBOR response encoding
 * -------------------------------------------------------------------------- */

/* Max CBOR size for GET /keys list response */
#define KEYS_LIST_CBOR_MAX_SIZE 512

/* Max CBOR size for GET /keys/{iid} single key response */
#define KEY_SINGLE_CBOR_MAX_SIZE 256
#define KEY_LIST_ENTRY_CBOR_MAX_SIZE 192

static size_t encode_iso8601_timestamp(uint32_t unix_time, char *buf, size_t buf_len)
{
	/*
	 * Simple ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
	 * This is a minimal implementation; for production, use a proper
	 * time library or Zephyr's time functions.
	 */
	if (buf_len < 21) {
		return 0;
	}

	/* Calculate year/month/day from Unix timestamp */
	uint32_t days = unix_time / 86400;
	uint32_t secs = unix_time % 86400;
	uint16_t year = 1970;
	uint8_t month = 1;
	uint8_t day = 1;

	static const uint16_t days_in_month[] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};

	while (days >= 365) {
		bool leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
		uint16_t year_days = leap ? 366 : 365;

		if (days < year_days) {
			break;
		}
		days -= year_days;
		year++;
	}

	for (int m = 0; m < 12; m++) {
		uint16_t mdays = days_in_month[m];

		if (m == 1 && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))) {
			mdays = 29;
		}
		if (days < mdays) {
			month = m + 1;
			day = days + 1;
			break;
		}
		days -= mdays;
	}

	uint8_t hour = secs / 3600;
	uint8_t min = (secs % 3600) / 60;
	uint8_t sec = secs % 60;

	int pr = snprintf(buf, buf_len, "%04u-%02u-%02uT%02u:%02u:%02uZ",
		 year, month, day, hour, min, sec);
	if (pr < 0 || (size_t)pr >= buf_len) {
		return 0;
	}
	return (size_t)pr;
}

static size_t encode_keys_list_cbor(uint8_t *buf, size_t buf_size)
{
	size_t off = 0;
	size_t encoded = 0;

	if (buf == NULL || buf_size < 32) {
		return 0;
	}

	/* Outer map: { "keys": [...] } */
	cbor_put_map_header(buf, &off, 1);
	cbor_put_key(buf, &off, KEY_KEYS);

	/* Get all keys */
	struct lichen_key_entry entries[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES];
	size_t n = lichen_key_store_list(entries, ARRAY_SIZE(entries));

	/* Reserve a fixed-width definite array header; patch its count after
	 * bounded entries are encoded so truncation always remains valid CBOR. */
	buf[off++] = 0x98;
	size_t count_offset = off++;

	for (size_t i = 0; i < n; i++) {
		uint8_t entry[KEY_LIST_ENTRY_CBOR_MAX_SIZE];
		size_t entry_off = 0;
		char iid_str[LICHEN_KEY_IID_STR_LEN];
		char fp_str[LICHEN_KEY_FINGERPRINT_STR_LEN];
		char first_str[24];
		char last_str[24];

		lichen_key_iid_to_str(entries[i].iid, iid_str, sizeof(iid_str));
		lichen_key_pubkey_fingerprint(entries[i].pubkey, fp_str, sizeof(fp_str));
		encode_iso8601_timestamp(entries[i].first_seen, first_str, sizeof(first_str));
		encode_iso8601_timestamp(entries[i].last_seen, last_str, sizeof(last_str));

		/* Each key entry: 5 fields */
		cbor_put_map_header(entry, &entry_off, 5);

		cbor_put_key(entry, &entry_off, KEY_IID);
		cbor_put_tstr(entry, &entry_off, iid_str);

		cbor_put_key(entry, &entry_off, KEY_PUBKEY_FP);
		cbor_put_tstr(entry, &entry_off, fp_str);

		cbor_put_key(entry, &entry_off, KEY_TRUST);
		cbor_put_tstr(entry, &entry_off, trust_to_str(entries[i].trust));

		cbor_put_key(entry, &entry_off, KEY_FIRST_SEEN);
		cbor_put_tstr(entry, &entry_off, first_str);

		cbor_put_key(entry, &entry_off, KEY_LAST_SEEN);
		cbor_put_tstr(entry, &entry_off, last_str);

		if (off + entry_off > buf_size) {
			break;
		}
		memcpy(&buf[off], entry, entry_off);
		off += entry_off;
		encoded++;
	}

	buf[count_offset] = (uint8_t)encoded;
	return off;
}

#ifdef CONFIG_LICHEN_COAP_KEYS_TEST_HOOKS
size_t lichen_key_store_test_encode_list(uint8_t *_Nonnull buf, size_t buf_size)
{
	return encode_keys_list_cbor(buf, buf_size);
}
#endif

static size_t encode_key_single_cbor(const struct lichen_key_entry *entry,
				     uint8_t *buf, size_t buf_size)
{
	size_t off = 0;
	char iid_str[LICHEN_KEY_IID_STR_LEN];
	char first_str[24];
	char last_str[24];

	if (entry == NULL || buf == NULL || buf_size < 100) {
		return 0; /* prevents underflow in offset checks */
	}

	lichen_key_iid_to_str(entry->iid, iid_str, sizeof(iid_str));
	encode_iso8601_timestamp(entry->first_seen, first_str, sizeof(first_str));
	encode_iso8601_timestamp(entry->last_seen, last_str, sizeof(last_str));

	/* 5 fields: iid, pubkey, trust, first_seen, last_seen */
	cbor_put_map_header(buf, &off, 5);

	cbor_put_key(buf, &off, KEY_IID);
	cbor_put_tstr(buf, &off, iid_str);

	/* Pubkey as base64 string per spec */
	cbor_put_key(buf, &off, KEY_PUBKEY);
	char pubkey_b64[48];
	base64_encode(entry->pubkey, LICHEN_KEY_PUBKEY_LEN, pubkey_b64, sizeof(pubkey_b64));
	cbor_put_tstr(buf, &off, pubkey_b64);

	cbor_put_key(buf, &off, KEY_TRUST);
	cbor_put_tstr(buf, &off, trust_to_str(entry->trust));

	cbor_put_key(buf, &off, KEY_FIRST_SEEN);
	cbor_put_tstr(buf, &off, first_str);

	cbor_put_key(buf, &off, KEY_LAST_SEEN);
	cbor_put_tstr(buf, &off, last_str);

	return off;
}

static int decode_key_put_cbor(const uint8_t *payload, size_t payload_len,
			       uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
			       enum lichen_key_trust *_Nonnull trust)
{
	if (payload == NULL || pubkey == NULL || trust == NULL || payload_len < 5) {
		return -EINVAL;
	}

	ZCBOR_STATE_D(state, 4, payload, payload_len, 1, 0);

	if (!zcbor_map_start_decode(state)) {
		return -EINVAL;
	}

	bool has_pubkey = false;
	*trust = LICHEN_KEY_TRUST_VERIFIED;

	while (!zcbor_array_at_end(state)) {
		struct zcbor_string key;

		if (!zcbor_tstr_decode(state, &key)) {
			(void)zcbor_list_map_end_force_decode(state);
			return -EINVAL;
		}

		if (key.len == sizeof(KEY_PUBKEY) - 1 &&
		    memcmp(key.value, KEY_PUBKEY, key.len) == 0) {
			struct zcbor_string val;
			if (!zcbor_tstr_decode(state, &val) || val.len == 0) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
			int dec_len = base64_decode((const char *)val.value, val.len,
						    pubkey, LICHEN_KEY_PUBKEY_LEN);
			if (dec_len != LICHEN_KEY_PUBKEY_LEN) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
			has_pubkey = true;
		} else if (key.len == sizeof(KEY_TRUST) - 1 &&
			   memcmp(key.value, KEY_TRUST, key.len) == 0) {
			struct zcbor_string val;
			if (!zcbor_tstr_decode(state, &val) || val.len == 0) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
			*trust = str_to_trust((const char *)val.value, val.len);
		} else {
			if (!zcbor_any_skip(state, NULL)) {
				(void)zcbor_list_map_end_force_decode(state);
				return -EINVAL;
			}
		}
	}

	if (!zcbor_map_end_decode(state) || !has_pubkey) {
		return -EINVAL;
	}

	return 0;
}

/* --------------------------------------------------------------------------
 * Access control
 * -------------------------------------------------------------------------- */

/*
 * SECURITY: Check if request comes from a local admin client.
 * Write operations (PUT/DELETE) require local access.
 *
 * Link-local addresses are only accepted from the SLIP LCI interface,
 * NOT from the LoRa mesh interface. This prevents mesh neighbors from
 * modifying the key store via PUT/DELETE /keys/{iid}.
 */
bool lichen_coap_is_local_admin(const struct sockaddr *addr, socklen_t addr_len)
{
	if (addr == NULL) {
		/* Unit test context */
		return IS_ENABLED(CONFIG_ZTEST);
	}

	if (addr_len < sizeof(struct sockaddr_in6) || addr->sa_family != AF_INET6) {
		return false;
	}

	const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;

	/* Loopback is always local admin */
	if (net_ipv6_is_addr_loopback((struct in6_addr *)&in6->sin6_addr)) {
		return true;
	}

	/*
	 * SECURITY: Link-local addresses require interface verification.
	 * Only accept from SLIP LCI interface - reject LoRa mesh traffic.
	 */
	if (net_ipv6_is_ll_addr(&in6->sin6_addr)) {
		struct net_if *slip_iface = slip_transport_iface_get();

		if (slip_iface == NULL) {
			/* SLIP not available - reject link-local admin access */
			LOG_WRN("Admin rejected: SLIP interface not available");
			return false;
		}

		int slip_idx = net_if_get_by_iface(slip_iface);

		/*
		 * sin6_scope_id holds the interface index for link-local.
		 * Only accept if it matches the SLIP LCI interface.
		 */
		if (in6->sin6_scope_id != (uint32_t)slip_idx) {
			LOG_WRN("Admin rejected: link-local from wrong interface "
				"(scope_id=%u, slip_idx=%d)",
				in6->sin6_scope_id, slip_idx);
			return false;
		}

		return true;
	}
	return false;
}

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
/*
 * Protected OSCORE response helper for /keys handlers.
 * Symmetric with deaddrop_oscore_respond in coap_dtn.c.
 * Uses coap_oscore_protect_response and falls back on error.
 */
static int keys_oscore_respond(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len,
			       struct oscore_ctx *ctx,
			       const uint8_t *piv, size_t piv_len,
			       uint8_t code)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	int ret = coap_oscore_protect_response(ctx, piv, piv_len, request, code,
					       NULL, 0, &resp, buf, sizeof(buf));
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}
	ret = coap_resource_send(resource, &resp, addr, addr_len, NULL);
	return ret;
}
#endif /* CONFIG_LICHEN_COAP_SERVER_OSCORE */

/* --------------------------------------------------------------------------
 * CoAP resource handlers
 * --------------------------------------------------------------------------
 */

/*
 * GET /keys - List all keys with fingerprints and trust levels
 */
static int keys_list_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[KEYS_LIST_CBOR_MAX_SIZE];
	size_t len = encode_keys_list_cbor(cbor_buf, sizeof(cbor_buf));

	if (len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, len);
}


/*
 * GET /keys/{iid} - Get single key with full pubkey
 */
static int keys_single_get(struct coap_resource *resource,
			   struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_option options[4];
	int opt_count;
	uint8_t iid[LICHEN_KEY_IID_LEN];
	struct lichen_key_entry entry;
	uint8_t cbor_buf[KEY_SINGLE_CBOR_MAX_SIZE];
	size_t len;
	int ret;

	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));
	if (opt_count < 2) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	char iid_str[LICHEN_KEY_IID_STR_LEN];

	if (options[1].len >= LICHEN_KEY_IID_STR_LEN) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	memcpy(iid_str, options[1].value, options[1].len);
	iid_str[options[1].len] = '\0';

	ret = lichen_key_str_to_iid(iid_str, iid);
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	ret = lichen_key_store_get(iid, &entry);
	if (ret == -ENOENT) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	len = encode_key_single_cbor(&entry, cbor_buf, sizeof(cbor_buf));
	if (len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, len);
}

/*
 * PUT /keys/{iid} - Add/update key (requires admin)
 */
static int keys_single_put(struct coap_resource *resource,
			   struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_option options[4];
	int opt_count;
	uint8_t iid[LICHEN_KEY_IID_LEN];
	uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];
	enum lichen_key_trust trust;
	uint16_t payload_len = 0;
	const uint8_t *payload = NULL;
	int ret;

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	struct oscore_ctx *ctx = NULL;
	uint8_t peer_eui64[8] = {0};
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = sizeof(piv);
	bool is_protected = coap_oscore_is_protected(request);
	if (is_protected) {
		if (addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
			const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
			memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
			lichen_eui64_to_iid(peer_eui64, peer_eui64);
		}
		if (oscore_ctx_get_by_eui64(peer_eui64, &ctx) != OSCORE_OK || ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		uint8_t plain[LICHEN_COAP_SERVER_MAX_PAYLOAD];
		size_t plain_len = sizeof(plain);
		int r = coap_oscore_unprotect_request(ctx, request, &orig_code, opts, &opt_len,
						      plain, &plain_len, piv, &piv_len);
		if (r != OSCORE_OK) {
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
		if (orig_code != COAP_METHOD_PUT) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
		payload = plain;
		payload_len = (uint16_t)plain_len;
	}
#endif

	/* SECURITY: Require local admin access for write operations */
	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		LOG_WRN("PUT /keys rejected: not local admin");
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_UNAUTHORIZED);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
	}

	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));
	if (opt_count < 2) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	char iid_str[LICHEN_KEY_IID_STR_LEN];

	if (options[1].len >= LICHEN_KEY_IID_STR_LEN) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	memcpy(iid_str, options[1].value, options[1].len);
	iid_str[options[1].len] = '\0';

	ret = lichen_key_str_to_iid(iid_str, iid);
	if (ret < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	/* Parse payload - from unprotect if OSCORE-protected, else from CoAP packet */
	if (payload == NULL) {
		payload = coap_packet_get_payload(request, &payload_len);
	}
	if (payload == NULL || payload_len == 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	ret = decode_key_put_cbor(payload, payload_len, pubkey, &trust);
	if (ret < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	/* Store key */
	ret = lichen_key_store_put(iid, pubkey, trust);
	if (ret == -EEXIST) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_CONFLICT);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_CONFLICT, 0, NULL, 0);
	}
	if (ret == -ENOSPC) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0, NULL, 0);
	}
	if (ret < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_INTERNAL_ERROR);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	LOG_INF("Key added/updated for IID %s", iid_str);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && ctx != NULL && piv_len > 0) {
		return keys_oscore_respond(resource, request, addr, addr_len,
					   ctx, piv, piv_len, COAP_RESPONSE_CODE_CHANGED);
	}
#endif
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CHANGED, 0, NULL, 0);
}

static int keys_single_delete(struct coap_resource *resource,
			      struct coap_packet *request,
			      struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_option options[4];
	int opt_count;
	uint8_t iid[LICHEN_KEY_IID_LEN];
	int ret;

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	struct oscore_ctx *ctx = NULL;
	uint8_t peer_eui64[8] = {0};
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = sizeof(piv);
	bool is_protected = coap_oscore_is_protected(request);
	if (is_protected) {
		if (addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
			const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
			memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
			lichen_eui64_to_iid(peer_eui64, peer_eui64);
		}
		if (oscore_ctx_get_by_eui64(peer_eui64, &ctx) != OSCORE_OK || ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		uint8_t plain[16]; /* DELETE has no payload */
		size_t plain_len = sizeof(plain);
		int r = coap_oscore_unprotect_request(ctx, request, &orig_code, opts, &opt_len,
						      plain, &plain_len, piv, &piv_len);
		if (r != OSCORE_OK) {
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
		if (orig_code != COAP_METHOD_DELETE) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
	}
#endif

	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		LOG_WRN("DELETE /keys rejected: not local admin");
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_UNAUTHORIZED);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
	}

	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));
	if (opt_count < 2) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	char iid_str[LICHEN_KEY_IID_STR_LEN];

	if (options[1].len >= LICHEN_KEY_IID_STR_LEN) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	memcpy(iid_str, options[1].value, options[1].len);
	iid_str[options[1].len] = '\0';

	ret = lichen_key_str_to_iid(iid_str, iid);
	if (ret < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	ret = lichen_key_store_delete(iid);
	if (ret == -ENOENT) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_NOT_FOUND);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}
	if (ret < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_INTERNAL_ERROR);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	LOG_INF("Key deleted for IID %s", iid_str);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && ctx != NULL && piv_len > 0) {
		return keys_oscore_respond(resource, request, addr, addr_len,
					   ctx, piv, piv_len, COAP_RESPONSE_CODE_DELETED);
	}
#endif
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_DELETED, 0, NULL, 0);
}

/* --------------------------------------------------------------------------
 * CoAP resource definitions
 * -------------------------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LICHEN_COAP_KEYS)

static const char * const keys_path[] = { "keys", NULL };
COAP_RESOURCE_DEFINE(keys_list, lichen_coap_server, {
	.get = keys_list_get,
	.path = keys_path,
});

/*
 * Wildcard path for /keys/{iid}
 * Requires CONFIG_COAP_URI_WILDCARD=y
 */
static const char * const keys_single_path[] = { "keys", "+", NULL };
COAP_RESOURCE_DEFINE(keys_single, lichen_coap_server, {
	.get = keys_single_get,
	.put = keys_single_put,
	.del = keys_single_delete,
	.path = keys_single_path,
});

#endif /* CONFIG_LICHEN_COAP_KEYS */

