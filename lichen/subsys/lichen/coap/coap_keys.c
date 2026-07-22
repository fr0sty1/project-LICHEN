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

#include <lichen/coap_keys.h>
#include <lichen/transport/slip_transport.h>

#ifdef CONFIG_TINYCRYPT_SHA256
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#endif

LOG_MODULE_REGISTER(lichen_coap_keys, CONFIG_LICHEN_COAP_KEYS_LOG_LEVEL);

#ifndef CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES
#define CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES 16
#endif
BUILD_ASSERT(CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES <= 16, "CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES >16 risks stack overflow in encode_keys_list_cbor (project-LICHEN-vw14)");

/* CBOR content-format code */
#define CBOR_CONTENT_FORMAT 60

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
	size_t len = strlen(value);

	if (len < 24U) {
		buf[(*off)++] = 0x60U | (uint8_t)len;
	} else if (len <= UINT8_MAX) {
		buf[(*off)++] = 0x78;
		buf[(*off)++] = (uint8_t)len;
	} else {
		buf[(*off)++] = 0x79;
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
<<<<<<< HEAD
		if (out_idx + 4 > out_len) {
=======
		if (out_idx + 5 > out_len) {
>>>>>>> origin/integration/worker7-20260722
			return 0;
		}
		out[out_idx++] = base64_chars[(data[i] >> 2) & 0x3f];
		out[out_idx++] = base64_chars[((data[i] & 0x03) << 4) | ((data[i + 1] >> 4) & 0x0f)];
		out[out_idx++] = base64_chars[((data[i + 1] & 0x0f) << 2) | ((data[i + 2] >> 6) & 0x03)];
		out[out_idx++] = base64_chars[data[i + 2] & 0x3f];
	}

	if (i < len) {
<<<<<<< HEAD
		if (out_idx + 4 > out_len) {
=======
		if (out_idx + 5 > out_len) {
>>>>>>> origin/integration/worker7-20260722
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
		return -ENOMEM;
	}

	return 7 + (int)b64_len;
#else
	/* Fallback: truncated hex of pubkey (not a real fingerprint) */
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

int lichen_key_pubkey_to_iid(const uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN], uint8_t iid[LICHEN_KEY_IID_LEN]) {
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
	memcpy(iid, hash, LICHEN_KEY_IID_LEN);
	iid[0] &= ~0x02U;
	memset(hash, 0, sizeof(hash));
	return 0;
#else
	return -ENOSYS;
#endif
}

/* --------------------------------------------------------------------------
 * Key store implementation
 * -------------------------------------------------------------------------- */

static int find_key_locked(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN])
{
	for (int i = 0; i < CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES; i++) {
		if (s_keys[i].valid &&
		    memcmp(s_keys[i].iid, iid, LICHEN_KEY_IID_LEN) == 0) {
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
	return -ENOMEM;
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
		if (memcmp(s_keys[slot].pubkey, pubkey, LICHEN_KEY_PUBKEY_LEN) != 0) {
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
		return -ENOMEM;
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

size_t lichen_key_store_list(struct lichen_key_entry *entries, size_t max_entries)
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

	snprintf(buf, buf_len, "%04u-%02u-%02uT%02u:%02u:%02uZ",
		 year, month, day, hour, min, sec);
	return strlen(buf);
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
	cbor_put_key(buf, &off, "keys");

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

		cbor_put_key(entry, &entry_off, "iid");
		cbor_put_tstr(entry, &entry_off, iid_str);

		cbor_put_key(entry, &entry_off, "pubkey_fp");
		cbor_put_tstr(entry, &entry_off, fp_str);

		cbor_put_key(entry, &entry_off, "trust");
		cbor_put_tstr(entry, &entry_off, trust_to_str(entries[i].trust));

		cbor_put_key(entry, &entry_off, "first_seen");
		cbor_put_tstr(entry, &entry_off, first_str);

		cbor_put_key(entry, &entry_off, "last_seen");
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
size_t lichen_key_store_test_encode_list(uint8_t *buf, size_t buf_size)
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
		return 0; /* prevents underflow in offset checks (project-LICHEN-byge) */
	}

	lichen_key_iid_to_str(entry->iid, iid_str, sizeof(iid_str));
	encode_iso8601_timestamp(entry->first_seen, first_str, sizeof(first_str));
	encode_iso8601_timestamp(entry->last_seen, last_str, sizeof(last_str));

	/* 5 fields: iid, pubkey, trust, first_seen, last_seen */
	cbor_put_map_header(buf, &off, 5);

	cbor_put_key(buf, &off, "iid");
	cbor_put_tstr(buf, &off, iid_str);

	/* Pubkey as base64 string per spec */
	cbor_put_key(buf, &off, "pubkey");
	char pubkey_b64[48];
	base64_encode(entry->pubkey, LICHEN_KEY_PUBKEY_LEN, pubkey_b64, sizeof(pubkey_b64));
	cbor_put_tstr(buf, &off, pubkey_b64);

	cbor_put_key(buf, &off, "trust");
	cbor_put_tstr(buf, &off, trust_to_str(entry->trust));

	cbor_put_key(buf, &off, "first_seen");
	cbor_put_tstr(buf, &off, first_str);

	cbor_put_key(buf, &off, "last_seen");
	cbor_put_tstr(buf, &off, last_str);

	return off;
}

/* --------------------------------------------------------------------------
 * CBOR payload decoding for PUT
 * -------------------------------------------------------------------------- */

/*
 * Minimal CBOR decoder for PUT /keys/{iid} payload.
 * Expected format: { "pubkey": "<base64>", "trust": "<trust>" }
 */
static int decode_key_put_cbor(const uint8_t *payload, size_t payload_len,
			       uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
			       enum lichen_key_trust *_Nonnull trust)
{
	if (payload == NULL || pubkey == NULL || trust == NULL || payload_len < 5) {
		return -EINVAL;
	}

	/*
	 * Parse CBOR map header (major type 5).
	 * CBOR encoding for maps:
	 *   0xa0-0xb7: Small map with 0-23 items (count in lower 5 bits)
	 *   0xb8 NN:   Map with 1-byte length (up to 255 items)
	 *   0xb9 NNNN: Map with 2-byte length (big-endian)
	 *   0xba NNNNNNNN: Map with 4-byte length (big-endian)
	 *   0xbf:      Indefinite-length map (not supported - requires break code)
	 *
	 * For key management, we limit map_count to 32 entries max.
	 */
	uint8_t first_byte = payload[0];
	uint8_t major_type = first_byte >> 5;
	uint8_t additional_info = first_byte & 0x1f;
	size_t map_count;
	size_t pos;

	if (major_type != 5) {
		/* Not a map */
		return -EINVAL;
	}

	if (additional_info < 24) {
		/* Small map: count is in lower 5 bits */
		map_count = additional_info;
		pos = 1;
	} else if (additional_info == 24 && payload_len > 1) {
		/* 1-byte length */
		map_count = payload[1];
		pos = 2;
	} else if (additional_info == 25 && payload_len > 2) {
		/* 2-byte length (big-endian) */
		map_count = ((size_t)payload[1] << 8) | payload[2];
		pos = 3;
	} else if (additional_info == 26 && payload_len > 4) {
		/* 4-byte length (big-endian) */
		map_count = ((size_t)payload[1] << 24) | ((size_t)payload[2] << 16) |
			    ((size_t)payload[3] << 8) | payload[4];
		pos = 5;
	} else {
		/* 8-byte length (27), indefinite-length (31), or reserved: not supported */
		return -EINVAL;
	}

	/* Sanity check: key management payloads should not have huge maps */
	if (map_count > 32) {
		return -EINVAL;
	}
	bool has_pubkey = false;
	bool has_trust = false;

	*trust = LICHEN_KEY_TRUST_VERIFIED; /* default for manual add */

	for (size_t i = 0; i < map_count && pos < payload_len; i++) {
		/* Read key (text string) */
		uint8_t key_type = payload[pos];
		size_t key_len;
		const char *key_str;

		if ((key_type & 0xe0) == 0x60) {
			key_len = key_type & 0x1f;
			pos++;
		} else if (key_type == 0x78 && pos + 1 < payload_len) {
			key_len = payload[pos + 1];
			pos += 2;
		} else {
			return -EINVAL;
		}

		if (pos + key_len > payload_len) {
			return -EINVAL;
		}
		key_str = (const char *)&payload[pos];
		pos += key_len;

		/* Bounds check before reading value type */
		if (pos >= payload_len) {
			return -EINVAL;
		}

		/* Read value */
		uint8_t val_type = payload[pos];
		size_t val_len;
		const uint8_t *val_data;

		if ((val_type & 0xe0) == 0x60) {
			/* Text string */
			val_len = val_type & 0x1f;
			pos++;
		} else if (val_type == 0x78 && pos + 1 < payload_len) {
			val_len = payload[pos + 1];
			pos += 2;
		} else {
			/* Skip other CBOR types by advancing pos past the value */
			uint8_t major = (val_type >> 5) & 0x07;
			uint8_t info = val_type & 0x1f;

			pos++; /* advance past the initial byte */

			if (major == 0 || major == 1) {
				/* Unsigned or negative integer */
				if (info < 24) {
					/* value is inline, no extra bytes */
				} else if (info == 24) {
					pos += 1;
				} else if (info == 25) {
					pos += 2;
				} else if (info == 26) {
					pos += 4;
				} else if (info == 27) {
					pos += 8;
				} else {
					return -EINVAL;
				}
			} else if (major == 2) {
				/* Byte string - skip header + data */
				size_t bstr_len;

				if (info < 24) {
					bstr_len = info;
				} else if (info == 24 && pos < payload_len) {
					bstr_len = payload[pos];
					pos++;
				} else {
					return -EINVAL;
				}
				pos += bstr_len;
			} else if (major == 7) {
				/* Simple values: false(20), true(21), null(22), undefined(23) */
				if (info < 24) {
					/* value is inline, no extra bytes */
				} else {
					return -EINVAL;
				}
			} else {
				/* Arrays, maps, tags - not expected in key PUT payload */
				return -EINVAL;
			}

			if (pos > payload_len) {
				return -EINVAL;
			}
			continue;
		}

		if (pos + val_len > payload_len) {
			return -EINVAL;
		}
		val_data = &payload[pos];
		pos += val_len;

		/* Process known keys */
		if (key_len == 6 && memcmp(key_str, "pubkey", 6) == 0) {
			/* Decode base64 pubkey */
			int dec_len = base64_decode((const char *)val_data, val_len,
						    pubkey, LICHEN_KEY_PUBKEY_LEN);
			if (dec_len != LICHEN_KEY_PUBKEY_LEN) {
				return -EINVAL;
			}
			has_pubkey = true;
		} else if (key_len == 5 && memcmp(key_str, "trust", 5) == 0) {
			*trust = str_to_trust((const char *)val_data, val_len);
			has_trust = true;
		}
	}

	if (!has_pubkey) {
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
static bool is_local_admin(const struct sockaddr *addr, socklen_t addr_len)
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

/* --------------------------------------------------------------------------
 * CoAP response helper
 * -------------------------------------------------------------------------- */

static int coap_respond(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len,
			uint8_t resp_code,
			const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
		       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int ret;

	ret = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1,
			       type, tkl, token, resp_code,
			       coap_header_get_id(request));
	if (ret < 0) {
		return ret;
	}

	if (payload && payload_len > 0) {
		ret = coap_append_option_int(&resp, COAP_OPTION_CONTENT_FORMAT,
					     CBOR_CONTENT_FORMAT);
		if (ret < 0) {
			return ret;
		}
		ret = coap_packet_append_payload_marker(&resp);
		if (ret < 0) {
			return ret;
		}
		ret = coap_packet_append_payload(&resp, payload, payload_len);
		if (ret < 0) {
			return ret;
		}
	}

	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}

/* --------------------------------------------------------------------------
 * CoAP resource handlers
 * -------------------------------------------------------------------------- */

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
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
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

	/* Get URI path options */
	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));
	if (opt_count < 2) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Parse IID from second path component */
	char iid_str[LICHEN_KEY_IID_STR_LEN];

	if (options[1].len >= LICHEN_KEY_IID_STR_LEN) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}
	memcpy(iid_str, options[1].value, options[1].len);
	iid_str[options[1].len] = '\0';

	ret = lichen_key_str_to_iid(iid_str, iid);
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Look up key */
	ret = lichen_key_store_get(iid, &entry);
	if (ret == -ENOENT) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	len = encode_key_single_cbor(&entry, cbor_buf, sizeof(cbor_buf));
	if (len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
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
	const uint8_t *payload;
	int ret;

	/* SECURITY: Require local admin access for write operations */
	if (!is_local_admin(addr, addr_len)) {
		LOG_WRN("PUT /keys rejected: not local admin");
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_UNAUTHORIZED, NULL, 0);
	}

	/* Get URI path options */
	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));
	if (opt_count < 2) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Parse IID from second path component */
	char iid_str[LICHEN_KEY_IID_STR_LEN];

	if (options[1].len >= LICHEN_KEY_IID_STR_LEN) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}
	memcpy(iid_str, options[1].value, options[1].len);
	iid_str[options[1].len] = '\0';

	ret = lichen_key_str_to_iid(iid_str, iid);
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Parse payload */
	payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	ret = decode_key_put_cbor(payload, payload_len, pubkey, &trust);
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Store key */
	ret = lichen_key_store_put(iid, pubkey, trust);
	if (ret == -EEXIST) {
		/* TOFU violation */
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_CONFLICT, NULL, 0);
	}
	if (ret == -ENOMEM) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, NULL, 0);
	}
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	LOG_INF("Key added/updated for IID %s", iid_str);
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CHANGED, NULL, 0);
}

/*
 * DELETE /keys/{iid} - Remove key (requires admin)
 */
static int keys_single_delete(struct coap_resource *resource,
			      struct coap_packet *request,
			      struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_option options[4];
	int opt_count;
	uint8_t iid[LICHEN_KEY_IID_LEN];
	int ret;

	/* SECURITY: Require local admin access for write operations */
	if (!is_local_admin(addr, addr_len)) {
		LOG_WRN("DELETE /keys rejected: not local admin");
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_UNAUTHORIZED, NULL, 0);
	}

	/* Get URI path options */
	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));
	if (opt_count < 2) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Parse IID from second path component */
	char iid_str[LICHEN_KEY_IID_STR_LEN];

	if (options[1].len >= LICHEN_KEY_IID_STR_LEN) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}
	memcpy(iid_str, options[1].value, options[1].len);
	iid_str[options[1].len] = '\0';

	ret = lichen_key_str_to_iid(iid_str, iid);
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Delete key */
	ret = lichen_key_store_delete(iid);
	if (ret == -ENOENT) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	LOG_INF("Key deleted for IID %s", iid_str);
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_DELETED, NULL, 0);
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
