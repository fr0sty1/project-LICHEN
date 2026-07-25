/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_keys_cbor.c
 * @brief CBOR encoding/decoding for /keys resource
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zcbor_decode.h>

#include <lichen/coap_keys.h>
#include "coap_keys_internal.h"

/* --------------------------------------------------------------------------
 * CBOR helpers with overflow detection (string-keyed encoding per spec)
 * -------------------------------------------------------------------------- */

void cbor_ctx_init(struct cbor_ctx *ctx, uint8_t *buf, size_t size)
{
	ctx->buf = buf;
	ctx->off = 0;
	ctx->size = size;
	ctx->overflow = false;
}

bool cbor_check_space(struct cbor_ctx *ctx, size_t n)
{
	if (ctx->overflow || ctx->off + n > ctx->size) {
		ctx->overflow = true;
		return false;
	}
	return true;
}

void cbor_put_map_header(struct cbor_ctx *ctx, uint8_t count)
{
	if (count < 24U) {
		if (!cbor_check_space(ctx, 1)) {
			return;
		}
		ctx->buf[ctx->off++] = 0xa0U | count;
	} else {
		if (!cbor_check_space(ctx, 2)) {
			return;
		}
		ctx->buf[ctx->off++] = 0xb8;
		ctx->buf[ctx->off++] = count;
	}
}

void cbor_put_tstr(struct cbor_ctx *ctx, const char *value)
{
	size_t len = value ? strlen(value) : 0;
	if (len > 0xffffffffU) {
		ctx->overflow = true;
		return;
	}
	size_t header_len;
	if (len < 24U) {
		header_len = 1;
	} else if (len <= UINT8_MAX) {
		header_len = 2;
	} else if (len <= 0xffffU) {
		header_len = 3;
	} else {
		header_len = 5;
	}
	if (!cbor_check_space(ctx, header_len + len)) {
		return;
	}
	if (len < 24U) {
		ctx->buf[ctx->off++] = 0x60U | (uint8_t)len;
	} else if (len <= UINT8_MAX) {
		ctx->buf[ctx->off++] = 0x78;
		ctx->buf[ctx->off++] = (uint8_t)len;
	} else if (len <= 0xffffU) {
		ctx->buf[ctx->off++] = 0x79;
		ctx->buf[ctx->off++] = (uint8_t)(len >> 8);
		ctx->buf[ctx->off++] = (uint8_t)(len & 0xffU);
	} else {
		ctx->buf[ctx->off++] = 0x7a;
		ctx->buf[ctx->off++] = (uint8_t)(len >> 24);
		ctx->buf[ctx->off++] = (uint8_t)(len >> 16);
		ctx->buf[ctx->off++] = (uint8_t)(len >> 8);
		ctx->buf[ctx->off++] = (uint8_t)(len & 0xffU);
	}
	memcpy(&ctx->buf[ctx->off], value, len);
	ctx->off += len;
}

void cbor_put_key(struct cbor_ctx *ctx, const char *key)
{
	cbor_put_tstr(ctx, key);
}

/* --------------------------------------------------------------------------
 * Timestamp encoding
 * -------------------------------------------------------------------------- */

size_t encode_iso8601_timestamp(uint32_t unix_time, char *buf, size_t buf_len)
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

/* --------------------------------------------------------------------------
 * CBOR response encoding
 * -------------------------------------------------------------------------- */

size_t encode_keys_list_cbor(uint8_t *buf, size_t buf_size)
{
	struct cbor_ctx ctx;
	cbor_ctx_init(&ctx, buf, buf_size);
	size_t encoded = 0;

	if (buf == NULL || buf_size < 32) {
		return 0;
	}

	/* Outer map: { "keys": [...] } */
	cbor_put_map_header(&ctx, 1);
	cbor_put_key(&ctx, KEY_KEYS);

	/* Get all keys */
	struct lichen_key_entry entries[CONFIG_LICHEN_COAP_KEYS_MAX_ENTRIES];
	size_t n = lichen_key_store_list(entries, ARRAY_SIZE(entries));

	/* Reserve a fixed-width definite array header; patch its count after
	 * bounded entries are encoded so truncation always remains valid CBOR. */
	size_t count_offset = ctx.off;
	ctx.buf[ctx.off++] = 0x98;
	ctx.buf[ctx.off++] = 0;

	for (size_t i = 0; i < n; i++) {
		uint8_t entry_buf[KEY_LIST_ENTRY_CBOR_MAX_SIZE];
		struct cbor_ctx ectx;
		cbor_ctx_init(&ectx, entry_buf, sizeof(entry_buf));
		char iid_str[LICHEN_KEY_IID_STR_LEN];
		char fp_str[LICHEN_KEY_FINGERPRINT_STR_LEN];
		char first_str[24];
		char last_str[24];

		lichen_key_iid_to_str(entries[i].iid, iid_str, sizeof(iid_str));
		lichen_key_pubkey_fingerprint(entries[i].pubkey, fp_str, sizeof(fp_str));
		encode_iso8601_timestamp(entries[i].first_seen, first_str, sizeof(first_str));
		encode_iso8601_timestamp(entries[i].last_seen, last_str, sizeof(last_str));

		/* Each key entry: 5 fields */
		cbor_put_map_header(&ectx, 5);

		cbor_put_key(&ectx, KEY_IID);
		cbor_put_tstr(&ectx, iid_str);

		cbor_put_key(&ectx, KEY_PUBKEY_FP);
		cbor_put_tstr(&ectx, fp_str);

		cbor_put_key(&ectx, KEY_TRUST);
		cbor_put_tstr(&ectx, trust_to_str(entries[i].trust));

		cbor_put_key(&ectx, KEY_FIRST_SEEN);
		cbor_put_tstr(&ectx, first_str);

		cbor_put_key(&ectx, KEY_LAST_SEEN);
		cbor_put_tstr(&ectx, last_str);

		if (ectx.overflow) {
			break;
		}
		if (ctx.off + ectx.off > ctx.size) {
			break;
		}
		memcpy(&ctx.buf[ctx.off], ectx.buf, ectx.off);
		ctx.off += ectx.off;
		encoded++;
	}

	ctx.buf[count_offset + 1] = (uint8_t)encoded;
	return ctx.off;
}

#ifdef CONFIG_LICHEN_COAP_KEYS_TEST_HOOKS
size_t lichen_key_store_test_encode_list(uint8_t *_Nonnull buf, size_t buf_size)
{
	return encode_keys_list_cbor(buf, buf_size);
}
#endif

size_t encode_key_single_cbor(const struct lichen_key_entry *entry,
			      uint8_t *buf, size_t buf_size)
{
	struct cbor_ctx ctx;
	cbor_ctx_init(&ctx, buf, buf_size);
	char iid_str[LICHEN_KEY_IID_STR_LEN];
	char first_str[24];
	char last_str[24];

	if (entry == NULL || buf == NULL || buf_size < 100) {
		return 0;
	}

	lichen_key_iid_to_str(entry->iid, iid_str, sizeof(iid_str));
	encode_iso8601_timestamp(entry->first_seen, first_str, sizeof(first_str));
	encode_iso8601_timestamp(entry->last_seen, last_str, sizeof(last_str));

	/* 5 fields: iid, pubkey, trust, first_seen, last_seen */
	cbor_put_map_header(&ctx, 5);

	cbor_put_key(&ctx, KEY_IID);
	cbor_put_tstr(&ctx, iid_str);

	/* Pubkey as base64 string per spec */
	cbor_put_key(&ctx, KEY_PUBKEY);
	char pubkey_b64[48];
	base64_encode(entry->pubkey, LICHEN_KEY_PUBKEY_LEN, pubkey_b64, sizeof(pubkey_b64));
	cbor_put_tstr(&ctx, pubkey_b64);

	cbor_put_key(&ctx, KEY_TRUST);
	cbor_put_tstr(&ctx, trust_to_str(entry->trust));

	cbor_put_key(&ctx, KEY_FIRST_SEEN);
	cbor_put_tstr(&ctx, first_str);

	cbor_put_key(&ctx, KEY_LAST_SEEN);
	cbor_put_tstr(&ctx, last_str);

	return ctx.overflow ? 0 : ctx.off;
}

int decode_key_put_cbor(const uint8_t *payload, size_t payload_len,
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
