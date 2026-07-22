/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief LICHEN CoAP /keys store tests
 *
 * Primary purpose (bd a2a2): give CONFIG_LICHEN_COAP_KEYS a build that
 * actually compiles and links coap_keys.c, which no app/test config did
 * before. Also validates the peer key store's CRUD + TOFU semantics.
 */

#include <zephyr/ztest.h>

#include <lichen/coap_keys.h>

#include <string.h>

static const uint8_t iid_a[LICHEN_KEY_IID_LEN] = {
	0x02, 0x00, 0x5e, 0x10, 0x20, 0x30, 0x40, 0x50
};
static const uint8_t iid_b[LICHEN_KEY_IID_LEN] = {
	0x7a, 0x7f, 0xf0, 0x9d, 0xc8, 0x6c, 0x2c, 0x10
};
static const uint8_t pubkey_a[LICHEN_KEY_PUBKEY_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t pubkey_b[LICHEN_KEY_PUBKEY_LEN] = {
	0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
	0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
	0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
	0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0
};

static void reset_store(void *fixture)
{
	ARG_UNUSED(fixture);
	lichen_key_store_test_reset();
}

ZTEST_SUITE(coap_keys, NULL, NULL, reset_store, NULL, NULL);

ZTEST(coap_keys, test_put_get_roundtrip)
{
	struct lichen_key_entry entry;
	int ret;

	zassert_equal(lichen_key_store_count(), 0, "store should start empty");

	ret = lichen_key_store_put(iid_a, pubkey_a, LICHEN_KEY_TRUST_TOFU);
	zassert_equal(ret, 0, "put failed: %d", ret);
	zassert_equal(lichen_key_store_count(), 1, "count should be 1");

	ret = lichen_key_store_get(iid_a, &entry);
	zassert_equal(ret, 0, "get failed: %d", ret);
	zassert_mem_equal(entry.iid, iid_a, LICHEN_KEY_IID_LEN, "iid mismatch");
	zassert_mem_equal(entry.pubkey, pubkey_a, LICHEN_KEY_PUBKEY_LEN,
			  "pubkey mismatch");
	zassert_equal(entry.trust, LICHEN_KEY_TRUST_TOFU, "trust mismatch");
	zassert_true(entry.valid, "entry should be valid");
}

ZTEST(coap_keys, test_get_missing_returns_enoent)
{
	struct lichen_key_entry entry;

	zassert_equal(lichen_key_store_get(iid_a, &entry), -ENOENT,
		      "get of absent iid should be -ENOENT");
}

ZTEST(coap_keys, test_tofu_pinning_rejects_key_change)
{
	struct lichen_key_entry entry;
	int ret;

	zassert_equal(lichen_key_store_put(iid_a, pubkey_a,
					   LICHEN_KEY_TRUST_TOFU), 0,
		      "initial put failed");

	/* Same IID, DIFFERENT pubkey: TOFU pinning must reject it. */
	ret = lichen_key_store_put(iid_a, pubkey_b, LICHEN_KEY_TRUST_TOFU);
	zassert_equal(ret, -EEXIST, "key change should be rejected (-EEXIST)");

	/* Pinned key must be unchanged. */
	zassert_equal(lichen_key_store_get(iid_a, &entry), 0, "get failed");
	zassert_mem_equal(entry.pubkey, pubkey_a, LICHEN_KEY_PUBKEY_LEN,
			  "pinned pubkey must not change");
}

ZTEST(coap_keys, test_put_same_key_updates_trust)
{
	struct lichen_key_entry entry;

	zassert_equal(lichen_key_store_put(iid_a, pubkey_a,
					   LICHEN_KEY_TRUST_TOFU), 0,
		      "initial put failed");
	/* Same IID and SAME pubkey with a higher trust level: allowed. */
	zassert_equal(lichen_key_store_put(iid_a, pubkey_a,
					   LICHEN_KEY_TRUST_VERIFIED), 0,
		      "trust upgrade should be accepted");
	zassert_equal(lichen_key_store_count(), 1, "count should stay 1");
	zassert_equal(lichen_key_store_get(iid_a, &entry), 0, "get failed");
	zassert_equal(entry.trust, LICHEN_KEY_TRUST_VERIFIED,
		      "trust should be upgraded");
}

ZTEST(coap_keys, test_delete)
{
	struct lichen_key_entry entry;

	zassert_equal(lichen_key_store_put(iid_a, pubkey_a,
					   LICHEN_KEY_TRUST_TOFU), 0, "put failed");
	zassert_equal(lichen_key_store_delete(iid_a), 0, "delete failed");
	zassert_equal(lichen_key_store_count(), 0, "count should be 0");
	zassert_equal(lichen_key_store_get(iid_a, &entry), -ENOENT,
		      "get after delete should be -ENOENT");
	zassert_equal(lichen_key_store_delete(iid_a), -ENOENT,
		      "delete of absent iid should be -ENOENT");
}

ZTEST(coap_keys, test_list)
{
	struct lichen_key_entry entries[4];
	size_t n;

	zassert_equal(lichen_key_store_put(iid_a, pubkey_a,
					   LICHEN_KEY_TRUST_TOFU), 0, "put a failed");
	zassert_equal(lichen_key_store_put(iid_b, pubkey_b,
					   LICHEN_KEY_TRUST_VERIFIED), 0,
		      "put b failed");

	n = lichen_key_store_list(entries, ARRAY_SIZE(entries));
	zassert_equal(n, 2, "list should return 2 entries, got %zu", n);
}

ZTEST(coap_keys, test_iid_str_roundtrip)
{
	char buf[LICHEN_KEY_FINGERPRINT_STR_LEN];
	uint8_t parsed[LICHEN_KEY_IID_LEN];
	int ret;

	ret = lichen_key_iid_to_str(iid_a, buf, sizeof(buf));
	zassert_true(ret >= 0, "iid_to_str failed: %d", ret);

	ret = lichen_key_str_to_iid(buf, parsed);
	zassert_equal(ret, 0, "str_to_iid failed: %d", ret);
	zassert_mem_equal(parsed, iid_a, LICHEN_KEY_IID_LEN,
			  "iid string roundtrip mismatch");
}

ZTEST(coap_keys, test_fingerprint_format_and_stability)
{
	char fp_a1[LICHEN_KEY_FINGERPRINT_STR_LEN];
	char fp_a2[LICHEN_KEY_FINGERPRINT_STR_LEN];
	char fp_b[LICHEN_KEY_FINGERPRINT_STR_LEN];

	zassert_true(lichen_key_pubkey_fingerprint(pubkey_a, fp_a1,
						   sizeof(fp_a1)) > 0,
		     "fingerprint a1 failed");
	zassert_true(lichen_key_pubkey_fingerprint(pubkey_a, fp_a2,
						   sizeof(fp_a2)) > 0,
		     "fingerprint a2 failed");
	zassert_true(lichen_key_pubkey_fingerprint(pubkey_b, fp_b,
						   sizeof(fp_b)) > 0,
		     "fingerprint b failed");

	zassert_equal(strncmp(fp_a1, "SHA256:", 7), 0, "prefix should be SHA256:");
	/* Deterministic for the same key, distinct for different keys. */
	zassert_str_equal(fp_a1, fp_a2, "fingerprint must be stable");
	zassert_true(strcmp(fp_a1, fp_b) != 0,
		     "distinct keys must have distinct fingerprints");
}

ZTEST(coap_keys, test_pubkey_to_iid_derivation)
{
	uint8_t iid[LICHEN_KEY_IID_LEN];
	uint8_t iid2[LICHEN_KEY_IID_LEN];

	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid));
	zassert_ok(lichen_key_pubkey_to_iid(pubkey_a, iid2));
	zassert_mem_equal(iid, iid2, LICHEN_KEY_IID_LEN, "must be deterministic");

	zassert_ok(lichen_key_pubkey_to_iid(pubkey_b, iid2));
	/* Different pubkeys produce different IIDs (with high probability) */
	zassert_true(memcmp(iid, iid2, LICHEN_KEY_IID_LEN) != 0,
		     "distinct keys must produce distinct IIDs");
}

ZTEST(coap_keys, test_list_endpoint_truncates_with_valid_array_count)
{
	uint8_t cbor[512];
	size_t len;

	for (uint8_t i = 0; i < 8; i++) {
		uint8_t iid[LICHEN_KEY_IID_LEN] = { 0 };
		uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN] = { 0 };

		iid[7] = i;
		pubkey[0] = i;
		zassert_equal(lichen_key_store_put(iid, pubkey,
					   LICHEN_KEY_TRUST_TOFU), 0);
	}

	len = lichen_key_store_test_encode_list(cbor, sizeof(cbor));
	zassert_true(len > 8U && len <= sizeof(cbor), "invalid endpoint length");
	zassert_equal(cbor[0], 0xa1, "outer value must be a map");
	zassert_equal(cbor[1], 0x64, "outer key must be text(4)");
	zassert_mem_equal(&cbor[2], "keys", 4, "outer key mismatch");
	zassert_equal(cbor[6], 0x98, "keys must use a definite array");
	zassert_equal(cbor[7], 3U,
		      "eight-key endpoint must deterministically truncate to three");

	/* Every encoded entry starts with a five-pair map. Walk the known
	 * fixed schema to prove the declared count consumes the full payload. */
	size_t off = 8U;
	for (uint8_t i = 0; i < cbor[7]; i++) {
		zassert_equal(cbor[off++], 0xa5, "entry %u is not map(5)", i);
		for (int field = 0; field < 10; field++) {
			uint8_t head = cbor[off++];
			size_t str_len = head & 0x1fU;

			zassert_equal(head >> 5, 3U, "entry %u field is not text", i);
			if (str_len == 24U) {
				str_len = cbor[off++];
			}
			off += str_len;
			zassert_true(off <= len, "entry %u exceeds payload", i);
		}
	}
	zassert_equal(off, len, "array count does not match encoded entries");
}
