/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <lichen/app_identity/app_identity.h>
#include <lichen/link_ctx.h>

static const uint8_t test_eui64[LICHEN_EUI64_LEN] = {
	0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01,
};
static const uint8_t test_seed[LICHEN_SEED_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static void reset_before(void *fixture)
{
	ARG_UNUSED(fixture);
	lichen_app_identity_test_reset();
}

static bool buffer_contains(const uint8_t *haystack, size_t haystack_len,
			    const uint8_t *needle, size_t needle_len)
{
	if (needle_len == 0U || haystack_len < needle_len) {
		return false;
	}

	for (size_t i = 0U; i <= haystack_len - needle_len; i++) {
		if (memcmp(&haystack[i], needle, needle_len) == 0) {
			return true;
		}
	}
	return false;
}

ZTEST(app_identity, test_missing_self_identity)
{
	struct lichen_app_identity_self out;

	zassert_equal(lichen_app_identity_copy_self(&out), -ENOENT);
	zassert_equal(lichen_app_identity_copy_self(NULL), -EINVAL);
}

ZTEST(app_identity, test_self_identity_from_link_ctx)
{
	struct lichen_link_ctx ctx;
	struct lichen_app_identity_self out;
	uint8_t expected_iid[LICHEN_EUI64_LEN];

	zassert_ok(lichen_link_init(&ctx, test_eui64));
	zassert_equal(lichen_app_identity_set_self_from_link_ctx(
			      &ctx, "node", "fw"),
		      -ENOKEY);
	zassert_ok(lichen_link_load_key(&ctx, test_seed));
	zassert_ok(lichen_app_identity_set_self_from_link_ctx(
			   &ctx, "node", "fw"));
	zassert_ok(lichen_app_identity_copy_self(&out));

	memcpy(expected_iid, test_eui64, sizeof(expected_iid));
	expected_iid[0] ^= 0x02U;
	zassert_mem_equal(out.eui64, test_eui64, sizeof(test_eui64));
	zassert_mem_equal(out.iid, expected_iid, sizeof(expected_iid));
	zassert_mem_equal(out.public_key, ctx.ed25519_pk, sizeof(out.public_key));
	zassert_true(out.has_public_key);
	zassert_mem_equal(out.display_name, "node", 5U);
	zassert_mem_equal(out.firmware_name, "fw", 3U);
	zassert_false(buffer_contains((const uint8_t *)&out, sizeof(out),
				      ctx.ed25519_sk, LICHEN_SK_LEN),
		      "self snapshot must not contain private key bytes");
}

ZTEST(app_identity, test_reject_long_display_names)
{
	struct lichen_link_ctx ctx;
	struct lichen_app_identity_self identity = {
		.has_public_key = true,
	};
	const char too_long[] = "01234567890123456789012345678901";

	zassert_ok(lichen_link_init(&ctx, test_eui64));
	zassert_ok(lichen_link_load_key(&ctx, test_seed));
	zassert_equal(lichen_app_identity_set_self_from_link_ctx(
			      &ctx, too_long, "fw"),
		      -ENAMETOOLONG);

	memset(identity.eui64, 0x01, sizeof(identity.eui64));
	memset(identity.public_key, 0x02, sizeof(identity.public_key));
	memset(identity.display_name, 'x', sizeof(identity.display_name));
	zassert_equal(lichen_app_identity_set_self(&identity), -ENAMETOOLONG);
	memset(identity.display_name, 0, sizeof(identity.display_name));
	memset(identity.firmware_name, 'f', sizeof(identity.firmware_name));
	zassert_equal(lichen_app_identity_set_self(&identity), -ENAMETOOLONG);
}

ZTEST(app_identity, test_direct_self_identity_normalizes_strings)
{
	struct lichen_app_identity_self identity = {
		.has_public_key = true,
	};
	struct lichen_app_identity_self out;

	memcpy(identity.eui64, test_eui64, sizeof(identity.eui64));
	memset(identity.public_key, 0x55, sizeof(identity.public_key));
	memcpy(identity.display_name, "node", 5U);
	memcpy(&identity.display_name[5], "stale", 5U);
	memcpy(identity.firmware_name, "fw", 3U);
	memcpy(&identity.firmware_name[3], "stale", 5U);

	zassert_ok(lichen_app_identity_set_self(&identity));
	zassert_ok(lichen_app_identity_copy_self(&out));
	zassert_mem_equal(out.display_name, "node", 5U);
	zassert_mem_equal(&out.display_name[5], "\0\0\0\0\0", 5U);
	zassert_mem_equal(out.firmware_name, "fw", 3U);
	zassert_mem_equal(&out.firmware_name[3], "\0\0\0\0\0", 5U);
}

ZTEST(app_identity, test_peer_lookup_and_enumeration)
{
	const uint8_t peer1_eui64[LICHEN_EUI64_LEN] = {
		0x02, 0xaa, 0, 0, 0, 0, 0, 1,
	};
	const uint8_t peer2_eui64[LICHEN_EUI64_LEN] = {
		0x02, 0xaa, 0, 0, 0, 0, 0, 2,
	};
	const uint8_t peer3_eui64[LICHEN_EUI64_LEN] = {
		0x02, 0xaa, 0, 0, 0, 0, 0, 3,
	};
	uint8_t key1[LICHEN_PK_LEN];
	uint8_t key2[LICHEN_PK_LEN];
	uint8_t key3[LICHEN_PK_LEN];
	struct lichen_app_identity_peer out;
	struct lichen_app_identity_peer peers[2];
	size_t copied;

	memset(key1, 0x11, sizeof(key1));
	memset(key2, 0x22, sizeof(key2));
	memset(key3, 0x33, sizeof(key3));

	zassert_equal(lichen_app_identity_copy_peer(peer1_eui64, &out),
		      -ENOENT);
	zassert_ok(lichen_app_identity_upsert_peer_key(peer1_eui64, key1));
	zassert_ok(lichen_app_identity_upsert_peer_key(peer2_eui64, key2));
	zassert_equal(lichen_app_identity_peer_count(), 2U);
	zassert_equal(lichen_app_identity_upsert_peer_key(peer3_eui64, key3),
		      -ENOMEM);

	zassert_ok(lichen_app_identity_copy_peer(peer1_eui64, &out));
	zassert_mem_equal(out.eui64, peer1_eui64, sizeof(peer1_eui64));
	zassert_mem_equal(out.public_key, key1, sizeof(key1));
	zassert_equal(out.iid[0], peer1_eui64[0] ^ 0x02U);
	zassert_true(out.has_public_key);

	memset(key1, 0x44, sizeof(key1));
	zassert_ok(lichen_app_identity_upsert_peer_key(peer1_eui64, key1));
	zassert_ok(lichen_app_identity_copy_peer(peer1_eui64, &out));
	zassert_mem_equal(out.public_key, key1, sizeof(key1));
	zassert_equal(lichen_app_identity_peer_count(), 2U);

	copied = lichen_app_identity_copy_peers(peers, ARRAY_SIZE(peers));
	zassert_equal(copied, 2U);
	zassert_equal(lichen_app_identity_copy_peers(NULL, 2U), 0U);
}

ZTEST(app_identity, test_validation)
{
	struct lichen_app_identity_peer peer = { 0 };
	uint8_t key[LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN] = { 0 };

	zassert_equal(LICHEN_APP_IDENTITY_EUI64_LEN, 8U);
	zassert_equal(LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN, 32U);

	zassert_equal(lichen_app_identity_set_self(NULL), -EINVAL);
	zassert_equal(lichen_app_identity_set_self_from_link_ctx(NULL, NULL, NULL),
		      -EINVAL);
	zassert_equal(lichen_app_identity_upsert_peer(NULL), -EINVAL);
	zassert_equal(lichen_app_identity_upsert_peer(&peer), -ENOKEY);
	zassert_equal(lichen_app_identity_upsert_peer_key(NULL, key), -EINVAL);
	zassert_equal(lichen_app_identity_upsert_peer_key(test_eui64, NULL),
		      -EINVAL);
	zassert_equal(lichen_app_identity_copy_peer(NULL, &peer), -EINVAL);
	zassert_equal(lichen_app_identity_copy_peer(test_eui64, NULL), -EINVAL);
}

ZTEST_SUITE(app_identity, NULL, NULL, reset_before, NULL, NULL);
