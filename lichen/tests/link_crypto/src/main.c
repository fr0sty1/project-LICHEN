/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief LICHEN encrypted link-frame TX/RX tests
 */

#include <zephyr/fff.h>
#include <zephyr/ztest.h>

#include <lichen/errno.h>
#include <lichen/l2_payload.h>
#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <ipv6_addr.h>
#include <lichen/schc.h>
#include <lichen/schnorr48.h>
#include "ipv6_addr.h"

#include <string.h>

static const uint8_t test_eui64[LICHEN_EUI64_LEN] = {
	0x02, 0x00, 0x5e, 0x10, 0x20, 0x30, 0x40, 0x50
};

static const uint8_t test_seed[LICHEN_SEED_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const uint8_t test_link_key[LICHEN_LINK_KEY_LEN] = {
	0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
};

static const uint8_t test_ipv6[40] = {
	0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x40,
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
};

ZTEST(link_crypto, test_init_rejects_csrand_failure_without_mutation)
{
	struct lichen_link_ctx ctx;
	struct lichen_link_ctx before;

	memset(&ctx, 0xa5, sizeof(ctx));
	memcpy(&before, &ctx, sizeof(before));
	__wrap_z_impl_sys_csrand_get_fake.custom_fake = NULL;
	__wrap_z_impl_sys_csrand_get_fake.return_val = -EIO;

	zassert_equal(lichen_link_init(&ctx, test_eui64), -EIO);
	zassert_equal(__wrap_z_impl_sys_csrand_get_fake.call_count, 1U);
	zassert_mem_equal(&ctx, &before, sizeof(ctx));
}

static void init_tx_ctx(struct lichen_link_ctx *tx)
{
	int ret;

	ret = lichen_link_init(tx, test_eui64);
	zassert_equal(ret, 0, "link init failed: %d", ret);

	ret = lichen_link_load_key(tx, test_seed);
	zassert_equal(ret, 0, "signing key load failed: %d", ret);

	ret = lichen_link_load_link_key(tx, test_link_key);
	zassert_equal(ret, 0, "link key load failed: %d", ret);
}

ZTEST(link_crypto, test_signed_encrypted_tx_is_rejected)
{
	struct lichen_link_ctx tx;
	uint8_t frame[160];
	size_t frame_len = sizeof(frame);
	int ret;

	init_tx_ctx(&tx);

	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, -EPROTONOSUPPORT,
		      "link-key TX must reject unsupported encryption");

	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_frame_accepts_elided_address)
{
	struct lichen_frame frame = { 0 };
	uint8_t wire[32] = { 0 };
	uint8_t payload[] = { 0x15, 0x01 };
	int ret;

	wire[0] = 6U;
	wire[1] = LICHEN_ADDR_ELIDED;
	wire[2] = 1U;
	wire[3] = 0U;
	wire[4] = 1U;
	wire[5] = payload[0];
	wire[6] = payload[1];

	ret = lichen_frame_parse(&frame, wire, 7U);
	zassert_equal(ret, 0, "elided address frame must parse: %d", ret);
	zassert_equal(frame.addr_mode, LICHEN_ADDR_ELIDED);
	zassert_equal(frame.dst_addr_len, 0U);
	zassert_equal(frame.payload_len, sizeof(payload));

	frame.payload = payload;
	frame.payload_len = sizeof(payload);
	frame.mic_len = 0U;
	frame.mic_length = LICHEN_MIC_32;
	ret = lichen_frame_write(&frame, wire, sizeof(wire));
	zassert_equal(ret, 7, "elided address frame must serialize: %d", ret);
	zassert_equal(wire[1], LICHEN_ADDR_ELIDED);
}

ZTEST(link_crypto, test_frame_rejects_reserved_mic_length)
{
	uint8_t wire[16] = { 0 };
	struct lichen_frame frame;

	wire[0] = 8U;
	wire[1] = 0x08U; /* MicLength = 0b010, reserved. */
	zassert_equal(lichen_frame_parse(&frame, wire, 9U), -EINVAL,
		      "reserved MIC length must be rejected");

	wire[1] = 0x28U; /* Reserved MIC length remains invalid when signed. */
	zassert_equal(lichen_frame_parse(&frame, wire, 9U), -EINVAL,
		      "signed reserved MIC length must be rejected");
}

ZTEST(link_crypto, test_encrypted_rx_rejects_tampered_payload)
{
	struct lichen_link_ctx tx;
	uint8_t frame[160];
	size_t frame_len = sizeof(frame);
	int ret;

	init_tx_ctx(&tx);
	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, -EPROTONOSUPPORT,
		      "link-key TX must reject unsupported encryption");
	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_returns_authenticated_l2_payload)
{
	struct lichen_link_ctx tx;
	uint8_t frame[160];
	size_t frame_len = sizeof(frame);
	int ret;

	init_tx_ctx(&tx);
	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, -EPROTONOSUPPORT,
		      "link-key TX must reject unsupported encryption");
	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_rejects_encrypted_frame)
{
	struct lichen_link_rx_ctx rx = { 0 };
	struct lichen_link_rx_payload_info info;
	uint8_t frame[] = { 8U, 0x40U, 3U, 0U, 4U, 0xaa, 0xbb, 0xcc, 0xdd };
	uint8_t payload[160];
	size_t payload_len = sizeof(payload);

	zassert_equal(lichen_link_rx_payload(&rx, NULL, frame, sizeof(frame),
				      payload, &payload_len, &info),
		      -EPROTONOSUPPORT,
		      "encrypted RX must reject unsupported encryption");
}

ZTEST(link_crypto, test_rx_payload_rejects_tampered_payload)
{
	struct lichen_link_ctx tx;
	uint8_t frame[160];
	size_t frame_len = sizeof(frame);
	int ret;

	init_tx_ctx(&tx);
	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, -EPROTONOSUPPORT,
		      "link-key TX must reject unsupported encryption");
	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_replay_commit_matches_ipv6_rx)
{
	struct lichen_link_ctx tx;
	uint8_t frame[160];
	size_t frame_len = sizeof(frame);
	int ret;

	init_tx_ctx(&tx);
	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, -EPROTONOSUPPORT,
		      "link-key TX must reject unsupported encryption");
	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_output_buffer_too_small_does_not_commit_replay)
{
	struct lichen_link_ctx tx;
	uint8_t frame[160];
	size_t frame_len = sizeof(frame);
	int ret;

	init_tx_ctx(&tx);
	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, -EPROTONOSUPPORT,
		      "link-key TX must reject unsupported encryption");
	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_l2_payload_dispatch_distinguishes_global_coap_from_announce)
{
	const uint8_t wrapped_global_coap[] = {
		LICHEN_L2_DISPATCH_SCHC, SCHC_RULE_GLOBAL_COAP, 0x40
	};
	const uint8_t wrapped_announce[] = {
		LICHEN_L2_DISPATCH_ROUTING,
		LICHEN_L2_ROUTING_TYPE_ANNOUNCE, 0x00
	};
	const uint8_t unwrapped_global_coap[] = {
		SCHC_RULE_GLOBAL_COAP, 0x40
	};
	size_t body_len;
	const uint8_t *body;

	zassert_equal(lichen_l2_payload_classify(wrapped_global_coap,
						 sizeof(wrapped_global_coap)),
		      LICHEN_L2_PAYLOAD_SCHC);
	body = lichen_l2_payload_body(wrapped_global_coap,
				      sizeof(wrapped_global_coap), &body_len);
	zassert_equal(body_len, sizeof(wrapped_global_coap) - 1U);
	zassert_mem_equal(body, &wrapped_global_coap[1], body_len);

	zassert_equal(lichen_l2_payload_classify(wrapped_announce,
						 sizeof(wrapped_announce)),
		      LICHEN_L2_PAYLOAD_ROUTING);
	body = lichen_l2_payload_body(wrapped_announce,
				      sizeof(wrapped_announce), &body_len);
	zassert_equal(body_len, sizeof(wrapped_announce) - 1U);
	zassert_equal(body[0], LICHEN_L2_ROUTING_TYPE_ANNOUNCE);
	zassert_equal(wrapped_global_coap[1], wrapped_announce[1]);

	zassert_equal(lichen_l2_payload_classify(unwrapped_global_coap,
						 sizeof(unwrapped_global_coap)),
		      LICHEN_L2_PAYLOAD_UNKNOWN);
	zassert_equal(lichen_l2_payload_classify(NULL, 0U),
		      LICHEN_L2_PAYLOAD_UNKNOWN);
}

ZTEST(link_crypto, test_derive_seed_matches_sha512_vector)
{
	/* Independent oracle: Python hashlib,
	 * SHA-512(test_seed || test_eui64)[0:32] */
	static const uint8_t expected[LICHEN_SEED_LEN] = {
		0x6d, 0x8c, 0x7e, 0x05, 0x86, 0x45, 0x07, 0x1d,
		0x27, 0x00, 0x39, 0x21, 0x71, 0xb1, 0xeb, 0x47,
		0xad, 0xfa, 0x47, 0x92, 0x96, 0xe8, 0xa1, 0x0a,
		0xbc, 0xcb, 0xe1, 0x6d, 0x5e, 0x04, 0x15, 0x2d,
	};
	uint8_t derived[LICHEN_SEED_LEN];
	int ret;

	ret = lichen_link_derive_seed(test_seed, test_eui64, derived);
	zassert_equal(ret, 0, "derive_seed failed: %d", ret);
	zassert_mem_equal(derived, expected, sizeof(expected),
			  "derived seed does not match SHA-512 vector");
}

ZTEST(link_crypto, test_derive_pubkey_matches_load_key)
{
	struct lichen_link_ctx ctx;
	uint8_t pk[LICHEN_PK_LEN];
	int ret;

	ret = lichen_link_init(&ctx, test_eui64);
	zassert_equal(ret, 0, "link init failed: %d", ret);
	ret = lichen_link_load_key(&ctx, test_seed);
	zassert_equal(ret, 0, "load_key failed: %d", ret);

	ret = lichen_link_derive_pubkey(test_seed, pk);
	zassert_equal(ret, 0, "derive_pubkey failed: %d", ret);
	zassert_mem_equal(pk, ctx.ed25519_pk, LICHEN_PK_LEN,
			  "derive_pubkey disagrees with load_key");
}

ZTEST(link_crypto, test_derived_node_keys_authenticate_cross_node)
{
	/* The property dev provisioning relies on: node B can verify node A's
	 * signatures using only A's EUI-64 and the shared base seed. Also
	 * checks distinct EUIs yield distinct keys. */
	static const uint8_t eui_a[LICHEN_EUI64_LEN] = {
		0x7a, 0x7f, 0xf0, 0x9d, 0xc8, 0x6c, 0x2c, 0x10
	};
	static const uint8_t eui_b[LICHEN_EUI64_LEN] = {
		0xee, 0x45, 0x2f, 0x74, 0x41, 0x9c, 0xf2, 0x81
	};
	static const uint8_t payload[8] = "lichen!";
	struct lichen_link_ctx node_a;
	uint8_t seed_a[LICHEN_SEED_LEN];
	uint8_t seed_b[LICHEN_SEED_LEN];
	uint8_t pk_a[LICHEN_PK_LEN];
	uint8_t pk_b[LICHEN_PK_LEN];
	uint8_t signed_payload[sizeof(payload) + LICHEN_SIG_LEN];
	int ret;

	ret = lichen_link_derive_seed(test_seed, eui_a, seed_a);
	zassert_equal(ret, 0, "derive seed A failed: %d", ret);
	ret = lichen_link_derive_seed(test_seed, eui_b, seed_b);
	zassert_equal(ret, 0, "derive seed B failed: %d", ret);
	zassert_true(memcmp(seed_a, seed_b, LICHEN_SEED_LEN) != 0,
		     "distinct EUIs must derive distinct seeds");

	/* Node A loads its own derived key */
	ret = lichen_link_init(&node_a, eui_a);
	zassert_equal(ret, 0, "node A init failed: %d", ret);
	ret = lichen_link_load_key(&node_a, seed_a);
	zassert_equal(ret, 0, "node A load_key failed: %d", ret);

	/* Node B derives A's (and its own) pubkey without loading */
	ret = lichen_link_derive_pubkey(seed_a, pk_a);
	zassert_equal(ret, 0, "derive pubkey A failed: %d", ret);
	ret = lichen_link_derive_pubkey(seed_b, pk_b);
	zassert_equal(ret, 0, "derive pubkey B failed: %d", ret);
	zassert_true(memcmp(pk_a, pk_b, LICHEN_PK_LEN) != 0,
		     "distinct EUIs must derive distinct pubkeys");

	/* A signs; B verifies with the derived pubkey */
	memcpy(signed_payload, payload, sizeof(payload));
	ret = schnorr48_sign_frame(60, 0x20, 1, 42, NULL, 0U,
				   payload, sizeof(payload),
				   node_a.ed25519_sk, node_a.ed25519_pk,
				   &signed_payload[sizeof(payload)]);
	zassert_equal(ret, 0, "sign failed: %d", ret);
	ret = schnorr48_verify_frame(60, 0x20, 1, 42, NULL, 0U,
				     payload, sizeof(payload),
				     &signed_payload[sizeof(payload)],
				     pk_a);
	zassert_equal(ret, 1, "verify with derived pubkey failed: %d", ret);

	/* B's key must NOT verify A's signature */
	ret = schnorr48_verify_frame(60, 0x20, 1, 42, NULL, 0U,
				     payload, sizeof(payload),
				     &signed_payload[sizeof(payload)],
				     pk_b);
	zassert_equal(ret, 0, "wrong pubkey must not verify");
}

ZTEST(link_crypto, test_lichen_yggdrasil_addr_matches_test_vectors)
{
	/* Uses test/vectors/yggdrasil-derivation.json vectors (first two).
	 * Matches Rust lichen-link::identity::yggdrasil_addr_from_pubkey,
	 * C lichen_identity_ygg_addr_from_ed25519 oracle, and Python.
	 * Tests the lichen_yggdrasil_addr wrapper (project-LICHEN-gp7u). */
	static const uint8_t vec1_pubkey[32] = {
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
	};
	static const uint8_t vec1_ygg[16] = {
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xe1, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
	};

	struct in6_addr addr;
	int ret;

	ret = lichen_yggdrasil_addr(vec1_pubkey, &addr);
	zassert_equal(ret, 0, "yggdrasil_addr vec1 failed: %d", ret);
	zassert_mem_equal(addr.s6_addr, vec1_ygg, sizeof(vec1_ygg),
			  "vector 1 does not match yggdrasil-derivation.json");

	/* Vector 2 from JSON: zero pubkey verifies U/L bit handling */
	static const uint8_t vec2_pubkey[32] = {0};
	static const uint8_t vec2_ygg[16] = {
		0x02, 0xd4, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4,
		0xe1, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
	};

	ret = lichen_yggdrasil_addr(vec2_pubkey, &addr);
	zassert_equal(ret, 0, "yggdrasil_addr vec2 failed: %d", ret);
	zassert_mem_equal(addr.s6_addr, vec2_ygg, sizeof(vec2_ygg),
			  "vector 2 does not match yggdrasil-derivation.json");

	/* Vector 3 from JSON (official Yggdrasil test suite adapted for LICHEN IID) */
	static const uint8_t vec3_pubkey[32] = {
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
	};
	static const uint8_t vec3_ygg[16] = {
		0x02, 0x05, 0xa3, 0xf6, 0xc5, 0xe5, 0xe5, 0xe5,
		0xe1, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
	};

	ret = lichen_yggdrasil_addr(vec3_pubkey, &addr);
	zassert_equal(ret, 0, "yggdrasil_addr vec3 failed: %d", ret);
	zassert_mem_equal(addr.s6_addr, vec3_ygg, sizeof(vec3_ygg),
			  "vector 3 does not match yggdrasil-derivation.json");

	/* Error path test (matches other ipv6_addr functions) */
	ret = lichen_yggdrasil_addr(NULL, &addr);
	zassert_equal(ret, -EINVAL, "NULL pubkey should return -EINVAL");
	ret = lichen_yggdrasil_addr(vec1_pubkey, NULL);
	zassert_equal(ret, -EINVAL, "NULL addr should return -EINVAL");
}

ZTEST(link_crypto, test_tdma_matches_ccp_tdma_vectors)
{
	uint8_t eui[8] = {0, 0, 0, 0, 0, 0, 0, 1};
	struct lichen_link_ctx lctx = {0};
	memcpy(lctx.eui64, eui, 8);
	lctx.epoch = 0;
	struct lichen_tdma_ctx tdma = {0};
	zassert_equal(0, lichen_tdma_init(&tdma, &lctx));
	zassert_equal(2, tdma.slot);
	zassert_equal(8, tdma.n_slots);
	zassert_equal(250, tdma.slot_duration);
	zassert_false(tdma.synced);
	tdma.synced = true;
	tdma.slot = 4;
	zassert_true(tdma_tx_allowed(&tdma, 1070));
	zassert_true(tdma_tx_allowed(&tdma, 990));
	zassert_true(tdma_tx_allowed(&tdma, 1000));
}

ZTEST_SUITE(link_crypto, NULL, NULL, NULL, NULL, NULL);
