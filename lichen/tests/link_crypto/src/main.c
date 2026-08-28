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

DEFINE_FFF_GLOBALS;
FAKE_VALUE_FUNC(int, __wrap_z_impl_sys_csrand_get, void *, size_t);

static int csrand_success(void *dst, size_t len)
{
	memset(dst, 0xa5, len);
	return 0;
}

static void reset_csrand_fake(void)
{
	RESET_FAKE(__wrap_z_impl_sys_csrand_get);
	FFF_RESET_HISTORY();
	__wrap_z_impl_sys_csrand_get_fake.custom_fake = csrand_success;
}

static void link_crypto_before(void *fixture)
{
	ARG_UNUSED(fixture);
	reset_csrand_fake();
}

static void link_crypto_after(void *fixture)
{
	ARG_UNUSED(fixture);
	reset_csrand_fake();
}

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
	ret = schnorr48_sign_frame(68, 0xa0, 1, 42, NULL, 0U,
				   eui_a, sizeof(eui_a),
				   payload, sizeof(payload),
				   node_a.ed25519_sk, node_a.ed25519_pk,
				   &signed_payload[sizeof(payload)]);
	zassert_equal(ret, 0, "sign failed: %d", ret);
	ret = schnorr48_verify_frame(68, 0xa0, 1, 42, NULL, 0U,
				     eui_a, sizeof(eui_a),
				     payload, sizeof(payload),
				     &signed_payload[sizeof(payload)],
				     SCHNORR48_SIG_LEN, pk_a);
	zassert_equal(ret, 1, "verify with derived pubkey failed: %d", ret);

	/* B's key must NOT verify A's signature */
	ret = schnorr48_verify_frame(68, 0xa0, 1, 42, NULL, 0U,
				     eui_a, sizeof(eui_a),
				     payload, sizeof(payload),
				     &signed_payload[sizeof(payload)],
				     SCHNORR48_SIG_LEN, pk_b);
	zassert_equal(ret, 0, "wrong pubkey must not verify");
}

ZTEST(link_crypto, test_lichen_yggdrasil_addr_matches_test_vectors)
{
	/* Uses test/vectors/yggdrasil-derivation.json vectors (first two).
	 * Matches Rust lichen-core::addr::ygg_addr_from_pubkey,
	 * C lichen_identity_ygg_addr_from_ed25519 oracle, and Python.
	 * addr = [0x02] + SHA-512(pubkey)[0:7] + SHA-512(pubkey)[0:8] (U/L cleared)
	 * Tests the lichen_yggdrasil_addr wrapper (project-LICHEN-gp7u). */
	static const uint8_t vec1_pubkey[32] = {
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
	};
	static const uint8_t vec1_ygg[16] = {
		0x02, 0x6b, 0x4e, 0x6c, 0x1f, 0xe3, 0x65, 0x04,
		0x69, 0x4e, 0x6c, 0x1f, 0xe3, 0x65, 0x04, 0xe1
	};

	struct in6_addr addr;
	int ret;

	ret = lichen_yggdrasil_addr(vec1_pubkey, &addr);
	zassert_equal(ret, 0, "yggdrasil_addr vec1 failed: %d", ret);
	zassert_mem_equal(addr.s6_addr, vec1_ygg, sizeof(vec1_ygg),
			  "vector 1 does not match yggdrasil-derivation.json");

	/* Vector 2 from JSON: zero pubkey verifies U/L bit + SHA-512 prefix handling */
	static const uint8_t vec2_pubkey[32] = {0};
	static const uint8_t vec2_ygg[16] = {
		0x02, 0x50, 0x46, 0xad, 0xc1, 0xdb, 0xa8, 0x38,
		0x50, 0x46, 0xad, 0xc1, 0xdb, 0xa8, 0x38, 0x86
	};

	ret = lichen_yggdrasil_addr(vec2_pubkey, &addr);
	zassert_equal(ret, 0, "yggdrasil_addr vec2 failed: %d", ret);
	zassert_mem_equal(addr.s6_addr, vec2_ygg, sizeof(vec2_ygg),
			  "vector 2 does not match yggdrasil-derivation.json");

	/* Vector 3 from JSON */
	static const uint8_t vec3_pubkey[32] = {
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
	};
	static const uint8_t vec3_ygg[16] = {
		0x02, 0x0e, 0x02, 0xa5, 0x02, 0x25, 0xb4, 0xba,
		0x0c, 0x02, 0xa5, 0x02, 0x25, 0xb4, 0xba, 0xaa
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
	/* Verifies hash slot calculation and timing windows against
	 * spec/02a-coordinated-capacity.md §2a.2 + test/vectors/ccp16.json,
	 * ccp_tdma.json (independent oracles for hash, 50ms guard, SFN wrap).
	 */

	/* Slot static hash vector 1: eui64=0000000000000001, epoch=0, n_slots=8 -> expected_slot=2 */
	{
		uint8_t eui1[8] = {0};
		eui1[7] = 1;
		int slot = lichen_tdma_compute_slot(eui1, 0, 8);
		zassert_equal(2, slot, "slot_static_hash_eui1: expected_slot=2, got=%d", slot);
	}

	/* Slot static hash vector 2: eui64=aabbccddeeff0011, epoch=0, n_slots=16 -> expected_slot=13 */
	{
		uint8_t eui2[8] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11};
		int slot = lichen_tdma_compute_slot(eui2, 0, 16);
		zassert_equal(13, slot, "slot_static_hash_eui2: expected_slot=13, got=%d", slot);
	}

	/* Timing windows (guard=50ms per spec/02a §2a.2 "MUST be 50", d=250ms
	 * per LICHEN_TDMA_SLOT_MS).
	 * Spec/02a §2a.4: data window begins at slot start and ends BEFORE
	 * the single trailing guard: TX window is [start, start + d - g)
	 * with no leading-edge tolerance — matches TDMAScheduler.is_tx_allowed()
	 * (python/src/lichen/sim/tdma.py) and tdma_clock::tx_allowed (rust).
	 * Expected values below are hand-computed from the slot parameters
	 * as an independent oracle (offset = now - start mod 2^32, allowed iff
	 * offset in [0, d-g) = [0, 200)), never copied from implementation
	 * output. */
	struct lichen_link_ctx lctx;
	memset(&lctx, 0, sizeof(lctx));
	memcpy(lctx.eui64, test_eui64, 8);
	struct lichen_tdma_ctx tdma = {0};
	zassert_equal(0, lichen_tdma_init(&tdma, &lctx));
	zassert_equal(1, tdma.slot);
	zassert_equal(8, tdma.n_slots);
	zassert_equal(250, tdma.slot_duration);
	zassert_false(tdma.synced);
	tdma.synced = true;

	/* Case A: slot=4, superframe=0 -> start=4*250=1000; window [1000,1200) */
	tdma.slot = 4;
	tdma.superframe = 0;
	zassert_true(tdma_tx_allowed(&tdma, 1070));      /* offset 70  */
	zassert_true(tdma_tx_allowed(&tdma, 1000));      /* offset 0 (start inclusive) */
	zassert_true(tdma_tx_allowed(&tdma, 1199));      /* offset 199 (last data ms) */
	zassert_false(tdma_tx_allowed(&tdma, 999));      /* 1ms before start rejected */
	zassert_false(tdma_tx_allowed(&tdma, 1200));     /* offset 200 = guard begins */
	zassert_false(tdma_tx_allowed(&tdma, 1201));     /* inside trailing guard */
	zassert_false(tdma_tx_allowed(&tdma, 1349));     /* offset 349: slot tail, still guarded */

	/* Sentinel auto-derive with NULL context must be rejected (no write) */
	{
		struct lichen_tdma_ctx sent = {0};
		zassert_equal(-EINVAL,
			      lichen_link_set_slot(NULL, &sent, 0xff, 8, 0),
			      "set_slot must reject sentinel 0xff with NULL ctx");
		zassert_equal(0U, sent.slot);
		zassert_false(sent.synced);
	}

	/* Case B: beacon advances superframe -> set_slot(sfn=1), slot=4
	 * start = 1*8*250 + 4*250 = 3000; window [3000,3200) */
	zassert_equal(0, lichen_link_set_slot(&lctx, &tdma, 4, 8, 1));
	zassert_true(tdma.synced);
	zassert_true(tdma_tx_allowed(&tdma, 3000));
	zassert_false(tdma_tx_allowed(&tdma, 2999));
	zassert_true(tdma_tx_allowed(&tdma, 3150));      /* offset 150: inside data window at g=50 */
	zassert_true(tdma_tx_allowed(&tdma, 3199));      /* offset 199 (last data ms) */
	zassert_false(tdma_tx_allowed(&tdma, 3200));     /* offset 200 = guard begins */

	/* Case C: u32 clock wrap. superframe=2147483, slot=5 ->
	 * start = 2147483*8*250 + 5*250 = 4294967250 (fits u32);
	 * window [4294967250, 4294967450) exceeds 2^32: end wraps to 154.
	 * offset(0)=46, offset(103)=149, offset(153)=199, offset(154)=200. */
	zassert_equal(0, lichen_link_set_slot(&lctx, &tdma, 5, 8, 2147483U));
	zassert_true(tdma_tx_allowed(&tdma, 4294967250U));
	zassert_true(tdma_tx_allowed(&tdma, 4294967295U)); /* offset 45 */
	zassert_true(tdma_tx_allowed(&tdma, 0));           /* post-wrap clock, offset 46 */
	zassert_true(tdma_tx_allowed(&tdma, 103));         /* offset 149 */
	zassert_true(tdma_tx_allowed(&tdma, 153));         /* offset 199: last data ms across wrap */
	zassert_false(tdma_tx_allowed(&tdma, 154));        /* offset 200: guard resumes after wrap */
	zassert_false(tdma_tx_allowed(&tdma, 4294967249U));/* 1ms before start */

	/* Case D: first SFN whose schedule product overflows u32.
	 * superframe=2147484, slot=5 -> true start = 2147484*8*250 + 5*250 =
	 * 4294969250; reduced modulo 2^32 per spec §2a.2 unsigned rule:
	 * 4294969250 - 4294967296 = 1954; window [1954, 2154).
	 * Hand-computed offsets only, as above. */
	zassert_equal(0, lichen_link_set_slot(&lctx, &tdma, 5, 8, 2147484U));
	zassert_equal(2147484U, tdma.superframe);
	zassert_true(tdma_tx_allowed(&tdma, 1954));        /* offset 0 */
	zassert_true(tdma_tx_allowed(&tdma, 2000));        /* offset 46 */
	zassert_true(tdma_tx_allowed(&tdma, 2153));        /* offset 199: last data ms */
	zassert_false(tdma_tx_allowed(&tdma, 1953));       /* 1ms before start: huge offset */
	zassert_false(tdma_tx_allowed(&tdma, 2154));       /* offset 200: guard begins */
	zassert_false(tdma_tx_allowed(&tdma, 1000000U));   /* mid-cycle, outside window */

	/* Sentinel auto-derivation MUST hash the beacon SFN argument per
	 * ccp_sfn_wrap_slot_hash.json, not ctx->epoch:
	 * vectors[slot_for_sfn_one]: EUI64=0102030405060708,
	 * fnv1a32=0x2804678d, sfn=1, n=16 -> (h+1) % 16 = 14.
	 * vectors[slot_for_wrapping_sum_before_non_power_of_two_modulus]:
	 * sfn=0xFFFFFFFF, n=3 -> (0x2804678d+0xffffffff) & 0xffffffff = 0x2804678c
	 * -> 0x2804678c % 3 = 2 (wrap happens BEFORE the non-power-of-two modulus).
	 * A memset ctx carries epoch==0; epoch substitution would yield
	 * 0x2804678d % 16 = 13 for both calls instead. */
	{
		static const uint8_t vec_eui[8] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
		};
		struct lichen_link_ctx vctx;
		struct lichen_tdma_ctx vtd;

		memset(&vctx, 0, sizeof(vctx));
		memcpy(vctx.eui64, vec_eui, sizeof(vec_eui));
		memset(&vtd, 0, sizeof(vtd));

		zassert_equal(0, lichen_link_set_slot(&vctx, &vtd, 0xff, 16, 1));
		zassert_equal(14, vtd.slot, "sfn=1 n=16 must give slot 14");
		zassert_equal(16, vtd.n_slots);
		zassert_equal(1U, vtd.superframe);
		zassert_true(vtd.synced);

		zassert_equal(0, lichen_link_set_slot(&vctx, &vtd, 0xff, 3, 0xFFFFFFFFU));
		zassert_equal(2, vtd.slot, "sfn wrap must land before %%3 modulus");
		zassert_equal(3, vtd.n_slots);
		zassert_equal(0xFFFFFFFFU, vtd.superframe);
	}

	/* Case F: ccp_tdma.json data_window_last_millisecond probe (the
	 * previously-failing vector at g=100). Profile-max 2346 ms slot,
	 * guard=50: boundary d-g = 2346-50 = 2296; data window is
	 * [start, start+2296). Vector slot_start_ms=1000, current 3295/3296,
	 * i.e. offsets 2295/2296 from slot start; reproduced here with
	 * slot=4, superframe=0, d=2346 -> start=9384, probes at
	 * 9384+2295=11679 (allowed) and 9384+2296=11680 (rejected). */
	tdma.slot = 4;
	tdma.superframe = 0;
	tdma.slot_duration = 2346;
	zassert_true(tdma_tx_allowed(&tdma, 11679U));    /* offset 2295 < 2296 */
	zassert_false(tdma_tx_allowed(&tdma, 11680U));   /* offset 2296 = guard start */
	tdma.slot_duration = LICHEN_TDMA_SLOT_MS;
}

ZTEST(link_crypto, test_lichen_pubkey_to_human_address_matches_node_address_vectors)
{
	/* Literals from test/vectors/node_address.json (shared cross-impl
	 * oracle; identical values asserted by the Rust node_address_vectors
	 * suite). Uniform-byte pubkeys cover the derivation, not specific
	 * curves. */
	static const uint8_t pk0[32] = {0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
	static const uint8_t pk1[32] = {0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U, 0x01U};
	static const uint8_t pk2[32] = {0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U, 0x02U};
	char buf[16];
	int ret = lichen_pubkey_to_human_address(pk0, buf, sizeof(buf));
	zassert_equal(ret, 0, "human addr pk0 failed: %d", ret);
	zassert_equal(strcmp(buf, "50HN-DR7D-TGE46"), 0, "pk0 human address mismatch");

	ret = lichen_pubkey_to_human_address(pk1, buf, sizeof(buf));
	zassert_equal(ret, 0, "human addr pk1 failed: %d", ret);
	zassert_equal(strcmp(buf, "5ST3-EZDT-ZMKHC"), 0, "pk1 human address mismatch");

	ret = lichen_pubkey_to_human_address(pk2, buf, sizeof(buf));
	zassert_equal(ret, 0, "human addr pk2 failed: %d", ret);
	zassert_equal(strcmp(buf, "AGF3-2DF4-W734C"), 0, "pk2 human address mismatch");

	ret = lichen_pubkey_to_human_address(NULL, buf, sizeof(buf));
	zassert_equal(ret, -EINVAL, "NULL pubkey should return -EINVAL");

	ret = lichen_pubkey_to_human_address(pk0, NULL, sizeof(buf));
	zassert_equal(ret, -EINVAL, "NULL buf should return -EINVAL");

	ret = lichen_pubkey_to_human_address(pk0, buf, 10);
	zassert_equal(ret, -EINVAL, "small buffer should return -EINVAL");
}

ZTEST(link_crypto, test_rx_fallback_eui64_is_canonical_key_derived)
{
	/* Independent oracle (python hashlib + RFC 8032 Ed25519):
	 *   seed   = SHA-512(test_seed || fb_eui)[0:32]
	 *   fb_pk  = Ed25519 public key of seed
	 *   fb_wire = SHA-512(fb_pk)[0:8] with the U/L bit (0x02) set
	 * fb_wire is the canonical key-derived wire EUI-64 that the rx
	 * fallback MUST report (test/vectors/link-addressing.json scheme,
	 * key_derived_extended_eui64). */
	static const uint8_t fb_eui[LICHEN_EUI64_LEN] = {
		0x7a, 0x7f, 0xf0, 0x9d, 0xc8, 0x6c, 0x2c, 0x10
	};
	static const uint8_t fb_pk[LICHEN_PK_LEN] = {
		0x89, 0x45, 0xac, 0x71, 0x84, 0xa2, 0xa2, 0x6a,
		0x67, 0x73, 0x7b, 0x4b, 0x85, 0xd5, 0xcc, 0x06,
		0xcd, 0xf0, 0xdd, 0x5c, 0x2d, 0xf8, 0x43, 0x7e,
		0xd9, 0xe8, 0x3d, 0xa1, 0x2f, 0xcc, 0x12, 0x50
	};
	static const uint8_t fb_wire[LICHEN_EUI64_LEN] = {
		0xae, 0xa6, 0xd0, 0xf1, 0x94, 0x38, 0x44, 0xbb
	};
	/* test/vectors/link-addressing.json key_derived_extended_eui64:
	 * canonical C derivation must match the cross-impl vector. */
	static const uint8_t vec_pk[32] = {
		0x29, 0xac, 0xba, 0xe1, 0x41, 0xbc, 0xca, 0xf0,
		0xb6, 0x19, 0xc8, 0xe9, 0x61, 0xf5, 0x99, 0x29,
		0xc8, 0xf3, 0x4e, 0x8c, 0xde, 0x0c, 0xcf, 0xf3,
		0x8e, 0xc7, 0x6e, 0xf9, 0x81, 0x59, 0x6f, 0xd0
	};
	static const uint8_t vec_iid[LICHEN_EUI64_LEN] = {
		0x3c, 0x8d, 0x1d, 0x92, 0x94, 0x60, 0xb4, 0x21
	};
	static const uint8_t payload[] = { 0x15, 0x01, 0x02 };
	uint8_t dst[LICHEN_EUI64_LEN];
	uint8_t seed[LICHEN_SEED_LEN];
	uint8_t wire[160];
	uint8_t out[64];
	uint8_t iid[LICHEN_EUI64_LEN];
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_frame f;
	struct lichen_link_rx_payload_info info;
	size_t frame_len;
	size_t out_len = sizeof(out);
	int ret;

	/* Canonical pubkey->IID derivation matches the pinned vector. */
	ret = lichen_pubkey_to_iid(vec_pk, iid);
	zassert_equal(ret, 0, "pubkey_to_iid failed: %d", ret);
	zassert_mem_equal(iid, vec_iid, sizeof(vec_iid),
			  "canonical IID does not match link-addressing.json");

	/* Signer keypair: RFC 8032 oracle above pins the derived pubkey. */
	ret = lichen_link_derive_seed(test_seed, fb_eui, seed);
	zassert_equal(ret, 0, "derive seed failed: %d", ret);
	ret = lichen_link_init(&tx, fb_eui);
	zassert_equal(ret, 0, "link init failed: %d", ret);
	ret = lichen_link_load_key(&tx, seed);
	zassert_equal(ret, 0, "load key failed: %d", ret);
	zassert_mem_equal(tx.ed25519_pk, fb_pk, sizeof(fb_pk),
			  "derived pubkey does not match Ed25519 oracle");

	/* Build a signed EXTENDED frame; receiver has NO provisioned
	 * peer_eui64, so rx must fall back to the canonical derivation. */
	memset(&f, 0, sizeof(f));
	memcpy(dst, vec_iid, sizeof(dst));
	dst[0] |= 0x02; /* wire form of the vector IID as destination */
	f.addr_mode = LICHEN_ADDR_EUI64;
	f.dst_addr_len = sizeof(dst);
	memcpy(f.dst_addr, dst, sizeof(dst));
	f.epoch = 1U;
	f.seqnum = 42U;
	f.payload = payload;
	f.payload_len = sizeof(payload);
	f.signature_present = true;
	f.signer_iid_present = true;
	f.signer_iid_len = LICHEN_EUI64_LEN;
	memcpy(f.signer_iid, fb_wire, sizeof(fb_wire));
	f.mic_length = LICHEN_MIC_32;
	f.mic_len = LICHEN_SIG_LEN;

	ret = lichen_frame_write(&f, wire, sizeof(wire));
	zassert_true(ret > 0, "frame pre-write failed: %d", ret);
	ret = schnorr48_sign_frame(wire[0], wire[1], f.epoch, f.seqnum,
				   f.dst_addr, f.dst_addr_len,
				   f.signer_iid, f.signer_iid_len,
				   payload, sizeof(payload),
				   tx.ed25519_sk, tx.ed25519_pk, f.mic);
	zassert_equal(ret, 0, "sign failed: %d", ret);
	ret = lichen_frame_write(&f, wire, sizeof(wire));
	zassert_true(ret > 0, "frame write failed: %d", ret);
	frame_len = (size_t)ret;

	memset(&rx, 0, sizeof(rx));
	rx.peer_pubkey = fb_pk; /* peer_eui64 left NULL: exercises fallback */
	ret = lichen_link_rx_payload(&rx, NULL, wire, frame_len,
				     out, &out_len, &info);
	zassert_equal(ret, 0, "rx_payload failed: %d", ret);
	zassert_mem_equal(info.src_eui64, fb_wire, sizeof(fb_wire),
			  "fallback src_eui64 is not the canonical "
			  "key-derived EUI-64");
	zassert_equal(info.addr_mode, LICHEN_ADDR_EUI64);
	zassert_equal(info.epoch, 1U);
	zassert_equal(info.seqnum, 42U);
	zassert_true(info.signature_present);

	lichen_link_cleanup(&tx);
}

ZTEST_SUITE(link_crypto, NULL, NULL, link_crypto_before, link_crypto_after,
	    NULL);
