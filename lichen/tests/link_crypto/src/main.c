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
#include <lichen/schc.h>
#include <lichen/schnorr48.h>

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

static void init_rx_ctx(struct lichen_link_rx_ctx *rx,
			const struct lichen_link_ctx *tx)
{
	memset(rx, 0, sizeof(*rx));
	rx->peer_pubkey = tx->ed25519_pk;
	rx->peer_eui64 = test_eui64;
}

ZTEST(link_crypto, test_keypair_snapshot_matches_and_clears)
{
	struct lichen_link_ctx tx;
	struct lichen_link_keypair_snapshot snapshot;
	const uint8_t zeros[sizeof(snapshot)] = { 0 };

	init_tx_ctx(&tx);
	zassert_equal(lichen_link_snapshot_keypair(&tx, &snapshot), 0);
	zassert_mem_equal(snapshot.eui64, tx.eui64, sizeof(snapshot.eui64));
	zassert_mem_equal(snapshot.sk, tx.ed25519_sk, sizeof(snapshot.sk));
	zassert_mem_equal(snapshot.pk, tx.ed25519_pk, sizeof(snapshot.pk));
	lichen_link_clear_keypair_snapshot(&snapshot);
	zassert_mem_equal(&snapshot, zeros, sizeof(snapshot));
	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_key_rotation_resets_exhaustion_only_for_new_key)
{
	struct lichen_link_ctx tx;
	uint8_t rotated_seed[LICHEN_SEED_LEN];

	init_tx_ctx(&tx);
	tx.epoch = UINT8_MAX;
	tx.tx_seq = UINT16_MAX;
	tx.nonce_exhausted = true;

	zassert_equal(lichen_link_load_key(&tx, test_seed), 0);
	zassert_true(tx.nonce_exhausted,
		     "same-key reload must not reopen exhausted tuple space");

	memcpy(rotated_seed, test_seed, sizeof(rotated_seed));
	rotated_seed[sizeof(rotated_seed) - 1] ^= 1U;
	zassert_equal(lichen_link_load_key(&tx, rotated_seed), 0);
	zassert_false(tx.nonce_exhausted,
		      "new signing key must create a fresh tuple domain");
	zassert_equal(tx.tx_seq, 0U);
	zassert_true(tx.epoch >= 128U);
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

ZTEST(link_crypto, test_authenticated_rx_rejects_unsigned_frame)
{
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_replay_table replay;
	struct lichen_link_rx_payload_info info;
	uint8_t wire[] = { 0x06, 0x00, 0x01, 0x00, 0x01, 0x15, 0x01 };
	uint8_t payload[8];
	size_t payload_len = sizeof(payload);

	init_tx_ctx(&tx);
	init_rx_ctx(&rx, &tx);
	lichen_replay_table_init(&replay);
	zassert_equal(lichen_link_rx_payload(&rx, &replay, wire, sizeof(wire),
					     payload, &payload_len, &info),
		      -LICHEN_EAUTH);
	lichen_link_cleanup(&tx);
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

ZTEST(link_crypto, test_signed_tx_rx_round_trip_with_retained_link_key)
{
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_frame parsed;
	uint8_t frame[160];
	uint8_t l2_payload[160];
	uint8_t schc[160];
	uint8_t out_ipv6[80];
	uint8_t src_eui64[LICHEN_EUI64_LEN];
	size_t frame_len = sizeof(frame);
	size_t out_len = sizeof(out_ipv6);
	int schc_len;
	int ret;

	init_tx_ctx(&tx);
	init_rx_ctx(&rx, &tx);
	zassert_true(tx.has_link_key, "test must retain legacy link key state");

	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, 0, "signed TX failed: %d", ret);

	ret = lichen_frame_parse(&parsed, frame, frame_len);
	zassert_equal(ret, 0, "frame parse failed: %d", ret);
	zassert_true(parsed.signature_present);
	zassert_false(parsed.encrypted);
	zassert_equal(parsed.mic_len, LICHEN_SIG_LEN);

	schc_len = lichen_schc_compress(test_ipv6, sizeof(test_ipv6),
					schc, sizeof(schc));
	zassert_true(schc_len > 0, "SCHC compression failed: %d", schc_len);
	l2_payload[0] = LICHEN_L2_DISPATCH_SCHC;
	memcpy(&l2_payload[1], schc, (size_t)schc_len);
	zassert_equal(parsed.payload_len, (size_t)schc_len + 1U);
	zassert_mem_equal(parsed.payload, l2_payload, parsed.payload_len);

	ret = lichen_link_rx(&rx, NULL, frame, frame_len,
			     out_ipv6, &out_len, src_eui64);
	zassert_equal(ret, 0, "signed RX failed: %d", ret);
	zassert_equal(out_len, sizeof(test_ipv6));
	zassert_mem_equal(out_ipv6, test_ipv6, sizeof(test_ipv6));
	zassert_mem_equal(src_eui64, test_eui64, sizeof(test_eui64));

	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_returns_authenticated_l2_payload)
{
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_frame parsed;
	struct lichen_link_rx_payload_info info;
	uint8_t frame[160];
	uint8_t payload[160];
	uint8_t schc[160];
	size_t frame_len = sizeof(frame);
	size_t payload_len = sizeof(payload);
	int schc_len;
	int ret;

	init_tx_ctx(&tx);
	init_rx_ctx(&rx, &tx);
	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, 0, "signed TX failed: %d", ret);
	zassert_equal(lichen_frame_parse(&parsed, frame, frame_len), 0);

	schc_len = lichen_schc_compress(test_ipv6, sizeof(test_ipv6),
					schc, sizeof(schc));
	zassert_true(schc_len > 0);
	ret = lichen_link_rx_payload(&rx, NULL, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, 0, "raw payload RX failed: %d", ret);
	zassert_equal(payload_len, (size_t)schc_len + 1U);
	zassert_equal(payload[0], LICHEN_L2_DISPATCH_SCHC);
	zassert_mem_equal(&payload[1], schc, (size_t)schc_len);
	zassert_mem_equal(info.src_eui64, test_eui64, sizeof(test_eui64));
	zassert_equal(info.epoch, parsed.epoch);
	zassert_equal(info.seqnum, parsed.seqnum);
	zassert_true(info.signature_present);
	zassert_false(info.encrypted);
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

ZTEST(link_crypto, test_rx_payload_rejects_tampered_payload_and_mic)
{
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_frame parsed;
	struct lichen_link_rx_payload_info info;
	uint8_t frame[160];
	uint8_t payload[160];
	size_t frame_len = sizeof(frame);
	size_t payload_len = sizeof(payload);
	int ret;

	init_tx_ctx(&tx);
	init_rx_ctx(&rx, &tx);
	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, 0, "signed TX failed: %d", ret);
	zassert_equal(lichen_frame_parse(&parsed, frame, frame_len), 0);

	frame[LICHEN_FRAME_PAYLOAD_OFFSET(parsed.dst_addr_len)] ^= 1U;
	ret = lichen_link_rx_payload(&rx, NULL, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, -LICHEN_EAUTH, "tampered payload must fail");
	frame[LICHEN_FRAME_PAYLOAD_OFFSET(parsed.dst_addr_len)] ^= 1U;
	frame[frame_len - 1U] ^= 1U;
	payload_len = sizeof(payload);
	ret = lichen_link_rx_payload(&rx, NULL, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, -LICHEN_EAUTH, "tampered MIC signature must fail");
	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_replay_commit_matches_ipv6_rx)
{
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_replay_table replay;
	struct lichen_link_rx_payload_info info;
	uint8_t frame[160];
	uint8_t payload[160];
	uint8_t out_ipv6[80];
	uint8_t src_eui64[LICHEN_EUI64_LEN];
	size_t frame_len = sizeof(frame);
	size_t payload_len = sizeof(payload);
	size_t out_len = sizeof(out_ipv6);
	int ret;

	init_tx_ctx(&tx);
	init_rx_ctx(&rx, &tx);
	lichen_replay_table_init(&replay);
	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, 0, "signed TX failed: %d", ret);
	ret = lichen_link_rx_payload(&rx, &replay, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, 0);

	payload_len = sizeof(payload);
	memset(payload, 0xcc, sizeof(payload));
	memset(&info, 0xdd, sizeof(info));
	struct lichen_link_rx_payload_info expected_info = info;
	ret = lichen_link_rx_payload(&rx, &replay, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, -EALREADY);
	zassert_equal(payload_len, sizeof(payload));
	for (size_t i = 0U; i < sizeof(payload); i++) {
		zassert_equal(payload[i], 0xcc);
	}
	zassert_mem_equal(&info, &expected_info, sizeof(info));

	memset(out_ipv6, 0xcc, sizeof(out_ipv6));
	memset(src_eui64, 0xdd, sizeof(src_eui64));
	uint8_t expected_ipv6[sizeof(out_ipv6)];
	uint8_t expected_src[sizeof(src_eui64)];
	memcpy(expected_ipv6, out_ipv6, sizeof(expected_ipv6));
	memcpy(expected_src, src_eui64, sizeof(expected_src));
	ret = lichen_link_rx(&rx, &replay, frame, frame_len,
			     out_ipv6, &out_len, src_eui64);
	zassert_equal(ret, -EALREADY);
	zassert_equal(out_len, sizeof(out_ipv6));
	zassert_mem_equal(out_ipv6, expected_ipv6, sizeof(out_ipv6));
	zassert_mem_equal(src_eui64, expected_src, sizeof(src_eui64));
	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_output_buffer_too_small_does_not_commit_replay)
{
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_replay_table replay;
	struct lichen_link_rx_payload_info info;
	uint8_t frame[160];
	uint8_t tiny_payload[1];
	uint8_t out_ipv6[80];
	uint8_t src_eui64[LICHEN_EUI64_LEN];
	size_t frame_len = sizeof(frame);
	size_t payload_len = sizeof(tiny_payload);
	size_t out_len = sizeof(out_ipv6);
	int ret;

	init_tx_ctx(&tx);
	init_rx_ctx(&rx, &tx);
	lichen_replay_table_init(&replay);
	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, 0, "signed TX failed: %d", ret);
	ret = lichen_link_rx_payload(&rx, &replay, frame, frame_len,
				     tiny_payload, &payload_len, &info);
	zassert_equal(ret, -ENOMEM);

	ret = lichen_link_rx(&rx, &replay, frame, frame_len,
			     out_ipv6, &out_len, src_eui64);
	zassert_equal(ret, 0, "buffer failure must not commit replay");
	zassert_mem_equal(out_ipv6, test_ipv6, sizeof(test_ipv6));
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

ZTEST_SUITE(link_crypto, NULL, NULL,
	    link_crypto_before, link_crypto_after, NULL);
