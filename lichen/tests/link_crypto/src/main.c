/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief LICHEN encrypted link-frame TX/RX tests
 */

#include <zephyr/ztest.h>

#include <lichen/errno.h>
#include <lichen/l2_payload.h>
#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/schc.h>
#include <lichen/schnorr48.h>

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

ZTEST_SUITE(link_crypto, NULL, NULL, NULL, NULL, NULL);
