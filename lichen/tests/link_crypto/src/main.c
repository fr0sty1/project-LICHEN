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

static void init_rx_ctx(struct lichen_link_rx_ctx *rx,
			const struct lichen_link_ctx *tx)
{
	memset(rx, 0, sizeof(*rx));
	rx->peer_pubkey = tx->ed25519_pk;
	rx->peer_eui64 = test_eui64;
	rx->link_key = test_link_key;
}

ZTEST(link_crypto, test_encrypted_tx_rx_round_trip)
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

	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, 0, "encrypted TX failed: %d", ret);

	ret = lichen_frame_parse(&parsed, frame, frame_len);
	zassert_equal(ret, 0, "frame parse failed: %d", ret);
	zassert_true(parsed.encrypted, "link-key TX must set encrypted flag");
	zassert_true(parsed.signature_present, "signed TX must keep signature flag");
	zassert_equal(parsed.mic_len, LICHEN_MIC_64_LEN,
		      "encrypted frame must use 64-bit CCM tag");

	schc_len = lichen_schc_compress(test_ipv6, sizeof(test_ipv6),
					schc, sizeof(schc));
	zassert_true(schc_len > 0, "SCHC compression failed: %d", schc_len);
	l2_payload[0] = LICHEN_L2_DISPATCH_SCHC;
	memcpy(&l2_payload[1], schc, (size_t)schc_len);
	zassert_not_equal(memcmp(parsed.payload, schc, (size_t)schc_len), 0,
			  "encrypted payload leaked SCHC plaintext");
	zassert_not_equal(memcmp(parsed.payload, l2_payload,
				 (size_t)schc_len + 1U), 0,
			  "encrypted payload leaked L2 plaintext");

	ret = lichen_link_rx(&rx, NULL, frame, frame_len,
			     out_ipv6, &out_len, src_eui64);
	zassert_equal(ret, 0, "encrypted RX failed: %d", ret);
	zassert_equal(out_len, sizeof(test_ipv6), "unexpected RX packet length");
	zassert_mem_equal(out_ipv6, test_ipv6, sizeof(test_ipv6),
			  "RX packet mismatch");
	zassert_mem_equal(src_eui64, test_eui64, sizeof(test_eui64),
			  "source EUI-64 mismatch");

	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_encrypted_rx_rejects_tampered_payload)
{
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_frame parsed;
	uint8_t frame[160];
	uint8_t out_ipv6[80];
	uint8_t src_eui64[LICHEN_EUI64_LEN];
	size_t frame_len = sizeof(frame);
	size_t out_len = sizeof(out_ipv6);
	int ret;

	init_tx_ctx(&tx);
	init_rx_ctx(&rx, &tx);

	ret = lichen_link_tx(&tx, test_ipv6, sizeof(test_ipv6), NULL,
			     frame, &frame_len);
	zassert_equal(ret, 0, "encrypted TX failed: %d", ret);

	ret = lichen_frame_parse(&parsed, frame, frame_len);
	zassert_equal(ret, 0, "frame parse failed: %d", ret);

	frame[LICHEN_FRAME_PAYLOAD_OFFSET(parsed.dst_addr_len)] ^= 0x01;

	ret = lichen_link_rx(&rx, NULL, frame, frame_len,
			     out_ipv6, &out_len, src_eui64);
	zassert_equal(ret, -LICHEN_EAUTH,
		      "tampered encrypted frame must fail authentication");

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
