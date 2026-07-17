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

#include "aes_ccm.h"

#include <string.h>

#define TEST_PROTECTED_PAYLOAD_MAX (LICHEN_MAX_PAYLOAD + LICHEN_SIG_LEN)

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

static void build_nonce(uint8_t nonce[AES_CCM_NONCE_LEN],
			const uint8_t eui64[LICHEN_EUI64_LEN],
			uint8_t epoch, uint16_t seqnum)
{
	memcpy(&nonce[0], eui64, LICHEN_EUI64_LEN);
	nonce[8] = epoch;
	nonce[9] = (uint8_t)(seqnum >> 8);
	nonce[10] = (uint8_t)(seqnum & 0xff);
	nonce[11] = 0x00;
	nonce[12] = 0x00;
}

static int build_raw_l2_frame(struct lichen_link_ctx *tx,
			      const uint8_t *l2_payload, size_t l2_payload_len,
			      bool sign, bool encrypt,
			      uint8_t *out_frame, size_t *out_len)
{
	uint8_t payload_buf[TEST_PROTECTED_PAYLOAD_MAX];
	uint8_t epoch;
	uint16_t seqnum;
	size_t payload_len;
	size_t frame_body_len;
	size_t aad_len;
	size_t off;
	int ret;

	if (tx == NULL || l2_payload == NULL || out_frame == NULL ||
	    out_len == NULL || l2_payload_len == 0U ||
	    l2_payload_len > LICHEN_MAX_PAYLOAD) {
		return -EINVAL;
	}
	if (sign && l2_payload_len + LICHEN_SIG_LEN > sizeof(payload_buf)) {
		return -EMSGSIZE;
	}

	ret = lichen_link_next_tx(tx, &epoch, &seqnum);
	if (ret != 0) {
		return ret;
	}

	memcpy(payload_buf, l2_payload, l2_payload_len);
	payload_len = l2_payload_len;
	if (sign) {
		ret = schnorr48_sign_frame(epoch, seqnum, NULL, 0U,
					   l2_payload, l2_payload_len,
					   tx->ed25519_sk, tx->ed25519_pk,
					   &payload_buf[l2_payload_len]);
		if (ret != 0) {
			memset(payload_buf, 0, sizeof(payload_buf));
			return -EINVAL;
		}
		payload_len += LICHEN_SIG_LEN;
	}

	frame_body_len = (LICHEN_FRAME_PAYLOAD_OFFSET(0U) -
			  LICHEN_FRAME_LEN_FIELD_LEN) + payload_len +
			 (encrypt ? LICHEN_MIC_64_LEN : LICHEN_MIC_32_LEN);
	if (frame_body_len > 255U) {
		memset(payload_buf, 0, sizeof(payload_buf));
		return -EMSGSIZE;
	}
	if (*out_len < frame_body_len + LICHEN_FRAME_LEN_FIELD_LEN) {
		memset(payload_buf, 0, sizeof(payload_buf));
		return -ENOMEM;
	}

	off = 0U;
	out_frame[off++] = (uint8_t)frame_body_len;
	out_frame[off] = LICHEN_ADDR_BROADCAST;
	if (encrypt) {
		out_frame[off] |= 0x04;
		out_frame[off] |= 0x40;
	}
	if (sign) {
		out_frame[off] |= 0x20;
	}
	off++;
	out_frame[off++] = epoch;
	out_frame[off++] = (uint8_t)(seqnum >> 8);
	out_frame[off++] = (uint8_t)(seqnum & 0xff);
	aad_len = off;

	if (encrypt) {
		uint8_t nonce[AES_CCM_NONCE_LEN];

		build_nonce(nonce, tx->eui64, epoch, seqnum);
		ret = lichen_aes_ccm_encrypt(tx->link_key, nonce,
					     out_frame, aad_len,
					     payload_buf, payload_len,
					     &out_frame[off]);
		if (ret != 0) {
			memset(payload_buf, 0, sizeof(payload_buf));
			return -EINVAL;
		}
		off += payload_len + AES_CCM_TAG_LEN;
	} else {
		return -EINVAL;
	}

	*out_len = off;
	memset(payload_buf, 0, sizeof(payload_buf));
	return 0;
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
	zassert_equal(ret, 0, "encrypted TX failed: %d", ret);
	ret = lichen_frame_parse(&parsed, frame, frame_len);
	zassert_equal(ret, 0, "frame parse failed: %d", ret);

	schc_len = lichen_schc_compress(test_ipv6, sizeof(test_ipv6),
					schc, sizeof(schc));
	zassert_true(schc_len > 0, "SCHC compression failed: %d", schc_len);

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
	zassert_true(info.encrypted);
	zassert_equal(info.addr_mode, LICHEN_ADDR_BROADCAST);
	zassert_equal(info.dst_addr_len, 0U);

	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_returns_authenticated_routing_payload)
{
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_replay_table replay;
	struct lichen_link_rx_payload_info info;
	const uint8_t routing_payload[] = {
		LICHEN_L2_DISPATCH_ROUTING,
		LICHEN_L2_ROUTING_TYPE_ANNOUNCE,
		0x01, 0x02, 0x03, 0x04
	};
	uint8_t frame[160];
	uint8_t frame2[160];
	uint8_t payload[160];
	uint8_t out_ipv6[80];
	uint8_t src_eui64[LICHEN_EUI64_LEN];
	size_t frame_len = sizeof(frame);
	size_t frame2_len = sizeof(frame2);
	size_t payload_len = sizeof(payload);
	size_t out_len = sizeof(out_ipv6);
	int ret;

	init_tx_ctx(&tx);
	init_rx_ctx(&rx, &tx);
	lichen_replay_table_init(&replay);

	ret = build_raw_l2_frame(&tx, routing_payload, sizeof(routing_payload),
				 true, true, frame, &frame_len);
	zassert_equal(ret, 0, "raw routing frame build failed: %d", ret);

	ret = lichen_link_rx_payload(&rx, &replay, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, 0, "raw routing payload RX failed: %d", ret);
	zassert_equal(payload_len, sizeof(routing_payload));
	zassert_mem_equal(payload, routing_payload, sizeof(routing_payload));
	zassert_mem_equal(info.src_eui64, test_eui64, sizeof(test_eui64));
	zassert_true(info.signature_present);
	zassert_true(info.encrypted);

	payload_len = sizeof(payload);
	memset(payload, 0xcc, sizeof(payload));
	memset(&info, 0xdd, sizeof(info));
	ret = lichen_link_rx_payload(&rx, &replay, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, -EALREADY,
		      "raw routing replay must be rejected");
	zassert_equal(payload_len, sizeof(payload),
		      "replay failure must not rewrite payload length");
	for (size_t i = 0U; i < sizeof(payload); i++) {
		zassert_equal(payload[i], 0xcc,
			      "replay failure wrote payload byte %zu", i);
	}
	zassert_equal(info.epoch, 0xdd,
		      "replay failure must not publish metadata");

	ret = build_raw_l2_frame(&tx, routing_payload, sizeof(routing_payload),
				 true, true, frame2, &frame2_len);
	zassert_equal(ret, 0, "second raw routing frame build failed: %d", ret);
	ret = lichen_link_rx(&rx, NULL, frame2, frame2_len,
			     out_ipv6, &out_len, src_eui64);
	zassert_equal(ret, -EPROTONOSUPPORT,
		      "IPv6 RX must reject authenticated routing dispatch");

	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_accepts_large_signed_encrypted_inner_payload)
{
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_link_rx_payload_info info;
	uint8_t l2_payload[170];
	uint8_t frame[240];
	uint8_t payload[LICHEN_MAX_PAYLOAD];
	size_t frame_len = sizeof(frame);
	size_t payload_len = sizeof(payload);
	int ret;

	init_tx_ctx(&tx);
	init_rx_ctx(&rx, &tx);

	memset(l2_payload, 0xa5, sizeof(l2_payload));
	l2_payload[0] = LICHEN_L2_DISPATCH_ROUTING;
	l2_payload[1] = LICHEN_L2_ROUTING_TYPE_ANNOUNCE;

	ret = build_raw_l2_frame(&tx, l2_payload, sizeof(l2_payload),
				 true, true, frame, &frame_len);
	zassert_equal(ret, 0, "large signed encrypted frame build failed: %d", ret);

	ret = lichen_link_rx_payload(&rx, NULL, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, 0,
		      "large signed encrypted raw payload RX failed: %d", ret);
	zassert_equal(payload_len, sizeof(l2_payload));
	zassert_mem_equal(payload, l2_payload, sizeof(l2_payload));
	zassert_true(info.signature_present);
	zassert_true(info.encrypted);

	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_rejects_tampered_payload)
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
	zassert_equal(ret, 0, "encrypted TX failed: %d", ret);
	ret = lichen_frame_parse(&parsed, frame, frame_len);
	zassert_equal(ret, 0, "frame parse failed: %d", ret);

	frame[LICHEN_FRAME_PAYLOAD_OFFSET(parsed.dst_addr_len)] ^= 0x01;

	ret = lichen_link_rx_payload(&rx, NULL, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, -LICHEN_EAUTH,
		      "tampered encrypted frame must fail raw payload auth");

	lichen_link_cleanup(&tx);
}

ZTEST(link_crypto, test_rx_payload_replays_encrypted_unsigned_frames)
{
	struct lichen_link_ctx tx;
	struct lichen_link_rx_ctx rx;
	struct lichen_replay_table replay;
	struct lichen_link_rx_payload_info info;
	const uint8_t routing_payload[] = {
		LICHEN_L2_DISPATCH_ROUTING,
		LICHEN_L2_ROUTING_TYPE_ANNOUNCE,
		0xaa, 0xbb
	};
	uint8_t frame[160];
	uint8_t payload[160];
	size_t frame_len = sizeof(frame);
	size_t payload_len = sizeof(payload);
	int ret;

	ret = lichen_link_init(&tx, test_eui64);
	zassert_equal(ret, 0, "link init failed: %d", ret);
	ret = lichen_link_load_link_key(&tx, test_link_key);
	zassert_equal(ret, 0, "link key load failed: %d", ret);

	memset(&rx, 0, sizeof(rx));
	rx.peer_eui64 = test_eui64;
	rx.link_key = test_link_key;
	lichen_replay_table_init(&replay);

	ret = build_raw_l2_frame(&tx, routing_payload, sizeof(routing_payload),
				 false, true, frame, &frame_len);
	zassert_equal(ret, 0, "unsigned encrypted frame build failed: %d", ret);

	ret = lichen_link_rx_payload(&rx, &replay, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, 0, "first unsigned encrypted RX failed: %d", ret);
	zassert_false(info.signature_present);
	zassert_true(info.encrypted);
	zassert_mem_equal(payload, routing_payload, sizeof(routing_payload));

	payload_len = sizeof(payload);
	memset(payload, 0xcc, sizeof(payload));
	memset(&info, 0xdd, sizeof(info));
	ret = lichen_link_rx_payload(&rx, &replay, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, -EALREADY,
		      "second unsigned encrypted RX must be replay rejected");
	zassert_equal(payload_len, sizeof(payload),
		      "replay failure must not rewrite payload length");
	for (size_t i = 0U; i < sizeof(payload); i++) {
		zassert_equal(payload[i], 0xcc,
			      "replay failure wrote payload byte %zu", i);
	}
	zassert_equal(info.epoch, 0xdd,
		      "replay failure must not publish metadata");

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
	zassert_equal(ret, 0, "encrypted TX failed: %d", ret);

	ret = lichen_link_rx_payload(&rx, &replay, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, 0, "first raw payload RX failed: %d", ret);

	payload_len = sizeof(payload);
	memset(payload, 0xcc, sizeof(payload));
	memset(&info, 0xdd, sizeof(info));
	ret = lichen_link_rx_payload(&rx, &replay, frame, frame_len,
				     payload, &payload_len, &info);
	zassert_equal(ret, -EALREADY,
		      "second raw payload RX must be replay rejected");
	zassert_equal(payload_len, sizeof(payload),
		      "replay failure must not rewrite payload length");
	for (size_t i = 0U; i < sizeof(payload); i++) {
		zassert_equal(payload[i], 0xcc,
			      "replay failure wrote payload byte %zu", i);
	}
	zassert_equal(info.epoch, 0xdd,
		      "replay failure must not publish metadata");

	out_len = sizeof(out_ipv6);
	ret = lichen_link_rx(&rx, &replay, frame, frame_len,
			     out_ipv6, &out_len, src_eui64);
	zassert_equal(ret, -EALREADY,
		      "IPv6 RX after raw payload RX must be replay rejected");

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
	zassert_equal(ret, 0, "encrypted TX failed: %d", ret);

	ret = lichen_link_rx_payload(&rx, &replay, frame, frame_len,
				     tiny_payload, &payload_len, &info);
	zassert_equal(ret, -ENOMEM,
		      "too-small raw payload buffer must fail before replay commit");

	ret = lichen_link_rx(&rx, &replay, frame, frame_len,
			     out_ipv6, &out_len, src_eui64);
	zassert_equal(ret, 0,
		      "IPv6 RX after raw payload buffer failure should still pass");
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
	ret = schnorr48_sign_frame(1, 42, NULL, 0U,
				   payload, sizeof(payload),
				   node_a.ed25519_sk, node_a.ed25519_pk,
				   &signed_payload[sizeof(payload)]);
	zassert_equal(ret, 0, "sign failed: %d", ret);
	ret = schnorr48_verify_frame(1, 42, NULL, 0U,
				     signed_payload, sizeof(signed_payload),
				     pk_a);
	zassert_equal(ret, 1, "verify with derived pubkey failed: %d", ret);

	/* B's key must NOT verify A's signature */
	ret = schnorr48_verify_frame(1, 42, NULL, 0U,
				     signed_payload, sizeof(signed_payload),
				     pk_b);
	zassert_equal(ret, 0, "wrong pubkey must not verify");
}

ZTEST_SUITE(link_crypto, NULL, NULL, NULL, NULL, NULL);
