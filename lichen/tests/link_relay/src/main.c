/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/fff.h>
#include <zephyr/ztest.h>

#include <lichen/errno.h>
#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/replay.h>
#include <lichen/schnorr48.h>
#include <monocypher.h>
#include <monocypher-ed25519.h>

#include <string.h>

DEFINE_FFF_GLOBALS;
FAKE_VALUE_FUNC(int, __wrap_z_impl_sys_csrand_get, void *, size_t);

static int csrand_success(void *dst, size_t len)
{
	memset(dst, 0xa5, len);
	return 0;
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);
	RESET_FAKE(__wrap_z_impl_sys_csrand_get);
	FFF_RESET_HISTORY();
	__wrap_z_impl_sys_csrand_get_fake.custom_fake = csrand_success;
}

static void canonical_eui64(const uint8_t pubkey[LICHEN_PK_LEN],
			    uint8_t eui64[LICHEN_EUI64_LEN])
{
	uint8_t hash[64];

	crypto_sha512(hash, pubkey, LICHEN_PK_LEN);
	memcpy(eui64, hash, LICHEN_EUI64_LEN);
	eui64[0] |= 0x02U;
	crypto_wipe(hash, sizeof(hash));
}

static void init_keyed(struct lichen_link_ctx *ctx, uint8_t identity_tag,
		       uint8_t seed_tag)
{
	uint8_t eui64[LICHEN_EUI64_LEN] = { 0x02, 0, 0, 0, 0, 0, 0, identity_tag };
	uint8_t seed[LICHEN_SEED_LEN];

	memset(seed, seed_tag, sizeof(seed));
	zassert_ok(lichen_link_init(ctx, eui64));
	zassert_ok(lichen_link_load_key(ctx, seed));
	crypto_wipe(seed, sizeof(seed));
}

static size_t build_noncanonical_siid(struct lichen_link_ctx *sender,
				      const uint8_t *payload,
				      size_t payload_len,
				      uint8_t *wire,
				      size_t wire_size)
{
	struct lichen_frame frame = { 0 };
	uint8_t arbitrary_siid[LICHEN_EUI64_LEN] = { 0x02, 1, 2, 3, 4, 5, 6, 7 };
	int ret;

	frame.addr_mode = LICHEN_ADDR_BROADCAST;
	frame.epoch = 9U;
	frame.seqnum = 17U;
	frame.signer_iid_present = true;
	frame.signer_iid_len = sizeof(arbitrary_siid);
	memcpy(frame.signer_iid, arbitrary_siid, sizeof(arbitrary_siid));
	frame.payload = payload;
	frame.payload_len = payload_len;
	frame.signature_present = true;
	frame.mic_length = LICHEN_MIC_32;
	frame.mic_len = LICHEN_SIG_LEN;

	ret = lichen_frame_write(&frame, wire, wire_size);
	zassert_true(ret > 0);
	zassert_ok(schnorr48_sign_frame(wire[0], wire[1], frame.epoch,
					frame.seqnum, NULL, 0U,
					frame.signer_iid, frame.signer_iid_len,
					payload, payload_len,
					sender->ed25519_sk, sender->ed25519_pk,
					frame.mic));
	ret = lichen_frame_write(&frame, wire, wire_size);
	zassert_true(ret > 0);
	return (size_t)ret;
}

ZTEST(link_relay, test_authenticates_then_resigns_with_relayer_identity)
{
	static const uint8_t payload[] = { 0x15, 0x81, 0x02, 0xa5, 0x00 };
	static const uint8_t next_hop[LICHEN_EUI64_LEN] = {
		0x02, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80
	};
	struct lichen_link_ctx sender;
	struct lichen_link_ctx relay;
	struct lichen_link_rx_ctx relay_rx = { 0 };
	struct lichen_link_rx_ctx receiver_rx = { 0 };
	struct lichen_replay_table replay;
	struct lichen_link_rx_payload_info info;
	struct lichen_frame parsed;
	uint8_t incoming[LICHEN_MAX_FRAME_LEN];
	uint8_t outgoing[LICHEN_MAX_FRAME_LEN];
	uint8_t decoded[LICHEN_MAX_PAYLOAD];
	uint8_t expected_siid[LICHEN_EUI64_LEN];
	size_t incoming_len = sizeof(incoming);
	size_t outgoing_len = sizeof(outgoing);
	size_t decoded_len = sizeof(decoded);

	init_keyed(&sender, 1U, 0x11U);
	init_keyed(&relay, 2U, 0x22U);
	zassert_ok(lichen_link_relay_raw(&sender, payload, sizeof(payload), NULL,
					 incoming, &incoming_len));

	relay_rx.peer_pubkey = sender.ed25519_pk;
	lichen_replay_table_init(&replay);
	zassert_ok(lichen_link_relay_frame(&relay_rx, &replay, &relay,
					  incoming, incoming_len, next_hop,
					  outgoing, &outgoing_len));

	zassert_ok(lichen_frame_parse(&parsed, outgoing, outgoing_len));
	zassert_true(parsed.signature_present);
	zassert_true(parsed.signer_iid_present);
	zassert_equal(parsed.addr_mode, LICHEN_ADDR_EUI64);
	zassert_mem_equal(parsed.dst_addr, next_hop, sizeof(next_hop));
	zassert_mem_equal(parsed.payload, payload, sizeof(payload));
	canonical_eui64(relay.ed25519_pk, expected_siid);
	zassert_mem_equal(parsed.signer_iid, expected_siid, sizeof(expected_siid));
	zassert_not_equal(memcmp(&incoming[incoming_len - LICHEN_SIG_LEN],
				 outgoing + outgoing_len - LICHEN_SIG_LEN,
				 LICHEN_SIG_LEN), 0);

	receiver_rx.peer_pubkey = relay.ed25519_pk;
	zassert_ok(lichen_link_rx_payload(&receiver_rx, NULL, outgoing, outgoing_len,
					 decoded, &decoded_len, &info));
	zassert_equal(decoded_len, sizeof(payload));
	zassert_mem_equal(decoded, payload, sizeof(payload));
	zassert_mem_equal(info.src_eui64, expected_siid, sizeof(expected_siid));

	lichen_link_cleanup(&sender);
	lichen_link_cleanup(&relay);
}

ZTEST(link_relay, test_rejects_tamper_wrong_key_replay_and_small_output_atomically)
{
	static const uint8_t payload[] = { 0x15, 0x01, 0x02 };
	struct lichen_link_ctx sender;
	struct lichen_link_ctx wrong_sender;
	struct lichen_link_ctx relay;
	struct lichen_link_rx_ctx rx = { 0 };
	struct lichen_replay_table replay;
	uint8_t incoming[LICHEN_MAX_FRAME_LEN];
	uint8_t tampered[LICHEN_MAX_FRAME_LEN];
	uint8_t output[LICHEN_MAX_FRAME_LEN];
	uint8_t before_output[LICHEN_MAX_FRAME_LEN];
	size_t incoming_len = sizeof(incoming);
	size_t output_len;
	uint16_t seq_before;
	int ret;

	init_keyed(&sender, 1U, 0x11U);
	init_keyed(&wrong_sender, 3U, 0x33U);
	init_keyed(&relay, 2U, 0x22U);
	zassert_ok(lichen_link_relay_raw(&sender, payload, sizeof(payload), NULL,
					 incoming, &incoming_len));
	rx.peer_pubkey = sender.ed25519_pk;
	lichen_replay_table_init(&replay);

	/* Capacity failure is rejected before replay/TX state is consumed. */
	memset(output, 0x5a, sizeof(output));
	memcpy(before_output, output, sizeof(output));
	output_len = 1U;
	seq_before = relay.tx_seq;
	ret = lichen_link_relay_frame(&rx, &replay, &relay, incoming, incoming_len,
				      NULL, output, &output_len);
	zassert_equal(ret, -ENOMEM);
	zassert_equal(output_len, 1U);
	zassert_equal(relay.tx_seq, seq_before);
	zassert_mem_equal(output, before_output, sizeof(output));

	/* A signed payload/header tamper fails before output or local nonce state. */
	memcpy(tampered, incoming, incoming_len);
	tampered[incoming_len - LICHEN_SIG_LEN - 1U] ^= 0x01U;
	output_len = sizeof(output);
	seq_before = relay.tx_seq;
	ret = lichen_link_relay_frame(&rx, NULL, &relay, tampered, incoming_len,
				      NULL, output, &output_len);
	zassert_equal(ret, -LICHEN_EAUTH);
	zassert_equal(output_len, sizeof(output));
	zassert_equal(relay.tx_seq, seq_before);
	zassert_mem_equal(output, before_output, sizeof(output));

	/* A different provisioned peer key cannot authorize the frame. */
	rx.peer_pubkey = wrong_sender.ed25519_pk;
	output_len = sizeof(output);
	ret = lichen_link_relay_frame(&rx, NULL, &relay, incoming, incoming_len,
				      NULL, output, &output_len);
	zassert_equal(ret, -LICHEN_EAUTH);
	zassert_mem_equal(output, before_output, sizeof(output));

	/* First authentic relay commits the incoming tuple; duplicate does not
	 * consume another relay tuple or publish output. */
	rx.peer_pubkey = sender.ed25519_pk;
	output_len = sizeof(output);
	zassert_ok(lichen_link_relay_frame(&rx, &replay, &relay, incoming,
					  incoming_len, NULL, output, &output_len));
	memset(output, 0x5a, sizeof(output));
	memcpy(before_output, output, sizeof(output));
	output_len = sizeof(output);
	seq_before = relay.tx_seq;
	ret = lichen_link_relay_frame(&rx, &replay, &relay, incoming, incoming_len,
				      NULL, output, &output_len);
	zassert_equal(ret, -EALREADY);
	zassert_equal(output_len, sizeof(output));
	zassert_equal(relay.tx_seq, seq_before);
	zassert_mem_equal(output, before_output, sizeof(output));

	lichen_link_cleanup(&sender);
	lichen_link_cleanup(&wrong_sender);
	lichen_link_cleanup(&relay);
}

ZTEST(link_relay, test_rejects_valid_signature_with_noncanonical_siid)
{
	static const uint8_t payload[] = { 0x15, 0x09 };
	struct lichen_link_ctx sender;
	struct lichen_link_ctx relay;
	struct lichen_link_rx_ctx rx = { 0 };
	uint8_t incoming[LICHEN_MAX_FRAME_LEN];
	uint8_t output[LICHEN_MAX_FRAME_LEN];
	uint8_t before_output[LICHEN_MAX_FRAME_LEN];
	size_t incoming_len;
	size_t output_len = sizeof(output);
	uint16_t seq_before;
	int ret;

	init_keyed(&sender, 1U, 0x11U);
	init_keyed(&relay, 2U, 0x22U);
	incoming_len = build_noncanonical_siid(&sender, payload, sizeof(payload),
					       incoming, sizeof(incoming));
	rx.peer_pubkey = sender.ed25519_pk;
	memset(output, 0x5a, sizeof(output));
	memcpy(before_output, output, sizeof(output));
	seq_before = relay.tx_seq;

	ret = lichen_link_relay_frame(&rx, NULL, &relay, incoming, incoming_len,
				      NULL, output, &output_len);
	zassert_equal(ret, -LICHEN_EAUTH);
	zassert_equal(output_len, sizeof(output));
	zassert_equal(relay.tx_seq, seq_before);
	zassert_mem_equal(output, before_output, sizeof(output));

	lichen_link_cleanup(&sender);
	lichen_link_cleanup(&relay);
}

ZTEST_SUITE(link_relay, NULL, NULL, before, NULL, NULL);
