/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>
#include <zephyr/sys/util.h>

#include <monocypher.h>
#include <monocypher-ed25519.h>

#include <lichen/l2_payload.h>
#include <lichen/routing/announce.h>
#include <lichen/schnorr48.h>

struct callback_state {
	int ret;
	unsigned int calls;
	struct lichen_announce_view last_announce;
	struct lichen_announce_rx_meta last_meta;
};

static const uint8_t seed_a[32] = {
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};

static const uint8_t seed_b[32] = {
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
};

/* announce_signed_data.json:announce_signed_data_transcript */
static const uint8_t canonical_seed[32] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

static const uint8_t canonical_announce_frame[97] = {
	0x01, 0x03, 0x00, 0x12, 0x34, 0x71, 0x59, 0xbd,
	0x63, 0x3b, 0x2e, 0x91, 0x20, 0x20, 0x7a, 0x06,
	0x78, 0x92, 0x82, 0x1e, 0x25, 0xd7, 0x70, 0xf1,
	0xfb, 0xa0, 0xc4, 0x7c, 0x11, 0xff, 0x4b, 0x81,
	0x3e, 0x54, 0x16, 0x2e, 0xce, 0x9e, 0xb8, 0x39,
	0xe0, 0x76, 0x23, 0x1a, 0xb6, 0x8f, 0xb8, 0x02,
	0x65, 0x60, 0x20, 0x5a, 0x28, 0x14, 0x05, 0xca,
	0x54, 0x47, 0x42, 0xaa, 0xb4, 0x1f, 0x72, 0xff,
	0x9e, 0xbb, 0xbc, 0xc6, 0x1f, 0xd4, 0x93, 0xf0,
	0xa4, 0xad, 0x72, 0x64, 0x83, 0x91, 0x49, 0xea,
	0x51, 0xca, 0x84, 0x2e, 0xf1, 0xbf, 0x82, 0x3c,
	0x24, 0xdf, 0xfa, 0x5e, 0x0d, 0xde, 0xad, 0xbe,
	0xef,
};

static void put_be32(uint8_t *buf, uint32_t value)
{
	buf[0] = (uint8_t)(value >> 24);
	buf[1] = (uint8_t)(value >> 16);
	buf[2] = (uint8_t)(value >> 8);
	buf[3] = (uint8_t)value;
}

static void pubkey_to_iid(const uint8_t pubkey[32], uint8_t iid[8])
{
	uint8_t hash[64];

	crypto_sha512(hash, pubkey, 32U);
	memcpy(iid, hash, 8U);
	iid[0] &= (uint8_t)~0x02U;
	crypto_wipe(hash, sizeof(hash));
}

static void build_coords(uint8_t app_data[9], int32_t lat_e7, int32_t lon_e7)
{
	app_data[0] = 0x01U;
	put_be32(&app_data[1], (uint32_t)lat_e7);
	put_be32(&app_data[5], (uint32_t)lon_e7);
}

static size_t build_signed_announce(uint8_t *buf, size_t cap,
				    const uint8_t seed[32], uint16_t seq_num,
				    uint8_t rx_channel, const uint8_t *app_data,
				    size_t app_data_len)
{
	uint8_t privkey[32];
	uint8_t pubkey[32];
	uint8_t signed_data[256];
	uint8_t signature[48];
	size_t signed_len;
	static const uint8_t signing_domain[] = "LICHEN-ANNOUNCE-v1";

	zassert_true(cap >= LICHEN_ANNOUNCE_MIN_LEN + app_data_len);
	zassert_equal(sizeof(signing_domain), 19U);
	zassert_true(sizeof(signed_data) >= 64U + app_data_len);
	zassert_true(rx_channel < 8U);
	zassert_true(app_data_len <= LICHEN_ANNOUNCE_MAX_APP_DATA_LEN);

	schnorr48_derive_keypair(seed, privkey, pubkey);
	pubkey_to_iid(pubkey, &buf[5]);

	memcpy(&signed_data[0], signing_domain, sizeof(signing_domain));
	memcpy(&signed_data[19], &buf[5], 8U);
	memcpy(&signed_data[27], pubkey, sizeof(pubkey));
	signed_data[59] = (uint8_t)(seq_num >> 8);
	signed_data[60] = (uint8_t)seq_num;
	signed_data[61] = rx_channel; /* rx_channel in flags, signed per CCP-9 */
	signed_data[62] = (uint8_t)(app_data_len >> 8);
	signed_data[63] = (uint8_t)app_data_len;
	if (app_data_len > 0U) {
		memcpy(&signed_data[64], app_data, app_data_len);
	}
	signed_len = 64U + app_data_len;
	zassert_ok(schnorr48_sign(privkey, pubkey, signed_data, signed_len,
				  signature));

	buf[0] = LICHEN_ANNOUNCE_TYPE;
	buf[1] = rx_channel; /* flags = rx_channel per CCP-9 */
	buf[2] = 0U; /* hop */
	buf[3] = (uint8_t)(seq_num >> 8);
	buf[4] = (uint8_t)seq_num;
	memcpy(&buf[13], pubkey, sizeof(pubkey));
	memcpy(&buf[45], signature, sizeof(signature));
	if (app_data_len > 0U) {
		memcpy(&buf[LICHEN_ANNOUNCE_MIN_LEN], app_data, app_data_len);
	}
	return LICHEN_ANNOUNCE_MIN_LEN + app_data_len;
}

static int capture_callback(const struct lichen_announce_view *announce,
			    const struct lichen_announce_rx_meta *meta,
			    void *user_data)
{
	struct callback_state *state = user_data;

	state->calls++;
	state->last_announce = *announce;
	state->last_meta = *meta;
	return state->ret;
}

static int capture_callback_alt(const struct lichen_announce_view *announce,
				const struct lichen_announce_rx_meta *meta,
				void *user_data)
{
	return capture_callback(announce, meta, user_data);
}

static void before(void *fixture)
{
	ARG_UNUSED(fixture);
	lichen_announce_reset();
}

ZTEST(routing_announce, test_parse_accepts_minimal_and_app_data)
{
	uint8_t app_data[9];
	uint8_t announce[LICHEN_ANNOUNCE_MIN_LEN + sizeof(app_data)];
	struct lichen_announce_view view;
	size_t len;

	build_coords(app_data, 476062000, -1223321000);
	len = build_signed_announce(announce, sizeof(announce), seed_a, 0x1234U,
				    0U, app_data, sizeof(app_data));

	zassert_ok(lichen_announce_parse(announce, len, &view));
	zassert_equal(view.hop_count, 0U);
	zassert_equal(view.rx_channel, 0U);
	zassert_equal(view.wire_seq_num, 0x1234U);
	zassert_equal(view.seq_num, 0x1234U);
	zassert_false(view.seq_stale);
	zassert_mem_equal(view.originator_iid, &announce[5], 8U);
	zassert_mem_equal(view.pubkey, &announce[13], 32U);
	zassert_mem_equal(view.signature, &announce[45], 48U);
	zassert_mem_equal(view.app_data, app_data, sizeof(app_data));
	zassert_equal(view.app_data_len, sizeof(app_data));
}

ZTEST(routing_announce, test_canonical_vector_encode_decode)
{
	static const uint8_t app_data[] = { 0xde, 0xad, 0xbe, 0xef };
	uint8_t built[sizeof(canonical_announce_frame)];
	uint8_t encoded[sizeof(canonical_announce_frame)];
	struct lichen_announce_view view;
	size_t len;

	len = build_signed_announce(built, sizeof(built), canonical_seed,
				    0x1234U, 3U, app_data, sizeof(app_data));
	zassert_equal(len, sizeof(canonical_announce_frame));
	zassert_mem_equal(built, canonical_announce_frame,
			  sizeof(canonical_announce_frame));

	zassert_ok(lichen_announce_parse(canonical_announce_frame,
					 sizeof(canonical_announce_frame), &view));
	zassert_equal(view.rx_channel, 3U);
	zassert_equal(view.hop_count, 0U);
	zassert_equal(view.wire_seq_num, 0x1234U);
	zassert_mem_equal(view.app_data, app_data, sizeof(app_data));
	zassert_equal(lichen_announce_encode(&view, encoded, sizeof(encoded)),
		      sizeof(encoded));
	zassert_mem_equal(encoded, canonical_announce_frame, sizeof(encoded));

	/* This also verifies the canonical domain-separated signature transcript. */
	zassert_ok(lichen_announce_ingest_authenticated(
		canonical_announce_frame, sizeof(canonical_announce_frame), NULL));
}

ZTEST(routing_announce, test_encode_decode_profile_boundaries)
{
	uint8_t iid[LICHEN_ANNOUNCE_IID_LEN] = { 0 };
	uint8_t pubkey[LICHEN_ANNOUNCE_PUBKEY_LEN] = { 0 };
	uint8_t signature[LICHEN_ANNOUNCE_SIGNATURE_LEN] = { 0 };
	uint8_t app_data[LICHEN_ANNOUNCE_MAX_APP_DATA_LEN + 1U] = { 0 };
	uint8_t wire[LICHEN_ANNOUNCE_MAX_LEN + 1U] = { 0 };
	struct lichen_announce_view decoded;
	struct lichen_announce_view announce = {
		.hop_count = LICHEN_ANNOUNCE_MAX_HOPS,
		.rx_channel = 7U,
		.wire_seq_num = UINT16_MAX,
		.seq_num = UINT16_MAX,
		.originator_iid = iid,
		.pubkey = pubkey,
		.signature = signature,
		.app_data = app_data,
		.app_data_len = LICHEN_ANNOUNCE_MAX_APP_DATA_LEN,
	};

	zassert_equal(lichen_announce_encode(&announce, wire,
					     LICHEN_ANNOUNCE_MAX_LEN),
		      LICHEN_ANNOUNCE_MAX_LEN);
	zassert_ok(lichen_announce_parse(wire, LICHEN_ANNOUNCE_MAX_LEN,
					 &decoded));
	zassert_equal(decoded.app_data_len, LICHEN_ANNOUNCE_MAX_APP_DATA_LEN);
	zassert_equal(decoded.hop_count, LICHEN_ANNOUNCE_MAX_HOPS);
	zassert_equal(decoded.rx_channel, 7U);
	zassert_equal(decoded.wire_seq_num, UINT16_MAX);

	zassert_equal(lichen_announce_encode(&announce, wire,
					     LICHEN_ANNOUNCE_MAX_LEN - 1U),
		      -ENOMEM);
	announce.app_data_len = LICHEN_ANNOUNCE_MAX_APP_DATA_LEN + 1U;
	zassert_equal(lichen_announce_encode(&announce, wire, sizeof(wire)),
		      -EMSGSIZE);
	announce.app_data_len = 0U;
	announce.rx_channel = 8U;
	zassert_equal(lichen_announce_encode(&announce, wire, sizeof(wire)),
		      -EINVAL);
	announce.rx_channel = 0U;
	announce.hop_count = LICHEN_ANNOUNCE_MAX_HOPS + 1U;
	zassert_equal(lichen_announce_encode(&announce, wire, sizeof(wire)),
		      -EINVAL);

	wire[0] = LICHEN_ANNOUNCE_TYPE;
	wire[1] = 0U;
	wire[2] = 0U;
	zassert_equal(lichen_announce_parse(wire, sizeof(wire), &decoded),
		      -EMSGSIZE);
}

ZTEST(routing_announce, test_ingest_invokes_observer_with_meta_and_extended_seq)
{
	uint8_t app_data[9];
	uint8_t announce[LICHEN_ANNOUNCE_MIN_LEN + sizeof(app_data)];
	struct callback_state state = { 0 };
	const struct lichen_announce_rx_meta meta = {
		.immediate_eui64 = { 1, 2, 3, 4, 5, 6, 7, 8 },
		.rssi_dbm = -91,
		.snr_db = 7,
		.link_epoch = 3,
		.link_seqnum = 0x4567U,
		.observed_uptime_s = 123U,
	};
	size_t len;

	build_coords(app_data, 476062000, -1223321000);
	zassert_ok(lichen_announce_register_app_data_observer(capture_callback,
							      &state));

	len = build_signed_announce(announce, sizeof(announce), seed_a, 0xffffU,
				    0U, app_data, sizeof(app_data));
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, &meta));
	len = build_signed_announce(announce, sizeof(announce), seed_a, 0U,
				    0U, app_data, sizeof(app_data));
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, &meta));

	zassert_equal(state.calls, 2U);
	zassert_equal(state.last_announce.seq_num, 0x10000U);
	zassert_equal(state.last_announce.wire_seq_num, 0U);
	zassert_mem_equal(state.last_announce.app_data, app_data,
			  sizeof(app_data));
	zassert_mem_equal(state.last_meta.immediate_eui64, meta.immediate_eui64,
			  sizeof(meta.immediate_eui64));
	zassert_equal(state.last_meta.rssi_dbm, -91);
	zassert_equal(state.last_meta.snr_db, 7);
	zassert_equal(state.last_meta.link_epoch, 3U);
	zassert_equal(state.last_meta.link_seqnum, 0x4567U);
	zassert_equal(state.last_meta.observed_uptime_s, 123U);
}

ZTEST(routing_announce, test_ingest_invokes_multiple_observers)
{
	uint8_t app_data[9];
	uint8_t announce[LICHEN_ANNOUNCE_MIN_LEN + sizeof(app_data)];
	struct callback_state first = { 0 };
	struct callback_state second = { 0 };
	size_t len;

	build_coords(app_data, 476062000, -1223321000);
	zassert_ok(lichen_announce_register_app_data_observer(capture_callback,
							      &first));
	zassert_ok(lichen_announce_register_app_data_observer(capture_callback_alt,
							      &second));

	len = build_signed_announce(announce, sizeof(announce), seed_a, 3U,
				    0U, app_data, sizeof(app_data));
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, NULL));

	zassert_equal(first.calls, 1U);
	zassert_equal(second.calls, 1U);
	zassert_equal(first.last_announce.seq_num, 3U);
	zassert_equal(second.last_announce.seq_num, 3U);
}

ZTEST(routing_announce, test_ingest_rejects_stale_seq_and_bad_pubkey_pin)
{
	uint8_t app_data[9];
	uint8_t announce[LICHEN_ANNOUNCE_MIN_LEN + sizeof(app_data)];
	uint8_t pinned_iid[8];
	struct callback_state state = { 0 };
	size_t len;

	build_coords(app_data, 100000000, 200000000);
	zassert_ok(lichen_announce_register_app_data_observer(capture_callback,
							      &state));

	len = build_signed_announce(announce, sizeof(announce), seed_a, 10U,
				    0U, app_data, sizeof(app_data));
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, NULL));
	memcpy(pinned_iid, &announce[5], sizeof(pinned_iid));
	zassert_equal(lichen_announce_ingest_authenticated(announce, len, NULL),
		      -EALREADY);
	zassert_equal(state.calls, 1U);

	len = build_signed_announce(announce, sizeof(announce), seed_b, 11U,
				    0U, app_data, sizeof(app_data));
	memcpy(&announce[5], pinned_iid, sizeof(pinned_iid));
	zassert_equal(lichen_announce_ingest_authenticated(announce, len, NULL),
		      -EACCES);
}

ZTEST(routing_announce, test_stale_seq_requires_reset_aware_observer)
{
	uint8_t app_data[9];
	uint8_t announce[LICHEN_ANNOUNCE_MIN_LEN + sizeof(app_data)];
	struct callback_state normal = { 0 };
	struct callback_state reset_aware = {
		.ret = LICHEN_ANNOUNCE_ACCEPT_SEQ_RESET,
	};
	size_t len;

	build_coords(app_data, 300000000, 400000000);
	zassert_ok(lichen_announce_register_app_data_observer(capture_callback,
							      &normal));
	zassert_ok(lichen_announce_register_app_data_observer_ex(
		capture_callback_alt, &reset_aware,
		LICHEN_ANNOUNCE_OBSERVER_F_ALLOW_SEQ_RESET));

	len = build_signed_announce(announce, sizeof(announce), seed_a, 10U,
				    0U, app_data, sizeof(app_data));
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, NULL));
	zassert_equal(normal.calls, 1U);
	zassert_equal(reset_aware.calls, 1U);

	len = build_signed_announce(announce, sizeof(announce), seed_a, 1U,
				    0U, app_data, sizeof(app_data));
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, NULL));
	zassert_equal(normal.calls, 1U);
	zassert_equal(reset_aware.calls, 2U);
	zassert_equal(reset_aware.last_announce.seq_num, 0x10001U);
	zassert_equal(reset_aware.last_announce.wire_seq_num, 1U);
	zassert_true(reset_aware.last_announce.seq_stale);
}

ZTEST(routing_announce, test_l2_payload_requires_routing_dispatch)
{
	uint8_t app_data[9];
	uint8_t announce[LICHEN_ANNOUNCE_MIN_LEN + sizeof(app_data)];
	uint8_t wrapped[1U + sizeof(announce)];
	struct callback_state state = { 0 };
	size_t len;

	build_coords(app_data, 300000000, 400000000);
	zassert_ok(lichen_announce_register_app_data_observer(capture_callback,
							      &state));
	len = build_signed_announce(announce, sizeof(announce), seed_a, 1U,
				    0U, app_data, sizeof(app_data));
	wrapped[0] = LICHEN_L2_DISPATCH_ROUTING;
	memcpy(&wrapped[1], announce, len);

	zassert_equal(lichen_announce_ingest_l2_payload(announce, len, NULL),
		      -EPROTONOSUPPORT);
	zassert_ok(lichen_announce_ingest_l2_payload(wrapped, len + 1U, NULL));
	zassert_equal(state.calls, 1U);
}

ZTEST(routing_announce, test_callback_failure_allows_same_seq_retry)
{
	uint8_t app_data[9];
	uint8_t announce[LICHEN_ANNOUNCE_MIN_LEN + sizeof(app_data)];
	struct callback_state state = { .ret = -EINVAL };
	size_t len;

	build_coords(app_data, 300000000, 400000000);
	zassert_ok(lichen_announce_register_app_data_observer(capture_callback,
							      &state));
	len = build_signed_announce(announce, sizeof(announce), seed_a, 7U,
				    0U, app_data, sizeof(app_data));

	zassert_equal(lichen_announce_ingest_authenticated(announce, len, NULL),
		      -EINVAL);
	state.ret = 0;
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, NULL));
	zassert_equal(state.calls, 2U);
}

ZTEST_SUITE(routing_announce, NULL, NULL, before, NULL, NULL);
