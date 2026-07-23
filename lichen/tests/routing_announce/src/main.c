/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>
#include <zephyr/sys/util.h>

#include <tinycrypt/sha256.h>

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

static void put_be32(uint8_t *buf, uint32_t value)
{
	buf[0] = (uint8_t)(value >> 24);
	buf[1] = (uint8_t)(value >> 16);
	buf[2] = (uint8_t)(value >> 8);
	buf[3] = (uint8_t)value;
}

static void pubkey_to_iid(const uint8_t pubkey[32], uint8_t iid[8])
{
	struct tc_sha256_state_struct sha_state;
	uint8_t hash[TC_SHA256_DIGEST_SIZE];

	(void)tc_sha256_init(&sha_state);
	(void)tc_sha256_update(&sha_state, pubkey, 32U);
	(void)tc_sha256_final(hash, &sha_state);
	memcpy(iid, hash, 8U);
	iid[0] &= (uint8_t)~0x02U;
}

static void build_coords(uint8_t app_data[9], int32_t lat_e7, int32_t lon_e7)
{
	app_data[0] = 0x01U;
	put_be32(&app_data[1], (uint32_t)lat_e7);
	put_be32(&app_data[5], (uint32_t)lon_e7);
}

static size_t build_signed_announce(uint8_t *buf, size_t cap,
				    const uint8_t seed[32], uint16_t seq_num,
				    uint8_t rx_channel,
				    const uint8_t *app_data, size_t app_data_len)
{
	uint8_t privkey[32];
	uint8_t pubkey[32];
	uint8_t signed_data[256];
	uint8_t signature[48];
	size_t signed_len;

	zassert_true(cap >= LICHEN_ANNOUNCE_MIN_LEN + app_data_len);
	zassert_true(sizeof(signed_data) >= 43U + app_data_len);

	schnorr48_derive_keypair(seed, privkey, pubkey);
	pubkey_to_iid(pubkey, &buf[5]);

	memcpy(&signed_data[0], &buf[5], 8U);
	memcpy(&signed_data[8], pubkey, sizeof(pubkey));
	signed_data[40] = (uint8_t)(seq_num >> 8);
	signed_data[41] = (uint8_t)seq_num;
	signed_data[42] = rx_channel;
	if (app_data_len > 0U) {
		memcpy(&signed_data[43], app_data, app_data_len);
	}
	signed_len = 43U + app_data_len;
	zassert_ok(schnorr48_sign(privkey, pubkey, signed_data, signed_len,
				  signature));

	buf[0] = LICHEN_ANNOUNCE_TYPE;
	buf[1] = rx_channel; /* rx_channel reuses flags byte per CCP-9 test vector */
	buf[2] = 0U; /* hop_count */
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
				    0U /* rx_channel */, app_data, sizeof(app_data));

	zassert_ok(lichen_announce_parse(announce, len, &view));
	zassert_equal(view.flags, 0U);
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
				    0U /* rx_channel */, app_data, sizeof(app_data));
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, &meta));
	len = build_signed_announce(announce, sizeof(announce), seed_a, 0U,
				    0U /* rx_channel */, app_data, sizeof(app_data));
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
				    0U /* rx_channel */, app_data, sizeof(app_data));
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
				    0U /* rx_channel */, app_data, sizeof(app_data));
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, NULL));
	memcpy(pinned_iid, &announce[5], sizeof(pinned_iid));
	zassert_equal(lichen_announce_ingest_authenticated(announce, len, NULL),
		      -EALREADY);
	zassert_equal(state.calls, 1U);

	len = build_signed_announce(announce, sizeof(announce), seed_b, 11U,
				    0U /* rx_channel */, app_data, sizeof(app_data));
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
				    0U /* rx_channel */, app_data, sizeof(app_data));
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, NULL));
	zassert_equal(normal.calls, 1U);
	zassert_equal(reset_aware.calls, 1U);

	len = build_signed_announce(announce, sizeof(announce), seed_a, 1U,
				    0U /* rx_channel */, app_data, sizeof(app_data));
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
				    0U /* rx_channel */, app_data, sizeof(app_data));
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
				    0U /* rx_channel */, app_data, sizeof(app_data));

	zassert_equal(lichen_announce_ingest_authenticated(announce, len, NULL),
		      -EINVAL);
	state.ret = 0;
	zassert_ok(lichen_announce_ingest_authenticated(announce, len, NULL));
	zassert_equal(state.calls, 2U);
}

ZTEST_SUITE(routing_announce, NULL, NULL, before, NULL, NULL);
