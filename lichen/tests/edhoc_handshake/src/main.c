/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>
#include <lichen/edhoc.h>

/* Fixed cross-language fixture: Python, Rust and Zephyr must consume these
 * bytes rather than computing expectations from the implementation under test. */
static const char msg1_hex[] =
	"00005820132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f4724100";
static const char msg2_hex[] =
	"585e132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f4724"
	"f91e93515795dcc37933a420157da449c6884e46f932e90111f5653ddfd677c706340631426a0c59cddbe2bd3873284e620b7dcde9703f2eee0a3d45593";
static const char msg3_hex[] =
	"5845f66b86fd0501ff4a8ef8a5d6e065298ee19889f4502c8161c0461ddfde5471d0af7aa2bd7e7e931a4b22cc323da67d39ca1e8e43494623b6425229340d63648236da5c635f";
static const char pub_i_hex[] = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
static const char pub_r_hex[] = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";
static const char eph_pk_hex[] = "132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472";
static const char th2_hex[] = "ff87fefbc6d2556859515b9e085eadaddc76a18aa104d7de965b2fe7c4cebc58";
static const char th3_hex[] = "792dba3b5ecc4dcc70ee80ad7b632b77731a96aea27628f4f6ce0e0e8a0cb457";
static const char th4_hex[] = "fbdc483c50e3c584b95796ed16231685d29e55e23c6320e0bacb5990b953cd16";
static const char secret_hex[] = "8157a9957b44147e13a55bb4495c153f";
static const char salt_hex[] = "5679a884145655c1";

static uint8_t nibble(char c)
{
	return (uint8_t)(c <= '9' ? c - '0' : c - 'a' + 10);
}

static size_t decode(const char *hex, uint8_t *out, size_t capacity)
{
	size_t len = strlen(hex) / 2;
	zassert_true(len <= capacity);
	for (size_t i = 0; i < len; ++i) {
		out[i] = (uint8_t)((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
	}
	return len;
}

static void setup(struct edhoc_initiator *i, struct edhoc_responder *r,
		  uint8_t pub_i[32], uint8_t pub_r[32])
{
	uint8_t seed_i[32], seed_r[32], eph_pk[32];
	for (size_t n = 0; n < 32; ++n) {
		seed_i[n] = (uint8_t)n;
		seed_r[n] = (uint8_t)(n + 32);
	}
	decode(pub_i_hex, pub_i, 32); decode(pub_r_hex, pub_r, 32);
	decode(eph_pk_hex, eph_pk, 32);
	memset(i, 0, sizeof(*i)); memset(r, 0, sizeof(*r));
	i->state = EDHOC_STATE_IDLE; i->method = EDHOC_METHOD_SIGN_SIGN;
	r->state = EDHOC_STATE_IDLE; r->method = EDHOC_METHOD_SIGN_SIGN;
	memcpy(i->ed_seed, seed_i, 32); memcpy(i->ed_pubkey, pub_i, 32);
	memcpy(r->ed_seed, seed_r, 32); memcpy(r->ed_pubkey, pub_r, 32);
	i->c_i[0] = 0; i->c_i_len = 1; r->c_r[0] = 1; r->c_r_len = 1;
	memset(i->eph_sk, 0x42, 32); memcpy(i->eph_pk, eph_pk, 32);
	memset(r->eph_sk, 0x42, 32); memcpy(r->eph_pk, eph_pk, 32);
}

ZTEST(edhoc_handshake, test_exact_method0_handshake_and_export)
{
	struct edhoc_initiator i = {0}; struct edhoc_responder r = {0};
	struct edhoc_oscore_ctx oi = {0}, or = {0};
	uint8_t pub_i[32], pub_r[32], expected[192], msg1[64], msg2[160], msg3[96];
	size_t expected_len, len1 = 0, len2 = 0, len3 = 0;
	setup(&i, &r, pub_i, pub_r);
	zassert_equal(edhoc_initiator_create_msg1(&i, msg1, sizeof(msg1), &len1), 0);
	expected_len = decode(msg1_hex, expected, sizeof(expected));
	zassert_equal(len1, expected_len); zassert_mem_equal(msg1, expected, len1);
	zassert_equal(edhoc_responder_process_msg1(&r, msg1, len1, msg2, sizeof(msg2), &len2), 0);
	expected_len = decode(msg2_hex, expected, sizeof(expected));
	zassert_equal(len2, expected_len);
	zassert_mem_equal(msg2, expected, len2);
	zassert_equal(edhoc_initiator_process_msg2(&i, msg2, len2, pub_r,
					  msg3, sizeof(msg3), &len3), 0);
	expected_len = decode(msg3_hex, expected, sizeof(expected));
	zassert_equal(len3, expected_len); zassert_mem_equal(msg3, expected, len3);
	zassert_equal(edhoc_responder_process_msg3(&r, msg3, len3, pub_i), 0);
	zassert_equal(edhoc_responder_process_msg1(&r, msg1, len1,
					  msg2, sizeof(msg2), &len2), -EBUSY);
	zassert_equal(edhoc_initiator_process_msg2(&i, msg2, len2, pub_r,
					  msg3, sizeof(msg3), &len3), -EBUSY);
	zassert_equal(edhoc_responder_process_msg3(&r, msg3, len3, pub_i), -EBUSY);
	decode(th2_hex, expected, sizeof(expected)); zassert_mem_equal(i.th_2, expected, 32);
	zassert_mem_equal(r.th_2, expected, 32);
	decode(th3_hex, expected, sizeof(expected)); zassert_mem_equal(i.th_3, expected, 32);
	zassert_mem_equal(r.th_3, expected, 32);
	decode(th4_hex, expected, sizeof(expected)); zassert_mem_equal(i.th_4, expected, 32);
	zassert_mem_equal(r.th_4, expected, 32);
	zassert_equal(edhoc_initiator_export_oscore(&i, &oi), 0);
	zassert_equal(edhoc_responder_export_oscore(&r, &or), 0);
	decode(secret_hex, expected, sizeof(expected)); zassert_mem_equal(oi.master_secret, expected, 16);
	zassert_mem_equal(or.master_secret, expected, 16);
	decode(salt_hex, expected, sizeof(expected)); zassert_mem_equal(oi.master_salt, expected, 8);
	zassert_mem_equal(or.master_salt, expected, 8);
	zassert_equal(oi.sender_id[0], 1); zassert_equal(oi.recipient_id[0], 0);
	zassert_equal(or.sender_id[0], 0); zassert_equal(or.recipient_id[0], 1);
}

ZTEST(edhoc_handshake, test_rejection_is_terminal_and_output_atomic)
{
	struct edhoc_initiator i = {0}; struct edhoc_responder r = {0};
	uint8_t pub_i[32], pub_r[32], msg1[64], msg2[160], msg3[96], before[96];
	size_t len1 = 0, len2 = 0, len3 = 0;
	setup(&i, &r, pub_i, pub_r);
	zassert_equal(edhoc_initiator_create_msg1(&i, msg1, sizeof(msg1), &len1), 0);
	zassert_equal(edhoc_responder_process_msg1(&r, msg1, len1, msg2, sizeof(msg2), &len2), 0);
	memset(msg3, 0xa5, sizeof(msg3)); memcpy(before, msg3, sizeof(msg3)); len3 = 77;
	zassert_not_equal(edhoc_initiator_process_msg2(&i, msg2, len2 - 1, pub_r,
					      msg3, sizeof(msg3), &len3), 0);
	zassert_equal(i.state, EDHOC_STATE_ERROR); zassert_equal(len3, 77);
	zassert_mem_equal(msg3, before, sizeof(msg3));
	zassert_equal(edhoc_initiator_process_msg2(&i, msg2, len2, pub_r,
					  msg3, sizeof(msg3), &len3), -EBUSY);

	setup(&i, &r, pub_i, pub_r);
	zassert_equal(edhoc_initiator_create_msg1(&i, msg1, sizeof(msg1), &len1), 0);
	zassert_equal(edhoc_responder_process_msg1(&r, msg1, len1, msg2, sizeof(msg2), &len2), 0);
	zassert_equal(edhoc_initiator_process_msg2(&i, msg2, len2, pub_r,
					  msg3, sizeof(msg3), &len3), 0);
	msg3[len3 - 1] ^= 1;
	zassert_not_equal(edhoc_responder_process_msg3(&r, msg3, len3, pub_i), 0);
	zassert_equal(r.state, EDHOC_STATE_ERROR);

	setup(&i, &r, pub_i, pub_r);
	zassert_equal(edhoc_initiator_create_msg1(&i, msg1, sizeof(msg1), &len1), 0);
	zassert_equal(edhoc_responder_process_msg1(&r, msg1, len1, msg2, sizeof(msg2), &len2), 0);
	memset(msg3, 0x3c, sizeof(msg3)); memcpy(before, msg3, sizeof(msg3)); len3 = 55;
	uint8_t wrong_peer[32] = {0};
	zassert_not_equal(edhoc_initiator_process_msg2(&i, msg2, len2, wrong_peer,
					      msg3, sizeof(msg3), &len3), 0);
	zassert_equal(i.state, EDHOC_STATE_ERROR); zassert_equal(len3, 55);
	zassert_mem_equal(msg3, before, sizeof(msg3));
}

ZTEST_SUITE(edhoc_handshake, NULL, NULL, NULL, NULL, NULL);
