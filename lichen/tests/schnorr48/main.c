/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Schnorr-48 unit tests using vectors from test/vectors/schnorr48.json
 *
 * Full cross-implementation coverage matching Rust/Python: all 5 valid + all
 * invalid cases (including low-order points, non-canonical scalars, identity,
 * zero-s, etc.).
 */

#include <lichen/schnorr48.h>
#include <lichen/link.h>
#include <errno.h>
#include <string.h>

_Static_assert(SCHNORR48_SIG_LEN == 48, "Schnorr wire signature changed");

typedef int (*schnorr48_sign_frame_api)(
	uint8_t, uint8_t, uint8_t, uint16_t, const uint8_t *, size_t,
	const uint8_t *, size_t, const uint8_t *, const uint8_t *, uint8_t *);
typedef int (*schnorr48_verify_frame_api)(
	uint8_t, uint8_t, uint8_t, uint16_t, const uint8_t *, size_t,
	const uint8_t *, size_t, const uint8_t *, const uint8_t *);

static schnorr48_sign_frame_api const sign_frame_api = schnorr48_sign_frame;
static schnorr48_verify_frame_api const verify_frame_api = schnorr48_verify_frame;
#include <stdio.h>
#include <stdint.h>

/* Hex decode helpers */

static int hex_digit(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t max_len)
{
	size_t hex_len = strlen(hex);
	if (hex_len % 2 != 0) {
		return 0;  /* odd-length hex is invalid */
	}
	size_t bytes = hex_len / 2;

	if (bytes > max_len) {
		return 0;
	}

	for (size_t i = 0; i < bytes; i++) {
		int hi = hex_digit(hex[i * 2]);
		int lo = hex_digit(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0) {
			return 0;
		}
		out[i] = (hi << 4) | lo;
	}
	return bytes;
}

static void hex_dump(const char *label, const uint8_t *buf, size_t len)
{
	printf("%s: ", label);
	for (size_t i = 0; i < len; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

/* Test infrastructure */

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
	if (memcmp((a), (b), (len)) != 0) { \
		printf("  FAIL: %s\n", msg); \
		hex_dump("    got", (a), (len)); \
		hex_dump("    exp", (b), (len)); \
		return 0; \
	} \
} while (0)

#define ASSERT_TRUE(cond, msg) do { \
	if (!(cond)) { \
		printf("  FAIL: %s\n", msg); \
		return 0; \
	} \
} while (0)

#define ASSERT_FALSE(cond, msg) do { \
	if ((cond)) { \
		printf("  FAIL: %s (expected false)\n", msg); \
		return 0; \
	} \
} while (0)

/* Test vector structure */

struct test_vector {
	const char *description;
	const char *seed;
	const char *private_key;
	const char *public_key;
	const char *message;
	const char *signature;
	int valid;
};

/*
 * Test vectors from test/vectors/schnorr48.json
 */

static const struct test_vector valid_vectors[] = {
	{
		.description = "Empty message, zero seed",
		.seed = "0000000000000000000000000000000000000000000000000000000000000000",
		.private_key = "5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156",
		.public_key = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
		.message = "",
		.signature = "26f70691bbde0c1e8becc00e7e7663cb6b72364b6ea208fdabef226c5b0d07cec9c661fd69671981ca40277598ea9c01",
		.valid = 1,
	},
	{
		.description = "Simple 'test' message",
		.seed = "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
		.private_key = "50b8c29238a8403e0ac69e23d47b9184c371a92460d518351b099944bbdfa867",
		.public_key = "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
		.message = "74657374",
		.signature = "c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009",
		.valid = 1,
	},
	{
		.description = "Longer message (pangram)",
		.seed = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		.private_key = "b0829ce3ccf1d8edd5da1132d46271b0169f58b6414fd263d3c98da627170f5e",
		.public_key = "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6",
		.message = "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
		.signature = "e15b69ed5bd6fccc6c624431eb1bb08341ba571158da31249ac72a28af7f77ea0534b94cc1f8650dead98ccae16ec803",
		.valid = 1,
	},
	{
		.description = "Binary message with null bytes",
		.seed = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		.private_key = "20cd6935864716a79d74dd5fabbd8964304051ca41a31c4659158ebb7c3d0b57",
		.public_key = "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
		.message = "000102030000fffe",
		.signature = "5f305af4656afd6278b1f2be87853e67e952b1449f17380a24ff98ee90fbcec193b82bd58f33291658b452b610febe0a",
		.valid = 1,
	},
	{
		.description = "LICHEN frame-like structure",
		.seed = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		.private_key = "68ae63a46076e4e250dd1cf4b15c5f645827bb55af53e23b76d8f3ffd1b8dd55",
		.public_key = "9474957069b71153ee776274d7d7b842fe9ddf33df44dc61b851f73c885af800",
		.message = "0100000100000000000000000000000000000000436f4150207061796c6f6164",
		.signature = "9d76e7510ffc2bad6e5d45b3b6db1ebe2586389ec18b4fb8297c4e366e912f5a0a6ac2f2e52769009e006e92ba864403",
		.valid = 1,
	},
};

static const struct test_vector invalid_vectors[] = {
	{
		.description = "Invalid: signature from vector 2 with wrong message",
		.public_key = "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
		.message = "77726f6e67",
		.signature = "c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009",
		.valid = 0,
	},
	{
		.description = "Invalid: tampered challenge byte",
		.public_key = "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
		.message = "74657374",
		.signature = "c9bec10578953fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009",
		.valid = 0,
	},
	{
		.description = "Invalid: tampered response byte",
		.public_key = "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
		.message = "74657374",
		.signature = "c9bec10578943fc8d453252fb262fa03ad2220609c98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009",
		.valid = 0,
	},
	{
		.description = "Invalid: wrong public key",
		.public_key = "207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6",
		.message = "74657374",
		.signature = "c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009",
		.valid = 0,
	},
	{
		.description = "Invalid: truncated signature (47 bytes)",
		.public_key = "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
		.message = "74657374",
		.signature = "c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e20",
		.valid = 0,
	},
	{
		.description = "Invalid: all-zero signature",
		.public_key = "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
		.message = "74657374",
		.signature = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		.valid = 0,
	},
	{
		.description = "Invalid: identity point as public key",
		.public_key = "0100000000000000000000000000000000000000000000000000000000000000",
		.message = "74657374",
		.signature = "c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009",
		.valid = 0,
	},
	{
		.description = "Invalid: low-order (8-torsion) point as public key",
		.public_key = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		.message = "74657374",
		.signature = "c9bec10578943fc8d453252fb262fa03ad2220609d98dda4b561d4b02281f1e8706676c26685a806d6e0d74f345e2009",
		.valid = 0,
	},
	{
		.description = "Invalid: non-canonical s (s = L, curve order)",
		.public_key = "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
		.message = "74657374",
		.signature = "c9bec10578943fc8d453252fb262fa03edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
		.valid = 0,
	},
	{
		.description = "Invalid: zero scalar s",
		.public_key = "9d7725e28403e00e9ee54f9b14c868faf99b4b2fafa936eda28f8ae40207780d",
		.message = "74657374",
		.signature = "c9bec10578943fc8d453252fb262fa030000000000000000000000000000000000000000000000000000000000000000",
		.valid = 0,
	},
};

/* Test functions */

static int test_keypair_derivation(void)
{
	for (size_t i = 0; i < sizeof(valid_vectors) / sizeof(valid_vectors[0]); i++) {
		const struct test_vector *v = &valid_vectors[i];

		uint8_t seed[32], expected_priv[32], expected_pub[32];
		uint8_t got_priv[32], got_pub[32];
		size_t n;

		n = hex_decode(v->seed, seed, 32);
		ASSERT_TRUE(n == 32, "seed hex_decode");

		n = hex_decode(v->private_key, expected_priv, 32);
		ASSERT_TRUE(n == 32, "private_key hex_decode");

		n = hex_decode(v->public_key, expected_pub, 32);
		ASSERT_TRUE(n == 32, "public_key hex_decode");

		schnorr48_derive_keypair(seed, got_priv, got_pub);

		char msg[128];
		snprintf(msg, sizeof(msg), "vector %zu privkey: %s", i, v->description);
		ASSERT_MEM_EQ(got_priv, expected_priv, 32, msg);

		snprintf(msg, sizeof(msg), "vector %zu pubkey: %s", i, v->description);
		ASSERT_MEM_EQ(got_pub, expected_pub, 32, msg);
	}
	return 1;
}

static int test_sign_matches_vectors(void)
{
	for (size_t i = 0; i < sizeof(valid_vectors) / sizeof(valid_vectors[0]); i++) {
		const struct test_vector *v = &valid_vectors[i];

		uint8_t privkey[32], pubkey[32], expected_sig[48], got_sig[48];
		uint8_t message[256];
		size_t msg_len, n;

		n = hex_decode(v->private_key, privkey, 32);
		ASSERT_TRUE(n == 32, "private_key hex_decode");

		n = hex_decode(v->public_key, pubkey, 32);
		ASSERT_TRUE(n == 32, "public_key hex_decode");

		n = hex_decode(v->signature, expected_sig, 48);
		ASSERT_TRUE(n == 48, "signature hex_decode");

		/* Empty message is valid (strlen == 0) */
		msg_len = hex_decode(v->message, message, sizeof(message));

		schnorr48_sign(privkey, pubkey, message, msg_len, got_sig);

		char msg_buf[128];
		snprintf(msg_buf, sizeof(msg_buf), "vector %zu signature: %s", i, v->description);
		ASSERT_MEM_EQ(got_sig, expected_sig, 48, msg_buf);
	}
	return 1;
}

static int test_verify_valid_signatures(void)
{
	for (size_t i = 0; i < sizeof(valid_vectors) / sizeof(valid_vectors[0]); i++) {
		const struct test_vector *v = &valid_vectors[i];

		uint8_t pubkey[32], sig[48];
		uint8_t message[256];
		size_t msg_len, n;

		n = hex_decode(v->public_key, pubkey, 32);
		ASSERT_TRUE(n == 32, "public_key hex_decode");

		n = hex_decode(v->signature, sig, 48);
		ASSERT_TRUE(n == 48, "signature hex_decode");

		/* Empty message is valid (strlen == 0) */
		msg_len = hex_decode(v->message, message, sizeof(message));

		char msg_buf[128];
		snprintf(msg_buf, sizeof(msg_buf), "vector %zu: %s", i, v->description);
		ASSERT_TRUE(schnorr48_verify(pubkey, message, msg_len, sig), msg_buf);
	}
	return 1;
}

static int test_verify_invalid_signatures(void)
{
	for (size_t i = 0; i < sizeof(invalid_vectors) / sizeof(invalid_vectors[0]); i++) {
		const struct test_vector *v = &invalid_vectors[i];

		uint8_t pubkey[32], sig[48] = {0};
		uint8_t message[256];
		size_t msg_len, n, expected_sig_len = strlen(v->signature) / 2;

		n = hex_decode(v->public_key, pubkey, 32);
		ASSERT_TRUE(n == 32, "public_key hex_decode");

		n = hex_decode(v->signature, sig, 48);
		ASSERT_TRUE(n == expected_sig_len, "signature hex_decode");

		msg_len = hex_decode(v->message, message, sizeof(message));

		char msg_buf[128];
		snprintf(msg_buf, sizeof(msg_buf), "vector %zu: %s", i, v->description);
		ASSERT_FALSE(schnorr48_verify(pubkey, message, msg_len, sig), msg_buf);
	}
	return 1;
}

static int test_sign_verify_roundtrip(void)
{
	/* Test with fresh keys and arbitrary message */
	uint8_t seed[32] = {
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
	};
	uint8_t privkey[32], pubkey[32];
	uint8_t message[] = "hello LICHEN mesh network";
	uint8_t sig[48] = { 0 };

	schnorr48_derive_keypair(seed, privkey, pubkey);
	schnorr48_sign(privkey, pubkey, message, sizeof(message) - 1, sig);

	ASSERT_TRUE(schnorr48_verify(pubkey, message, sizeof(message) - 1, sig),
		    "roundtrip verify");

	/* Tamper with message */
	message[0] ^= 1;
	ASSERT_FALSE(schnorr48_verify(pubkey, message, sizeof(message) - 1, sig),
		     "tampered message should fail");
	message[0] ^= 1;  /* restore */

	/* Tamper with signature */
	sig[0] ^= 1;
	ASSERT_FALSE(schnorr48_verify(pubkey, message, sizeof(message) - 1, sig),
		     "tampered signature should fail");
	sig[0] ^= 1;  /* restore */

	/* Wrong pubkey */
	uint8_t wrong_pubkey[32];
	memset(wrong_pubkey, 0x42, 32);
	ASSERT_FALSE(schnorr48_verify(wrong_pubkey, message, sizeof(message) - 1, sig),
		     "wrong pubkey should fail");

	return 1;
}

static int test_frame_sign_verify(void)
{
	uint8_t seed[32] = { 0 };
	uint8_t privkey[32], pubkey[32];

	schnorr48_derive_keypair(seed, privkey, pubkey);

	uint8_t dst_addr[] = { 0x00, 0x01 };
	uint8_t inner_payload[] = "CoAP";
	uint8_t sig[48];

	/* schnorr48_sign_frame returns 0 on success */
	ASSERT_TRUE(sign_frame_api(58, 0x21, 1, 42, dst_addr, 2, inner_payload, 4,
					 privkey, pubkey, sig) == 0,
		    "sign_frame returns 0 on success");

	/* schnorr48_verify_frame returns 1 on valid signature */
	ASSERT_TRUE(verify_frame_api(58, 0x21, 1, 42, dst_addr, 2, inner_payload, 4, sig, pubkey) == 1,
		    "frame verify");

	/* Wrong epoch - returns 0 (invalid signature) */
	ASSERT_TRUE(schnorr48_verify_frame(58, 0x21, 2, 42, dst_addr, 2, inner_payload, 4, sig, pubkey) == 0,
		    "wrong epoch should fail");

	/* Wrong seqnum - returns 0 (invalid signature) */
	ASSERT_TRUE(schnorr48_verify_frame(58, 0x21, 1, 43, dst_addr, 2, inner_payload, 4, sig, pubkey) == 0,
		    "wrong seqnum should fail");

	return 1;
}

static int test_frame_bounds_checking(void)
{
	uint8_t seed[32] = { 0 };
	uint8_t privkey[32], pubkey[32];

	schnorr48_derive_keypair(seed, privkey, pubkey);

	uint8_t dst_addr[9] = { 0 };  /* Too long - max is 8 */
	uint8_t inner_payload[] = "CoAP";
	uint8_t sig[48] = { 0 };

	/* sign_frame should return -EINVAL for dst_addr_len > 8 */
	ASSERT_TRUE(schnorr48_sign_frame(58, 0x21, 1, 42, dst_addr, 9, inner_payload, 4,
					 privkey, pubkey, sig) == -EINVAL,
		    "sign_frame rejects dst_addr_len > 8");

	/* verify_frame should return -EINVAL for dst_addr_len > 8 */
	ASSERT_TRUE(schnorr48_verify_frame(58, 0x21, 1, 42, dst_addr, 9, inner_payload, 4, sig, pubkey) == -EINVAL,
		    "verify_frame rejects dst_addr_len > 8");

	return 1;
}

static int test_signed_frame_cross_language_oracle(void)
{
	static const char seed_hex[] =
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	static const char private_hex[] =
		"3894eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6f";
	static const char public_hex[] =
		"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
	static const char signature_hex[] =
		"bc6fe764bf7f37be5152ad40a8d2dcc2b06cf4da946e1690d3398874a5686dc"
		"ca3ace783caf4d3950699082eea0f5b09";
	static const char wire_hex[] =
		"3d25123456beef147369676e6564"
		"bc6fe764bf7f37be5152ad40a8d2dcc2b06cf4da946e1690d3398874a5686dc"
		"ca3ace783caf4d3950699082eea0f5b09";
	uint8_t seed[32], expected_private[32], expected_public[32];
	uint8_t private_key[32], public_key[32], expected_signature[48], signature[48];
	uint8_t expected_wire[62], wire[62];
	uint8_t dst_addr[] = { 0xbe, 0xef };
	uint8_t payload[] = { 0x14, 's', 'i', 'g', 'n', 'e', 'd' };
	struct lichen_frame frame;

	ASSERT_TRUE(hex_decode(seed_hex, seed, sizeof(seed)) == sizeof(seed), "decode oracle seed");
	ASSERT_TRUE(hex_decode(private_hex, expected_private, sizeof(expected_private)) == sizeof(expected_private),
		    "decode oracle private key");
	ASSERT_TRUE(hex_decode(public_hex, expected_public, sizeof(expected_public)) == sizeof(expected_public),
		    "decode oracle public key");
	ASSERT_TRUE(hex_decode(signature_hex, expected_signature, sizeof(expected_signature)) == sizeof(expected_signature),
		    "decode oracle signature");
	ASSERT_TRUE(hex_decode(wire_hex, expected_wire, sizeof(expected_wire)) == sizeof(expected_wire),
		    "decode oracle wire frame");

	schnorr48_derive_keypair(seed, private_key, public_key);
	ASSERT_MEM_EQ(private_key, expected_private, sizeof(private_key), "oracle private key");
	ASSERT_MEM_EQ(public_key, expected_public, sizeof(public_key), "oracle public key");
	ASSERT_TRUE(schnorr48_sign_frame(0x3d, 0x21, 0x12, 0x3456,
					dst_addr, sizeof(dst_addr), payload, sizeof(payload),
					private_key, public_key, signature) == 0,
		    "sign oracle frame");
	ASSERT_MEM_EQ(signature, expected_signature, sizeof(signature), "oracle signature");

	memset(&frame, 0, sizeof(frame));
	frame.epoch = 0x12;
	frame.seqnum = 0x3456;
	memcpy(frame.dst_addr, dst_addr, sizeof(dst_addr));
	frame.dst_addr_len = sizeof(dst_addr);
	frame.payload = payload;
	frame.payload_len = sizeof(payload);
	memcpy(frame.mic, signature, sizeof(signature));
	frame.mic_len = sizeof(signature);
	frame.addr_mode = LICHEN_ADDR_SHORT;
	frame.mic_length = LICHEN_MIC_32;
	frame.signature_present = true;
	ASSERT_TRUE(lichen_frame_write(&frame, wire, sizeof(wire)) == sizeof(wire),
		    "serialize oracle frame");
	ASSERT_MEM_EQ(wire, expected_wire, sizeof(wire), "oracle wire frame");
	ASSERT_TRUE(schnorr48_verify_frame(0x3d, 0x21, 0x12, 0x3456,
					  dst_addr, sizeof(dst_addr), payload, sizeof(payload),
					  signature, public_key) == 1,
		    "verify oracle frame");

	dst_addr[0] ^= 1;
	ASSERT_FALSE(schnorr48_verify_frame(0x3d, 0x21, 0x12, 0x3456,
					   dst_addr, sizeof(dst_addr), payload, sizeof(payload),
					   signature, public_key), "reject tampered destination");
	dst_addr[0] ^= 1;
	payload[0] ^= 1;
	ASSERT_FALSE(schnorr48_verify_frame(0x3d, 0x21, 0x12, 0x3456,
					   dst_addr, sizeof(dst_addr), payload, sizeof(payload),
					   signature, public_key), "reject tampered payload");
	payload[0] ^= 1;
	ASSERT_FALSE(schnorr48_verify_frame(0x3c, 0x21, 0x12, 0x3456,
					   dst_addr, sizeof(dst_addr), payload, sizeof(payload),
					   signature, public_key), "reject tampered length");
	ASSERT_FALSE(schnorr48_verify_frame(0x3d, 0x20, 0x12, 0x3456,
					   dst_addr, sizeof(dst_addr), payload, sizeof(payload),
					   signature, public_key), "reject tampered LLSec");
	ASSERT_FALSE(schnorr48_verify_frame(0x3d, 0x21, 0x13, 0x3456,
					   dst_addr, sizeof(dst_addr), payload, sizeof(payload),
					   signature, public_key), "reject tampered epoch");
	ASSERT_FALSE(schnorr48_verify_frame(0x3d, 0x21, 0x12, 0x3457,
					   dst_addr, sizeof(dst_addr), payload, sizeof(payload),
					   signature, public_key), "reject tampered sequence");
	signature[0] ^= 1;
	ASSERT_FALSE(schnorr48_verify_frame(0x3d, 0x21, 0x12, 0x3456,
					   dst_addr, sizeof(dst_addr), payload, sizeof(payload),
					   signature, public_key), "reject tampered signature");

	return 1;
}

/* Test runner */

#define RUN_TEST(fn) do { \
	printf("  %s...", #fn); \
	tests_run++; \
	if (fn()) { \
		printf(" OK\n"); \
		tests_passed++; \
	} \
} while (0)

int main(void)
{
	printf("Schnorr-48 Unit Tests\n");
	printf("=====================\n\n");

	RUN_TEST(test_keypair_derivation);
	RUN_TEST(test_sign_matches_vectors);
	RUN_TEST(test_verify_valid_signatures);
	RUN_TEST(test_verify_invalid_signatures);
	RUN_TEST(test_sign_verify_roundtrip);
	RUN_TEST(test_frame_sign_verify);
	RUN_TEST(test_frame_bounds_checking);
	RUN_TEST(test_signed_frame_cross_language_oracle);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
