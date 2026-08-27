/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>
#include <string.h>
#include <limits.h>

#include <lichen/oscore.h>

/*
 * Hex decode helper for RFC 8613 test vector constants.
 */
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
		return 0;
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
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return bytes;
}

/*
 * RFC 8613 Appendix C test vector constants.
 * All vectors use master_secret = 0102030405060708090a0b0c0d0e0f10.
 */

/* Common master secret across all C.1-C.8 vectors */
static const uint8_t rfc8613_master_secret[OSCORE_KEY_LEN] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};

/* Master salt: 9e7ca92223786340 */
static const uint8_t rfc8613_master_salt[] = {
	0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40,
};

/*
 * C.1.1: Client key derivation with master salt (sender_id empty)
 * Expected:
 *   sender_key = f0910ed7295e6ad4b54fc793154302ff
 *   recipient_key = ffb14e093c94c9cac9471648b4f98710
 *   common_iv = 4622d4dd6d944168eefb54987c
 */
static const uint8_t rfc8613_c1_sender_key[OSCORE_KEY_LEN] = {
	0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
	0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff,
};
static const uint8_t rfc8613_c1_recipient_key[OSCORE_KEY_LEN] = {
	0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
	0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10,
};
static const uint8_t rfc8613_c1_common_iv[OSCORE_NONCE_LEN] = {
	0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
	0xee, 0xfb, 0x54, 0x98, 0x7c,
};

/*
 * C.2.1: Client key derivation without master salt (sender_id = 0x00)
 * Expected:
 *   sender_key = 321b26943253c7ffb6003b0b64d74041
 *   recipient_key = e57b5635815177cd679ab4bcec9d7dda
 *   common_iv = be35ae297d2dace910c52e99f9
 */
static const uint8_t rfc8613_c2_sender_key[OSCORE_KEY_LEN] = {
	0x32, 0x1b, 0x26, 0x94, 0x32, 0x53, 0xc7, 0xff,
	0xb6, 0x00, 0x3b, 0x0b, 0x64, 0xd7, 0x40, 0x41,
};
static const uint8_t rfc8613_c2_recipient_key[OSCORE_KEY_LEN] = {
	0xe5, 0x7b, 0x56, 0x35, 0x81, 0x51, 0x77, 0xcd,
	0x67, 0x9a, 0xb4, 0xbc, 0xec, 0x9d, 0x7d, 0xda,
};
static const uint8_t rfc8613_c2_common_iv[OSCORE_NONCE_LEN] = {
	0xbe, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
	0x10, 0xc5, 0x2e, 0x99, 0xf9,
};

/*
 * C.3.1: Client key derivation with ID Context
 *   master_salt = 9e7ca92223786340, sender_id = ""
 *   recipient_id = 01, id_context = 37cbf3210017a2d3
 * Note: Requires id_context support which the current C API does not expose.
 * Keys listed for reference / future testing:
 *   sender_key = af2a1300a5e95788b356336eeecd2b92
 *   recipient_key = e39a0c7c77b43f03b4b39ab9a268699f
 *   common_iv = 2ca58fb85ff1b81c0b7181b85e
 */

/*
 * C.4: Request protection (GET /tv1), sender_id = ""
 *   sender_seq = 20 (PIV = 0x14)
 *   code = 1 (GET), options = b3747631 (Uri-Path:tv1), payload = ""
 * Expected:
 *   nonce = 4622d4dd6d944168eefb549868
 *   oscore_option = 0914
 *   ciphertext = 612f1092f1776f1c1668b3825e
 */
static const uint8_t rfc8613_c4_options[] = { 0xb3, 0x74, 0x76, 0x31 };
static const uint8_t rfc8613_c4_expected_nonce[OSCORE_NONCE_LEN] = {
	0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
	0xee, 0xfb, 0x54, 0x98, 0x68,
};
static const uint8_t rfc8613_c4_expected_oscore_opt[] = { 0x09, 0x14 };
static const uint8_t rfc8613_c4_expected_ciphertext[] = {
	0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c,
	0x16, 0x68, 0xb3, 0x82, 0x5e,
};

/*
 * C.5: Request protection without salt (GET /tv1), sender_id = "00"
 *   sender_seq = 20 (PIV = 0x14)
 * Expected:
 *   nonce = bf35ae297d2dace910c52e99ed
 *   oscore_option = 091400
 *   ciphertext = 4ed339a5a379b0b8bc731fffb0
 */
static const uint8_t rfc8613_c5_sender_id[] = { 0x00 };
static const uint8_t rfc8613_c5_options[] = { 0xb3, 0x74, 0x76, 0x31 };
static const uint8_t rfc8613_c5_expected_nonce[OSCORE_NONCE_LEN] = {
	0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
	0x10, 0xc5, 0x2e, 0x99, 0xed,
};
static const uint8_t rfc8613_c5_expected_oscore_opt[] = { 0x09, 0x14, 0x00 };
static const uint8_t rfc8613_c5_expected_ciphertext[] = {
	0x4e, 0xd3, 0x39, 0xa5, 0xa3, 0x79, 0xb0, 0xb8,
	0xbc, 0x73, 0x1f, 0xff, 0xb0,
};

/*
 * C.6: Request protection with ID Context
 *   sender_seq = 20, id_context = 37cbf3210017a2d3
 * Requires id_context API support (not yet exposed).
 * Expected for reference:
 *   oscore_option = 19140837cbf3210017a2d3
 *   ciphertext = 72cd7273fd331ac45cffbe55c3
 */

/*
 * C.7: Response protection (2.05 Content, 'Hello World!')
 *   sender_id = "01", recipient_id = ""
 *   sender_seq = 0 (not used for response nonce)
 *   request_piv = 0x14, request_kid = ""
 *   code = 69 (2.05), options = "", payload = "48656c6c6f20576f726c6421"
 *   include_piv = false
 * Expected:
 *   nonce = 4622d4dd6d944168eefb549868
 *   oscore_option = "" (empty)
 *   ciphertext = dbaad1e9a7e7b2a813d3c31524378303cdafae119106
 */
static const uint8_t rfc8613_c7_request_piv[] = { 0x14 };
static const uint8_t rfc8613_c7_payload[] = {
	0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
	0x72, 0x6c, 0x64, 0x21,
};
static const uint8_t rfc8613_c7_expected_nonce[OSCORE_NONCE_LEN] = {
	0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
	0xee, 0xfb, 0x54, 0x98, 0x68,
};
static const uint8_t rfc8613_c7_expected_ciphertext[] = {
	0xdb, 0xaa, 0xd1, 0xe9, 0xa7, 0xe7, 0xb2, 0xa8,
	0x13, 0xd3, 0xc3, 0x15, 0x24, 0x37, 0x83, 0x03,
	0xcd, 0xaf, 0xae, 0x11, 0x91, 0x06,
};

/*
 * C.8: Response protection with Partial IV
 *   Same as C.7 but include_piv = true
 *   Expected:
 *     nonce = 4722d4dd6d944169eefb54987c
 *     oscore_option = 0100
 *     ciphertext = 4d4c13669384b67354b2b6175ff4b8658c666a6cf88e
 */
static const uint8_t rfc8613_c8_expected_option[] = { 0x01, 0x00 };
static const uint8_t rfc8613_c8_expected_ciphertext[] = {
	0x4d, 0x4c, 0x13, 0x66, 0x93, 0x84, 0xb6, 0x73,
	0x54, 0xb2, 0xb6, 0x17, 0x5f, 0xf4, 0xb8, 0x65,
	0x8c, 0x66, 0x6a, 0x6c, 0xf8, 0x8e,
};

static const uint8_t master_secret[OSCORE_KEY_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t sender_id[] = { 0x01 };
static const uint8_t recipient_id[] = { 0x02 };

static const uint8_t peer_eui64_1[OSCORE_EUI64_LEN] = {
	0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11
};
static const uint8_t peer_eui64_2[OSCORE_EUI64_LEN] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

static uint8_t mock_nvm_eui64[OSCORE_EUI64_LEN];
static uint64_t mock_nvm_ssn;
static bool mock_nvm_has_data;
static int mock_nvm_write_count;
static int mock_nvm_read_count;
static bool mock_nvm_write_fails;

static int mock_nvm_write(const uint8_t *eui64, uint64_t ssn)
{
	mock_nvm_write_count++;
	if (mock_nvm_write_fails) {
		return -1;
	}
	if (eui64 != NULL) {
		memcpy(mock_nvm_eui64, eui64, OSCORE_EUI64_LEN);
	}
	mock_nvm_ssn = ssn;
	mock_nvm_has_data = true;
	return 0;
}

static int mock_nvm_read(const uint8_t *eui64, uint64_t *ssn)
{
	mock_nvm_read_count++;
	if (ssn == NULL) {
		return -1;
	}
	if (!mock_nvm_has_data) {
		return -1;
	}
	if (eui64 != NULL && memcmp(mock_nvm_eui64, eui64, OSCORE_EUI64_LEN) != 0) {
		return -1;
	}
	*ssn = mock_nvm_ssn;
	return 0;
}

static void mock_nvm_reset(void)
{
	memset(mock_nvm_eui64, 0, sizeof(mock_nvm_eui64));
	mock_nvm_ssn = 0;
	mock_nvm_has_data = false;
	mock_nvm_write_count = 0;
	mock_nvm_read_count = 0;
	mock_nvm_write_fails = false;
}

static void mock_nvm_set_write_fail(bool fail)
{
	mock_nvm_write_fails = fail;
	mock_nvm_write_count = 0;
}

static void *oscore_ctx_setup(void)
{
	oscore_init();
	mock_nvm_reset();
	oscore_nvm_register_callbacks(NULL, NULL);
	return NULL;
}

static void oscore_ctx_before(void *fixture)
{
	ARG_UNUSED(fixture);
	mock_nvm_reset();
}

/*
 * RFC 8613 test vector test cases
 * ================================
 *
 * These tests verify the C OSCORE implementation against known-answer test
 * vectors from RFC 8613 Appendices C.1-C.8 and test/vectors/oscore.json.
 * They provide cross-implementation interop coverage against Python/aiocoap.
 */

static void *rfc8613_vectors_setup(void)
{
	oscore_init();
	mock_nvm_reset();
	oscore_nvm_register_callbacks(NULL, NULL);
	return NULL;
}

/*
 * C.1.1: Key derivation with master salt, sender_id empty
 */
ZTEST(rfc8613_vectors, test_c1_key_derivation_client_with_salt)
{
	struct oscore_ctx *ctx = NULL;

	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					NULL, 0,
					(uint8_t[]){0x01}, 1,
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	uint64_t seq;
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &seq), OSCORE_OK);
	zassert_equal(seq, 0U);

	oscore_ctx_free(ctx);
}

/*
 * C.1.2: Server key derivation (sender_id = 0x01, recipient_id empty)
 */
ZTEST(rfc8613_vectors, test_c1_key_derivation_server_with_salt)
{
	struct oscore_ctx *ctx = NULL;

	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					(uint8_t[]){0x01}, 1,
					NULL, 0,
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	uint64_t seq;
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &seq), OSCORE_OK);
	zassert_equal(seq, 0U);

	oscore_ctx_free(ctx);
}

/*
 * C.2.1: Key derivation without master salt, sender_id = 0x00
 */
ZTEST(rfc8613_vectors, test_c2_key_derivation_client_no_salt)
{
	struct oscore_ctx *ctx = NULL;

	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					NULL, 0,
					(uint8_t[]){0x00}, 1,
					(uint8_t[]){0x01}, 1,
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	uint64_t seq;
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &seq), OSCORE_OK);
	zassert_equal(seq, 0U);

	oscore_ctx_free(ctx);
}

/*
 * C.2.2: Server key derivation without master salt
 */
ZTEST(rfc8613_vectors, test_c2_key_derivation_server_no_salt)
{
	struct oscore_ctx *ctx = NULL;

	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					NULL, 0,
					(uint8_t[]){0x01}, 1,
					(uint8_t[]){0x00}, 1,
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	uint64_t seq;
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &seq), OSCORE_OK);
	zassert_equal(seq, 0U);

	oscore_ctx_free(ctx);
}

/*
 * C.4: Request protection (GET /tv1), empty sender_id, sender_seq = 20
 */
ZTEST(rfc8613_vectors, test_c4_request_protection)
{
	struct oscore_ctx *ctx = NULL;
	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);

	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					NULL, 0,
					(uint8_t[]){0x01}, 1,
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	zassert_equal(oscore_ctx_set_sender_seq(ctx, 20), OSCORE_OK);

	zassert_equal(oscore_protect_request(ctx, 0x01,
					     rfc8613_c4_options, sizeof(rfc8613_c4_options),
					     NULL, 0,
					     ciphertext, &ct_len,
					     oscore_opt, &opt_len),
		      OSCORE_OK);

	zassert_mem_equal(ciphertext, rfc8613_c4_expected_ciphertext,
			  sizeof(rfc8613_c4_expected_ciphertext),
			  "C.4 ciphertext mismatch");
	zassert_equal(ct_len, sizeof(rfc8613_c4_expected_ciphertext));
	zassert_mem_equal(oscore_opt, rfc8613_c4_expected_oscore_opt,
			  sizeof(rfc8613_c4_expected_oscore_opt),
			  "C.4 oscore_option mismatch");
	zassert_equal(opt_len, sizeof(rfc8613_c4_expected_oscore_opt));

	oscore_ctx_free(ctx);
}

/*
 * C.5: Request protection without salt (sender_id = 0x00), sender_seq = 20
 */
ZTEST(rfc8613_vectors, test_c5_request_protection_no_salt)
{
	struct oscore_ctx *ctx = NULL;
	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);

	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					NULL, 0,
					rfc8613_c5_sender_id, sizeof(rfc8613_c5_sender_id),
					(uint8_t[]){0x01}, 1,
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	zassert_equal(oscore_ctx_set_sender_seq(ctx, 20), OSCORE_OK);

	zassert_equal(oscore_protect_request(ctx, 0x01,
					     rfc8613_c5_options, sizeof(rfc8613_c5_options),
					     NULL, 0,
					     ciphertext, &ct_len,
					     oscore_opt, &opt_len),
		      OSCORE_OK);

	zassert_mem_equal(ciphertext, rfc8613_c5_expected_ciphertext,
			  sizeof(rfc8613_c5_expected_ciphertext),
			  "C.5 ciphertext mismatch");
	zassert_equal(ct_len, sizeof(rfc8613_c5_expected_ciphertext));
	zassert_mem_equal(oscore_opt, rfc8613_c5_expected_oscore_opt,
			  sizeof(rfc8613_c5_expected_oscore_opt),
			  "C.5 oscore_option mismatch");
	zassert_equal(opt_len, sizeof(rfc8613_c5_expected_oscore_opt));

	oscore_ctx_free(ctx);
}

/*
 * C.7: Response protection roundtrip (2.05 Content, 'Hello World!')
 *
 * Protect a response using server context (sender_id=0x01, recipient_id="")
 * with request_piv=0x14, then unprotect using client context
 * (sender_id="", recipient_id=0x01).
 *
 * The no-PIV response reuses the original request nonce and is checked both
 * byte-for-byte against Appendix C.7 and through the client round trip.
 */
ZTEST(rfc8613_vectors, test_c7_response_roundtrip)
{
	/* Server context (protects the response) */
	struct oscore_ctx *server_ctx = NULL;
	/* Client context (unprotects the response) */
	struct oscore_ctx *client_ctx = NULL;

	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);

	uint8_t decrypted_code;
	uint8_t decrypted_opts[64];
	size_t decrypted_opts_len = sizeof(decrypted_opts);
	uint8_t decrypted_payload[64];
	size_t decrypted_payload_len = sizeof(decrypted_payload);

	/* Server context: sender_id=0x01, recipient_id="" */
	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					(uint8_t[]){0x01}, 1,
					NULL, 0,
					&server_ctx),
		      OSCORE_OK);
	zassert_not_null(server_ctx);
	zassert_equal(oscore_ctx_set_sender_seq(server_ctx, 0), OSCORE_OK);

	/* Client context: sender_id="", recipient_id=0x01 */
	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					NULL, 0,
					(uint8_t[]){0x01}, 1,
					&client_ctx),
		      OSCORE_OK);
	zassert_not_null(client_ctx);

	/* Protect response: 2.05 (0x45) Content, "Hello World!" */
	zassert_equal(oscore_protect_response(server_ctx,
					      rfc8613_c7_request_piv, sizeof(rfc8613_c7_request_piv),
					      0x45,
					      NULL, 0,
					      rfc8613_c7_payload, sizeof(rfc8613_c7_payload),
					      ciphertext, &ct_len,
					      oscore_opt, &opt_len),
		      OSCORE_OK);

	zassert_true(ct_len > 0, "response ciphertext should not be empty");
	zassert_mem_equal(ciphertext, rfc8613_c7_expected_ciphertext,
			  sizeof(rfc8613_c7_expected_ciphertext),
			  "C.7 response ciphertext mismatch");
	zassert_equal(ct_len, sizeof(rfc8613_c7_expected_ciphertext));
	zassert_equal(opt_len, 0U,
		      "C.7 expected empty oscore_option (no PIV in response)");

	/* A no-PIV response may be created only once for a request correlation. */
	zassert_equal(oscore_protect_response(server_ctx,
					      rfc8613_c7_request_piv,
					      sizeof(rfc8613_c7_request_piv),
					      0x45, NULL, 0,
					      rfc8613_c7_payload,
					      sizeof(rfc8613_c7_payload),
					      ciphertext, &ct_len,
					      oscore_opt, &opt_len),
		      OSCORE_ERR_REPLAY);
	zassert_equal(ct_len, sizeof(rfc8613_c7_expected_ciphertext));
	zassert_equal(opt_len, 0U);

	/* Unprotect response (client side) */
	zassert_equal(oscore_unprotect_response(client_ctx,
						rfc8613_c7_request_piv, sizeof(rfc8613_c7_request_piv),
						oscore_opt, opt_len,
						ciphertext, ct_len,
						&decrypted_code,
						decrypted_opts, &decrypted_opts_len,
						decrypted_payload, &decrypted_payload_len),
		      OSCORE_OK);

	zassert_equal(decrypted_code, 0x45, "C.7 response code mismatch");
	zassert_equal(decrypted_opts_len, 0U,
		      "C.7 expected no options");
	zassert_mem_equal(decrypted_payload, rfc8613_c7_payload,
			  sizeof(rfc8613_c7_payload),
			  "C.7 response payload mismatch");
	zassert_equal(decrypted_payload_len, sizeof(rfc8613_c7_payload),
		      "C.7 response payload length mismatch");

	oscore_ctx_free(server_ctx);
	oscore_ctx_free(client_ctx);
}

ZTEST(rfc8613_vectors, test_c8_response_with_fresh_partial_iv)
{
	struct oscore_ctx *server_ctx = NULL;
	struct oscore_ctx *client_ctx = NULL;
	uint8_t ciphertext[64];
	size_t ciphertext_len = sizeof(ciphertext);
	uint8_t oscore_opt[8];
	size_t oscore_opt_len = sizeof(oscore_opt);
	uint8_t code;
	uint8_t options[8];
	size_t options_len = sizeof(options);
	uint8_t payload[32];
	size_t payload_len = sizeof(payload);
	uint64_t sender_seq;

	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					(uint8_t[]){0x01}, 1, NULL, 0,
					&server_ctx), OSCORE_OK);
	zassert_equal(oscore_ctx_set_sender_seq(server_ctx, 0), OSCORE_OK);
	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					NULL, 0, (uint8_t[]){0x01}, 1,
					&client_ctx), OSCORE_OK);

	zassert_equal(oscore_protect_response_with_piv(
			server_ctx,
			rfc8613_c7_request_piv, sizeof(rfc8613_c7_request_piv),
			0x45, NULL, 0,
			rfc8613_c7_payload, sizeof(rfc8613_c7_payload),
			ciphertext, &ciphertext_len, oscore_opt, &oscore_opt_len),
		      OSCORE_OK);
	zassert_mem_equal(ciphertext, rfc8613_c8_expected_ciphertext,
			  sizeof(rfc8613_c8_expected_ciphertext));
	zassert_equal(ciphertext_len, sizeof(rfc8613_c8_expected_ciphertext));
	zassert_mem_equal(oscore_opt, rfc8613_c8_expected_option,
			  sizeof(rfc8613_c8_expected_option));
	zassert_equal(oscore_opt_len, sizeof(rfc8613_c8_expected_option));
	zassert_equal(oscore_ctx_get_sender_seq(server_ctx, &sender_seq), OSCORE_OK);
	zassert_equal(sender_seq, 1U);

	zassert_equal(oscore_unprotect_response(
			client_ctx,
			rfc8613_c7_request_piv, sizeof(rfc8613_c7_request_piv),
			oscore_opt, oscore_opt_len, ciphertext, ciphertext_len,
			&code, options, &options_len, payload, &payload_len), OSCORE_OK);
	zassert_equal(code, 0x45);
	zassert_equal(options_len, 0U);
	zassert_mem_equal(payload, rfc8613_c7_payload, sizeof(rfc8613_c7_payload));
	zassert_equal(payload_len, sizeof(rfc8613_c7_payload));

	oscore_ctx_free(server_ctx);
	oscore_ctx_free(client_ctx);
}

ZTEST(rfc8613_vectors, test_fresh_response_failures_rollback_without_output)
{
	struct oscore_ctx *server_ctx = NULL;
	uint8_t ciphertext[64];
	uint8_t oscore_opt[8];
	size_t ciphertext_len;
	size_t oscore_opt_len;
	uint64_t sender_seq;

	zassert_equal(oscore_ctx_create_with_eui64(
				rfc8613_master_secret,
				rfc8613_master_salt, sizeof(rfc8613_master_salt),
				(uint8_t[]){0x01}, 1, NULL, 0,
				peer_eui64_1, &server_ctx), OSCORE_OK);
	zassert_equal(oscore_ctx_set_sender_seq(server_ctx, 0), OSCORE_OK);

	/* Capacity failures are detected before consuming a sender sequence. */
	ciphertext_len = 1;
	oscore_opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_response_with_piv(
			server_ctx,
			rfc8613_c7_request_piv, sizeof(rfc8613_c7_request_piv),
			0x45, NULL, 0,
			rfc8613_c7_payload, sizeof(rfc8613_c7_payload),
			ciphertext, &ciphertext_len, oscore_opt, &oscore_opt_len),
		      OSCORE_ERR_BUFFER_TOO_SMALL);
	zassert_equal(ciphertext_len, 1U);
	zassert_equal(oscore_opt_len, sizeof(oscore_opt));
	zassert_equal(oscore_ctx_get_sender_seq(server_ctx, &sender_seq), OSCORE_OK);
	zassert_equal(sender_seq, 0U);

	/* Persistence failure rolls back the reservation and publishes nothing. */
	mock_nvm_reset();
	mock_nvm_set_write_fail(true);
	oscore_nvm_register_callbacks(mock_nvm_write, NULL);
	memset(ciphertext, 0xa5, sizeof(ciphertext));
	memset(oscore_opt, 0xa5, sizeof(oscore_opt));
	ciphertext_len = sizeof(ciphertext);
	oscore_opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_response_with_piv(
			server_ctx,
			rfc8613_c7_request_piv, sizeof(rfc8613_c7_request_piv),
			0x45, NULL, 0,
			rfc8613_c7_payload, sizeof(rfc8613_c7_payload),
			ciphertext, &ciphertext_len, oscore_opt, &oscore_opt_len),
		      OSCORE_ERR_NVM_FAILED);
	zassert_equal(mock_nvm_write_count, 3);
	zassert_equal(ciphertext_len, sizeof(ciphertext));
	zassert_equal(oscore_opt_len, sizeof(oscore_opt));
	zassert_equal(ciphertext[0], 0xa5);
	zassert_equal(oscore_opt[0], 0xa5);
	zassert_equal(oscore_ctx_get_sender_seq(server_ctx, &sender_seq), OSCORE_OK);
	zassert_equal(sender_seq, 0U);

	oscore_nvm_register_callbacks(NULL, NULL);
	mock_nvm_set_write_fail(false);
	oscore_ctx_free(server_ctx);
}

/*
 * Canonical cross-implementation response vectors from
 * test/vectors/oscore_cross_exchange.json. The ciphertexts are independently
 * produced by the Python and Rust implementations.
 */
ZTEST(rfc8613_vectors, test_cross_response_vectors_and_fresh_piv_replay)
{
	static const uint8_t requester_id[] = { 0x00 };
	static const uint8_t responder_id[] = { 0x01 };
	static const uint8_t request_piv[] = { 0x00 };
	static const uint8_t fresh_opt[] = { 0x01, 0x00 };
	static const uint8_t expected_payload[] = "LICHEN cross response";
	static const uint8_t no_piv_ciphertext[] = {
		0x93, 0x9e, 0xa8, 0x9e, 0x47, 0xf1, 0x07, 0x00,
		0x90, 0x5b, 0x7f, 0x5c, 0xa2, 0xf6, 0xc4, 0x87,
		0x45, 0xd0, 0x9e, 0x45, 0x4e, 0xb5, 0x97, 0x2b,
		0x66, 0xd0, 0xb6, 0x21, 0x98, 0x0e, 0x4e,
	};
	static const uint8_t fresh_ciphertext[] = {
		0x4d, 0x4c, 0x17, 0x4a, 0xbc, 0xa0, 0x9c, 0x1d,
		0x23, 0xbe, 0xb6, 0x14, 0x48, 0xa6, 0x07, 0xf8,
		0x22, 0x00, 0xf6, 0xb3, 0xe0, 0xc4, 0x2e, 0xec,
		0xd0, 0x07, 0x04, 0x1f, 0xa9, 0x6a, 0xf8,
	};
	struct oscore_ctx *client_ctx = NULL;
	uint8_t code;
	uint8_t options[8];
	uint8_t payload[64];
	size_t options_len;
	size_t payload_len;
	uint8_t tampered[sizeof(fresh_ciphertext)];

	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					requester_id, sizeof(requester_id),
					responder_id, sizeof(responder_id),
					&client_ctx), OSCORE_OK);

	/* A response without a fresh PIV is bound to the original request PIV. */
	code = 0xa5;
	memset(options, 0xa5, sizeof(options));
	memset(payload, 0xa5, sizeof(payload));
	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_response(client_ctx,
						request_piv, sizeof(request_piv), NULL, 0,
						no_piv_ciphertext, sizeof(no_piv_ciphertext),
						&code, options, &options_len,
						payload, &payload_len), OSCORE_OK);
	zassert_equal(code, 0x45);
	zassert_equal(options_len, 0U);
	zassert_equal(payload_len, sizeof(expected_payload) - 1);
	zassert_mem_equal(payload, expected_payload, sizeof(expected_payload) - 1);

	/* A wrong request PIV must fail authentication without publishing output. */
	code = 0xa5;
	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_response(client_ctx,
						(uint8_t[]){0x01}, 1, NULL, 0,
						no_piv_ciphertext, sizeof(no_piv_ciphertext),
						&code, options, &options_len,
						payload, &payload_len), OSCORE_ERR_DECRYPT_FAILED);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, sizeof(payload));

	/* The successful no-PIV response consumes its request correlation once. */
	zassert_equal(oscore_unprotect_response(client_ctx,
						request_piv, sizeof(request_piv), NULL, 0,
						no_piv_ciphertext, sizeof(no_piv_ciphertext),
						&code, options, &options_len,
						payload, &payload_len), OSCORE_ERR_REPLAY);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, sizeof(payload));

	/* Failed authentication must release, rather than commit, the fresh PIV. */
	memcpy(tampered, fresh_ciphertext, sizeof(tampered));
	tampered[sizeof(tampered) - 1] ^= 0x01;
	zassert_equal(oscore_unprotect_response(client_ctx,
						request_piv, sizeof(request_piv),
						fresh_opt, sizeof(fresh_opt),
						tampered, sizeof(tampered),
						&code, options, &options_len,
						payload, &payload_len), OSCORE_ERR_DECRYPT_FAILED);
	zassert_equal(code, 0xa5);

	/* A local buffer error likewise cannot consume an authenticated PIV. */
	options_len = sizeof(options);
	payload_len = 4;
	zassert_equal(oscore_unprotect_response(client_ctx,
						request_piv, sizeof(request_piv),
						fresh_opt, sizeof(fresh_opt),
						fresh_ciphertext, sizeof(fresh_ciphertext),
						&code, options, &options_len,
						payload, &payload_len), OSCORE_ERR_BUFFER_TOO_SMALL);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, 4U);

	/* The authentic response now succeeds and commits the fresh PIV. */
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_response(client_ctx,
						request_piv, sizeof(request_piv),
						fresh_opt, sizeof(fresh_opt),
						fresh_ciphertext, sizeof(fresh_ciphertext),
						&code, options, &options_len,
						payload, &payload_len), OSCORE_OK);
	zassert_equal(code, 0x45);
	zassert_equal(options_len, 0U);
	zassert_equal(payload_len, sizeof(expected_payload) - 1);
	zassert_mem_equal(payload, expected_payload, sizeof(expected_payload) - 1);

	/* Replaying the same response PIV is rejected before any output mutation. */
	code = 0xa5;
	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_response(client_ctx,
						request_piv, sizeof(request_piv),
						fresh_opt, sizeof(fresh_opt),
						fresh_ciphertext, sizeof(fresh_ciphertext),
						&code, options, &options_len,
						payload, &payload_len), OSCORE_ERR_REPLAY);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, sizeof(payload));

	oscore_ctx_free(client_ctx);
}

ZTEST(rfc8613_vectors, test_unprotect_response_rejects_malformed_correlation)
{
	static const uint8_t request_piv[] = { 0x00 };
	static const uint8_t wrong_kid[] = { 0x08, 0x02 };
	static const uint8_t wrong_kid_context[] = { 0x10, 0x01, 0x99 };
	static const uint8_t malformed_options[][2] = {
		{ 0x81, 0x00 }, /* reserved flag bit */
		{ 0x02, 0x00 }, /* truncated two-byte PIV */
		{ 0x06, 0x00 }, /* PIV length exceeds the five-byte profile */
	};
	static const size_t malformed_lengths[] = { 2, 2, 2 };
	static const uint8_t ciphertext[OSCORE_TAG_LEN + 1] = {0};
	struct oscore_ctx *client_ctx = NULL;
	uint8_t code = 0xa5;
	uint8_t options[4] = { 0xa5, 0xa5, 0xa5, 0xa5 };
	uint8_t payload[4] = { 0xa5, 0xa5, 0xa5, 0xa5 };
	size_t options_len = sizeof(options);
	size_t payload_len = sizeof(payload);

	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					(uint8_t[]){0x00}, 1,
					(uint8_t[]){0x01}, 1,
					&client_ctx), OSCORE_OK);

	for (size_t i = 0; i < ARRAY_SIZE(malformed_options); i++) {
		zassert_equal(oscore_unprotect_response(client_ctx,
							request_piv, sizeof(request_piv),
							malformed_options[i], malformed_lengths[i],
							ciphertext, sizeof(ciphertext),
							&code, options, &options_len,
							payload, &payload_len),
			      OSCORE_ERR_INVALID_PARAM);
		zassert_equal(code, 0xa5);
		zassert_equal(options_len, sizeof(options));
		zassert_equal(payload_len, sizeof(payload));
		zassert_equal(options[0], 0xa5);
		zassert_equal(payload[0], 0xa5);
	}

	/* Explicit response identifiers must select this exact context. */
	zassert_equal(oscore_unprotect_response(client_ctx,
						request_piv, sizeof(request_piv),
						wrong_kid, sizeof(wrong_kid),
						ciphertext, sizeof(ciphertext),
						&code, options, &options_len,
						payload, &payload_len), OSCORE_ERR_NO_CONTEXT);
	zassert_equal(oscore_unprotect_response(client_ctx,
						request_piv, sizeof(request_piv),
						wrong_kid_context, sizeof(wrong_kid_context),
						ciphertext, sizeof(ciphertext),
						&code, options, &options_len,
						payload, &payload_len), OSCORE_ERR_NO_CONTEXT);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, sizeof(payload));

	/* Original request correlation always carries a one-to-five-byte PIV. */
	zassert_equal(oscore_unprotect_response(client_ctx,
						NULL, 0, NULL, 0,
						ciphertext, sizeof(ciphertext),
						&code, options, &options_len,
						payload, &payload_len),
		      OSCORE_ERR_INVALID_PARAM);

	oscore_ctx_free(client_ctx);
}

/*
 * Roundtrip: protect then unprotect a GET request
 * Uses C.4 context but with sender_seq = 0 and no options/payload
 */
ZTEST(rfc8613_vectors, test_roundtrip_protect_unprotect)
{
	struct oscore_ctx *sender_ctx = NULL;
	struct oscore_ctx *recipient_ctx = NULL;
	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	uint8_t decrypted_code;
	uint8_t decrypted_opts[64];
	size_t decrypted_opts_len = sizeof(decrypted_opts);
	uint8_t decrypted_payload[64];
	size_t decrypted_payload_len = sizeof(decrypted_payload);

	/* Sender: client perspective (sender_id = 0x00, recipient_id = 0x01) */
	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					(uint8_t[]){0x00}, 1,
					(uint8_t[]){0x01}, 1,
					&sender_ctx),
		      OSCORE_OK);
	zassert_not_null(sender_ctx);
	zassert_equal(oscore_ctx_set_sender_seq(sender_ctx, 5), OSCORE_OK);

	/* Recipient: server perspective (sender_id = 0x01, recipient_id = 0x00) */
	zassert_equal(oscore_ctx_create(rfc8613_master_secret,
					rfc8613_master_salt, sizeof(rfc8613_master_salt),
					(uint8_t[]){0x01}, 1,
					(uint8_t[]){0x00}, 1,
					&recipient_ctx),
		      OSCORE_OK);
	zassert_not_null(recipient_ctx);

	/* PROTECT: GET /hello */
	/* Uri-Path "hello": delta 11, literal five-byte value. */
	uint8_t req_options[] = { 0xb5, 0x68, 0x65, 0x6c, 0x6c, 0x6f };
	uint8_t req_payload[] = { 0x00 };

	zassert_equal(oscore_protect_request(sender_ctx, 0x01,
					     req_options, sizeof(req_options),
					     req_payload, sizeof(req_payload),
					     ciphertext, &ct_len,
					     oscore_opt, &opt_len),
		      OSCORE_OK);
	zassert_true(ct_len > 0, "ciphertext should not be empty");

	/* UNPROTECT */
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					       oscore_opt, opt_len,
					       ciphertext, ct_len,
					       &decrypted_code,
					       decrypted_opts, &decrypted_opts_len,
					       decrypted_payload, &decrypted_payload_len),
		      OSCORE_OK);

	zassert_equal(decrypted_code, 0x01, "roundtrip code mismatch");
	zassert_equal(decrypted_opts_len, sizeof(req_options),
		      "roundtrip options length mismatch");
	zassert_mem_equal(decrypted_opts, req_options, sizeof(req_options),
			  "roundtrip options mismatch");
	zassert_equal(decrypted_payload_len, sizeof(req_payload),
		      "roundtrip payload length mismatch");
	zassert_mem_equal(decrypted_payload, req_payload, sizeof(req_payload),
			  "roundtrip payload mismatch");

	oscore_ctx_free(sender_ctx);
	oscore_ctx_free(recipient_ctx);
}

ZTEST_SUITE(rfc8613_vectors, NULL, rfc8613_vectors_setup, NULL, NULL, NULL);

ZTEST(oscore_ctx, test_rejects_identical_nonempty_sender_and_recipient_ids)
{
	const uint8_t id[] = { 0x01 };
	struct oscore_ctx *ctx = NULL;

	zassert_equal(oscore_ctx_create(master_secret, NULL, 0,
					id, sizeof(id),
					id, sizeof(id),
					&ctx),
		      OSCORE_ERR_INVALID_PARAM);
	zassert_is_null(ctx);
}

ZTEST(oscore_ctx, test_rejects_both_empty_sender_and_recipient_ids)
{
	struct oscore_ctx *ctx = NULL;

	/* Both empty IDs would derive identical keys - must reject */
	zassert_equal(oscore_ctx_create(master_secret, NULL, 0,
					NULL, 0,
					NULL, 0,
					&ctx),
		      OSCORE_ERR_INVALID_PARAM);
	zassert_is_null(ctx);
}

ZTEST(oscore_ctx, test_create_with_eui64_associates_peer)
{
	struct oscore_ctx *ctx = NULL;
	struct oscore_ctx *found = NULL;

	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0,
						   sender_id, sizeof(sender_id),
						   recipient_id, sizeof(recipient_id),
						   peer_eui64_1, &ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	/* Should find context by EUI-64 */
	zassert_equal(oscore_ctx_get_by_eui64(peer_eui64_1, &found), OSCORE_OK);
	zassert_equal_ptr(ctx, found);

	/* Should not find different EUI-64 */
	zassert_equal(oscore_ctx_get_by_eui64(peer_eui64_2, &found),
		      OSCORE_ERR_NO_CONTEXT);

	oscore_ctx_free(ctx);
}

ZTEST(oscore_ctx, test_set_peer_eui64_enables_lookup)
{
	struct oscore_ctx *ctx = NULL;
	struct oscore_ctx *found = NULL;

	/* Create without EUI-64 */
	zassert_equal(oscore_ctx_create(master_secret, NULL, 0,
					sender_id, sizeof(sender_id),
					recipient_id, sizeof(recipient_id),
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	/* Should not be findable by EUI-64 initially */
	zassert_equal(oscore_ctx_get_by_eui64(peer_eui64_1, &found),
		      OSCORE_ERR_NO_CONTEXT);

	/* Set EUI-64 */
	zassert_equal(oscore_ctx_set_peer_eui64(ctx, peer_eui64_1), OSCORE_OK);

	/* Now should be findable */
	zassert_equal(oscore_ctx_get_by_eui64(peer_eui64_1, &found), OSCORE_OK);
	zassert_equal_ptr(ctx, found);

	oscore_ctx_free(ctx);
}

ZTEST(oscore_ctx, test_check_freshness_ok_for_new_context)
{
	struct oscore_ctx *ctx = NULL;
	enum oscore_freshness status;

	zassert_equal(oscore_ctx_create(master_secret, NULL, 0,
					sender_id, sizeof(sender_id),
					recipient_id, sizeof(recipient_id),
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	/* Initialize SSN to 0 */
	zassert_equal(oscore_ctx_set_sender_seq(ctx, 0), OSCORE_OK);

	/* Fresh context should be OK */
	zassert_equal(oscore_ctx_check_freshness(ctx, &status), OSCORE_OK);
	zassert_equal(status, OSCORE_FRESHNESS_OK);

	oscore_ctx_free(ctx);
}

ZTEST(oscore_ctx, test_check_freshness_critical_near_exhaustion)
{
	struct oscore_ctx *ctx = NULL;
	enum oscore_freshness status;

	zassert_equal(oscore_ctx_create(master_secret, NULL, 0,
					sender_id, sizeof(sender_id),
					recipient_id, sizeof(recipient_id),
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	/* Set SSN near exhaustion */
	zassert_equal(oscore_ctx_set_sender_seq(ctx, OSCORE_SSN_MAX - 5000), OSCORE_OK);

	/* Should report critical */
	zassert_equal(oscore_ctx_check_freshness(ctx, &status), OSCORE_OK);
	zassert_equal(status, OSCORE_FRESHNESS_CRITICAL);

	oscore_ctx_free(ctx);
}

ZTEST(oscore_ctx, test_check_freshness_exhausted_returns_error)
{
	struct oscore_ctx *ctx = NULL;
	enum oscore_freshness status;

	zassert_equal(oscore_ctx_create(master_secret, NULL, 0,
					sender_id, sizeof(sender_id),
					recipient_id, sizeof(recipient_id),
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	/* The value after the terminal five-byte PIV is the exhausted sentinel. */
	zassert_equal(oscore_ctx_set_sender_seq(ctx, OSCORE_SSN_MAX + 1), OSCORE_OK);

	/* Should return error for exhausted context */
	zassert_equal(oscore_ctx_check_freshness(ctx, &status),
		      OSCORE_ERR_CONTEXT_STALE);
	zassert_equal(status, OSCORE_FRESHNESS_EXHAUSTED);

	oscore_ctx_free(ctx);
}

ZTEST(oscore_ctx, test_nvm_persistence_write)
{
	struct oscore_ctx *ctx = NULL;

	oscore_nvm_register_callbacks(mock_nvm_write, mock_nvm_read);

	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0,
						   sender_id, sizeof(sender_id),
						   recipient_id, sizeof(recipient_id),
						   peer_eui64_1, &ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	zassert_equal(oscore_ctx_set_sender_seq(ctx, 12345), OSCORE_OK);

	zassert_equal(mock_nvm_write_count, 1);
	zassert_equal(mock_nvm_ssn, 12345U);
	zassert_mem_equal(mock_nvm_eui64, peer_eui64_1, OSCORE_EUI64_LEN);

	oscore_ctx_free(ctx);
	oscore_nvm_register_callbacks(NULL, NULL);
}

ZTEST(oscore_ctx, test_nvm_persistence_restore)
{
	struct oscore_ctx *ctx = NULL;
	uint64_t restored_ssn;

	memcpy(mock_nvm_eui64, peer_eui64_1, OSCORE_EUI64_LEN);
	mock_nvm_ssn = 54321;
	mock_nvm_has_data = true;

	oscore_nvm_register_callbacks(mock_nvm_write, mock_nvm_read);

	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0,
						   sender_id, sizeof(sender_id),
						   recipient_id, sizeof(recipient_id),
						   peer_eui64_1, &ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	zassert_equal(mock_nvm_read_count, 1);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &restored_ssn), OSCORE_OK);
	zassert_equal(restored_ssn, 54321U);

	oscore_ctx_free(ctx);
	oscore_nvm_register_callbacks(NULL, NULL);
}

ZTEST(oscore_ctx, test_nvm_set_sender_seq_failure)
{
	struct oscore_ctx *ctx = NULL;
	uint8_t ciphertext[32];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);

	oscore_nvm_register_callbacks(mock_nvm_write, mock_nvm_read);

	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0,
						   sender_id, sizeof(sender_id),
						   recipient_id, sizeof(recipient_id),
						   peer_eui64_1, &ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	mock_nvm_set_write_fail(true);

	zassert_equal(oscore_ctx_set_sender_seq(ctx, 12345), OSCORE_ERR_NVM_FAILED);
	zassert_equal(mock_nvm_write_count, 1);

	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0,
					     ciphertext, &ct_len,
					     oscore_opt, &opt_len),
		      OSCORE_ERR_INVALID_PARAM);

	oscore_ctx_free(ctx);
	mock_nvm_set_write_fail(false);
	oscore_nvm_register_callbacks(NULL, NULL);
}

ZTEST(oscore_ctx, test_get_by_eui64_rejects_null)
{
	struct oscore_ctx *ctx = NULL;

	zassert_equal(oscore_ctx_get_by_eui64(NULL, &ctx), OSCORE_ERR_INVALID_PARAM);
	zassert_equal(oscore_ctx_get_by_eui64(peer_eui64_1, NULL), OSCORE_ERR_INVALID_PARAM);
}

ZTEST(oscore_ctx, test_persist_ssn_noop_without_callback)
{
	struct oscore_ctx *ctx = NULL;

	oscore_nvm_register_callbacks(NULL, NULL);

	zassert_equal(oscore_ctx_create(master_secret, NULL, 0,
					sender_id, sizeof(sender_id),
					recipient_id, sizeof(recipient_id),
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	zassert_equal(oscore_ctx_persist_ssn(ctx), OSCORE_OK);

	oscore_ctx_free(ctx);
}

/*
 * Decode a PIV out of a public oscore_option struct (big-endian).
 */
static uint64_t decode_option_piv(const struct oscore_option *opt)
{
	uint64_t seq = 0;

	for (size_t i = 0; i < opt->piv_len; i++) {
		seq = (seq << 8) | opt->piv[i];
	}
	return seq;
}

/*
 * RFC 8613 Section 7.2 / Appendix D.4: after a simulated reboot (context
 * freed and reloaded from the NVM store), the reloaded sender_seq must be
 * strictly above every sequence transmitted before the crash, the skipped
 * safety-margin range must never appear as a PIV, and the post-reboot
 * transmission must continue from the reloaded value.
 */
ZTEST(oscore_ctx, test_persist_ssn_safety_margin_prevents_reboot_reuse)
{
	struct oscore_ctx *ctx = NULL;
	struct oscore_option opt;
	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	uint64_t transmitted;
	uint64_t ssn;

	oscore_nvm_register_callbacks(mock_nvm_write, mock_nvm_read);

	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0,
						   sender_id, sizeof(sender_id),
						   recipient_id, sizeof(recipient_id),
						   peer_eui64_1, &ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);
	zassert_equal(oscore_ctx_set_sender_seq(ctx, 100), OSCORE_OK);

	ct_len = sizeof(ciphertext);
	opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0,
					     ciphertext, &ct_len,
					     oscore_opt, &opt_len),
		      OSCORE_OK);
	zassert_equal(oscore_option_parse(oscore_opt, opt_len, &opt), OSCORE_OK);
	zassert_true(opt.has_piv, "request carries a PIV");
	transmitted = decode_option_piv(&opt);
	zassert_equal(transmitted, 100U);

	/* Simulated reboot: free the context and reload from the store. */
	oscore_ctx_free(ctx);
	ctx = NULL;
	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0,
						   sender_id, sizeof(sender_id),
						   recipient_id, sizeof(recipient_id),
						   peer_eui64_1, &ctx),
		      OSCORE_OK);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	zassert_true(ssn > transmitted,
		     "reloaded SSN must strictly exceed the pre-crash transmission");
	zassert_equal(ssn, 101U + OSCORE_SSN_SAFETY_MARGIN);

	/* The reloaded SSN is the next PIV; the skipped range is never used. */
	ct_len = sizeof(ciphertext);
	opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0,
					     ciphertext, &ct_len,
					     oscore_opt, &opt_len),
		      OSCORE_OK);
	zassert_equal(oscore_option_parse(oscore_opt, opt_len, &opt), OSCORE_OK);
	zassert_equal(decode_option_piv(&opt), 101U + OSCORE_SSN_SAFETY_MARGIN);

	oscore_ctx_free(ctx);
	oscore_nvm_register_callbacks(NULL, NULL);
}

/*
 * Near the end of the sequence space the durable value caps at the
 * exhaustion sentinel OSCORE_SSN_MAX + 1 (never at OSCORE_SSN_MAX: a
 * reloaded OSCORE_SSN_MAX could transmit the terminal PIV a second time
 * after a crash). A reloaded sentinel must refuse to protect.
 */
ZTEST(oscore_ctx, test_persist_ssn_margin_caps_at_exhaustion_sentinel)
{
	struct oscore_ctx *ctx = NULL;
	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	uint64_t ssn;

	oscore_nvm_register_callbacks(mock_nvm_write, mock_nvm_read);

	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0,
						   sender_id, sizeof(sender_id),
						   recipient_id, sizeof(recipient_id),
						   peer_eui64_1, &ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);
	zassert_equal(oscore_ctx_set_sender_seq(ctx, OSCORE_SSN_MAX - 2),
		      OSCORE_OK);

	ct_len = sizeof(ciphertext);
	opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0,
					     ciphertext, &ct_len,
					     oscore_opt, &opt_len),
		      OSCORE_OK);
	zassert_equal(mock_nvm_ssn, OSCORE_SSN_MAX + 1U);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	zassert_equal(ssn, OSCORE_SSN_MAX + 1U);

	/* Simulated reboot: the reloaded sentinel refuses to protect. */
	oscore_ctx_free(ctx);
	ctx = NULL;
	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0,
						   sender_id, sizeof(sender_id),
						   recipient_id, sizeof(recipient_id),
						   peer_eui64_1, &ctx),
		      OSCORE_OK);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	zassert_equal(ssn, OSCORE_SSN_MAX + 1U);
	ct_len = sizeof(ciphertext);
	opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0,
					     ciphertext, &ct_len,
					     oscore_opt, &opt_len),
		      OSCORE_ERR_SEQ_EXHAUSTED);

	oscore_ctx_free(ctx);
	oscore_nvm_register_callbacks(NULL, NULL);
}

ZTEST(oscore_ctx, test_nvm_protect_request_nvm_failure)
{
	struct oscore_ctx *ctx = NULL;
	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	uint64_t ssn;
	oscore_nvm_register_callbacks(mock_nvm_write, mock_nvm_read);
	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0, sender_id, sizeof(sender_id), recipient_id, sizeof(recipient_id), peer_eui64_1, &ctx), OSCORE_OK);
	zassert_not_null(ctx);
	zassert_equal(oscore_ctx_set_sender_seq(ctx, 100), OSCORE_OK);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	zassert_equal(ssn, 100U);
	mock_nvm_set_write_fail(true);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0, ciphertext, &ct_len, oscore_opt, &opt_len), OSCORE_ERR_NVM_FAILED);
	zassert_equal(mock_nvm_write_count, 3);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	zassert_equal(ssn, 100U);
	mock_nvm_set_write_fail(false);
	ct_len = sizeof(ciphertext); opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0, ciphertext, &ct_len, oscore_opt, &opt_len), OSCORE_OK);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	/* Persisted SSN skips OSCORE_SSN_SAFETY_MARGIN past the next unused
	 * sequence; the in-RAM SSN advances to the same durable value. */
	zassert_equal(ssn, 101U + OSCORE_SSN_SAFETY_MARGIN);
	zassert_equal(mock_nvm_ssn, 101U + OSCORE_SSN_SAFETY_MARGIN);
	oscore_ctx_free(ctx);
	oscore_nvm_register_callbacks(NULL, NULL);
}

ZTEST(oscore_ctx, test_nvm_read_failure_fallback_to_zero)
{
	struct oscore_ctx *ctx = NULL;
	uint64_t ssn;
	enum oscore_freshness status;
	oscore_nvm_register_callbacks(mock_nvm_write, mock_nvm_read);
	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0,
						   sender_id, sizeof(sender_id),
						   recipient_id, sizeof(recipient_id),
						   peer_eui64_1, &ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);
	zassert_equal(mock_nvm_read_count, 1);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	zassert_equal(ssn, 0U);
	zassert_equal(oscore_ctx_check_freshness(ctx, &status), OSCORE_OK);
	zassert_equal(status, OSCORE_FRESHNESS_OK);
	uint8_t ciphertext[32];
	size_t ciphertext_len = sizeof(ciphertext);
	uint8_t oscore_opt[16];
	size_t oscore_opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0,
					     ciphertext, &ciphertext_len,
					     oscore_opt, &oscore_opt_len),
		      OSCORE_ERR_INVALID_PARAM);
	zassert_equal(oscore_ctx_set_sender_seq(ctx, 0), OSCORE_OK);
	ciphertext_len = sizeof(ciphertext);
	oscore_opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0,
					     ciphertext, &ciphertext_len,
					     oscore_opt, &oscore_opt_len),
		      OSCORE_OK);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	/* Persist path skips OSCORE_SSN_SAFETY_MARGIN; in-RAM SSN follows. */
	zassert_equal(ssn, 1U + OSCORE_SSN_SAFETY_MARGIN);
	oscore_ctx_free(ctx);
	oscore_nvm_register_callbacks(NULL, NULL);
}

ZTEST_SUITE(oscore_ctx, NULL, oscore_ctx_setup, oscore_ctx_before, NULL, NULL);

/*
 * RFC 8613 test vectors - byte-exact cross-implementation interop tests.
 * These vectors are from test/vectors/oscore.json and MUST produce byte-exact
 * output matching the Python reference implementation (aiocoap).
 *
 * Static master secrets are duplicated because oscore_ctx_create() wipes
 * the master secret in the context after key derivation (line 692 in oscore.c).
 * Roundtrip tests that create two contexts from the same master need
 * independent static arrays (the original in the test file is not touched).
 */

/* RFC 8613 Appendix C.1 master secret (duplicate for independent contexts) */
static const uint8_t rfc8613_ms[OSCORE_KEY_LEN] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};

static const uint8_t rfc8613_ms2[OSCORE_KEY_LEN] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};

static const uint8_t rfc8613_ms3[OSCORE_KEY_LEN] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};

static const uint8_t rfc8613_salt[8] = {
	0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40,
};

static const uint8_t rfc8613_salt2[8] = {
	0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40,
};

/* C4 client: sender_id empty, recipient_id = {0x01} */
static const uint8_t c4_recipient_id[] = { 0x01 };

/* C4 expected outputs per RFC 8613 Appendix C.4 */
static const uint8_t c4_expected_oscore_opt[] = { 0x09, 0x14 };
static const uint8_t c4_expected_ciphertext[] = {
	0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c,
	0x16, 0x68, 0xb3, 0x82, 0x5e,
};
static const uint8_t c4_options[] = { 0xb3, 0x74, 0x76, 0x31 };

/* Roundtrip test vectors */
static const uint8_t rt_ms[OSCORE_KEY_LEN] = {
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
};

static const uint8_t rt_ms2[OSCORE_KEY_LEN] = {
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
};

static const uint8_t rt_salt[8] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
};

static const uint8_t rt_salt2[8] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
};

static const uint8_t rt_sender_id[] = { 0xaa };
static const uint8_t rt_recipient_id[] = { 0xbb };

static const uint8_t rt_payload[] = {
	0x7b, 0x22, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x22, 0x3a, 0x22, 0x74, 0x65, 0x73, 0x74,
	0x22, 0x7d,
};

static void *oscore_vectors_setup(void)
{
	oscore_init();
	mock_nvm_reset();
	oscore_nvm_register_callbacks(NULL, NULL);
	return NULL;
}

static void oscore_vectors_before(void *fixture)
{
	ARG_UNUSED(fixture);
	mock_nvm_reset();
}

/*
 * RFC 8613 Appendix C.4: Request protection with empty sender ID.
 * The sender_id is empty (""), so the nonce construction bypasses
 * the s-field + sender_id path and produces a byte-exact match to
 * the Python/aiocoap reference.
 */
ZTEST(oscore_vectors, test_rfc8613_c4_request_protect_exact)
{
	struct oscore_ctx *ctx = NULL;
	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);

	zassert_equal(oscore_ctx_create(rfc8613_ms, rfc8613_salt, sizeof(rfc8613_salt),
					NULL, 0,
					c4_recipient_id, sizeof(c4_recipient_id),
					&ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	zassert_equal(oscore_ctx_set_sender_seq(ctx, 20), OSCORE_OK);

	zassert_equal(oscore_protect_request(ctx, 0x01,
					c4_options, sizeof(c4_options),
					NULL, 0,
					ciphertext, &ct_len,
					oscore_opt, &opt_len),
		      OSCORE_OK);

	zassert_equal(ct_len, sizeof(c4_expected_ciphertext),
		      "C4 ciphertext length mismatch");
	zassert_mem_equal(ciphertext, c4_expected_ciphertext,
			  sizeof(c4_expected_ciphertext),
			  "C4 ciphertext mismatch (check nonce/AAD construction)");

	zassert_equal(opt_len, sizeof(c4_expected_oscore_opt),
		      "C4 oscore_option length mismatch");
	zassert_mem_equal(oscore_opt, c4_expected_oscore_opt,
			  sizeof(c4_expected_oscore_opt),
			  "C4 oscore_option mismatch");

	oscore_ctx_free(ctx);
}

/*
 * Full request roundtrip: protect with client context,
 * unprotect with server context (swapped IDs).
 */
ZTEST(oscore_vectors, test_request_roundtrip)
{
	struct oscore_ctx *sender_ctx = NULL;
	struct oscore_ctx *recipient_ctx = NULL;
	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	uint8_t code;
	uint8_t options[32];
	size_t recv_opt_len = sizeof(options);
	uint8_t payload[64];
	size_t recv_pay_len = sizeof(payload);

	zassert_equal(oscore_ctx_create(rt_ms, rt_salt, sizeof(rt_salt),
					rt_sender_id, sizeof(rt_sender_id),
					rt_recipient_id, sizeof(rt_recipient_id),
					&sender_ctx),
		      OSCORE_OK);
	zassert_not_null(sender_ctx);

	zassert_equal(oscore_ctx_create(rt_ms2, rt_salt2, sizeof(rt_salt2),
					rt_recipient_id, sizeof(rt_recipient_id),
					rt_sender_id, sizeof(rt_sender_id),
					&recipient_ctx),
		      OSCORE_OK);
	zassert_not_null(recipient_ctx);

	zassert_equal(oscore_ctx_set_sender_seq(sender_ctx, 42), OSCORE_OK);

	zassert_equal(oscore_protect_request(sender_ctx, 0x02,
					NULL, 0,
					rt_payload, sizeof(rt_payload),
					ciphertext, &ct_len,
					oscore_opt, &opt_len),
		      OSCORE_OK);

	zassert_equal(oscore_unprotect_request(recipient_ctx,
					oscore_opt, opt_len,
					ciphertext, ct_len,
					&code,
					options, &recv_opt_len,
					payload, &recv_pay_len),
		      OSCORE_OK);

	zassert_equal(code, 0x02, "roundtrip code mismatch");
	zassert_equal(recv_pay_len, sizeof(rt_payload), "roundtrip payload len mismatch");
	zassert_mem_equal(payload, rt_payload, sizeof(rt_payload),
			  "roundtrip payload mismatch");

	oscore_ctx_free(sender_ctx);
	oscore_ctx_free(recipient_ctx);
}

/*
 * A 40-bit Partial IV must remain 64-bit through replay processing. First
 * commit sequence 1, then accept 2^32 + 1 even though the low 32 bits collide.
 * At the highest usable sequence, failed authentication must also release the
 * pending reservation without advancing replay state.
 */
ZTEST(oscore_vectors, test_request_replay_uses_full_40_bit_partial_iv)
{
	struct oscore_ctx *sender_ctx = NULL;
	struct oscore_ctx *recipient_ctx = NULL;
	uint8_t ciphertext[64];
	uint8_t saved_ciphertext[64];
	uint8_t oscore_opt[32];
	uint8_t saved_oscore_opt[32];
	uint8_t code;
	uint8_t options[8];
	uint8_t payload[64];
	size_t ct_len;
	size_t opt_len;
	size_t recv_opt_len;
	size_t recv_pay_len;

	zassert_equal(oscore_ctx_create(rt_ms, rt_salt, sizeof(rt_salt),
					rt_sender_id, sizeof(rt_sender_id),
					rt_recipient_id, sizeof(rt_recipient_id),
					&sender_ctx),
		      OSCORE_OK);
	zassert_equal(oscore_ctx_create(rt_ms2, rt_salt2, sizeof(rt_salt2),
					rt_recipient_id, sizeof(rt_recipient_id),
					rt_sender_id, sizeof(rt_sender_id),
					&recipient_ctx),
		      OSCORE_OK);

	const uint64_t sequences[] = { 1, (1ULL << 32) + 1 };
	for (size_t i = 0; i < ARRAY_SIZE(sequences); i++) {
		ct_len = sizeof(ciphertext);
		opt_len = sizeof(oscore_opt);
		recv_opt_len = sizeof(options);
		recv_pay_len = sizeof(payload);
		zassert_equal(oscore_ctx_set_sender_seq(sender_ctx, sequences[i]), OSCORE_OK);
		zassert_equal(oscore_protect_request(sender_ctx, 0x02,
						NULL, 0, rt_payload, sizeof(rt_payload),
						ciphertext, &ct_len, oscore_opt, &opt_len),
			      OSCORE_OK);
		zassert_equal(oscore_unprotect_request(recipient_ctx,
						  oscore_opt, opt_len, ciphertext, ct_len,
						  &code, options, &recv_opt_len,
						  payload, &recv_pay_len),
			      OSCORE_OK,
			      "40-bit PIV was truncated at sequence %llu",
			      (unsigned long long)sequences[i]);
	}

	/* The exact high-PIV ciphertext is still rejected as a replay. */
	recv_opt_len = sizeof(options);
	recv_pay_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  oscore_opt, opt_len, ciphertext, ct_len,
					  &code, options, &recv_opt_len,
					  payload, &recv_pay_len),
		      OSCORE_ERR_REPLAY);

	/* OSCORE_SSN_MAX is the terminal usable five-byte PIV. */
	ct_len = sizeof(ciphertext);
	opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_ctx_set_sender_seq(sender_ctx, OSCORE_SSN_MAX), OSCORE_OK);
	zassert_equal(oscore_protect_request(sender_ctx, 0x02,
					NULL, 0, rt_payload, sizeof(rt_payload),
					ciphertext, &ct_len, oscore_opt, &opt_len),
		      OSCORE_OK);
	zassert_equal(opt_len, 7U);
	zassert_equal(oscore_opt[0], 0x0d);
	zassert_mem_equal(&oscore_opt[1], "\xff\xff\xff\xff\xff", 5);
	zassert_equal(oscore_opt[6], rt_sender_id[0]);
	memcpy(saved_ciphertext, ciphertext, ct_len);
	memcpy(saved_oscore_opt, oscore_opt, opt_len);

	/* Authentication failure must neither commit nor strand the reservation. */
	ciphertext[0] ^= 0x80;
	recv_opt_len = sizeof(options);
	recv_pay_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  oscore_opt, opt_len, ciphertext, ct_len,
					  &code, options, &recv_opt_len,
					  payload, &recv_pay_len),
		      OSCORE_ERR_DECRYPT_FAILED);

	recv_opt_len = sizeof(options);
	recv_pay_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  saved_oscore_opt, opt_len,
					  saved_ciphertext, ct_len,
					  &code, options, &recv_opt_len,
					  payload, &recv_pay_len),
		      OSCORE_OK);
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  saved_oscore_opt, opt_len,
					  saved_ciphertext, ct_len,
					  &code, options, &recv_opt_len,
					  payload, &recv_pay_len),
		      OSCORE_ERR_REPLAY);

	/* The terminal PIV is single-use; the following request is exhausted. */
	memset(ciphertext, 0xa5, sizeof(ciphertext));
	memset(oscore_opt, 0x5a, sizeof(oscore_opt));
	ct_len = sizeof(ciphertext);
	opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(sender_ctx, 0x02,
					NULL, 0, rt_payload, sizeof(rt_payload),
					ciphertext, &ct_len, oscore_opt, &opt_len),
		      OSCORE_ERR_SEQ_EXHAUSTED);
	zassert_equal(ct_len, sizeof(ciphertext));
	zassert_equal(opt_len, sizeof(oscore_opt));
	for (size_t i = 0; i < sizeof(ciphertext); i++) {
		zassert_equal(ciphertext[i], 0xa5);
	}
	for (size_t i = 0; i < sizeof(oscore_opt); i++) {
		zassert_equal(oscore_opt[i], 0x5a);
	}

	oscore_ctx_free(sender_ctx);
	oscore_ctx_free(recipient_ctx);
}

ZTEST(oscore_vectors, test_protect_request_rolls_back_before_publish)
{
	struct oscore_ctx *ctx = NULL;
	uint8_t ciphertext[32];
	uint8_t oscore_opt[16];
	uint64_t seq;
	size_t ct_len;
	size_t opt_len;

	zassert_equal(oscore_ctx_create(rt_ms, rt_salt, sizeof(rt_salt),
					rt_sender_id, sizeof(rt_sender_id),
					rt_recipient_id, sizeof(rt_recipient_id), &ctx),
		      OSCORE_OK);
	zassert_equal(oscore_ctx_set_sender_seq(ctx, 9), OSCORE_OK);

	/* Invalid input and an undersized option fail before consuming SSN 9. */
	ct_len = sizeof(ciphertext);
	opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01,
					NULL, 1, NULL, 0,
					ciphertext, &ct_len, oscore_opt, &opt_len),
		      OSCORE_ERR_INVALID_PARAM);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &seq), OSCORE_OK);
	zassert_equal(seq, 9U);

	memset(ciphertext, 0xa5, sizeof(ciphertext));
	memset(oscore_opt, 0x5a, sizeof(oscore_opt));
	ct_len = sizeof(ciphertext);
	opt_len = 1;
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0,
					ciphertext, &ct_len, oscore_opt, &opt_len),
		      OSCORE_ERR_BUFFER_TOO_SMALL);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &seq), OSCORE_OK);
	zassert_equal(seq, 9U);
	zassert_equal(ct_len, sizeof(ciphertext));
	zassert_equal(opt_len, 1U);
	for (size_t i = 0; i < sizeof(ciphertext); i++) {
		zassert_equal(ciphertext[i], 0xa5);
	}
	for (size_t i = 0; i < sizeof(oscore_opt); i++) {
		zassert_equal(oscore_opt[i], 0x5a);
	}

	/* Failed durable reservation likewise rolls back and publishes nothing. */
	oscore_nvm_register_callbacks(mock_nvm_write, mock_nvm_read);
	mock_nvm_set_write_fail(true);
	ct_len = sizeof(ciphertext);
	opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0,
					ciphertext, &ct_len, oscore_opt, &opt_len),
		      OSCORE_ERR_NVM_FAILED);
	zassert_equal(mock_nvm_write_count, 3);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &seq), OSCORE_OK);
	zassert_equal(seq, 9U);
	zassert_equal(ct_len, sizeof(ciphertext));
	zassert_equal(opt_len, sizeof(oscore_opt));
	for (size_t i = 0; i < sizeof(ciphertext); i++) {
		zassert_equal(ciphertext[i], 0xa5);
	}
	for (size_t i = 0; i < sizeof(oscore_opt); i++) {
		zassert_equal(oscore_opt[i], 0x5a);
	}

	mock_nvm_set_write_fail(false);
	ct_len = sizeof(ciphertext);
	opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0,
					ciphertext, &ct_len, oscore_opt, &opt_len),
		      OSCORE_OK);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &seq), OSCORE_OK);
	/* Durable persist skips OSCORE_SSN_SAFETY_MARGIN past the next
	 * unused sequence; in-RAM SSN and NVM hold the same skipped value. */
	zassert_equal(seq, 10U + OSCORE_SSN_SAFETY_MARGIN);
	zassert_equal(mock_nvm_ssn, 10U + OSCORE_SSN_SAFETY_MARGIN);
	zassert_equal(oscore_opt[0], 0x09);
	zassert_equal(oscore_opt[1], 9U);
	zassert_equal(oscore_opt[2], rt_sender_id[0]);

	oscore_ctx_free(ctx);
	oscore_nvm_register_callbacks(NULL, NULL);
}

ZTEST(oscore_vectors, test_request_unprotect_is_bound_and_fail_before_output)
{
	static const uint8_t valid_options[] = { 0xb1, 'x' };
	static const uint8_t valid_payload[] = { 0x10, 0x20 };
	struct oscore_ctx *sender_ctx = NULL;
	struct oscore_ctx *recipient_ctx = NULL;
	uint8_t ciphertext[64];
	uint8_t saved_ciphertext[64];
	uint8_t oscore_opt[32];
	uint8_t saved_oscore_opt[32];
	uint8_t bad_opt[32];
	uint8_t code;
	uint8_t options[16];
	uint8_t payload[16];
	size_t ct_len;
	size_t opt_len;
	size_t options_len;
	size_t payload_len;

	zassert_equal(oscore_ctx_create(rt_ms, rt_salt, sizeof(rt_salt),
					rt_sender_id, sizeof(rt_sender_id),
					rt_recipient_id, sizeof(rt_recipient_id),
					&sender_ctx), OSCORE_OK);
	zassert_equal(oscore_ctx_create(rt_ms2, rt_salt2, sizeof(rt_salt2),
					rt_recipient_id, sizeof(rt_recipient_id),
					rt_sender_id, sizeof(rt_sender_id),
					&recipient_ctx), OSCORE_OK);

	ct_len = sizeof(ciphertext);
	opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_ctx_set_sender_seq(sender_ctx, 77), OSCORE_OK);
	zassert_equal(oscore_protect_request(sender_ctx, 0x01,
					valid_options, sizeof(valid_options),
					valid_payload, sizeof(valid_payload),
					ciphertext, &ct_len, oscore_opt, &opt_len),
		      OSCORE_OK);
	memcpy(saved_ciphertext, ciphertext, ct_len);
	memcpy(saved_oscore_opt, oscore_opt, opt_len);

	/* Insufficient output must not expose plaintext or consume the request. */
	code = 0xa5;
	memset(options, 0xa5, sizeof(options));
	memset(payload, 0xa5, sizeof(payload));
	options_len = 1;
	payload_len = 1;
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  saved_oscore_opt, opt_len,
					  saved_ciphertext, ct_len,
					  &code, options, &options_len,
					  payload, &payload_len),
		      OSCORE_ERR_BUFFER_TOO_SMALL);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, 1U);
	zassert_equal(payload_len, 1U);
	zassert_equal(options[0], 0xa5);
	zassert_equal(payload[0], 0xa5);

	/* A KID, KID Context, or reserved-bit mismatch selects no usable context. */
	memcpy(bad_opt, saved_oscore_opt, opt_len);
	bad_opt[opt_len - 1] ^= 0x01;
	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(recipient_ctx, bad_opt, opt_len,
					  saved_ciphertext, ct_len, &code,
					  options, &options_len, payload, &payload_len),
		      OSCORE_ERR_NO_CONTEXT);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, sizeof(payload));

	bad_opt[0] = (uint8_t)(saved_oscore_opt[0] | 0x10);
	/* Rebuild h=1 ordering: flags, PIV, context length/value, then KID. */
	bad_opt[1] = saved_oscore_opt[1];
	bad_opt[2] = 1;
	bad_opt[3] = 0x99;
	bad_opt[4] = rt_sender_id[0];
	zassert_equal(oscore_unprotect_request(recipient_ctx, bad_opt, 5,
					  saved_ciphertext, ct_len, &code,
					  options, &options_len, payload, &payload_len),
		      OSCORE_ERR_NO_CONTEXT);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, sizeof(payload));

	memcpy(bad_opt, saved_oscore_opt, opt_len);
	bad_opt[0] |= 0x20;
	zassert_equal(oscore_unprotect_request(recipient_ctx, bad_opt, opt_len,
					  saved_ciphertext, ct_len, &code,
					  options, &options_len, payload, &payload_len),
		      OSCORE_ERR_INVALID_PARAM);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, sizeof(payload));

	/* Missing/non-canonical PIVs fail before authentication state. */
	static const uint8_t missing_piv[] = { 0x08, 0xaa };
	static const uint8_t missing_kid[] = { 0x01, 77 };
	static const uint8_t noncanonical_piv[] = { 0x0a, 0x00, 0x4d, 0xaa };
	static const uint8_t terminal_piv_wrong_ciphertext[] = {
		0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa
	};
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  missing_piv, sizeof(missing_piv),
					  saved_ciphertext, ct_len, &code,
					  options, &options_len, payload, &payload_len),
		      OSCORE_ERR_INVALID_PARAM);
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  missing_kid, sizeof(missing_kid),
					  saved_ciphertext, ct_len, &code,
					  options, &options_len, payload, &payload_len),
		      OSCORE_ERR_NO_CONTEXT);
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  noncanonical_piv, sizeof(noncanonical_piv),
					  saved_ciphertext, ct_len, &code,
					  options, &options_len, payload, &payload_len),
		      OSCORE_ERR_INVALID_PARAM);
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  terminal_piv_wrong_ciphertext,
					  sizeof(terminal_piv_wrong_ciphertext),
					  saved_ciphertext, ct_len, &code,
					  options, &options_len, payload, &payload_len),
		      OSCORE_ERR_DECRYPT_FAILED);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, sizeof(payload));

	/* Authentication failure rolls the reservation back for an exact retry. */
	ciphertext[0] ^= 0x80;
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  saved_oscore_opt, opt_len, ciphertext, ct_len,
					  &code, options, &options_len,
					  payload, &payload_len),
		      OSCORE_ERR_DECRYPT_FAILED);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, sizeof(payload));
	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  saved_oscore_opt, opt_len,
					  saved_ciphertext, ct_len,
					  &code, options, &options_len,
					  payload, &payload_len), OSCORE_OK);
	zassert_equal(code, 0x01);
	zassert_mem_equal(options, valid_options, sizeof(valid_options));
	zassert_mem_equal(payload, valid_payload, sizeof(valid_payload));

	code = 0xa5;
	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(recipient_ctx,
					  saved_oscore_opt, opt_len,
					  saved_ciphertext, ct_len,
					  &code, options, &options_len,
					  payload, &payload_len), OSCORE_ERR_REPLAY);
	zassert_equal(code, 0xa5);
	zassert_equal(options_len, sizeof(options));
	zassert_equal(payload_len, sizeof(payload));

	oscore_ctx_free(sender_ctx);
	oscore_ctx_free(recipient_ctx);
}

ZTEST(oscore_vectors, test_request_plaintext_validation_rolls_back_replay)
{
	static const uint8_t malformed_options[] = { 0xf0 };
	static const uint8_t empty_payload_marker[] = { 0xff };
	struct oscore_ctx *sender_ctx = NULL;
	struct oscore_ctx *recipient_ctx = NULL;
	uint8_t ciphertext[64];
	uint8_t oscore_opt[32];
	uint8_t code;
	uint8_t options[8] = {0};
	uint8_t payload[8] = {0};
	size_t ct_len;
	size_t opt_len;
	size_t options_len;
	size_t payload_len;
	const uint8_t *bad_options[] = { NULL, malformed_options, empty_payload_marker };
	const size_t bad_options_len[] = { 0, sizeof(malformed_options),
					   sizeof(empty_payload_marker) };
	const uint8_t bad_codes[] = { 0x00, 0x01, 0x01 };

	zassert_equal(oscore_ctx_create(rt_ms, rt_salt, sizeof(rt_salt),
					rt_sender_id, sizeof(rt_sender_id),
					rt_recipient_id, sizeof(rt_recipient_id),
					&sender_ctx), OSCORE_OK);
	zassert_equal(oscore_ctx_create(rt_ms2, rt_salt2, sizeof(rt_salt2),
					rt_recipient_id, sizeof(rt_recipient_id),
					rt_sender_id, sizeof(rt_sender_id),
					&recipient_ctx), OSCORE_OK);

	for (size_t i = 0; i < ARRAY_SIZE(bad_codes); i++) {
		uint64_t seq = 100 + i;
		ct_len = sizeof(ciphertext);
		opt_len = sizeof(oscore_opt);
		zassert_equal(oscore_ctx_set_sender_seq(sender_ctx, seq), OSCORE_OK);
		zassert_equal(oscore_protect_request(sender_ctx, bad_codes[i],
						bad_options[i], bad_options_len[i],
						NULL, 0, ciphertext, &ct_len,
						oscore_opt, &opt_len), OSCORE_OK);
		code = 0xa5;
		options_len = sizeof(options);
		payload_len = sizeof(payload);
		zassert_equal(oscore_unprotect_request(recipient_ctx,
						  oscore_opt, opt_len, ciphertext, ct_len,
						  &code, options, &options_len,
						  payload, &payload_len),
			      OSCORE_ERR_INVALID_PARAM);
		zassert_equal(code, 0xa5);
		zassert_equal(options_len, sizeof(options));
		zassert_equal(payload_len, sizeof(payload));

		/* The same sequence remains usable by a valid authenticated request. */
		ct_len = sizeof(ciphertext);
		opt_len = sizeof(oscore_opt);
		zassert_equal(oscore_ctx_set_sender_seq(sender_ctx, seq), OSCORE_OK);
		zassert_equal(oscore_protect_request(sender_ctx, 0x01, NULL, 0, NULL, 0,
						ciphertext, &ct_len, oscore_opt, &opt_len),
			      OSCORE_OK);
		options_len = sizeof(options);
		payload_len = sizeof(payload);
		zassert_equal(oscore_unprotect_request(recipient_ctx,
						  oscore_opt, opt_len, ciphertext, ct_len,
						  &code, options, &options_len,
						  payload, &payload_len), OSCORE_OK);
	}

	oscore_ctx_free(sender_ctx);
	oscore_ctx_free(recipient_ctx);
}

/*
 * Full request roundtrip with RFC 8613 C4 vectors:
 * Client context (sender_id="", recipient_id="01") protects,
 * Server context (sender_id="01", recipient_id="") unprotects.
 * This validates byte-exact interop at the roundtrip level
 * for the case where the server has a KID.
 */
ZTEST(oscore_vectors, test_rfc8613_c4_roundtrip)
{
	struct oscore_ctx *client_ctx = NULL;
	struct oscore_ctx *server_ctx = NULL;
	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	uint8_t code;
	uint8_t options[32];
	size_t recv_opt_len = sizeof(options);
	uint8_t payload[64];
	size_t recv_pay_len = sizeof(payload);

	zassert_equal(oscore_ctx_create(rfc8613_ms2, rfc8613_salt2, sizeof(rfc8613_salt2),
					NULL, 0,
					c4_recipient_id, sizeof(c4_recipient_id),
					&client_ctx),
		      OSCORE_OK);
	zassert_not_null(client_ctx);

	zassert_equal(oscore_ctx_create(rfc8613_ms3, rfc8613_salt, sizeof(rfc8613_salt),
					c4_recipient_id, sizeof(c4_recipient_id),
					NULL, 0,
					&server_ctx),
		      OSCORE_OK);
	zassert_not_null(server_ctx);

	zassert_equal(oscore_ctx_set_sender_seq(client_ctx, 20), OSCORE_OK);

	zassert_equal(oscore_protect_request(client_ctx, 0x01,
					c4_options, sizeof(c4_options),
					NULL, 0,
					ciphertext, &ct_len,
					oscore_opt, &opt_len),
		      OSCORE_OK);

	zassert_equal(oscore_unprotect_request(server_ctx,
					oscore_opt, opt_len,
					ciphertext, ct_len,
					&code,
					options, &recv_opt_len,
					payload, &recv_pay_len),
		      OSCORE_OK);

	zassert_equal(code, 0x01, "C4 roundtrip code mismatch");
	zassert_equal(recv_opt_len, sizeof(c4_options),
		      "C4 roundtrip options length mismatch");
	zassert_mem_equal(options, c4_options, sizeof(c4_options),
			  "C4 roundtrip options mismatch");
	zassert_equal(recv_pay_len, 0, "C4 roundtrip payload len mismatch");

	oscore_ctx_free(client_ctx);
	oscore_ctx_free(server_ctx);
}

ZTEST_SUITE(oscore_vectors, NULL, oscore_vectors_setup, oscore_vectors_before, NULL, NULL);
