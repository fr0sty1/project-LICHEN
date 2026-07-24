/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>
#include <string.h>

#include <lichen/oscore.h>

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
static uint32_t mock_nvm_ssn;
static bool mock_nvm_has_data;
static int mock_nvm_write_count;
static int mock_nvm_read_count;
static bool mock_nvm_write_fails;

static int mock_nvm_write(const uint8_t *eui64, uint32_t ssn)
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

static int mock_nvm_read(const uint8_t *eui64, uint32_t *ssn)
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
	zassert_equal(oscore_ctx_set_sender_seq(ctx, UINT32_MAX - 5000), OSCORE_OK);

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

	/* Set SSN to max */
	zassert_equal(oscore_ctx_set_sender_seq(ctx, UINT32_MAX), OSCORE_OK);

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
	uint32_t restored_ssn;

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

ZTEST(oscore_ctx, test_nvm_protect_request_nvm_failure)
{
	struct oscore_ctx *ctx = NULL;
	uint8_t ciphertext[64];
	size_t ct_len = sizeof(ciphertext);
	uint8_t oscore_opt[32];
	size_t opt_len = sizeof(oscore_opt);
	uint32_t ssn;
	oscore_nvm_register_callbacks(mock_nvm_write, mock_nvm_read);
	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0, sender_id, sizeof(sender_id), recipient_id, sizeof(recipient_id), peer_eui64_1, &ctx), OSCORE_OK);
	zassert_not_null(ctx);
	zassert_equal(oscore_ctx_set_sender_seq(ctx, 100), OSCORE_OK);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	zassert_equal(ssn, 100U);
	mock_nvm_set_write_fail(true);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0, ciphertext, &ct_len, oscore_opt, &opt_len), OSCORE_ERR_NVM_FAILED);
	zassert_equal(mock_nvm_write_count, 1);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	zassert_equal(ssn, 100U);
	mock_nvm_set_write_fail(false);
	ct_len = sizeof(ciphertext); opt_len = sizeof(oscore_opt);
	zassert_equal(oscore_protect_request(ctx, 0x01, NULL, 0, NULL, 0, ciphertext, &ct_len, oscore_opt, &opt_len), OSCORE_OK);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &ssn), OSCORE_OK);
	zassert_equal(ssn, 101U);
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
