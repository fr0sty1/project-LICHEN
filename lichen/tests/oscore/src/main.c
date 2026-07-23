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

/* NVM mock storage */
static uint8_t mock_nvm_eui64[OSCORE_EUI64_LEN];
static uint32_t mock_nvm_ssn;
static bool mock_nvm_has_data;
static int mock_nvm_write_count;
static int mock_nvm_read_count;

static int mock_nvm_write(const uint8_t *eui64, uint32_t ssn)
{
	mock_nvm_write_count++;
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

	/* Set SSN and persist */
	zassert_equal(oscore_ctx_set_sender_seq(ctx, 12345), OSCORE_OK);
	zassert_equal(oscore_ctx_persist_ssn(ctx), OSCORE_OK);

	/* Verify NVM was written */
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

	/* Pre-populate NVM with stored SSN */
	memcpy(mock_nvm_eui64, peer_eui64_1, OSCORE_EUI64_LEN);
	mock_nvm_ssn = 54321;
	mock_nvm_has_data = true;

	oscore_nvm_register_callbacks(mock_nvm_write, mock_nvm_read);

	/* Create context - should restore SSN from NVM */
	zassert_equal(oscore_ctx_create_with_eui64(master_secret, NULL, 0,
						   sender_id, sizeof(sender_id),
						   recipient_id, sizeof(recipient_id),
						   peer_eui64_1, &ctx),
		      OSCORE_OK);
	zassert_not_null(ctx);

	/* Verify SSN was restored */
	zassert_equal(mock_nvm_read_count, 1);
	zassert_equal(oscore_ctx_get_sender_seq(ctx, &restored_ssn), OSCORE_OK);
	zassert_equal(restored_ssn, 54321U);

	oscore_ctx_free(ctx);
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

ZTEST(oscore_ctx, test_nvm_read_failure_fallback_to_zero)
{
	struct oscore_ctx *ctx = NULL;
	uint32_t ssn;
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
	zassert_equal(ssn, 2U);
	oscore_ctx_free(ctx);
	oscore_nvm_register_callbacks(NULL, NULL);
}

ZTEST_SUITE(oscore_ctx, NULL, oscore_ctx_setup, oscore_ctx_before, NULL, NULL);
