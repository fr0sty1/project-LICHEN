/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>

#include <lichen/oscore.h>

ZTEST(oscore_ctx, test_rejects_identical_nonempty_sender_and_recipient_ids)
{
	const uint8_t master_secret[OSCORE_KEY_LEN] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};
	const uint8_t id[] = { 0x01 };
	struct oscore_ctx *ctx = NULL;

	zassert_equal(oscore_ctx_create(master_secret, NULL, 0,
					id, sizeof(id),
					id, sizeof(id),
					&ctx),
		      OSCORE_ERR_INVALID_PARAM);
	zassert_is_null(ctx);
}

ZTEST_SUITE(oscore_ctx, NULL, NULL, NULL, NULL, NULL);
