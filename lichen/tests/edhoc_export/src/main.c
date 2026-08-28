/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <lichen/edhoc.h>

#include "../../../subsys/lichen/edhoc/edhoc_internal.h"
#include "fixture.h"

ZTEST(edhoc_export, test_rfc9529_export_chain)
{
	uint8_t actual[32] = {0};

	zassert_equal(edhoc_kdf_int(prk_4e3m, 7, th_4, sizeof(th_4),
				    actual, sizeof(actual)), 0);
	zassert_mem_equal(actual, prk_out, sizeof(prk_out));
	zassert_equal(edhoc_kdf_int(actual, 10, NULL, 0,
				    actual, sizeof(actual)), 0);
	zassert_mem_equal(actual, prk_exporter, sizeof(prk_exporter));
	zassert_equal(edhoc_kdf_int(actual, 0, NULL, 0,
				    actual, sizeof(master_secret)), 0);
	zassert_mem_equal(actual, master_secret, sizeof(master_secret));
	zassert_equal(edhoc_kdf_int(prk_exporter, 1, NULL, 0,
				    actual, sizeof(master_salt)), 0);
	zassert_mem_equal(actual, master_salt, sizeof(master_salt));
}

ZTEST(edhoc_export, test_rfc9528_role_mapping_and_atomic_lifecycle)
{
	struct edhoc_initiator initiator = {0};
	struct edhoc_responder responder = {0};
	struct edhoc_oscore_ctx initiator_oscore = {0};
	struct edhoc_oscore_ctx responder_oscore = {0};

	initiator.state = EDHOC_STATE_COMPLETED;
	memcpy(initiator.prk_4e3m, prk_4e3m, sizeof(prk_4e3m));
	memcpy(initiator.th_4, th_4, sizeof(th_4));
	memcpy(initiator.c_i, c_i, sizeof(c_i));
	initiator.c_i_len = sizeof(c_i);
	memcpy(initiator.c_r, c_r, sizeof(c_r));
	initiator.c_r_len = sizeof(c_r);

	responder.state = EDHOC_STATE_COMPLETED;
	memcpy(responder.prk_4e3m, prk_4e3m, sizeof(prk_4e3m));
	memcpy(responder.th_4, th_4, sizeof(th_4));
	memcpy(responder.c_i, c_i, sizeof(c_i));
	responder.c_i_len = sizeof(c_i);
	memcpy(responder.c_r, c_r, sizeof(c_r));
	responder.c_r_len = sizeof(c_r);

	zassert_equal(edhoc_initiator_export_oscore(&initiator, &initiator_oscore), 0);
	zassert_equal(edhoc_responder_export_oscore(&responder, &responder_oscore), 0);
	zassert_mem_equal(initiator_oscore.master_secret, master_secret,
			  sizeof(master_secret));
	zassert_mem_equal(responder_oscore.master_secret, master_secret,
			  sizeof(master_secret));
	zassert_mem_equal(initiator_oscore.master_salt, master_salt,
			  sizeof(master_salt));
	zassert_mem_equal(responder_oscore.master_salt, master_salt,
			  sizeof(master_salt));
	zassert_mem_equal(initiator_oscore.sender_id, initiator_sender_id,
			  sizeof(initiator_sender_id));
	zassert_mem_equal(initiator_oscore.recipient_id, initiator_recipient_id,
			  sizeof(initiator_recipient_id));
	zassert_mem_equal(responder_oscore.sender_id, responder_sender_id,
			  sizeof(responder_sender_id));
	zassert_mem_equal(responder_oscore.recipient_id, responder_recipient_id,
			  sizeof(responder_recipient_id));
	zassert_equal(initiator.state, EDHOC_STATE_EXPORTED);
	zassert_equal(responder.state, EDHOC_STATE_EXPORTED);
	zassert_mem_equal(initiator.prk_4e3m, (uint8_t[32]){0}, 32);
	zassert_mem_equal(responder.prk_4e3m, (uint8_t[32]){0}, 32);

	/* Re-export and pre-completion export fail before mutating output. */
	memset(&initiator_oscore, 0xa5, sizeof(initiator_oscore));
	zassert_equal(edhoc_initiator_export_oscore(&initiator, &initiator_oscore),
		      -EBUSY);
	zassert_equal(initiator_oscore.master_secret[0], 0xa5);
	memset(&responder_oscore, 0x5a, sizeof(responder_oscore));
	responder.state = EDHOC_STATE_MSG2_SENT;
	zassert_equal(edhoc_responder_export_oscore(&responder, &responder_oscore),
		      -EBUSY);
	zassert_equal(responder_oscore.master_secret[0], 0x5a);
}

ZTEST_SUITE(edhoc_export, NULL, NULL, NULL, NULL, NULL);

