/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stddef.h>
#include <stdint.h>

#include <zephyr/ztest.h>

#include <lichen/l2_payload.h>
#include "l2_dispatch_vectors.h"

ZTEST(l2_dispatch, test_canonical_cross_implementation_vectors)
{
	for (size_t i = 0U; i < L2_DISPATCH_VECTOR_COUNT; ++i) {
		const struct l2_dispatch_vector *vector = &l2_dispatch_vectors[i];

		zassert_equal(vector->wrapped[0], vector->dispatch, "%s dispatch", vector->name);
		zassert_equal(lichen_l2_payload_classify(vector->wrapped, vector->wrapped_len),
			      vector->expected, "%s kind", vector->name);
	}
}

ZTEST(l2_dispatch, test_all_dispatch_octets_and_short_payloads_fail_closed)
{
	for (uint16_t dispatch = 0U; dispatch <= UINT8_MAX; ++dispatch) {
		uint8_t payload[] = {(uint8_t)dispatch, 0x00U};
		enum lichen_l2_payload_kind expected = LICHEN_L2_PAYLOAD_UNKNOWN;

		if (dispatch == LICHEN_L2_DISPATCH_SCHC) {
			expected = LICHEN_L2_PAYLOAD_SCHC;
		} else if (dispatch == LICHEN_L2_DISPATCH_ROUTING) {
			expected = LICHEN_L2_PAYLOAD_ROUTING;
		}
		zassert_equal(lichen_l2_payload_classify(payload, sizeof(payload)), expected,
			      "dispatch 0x%02x", dispatch);
		zassert_equal(lichen_l2_payload_classify(payload, 1U),
			      LICHEN_L2_PAYLOAD_UNKNOWN, "short dispatch 0x%02x", dispatch);
	}

	zassert_equal(lichen_l2_payload_classify(NULL, 0U), LICHEN_L2_PAYLOAD_UNKNOWN);
}

ZTEST(l2_dispatch, test_reserved_and_malformed_inputs_do_not_expose_body)
{
	static const uint8_t reserved[] = {0x16U, 0x01U};
	static const uint8_t schc_short[] = {LICHEN_L2_DISPATCH_SCHC};
	static const uint8_t routing_short[] = {LICHEN_L2_DISPATCH_ROUTING};
	size_t body_len = SIZE_MAX;

	zassert_equal(lichen_l2_payload_classify(reserved, sizeof(reserved)),
		      LICHEN_L2_PAYLOAD_UNKNOWN);
	zassert_equal(lichen_l2_payload_classify(schc_short, sizeof(schc_short)),
		      LICHEN_L2_PAYLOAD_UNKNOWN);
	zassert_equal(lichen_l2_payload_classify(routing_short, sizeof(routing_short)),
		      LICHEN_L2_PAYLOAD_UNKNOWN);
	zassert_is_null(lichen_l2_payload_body(NULL, 0U, &body_len));
	zassert_equal(body_len, 0U);
}

ZTEST_SUITE(l2_dispatch, NULL, NULL, NULL, NULL, NULL);
