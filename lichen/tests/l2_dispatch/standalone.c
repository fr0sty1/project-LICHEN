/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <assert.h>
#include <stdint.h>

#include <lichen/l2_payload.h>

int main(void)
{
	for (uint16_t dispatch = 0U; dispatch <= UINT8_MAX; ++dispatch) {
		uint8_t payload[] = {(uint8_t)dispatch, 0x00U};
		enum lichen_l2_payload_kind expected = LICHEN_L2_PAYLOAD_UNKNOWN;

		if (dispatch == LICHEN_L2_DISPATCH_SCHC) {
			expected = LICHEN_L2_PAYLOAD_SCHC;
		} else if (dispatch == LICHEN_L2_DISPATCH_ROUTING) {
			expected = LICHEN_L2_PAYLOAD_ROUTING;
		}
		assert(lichen_l2_payload_classify(payload, sizeof(payload)) == expected);
		assert(lichen_l2_payload_classify(payload, 1U) == LICHEN_L2_PAYLOAD_UNKNOWN);
	}

	assert(lichen_l2_payload_classify(NULL, 0U) == LICHEN_L2_PAYLOAD_UNKNOWN);
	return 0;
}
