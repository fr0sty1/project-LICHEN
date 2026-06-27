/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file zcbor_encode.h
 * @brief Minimal zcbor stub for standalone SenML tests
 *
 * Implements just enough of zcbor to test senml.c outside of Zephyr.
 * This is NOT a full zcbor implementation - only what senml.c uses.
 */

#ifndef ZCBOR_ENCODE_H_
#define ZCBOR_ENCODE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
	uint8_t *payload;
	uint8_t *payload_end;
} zcbor_state_t;

#define ZCBOR_STATE_E(name, n, buf, buflen, elem_count) \
	zcbor_state_t name##_state = { .payload = (buf), .payload_end = (buf) + (buflen) }; \
	zcbor_state_t *name = &name##_state

bool zcbor_list_start_encode(zcbor_state_t *state, size_t max_num);
bool zcbor_list_end_encode(zcbor_state_t *state, size_t max_num);
bool zcbor_map_start_encode(zcbor_state_t *state, size_t max_num);
bool zcbor_map_end_encode(zcbor_state_t *state, size_t max_num);
bool zcbor_int32_put(zcbor_state_t *state, int32_t value);
bool zcbor_uint64_put(zcbor_state_t *state, uint64_t value);
bool zcbor_tstr_put_term(zcbor_state_t *state, const char *str, size_t maxlen);
bool zcbor_float32_put(zcbor_state_t *state, float value);
bool zcbor_bool_put(zcbor_state_t *state, bool value);

#endif /* ZCBOR_ENCODE_H_ */
