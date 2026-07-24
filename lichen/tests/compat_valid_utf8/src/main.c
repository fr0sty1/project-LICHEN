/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/ztest.h>

/*
 * Copy of compat_valid_utf8 from apps/gateway/src/meshcore_adapter.c
 *
 * This is a pure function with no external dependencies. The copy exists so
 * the unit test can compile independently of the gateway app's dependency
 * tree. Both copies MUST be kept identical.
 *
 * Validates RFC 3629 UTF-8 byte sequences:
 *   1-byte:  0x00-0x7F
 *   2-byte:  0xC2-0xDF + 0x80-0xBF
 *   3-byte:  0xE0       + 0xA0-0xBF + 0x80-0xBF
 *            0xE1-0xEC  + 0x80-0xBF + 0x80-0xBF
 *            0xED       + 0x80-0x9F + 0x80-0xBF
 *            0xEE-0xEF  + 0x80-0xBF + 0x80-0xBF
 *   4-byte:  0xF0       + 0x90-0xBF + 0x80-0xBF + 0x80-0xBF
 *            0xF1-0xF3  + 0x80-0xBF + 0x80-0xBF + 0x80-0xBF
 *            0xF4       + 0x80-0x8F + 0x80-0xBF + 0x80-0xBF
 */
static bool test_valid_utf8(const uint8_t *payload, size_t payload_len)
{
	size_t i = 0U;

	while (i < payload_len) {
		uint8_t c = payload[i];

		if (c < 0x80U) {
			i++;
		} else if (c >= 0xc2U && c <= 0xdfU) {
			if (i + 1U >= payload_len ||
			    (payload[i + 1U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 2U;
		} else if (c == 0xe0U) {
			if (i + 2U >= payload_len ||
			    payload[i + 1U] < 0xa0U ||
			    payload[i + 1U] > 0xbfU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 3U;
		} else if ((c >= 0xe1U && c <= 0xecU) ||
			   (c >= 0xeeU && c <= 0xefU)) {
			if (i + 2U >= payload_len ||
			    (payload[i + 1U] & 0xc0U) != 0x80U ||
			    (payload[i + 2U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 3U;
		} else if (c == 0xedU) {
			if (i + 2U >= payload_len ||
			    payload[i + 1U] < 0x80U ||
			    payload[i + 1U] > 0x9fU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 3U;
		} else if (c == 0xf0U) {
			if (i + 3U >= payload_len ||
			    payload[i + 1U] < 0x90U ||
			    payload[i + 1U] > 0xbfU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U ||
			    (payload[i + 3U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 4U;
		} else if (c >= 0xf1U && c <= 0xf3U) {
			if (i + 3U >= payload_len ||
			    (payload[i + 1U] & 0xc0U) != 0x80U ||
			    (payload[i + 2U] & 0xc0U) != 0x80U ||
			    (payload[i + 3U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 4U;
		} else if (c == 0xf4U) {
			if (i + 3U >= payload_len ||
			    payload[i + 1U] < 0x80U ||
			    payload[i + 1U] > 0x8fU ||
			    (payload[i + 2U] & 0xc0U) != 0x80U ||
			    (payload[i + 3U] & 0xc0U) != 0x80U) {
				return false;
			}
			i += 4U;
		} else {
			return false;
		}
	}
	return true;
}

/* Valid 1-byte (ASCII) sequences */
ZTEST(compat_valid_utf8, test_valid_1byte)
{
	zassert_true(test_valid_utf8((const uint8_t *)"", 0U));
	zassert_true(test_valid_utf8((const uint8_t *)"\x00", 1U));
	zassert_true(test_valid_utf8((const uint8_t *)"a", 1U));
	zassert_true(test_valid_utf8((const uint8_t *)"\x7f", 1U));
	zassert_true(test_valid_utf8((const uint8_t *)"hello", 5U));
}

/* Valid 2-byte sequences */
ZTEST(compat_valid_utf8, test_valid_2byte)
{
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xc2, 0x80 }, 2U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xdf, 0xbf }, 2U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xc3, 0xa9 }, 2U));
}

/* Valid 3-byte sequences */
ZTEST(compat_valid_utf8, test_valid_3byte)
{
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xe0, 0xa0, 0x80 }, 3U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xe0, 0xbf, 0xbf }, 3U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xe1, 0x80, 0x80 }, 3U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xec, 0xbf, 0xbf }, 3U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xee, 0x80, 0x80 }, 3U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xef, 0xbf, 0xbf }, 3U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xed, 0x80, 0x80 }, 3U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xed, 0x9f, 0xbf }, 3U));
}

/* Valid 4-byte sequences */
ZTEST(compat_valid_utf8, test_valid_4byte)
{
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xf0, 0x90, 0x80, 0x80 }, 4U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xf0, 0xbf, 0xbf, 0xbf }, 4U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xf1, 0x80, 0x80, 0x80 }, 4U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xf3, 0xbf, 0xbf, 0xbf }, 4U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xf4, 0x80, 0x80, 0x80 }, 4U));
	zassert_true(test_valid_utf8(
		(const uint8_t[]){ 0xf4, 0x8f, 0xbf, 0xbf }, 4U));
}

/* Reject overlong encodings */
ZTEST(compat_valid_utf8, test_reject_overlong)
{
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xc0, 0x80 }, 2U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xc1, 0xbf }, 2U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xe0, 0x9f, 0xbf }, 3U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xf0, 0x8f, 0xbf, 0xbf }, 4U));
}

/* Reject surrogate halves (0xD800-0xDFFF encoded as UTF-8) */
ZTEST(compat_valid_utf8, test_reject_surrogates)
{
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xed, 0xa0, 0x80 }, 3U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xed, 0xbf, 0xbf }, 3U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xed, 0xb0, 0x80 }, 3U));
}

/* Reject values above U+10FFFF */
ZTEST(compat_valid_utf8, test_reject_out_of_range)
{
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xf4, 0x90, 0x80, 0x80 }, 4U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xf5, 0x80, 0x80, 0x80 }, 4U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xff, 0x80, 0x80, 0x80 }, 4U));
}

/* Reject invalid continuation bytes */
ZTEST(compat_valid_utf8, test_reject_invalid_continuation)
{
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xc2 }, 1U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xc2, 0x00 }, 2U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xc2, 0xc0 }, 2U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xe0, 0xa0, 0x00 }, 3U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xc2, 0x7f }, 2U));
}

/* Reject truncated sequences */
ZTEST(compat_valid_utf8, test_reject_truncated)
{
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xc2 }, 1U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xe0, 0xa0 }, 2U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xf0, 0x90, 0x80 }, 3U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xf0, 0x90 }, 2U));
}

/* Reject lone continuation bytes */
ZTEST(compat_valid_utf8, test_reject_lone_continuation)
{
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0x80 }, 1U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 0xbf }, 1U));
	zassert_false(test_valid_utf8(
		(const uint8_t[]){ 'a', 0x80, 'b' }, 3U));
}

ZTEST_SUITE(compat_valid_utf8, NULL, NULL, NULL, NULL, NULL);
