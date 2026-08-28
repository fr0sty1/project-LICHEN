/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_COMPACT_COT_PLI_H_
#define LICHEN_COMPACT_COT_PLI_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Exact size of a Compact CoT PLI datagram. */
#define LICHEN_COMPACT_COT_PLI_SIZE 17U

#define LICHEN_COMPACT_COT_LAT_MIN (-90000000)
#define LICHEN_COMPACT_COT_LAT_MAX 90000000
#define LICHEN_COMPACT_COT_LON_MIN (-180000000)
#define LICHEN_COMPACT_COT_LON_MAX 180000000
#define LICHEN_COMPACT_COT_COURSE_MAX 35999U

/** Assigned Compact CoT PLI subtype bytes. */
enum lichen_compact_cot_pli_subtype {
	LICHEN_COMPACT_COT_PLI_FRIENDLY = 0x02,
	LICHEN_COMPACT_COT_PLI_HOSTILE = 0x03,
	LICHEN_COMPACT_COT_PLI_NEUTRAL = 0x04,
	LICHEN_COMPACT_COT_PLI_UNKNOWN = 0x05,
};

/** Decoded Position Location Information fields. */
struct lichen_compact_cot_pli {
	uint8_t subtype;
	int32_t latitude_microdegrees;
	int32_t longitude_microdegrees;
	int16_t altitude_decimeters;
	uint16_t course_centidegrees;
	uint16_t speed_cm_s;
	uint8_t team;
	uint8_t role;
};

/**
 * Encode one PLI datagram in network byte order.
 *
 * Team and role are carried as opaque enumeration bytes so future assigned
 * values remain forward-compatible. The output is not modified on error and
 * may overlap @p pli.
 *
 * @return 0 on success, -EINVAL for NULL/invalid fields, or -EMSGSIZE when
 *         @p output_size is smaller than LICHEN_COMPACT_COT_PLI_SIZE.
 */
int lichen_compact_cot_pli_encode(const struct lichen_compact_cot_pli *pli,
				  uint8_t *output, size_t output_size);

/**
 * Decode one exact-size PLI datagram in network byte order.
 *
 * The decoded structure is not modified on error and may overlap @p input.
 *
 * @return 0 on success, -EINVAL for NULL/invalid fields or a reserved
 *         subtype, or -EMSGSIZE unless @p input_size is exactly 17 bytes.
 */
int lichen_compact_cot_pli_decode(const uint8_t *input, size_t input_size,
				  struct lichen_compact_cot_pli *pli);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COMPACT_COT_PLI_H_ */
