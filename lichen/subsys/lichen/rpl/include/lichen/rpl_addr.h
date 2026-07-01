/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/rpl_addr.h
 * @brief IPv6 address helpers for RPL
 */

#ifndef LICHEN_RPL_ADDR_H_
#define LICHEN_RPL_ADDR_H_

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compare two 16-byte IPv6 addresses for equality.
 */
static inline bool rpl_addr_eq(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, 16) == 0;
}

/**
 * @brief Copy a 16-byte IPv6 address.
 */
static inline void rpl_addr_copy(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 16);
}

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_ADDR_H_ */
