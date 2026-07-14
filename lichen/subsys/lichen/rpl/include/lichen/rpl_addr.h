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

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compare two 16-byte IPv6 addresses for equality.
 */
static inline bool rpl_addr_eq(const uint8_t *_Nonnull a, const uint8_t *_Nonnull b)
{
	return memcmp(a, b, 16) == 0;
}

/**
 * @brief Copy a 16-byte IPv6 address.
 */
static inline void rpl_addr_copy(uint8_t *_Nonnull dst, const uint8_t *_Nonnull src)
{
	memcpy(dst, src, 16);
}

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_ADDR_H_ */
