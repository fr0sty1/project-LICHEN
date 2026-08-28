/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef ZEPHYR_SYS_BYTEORDER_H_
#define ZEPHYR_SYS_BYTEORDER_H_

#include <stdint.h>

static inline uint16_t sys_get_be16(const uint8_t *src)
{
	return (uint16_t)(((uint16_t)src[0] << 8) | src[1]);
}

static inline void sys_put_be16(uint16_t val, uint8_t *dst)
{
	dst[0] = (uint8_t)(val >> 8);
	dst[1] = (uint8_t)val;
}

static inline uint32_t sys_get_be32(const uint8_t *src)
{
	return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16)
	     | ((uint32_t)src[2] << 8) | src[3];
}

static inline void sys_put_be32(uint32_t val, uint8_t *dst)
{
	dst[0] = (uint8_t)(val >> 24);
	dst[1] = (uint8_t)(val >> 16);
	dst[2] = (uint8_t)(val >> 8);
	dst[3] = (uint8_t)val;
}

#endif /* ZEPHYR_SYS_BYTEORDER_H_ */
