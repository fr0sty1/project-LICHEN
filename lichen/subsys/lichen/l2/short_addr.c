/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "short_addr.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

static const uint8_t short_addr_iid_prefix[] = {
	0x00, 0x00, 0x00, 0xff, 0xfe, 0x00,
};

bool lichen_short_addr_is_reserved(uint16_t short_addr)
{
	return short_addr == LICHEN_SHORT_ADDR_RESERVED_NULL ||
	       short_addr == LICHEN_SHORT_ADDR_RESERVED_UNSPECIFIED ||
	       short_addr == LICHEN_SHORT_ADDR_RESERVED_BROADCAST;
}

int lichen_short_addr_to_iid(uint16_t short_addr, uint8_t *iid)
{
	if (iid == NULL) {
		return -EINVAL;
	}

	memcpy(iid, short_addr_iid_prefix, sizeof(short_addr_iid_prefix));
	iid[6] = (uint8_t)(short_addr >> 8);
	iid[7] = (uint8_t)short_addr;
	return 0;
}

int lichen_short_addr_from_iid(const uint8_t *iid, uint16_t *short_addr)
{
	if (iid == NULL || short_addr == NULL ||
	    memcmp(iid, short_addr_iid_prefix,
		   sizeof(short_addr_iid_prefix)) != 0) {
		return -EINVAL;
	}

	*short_addr = (uint16_t)(((uint16_t)iid[6] << 8) | iid[7]);
	return 0;
}
