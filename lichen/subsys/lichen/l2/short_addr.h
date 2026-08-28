/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file short_addr.h
 * @brief RFC 6282 short-address interface identifier mapping
 */

#ifndef LICHEN_SHORT_ADDR_H_
#define LICHEN_SHORT_ADDR_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_SHORT_ADDR_IID_LEN 8U
#define LICHEN_SHORT_ADDR_RESERVED_NULL UINT16_C(0x0000)
#define LICHEN_SHORT_ADDR_RESERVED_UNSPECIFIED UINT16_C(0xfffe)
#define LICHEN_SHORT_ADDR_RESERVED_BROADCAST UINT16_C(0xffff)

/** Return whether a short address is reserved rather than peer-addressable. */
bool lichen_short_addr_is_reserved(uint16_t short_addr);

/**
 * Map a 16-bit short address to the RFC 6282 interface identifier
 * ``0000:00ff:fe00:XXXX``. The final two bytes use network byte order.
 *
 * This mechanical mapping is defined for every uint16_t, including reserved
 * values. Call lichen_short_addr_is_reserved() before using an address for a
 * unicast peer.
 *
 * @param short_addr Short address to encode
 * @param iid Output buffer of at least LICHEN_SHORT_ADDR_IID_LEN bytes
 * @return 0 on success, -EINVAL if iid is NULL
 */
int lichen_short_addr_to_iid(uint16_t short_addr, uint8_t *iid);

/**
 * Parse a canonical RFC 6282 short-address IID.
 *
 * Reserved short addresses are returned intact so callers can distinguish a
 * malformed IID from a well-formed non-unicast value.
 *
 * @param iid Input buffer of exactly LICHEN_SHORT_ADDR_IID_LEN bytes
 * @param short_addr Output short address
 * @return 0 on success, -EINVAL for NULL or a non-canonical prefix
 */
int lichen_short_addr_from_iid(const uint8_t *iid, uint16_t *short_addr);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SHORT_ADDR_H_ */
