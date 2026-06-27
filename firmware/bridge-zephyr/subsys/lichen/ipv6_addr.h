/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ipv6_addr.h
 * @brief LICHEN IPv6 address utilities (spec sections 6.1, 6.2, 12)
 *
 * Standalone IPv6 address construction utilities:
 * - Link-local: fe80::<IID>
 * - ULA: fd00::/8 prefix + IID
 * - GUA: 2000::/3 prefix + IID
 *
 * IID derivation (spec 6.2):
 * - From EUI-64: flip the U/L bit (bit 1 of first octet)
 * - From Ed25519 pubkey: first 8 bytes with U/L bit set
 *
 * This module does not depend on Zephyr's networking stack.
 */

#ifndef LICHEN_IPV6_ADDR_H_
#define LICHEN_IPV6_ADDR_H_

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Use Zephyr's struct in6_addr when networking stack is available,
 * otherwise define our own compatible structure.
 */
#if defined(CONFIG_NET_IPV6) && defined(__ZEPHYR__)
#include <zephyr/net/net_ip.h>
#else
/**
 * @brief IPv6 address structure
 *
 * 128-bit IPv6 address. Compatible with Zephyr's struct in6_addr
 * and POSIX struct in6_addr.
 */
struct in6_addr {
    uint8_t s6_addr[16];
};
#endif

/**
 * @brief Buffer size for IPv6 address string (including null terminator)
 */
#define LICHEN_IPV6_ADDR_STR_LEN 40

/**
 * @brief Derive IID from EUI-64 by flipping U/L bit
 *
 * Per spec 6.2: IID = EUI-64 XOR 0x0200000000000000
 *
 * @param eui64 Input EUI-64 (8 bytes)
 * @param iid Output IID (8 bytes)
 *
 * @return 0 on success, -EINVAL if NULL pointer
 */
int lichen_eui64_to_iid(const uint8_t *eui64, uint8_t *iid);

/**
 * @brief Derive IID from Ed25519 public key
 *
 * Uses first 8 bytes of pubkey with locally-administered bit set.
 * This provides a cryptographically-derived address.
 *
 * @param pubkey Ed25519 public key (32 bytes)
 * @param iid Output IID (8 bytes)
 *
 * @return 0 on success, -EINVAL if NULL pointer
 */
int lichen_pubkey_to_iid(const uint8_t *pubkey, uint8_t *iid);

/**
 * @brief Construct link-local address from IID
 *
 * Builds fe80::<IID>
 *
 * @param iid Interface identifier (8 bytes)
 * @param addr Output IPv6 address
 *
 * @return 0 on success, -EINVAL if NULL pointer
 */
int lichen_make_link_local(const uint8_t *iid, struct in6_addr *addr);

/**
 * @brief Construct ULA address from prefix and IID
 *
 * Combines a fd00::/8 prefix with the IID.
 *
 * @param prefix 64-bit prefix (first 8 bytes, must be in fd00::/8)
 * @param iid Interface identifier (8 bytes)
 * @param addr Output IPv6 address
 *
 * @return 0 on success, -EINVAL if prefix not in fd00::/8
 */
int lichen_make_ula(const uint8_t *prefix, const uint8_t *iid,
                    struct in6_addr *addr);

/**
 * @brief Construct GUA address from prefix and IID
 *
 * Combines a 2000::/3 prefix with the IID.
 *
 * @param prefix 64-bit prefix (first 8 bytes, must be in 2000::/3)
 * @param iid Interface identifier (8 bytes)
 * @param addr Output IPv6 address
 *
 * @return 0 on success, -EINVAL if prefix not in 2000::/3
 */
int lichen_make_gua(const uint8_t *prefix, const uint8_t *iid,
                    struct in6_addr *addr);

/**
 * @brief Format IPv6 address as string
 *
 * @param addr IPv6 address to format
 * @param buf Output buffer
 * @param buflen Buffer length (must be >= LICHEN_IPV6_ADDR_STR_LEN)
 *
 * @return 0 on success, -EINVAL if NULL pointer
 */
int lichen_ipv6_addr_to_str(const struct in6_addr *addr, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_IPV6_ADDR_H_ */
