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
 * - From EUI-64: flip the U/L bit per RFC 4291 (universal MAC -> local IID)
 * - From Ed25519 pubkey: first 8 bytes with U/L=0, G=0 (locally-administered unicast)
 *
 * This module does not depend on Zephyr's networking stack.
 */

#ifndef LICHEN_IPV6_ADDR_H_
#define LICHEN_IPV6_ADDR_H_

#include <stddef.h>
#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * struct in6_addr detection. Define LICHEN_HAVE_IN6_ADDR=1 before including
 * this header if your platform provides struct in6_addr but uses a guard
 * macro not listed here.
 *
 * Detection strategy (most portable first):
 * - LICHEN_HAVE_IN6_ADDR: user override for unlisted platforms
 * - IN6ADDR_ANY_INIT: defined by any POSIX-compliant header providing struct in6_addr
 * - Zephyr with CONFIG_NET_IPV6: use zephyr/net/net_ip.h
 * - POSIX header guards: various platforms use different guard names
 * - Otherwise: provide fallback definition
 */
#if defined(LICHEN_HAVE_IN6_ADDR) && LICHEN_HAVE_IN6_ADDR
/* User says in6_addr is already defined - trust them */
#elif defined(IN6ADDR_ANY_INIT)
/* System header already provides struct in6_addr */
#elif defined(CONFIG_NET_IPV6) && defined(__ZEPHYR__)
#include <zephyr/net/net_ip.h>
#elif defined(_NETINET_IN_H) || defined(_NETINET_IN_H_) || defined(_NETINET6_IN6_H) || \
      defined(__NETINET_IN_H__) || defined(ZEPHYR_INCLUDE_POSIX_NETINET_IN_H_)
/* System header already provides struct in6_addr */
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
 *
 * LICHEN uses uncompressed lowercase hex format:
 * "fe80:0000:0000:0000:1234:5678:abcd:ef01" (39 chars + null)
 *
 * This differs from RFC 5952 compressed form ("fe80::1234:5678:abcd:ef01").
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
 * Computes SHA-256(pubkey) and uses the first 8 bytes as the IID,
 * with U/L bit cleared to mark as locally-administered. This matches
 * RFC 7343 (ORCHID) approach and ensures interoperability with the
 * Python implementation in lichen/crypto/identity.py.
 *
 * SECURITY: Uses SHA-256 hash rather than raw pubkey bytes because
 * Ed25519 public keys have structure that could leak information.
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
 * @return 0 on success
 * @retval -EINVAL NULL pointer or buffer too small
 * @retval -ENOSPC Output was truncated (should not occur if buflen >= LICHEN_IPV6_ADDR_STR_LEN)
 * @retval -EIO snprintf encoding error
 */
int lichen_ipv6_addr_to_str(const struct in6_addr *addr, char *buf, size_t buflen);

/**
 * @brief Derive link-local address from EUI-64 and log it
 *
 * Combines lichen_eui64_to_iid(), lichen_make_link_local(), and logging
 * into a single call. Logs at INFO level on success.
 *
 * @param eui64 Input EUI-64 (8 bytes)
 * @param ll_addr_out Output link-local address (may be NULL if caller doesn't need it)
 *
 * @return 0 on success, negative errno on failure
 */
int lichen_log_link_local_from_eui64(const uint8_t *eui64, struct in6_addr *ll_addr_out);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_IPV6_ADDR_H_ */
