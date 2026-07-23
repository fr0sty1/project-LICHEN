/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ipv6_addr.h
 * @brief LICHEN IPv6 address utilities (spec sections 6.1, 6.2, 12)
 *
 * Standalone IPv6 address construction utilities:
 * - Link-local: fe80::<IID>
 * - Yggdrasil primary: 02xx::/64 from Ed25519 pubkey (spec 6.1)
 * - ULA/GUA for compatibility and prefix delegation
 *
 * IID derivation (spec 6.2):
 * - From EUI-64: flip the U/L bit per RFC 4291
 * - From Ed25519 pubkey: SHA-512/SHA-256 derived per Yggdrasil
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
 * struct in6_addr detection and fallback definition.
 *
 * Problem: struct in6_addr is defined by system headers (POSIX netinet/in.h,
 * Zephyr net_ip.h), but there is no universal guard macro. Duplicate
 * definitions cause compile errors; missing definitions also break the build.
 *
 * Detection cascade (checked in order, first match wins):
 *
 *   Priority  Check                         Action           When to use
 *   --------  ----------------------------  ---------------  -----------------------
 *   1         LICHEN_HAVE_IN6_ADDR=1        skip fallback    user override (unlisted
 *                                                            platforms, custom setup)
 *   2         IN6ADDR_ANY_INIT or           skip fallback    POSIX-compliant headers
 *             IN6ADDR_LOOPBACK_INIT                          (most reliable signal)
 *   3         CONFIG_NET_IPV6 + __ZEPHYR__  include net_ip.h Zephyr with IPv6 enabled
 *   4         Platform header guards:       skip fallback    system header included
 *             _NETINET_IN_H (Linux glibc)                    before this header
 *             _NETINET_IN_H_ (BSD/macOS)
 *             _NETINET6_IN6_H (FreeBSD)
 *             __NETINET_IN_H__ (some BSDs)
 *             ZEPHYR_INCLUDE_POSIX_...
 *             _STRUCT_IN6_ADDR (macOS)
 *   5         (none of the above)           define fallback  bare-metal, minimal env
 *
 * Note: _SYS_SOCKET_H (from <sys/socket.h>) was intentionally removed from
 * the detection list. Including <sys/socket.h> does NOT define struct in6_addr;
 * that struct is defined in <netinet/in.h>. Checking _SYS_SOCKET_H would cause
 * a false positive: skipping the fallback when in6_addr isn't actually defined.
 *
 * Fallback definition: struct in6_addr { uint8_t s6_addr[16]; }
 * This is wire-compatible with all known implementations.
 *
 * If you see "redefinition of struct in6_addr":
 *   - Include your system's netinet/in.h BEFORE this header, or
 *   - Define LICHEN_HAVE_IN6_ADDR=1 before including this header
 */
#if defined(LICHEN_HAVE_IN6_ADDR) && LICHEN_HAVE_IN6_ADDR
/* User explicitly says in6_addr is already defined */
#elif defined(IN6ADDR_ANY_INIT) || defined(IN6ADDR_LOOPBACK_INIT)
/* POSIX-compliant header already provides struct in6_addr */
#elif defined(CONFIG_NET_IPV6) && defined(__ZEPHYR__)
#include <zephyr/net/net_ip.h>
#elif defined(_NETINET_IN_H) || defined(_NETINET_IN_H_) || defined(_NETINET6_IN6_H) || \
      defined(__NETINET_IN_H__) || defined(ZEPHYR_INCLUDE_POSIX_NETINET_IN_H_) || \
      (defined(__APPLE__) && defined(_STRUCT_IN6_ADDR))
/* System header already provides struct in6_addr */
#else
/**
 * @brief IPv6 address structure (fallback definition)
 *
 * 128-bit IPv6 address. Compatible with Zephyr's struct in6_addr
 * and POSIX struct in6_addr.
 *
 * If this conflicts with your platform's struct in6_addr, define
 * LICHEN_HAVE_IN6_ADDR=1 before including this header.
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
 * SECURITY: Both buffers MUST be exactly 8 bytes. The pointer parameters
 * provide no compile-time bounds checking (C array decay). Passing smaller
 * buffers causes undefined behavior. Callers should declare:
 *   uint8_t eui64[8], iid[8];
 *
 * @param eui64 Input EUI-64 (8 bytes, not bounds-checked at runtime)
 * @param iid Output IID (8 bytes, not bounds-checked at runtime)
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
 * SECURITY: Buffer sizes are not bounds-checked at runtime (C array decay).
 * pubkey MUST be 32 bytes, iid MUST be 8 bytes. Passing smaller buffers
 * causes undefined behavior.
 *
 * @param pubkey Ed25519 public key (32 bytes, not bounds-checked at runtime)
 * @param iid Output IID (8 bytes, not bounds-checked at runtime)
 *
 * @return 0 on success, -EINVAL if NULL pointer
 */
int lichen_pubkey_to_iid(const uint8_t *pubkey, uint8_t *iid);

/**
 * @brief Derive 13-character human-readable Crockford base32 node address
 *
 * From SHA-256(Ed25519 pubkey) first 8 bytes, encoded with alphabet
 * 0123456789ABCDEFGHJKMNPQRSTVWXYZ, formatted as XXXX-XXXX-XXXXX.
 * Buffer must hold at least 16 bytes (15 chars + NUL).
 *
 * Matches Rust `human_address_from_pubkey` and test vectors exactly.
 * Used for UI, voice, logs, and LCI display (spec 03-addressing).
 *
 * @param pubkey 32-byte Ed25519 public key
 * @param buf Output buffer for formatted string (must be >=16 bytes)
 * @param buflen Size of buf
 *
 * @return 0 on success, -EINVAL on NULL or insufficient buffer
 */
int lichen_pubkey_to_human_address(const uint8_t *pubkey,
                                   char *buf, size_t buflen);

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
 * Note: Only fd00::/8 is accepted, not the full fc00::/7 ULA range.
 * Per RFC 4193, fc00::/8 (L=0) is reserved; only fd00::/8 (L=1) is
 * allocated for locally-assigned ULAs.
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
 * @brief Construct primary Yggdrasil address from Ed25519 pubkey
 *
 * Builds 02xx::/64 address per Yggdrasil spec (project-LICHEN-p8i6):
 * - byte 0 = 0x02
 * - bytes 1-7 = SHA-512(pubkey)[0:7]
 * - bytes 8-15 = IID from SHA-256(pubkey)[0:8] with U/L bit cleared
 * This is the primary mesh address.
 *
 * @param pubkey 32-byte Ed25519 public key
 * @param addr Output struct in6_addr for the Yggdrasil address
 * @return 0 on success, negative errno on error
 */
int lichen_yggdrasil_addr(const uint8_t pubkey[32], struct in6_addr *addr);

/**
 * @brief Format IPv6 address as string
 *
 * @param addr IPv6 address to format
 * @param buf Output buffer
 * @param buflen Buffer length (must be >= LICHEN_IPV6_ADDR_STR_LEN)
 *
 * @return 0 on success
 * @retval -EINVAL NULL pointer or buffer too small
 */
int lichen_ipv6_addr_to_str(const struct in6_addr *addr, char *buf, size_t buflen);

/**
 * @brief Derive link-local address from EUI-64 and log it
 *
 * Combines lichen_eui64_to_iid(), lichen_make_link_local(), and logging
 * into a single call. Logs at INFO level on success.
 *
 * @param eui64 Input EUI-64 (8 bytes)
 * @param ll_addr_out Output link-local address (may be NULL if caller doesn't need it).
 *                    On error, zeroed to prevent stale data; on success, filled.
 *
 * @return 0 on success, negative errno on failure
 */
int lichen_log_link_local_from_eui64(const uint8_t *eui64, struct in6_addr *ll_addr_out);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_IPV6_ADDR_H_ */
