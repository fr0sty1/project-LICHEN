/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ipv6_addr.h
 * @brief LICHEN IPv6 address utilities (spec sections 6.1, 6.2, 12)
 *
 * Standalone IPv6 address construction utilities:
 * - Link-local: fe80::<IID>
 * - Native primary: key-derived 0200::/8 address (/128 per node)
 * - ULA/GUA for compatibility and prefix delegation
 *
 * IID derivation (spec 6.2):
 * - From EUI-64: flip the U/L bit per RFC 4291
 * - From Ed25519 pubkey: SHA-512 derived per the LICHEN native profile
 *
 * This module does not depend on Zephyr's networking stack.
 */

#ifndef LICHEN_IPV6_ADDR_H_
#define LICHEN_IPV6_ADDR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * struct in6_addr provisioning.
 *
 * Problem: struct in6_addr is defined by system headers (POSIX
 * netinet/in.h, Zephyr net_ip.h), but there is no universal guard macro
 * to detect it (glibc, musl, bionic, newlib, and the BSDs all use
 * different guards). Guessing guards breaks silently on unlisted libc's.
 *
 * Strategy (checked in order, first match wins): INCLUDE the platform
 * header instead of trying to detect it.
 *
 *   1  LICHEN_HAVE_IN6_ADDR=1     user override: the platform already
 *                                 provides struct in6_addr through some
 *                                 header this cascade cannot know about
 *                                 (custom bare-metal setups).
 *   2  __ZEPHYR__                 include <zephyr/net/net_ip.h>, which
 *                                 defines struct in6_addr unconditionally
 *                                 (independent of CONFIG_NET_IPV6).
 *   3  __has_include(<netinet/in.h>)  include <netinet/in.h>. The system
 *                                 header's own include guard makes this a
 *                                 no-op when it was already included, and
 *                                 makes later user includes no-ops too, so
 *                                 redefinition is impossible in either
 *                                 inclusion order.
 *   4  (none of the above)        define the fallback below. Reached only
 *                                 when neither Zephyr nor a POSIX libc is
 *                                 present, i.e. no other struct in6_addr
 *                                 definition exists in the build.
 *
 * Fallback definition: struct in6_addr { uint8_t s6_addr[16]; }
 * Wire- and layout-compatible with POSIX and Zephyr; this module only
 * touches the s6_addr member.
 */
#if defined(LICHEN_HAVE_IN6_ADDR) && LICHEN_HAVE_IN6_ADDR
/* User override: trust that the platform defines struct in6_addr. */
#elif defined(__ZEPHYR__)
#include <zephyr/net/net_ip.h>
#elif defined(__has_include)
#if __has_include(<netinet/in.h>)
#include <netinet/in.h>
#else
#define LICHEN_IPV6_ADDR_NEEDS_IN6_FALLBACK 1
#endif
#else
/* Compiler without __has_include and without Zephyr: bare-metal. */
#define LICHEN_IPV6_ADDR_NEEDS_IN6_FALLBACK 1
#endif

#if defined(LICHEN_IPV6_ADDR_NEEDS_IN6_FALLBACK) && \
    LICHEN_IPV6_ADDR_NEEDS_IN6_FALLBACK
/**
 * @brief IPv6 address structure (bare-metal fallback definition)
 *
 * 128-bit IPv6 address. Layout-compatible with Zephyr's struct in6_addr
 * and POSIX struct in6_addr; only s6_addr is used by this module.
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
 * @brief LICHEN CRC32 initial value for short address derivation (spec 12.3)
 *
 * Low 32 bits of ASCII "LICHEN" (0x4C 0x49 0x43 0x48 0x45 0x4E) = 0x4348454E.
 * This is intentionally different from the FNV-1a hash used for channel,
 * slot, and spreading-factor selection.
 */
#define LICHEN_CRC32_INITIAL 0x4348454Eu

/**
 * @brief Derive 16-bit short address from EUI-64 (spec 12.3)
 *
 * Uses CRC32-IEEE/ISO-HDLC with LICHEN_CRC32_INITIAL as the initial value.
 * Returns the low 16 bits of the CRC32 result. Reserved-address handling
 * belongs to Duplicate Address Detection (DAD), which can retry with a seed.
 *
 * SECURITY: eui64 MUST be exactly 8 bytes. No bounds checking at runtime.
 *
 * @param eui64 Input EUI-64 (8 bytes)
 * @return 16-bit short address (low 16 bits of CRC32)
 */
uint16_t lichen_derive_short_addr(const uint8_t *eui64);

/**
 * @brief Derive 16-bit short address with DAD retry seed (spec 12.3)
 *
 * Mixes the seed into the EUI-64 before CRC32 derivation. The seed bytes
 * (little-endian) are XORed into EUI-64 bytes 4 through 7 before applying
 * the same CRC32 derivation as lichen_derive_short_addr().
 *
 * SECURITY: eui64 MUST be exactly 8 bytes. No bounds checking at runtime.
 *
 * @param eui64 Input EUI-64 (8 bytes)
 * @param seed DAD retry seed (0 = no mixing, same as derive_short_addr)
 * @return 16-bit short address
 */
uint16_t lichen_derive_short_addr_with_seed(const uint8_t *eui64, uint32_t seed);

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
 * Computes SHA-512(pubkey) and uses the first 8 bytes as the IID,
 * with the U/L bit cleared to mark it as locally administered. This is
 * the IID embedded in the canonical 0200::/8 native address and matches
 * the Python and Rust implementations plus yggdrasil-derivation vectors.
 *
 * SECURITY: Uses SHA-512 rather than raw pubkey bytes because
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
 * @brief Check if IPv6 address is in mesh address space
 *
 * SECURITY: Validates that the target address is within the LICHEN mesh
 * address space. Used by forward proxy to prevent SSRF attacks by ensuring
 * only mesh-reachable addresses are accepted.
 *
 * Mesh address space:
 * - Native 0200::/8: key-derived primary node addresses
 * - Link-local fe80::/10: Direct neighbor addresses
 *
 * Non-mesh addresses rejected (SSRF prevention):
 * - Global unicast 2000::/3: Internet-routable addresses
 * - Loopback ::1: Host-local only
 * - IPv4-mapped ::ffff:0:0/96: IPv4 addresses
 * - Other special-use prefixes
 *
 * @param addr IPv6 address to validate
 * @return true if address is in mesh space, false otherwise (or if NULL)
 */
bool lichen_is_mesh_addr(const struct in6_addr *addr);

/** IPv6 multicast scope values used by the LICHEN profile (RFC 4291). */
enum lichen_ipv6_multicast_scope {
    LICHEN_IPV6_SCOPE_RESERVED_0 = 0,
    LICHEN_IPV6_SCOPE_INTERFACE_LOCAL = 1,
    LICHEN_IPV6_SCOPE_LINK_LOCAL = 2,
    LICHEN_IPV6_SCOPE_MESH_LOCAL = 3,
    LICHEN_IPV6_SCOPE_SITE_LOCAL = 5,
    LICHEN_IPV6_SCOPE_GLOBAL = 14,
    LICHEN_IPV6_SCOPE_RESERVED_15 = 15,
};

/**
 * @brief Extract the raw four-bit scope from an IPv6 multicast address.
 *
 * Flags in the high nibble of the second octet do not affect scope
 * extraction. Reserved scopes 0 and 15 are returned to let callers diagnose
 * malformed traffic; use lichen_ipv6_multicast_scope_is_transmittable() to
 * apply the LICHEN over-air validity rule.
 *
 * @param addr IPv6 address to inspect
 * @param scope Output scope value in the range 0..15
 * @return 0 on success, -EINVAL for NULL, -ENODATA for a unicast address
 */
int lichen_ipv6_multicast_scope(const struct in6_addr *addr, uint8_t *scope);

/**
 * @brief Check whether a multicast scope may be transmitted on LICHEN.
 *
 * Per spec/03-adaptation.md, scopes 2 through 14 are valid. Interface-local
 * scope 1 and reserved scopes 0 and 15 are not valid over the link.
 */
bool lichen_ipv6_multicast_scope_is_transmittable(uint8_t scope);

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
 * Implements the exact `AddrForKey` algorithm from yggdrasil-go
 * (`src/address/address.go`), matching the official Yggdrasil daemon
 * bit-for-bit:
 *   1. Compute `h = SHA-512(pubkey)`
 *   2. `addr = [0x02] || h[0:7] || h[0:8]`
 *   3. Clear U/L bit in IID byte: `addr[8] &= 0xfd`
 *
 * The exact 0200::/8 prefix byte (`0x02`) identifies the native profile.
 * Bytes 1-7 (from `h[0:7]`) provide routing dispersion within that prefix.
 * Bytes 8-15 (from `h[0:8]`) form the IID, binding the address to the pubkey.
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
