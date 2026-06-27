/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ipv6_addr.c
 * @brief LICHEN IPv6 address utilities implementation
 *
 * This module provides standalone IPv6 address construction utilities.
 * It does not depend on Zephyr's networking stack - just basic address
 * manipulation functions.
 */

#include "ipv6_addr.h"

#include <stdio.h>
#include <string.h>

#include "lichen_util.h"

/*
 * Logging abstraction: use Zephyr logging when available, otherwise
 * fall back to no-ops. This allows the module to be used in host-side
 * unit tests without stubbing the logging system.
 */
#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lichen_ipv6, LOG_LEVEL_INF);
#else
#define LOG_ERR(...)  ((void)0)
#define LOG_WRN(...)  ((void)0)
#define LOG_INF(...)  ((void)0)
#define LOG_DBG(...)  ((void)0)
#endif

/* Ed25519 public key length - compile-time check */
#define LICHEN_ED25519_PUBKEY_LEN 32

/* U/L bit position in EUI-64 (bit 1 of first octet) */
#define UL_BIT 0x02

/* Link-local prefix: fe80::/10 */
static const uint8_t link_local_prefix[8] = {
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int lichen_eui64_to_iid(const uint8_t *eui64, uint8_t *iid)
{
    if (eui64 == NULL || iid == NULL) {
        LOG_ERR("eui64_to_iid: NULL pointer");
        return -EINVAL;
    }

    /*
     * Copy and flip U/L bit per RFC 4291 and LICHEN spec 6.2.
     *
     * EUI-64 derived IIDs: XOR (flip) U/L bit because the source is a
     * universally-administered MAC address. RFC 4291 requires inverting
     * the U/L bit when embedding a universal identifier into an IID so
     * that locally-assigned IIDs can use the natural U/L=0 value.
     *
     * Compare with lichen_pubkey_to_iid() which clears U/L rather than
     * flipping it, because pubkey-derived IIDs are not derived from a
     * universally-administered identifier (they are synthetic).
     */
    memcpy(iid, eui64, 8);
    iid[0] ^= UL_BIT;
    return 0;
}

int lichen_pubkey_to_iid(const uint8_t *pubkey, uint8_t *iid)
{
    int ret;
    uint8_t hash[TC_SHA256_DIGEST_SIZE];

    if (pubkey == NULL || iid == NULL) {
        LOG_ERR("pubkey_to_iid: NULL pointer");
        return -EINVAL;
    }

    /*
     * SECURITY: Use SHA-256 hash of pubkey rather than raw bytes.
     * Raw Ed25519 public key bytes have structure that could leak
     * information. This matches RFC 7343 (ORCHID) approach and the
     * Python implementation in lichen/crypto/identity.py.
     */
    ret = lichen_sha256(pubkey, LICHEN_ED25519_PUBKEY_LEN, hash);
    if (ret != 0) {
        LOG_ERR("pubkey_to_iid: SHA-256 failed");
        goto cleanup;
    }

    /*
     * SECURITY: Using first 64 bits of SHA-256 for IID derivation.
     * This is safe for identifier derivation (not key material) because:
     * 1. Birthday collision requires 2^32 attempts (4B devices) for 50% collision
     * 2. Preimage resistance remains at 2^64 (sufficient for device identity)
     * 3. Matches RFC 7343 (ORCHID) approach for cryptographic identifiers
     */
    memcpy(iid, hash, 8);

    /*
     * IID semantics (RFC 4291 section 2.5.1):
     * - Bit 1 (U/L): 0=local, 1=universal
     *
     * For pubkey-derived IIDs, clear U/L bit to mark as locally-administered
     * since they are not derived from a universally-administered MAC address.
     *
     * This differs from lichen_eui64_to_iid() which flips (XORs) the U/L bit.
     * The reason: EUI-64 starts with a universal MAC (U/L=1), so RFC 4291
     * requires flipping it. Pubkey-derived IIDs start from hash output with
     * no inherent U/L semantics, so we simply clear the bit to indicate
     * "locally-administered" status. The Python implementation in
     * lichen/crypto/identity.py uses the same approach (clear, not flip).
     */
    iid[0] &= ~UL_BIT;  /* Clear U/L bit */

cleanup:
    /* SECURITY: Zero hash on all paths (sha_state zeroed by helper) */
    secure_zero(hash, sizeof(hash));
    return ret;
}

int lichen_make_link_local(const uint8_t *iid, struct in6_addr *addr)
{
    if (iid == NULL || addr == NULL) {
        LOG_ERR("make_link_local: NULL pointer");
        return -EINVAL;
    }

    /* fe80::0000:0000:0000:0000 + IID */
    memcpy(addr->s6_addr, link_local_prefix, 8);
    memcpy(&addr->s6_addr[8], iid, 8);
    return 0;
}

int lichen_make_ula(const uint8_t *prefix, const uint8_t *iid,
                    struct in6_addr *addr)
{
    if (prefix == NULL || iid == NULL || addr == NULL) {
        LOG_ERR("make_ula: NULL pointer");
        return -EINVAL;
    }

    /* Check prefix is in fd00::/8 */
    if (prefix[0] != 0xfd) {
        LOG_ERR("ULA prefix must be in fd00::/8, got %02x", prefix[0]);
        return -EINVAL;
    }

    memcpy(addr->s6_addr, prefix, 8);
    memcpy(&addr->s6_addr[8], iid, 8);
    return 0;
}

int lichen_make_gua(const uint8_t *prefix, const uint8_t *iid,
                    struct in6_addr *addr)
{
    if (prefix == NULL || iid == NULL || addr == NULL) {
        LOG_ERR("make_gua: NULL pointer");
        return -EINVAL;
    }

    /* Check prefix is in 2000::/3 (first 3 bits = 001) */
    if ((prefix[0] & 0xE0) != 0x20) {
        LOG_ERR("GUA prefix must be in 2000::/3, got %02x", prefix[0]);
        return -EINVAL;
    }

    memcpy(addr->s6_addr, prefix, 8);
    memcpy(&addr->s6_addr[8], iid, 8);
    return 0;
}

/*
 * IPv6 address string length: 8 groups * 4 hex chars + 7 colons = 39 chars + null.
 * Verify at compile time that our buffer constant is sufficient.
 */
#ifdef __ZEPHYR__
BUILD_ASSERT(LICHEN_IPV6_ADDR_STR_LEN >= 40,
             "LICHEN_IPV6_ADDR_STR_LEN must hold 39-char IPv6 string plus null");
#else
_Static_assert(LICHEN_IPV6_ADDR_STR_LEN >= 40,
               "LICHEN_IPV6_ADDR_STR_LEN must hold 39-char IPv6 string plus null");
#endif

int lichen_ipv6_addr_to_str(const struct in6_addr *addr, char *buf, size_t buflen)
{
    if (addr == NULL || buf == NULL) {
        LOG_ERR("ipv6_addr_to_str: NULL pointer");
        return -EINVAL;
    }

    if (buflen < LICHEN_IPV6_ADDR_STR_LEN) {
        if (buflen > 0) {
            buf[0] = '\0';
        }
        return -EINVAL;
    }

    /*
     * Uncompressed format chosen over RFC 5952 compressed form for:
     * 1. Deterministic output (same address always produces same string)
     * 2. Simpler parsing (no :: expansion needed by consumers)
     * 3. Consistent log line lengths for alignment
     */
    int ret = snprintf(buf, buflen,
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             addr->s6_addr[0], addr->s6_addr[1],
             addr->s6_addr[2], addr->s6_addr[3],
             addr->s6_addr[4], addr->s6_addr[5],
             addr->s6_addr[6], addr->s6_addr[7],
             addr->s6_addr[8], addr->s6_addr[9],
             addr->s6_addr[10], addr->s6_addr[11],
             addr->s6_addr[12], addr->s6_addr[13],
             addr->s6_addr[14], addr->s6_addr[15]);

    /* Handle snprintf error (encoding failure, rare) */
    if (ret < 0) {
        LOG_ERR("IPv6 addr format failed");
        if (buflen > 0) {
            buf[0] = '\0';
        }
        return -EIO;
    }

    /* Check for truncation (defensive - buflen check above should prevent this) */
    if ((size_t)ret >= buflen) {
        LOG_ERR("IPv6 addr format truncated");
        return -EINVAL;
    }

    return 0;
}

int lichen_log_link_local_from_eui64(const uint8_t *eui64, struct in6_addr *ll_addr_out)
{
    int ret;
    uint8_t iid[8];
    struct in6_addr ll_addr;
    char addr_str[LICHEN_IPV6_ADDR_STR_LEN];

    if (eui64 == NULL) {
        LOG_ERR("log_link_local: NULL eui64");
        return -EINVAL;
    }

    ret = lichen_eui64_to_iid(eui64, iid);
    if (ret < 0) {
        LOG_ERR("Failed to derive IID from EUI-64: %d", ret);
        return ret;
    }

    ret = lichen_make_link_local(iid, &ll_addr);
    if (ret < 0) {
        LOG_ERR("Failed to make link-local address: %d", ret);
        return ret;
    }

    ret = lichen_ipv6_addr_to_str(&ll_addr, addr_str, sizeof(addr_str));
    if (ret < 0) {
        LOG_WRN("Failed to format link-local address: %d", ret);
        /* Non-fatal - address is still valid, just can't log it */
    } else {
        LOG_INF("Link-local: %s", addr_str);
    }

    if (ll_addr_out != NULL) {
        memcpy(ll_addr_out, &ll_addr, sizeof(ll_addr));
    }

    return 0;
}
