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
 * fall back to fprintf(stderr) for host-side unit tests.
 *
 * Note: Host-side log output is best-effort for debugging. Production
 * (Zephyr) builds use proper logging levels. (project-LICHEN-tvfm.76)
 */
#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lichen_ipv6, LOG_LEVEL_INF);
#else
#define LOG_ERR(fmt, ...)  fprintf(stderr, "ERR: " fmt "\n", ##__VA_ARGS__)
#define LOG_WRN(fmt, ...)  fprintf(stderr, "WRN: " fmt "\n", ##__VA_ARGS__)
#define LOG_INF(fmt, ...)  ((void)0)  /* Suppress info in tests */
#define LOG_DBG(fmt, ...)  ((void)0)  /* Suppress debug in tests */
#endif

/* Ed25519 public key length - compile-time check */
#define LICHEN_ED25519_PUBKEY_LEN 32

/* U/L bit position in EUI-64 (bit 1 of first octet) */
#define UL_BIT 0x02

static const char hex_digits[] = "0123456789abcdef";

/* Link-local prefix: fe80::/10 */
static const uint8_t link_local_prefix[8] = {
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int lichen_eui64_to_iid(const uint8_t *eui64, uint8_t *iid)
{
    if (eui64 == NULL || iid == NULL) {
        LOG_ERR("eui64_to_iid failed (NULL input)");
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
    memmove(iid, eui64, 8);
    iid[0] ^= UL_BIT;
    return 0;
}

int lichen_pubkey_to_iid(const uint8_t *pubkey, uint8_t *iid)
{
    int ret;
    uint8_t hash[TC_SHA256_DIGEST_SIZE];

    if (pubkey == NULL || iid == NULL) {
        LOG_ERR("pubkey_to_iid failed (NULL input)");
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
        LOG_ERR("pubkey_to_iid failed (SHA-256 error %d)", ret);
        goto cleanup;
    }

    /*
     * SECURITY: Using first 64 bits of SHA-256 for IID derivation.
     * This is safe for identifier derivation (not key material) because:
     * 1. Birthday collision requires 2^32 attempts (4B devices) for 50% collision
     * 2. Preimage resistance remains at 2^64 (sufficient for device identity)
     *
     * Note: While inspired by RFC 7343 (ORCHID), this is NOT a compliant ORCHID.
     * ORCHIDs have additional structure (specific prefix, hash-index bits) that
     * we omit. Our derivation is simpler: SHA-256(pubkey) -> first 8 bytes ->
     * clear U/L bit. This is valid for LICHEN's internal IID generation.
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
        LOG_ERR("make_link_local failed (NULL input)");
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
        LOG_ERR("make_ula failed (NULL input)");
        return -EINVAL;
    }

    /*
     * Validate prefix is in fd00::/8 (locally-assigned ULA range).
     *
     * RFC 4193 ULA structure (fc00::/7):
     *   Bits 0-6:   1111110 (fc00::/7 prefix identifier)
     *   Bit 7:      L bit (1=local, 0=reserved for future central assignment)
     *   Bits 8-47:  40-bit Global ID (randomly generated per site)
     *   Bits 48-63: 16-bit Subnet ID (site-specific)
     *
     * The /8 prefix check means we validate all 8 bits of the first byte:
     *   0xfd = 11111101 = fc00::/7 prefix (1111110) + L=1 (locally assigned)
     *
     * We only accept fd00::/8 (L=1), not fc00::/8 (L=0) which is reserved.
     * The Global ID and Subnet ID (bytes 1-7) are site-specific and have
     * no format constraints beyond being randomly generated per RFC 4193.
     *
     * Global ID validation (project-LICHEN-tvfm.100):
     * We intentionally do NOT validate bytes 1-7 (the 40-bit Global ID + 16-bit
     * Subnet ID). RFC 4193 Section 3.2.2 recommends pseudo-random generation,
     * but "fd00:0000:0000::" (all-zeros Global ID) is technically valid. Using
     * a non-random Global ID risks collision with other sites using the same
     * simple prefix, but this is a deployment policy issue, not a protocol
     * violation. The caller (provisioning system or config) is responsible for
     * ensuring proper prefix selection.
     */
    if (prefix[0] != 0xfd) {
        LOG_ERR("make_ula failed (invalid prefix %02x, expected fd00::/8)", prefix[0]);
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
        LOG_ERR("make_gua failed (NULL input)");
        return -EINVAL;
    }

    /* Check prefix is in 2000::/3 (first 3 bits = 001) */
    if ((prefix[0] & 0xE0) != 0x20) {
        LOG_ERR("make_gua failed (invalid prefix %02x, expected 2000::/3)", prefix[0]);
        return -EINVAL;
    }

    memcpy(addr->s6_addr, prefix, 8);
    memcpy(&addr->s6_addr[8], iid, 8);
    return 0;
}

/*
 * IPv6 address string length: 8 groups * 4 hex chars + 7 colons = 39 chars + null.
 * Verify at compile time that our buffer constant is sufficient.
 *
 * For non-Zephyr builds (host tests), we use a portable compile-time assertion
 * that works with C99 and later. The negative-sized array typedef fails at
 * compile time if the condition is false.
 */
#ifdef __ZEPHYR__
BUILD_ASSERT(LICHEN_IPV6_ADDR_STR_LEN >= 40,
             "LICHEN_IPV6_ADDR_STR_LEN must hold 39-char IPv6 string plus null");
#else
typedef char _ipv6_addr_str_len_check[(LICHEN_IPV6_ADDR_STR_LEN >= 40) ? 1 : -1];
#endif

int lichen_ipv6_addr_to_str(const struct in6_addr *addr, char *buf, size_t buflen)
{
    if (addr == NULL || buf == NULL) {
        LOG_ERR("addr_to_str failed (NULL input)");
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
    size_t out = 0;
    for (size_t i = 0; i < sizeof(addr->s6_addr); i++) {
        uint8_t octet = addr->s6_addr[i];

        buf[out++] = hex_digits[octet >> 4];
        buf[out++] = hex_digits[octet & 0x0f];
        if ((i & 1U) != 0U && i != (sizeof(addr->s6_addr) - 1U)) {
            buf[out++] = ':';
        }
    }
    buf[out] = '\0';

    return 0;
}

int lichen_log_link_local_from_eui64(const uint8_t *eui64, struct in6_addr *ll_addr_out)
{
    int ret;
    uint8_t iid[8];
    struct in6_addr ll_addr;
    char addr_str[LICHEN_IPV6_ADDR_STR_LEN];

    if (eui64 == NULL) {
        LOG_ERR("log_link_local failed (NULL eui64)");
        if (ll_addr_out != NULL) {
            memset(ll_addr_out, 0, sizeof(*ll_addr_out));
        }
        return -EINVAL;
    }

    ret = lichen_eui64_to_iid(eui64, iid);
    if (ret < 0) {
        LOG_ERR("log_link_local failed (IID derivation error %d)", ret);
        if (ll_addr_out != NULL) {
            memset(ll_addr_out, 0, sizeof(*ll_addr_out));
        }
        return ret;
    }

    ret = lichen_make_link_local(iid, &ll_addr);
    if (ret < 0) {
        LOG_ERR("log_link_local failed (make_link_local error %d)", ret);
        if (ll_addr_out != NULL) {
            memset(ll_addr_out, 0, sizeof(*ll_addr_out));
        }
        return ret;
    }

    ret = lichen_ipv6_addr_to_str(&ll_addr, addr_str, sizeof(addr_str));
    if (ret < 0) {
        LOG_WRN("log_link_local warning (format error %d)", ret);
        /* Non-fatal - address is still valid, just can't log it */
    } else {
        LOG_INF("link-local %s", addr_str);
    }

    if (ll_addr_out != NULL) {
        memcpy(ll_addr_out, &ll_addr, sizeof(ll_addr));
    }

    return 0;
}
