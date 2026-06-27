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
#include <zephyr/logging/log.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>

LOG_MODULE_REGISTER(lichen_ipv6, LOG_LEVEL_INF);

/* Ed25519 public key length - compile-time check */
#define LICHEN_ED25519_PUBKEY_LEN 32

/*
 * SECURITY: Secure memset that won't be optimized away.
 * Standard memset() on dead buffers can be removed by the compiler.
 * The volatile pointer forces each store to actually execute.
 */
static inline void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = ptr;
    while (len--) {
        *p++ = 0;
    }
}

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

    /* Copy and flip U/L bit per spec 6.2 */
    memcpy(iid, eui64, 8);
    iid[0] ^= UL_BIT;
    return 0;
}

int lichen_pubkey_to_iid(const uint8_t *pubkey, uint8_t *iid)
{
    int ret = 0;
    struct tc_sha256_state_struct sha_state;
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
    if (tc_sha256_init(&sha_state) != TC_CRYPTO_SUCCESS) {
        LOG_ERR("pubkey_to_iid: SHA-256 init failed");
        ret = -EIO;
        goto cleanup;
    }
    if (tc_sha256_update(&sha_state, pubkey, LICHEN_ED25519_PUBKEY_LEN) != TC_CRYPTO_SUCCESS) {
        LOG_ERR("pubkey_to_iid: SHA-256 update failed");
        ret = -EIO;
        goto cleanup;
    }
    if (tc_sha256_final(hash, &sha_state) != TC_CRYPTO_SUCCESS) {
        LOG_ERR("pubkey_to_iid: SHA-256 final failed");
        ret = -EIO;
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
     * For pubkey-derived IIDs, mark as locally-administered (U/L=0)
     * since they are not globally-unique MAC addresses. The Python
     * implementation also clears only the U/L bit (bit 1).
     */
    iid[0] &= ~UL_BIT;  /* Clear U/L bit */

cleanup:
    /* SECURITY: Zero all crypto state on all paths (success and error) */
    secure_zero(&sha_state, sizeof(sha_state));
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

    /* Simple IPv6 formatting (not compressed) */
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

    /* Handle truncation (ret is chars that WOULD have been written, excl. null) */
    if ((size_t)ret >= buflen) {
        LOG_ERR("IPv6 addr truncated");
        return -ENOSPC;
    }

    return 0;
}
