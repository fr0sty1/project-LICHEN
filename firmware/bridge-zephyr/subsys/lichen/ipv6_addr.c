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

LOG_MODULE_REGISTER(lichen_ipv6, LOG_LEVEL_INF);

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
    if (pubkey == NULL || iid == NULL) {
        LOG_ERR("pubkey_to_iid: NULL pointer");
        return -EINVAL;
    }

    /* Use first 8 bytes of pubkey */
    memcpy(iid, pubkey, 8);

    /* Set locally administered bit, clear multicast bit */
    iid[0] = (iid[0] | UL_BIT) & 0xFE;
    return 0;
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

    /* Handle truncation or error */
    if (ret < 0 || (size_t)ret >= buflen) {
        LOG_WRN("IPv6 addr format truncated or failed");
        if (buflen > 0) {
            buf[buflen - 1] = '\0';
        }
    }
    return 0;
}
