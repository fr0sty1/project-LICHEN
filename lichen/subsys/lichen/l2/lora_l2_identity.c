/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lora_l2_identity.c
 * @brief LICHEN LoRa L2 EUI-64 identity generation
 *
 * Generates stable EUI-64 addresses from hardware device ID using SHA-256 hashing.
 */

#include "lora_l2_internal.h"
#include "lichen_util.h"

#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/drivers/hwinfo.h>
#include <lichen/hal.h>
#include <tinycrypt/sha256.h>

LOG_MODULE_DECLARE(lichen_lora_l2, CONFIG_LICHEN_LORA_L2_LOG_LEVEL);

/*
 * SECURITY: Domain separation prefix for EUI-64 derivation.
 * This ensures SHA-256(prefix || hwid) produces different output than
 * other uses of SHA-256 on the same hwid (e.g., key derivation).
 * The prefix is a fixed ASCII string with no trailing NUL in the hash input.
 */
#define EUI64_DOMAIN_PREFIX "LICHEN-EUI64-v1"
#define EUI64_DOMAIN_PREFIX_LEN (sizeof(EUI64_DOMAIN_PREFIX) - 1)
#define LICHEN_HWID_MAX_LEN 32U
#define LICHEN_EXPECTED_MAX_HWID_LEN 16U

BUILD_ASSERT(LICHEN_HWID_MAX_LEN >= LICHEN_EXPECTED_MAX_HWID_LEN,
             "hardware ID buffer must cover supported MCU IDs");

/**
 * @brief Generate stable EUI-64 from hardware device ID
 *
 * Hashes the full hardware ID using SHA-256 to produce a collision-resistant
 * EUI-64. This avoids issues with MCU-specific hwid layouts:
 * - STM32: 12-byte UID where bytes 0-3 are lot/wafer (shared across chips)
 * - ESP32: 6-byte MAC (would leave 2 bytes unfilled)
 * - nRF52: 8-byte unique ID
 *
 * By hashing the full hwid, we mix all available entropy bits uniformly.
 * Returns error if no stable identity is available - a mesh network node
 * must not start with an unstable EUI-64 that changes on each reboot.
 *
 * SECURITY: EUI-64 is derived from hardware ID only, NOT cryptographically
 * bound to the node's Ed25519 identity keypair. This is an architectural
 * limitation with the following implications:
 * - EUI-64 provides device identification, not authentication
 * - An attacker with a victim's private key can sign frames with any EUI-64
 * - The Ed25519 public key (verified via Schnorr signature) is the true
 *   cryptographic identity - EUI-64 is just a stable routing identifier
 * - Frame authenticity depends on signature verification, not EUI-64 matching
 *
 * Future work: LICHEN spec section 6.2 suggests deriving IID from Ed25519
 * public key. This would cryptographically bind EUI-64 to the keypair,
 * but requires keypair provisioning before network initialization.
 *
 * @param eui64 Output buffer for 8-byte EUI-64
 * @return 0 on success, negative errno on failure
 */
int generate_eui64(uint8_t *eui64)
{
    if (eui64 == NULL) {
        return -EINVAL;
    }
    int ret = 0;
    uint8_t hwid[LICHEN_HWID_MAX_LEN];
    ssize_t hwid_len;
    uint8_t hash[TC_SHA256_DIGEST_SIZE];
    uint8_t hash_input[EUI64_DOMAIN_PREFIX_LEN + sizeof(hwid)];
    BUILD_ASSERT(sizeof(hwid) == LICHEN_HWID_MAX_LEN,
                 "hwid buffer must match declared max hardware ID length");
    BUILD_ASSERT(sizeof(hash_input) == EUI64_DOMAIN_PREFIX_LEN + LICHEN_HWID_MAX_LEN,
                 "hash_input must cover domain prefix plus max hardware ID");

    hwid_len = hwinfo_get_device_id(hwid, sizeof(hwid));
    if (hwid_len < 0) {
        if (lichen_hal_synthetic_device_identity_allowed()) {
            /*
             * Simulation builds may not have a hardware identity provider. Use
             * a HAL-owned deterministic identity so CI can exercise the L2
             * path. Hardware builds still refuse to start without stable
             * device identity.
             */
            ret = lichen_hal_synthetic_device_identity_get(hwid, sizeof(hwid));
            if (ret < 0) {
                LOG_ERR("lora_l2: synthetic hardware ID failed (%d)", ret);
                goto cleanup;
            }
            hwid_len = ret;
            LOG_WRN("lora_l2: using synthetic hardware ID");
        } else {
            /*
             * SECURITY: Refusing to start without stable identity. A random EUI-64
             * would change on each reboot, breaking IPv6 NDP and mesh routing.
             */
            LOG_ERR("lora_l2: hwinfo_get_device_id failed (%ld)", (long)hwid_len);
            /* Cast safe: hwinfo errors are negative errno (-E*), always fit in int */
            ret = (int)hwid_len;
            goto cleanup;
        }
    }
    if (hwid_len == 0) {
        /* SECURITY: Zero-length hwid means no unique identity available */
        LOG_ERR("lora_l2: no hardware ID available, cannot generate stable EUI-64");
        ret = -ENODEV;
        goto cleanup;
    }
    /* DEFENSE-IN-DEPTH: This check is after hwinfo_get_device_id() already wrote
     * to hwid[]. The real protection is sizeof(hwid) passed as the buffer limit
     * to that call. If the driver returns len > sizeof(hwid), the buffer was
     * already overflown - this check catches the inconsistency defensively. */
    if ((size_t)hwid_len > sizeof(hwid)) {
        LOG_ERR("lora_l2: hwinfo returned invalid length (%ld)", (long)hwid_len);
        ret = -EINVAL;
        goto cleanup;
    }
    const size_t checked_hwid_len = (size_t)hwid_len;

    /* SECURITY: Reject all-zeros hwid which would cause EUI-64 collisions.
     * Some MCUs return zeros when fuses aren't programmed or in debug mode. */
    uint8_t nonzero = 0;
    for (ssize_t i = 0; i < hwid_len; i++) {
        nonzero |= hwid[i];
    }
    if (nonzero == 0) {
        LOG_ERR("lora_l2: hardware ID is all zeros, cannot generate unique EUI-64");
        ret = -EINVAL;
        goto cleanup;
    }

    /*
     * Hash prefix || hwid to derive EUI-64 with domain separation.
     * SECURITY: SHA-256 provides collision resistance - two different
     * hwids will produce different EUI-64s with overwhelming probability.
     * The domain prefix ensures this derivation is independent of other
     * SHA-256 uses (e.g., ipv6_addr.c:pubkey_to_iid uses different input).
     */
    memcpy(hash_input, EUI64_DOMAIN_PREFIX, EUI64_DOMAIN_PREFIX_LEN);
    memcpy(hash_input + EUI64_DOMAIN_PREFIX_LEN, hwid, checked_hwid_len);
    ret = lichen_sha256(hash_input, EUI64_DOMAIN_PREFIX_LEN + checked_hwid_len, hash, sizeof(hash));
    if (ret != 0) {
        LOG_ERR("lora_l2: EUI-64 SHA-256 failed");
        goto cleanup;
    }

    /*
     * SECURITY: Using first 64 bits of SHA-256 for EUI-64 derivation.
     * This is safe for identifier derivation (not key material) because:
     * 1. Birthday collision requires 2^32 attempts (4B devices) for 50% collision
     * 2. Preimage resistance remains at 2^64 (sufficient for device identity)
     * 3. Matches RFC 7343 (ORCHID) approach for cryptographic identifiers
     */
    memcpy(eui64, hash, 8);
    LOG_DBG("lora_l2: EUI-64 from hashed hardware ID (%ld bytes)", (long)hwid_len);

    /*
     * IEEE 802 EUI-64 first octet bit definitions (LSB numbering):
     *   Bit 0 (0x01): Individual/Group (I/G) - 0=unicast, 1=multicast
     *   Bit 1 (0x02): Universal/Local (U/L)  - 0=universally administered (OUI),
     *                                          1=locally administered
     *
     * We set U/L=1 because this EUI-64 is derived from device hardware ID,
     * not from an IEEE-assigned OUI. We clear I/G=0 to mark this as a unicast
     * address (individual device, not a multicast group).
     *
     * Reference: IEEE 802-2014 section 8.2, IEEE Guidelines for EUI-64.
     */
    eui64[0] = (eui64[0] | 0x02) & 0xFE;  /* Set U/L bit, clear I/G bit */

    LOG_DBG("lora_l2: EUI-64 %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            eui64[0], eui64[1], eui64[2], eui64[3],
            eui64[4], eui64[5], eui64[6], eui64[7]);

cleanup:
    /* SECURITY: Zero intermediate buffers and output on all error paths.
     * Defense-in-depth: ensure caller never sees undefined eui64 on failure,
     * even though callers should check return value. */
    secure_zero(hwid, sizeof(hwid));
    secure_zero(hash_input, sizeof(hash_input));
    secure_zero(hash, sizeof(hash));
    if (ret != 0) {
        secure_zero(eui64, 8);
    }
    return ret;
}

int lichen_lora_l2_copy_eui64(uint8_t out[8])
{
    enum lora_state state;
    int ret = 0;

    if (out == NULL) {
        return -EINVAL;
    }

    k_mutex_lock(&lora_mutex, K_FOREVER);
    state = lora_get_state();
    switch (state) {
    case LORA_STOPPED:
    case LORA_RUNNING:
        memcpy(out, lora_data.eui64, sizeof(lora_data.eui64));
        break;
    case LORA_UNINIT:
        LOG_ERR("lora_l2: not initialized");
        ret = -ENODEV;
        break;
    case LORA_ABORTED:
        LOG_ERR("lora_l2: EUI-64 unavailable until reinit after abort");
        ret = -ECANCELED;
        break;
    case LORA_DEINITING:
        LOG_ERR("lora_l2: EUI-64 unavailable during deinit");
        ret = -EBUSY;
        break;
    default:
        LOG_ERR("lora_l2: invalid state while copying EUI-64 (%d)", state);
        ret = -EINVAL;
        break;
    }
    k_mutex_unlock(&lora_mutex);
    return ret;
}

/*
 * Compatibility API: returns an alias to internal eui64 storage after a
 * mutex-protected state check. New callers should use copy_eui64() instead.
 *
 * Thread safety contract (caller responsibility):
 * - No mutex is held after return; concurrent deinit() can zero the backing memory
 * - Caller must prevent concurrent deinit() while using the pointer
 */
const uint8_t *lichen_lora_l2_get_eui64(void)
{
    const uint8_t *eui64 = NULL;
    enum lora_state state;

    k_mutex_lock(&lora_mutex, K_FOREVER);
    state = lora_get_state();
    if (state == LORA_STOPPED || state == LORA_RUNNING) {
        eui64 = lora_data.eui64;
    } else if (state == LORA_UNINIT) {
        LOG_ERR("lora_l2: not initialized");
    } else {
        LOG_ERR("lora_l2: EUI-64 unavailable in state %d", state);
    }
    k_mutex_unlock(&lora_mutex);

    return eui64;
}
