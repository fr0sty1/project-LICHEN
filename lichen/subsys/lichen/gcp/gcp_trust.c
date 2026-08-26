/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file gcp_trust.c
 * @brief GCP-3 Trust Models implementation per spec/08-gateway-coordination.md
 *
 * Dual-mode federation support for Zephyr border routers:
 * - Closed federation: PSK-based (handled by OSCORE layer)
 * - Open federation: Ed25519 + Schnorr-48 + TOFU
 *
 * Test vectors: test/vectors/gcp3_trust_models.json
 * Python oracle: python/src/lichen/crypto/trust.py
 */

#include <lichen/gcp_trust.h>
#include <string.h>

/* ---- Logging ------------------------------------------------------------ */

#include <lichen/lichen_log.h>

#ifdef __ZEPHYR__
#ifndef CONFIG_LICHEN_GCP_LOG_LEVEL
#define CONFIG_LICHEN_GCP_LOG_LEVEL LOG_LEVEL_INF
#endif
LICHEN_LOG_MODULE(gcp_trust, CONFIG_LICHEN_GCP_LOG_LEVEL);
#else
LICHEN_LOG_MODULE(gcp_trust, LOG_LEVEL_WRN);
#endif

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
#include "monocypher.h"

/* ---- IID/Address Derivation --------------------------------------------- */

void gcp_trust_derive_iid(const uint8_t *pubkey, uint8_t *iid)
{
    uint8_t hash[64];

    /* IID = SHA-512(pubkey)[0:8] with U/L bit cleared */
    crypto_sha512(hash, pubkey, GCP_TRUST_PUBKEY_LEN);
    memcpy(iid, hash, GCP_TRUST_IID_LEN);

    /* Clear U/L bit (bit 1 of byte 0) per spec 8.5 */
    iid[0] &= ~0x02;

    crypto_wipe(hash, sizeof(hash));
}

void gcp_trust_derive_ygg_addr(const uint8_t *pubkey, uint8_t *ygg_addr)
{
    uint8_t hash[64];

    /* 02xx = [0x02] || SHA-512(pubkey)[0:7] || IID */
    crypto_sha512(hash, pubkey, GCP_TRUST_PUBKEY_LEN);

    ygg_addr[0] = 0x02;
    memcpy(&ygg_addr[1], hash, 7);

    /* IID with U/L bit cleared */
    memcpy(&ygg_addr[8], hash, GCP_TRUST_IID_LEN);
    ygg_addr[8] &= ~0x02;

    crypto_wipe(hash, sizeof(hash));
}

/* ---- Verification ------------------------------------------------------- */

bool gcp_trust_verify_iid_derivation(const uint8_t *pubkey,
                                     const uint8_t *claimed_iid)
{
    uint8_t derived_iid[GCP_TRUST_IID_LEN];

    gcp_trust_derive_iid(pubkey, derived_iid);

    /* SECURITY: Constant-time comparison for 8-byte IID */
    uint8_t diff = 0;
    for (int i = 0; i < GCP_TRUST_IID_LEN; i++) {
        diff |= derived_iid[i] ^ claimed_iid[i];
    }

    crypto_wipe(derived_iid, sizeof(derived_iid));
    return diff == 0;
}

bool gcp_trust_verify_ygg_derivation(const uint8_t *pubkey,
                                     const uint8_t *claimed_addr)
{
    uint8_t derived_addr[GCP_TRUST_YGG_ADDR_LEN];

    gcp_trust_derive_ygg_addr(pubkey, derived_addr);

    /* SECURITY: Constant-time comparison */
    int result = crypto_verify16(derived_addr, claimed_addr);

    crypto_wipe(derived_addr, sizeof(derived_addr));
    return result == 0;
}

bool gcp_trust_verify_ygg_iid_binding(const uint8_t *ygg_addr,
                                      const uint8_t *iid)
{
    /* ygg_addr[8:16] must equal IID */
    uint8_t diff = 0;
    for (int i = 0; i < GCP_TRUST_IID_LEN; i++) {
        diff |= ygg_addr[8 + i] ^ iid[i];
    }
    return diff == 0;
}

/* ---- TOFU --------------------------------------------------------------- */

gcp_tofu_result_t gcp_trust_tofu_first_contact(const uint8_t *pubkey,
                                               const uint8_t *claimed_iid)
{
    if (gcp_trust_verify_iid_derivation(pubkey, claimed_iid)) {
        return GCP_TOFU_PIN_AND_ACCEPT;
    }
    LOG_WRN("TOFU: derivation mismatch for IID");
    return GCP_TOFU_REJECT_DERIVATION_MISMATCH;
}

/* ---- Slot Claim Verification (Open Federation) ------------------------- */

gcp_slot_claim_result_t gcp_trust_verify_slot_claim(
    const uint8_t *gateway_pubkey,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len)
{
    /* SECURITY: Reject oversized messages (DoS protection) */
    if (message_len > GCP_TRUST_MAX_CONTROL_MSG_LEN) {
        return GCP_SLOT_CLAIM_REJECT_INVALID;
    }

    /* SECURITY: Validate domain prefix (confused deputy prevention) */
    if (message_len < GCP_TRUST_SLOT_CLAIM_PREFIX_LEN) {
        return GCP_SLOT_CLAIM_REJECT_INVALID;
    }
    if (memcmp(message, GCP_TRUST_SLOT_CLAIM_PREFIX,
               GCP_TRUST_SLOT_CLAIM_PREFIX_LEN) != 0) {
        return GCP_SLOT_CLAIM_REJECT_INVALID;
    }

    /* Validate signature length */
    if (signature_len != GCP_TRUST_SIG_LEN) {
        return GCP_SLOT_CLAIM_REJECT_INVALID;
    }

    /* Verify Schnorr-48 signature */
    /* We need to include schnorr48.h and call schnorr48_verify */
    extern bool schnorr48_verify(const uint8_t *pubkey,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);

    if (schnorr48_verify(gateway_pubkey, message, message_len,
                         signature, signature_len)) {
        return GCP_SLOT_CLAIM_ACCEPT;
    }

    LOG_WRN("Slot claim: signature verification failed");
    return GCP_SLOT_CLAIM_REJECT_INVALID;
}

/* ---- Key Rotation ------------------------------------------------------- */

/* Transcript length: domain(22+1) + old_pubkey(32) + old_iid(8) + new_pubkey(32) + seq(8) = 103 */
#define GCP_ROTATION_TRANSCRIPT_LEN (GCP_TRUST_KEY_ROTATE_PREFIX_LEN + 1 + 32 + 8 + 32 + 8)

int gcp_trust_build_rotation_transcript(const uint8_t *old_pubkey,
                                        const uint8_t *new_pubkey,
                                        uint64_t rotation_sequence,
                                        uint8_t *transcript,
                                        size_t transcript_size)
{
    if (transcript_size < GCP_ROTATION_TRANSCRIPT_LEN) {
        return -1;
    }

    size_t offset = 0;

    /* Domain tag with null terminator */
    memcpy(transcript + offset, GCP_TRUST_KEY_ROTATE_PREFIX,
           GCP_TRUST_KEY_ROTATE_PREFIX_LEN);
    offset += GCP_TRUST_KEY_ROTATE_PREFIX_LEN;
    transcript[offset++] = 0x00;

    /* Old pubkey */
    memcpy(transcript + offset, old_pubkey, GCP_TRUST_PUBKEY_LEN);
    offset += GCP_TRUST_PUBKEY_LEN;

    /* Old IID (derived from old pubkey) */
    gcp_trust_derive_iid(old_pubkey, transcript + offset);
    offset += GCP_TRUST_IID_LEN;

    /* New pubkey */
    memcpy(transcript + offset, new_pubkey, GCP_TRUST_PUBKEY_LEN);
    offset += GCP_TRUST_PUBKEY_LEN;

    /* Sequence number (big-endian u64) */
    for (int i = 7; i >= 0; i--) {
        transcript[offset++] = (uint8_t)(rotation_sequence >> (i * 8));
    }

    return (int)offset;
}

gcp_rotation_result_t gcp_trust_verify_key_rotation(
    const uint8_t *old_pubkey,
    const uint8_t *new_pubkey,
    uint64_t rotation_sequence,
    uint64_t stored_sequence,
    const uint8_t *signature,
    size_t signature_len)
{
    uint8_t transcript[GCP_ROTATION_TRANSCRIPT_LEN];

    /* SECURITY: Anti-replay check - sequence must be strictly greater */
    if (rotation_sequence <= stored_sequence) {
        LOG_WRN("Key rotation: replay attack (seq %llu <= %llu)",
                (unsigned long long)rotation_sequence,
                (unsigned long long)stored_sequence);
        return GCP_ROTATION_REJECT_REPLAY;
    }

    /* Validate signature length */
    if (signature_len != GCP_TRUST_SIG_LEN) {
        return GCP_ROTATION_REJECT_INVALID_SIGNATURE;
    }

    /* SECURITY: Build canonical transcript internally (prevents replay) */
    int len = gcp_trust_build_rotation_transcript(old_pubkey, new_pubkey,
                                                  rotation_sequence,
                                                  transcript, sizeof(transcript));
    if (len < 0) {
        return GCP_ROTATION_REJECT_INVALID_SIGNATURE;
    }

    /* Verify signature from old key */
    extern bool schnorr48_verify(const uint8_t *pubkey,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);

    bool valid = schnorr48_verify(old_pubkey, transcript, (size_t)len,
                                  signature, signature_len);

    crypto_wipe(transcript, sizeof(transcript));

    if (valid) {
        return GCP_ROTATION_ACCEPT;
    }

    LOG_WRN("Key rotation: signature verification failed");
    return GCP_ROTATION_REJECT_INVALID_SIGNATURE;
}

/* ---- Utilities ---------------------------------------------------------- */

const char *gcp_trust_level_name(gcp_trust_level_t level)
{
    switch (level) {
    case GCP_TRUST_LEVEL_TOFU:
        return "TOFU";
    case GCP_TRUST_LEVEL_BR_PROVISIONED:
        return "BR_PROVISIONED";
    case GCP_TRUST_LEVEL_DANE:
        return "DANE";
    case GCP_TRUST_LEVEL_PKIX:
        return "PKIX";
    default:
        return "UNKNOWN";
    }
}

#else /* !CONFIG_LICHEN_CRYPTO_MONOCYPHER */

/*
 * Stub implementations for builds without Monocypher.
 * These abort at runtime to prevent silent security failures.
 */

#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noreturn))
#endif
static void gcp_trust_stub_abort(const char *func)
{
    LOG_WRN("%s called without Monocypher - aborting", func);
    abort();
}

void gcp_trust_derive_iid(const uint8_t *pubkey, uint8_t *iid)
{
    (void)pubkey;
    (void)iid;
    gcp_trust_stub_abort("gcp_trust_derive_iid");
}

void gcp_trust_derive_ygg_addr(const uint8_t *pubkey, uint8_t *ygg_addr)
{
    (void)pubkey;
    (void)ygg_addr;
    gcp_trust_stub_abort("gcp_trust_derive_ygg_addr");
}

bool gcp_trust_verify_iid_derivation(const uint8_t *pubkey,
                                     const uint8_t *claimed_iid)
{
    (void)pubkey;
    (void)claimed_iid;
    gcp_trust_stub_abort("gcp_trust_verify_iid_derivation");
    return false;
}

bool gcp_trust_verify_ygg_derivation(const uint8_t *pubkey,
                                     const uint8_t *claimed_addr)
{
    (void)pubkey;
    (void)claimed_addr;
    gcp_trust_stub_abort("gcp_trust_verify_ygg_derivation");
    return false;
}

bool gcp_trust_verify_ygg_iid_binding(const uint8_t *ygg_addr, const uint8_t *iid)
{
    (void)ygg_addr;
    (void)iid;
    gcp_trust_stub_abort("gcp_trust_verify_ygg_iid_binding");
    return false;
}

gcp_tofu_result_t gcp_trust_tofu_first_contact(const uint8_t *pubkey,
                                               const uint8_t *claimed_iid)
{
    (void)pubkey;
    (void)claimed_iid;
    gcp_trust_stub_abort("gcp_trust_tofu_first_contact");
    return GCP_TOFU_REJECT_DERIVATION_MISMATCH;
}

gcp_slot_claim_result_t gcp_trust_verify_slot_claim(
    const uint8_t *gateway_pubkey,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len)
{
    (void)gateway_pubkey;
    (void)message;
    (void)message_len;
    (void)signature;
    (void)signature_len;
    gcp_trust_stub_abort("gcp_trust_verify_slot_claim");
    return GCP_SLOT_CLAIM_REJECT_INVALID;
}

int gcp_trust_build_rotation_transcript(const uint8_t *old_pubkey,
                                        const uint8_t *new_pubkey,
                                        uint64_t rotation_sequence,
                                        uint8_t *transcript,
                                        size_t transcript_size)
{
    (void)old_pubkey;
    (void)new_pubkey;
    (void)rotation_sequence;
    (void)transcript;
    (void)transcript_size;
    gcp_trust_stub_abort("gcp_trust_build_rotation_transcript");
    return -1;
}

gcp_rotation_result_t gcp_trust_verify_key_rotation(
    const uint8_t *old_pubkey,
    const uint8_t *new_pubkey,
    uint64_t rotation_sequence,
    uint64_t stored_sequence,
    const uint8_t *signature,
    size_t signature_len)
{
    (void)old_pubkey;
    (void)new_pubkey;
    (void)rotation_sequence;
    (void)stored_sequence;
    (void)signature;
    (void)signature_len;
    gcp_trust_stub_abort("gcp_trust_verify_key_rotation");
    return GCP_ROTATION_REJECT_INVALID_SIGNATURE;
}

const char *gcp_trust_level_name(gcp_trust_level_t level)
{
    (void)level;
    return "STUB";
}

#endif /* CONFIG_LICHEN_CRYPTO_MONOCYPHER */
