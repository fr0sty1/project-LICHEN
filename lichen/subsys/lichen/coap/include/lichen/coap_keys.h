/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_keys.h
 * @brief LCI /keys CoAP resource handlers
 *
 * Implements the key store resource per LCI spec section 17.5.5.
 * Provides peer key management with trust levels and timestamps.
 */

#ifndef LICHEN_COAP_KEYS_H_
#define LICHEN_COAP_KEYS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <zephyr/net/coap.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** IID length in bytes (64-bit interface identifier) */
#define LICHEN_KEY_IID_LEN 8U

/** Public key length in bytes (Ed25519) */
#define LICHEN_KEY_PUBKEY_LEN 32U

/** SHA-256 fingerprint length in bytes */
#define LICHEN_KEY_FINGERPRINT_LEN 32U

/** IID string length: "xxxx:xxxx:xxxx:xxxx" + NUL */
#define LICHEN_KEY_IID_STR_LEN 20U

/* Fingerprint string length: "SHA256:" (7) + base64(32-byte SHA-256) + NUL.
 * base64_encode() pads, so a 32-byte hash is 44 chars, not 43 → 7+44+1 = 52.
 * The previous value (51) made lichen_key_pubkey_fingerprint() always fail:
 * base64_encode needs out_len >= 45 for 44 chars + NUL, but 51-7 = 44. */
#define LICHEN_KEY_FINGERPRINT_STR_LEN 52U

/**
 * @brief Key trust levels per LCI spec
 *
 * SECURITY: Trust levels indicate how a key was established:
 * - TOFU: Trust on first use, no verification
 * - VERIFIED: Manually verified (out-of-band confirmation)
 * - DANE: DNS-based authentication (DNSSEC-protected)
 */
enum lichen_key_trust {
	LICHEN_KEY_TRUST_UNKNOWN = 0,
	LICHEN_KEY_TRUST_TOFU,
	LICHEN_KEY_TRUST_VERIFIED,
	LICHEN_KEY_TRUST_DANE,
};

/**
 * @brief Key entry with metadata
 *
 * Stores a peer's public key with trust level and timestamps.
 */
struct lichen_key_entry {
	uint8_t iid[LICHEN_KEY_IID_LEN];
	uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];
	enum lichen_key_trust trust;
	uint32_t first_seen;    /**< Unix timestamp when first seen */
	uint32_t last_seen;     /**< Unix timestamp when last seen */
	bool valid;             /**< Entry in use */
};

/**
 * @brief Add or update a peer key
 *
 * SECURITY: TOFU key pinning enforced - existing keys with different
 * trust levels cannot have their pubkey changed. Remove first.
 *
 * @param[in] iid        8-byte interface identifier
 * @param[in] pubkey     32-byte Ed25519 public key
 * @param[in] trust      Trust level for the key
 * @return 0 on success, -ENOSPC if store full, -EEXIST on key mismatch
 */
int lichen_key_store_put(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
			 const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
			 enum lichen_key_trust trust);

/**
 * @brief Get a peer key entry
 *
 * @param[in]  iid   8-byte interface identifier
 * @param[out] entry Output buffer for key entry
 * @return 0 on success, -ENOENT if not found
 */
int lichen_key_store_get(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
			 struct lichen_key_entry *_Nonnull entry);

/**
 * @brief Remove a peer key
 *
 * @param[in] iid 8-byte interface identifier
 * @return 0 on success, -ENOENT if not found
 */
int lichen_key_store_delete(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN]);

/**
 * @brief Get number of stored keys
 *
 * @return Number of valid key entries
 */
size_t lichen_key_store_count(void);

/**
 * @brief Iterate over stored keys
 *
 * @param[out] entries  Array to fill with key entries
 * @param[in]  max_entries Maximum entries to return
 * @return Number of entries copied
 */
size_t lichen_key_store_list(struct lichen_key_entry *_Nonnull entries,
			     size_t max_entries);

/**
 * @brief Update last_seen timestamp for a key
 *
 * Called when traffic is received from a peer.
 *
 * @param[in] iid  8-byte interface identifier
 * @param[in] unix_time Current Unix timestamp
 * @return 0 on success, -ENOENT if not found
 */
int lichen_key_store_touch(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
			   uint32_t unix_time);

/**
 * @brief Format IID as colon-separated hex string
 *
 * Output format: "xxxx:xxxx:xxxx:xxxx"
 *
 * @param[in]  iid 8-byte interface identifier
 * @param[out] buf Output buffer (at least LICHEN_KEY_IID_STR_LEN bytes)
 * @param[in]  buf_len Buffer length
 * @return Number of characters written (excluding NUL), -EINVAL on error
 */
int lichen_key_iid_to_str(const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
			  char *_Nonnull buf, size_t buf_len);

/**
 * @brief Parse IID from colon-separated hex string
 *
 * Input format: "xxxx:xxxx:xxxx:xxxx" (case-insensitive)
 *
 * @param[in]  str Input string
 * @param[out] iid Output buffer (8 bytes)
 * @return 0 on success, -EINVAL on parse error
 */
int lichen_key_str_to_iid(const char *_Nonnull str,
			  uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN]);

/**
 * @brief Compute SHA-256 fingerprint of public key
 *
 * Output format: "SHA256:<base64>"
 *
 * @param[in]  pubkey 32-byte public key
 * @param[out] buf    Output buffer (at least LICHEN_KEY_FINGERPRINT_STR_LEN)
 * @param[in]  buf_len Buffer length
 * @return Number of characters written, -EINVAL on error
 */
int lichen_key_pubkey_fingerprint(const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
				  char *_Nonnull buf, size_t buf_len);

/**
 * @brief Derive 64-bit IID from Ed25519 public key (SHA-256 first 8 bytes)
 *
 * Implements node IPv6 address format:
 * link-local fe80::/10 (control plane only), primary 02xx::/iid (Yggdrasil-derived
 * for both local mesh and global backbone). IID = first 8 bytes of
 * SHA-256(pubkey). Matches Yggdrasil crypto addressing for unified identity.
 */
int lichen_key_pubkey_to_iid(const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
			     uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN]);

#ifdef CONFIG_LICHEN_COAP_KEYS_TEST_HOOKS
/**
 * @brief Reset key store for testing
 */
void lichen_key_store_test_reset(void);
size_t lichen_key_store_test_encode_list(uint8_t *buf, size_t buf_size);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_KEYS_H_ */
