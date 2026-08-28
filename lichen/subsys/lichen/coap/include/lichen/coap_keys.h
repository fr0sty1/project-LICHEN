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

/* Forward declaration - oscore.h is optional; we only need the pointer */
struct oscore_ctx;

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
 * @brief Group key trust levels
 *
 * Indicate how a group OSCORE key was established:
 * - UNKNOWN: Default/no trust
 * - PROVISIONED: Directly provisioned (out-of-band)
 * - ESTABLISHED: Established via key agreement protocol
 * - VERIFIED: Verified group membership
 */
enum lichen_group_key_trust {
	LICHEN_GROUP_KEY_TRUST_UNKNOWN = 0,
	LICHEN_GROUP_KEY_TRUST_PROVISIONED,
	LICHEN_GROUP_KEY_TRUST_ESTABLISHED,
	LICHEN_GROUP_KEY_TRUST_VERIFIED,
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

/** Result of an authenticated TOFU observation. */
enum lichen_key_pin_result {
	LICHEN_KEY_PIN_NEW = 0,
	LICHEN_KEY_PIN_MATCH,
};

/** Bounded audit record for an authenticated peer-key mismatch. */
struct lichen_key_mismatch_audit {
	uint8_t iid[LICHEN_KEY_IID_LEN];
	uint8_t pinned_pubkey[LICHEN_KEY_PUBKEY_LEN];
	uint8_t presented_pubkey[LICHEN_KEY_PUBKEY_LEN];
	uint64_t sequence;       /**< Monotonic event identifier for this boot. */
	uint32_t first_seen;     /**< First observation of this mismatch. */
	uint32_t last_seen;      /**< Most recent observation of this mismatch. */
	uint32_t attempts;       /**< Saturating count, including replays. */
	int last_delivery_error; /**< 0 after delivery, negative errno otherwise. */
	bool valid;
};

/**
 * Deliver a key-mismatch security event to an authenticated audit sink.
 *
 * The callback is synchronous, MUST copy the event before returning, and MUST
 * NOT re-enter the key-store API. A zero return means the sink durably accepted
 * the event; a negative errno leaves it pending for retry.
 */
typedef int (*lichen_key_mismatch_alert_cb)(
	void *_Nullable user,
	const struct lichen_key_mismatch_audit *_Nonnull event);

/**
 * Load one durable, compact key-store snapshot.
 *
 * The backend MUST authenticate the snapshot, reject rollback, and return
 * -ENOENT only when no snapshot has ever been committed. Entries occupy
 * indices [0, *count), and the revision is monotonically increasing.
 */
typedef int (*lichen_key_store_load_cb)(
	void *_Nullable user,
	struct lichen_key_entry *_Nonnull entries, size_t capacity,
	size_t *_Nonnull count, uint64_t *_Nonnull revision);

/**
 * Atomically persist one compact key-store snapshot.
 *
 * The callback MUST copy all input before returning and MUST return success
 * only after the snapshot and revision are durably committed. It MUST NOT
 * call back into the key-store API.
 */
typedef int (*lichen_key_store_save_cb)(
	void *_Nullable user,
	const struct lichen_key_entry *_Nonnull entries, size_t count,
	uint64_t revision);

/**
 * Initialize the durable TOFU store and restore its last committed snapshot.
 *
 * Loading and validation are atomic: on error, the active in-memory store is
 * unchanged and first-contact pinning remains disabled.
 */
int lichen_key_store_init(lichen_key_store_load_cb _Nonnull load_cb,
			  lichen_key_store_save_cb _Nonnull save_cb,
			  void *_Nullable user);

/**
 * Verify the key-derived IID and atomically pin a peer on first contact.
 *
 * Durable initialization is required. A new pin is published to readers only
 * after the persistence callback succeeds. An already pinned matching key is
 * accepted without another flash write.
 *
 * @return 0, -EKEYREJECTED for IID/key mismatch, -EEXIST for a changed pinned
 *         key, -EACCES before durable initialization, or a backend error.
 */
int lichen_key_store_verify_or_pin(
	const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
	const uint8_t pubkey[_Nonnull LICHEN_KEY_PUBKEY_LEN],
	enum lichen_key_pin_result *_Nullable result);

/**
 * Register or replace the authenticated key-mismatch alert sink.
 *
 * Pending undelivered audit records are retried immediately.
 * Pass NULL to detach the sink while retaining bounded audit state.
 *
 * @return 0 when all pending events were delivered, otherwise the first
 *         callback error. Registration remains active on callback error.
 */
int lichen_key_store_set_mismatch_alert_cb(
	lichen_key_mismatch_alert_cb _Nullable alert_cb,
	void *_Nullable user);

/**
 * Copy the current bounded mismatch audit record for a pinned peer.
 *
 * Replayed presentations of the same mismatched key increment @c attempts but
 * do not redeliver an event that the sink already accepted.
 */
int lichen_key_store_get_mismatch_audit(
	const uint8_t iid[_Nonnull LICHEN_KEY_IID_LEN],
	struct lichen_key_mismatch_audit *_Nonnull audit);

/**
 * @brief Add or update a peer key
 *
 * SECURITY: TOFU key pinning enforced - existing keys with different
 * trust levels cannot have their pubkey changed. Remove first.
 *
 * The trust level and IID/pubkey binding are validated on every call,
 * regardless of persistence readiness.
 *
 * @param[in] iid        8-byte interface identifier
 * @param[in] pubkey     32-byte Ed25519 public key
 * @param[in] trust      Trust level for the key
 * @return 0 on success, -ENOSPC if store full, -EEXIST on key mismatch,
 *         -EKEYREJECTED if trust is invalid or iid is not the key-derived IID
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

/**
 * @brief Create an OSCORE context from a stored peer key (TOFU).
 *
 * Looks up the peer's public key from the key store by IID, derives
 * an OSCORE master secret from it (via HKDF-SHA256), and creates an
 * OSCORE context. The master secret is ephemeral and wiped after
 * context creation.
 *
 * This enables E2E encryption for dead drops, confessions, and other
 * CoAP resources without requiring a separate EDHOC exchange.
 *
 * @param[in]  peer_iid        8-byte peer IID
 * @param[in]  peer_eui64      8-byte peer EUI-64
 * @param[in]  sender_id       Sender ID for OSCORE (e.g., local IID[0:1])
 * @param[in]  sender_id_len   Sender ID length
 * @param[in]  recipient_id    Recipient ID for OSCORE (e.g., peer IID[0:1])
 * @param[in]  recipient_id_len Recipient ID length
 * @param[out] ctx             Output OSCORE context pointer
 * @return 0 on success, -ENOENT if peer key not found, negative on error
 */
int lichen_key_store_get_oscore_ctx(
	const uint8_t peer_iid[_Nonnull LICHEN_KEY_IID_LEN],
	const uint8_t peer_eui64[_Nonnull 8],
	const uint8_t *_Nonnull sender_id, size_t sender_id_len,
	const uint8_t *_Nonnull recipient_id, size_t recipient_id_len,
	struct oscore_ctx *_Nullable *_Nonnull ctx);

/**
 * @brief Register a group key for OSCORE group communication.
 *
 * Stores the group master secret and creates a group OSCORE context.
 * The master_secret is copied internally.
 *
 * @param[in]  group_name       Group name (for lookup)
 * @param[in]  master_secret    16-byte group master secret
 * @param[in]  member_index     This node's member index in the group
 * @param[in]  trust            Group key trust level
 * @return 0 on success, -ENOSPC if group store is full, negative on error
 */
int lichen_key_store_group_put(const char *_Nonnull group_name,
			       const uint8_t master_secret[_Nonnull 16],
			       uint8_t member_index,
			       enum lichen_group_key_trust trust);

/**
 * @brief Get an OSCORE context for a registered group.
 *
 * Returns the per-member OSCORE context for sending/receiving
 * within the group.
 *
 * @param[in]  group_name Group name
 * @param[out] ctx        Output OSCORE context pointer
 * @return 0 on success, -ENOENT if group not found
 */
int lichen_key_store_group_get_ctx(const char *_Nonnull group_name,
				   struct oscore_ctx *_Nullable *_Nonnull ctx);

/**
 * @brief Get group key trust level.
 *
 * @param[in]  group_name Group name
 * @param[out] trust      Output trust level
 * @return 0 on success, -ENOENT if group not found
 */
int lichen_key_store_group_get_trust(const char *_Nonnull group_name,
				     enum lichen_group_key_trust *_Nonnull trust);

/**
 * @brief Set group key trust level (escalation only).
 *
 * @param[in] group_name Group name
 * @param[in] trust      New trust level
 * @return 0 on success, -ENOENT if group not found, -EPERM on downgrade
 */
int lichen_key_store_group_set_trust(const char *_Nonnull group_name,
				     enum lichen_group_key_trust trust);

/**
 * @brief Remove a registered group key.
 *
 * @param[in] group_name Group name
 * @return 0 on success, -ENOENT if group not found
 */
int lichen_key_store_group_delete(const char *_Nonnull group_name);

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
