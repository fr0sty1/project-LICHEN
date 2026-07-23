/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/app_identity/app_identity.h>
#include <lichen/coap_keys.h>

#ifndef ENOKEY
#define ENOKEY ENOENT
#endif
#include <lichen/link_ctx.h>
#include <monocypher.h>

BUILD_ASSERT(LICHEN_APP_IDENTITY_EUI64_LEN == LICHEN_EUI64_LEN,
	     "app identity EUI-64 length must match link context");
BUILD_ASSERT(LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN == LICHEN_PK_LEN,
	     "app identity public key length must match link context");

struct peer_slot {
	struct lichen_app_identity_peer peer;
	bool used;
};

static struct lichen_app_identity_self s_self;
static bool s_has_self;
static struct peer_slot s_peers[CONFIG_LICHEN_APP_IDENTITY_MAX_PEERS];
static K_MUTEX_DEFINE(s_mutex);

/*
 * Derive IPv6 IID from Ed25519 public key per project-LICHEN-oxul,
 * spec/03-addressing.md, and lichen_key_pubkey_to_iid() (SHA-256
 * first 8 bytes with U/L bit cleared for locally-administered IID).
 * This provides unified identity for LCI, mesh routing, and backbone.
 */
static void derive_iid(
	const uint8_t pubkey[_Nonnull LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN],
	uint8_t iid[_Nonnull LICHEN_APP_IDENTITY_EUI64_LEN])
{
	(void)lichen_key_pubkey_to_iid(pubkey, iid);
}

static int copy_string(char *dst, size_t dst_len, const char *src)
{
	if (dst == NULL || dst_len == 0U) {
		return -EINVAL;
	}

	if (src == NULL) {
		memset(dst, 0, dst_len);
		return 0;
	}
	const size_t len = strlen(src);
	if (len >= dst_len) {
		return -ENAMETOOLONG;
	}
	memset(dst, 0, dst_len);
	memcpy(dst, src, len);
	return 0;
}

static bool has_nul(const char *_Nonnull buf, size_t len)
{
	return memchr(buf, '\0', len) != NULL;
}

static bool eui64_equal(
	const uint8_t a[_Nonnull LICHEN_APP_IDENTITY_EUI64_LEN],
	const uint8_t b[_Nonnull LICHEN_APP_IDENTITY_EUI64_LEN])
{
	return memcmp(a, b, LICHEN_EUI64_LEN) == 0;
}

static int find_peer_locked(
	const uint8_t eui64[_Nonnull LICHEN_APP_IDENTITY_EUI64_LEN])
{
	for (uint8_t i = 0U; i < ARRAY_SIZE(s_peers); i++) {
		if (s_peers[i].used &&
		    eui64_equal(s_peers[i].peer.eui64, eui64)) {
			return i;
		}
	}
	return -ENOENT;
}

static int find_free_peer_locked(void)
{
	for (uint8_t i = 0U; i < ARRAY_SIZE(s_peers); i++) {
		if (!s_peers[i].used) {
			return i;
		}
	}
	return -ENOSPC; /* full table per CONFIG_LICHEN_APP_IDENTITY_MAX_PEERS */
}

int lichen_app_identity_set_self(
	const struct lichen_app_identity_self *identity)
{
	struct lichen_app_identity_self normalized;
	int ret;

	if (identity == NULL) {
		return -EINVAL;
	}
	if (!identity->has_public_key) {
		return -ENOKEY;
	}
	if (!has_nul(identity->display_name, sizeof(identity->display_name)) ||
	    !has_nul(identity->firmware_name, sizeof(identity->firmware_name))) {
		return -ENAMETOOLONG;
	}

	memset(&normalized, 0, sizeof(normalized));
	memcpy(normalized.eui64, identity->eui64, sizeof(normalized.eui64));
	memcpy(normalized.public_key, identity->public_key,
	       sizeof(normalized.public_key));
	normalized.has_public_key = true;
	ret = copy_string(normalized.display_name,
			  sizeof(normalized.display_name),
			  identity->display_name);
	if (ret < 0) {
		return ret;
	}
	ret = copy_string(normalized.firmware_name,
			  sizeof(normalized.firmware_name),
			  identity->firmware_name);
	if (ret < 0) {
		return ret;
	}
	derive_iid(normalized.public_key, normalized.iid);

	k_mutex_lock(&s_mutex, K_FOREVER);
	s_self = normalized;
	s_has_self = true;
	k_mutex_unlock(&s_mutex);
	return 0;
}

int lichen_app_identity_set_self_from_link_ctx(
	const struct lichen_link_ctx *ctx, const char *display_name,
	const char *firmware_name)
{
	struct lichen_app_identity_self identity;
	int ret;

	if (ctx == NULL) {
		return -EINVAL;
	}

	/*
	 * SECURITY: Use lichen_link_copy_identity() to atomically snapshot
	 * the EUI-64 and public key under the context's lock. This prevents
	 * a race with lichen_link_cleanup() that could yield a zeroed key.
	 */
	memset(&identity, 0, sizeof(identity));
	ret = lichen_link_copy_identity(ctx, identity.eui64, identity.public_key, NULL);
	if (ret < 0) {
		return ret;
	}
	identity.has_public_key = true;
	ret = copy_string(identity.display_name,
			  sizeof(identity.display_name), display_name);
	if (ret < 0) {
		return ret;
	}
	ret = copy_string(identity.firmware_name,
			  sizeof(identity.firmware_name), firmware_name);
	if (ret < 0) {
		return ret;
	}
	return lichen_app_identity_set_self(&identity);
}

int lichen_app_identity_copy_self(
	struct lichen_app_identity_self *out)
{
	if (out == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	if (!s_has_self) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}
	*out = s_self;
	k_mutex_unlock(&s_mutex);
	return 0;
}

int lichen_app_identity_upsert_peer(
	const struct lichen_app_identity_peer *peer)
{
	int slot;

	if (peer == NULL) {
		return -EINVAL;
	}
	if (!peer->has_public_key) {
		return -ENOKEY;
	}
	if (!has_nul(peer->display_name, sizeof(peer->display_name))) {
		return -ENAMETOOLONG;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	slot = find_peer_locked(peer->eui64);
	if (slot >= 0) {
		__ASSERT(s_peers[slot].peer.has_public_key,
			 "lichen_app_identity_upsert_peer: existing peer must have public key");
		/*
		 * SECURITY: TOFU key pinning (spec 8.6). First contact pins
		 * pubkey; subsequent contacts must present the same key.
		 * Key rotation requires explicit removal followed by re-add.
		 * Silent key changes are rejected to prevent impersonation.
		 */
		if (s_peers[slot].peer.has_public_key &&
		    crypto_verify32(s_peers[slot].peer.public_key, peer->public_key) != 0) {
			k_mutex_unlock(&s_mutex);
			return -EEXIST;  /* TOFU violation: pubkey mismatch */
		}
	} else {
		/*
		 * SECURITY: a full table rejects new peers (-ENOSPC) rather
		 * than evicting an LRU entry. TOFU pins (spec 8.6) must not
		 * be silently discarded: an attacker who floods the table
		 * with ephemeral peers could evict a victim's pinned key and
		 * then be accepted as that victim's "first contact". Freeing
		 * capacity requires explicit peer removal.
		 */
		slot = find_free_peer_locked();
	}
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return slot;
	}

	struct lichen_app_identity_peer normalized = *peer;
	size_t len = strlen(peer->display_name);
	memset(normalized.display_name + len + 1, 0,
	       sizeof(normalized.display_name) - len - 1);
	derive_iid(normalized.public_key, normalized.iid);
	s_peers[slot].peer = normalized;
	s_peers[slot].used = true;
	k_mutex_unlock(&s_mutex);
	return 0;
}

int lichen_app_identity_upsert_peer_key(
	const uint8_t eui64[LICHEN_APP_IDENTITY_EUI64_LEN],
	const uint8_t public_key[LICHEN_APP_IDENTITY_PUBLIC_KEY_LEN])
{
	struct lichen_app_identity_peer peer;

	if (eui64 == NULL || public_key == NULL) {
		return -EINVAL;
	}

	memset(&peer, 0, sizeof(peer));
	memcpy(peer.eui64, eui64, sizeof(peer.eui64));
	memcpy(peer.public_key, public_key, sizeof(peer.public_key));
	peer.has_public_key = true;
	return lichen_app_identity_upsert_peer(&peer);
}

int lichen_app_identity_copy_peer(
	const uint8_t eui64[LICHEN_APP_IDENTITY_EUI64_LEN],
	struct lichen_app_identity_peer *out)
{
	int slot;

	if (eui64 == NULL || out == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	slot = find_peer_locked(eui64);
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return slot;
	}
	*out = s_peers[slot].peer;
	k_mutex_unlock(&s_mutex);
	return 0;
}

size_t lichen_app_identity_copy_peers(
	struct lichen_app_identity_peer *out, size_t out_len)
{
	size_t count = 0U;

	if (out_len == 0U) {
		return 0U;
	}
	__ASSERT(out != NULL, "lichen_app_identity_copy_peers out cannot be NULL");

	k_mutex_lock(&s_mutex, K_FOREVER);
	size_t total = 0U;
	for (uint8_t i = 0U; i < ARRAY_SIZE(s_peers); i++) {
		if (s_peers[i].used) {
			total++;
			if (count < out_len) {
				out[count++] = s_peers[i].peer;
			}
		}
	}
	k_mutex_unlock(&s_mutex);
	return total;
}

size_t lichen_app_identity_peer_count(void)
{
	size_t count = 0U;

	k_mutex_lock(&s_mutex, K_FOREVER);
	for (uint8_t i = 0U; i < ARRAY_SIZE(s_peers); i++) {
		if (s_peers[i].used) {
			count++;
		}
	}
	k_mutex_unlock(&s_mutex);
	return count;
}

int lichen_app_identity_remove_peer(
	const uint8_t eui64[LICHEN_APP_IDENTITY_EUI64_LEN])
{
	int slot;

	if (eui64 == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	slot = find_peer_locked(eui64);
	if (slot < 0) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}
	memset(&s_peers[slot], 0, sizeof(s_peers[slot]));
	k_mutex_unlock(&s_mutex);
	return 0;
}

#ifdef CONFIG_LICHEN_APP_IDENTITY_TEST_HOOKS
void lichen_app_identity_test_reset(void)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	memset(&s_self, 0, sizeof(s_self));
	memset(s_peers, 0, sizeof(s_peers));
	s_has_self = false;
	k_mutex_unlock(&s_mutex);
}
#endif
