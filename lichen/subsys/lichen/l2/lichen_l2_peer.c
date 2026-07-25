/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2_peer.c
 * @brief LICHEN L2 peer table management
 *
 * Contains peer_find_locked(), peer_find_oldest_locked(), peer_try_all_pubkeys(),
 * lichen_peer_add(), lichen_peer_remove(), and lichen_l2_publish_app_identity().
 */

#include "lichen_l2_internal.h"

LOG_MODULE_DECLARE(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

/* ─── Peer table management ──────────────────────────────────────────────── */

#if HAVE_LICHEN_LINK
/**
 * @brief Find peer entry by EUI-64 (internal, caller must hold rx_mutex).
 *
 * Uses memcmp (not constant-time) because EUI-64 addresses are public
 * identifiers, not secrets. Peer-authenticated RX uses peer_try_all_pubkeys(),
 * which attempts lichen_link_rx() for every active peer and delays returning a
 * signature-verification success until the full peer table has been scanned, so
 * peer lookup timing does not reveal which public key matched.
 *
 * @param eui64 8-byte peer EUI-64 address
 * @return Pointer to entry if found, NULL otherwise
 */
struct lichen_peer_entry *peer_find_locked(const uint8_t eui64[8])
{
	/*
	 * CRASH SAFETY (project-LICHEN-tvfm.6): If peer_table_valid is 0,
	 * the table may be in an inconsistent state (partially cleared by a
	 * crash-mid-loop or by lichen_l2_enable disable path before the
	 * clearing loop started). Treat as empty.
	 */
	if (!atomic_get(&peer_table_valid)) {
		return NULL;
	}
	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (peer_table[i].active &&
		    memcmp(peer_table[i].eui64, eui64, LICHEN_EUI64_LEN) == 0) {
			return &peer_table[i];
		}
	}
	return NULL;
}

/**
 * @brief Find oldest (least-recently-seen) peer for eviction.
 *
 * Used for LRU eviction when the peer table is full (project-LICHEN-tvfm.98).
 * Caller must hold rx_mutex.
 *
 * @return Index of oldest peer, or -1 if table is empty
 */
int peer_find_oldest_locked(void)
{
	/*
	 * CRASH SAFETY (project-LICHEN-tvfm.6): If peer_table_valid is 0,
	 * the table may be partially cleared. Treat as empty.
	 */
	if (!atomic_get(&peer_table_valid)) {
		return -1;
	}
	int oldest_idx = -1;
	int64_t oldest_time = INT64_MAX;

	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (peer_table[i].active && peer_table[i].last_seen != INT64_MAX
		    && peer_table[i].last_seen < oldest_time) {
			oldest_time = peer_table[i].last_seen;
			oldest_idx = (int)i;
		}
	}
	return oldest_idx;
}

/**
 * @brief Try all peers' pubkeys to verify a frame signature.
 *
 * Since LICHEN frames don't include sender EUI-64 in the wire format,
 * we must try each known peer's pubkey until one verifies. This is O(n)
 * where n is the number of peers, but n is bounded by CONFIG_LICHEN_LINK_MAX_NEIGHBORS.
 *
 * SECURITY: This function is the authentication boundary. Only returns success
 * if a known peer's pubkey verifies the signature.
 *
 * THREAD SAFETY (project-LICHEN-tvfm.22): This function temporarily modifies
 * ctx->peer_pubkey and ctx->peer_eui64 during iteration, restoring the saved
 * values on error paths. This modify-then-restore pattern is safe because:
 * 1. The ctx is a local stack variable in the caller (lichen_l2_input), not
 *    shared global state. If this thread is preempted, no other code can
 *    observe the partial state.
 * 2. The caller holds rx_mutex, preventing concurrent RX operations.
 * 3. On thread abort (the only way to exit without restoration), the entire
 *    stack frame including ctx is discarded - there is no observable state
 *    corruption because the stack variable ceases to exist.
 *
 * Context restoration note (project-LICHEN-tvfm.104): We save peer_pubkey and
 * peer_eui64 on entry and restore them on error paths. For non-auth errors,
 * this restoration is technically redundant (caller doesn't use ctx on error)
 * but maintains the invariant that ctx is unmodified on failure. This makes
 * the function contract clear: success modifies ctx, failure leaves it clean.
 *
 * @param ctx        RX context (peer_pubkey will be set on success)
 * @param replay     Replay table for duplicate detection
 * @param frame      Raw LICHEN frame bytes
 * @param frame_len  Length of frame
 * @param out_ipv6   Output buffer for decompressed IPv6 packet
 * @param out_len    In: buffer size, Out: IPv6 packet length
 * @param src_eui64  Filled with sender's EUI-64 on success
 * @return 0 on success (peer found and verified), negative error otherwise
 */
int peer_try_all_pubkeys(struct lichen_link_rx_ctx *ctx,
			 struct lichen_replay_table *replay,
			 const uint8_t *frame, size_t frame_len,
			 uint8_t *out_ipv6, size_t *out_len,
			 uint8_t src_eui64[8])
{
	int ret;
	size_t saved_out_len = *out_len;
	const uint8_t *saved_peer_pubkey = ctx->peer_pubkey;
	const uint8_t *saved_peer_eui64 = ctx->peer_eui64;
	struct lichen_frame parsed;

	/*
	 * CRASH SAFETY (project-LICHEN-tvfm.6): If peer_table_valid is 0,
	 * the table may be partially cleared. Return auth failure rather
	 * than attempting verification against inconsistent state.
	 */
	if (!atomic_get(&peer_table_valid)) {
		ctx->peer_pubkey = saved_peer_pubkey;
		ctx->peer_eui64 = saved_peer_eui64;
		*out_len = saved_out_len;
		return -LICHEN_EAUTH;
	}

	ret = lichen_frame_parse(&parsed, frame, frame_len);
	if (ret < 0) {
		return -EINVAL;
	}

	/*
	 * SECURITY: This helper is the peer-authenticated RX path. Unsigned frames
	 * must not be attributed to a known peer by trying each peer's public key;
	 * without a signature, lichen_link_rx() has no peer-auth proof to verify.
	 */
	if (!parsed.signature_present) {
		return -LICHEN_EAUTH;
	}

	/*
	 * SECURITY: Constant-time peer iteration to prevent timing side-channel.
	 *
	 * Always iterate through ALL peers even after finding a match. This
	 * prevents an attacker from inferring which peer index matched based
	 * on how quickly the function returns.
	 *
	 * Non-auth errors (malformed frame, replay) still abort early since
	 * they don't leak peer identity - the frame is rejected before peer
	 * matching completes.
	 *
	 * FUTURE (project-LICHEN-i1gk.76): Iteration order is deterministic
	 * (index 0, 1, 2, ...). Cache/memory timing may still leak the matching
	 * peer's table position via microarchitectural side channels. For
	 * security-critical deployments, consider randomizing the iteration
	 * start index (start = random % count, wrap around).
	 */
	int found_idx = -1;

	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (!peer_table[i].active) {
			continue;
		}

		ctx->peer_pubkey = peer_table[i].pubkey;
		ctx->peer_eui64 = peer_table[i].eui64;
		*out_len = saved_out_len;

		ret = lichen_link_rx(ctx, replay, frame, frame_len,
				     out_ipv6, out_len, src_eui64);
		if (ret == 0) {
			if (found_idx >= 0) {
				LOG_WRN("multiple peers verify same signature (idx %d and %zu) - duplicate keypair",
					found_idx, i);
			}
			found_idx = (int)i;
#ifdef CONFIG_LICHEN_L2_DEV_PROVISIONING
			break;
#else
			continue;
#endif
		}

		if (ret != -LICHEN_EAUTH) {
			ctx->peer_pubkey = saved_peer_pubkey;
			ctx->peer_eui64 = saved_peer_eui64;
			*out_len = saved_out_len;
			return ret;
		}
	}

	if (found_idx >= 0) {
		ctx->peer_pubkey = peer_table[found_idx].pubkey;
		ctx->peer_eui64 = peer_table[found_idx].eui64;
		*out_len = saved_out_len;
		/* Final call skips replay commit (already done in probe path) to
		 * avoid duplicate replay_check failure. Fixes double-update and
		 * pre-auth mutation for project-LICHEN-bbti. */
		ret = lichen_link_rx(ctx, NULL, frame, frame_len,
				     out_ipv6, out_len, src_eui64);
		if (ret < 0) {
			ctx->peer_pubkey = saved_peer_pubkey;
			ctx->peer_eui64 = saved_peer_eui64;
			*out_len = saved_out_len;
			return ret;
		}

		peer_table[found_idx].last_seen = k_uptime_get();
		LOG_DBG("lichen_l2: RX auth ok (peer ..%02x:%02x)",
			peer_table[found_idx].eui64[6], peer_table[found_idx].eui64[7]);
		return 0;
	}

	ctx->peer_pubkey = saved_peer_pubkey;
	ctx->peer_eui64 = saved_peer_eui64;
	*out_len = saved_out_len;
	return -LICHEN_EAUTH;
}
#endif /* HAVE_LICHEN_LINK */

int lichen_peer_add(const uint8_t *eui64,
		    const uint8_t *pubkey)
{
#if HAVE_LICHEN_LINK
	/*
	 * SECURITY: Array parameters decay to pointers - no compile-time or
	 * runtime size enforcement. BUILD_ASSERTs at lines 108-111 verify the
	 * array sizes in the function signature (8, 32) match our constants.
	 * Callers MUST pass buffers of exactly these sizes; undersized buffers
	 * cause undefined behavior (buffer overread in memcpy below).
	 */
	if (eui64 == NULL || pubkey == NULL) {
		return -EINVAL;
	}

	/* SECURITY: Reject peer_add if interface initialization failed (project-LICHEN-0li1.66) */
	if (atomic_get(&iface_init_failed)) {
		LOG_ERR("lichen_l2: peer_add rejected (init failed)");
		return -ENODEV;
	}

	/*
	 * Check for prior abort BEFORE acquiring mutex (project-LICHEN-dq6n.21).
	 *
	 * If the lora_l2 RX thread was forcibly aborted, it may have been terminated
	 * while holding rx_mutex (during lichen_l2_input callback processing).
	 * Attempting to acquire rx_mutex would deadlock forever.
	 *
	 * Recovery requires: lichen_lora_l2_deinit() + lichen_lora_l2_init()
	 */
	if (lichen_lora_l2_needs_reinit()) {
		LOG_ERR("lichen_l2: peer_add rejected (reinit required after abort)");
		return -ECANCELED;
	}

	/*
	 * Reject peer_add when module is not initialized (project-LICHEN-i1gk.53).
	 *
	 * After deinit(), the state is UNINIT. needs_reinit() returns false (state !=
	 * ABORTED), so the check above passes. But peer_add() would populate peer_table
	 * that gets wiped by the next init() (via memset/secure_zero). This causes
	 * silent peer data loss. Reject early with a clear error.
	 *
	 * Note: is_running() returns false for UNINIT, STOPPED, ABORTED, and DEINITING.
	 * We specifically need the "not initialized at all" case, which is UNINIT.
	 * Using copy_eui64() as a proxy because there's no is_initialized() API.
	 */
	uint8_t self_eui64[LICHEN_EUI64_LEN];
	int ret = lichen_lora_l2_copy_eui64(self_eui64);
	if (ret < 0) {
		LOG_ERR("lichen_l2: peer_add rejected (LoRa L2 unavailable, %d)", ret);
		return ret;
	}

	k_mutex_lock(&rx_mutex, K_FOREVER);

	/*
	 * CRASH SAFETY (project-LICHEN-tvfm.6): Reject peer_add if the peer
	 * table is in an inconsistent state (e.g., crash during disable-path
	 * clearing mid-loop). We cannot safely add a peer to a partially-
	 * cleared table.
	 */
	if (!atomic_get(&peer_table_valid)) {
		k_mutex_unlock(&rx_mutex);
		return -EBUSY;
	}

	/* Check if peer already exists - update pubkey if so */
	struct lichen_peer_entry *existing = peer_find_locked(eui64);
	if (existing != NULL) {
		/*
		 * SECURITY: TOFU key pinning (spec 8.6). First contact pins
		 * pubkey; subsequent contacts must present the same key.
		 * Key rotation requires explicit removal (lichen_peer_remove)
		 * followed by re-add. Silent key changes are rejected to
		 * prevent impersonation attacks.
		 */
		if (crypto_verify32(existing->pubkey, pubkey) != 0) {
			LOG_WRN("lichen_l2: TOFU violation for ..%02x:%02x "
				"(pubkey mismatch)", eui64[6], eui64[7]);
			k_mutex_unlock(&rx_mutex);
			return -EEXIST;
		}
		/* Same key — just refresh last_seen timestamp */
		existing->last_seen = k_uptime_get();
		k_mutex_unlock(&rx_mutex);
		return 0;  /* Peer already known with same key */
	}

	/* Find an empty slot */
	int slot = -1;
	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (!peer_table[i].active) {
			slot = (int)i;
			break;
		}
	}

	/*
	 * LRU eviction when table is full (project-LICHEN-tvfm.98).
	 *
	 * If no empty slot, evict the least-recently-seen peer. This allows
	 * the mesh to adapt to topology changes without manual peer removal.
	 * The evicted peer can re-join via EDHOC handshake if still active.
	 */
	if (slot < 0) {
		slot = peer_find_oldest_locked();
		if (slot < 0) {
			/* Should not happen: table full but no oldest entry found */
			LOG_ERR("lichen_l2: peer table inconsistent (no eviction candidate)");
			crash_info_store(CRASH_STATE_CORRUPTION, __LINE__,
					 CONFIG_LICHEN_LINK_MAX_NEIGHBORS);
			k_mutex_unlock(&rx_mutex);
			return -ENOSPC;
		}
		/*
		 * SECURITY: Clear replay window before evicting peer.
		 * Stale replay state from the evicted peer could cause valid
		 * packets to be rejected if that peer reconnects and its new
		 * sequence numbers fall within the old window.
		 * (project-LICHEN-0li1.53)
		 */
		lichen_replay_remove(&replay_table, peer_table[slot].pubkey);
		LOG_INF("lichen_l2: peer table full, evicting ..%02x:%02x",
			peer_table[slot].eui64[6], peer_table[slot].eui64[7]);
	}

	memcpy(peer_table[slot].eui64, eui64, LICHEN_EUI64_LEN);
	memcpy(peer_table[slot].pubkey, pubkey, LICHEN_L2_PUBKEY_LEN);
	peer_table[slot].last_seen = k_uptime_get();
	peer_table[slot].active = true;
	LOG_INF("lichen_l2: peer added ..%02x:%02x",
		eui64[6], eui64[7]);
	k_mutex_unlock(&rx_mutex);
	return 0;
#else
	ARG_UNUSED(eui64);
	ARG_UNUSED(pubkey);
	return -ENOTSUP;
#endif
}

int lichen_peer_remove(const uint8_t *eui64)
{
#if HAVE_LICHEN_LINK
	if (eui64 == NULL) {
		return -EINVAL;
	}

	/* SECURITY: Reject peer_remove if interface initialization failed (project-LICHEN-0li1.66) */
	if (atomic_get(&iface_init_failed)) {
		LOG_ERR("lichen_l2: peer_remove rejected (init failed)");
		return -ENODEV;
	}

	/*
	 * Check for prior abort BEFORE acquiring mutex (project-LICHEN-dq6n.21).
	 *
	 * If the lora_l2 RX thread was forcibly aborted, it may have been terminated
	 * while holding rx_mutex (during lichen_l2_input callback processing).
	 * Attempting to acquire rx_mutex would deadlock forever.
	 *
	 * Recovery requires: lichen_lora_l2_deinit() + lichen_lora_l2_init()
	 */
	if (lichen_lora_l2_needs_reinit()) {
		LOG_ERR("lichen_l2: peer_remove rejected (reinit required after abort)");
		return -ECANCELED;
	}

	/*
	 * Reject peer_remove when module is not initialized (project-LICHEN-0li1.11).
	 *
	 * After deinit(), the state is UNINIT. needs_reinit() returns false (state !=
	 * ABORTED), so the check above passes. But peer_remove() would attempt to
	 * access peer_table that may be in an indeterminate state. Reject early with
	 * a clear error.
	 *
	 * Using copy_eui64() as a proxy because there's no is_initialized() API.
	 */
	uint8_t self_eui64[LICHEN_EUI64_LEN];
	int ret = lichen_lora_l2_copy_eui64(self_eui64);
	if (ret < 0) {
		LOG_ERR("lichen_l2: peer_remove rejected (LoRa L2 unavailable, %d)", ret);
		return ret;
	}

	k_mutex_lock(&rx_mutex, K_FOREVER);

	/*
	 * CRASH SAFETY (project-LICHEN-tvfm.6): Reject peer_remove if the peer
	 * table is in an inconsistent state.
	 */
	if (!atomic_get(&peer_table_valid)) {
		k_mutex_unlock(&rx_mutex);
		return -EBUSY;
	}

	struct lichen_peer_entry *entry = peer_find_locked(eui64);
	if (entry == NULL) {
		k_mutex_unlock(&rx_mutex);
		return -ENOENT;
	}

	/*
	 * SECURITY: Clear replay window for this peer before removing.
	 * Stale replay state could cause valid packets to be rejected
	 * (if sequence numbers overlap) or replayed packets to be accepted
	 * (if the peer reconnects and the attacker replays old frames).
	 * (project-LICHEN-tvfm.45)
	 */
	lichen_replay_remove(&replay_table, entry->pubkey);

	/* SECURITY: Zero pubkey before marking inactive */
	secure_zero(entry->pubkey, sizeof(entry->pubkey));
	secure_zero(entry->eui64, sizeof(entry->eui64));
	entry->active = false;
	LOG_INF("lichen_l2: peer removed ..%02x:%02x",
		eui64[6], eui64[7]);

	k_mutex_unlock(&rx_mutex);
	return 0;
#else
	ARG_UNUSED(eui64);
	return -ENOTSUP;
#endif
}

int lichen_l2_publish_app_identity(const char *display_name,
				   const char *firmware_name)
{
#if HAVE_LICHEN_LINK && IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
	int ret;

	if (atomic_get(&iface_init_failed)) {
		return -ENODEV;
	}
	if (!atomic_get(&link_ctx_initialized)) {
		return -EAGAIN;
	}

	k_mutex_lock(&tx_mutex, K_FOREVER);
	k_mutex_lock(&rx_mutex, K_FOREVER);
	ret = lichen_app_identity_set_self_from_link_ctx(
		&link_ctx, display_name, firmware_name);
	k_mutex_unlock(&rx_mutex);
	k_mutex_unlock(&tx_mutex);

	return ret;
#else
	ARG_UNUSED(display_name);
	ARG_UNUSED(firmware_name);
	return -ENOTSUP;
#endif
}
