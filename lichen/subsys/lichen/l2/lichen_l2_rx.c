/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2_rx.c
 * @brief LICHEN L2 RX path
 *
 * Contains lora_rx_callback() and lichen_l2_input().
 */

#include "lichen_l2_internal.h"

#if IS_ENABLED(CONFIG_STATS)
#include <zephyr/stats/stats.h>

/*
 * L2 RX funnel counters (lora_ipv6_mesh: T1000-E round-trip diagnosis),
 * exported over SMP as the "l2rx" STATS group so the console-less T1000-E's
 * receive path can be localized via if02:
 *   frames   - frames handed to L2 by the radio
 *   verified - passed peer signature verification + decompressed (for a
 *              pinned peer); about to be injected to the IPv6 stack
 *   rejected - failed verification or replay (non-beacon)
 *   injected - successfully injected to the IPv6 stack (net_recv_data ok)
 * If verified/injected climb but the app sees no CoAP response, the gap is
 * above L2 (addressing/CoAP); if they stay flat, the gateway's response is
 * not reaching L2-verified (routing/replay).
 */
STATS_SECT_START(lichen_l2rx_stats)
STATS_SECT_ENTRY32(frames)
STATS_SECT_ENTRY32(verified)
STATS_SECT_ENTRY32(rejected)
STATS_SECT_ENTRY32(injected)
STATS_SECT_END;

STATS_NAME_START(lichen_l2rx_stats)
STATS_NAME(lichen_l2rx_stats, frames)
STATS_NAME(lichen_l2rx_stats, verified)
STATS_NAME(lichen_l2rx_stats, rejected)
STATS_NAME(lichen_l2rx_stats, injected)
STATS_NAME_END(lichen_l2rx_stats);

STATS_SECT_DECL(lichen_l2rx_stats) lichen_l2rx_stats;
#define L2RX_STAT_INC(f) STATS_INC(lichen_l2rx_stats, f)
#else
#define L2RX_STAT_INC(f) do { } while (0)
#endif /* CONFIG_STATS */

LOG_MODULE_DECLARE(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

/**
 * @brief LoRa RX callback - invoked from lora_l2 RX thread
 */
void lora_rx_callback(const uint8_t *data, size_t len,
		      int16_t rssi, int8_t snr, void *user_data)
{
	ARG_UNUSED(user_data);

	/*
	 * Check both conditions to distinguish init-failure from never-initialized.
	 * (project-LICHEN-rwio.11)
	 */
	if (lichen_iface_read() == NULL || atomic_get(&iface_init_failed)) {
		LOG_WRN("lichen_l2: RX callback ignored (interface not ready)");
		return;
	}

	lichen_l2_input(lichen_iface_read(), data, len, rssi, snr);
}

void lichen_l2_input(struct net_if *iface, const uint8_t *data, size_t len,
		     int16_t rssi, int8_t snr)
{
	int ret;
	size_t ipv6_len;
	uint8_t rx_ipv6_copy[sizeof(rx_ipv6_buf)];

	/* Validate required parameters (project-LICHEN-ybal.28) */
	if (iface == NULL) {
		LOG_ERR("lichen_l2: input iface is NULL");
		return;
	}
	if (data == NULL) {
		LOG_ERR("lichen_l2: input data is NULL");
		return;
	}
	/* Reject empty frames before taking mutex (project-LICHEN-1ojj.7) */
	if (len == 0) {
		LOG_WRN("lichen_l2: RX empty frame ignored");
		return;
	}
	if (len < LICHEN_MIN_FRAME_LEN) {
		LOG_DBG("lichen_l2: RX frame too short (%zu < %d bytes)", len, LICHEN_MIN_FRAME_LEN);
		return;
	}
	if (len > MAX_LORA_FRAME) {
		LOG_WRN("lichen_l2: RX frame too large (%zu > %d bytes)", len, MAX_LORA_FRAME);
		return;
	}

#ifdef CONFIG_LICHEN_L2_TEST_HOOKS
	atomic_inc(&test_rx_frames);
#endif

	LOG_DBG("lichen_l2: RX %zu bytes (RSSI %d dBm, SNR %d dB)", len, rssi, snr);
	atomic_inc(&rx_stat_frames);
	L2RX_STAT_INC(frames);

	k_mutex_lock(&rx_mutex, K_FOREVER);

#if HAVE_LICHEN_LINK
	/* Guard against lora_l2 ABORTED setting rx_mutex for reinit mid-operation. */
	if (lichen_lora_l2_needs_reinit()) {
		LOG_ERR("lichen_l2: RX rejected (reinit required after abort)");
		k_mutex_unlock(&rx_mutex);
		return;
	}

	/*
	 * Guard against access before initialization.
	 * This shouldn't happen in normal operation, but could if a packet
	 * arrives during early startup before lichen_l2_iface_init() completes.
	 */
	if (!atomic_get(&link_ctx_initialized)) {
		LOG_ERR("lichen_l2: BUG: RX before link_ctx initialized, dropping");
		k_mutex_unlock(&rx_mutex);
		return;
	}

	/*
	 * Guard against processing on a module that has been aborted
	 * (project-LICHEN-d7ub.68). If the lora_l2 state transitions to
	 * ABORTED between the callback snapshot and this point, we must
	 * not continue processing on corrupt state.
	 *
	 * Recovery requires: lichen_lora_l2_deinit() + lichen_lora_l2_init()
	 * which reinitializes all mutexes and state.
	 */
	if (lichen_lora_l2_needs_reinit()) {
		LOG_WRN("lichen_l2: RX dropped (reinit required after abort)");
		k_mutex_unlock(&rx_mutex);
		return;
	}

	/*
	 * Use lichen_link_rx() to process the complete frame. This handles:
	 * - Frame parsing
	 * - Replay protection (if replay table provided)
	 * - Schnorr-48 signature verification (if peer_pubkey provided)
	 * - Unsigned or Schnorr-48 frame validation
	 * - SCHC decompression
	 *
	 * SECURITY: Copy key to stack to survive hypothetical cleanup reordering.
	 */
	uint8_t rx_link_key[LICHEN_LINK_KEY_LEN];
	const uint8_t *rx_link_key_ptr = NULL;
	if (link_ctx.has_link_key) {
		memcpy(rx_link_key, link_ctx.link_key, LICHEN_LINK_KEY_LEN);
		rx_link_key_ptr = rx_link_key;
	}

	/*
	 * SECURITY: Peer-authenticated frame acceptance
	 *
	 * Frames are verified against known peers in peer_table[]. The
	 * peer_try_all_pubkeys() function iterates through all registered
	 * peers and returns success only if one peer's pubkey verifies
	 * the Schnorr-48 signature. Frames from unknown senders are REJECTED.
	 *
	 * Peers are registered via lichen_peer_add() after EDHOC handshake
	 * or announce processing. Replay protection is scoped to authenticated
	 * peers only (replay windows allocated after signature verification),
	 * preventing the replay window poisoning attack described in
	 * replay.h:100-120.
	 */
	/*
	 * Defensive initialization: zero src_eui64 in case peer_try_all_pubkeys()
	 * fails before setting it. On success, src_eui64 is filled with the
	 * authenticated peer's address. On failure, we return early and never
	 * use this array. (project-LICHEN-tvfm.68)
	 */
	uint8_t src_eui64[8] = {0};
	struct lichen_link_rx_ctx rx_ctx = {
		.peer_pubkey = NULL,
		.peer_eui64 = src_eui64,
		.link_key = rx_link_key_ptr,
		.current_time = k_uptime_get_32(),
	};

	ipv6_len = sizeof(rx_ipv6_buf);
	ret = peer_try_all_pubkeys(&rx_ctx, &replay_table, data, len,
				   rx_ipv6_buf, &ipv6_len, src_eui64);
	if (ret < 0) {
		/*
		 * Puck neighbor beacons are 5-byte unsigned broadcast link frames
		 * with no SCHC/IPv6 payload: [len=4][LLSec=0x00][epoch][seq_hi][seq_lo]
		 * (see puck send_beacon()).
		 * lichen_link_rx() rightly rejects them (nothing to deliver), but
		 * they are valid neighbor traffic, not errors — log at INF instead
		 * of WRN. (lora_ipv6_mesh-v6g6)
		 */
		if (len == 5 && data[0] == 4 && data[1] == 0x00) {
				LOG_INF("lichen_l2: neighbor beacon epoch=%u seq=%u "
					"rssi=%d snr=%d",
					data[2],
					(uint16_t)(((uint16_t)data[3] << 8) | data[4]),
					rssi, snr);
				secure_zero(rx_link_key, sizeof(rx_link_key));
				k_mutex_unlock(&rx_mutex);
				return;
		}
		atomic_set(&rx_stat_last_err, ret);
		L2RX_STAT_INC(rejected);
		LOG_WRN("lichen_l2: RX failed: %s (%d)",
			lichen_link_strerror(ret), ret);
		secure_zero(rx_link_key, sizeof(rx_link_key));
		k_mutex_unlock(&rx_mutex);
		return;
	}
	L2RX_STAT_INC(verified);

#if defined(CONFIG_LICHEN_ADAPTIVE_SF_ENABLED)
	/*
	 * Feed per-neighbor SF tracking: update SNR EWMA for the authenticated
	 * source neighbor. This runs after signature verification (src_eui64 is
	 * from an authenticated peer). Gradient table pointer is set by the
	 * routing layer via lichen_l2_set_gradient_table().
	 */
	if (sf_gradient_table != NULL) {
		lichen_gradient_sf_update(sf_gradient_table, src_eui64,
					  snr, k_uptime_get_32());
	}
#endif

	/* SECURITY: Validate ipv6_len before using it (project-LICHEN-3pun.5) */
	if (ipv6_len > sizeof(rx_ipv6_buf)) {
		LOG_ERR("lichen_l2: RX returned oversized packet (%zu bytes)", ipv6_len);
		crash_info_store(CRASH_STATE_CORRUPTION, __LINE__, (uint32_t)ipv6_len);
		secure_zero(rx_link_key, sizeof(rx_link_key));
		k_mutex_unlock(&rx_mutex);
		return;
	}
	if (ipv6_len < IPV6_BASE_HDR_LEN) {
		LOG_WRN("lichen_l2: RX packet too small for IPv6 (%zu bytes)", ipv6_len);
		secure_zero(rx_link_key, sizeof(rx_link_key));
		k_mutex_unlock(&rx_mutex);
		return;
	}

	/* RFC 4291 section 2.7: Source address MUST NOT be multicast. */
	/* RFC 4443 section 2.2: Unspecified source not valid for upper-layer protocols. */
	if (rx_ipv6_buf[8] == 0xff) {
		LOG_WRN("lichen_l2: RX multicast source dropped");
		L2RX_STAT_INC(rejected);
		secure_zero(rx_link_key, sizeof(rx_link_key));
		k_mutex_unlock(&rx_mutex);
		return;
	}
	{
		bool all_zero = true;
		for (int i = 8; i < 24; i++) {
			if (rx_ipv6_buf[i] != 0) {
				all_zero = false;
				break;
			}
		}
		if (all_zero) {
			LOG_WRN("lichen_l2: RX unspecified source dropped");
			L2RX_STAT_INC(rejected);
			secure_zero(rx_link_key, sizeof(rx_link_key));
			k_mutex_unlock(&rx_mutex);
			return;
		}
	}

	/*
	 * SECURITY: Logging full EUI-64 at DEBUG level is acceptable because:
	 * 1. DEBUG logging requires explicit CONFIG_LICHEN_L2_LOG_LEVEL=4, not
	 *    enabled in production builds
	 * 2. This EUI-64 is from an AUTHENTICATED peer (signature verified above),
	 *    not arbitrary traffic - logging confirms which known peer sent data
	 * 3. EUI-64 is already exposed in IEEE 802.15.4-style link-layer addresses
	 *    and IPv6 link-local addresses (fe80::...IID)
	 * 4. Per-packet tracing is essential for mesh debugging; truncated addresses
	 *    would make multi-hop routing analysis impractical
	 */
	LOG_DBG("lichen_l2: RX decompressed %zu bytes from ..%02x:%02x",
		ipv6_len, src_eui64[6], src_eui64[7]);

	/* SECURITY: Zero local key copy before any exit (project-LICHEN-1ojj.28) */
	secure_zero(rx_link_key, sizeof(rx_link_key));
#else
	/* No LICHEN link layer - treat as raw IPv6 */
	if (len > sizeof(rx_ipv6_buf)) {
		LOG_WRN("lichen_l2: RX packet too large (%zu bytes)", len);
		k_mutex_unlock(&rx_mutex);
		return;
	}
	memcpy(rx_ipv6_buf, data, len);
	ipv6_len = len;
#endif

	/*
	 * Copy the shared RX buffer before releasing rx_mutex. The copy is small
	 * (264 bytes with the current MTU + OSCORE overhead) and keeps potentially-
	 * blocking packet allocation out of the RX critical section.
	 */
	memcpy(rx_ipv6_copy, rx_ipv6_buf, ipv6_len);
	k_mutex_unlock(&rx_mutex);

	/*
	 * Allocate net_pkt for the IPv6 packet.
	 * Timeout configured via CONFIG_LICHEN_L2_RX_ALLOC_TIMEOUT_MS.
	 * See Kconfig help for tradeoff rationale.
	 *
	 * Memory pressure behavior (project-LICHEN-tvfm.99):
	 * On allocation failure, we drop this packet and return. At LoRa data
	 * rates (~980 bps at SF10), sustained memory pressure would cause each
	 * incoming frame to block for the timeout (default 50ms) then fail.
	 * This allocation runs outside rx_mutex so peer management and enable/
	 * disable cleanup are not blocked by memory pressure.
	 *
	 * FUTURE (project-LICHEN-i1gk.62, project-LICHEN-i1gk.79): The timeout is
	 * fixed (CONFIG-driven). Adaptive backoff and allocation failure counters
	 * could improve observability under sustained memory pressure.
	 */
	struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(
		iface, ipv6_len, AF_INET6, 0,
		K_MSEC(CONFIG_LICHEN_L2_RX_ALLOC_TIMEOUT_MS));
	if (pkt == NULL) {
		LOG_ERR("lichen_l2: RX packet alloc failed");
		return;
	}

	/*
	 * Write IPv6 data into the packet.
	 *
	 * net_pkt_write() COPIES data from rx_ipv6_copy into the packet's internal
	 * buffer - it does not retain a pointer to our stack storage. net_recv_data()
	 * operates on pkt, which has its own copy. (project-LICHEN-tvfm.51)
	 */
	ret = net_pkt_write(pkt, rx_ipv6_copy, ipv6_len);
	if (ret < 0) {
		LOG_ERR("lichen_l2: RX packet write failed (%d)", ret);
		net_pkt_unref(pkt);
		return;
	}

	/*
	 * Inject into the network stack.
	 *
	 * Ownership semantics:
	 * - On success (ret >= 0): net_recv_data takes ownership of pkt.
	 *   The network stack will unref the packet when processing completes.
	 *   We MUST NOT access or unref pkt after this point.
	 * - On failure (ret < 0): We retain ownership and must unref pkt.
	 */
	ret = net_recv_data(iface, pkt);
	if (ret < 0) {
		LOG_ERR("lichen_l2: net_recv_data failed (%d)", ret);
		net_pkt_unref(pkt);
		return;
	}

	/* pkt ownership transferred to network stack - do not access */
#ifdef CONFIG_LICHEN_L2_TEST_HOOKS
	k_mutex_lock(&test_stats_mutex, K_FOREVER);
	test_last_injected_len = MIN(ipv6_len, sizeof(test_last_injected));
	memcpy(test_last_injected, rx_ipv6_copy, test_last_injected_len);
	k_mutex_unlock(&test_stats_mutex);
	atomic_inc(&test_rx_injected_packets);
#endif
	atomic_inc(&rx_stat_accepted);
	L2RX_STAT_INC(injected);
	LOG_DBG("lichen_l2: injected %zu bytes to IPv6 stack", ipv6_len);
}

#if HAVE_LICHEN_LINK && IS_ENABLED(CONFIG_STATS)
/* Called from lichen_l2_iface_init() to register stats */
void lichen_l2_stats_init(void)
{
	(void)STATS_INIT_AND_REG(lichen_l2rx_stats, STATS_SIZE_32, "l2rx");
}
#endif
