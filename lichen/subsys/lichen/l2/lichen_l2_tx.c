/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2_tx.c
 * @brief LICHEN L2 TX path
 *
 * Contains lichen_l2_send_inner() and lichen_l2_send().
 */

#include "lichen_l2_internal.h"

LOG_MODULE_DECLARE(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

/**
 * @brief L2 send handler
 *
 * Called by the IPv6 stack to transmit a packet. We:
 * 1. Extract IPv6 data from net_pkt
 * 2. Compress with SCHC
 * 3. Build LICHEN frame
 * 4. Send via LoRa
 *
 * Ownership: Per Zephyr net_l2 contract, on success (return >= 0 byte count)
 * this function takes ownership of @p pkt and calls net_pkt_unref(). On error
 * (return < 0), caller retains ownership and is responsible for cleanup.
 */
static int lichen_l2_send_inner(struct net_if *iface, struct net_pkt *pkt)
{
	int ret;

	/*
	 * Trust Zephyr's net_l2 contract: iface and pkt are guaranteed non-NULL.
	 * The IPv6 stack calls l2->send() only with valid parameters.
	 */
	ARG_UNUSED(iface);

	/* SECURITY: Reject TX if interface initialization failed (project-LICHEN-1ojj.2) */
	if (atomic_get(&iface_init_failed)) {
		LOG_ERR("lichen_l2: TX rejected (init failed)");
		return -ENODEV;
	}

	/*
	 * Guard against access before initialization. (project-LICHEN-tvfm.29)
	 * Check early before taking mutex or doing any packet processing.
	 * Could happen if IPv6 stack tries to transmit during early startup
	 * before lichen_l2_iface_init() completes.
	 */
	if (!atomic_get(&link_ctx_initialized)) {
		LOG_WRN("lichen_l2: TX rejected (link_ctx not ready)");
		return -EAGAIN;
	}

	if (!lichen_lora_l2_is_running()) {
		LOG_WRN("lichen_l2: TX rejected (LoRa L2 not running)");
		return -ENETDOWN;
	}

	/* Linearize the packet into our scratch buffer */
	size_t pkt_len = net_pkt_get_len(pkt);

	if (pkt_len > sizeof(tx_ipv6_buf)) {
		LOG_ERR("lichen_l2: TX pkt too large (%zu > %zu bytes)",
			pkt_len, sizeof(tx_ipv6_buf));
		return -EMSGSIZE;
	}

	if (pkt_len < IPV6_BASE_HDR_LEN) {
		LOG_ERR("lichen_l2: TX pkt too small for IPv6 (%zu bytes)", pkt_len);
		return -EINVAL;
	}

	k_mutex_lock(&tx_mutex, K_FOREVER);

	/*
	 * Linearize packet into scratch buffer using Zephyr's cursor API.
	 * net_pkt_read() handles multi-fragment packets transparently: the cursor
	 * iterates across all net_buf fragments, copying data contiguously into
	 * tx_ipv6_buf. This is the standard Zephyr pattern for linearizing packets.
	 *
	 * NOTE (project-LICHEN-i1gk.112): net_pkt_cursor_init() is void and cannot
	 * fail. We trust net_pkt_get_len() matches actual fragment data. If Zephyr's
	 * net_pkt is corrupted (len > actual data), net_pkt_read() will fail. The
	 * error check below handles this defensively.
	 */
	net_pkt_cursor_init(pkt);
	ret = net_pkt_read(pkt, tx_ipv6_buf, pkt_len);
	if (ret < 0) {
		LOG_ERR("lichen_l2: TX linearize failed (%d)", ret);
		k_mutex_unlock(&tx_mutex);
		return ret;
	}

	LOG_DBG("lichen_l2: TX IPv6 %zu bytes", pkt_len);

#if HAVE_LICHEN_LINK
	/*
	 * Use lichen_link_tx() to build the complete frame with Schnorr-48
	 * integrity protection. This handles:
	 * - SCHC compression
	 * - Schnorr-48 signature (always applied when has_key is set)
	 * - Returns -ENOKEY if has_key is not set (no unsigned frames)
	 */
	size_t frame_len = 0;
	/*
	 * Zero-initialize frame_len so that if lichen_link_tx() returns an
	 * error without writing frame_len, the frame_len == 0 check below
	 * catches it (project-LICHEN-i1gk.102).
	 *
	 * NULL dst_eui64 = broadcast (no destination address in frame header).
	 *
	 * DESIGN DECISION: LICHEN always transmits broadcast frames at L2.
	 * This is intentional for mesh operation:
	 * - All neighbors hear the frame for routing purposes
	 * - IPv6 destination address (after SCHC decompression) determines
	 *   actual recipient - L2 unicast is unnecessary
	 * - Saves frame overhead (no L2 destination address field)
	 *
	 * L2 unicast is NOT supported. If future requirements need directed
	 * addressing (e.g., certain RPL modes, energy optimization), extend
	 * this to pass a non-NULL dst_eui64 based on routing decisions.
	 *
	 * SECURITY IMPLICATIONS of L2 broadcast-only design:
	 * - Passive eavesdropping: all nodes in RF range receive every frame,
	 *   including metadata (source EUI-64, frame type, sequence numbers)
	 * - Replay attacks: attacker observes all frame sequence numbers,
	 *   making replay easier without L2 filtering
	 * - DoS amplification: every node must process (checksum, parse,
	 *   decompress, route) all frames, increasing battery drain
	 * - No L2 access control: frames reach all neighbors regardless of
	 *   trust relationship
	 *
	 * MITIGATIONS (must be enforced elsewhere in the stack):
	 * - OSCORE (CoAP E2E encryption) MANDATORY for sensitive payloads
	 * - Ed25519 link signatures authenticate frame origin
	 * - IPv6 destination filtering rejects non-unicast at L3
	 * - SCHC decompression drops frames that don't match local address
	 */
	ret = lichen_link_tx(&link_ctx, tx_ipv6_buf, pkt_len, NULL,
			     tx_frame_buf, &frame_len);
	if (ret < 0) {
		LOG_ERR("lichen_l2: TX frame build failed: %s (%d)",
			lichen_link_strerror(ret), ret);
		crash_info_store(CRASH_STATE_CORRUPTION, __LINE__, (uint32_t)(-ret));
		k_mutex_unlock(&tx_mutex);
		return lichen_l2_to_zephyr_errno(ret);
	}

	/* SECURITY: Validate frame_len before using it (project-LICHEN-i1gk.91) */
	if (frame_len == 0) {
		LOG_ERR("lichen_l2: TX returned zero-length frame");
		crash_info_store(CRASH_STATE_CORRUPTION, __LINE__, 0);
		k_mutex_unlock(&tx_mutex);
		return -EINVAL;
	}
	if (frame_len > sizeof(tx_frame_buf)) {
		LOG_ERR("lichen_l2: TX returned oversized frame (%zu bytes)", frame_len);
		crash_info_store(CRASH_STATE_CORRUPTION, __LINE__, (uint32_t)frame_len);
		k_mutex_unlock(&tx_mutex);
		return -EOVERFLOW;
	}

	LOG_DBG("lichen_l2: TX frame %zu bytes", frame_len);

	/*
	 * Pop the oldest frame from the TX queue to free the slot that was
	 * just enqueued by lichen_link_tx(). The pop result is intentionally
	 * discarded — the actual transmission uses tx_frame_buf directly.
	 * This keeps the queue from filling up and ensures the next call to
	 * lichen_link_tx() has a slot available.
	 */
	{
		uint8_t pop_buf[256];
		uint16_t pop_len = sizeof(pop_buf);
		int q_ret = tx_queue_pop(&link_ctx.tx_queue, pop_buf, &pop_len, NULL);
		if (q_ret < 0 && q_ret != -EAGAIN) {
			LOG_WRN("lichen_l2: TX queue pop failed (%d)", q_ret);
		}
	}

	/* Send via LoRa */
	ret = lichen_lora_l2_tx(tx_frame_buf, frame_len, 0U); /* CH0 control/fallback per CCP-9 */
#else
	/* No LICHEN link layer - send raw IPv6 (for testing) */
	ret = lichen_lora_l2_tx(tx_ipv6_buf, pkt_len, 0U);
#endif

	k_mutex_unlock(&tx_mutex);

	if (ret < 0) {
		LOG_ERR("lichen_l2: LoRa TX failed (%d)", ret);
		return ret;
	}

#ifdef CONFIG_LICHEN_L2_TEST_HOOKS
	atomic_inc(&test_tx_packets);
#endif

	/*
	 * Per Zephyr net_l2 contract: when L2 returns 0, it took ownership
	 * of the packet and must free it. The caller (IPv6 stack) will not
	 * free it on success.
	 *
	 * The packet is guaranteed valid here because lichen_lora_l2_tx(..., channel)
	 * only receives a pointer to our static tx_frame_buf/tx_ipv6_buf,
	 * not the net_pkt itself. The packet was linearized into that buffer
	 * earlier via net_pkt_read(), so the pkt structure is untouched by TX.
	 *
	 * KNOWN LIMITATION (project-LICHEN-d7ub.40): If this thread is forcibly
	 * aborted (k_thread_abort()) between the successful TX at line 1460 and
	 * this net_pkt_unref(), the packet leaks. This window has no yield point
	 * in normal operation, so it only occurs on thread abort. A memory pool
	 * exhaustion would follow. Fixing this would require atomic packet
	 * ownership tracking, which is disproportionate for an abort-only race.
	 */
	net_pkt_unref(pkt);
	return (int)pkt_len;
}

/* NET_L2_INIT-facing wrapper: keep the TX outcome counters in one place. */
int lichen_l2_send(struct net_if *iface, struct net_pkt *pkt)
{
	int ret;

	atomic_inc(&tx_stat_attempts);
	ret = lichen_l2_send_inner(iface, pkt);
	tx_stat_result(ret);
	return ret;
}
