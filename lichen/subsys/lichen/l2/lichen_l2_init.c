/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2_init.c
 * @brief LICHEN L2 lifecycle management
 *
 * Contains init_link_ctx_locked(), lichen_l2_enable(), NET_L2_INIT,
 * NET_DEVICE_INIT, lichen_l2_iface_init(), lichen_l2_reinit_after_abort().
 */

#include "lichen_l2_internal.h"

LOG_MODULE_DECLARE(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

/* Forward declaration for stats init */
#if HAVE_LICHEN_LINK && IS_ENABLED(CONFIG_STATS)
extern void lichen_l2_stats_init(void);
#endif

/* ─── L2 callbacks ───────────────────────────────────────────────────────── */

/*
 * Log level policy:
 *   LOG_ERR: Initialization failures, resource exhaustion, programming errors
 *            (NULL params), conditions that prevent operation.
 *   LOG_WRN: Transient conditions that drop a single packet but don't indicate
 *            system failure - e.g., RX during early startup, frame auth failure,
 *            oversized frame. These are expected in normal mesh operation (nodes
 *            may receive traffic before fully initialized, or from misconfigured
 *            peers). WRN avoids log spam while remaining visible for debugging.
 *   LOG_INF: State transitions, initialization success, configuration summary.
 *   LOG_DBG: Per-packet tracing, detailed state.
 */

/**
 * @brief L2 receive handler
 *
 * Called by net_recv_data() to let L2 process the packet before
 * passing it up to the IP layer.
 *
 * WHY THIS EXISTS (even though it just returns NET_CONTINUE):
 * Zephyr's net_if_recv_data() unconditionally calls iface->l2->recv() without
 * a NULL check. If we omit this callback from NET_L2_INIT, any packet injection
 * via net_recv_data() would dereference NULL and crash. This function must exist
 * even when it performs no L2-specific processing. Compare Zephyr's dummy L2
 * (subsys/net/l2/dummy/dummy.c) which follows the same pattern.
 *
 * WHY NET_CONTINUE IS ALWAYS RETURNED:
 * All L2 validation (MIC check, replay protection, decompression) happens in
 * lichen_l2_input() via the LoRa RX callback, before the packet reaches
 * net_recv_data(). By the time this callback is invoked, the packet has already
 * passed L2 validation and is ready for IP processing. Returning NET_DROP or
 * NET_OK here would be incorrect. (project-LICHEN-tvfm.75)
 */
static enum net_verdict lichen_l2_recv(struct net_if *iface,
				       struct net_pkt *pkt)
{
	/*
	 * Trust Zephyr's net_l2 contract: iface and pkt are guaranteed non-NULL.
	 * See net_if_recv_data() in zephyr/subsys/net/ip/net_if.c which calls
	 * l2->recv() unconditionally. Zephyr's dummy L2 follows the same pattern.
	 */
	ARG_UNUSED(iface);
	ARG_UNUSED(pkt);

	/* Packet is already an IPv6 packet (decompressed in lichen_l2_input).
	 * Let the IP layer handle it.
	 */
	return NET_CONTINUE;
}

/* Declared in lichen_l2_tx.c */
extern int lichen_l2_send(struct net_if *iface, struct net_pkt *pkt);

/**
 * @brief Initialize link_ctx with callers already holding both mutexes.
 *
 * Called by lichen_l2_enable() (post-boot re-init after disable) and
 * lichen_l2_iface_init() (boot-time init). Extracted to eliminate
 * duplicated initialization logic between the two paths.
 *
 * Caller MUST hold tx_mutex and rx_mutex before calling (LOCK ORDER:
 * tx_mutex before rx_mutex).
 *
 * @param eui64 8-byte EUI-64 address for this node
 * @return 0 on success, negative errno on failure
 */
int init_link_ctx_locked(const uint8_t eui64[LICHEN_EUI64_LEN])
{
	int ret;

	secure_zero(&link_ctx, sizeof(link_ctx));
	ret = lichen_link_init(&link_ctx, eui64);
	if (ret < 0) {
		LOG_ERR("lichen_link_init failed (%d)", ret);
		secure_zero(&link_ctx, sizeof(link_ctx));
		return ret;
	}
#ifdef CONFIG_LICHEN_LINK_EPOCH_PERSIST
	uint8_t boot_epoch;
	ret = lichen_link_epoch_advance_for_boot(link_ctx.epoch, &boot_epoch);
	if (ret < 0) {
		LOG_ERR("epoch persistence failed (%d)", ret);
		lichen_link_cleanup(&link_ctx);
		secure_zero(&link_ctx, sizeof(link_ctx));
		return ret;
	}
	ret = lichen_link_set_epoch(&link_ctx, boot_epoch);
	if (ret < 0) {
		LOG_ERR("lichen_link_set_epoch failed (%d)", ret);
		lichen_link_cleanup(&link_ctx);
		secure_zero(&link_ctx, sizeof(link_ctx));
		return ret;
	}
#endif
	lichen_replay_table_init(&replay_table);
	atomic_set(&link_ctx_initialized, 1);
	return 0;
}

/**
 * @brief L2 enable/disable handler
 */
static int lichen_l2_enable(struct net_if *iface, bool state)
{
	int ret;

	/*
	 * Trust Zephyr's net_l2 contract: iface is guaranteed non-NULL.
	 * The network stack calls l2->enable() only with valid parameters.
	 */
	ARG_UNUSED(iface);

	/* SECURITY: Reject enable if interface initialization failed (project-LICHEN-1ojj.2) */
	if (atomic_get(&iface_init_failed)) {
		LOG_ERR("lichen_l2: enable rejected (init failed)");
		return -ENODEV;
	}

	/*
	 * Check for prior abort BEFORE acquiring any mutex (project-LICHEN-3pun.16).
	 *
	 * If the lora_l2 RX thread was forcibly aborted, it may have been terminated
	 * while holding rx_mutex (during lichen_l2_input callback processing).
	 * Attempting to acquire rx_mutex below would deadlock forever.
	 *
	 * Recovery requires: lichen_lora_l2_deinit() + lichen_lora_l2_init()
	 * which reinitializes all mutexes and state.
	 */
	if (lichen_lora_l2_needs_reinit()) {
		LOG_ERR("lichen_l2: enable rejected (reinit required after abort)");
		return -ECANCELED;
	}

	LOG_INF("lichen_l2: %s", state ? "enabled" : "disabled");

	if (state) {
		uint8_t eui64_copy[LICHEN_EUI64_LEN];

		ret = lichen_lora_l2_copy_eui64(eui64_copy);
		if (ret < 0) {
			LOG_ERR("lichen_l2: enable rejected (LoRa L2 unavailable, %d)", ret);
			return ret;
		}

#if HAVE_LICHEN_LINK
		/*
		 * Re-initialize link_ctx if it was cleaned up by a prior disable.
		 * (project-LICHEN-rwio.1)
		 *
		 * Use shared helper init_link_ctx_locked() to keep the init logic
		 * in one place. Caller holds both mutexes (LOCK ORDER: tx_mutex
		 * before rx_mutex). The init path (lichen_l2_iface_init) uses the
		 * same helper during boot-time init.
		 *
		 * NOTE (project-LICHEN-i1gk.74): Replay table is cleared here but
		 * peer_table is NOT cleared on enable (only on disable). This is
		 * intentional: replay protection resets for security (peers must
		 * exceed their old sequence numbers), while peer keys persist so
		 * EDHOC re-handshake is not required. Peers that were mid-session
		 * will fail replay checks until their sequence numbers advance.
		 */
		k_mutex_lock(&tx_mutex, K_FOREVER);
		k_mutex_lock(&rx_mutex, K_FOREVER);
		if (!atomic_get(&link_ctx_initialized)) {
			ret = init_link_ctx_locked(eui64_copy);
			if (ret < 0) {
				k_mutex_unlock(&rx_mutex);
				k_mutex_unlock(&tx_mutex);
				return ret;
			}
		}
		/*
		 * NOTE: tx_mutex and rx_mutex are NOT released here.
		 * They are held across set_rx_callback() and start() to prevent
		 * a TOCTOU race with concurrent disable (project-LICHEN-tvfm.61).
		 * Release is at the end of the enable path (~line 1671-1672).
		 */
#endif
		/*
		 * Re-register RX callback before starting.
		 * lichen_lora_l2_stop() clears the callback (lora_l2.c:324-325),
		 * so we must re-register it on enable. (project-LICHEN-yw7i.28)
		 *
		 * TOCTOU FIX (project-LICHEN-tvfm.61): Hold tx_mutex and rx_mutex
		 * across set_rx_callback() and start() to prevent a concurrent
		 * disable from racing between initialization (lines 1537-1580) and
		 * RX thread startup (line 1602). By extending the critical section
		 * until after start() completes, we guarantee that no concurrent
		 * lichen_l2_enable(false) can observe link_ctx_initialized==1 and
		 * then see the RX thread start with stale/lost initialization.
		 *
		 * Lock ordering safety: lichen_lora_l2_start() acquires lora_mutex
		 * internally. lora_l2.c releases lora_mutex BEFORE invoking the
		 * RX callback, which acquires rx_mutex. Since lora_mutex is never
		 * held while acquiring rx_mutex, no lock ordering relationship
		 * exists between lora_mutex and tx_mutex/rx_mutex, so holding
		 * tx_mutex+rx_mutex while start() holds lora_mutex is safe.
		 */
		ret = lichen_lora_l2_set_rx_callback(lora_rx_callback, NULL);
		if (ret != 0) {
			LOG_ERR("lichen_l2: failed to set RX callback (%d)", ret);
#if HAVE_LICHEN_LINK
			if (atomic_get(&link_ctx_initialized)) {
				atomic_set(&link_ctx_initialized, 0);
				lichen_link_cleanup(&link_ctx);
			}
#endif
			k_mutex_unlock(&rx_mutex);
			k_mutex_unlock(&tx_mutex);
			return ret;
		}
		ret = lichen_lora_l2_start();
		/*
		 * Roll back callback on start() failure. (project-LICHEN-tvfm.72)
		 *
		 * If start() fails, the RX thread isn't running and won't invoke
		 * the callback, but leaving it registered creates inconsistent
		 * state. Clear it to match the stopped state.
		 *
		 * DEFENSIVE (project-LICHEN-0li1.50): Check and log callback clearing
		 * failure. This can only happen if state transitioned to UNINIT between
		 * start() failing and this call - a very narrow race. If clearing fails,
		 * the callback may remain registered pointing to lora_rx_callback, but
		 * this is SAFE because:
		 * 1. link_ctx_initialized is cleared below, so lichen_l2_input() will
		 *    check it at line ~1755 and drop any packets before using link_ctx
		 * 2. The RX thread isn't running (start() failed), so the callback
		 *    won't be invoked until a future successful start()
		 * 3. A future enable() will re-register the callback anyway
		 */
		if (ret != 0) {
			int cb_ret = lichen_lora_l2_set_rx_callback(NULL, NULL);
			if (cb_ret != 0) {
				LOG_WRN("lichen_l2: failed to clear callback on start failure (%d)", cb_ret);
			}
		}
#if HAVE_LICHEN_LINK
		/*
		 * Roll back link_ctx state on start() failure. (project-LICHEN-dq6n.20)
		 *
		 * If lichen_lora_l2_start() failed, force the next enable() to
		 * reinitialize link_ctx even if it was already marked initialized when
		 * this call began. The atomic flag is not a sufficient integrity check
		 * after abort/crash recovery; leaving it set would let a later enable
		 * skip lichen_link_init() and reuse potentially stale crypto state.
		 */
		if (ret != 0) {
			if (atomic_get(&link_ctx_initialized)) {
				atomic_set(&link_ctx_initialized, 0);
				lichen_link_cleanup(&link_ctx);
			}
		}
#endif
		/*
		 * Release mutexes now that start() has completed (or failed).
		 * On success: the RX thread is running. A concurrent disable
		 * will see link_ctx_initialized==1 and orderly stop the RX
		 * thread before cleaning up link_ctx.
		 *
		 * On failure from start(): we already rolled back the callback
		 * and link_ctx above. Mutexes were acquired at lines 1537-1538
		 * and not released since; release them now.
		 *
		 * On failure from set_rx_callback(): the early-return path above
		 * already released mutexes and returned. Execution only reaches
		 * here if set_rx_callback succeeded, so mutexes are still held.
		 */
		k_mutex_unlock(&rx_mutex);
		k_mutex_unlock(&tx_mutex);
		return ret;
	} else {
		/*
		 * lichen_lora_l2_stop() clears the RX callback before signaling
		 * the thread to exit, then joins the thread. This guarantees:
		 * 1. No NEW callbacks can start after stop() begins
		 * 2. Any in-flight callback (already past the snapshot) will still
		 *    execute and acquire rx_mutex in lichen_l2_input()
		 * 3. Thread join returns only after the loop iteration completes
		 * 4. Our mutex acquisition below waits for any in-flight callback
		 *
		 * This ordering ensures link_ctx cleanup is safe.
		 */
		int stop_ret = lichen_lora_l2_stop();
		/*
		 * If stop() aborted the RX thread (returned -ECANCELED), the thread
		 * may have been holding rx_mutex during lichen_l2_input(). We must
		 * call deinit() to reinitialize mutexes before acquiring them, or
		 * we'll deadlock. (project-LICHEN-i1gk.67)
		 */
		if (stop_ret == -ECANCELED) {
			int deinit_ret = lichen_lora_l2_deinit();
			if (deinit_ret != 0) {
				LOG_ERR("lichen_l2: deinit after abort failed (%d)", deinit_ret);
				/*
				 * SECURITY (project-LICHEN-0li1.46): Clear link_ctx_initialized
				 * even if deinit() failed. This ensures re-initialization on
				 * next enable() after the user manually recovers via deinit/init.
				 *
				 * Without this, link_ctx_initialized would remain set, causing
				 * enable() to skip link_ctx initialization and use stale state
				 * (potentially including stale cryptographic keys).
				 *
				 * We cannot safely call lichen_link_cleanup() here because we
				 * don't hold the mutexes (and can't acquire them - that's why
				 * deinit failed). The atomic clear is safe without locks.
				 * The link_ctx contents may be stale, but the next enable()
				 * will re-initialize it properly since link_ctx_initialized=0.
				 */
#if HAVE_LICHEN_LINK
				atomic_set(&link_ctx_initialized, 0);
#endif
				return deinit_ret;
			}
		}
		/*
		 * Retry incomplete queue destruction
		 * (project-LICHEN-worker6-l1qw.8.17.17.1.25).
		 *
		 * A previous disable whose deinit failed mid-queue-destroy leaves
		 * LORA_DESTROY_FAILED. stop() then reports success for the
		 * non-RUNNING state, so without this retry the disable path would
		 * skip deinit and falsely report complete teardown while the queue
		 * was never destroyed. Retry deinit (which re-enters at the destroy
		 * step) and propagate incomplete cleanup instead of reporting
		 * success.
		 */
		if (stop_ret == 0 && lichen_lora_l2_needs_destroy_retry()) {
			int deinit_ret = lichen_lora_l2_deinit();
			if (deinit_ret != 0) {
				LOG_ERR("lichen_l2: destroy retry deinit failed (%d)",
					deinit_ret);
#if HAVE_LICHEN_LINK
				atomic_set(&link_ctx_initialized, 0);
#endif
				return deinit_ret;
			}
		}
#if HAVE_LICHEN_LINK
		/*
		 * Clean up link context: wipe keys, reset sequence state.
		 * Hold both mutexes to prevent races with in-flight TX/RX:
		 * - tx_mutex: ensures lichen_l2_send() completes before cleanup
		 * - rx_mutex: ensures lichen_l2_input() completes before cleanup
		 *
		 * LOCK ORDER: tx_mutex before rx_mutex. See comment at mutex
		 * definitions (~line 217) for rationale.
		 *
		 * SECURITY: lichen_l2_input() copies link_key into a local buffer
		 * before use, but the copy happens under rx_mutex. Cleanup MUST
		 * acquire rx_mutex to ensure any in-flight RX completes first.
		 *
		 * DEADLOCK AVOIDANCE: Use trylock with timeout instead of K_FOREVER.
		 *
		 * By this point, stop() has already joined the RX thread, which means
		 * lichen_l2_input() has completed and released rx_mutex. The 100ms
		 * timeout is a defensive check - it should NEVER fire in normal
		 * operation. If it does, something unexpected happened (e.g., kernel
		 * bug, memory corruption, or an unhandled abort path).
		 *
		 * Note: lichen_l2_input() uses K_FOREVER when acquiring rx_mutex,
		 * which is correct for the callback path - it must finish signature
		 * verification etc.
		 * - Disable path (100ms): Defensive check after thread already exited
		 *
		 * The -ECANCELED path above handles aborted threads by calling deinit()
		 * to reinitialize mutexes. Return error rather than reinitializing a
		 * potentially-held mutex (UB). (project-LICHEN-0li1.7)
		 */
		k_mutex_lock(&tx_mutex, K_FOREVER);
		if (k_mutex_lock(&rx_mutex, K_MSEC(100)) != 0) {
			LOG_ERR("lichen_l2: rx_mutex timeout during disable, stop() "
				"may have left RX in bad state");
			crash_info_store(CRASH_MUTEX_FAILURE, __LINE__, 100);
			/*
			 * SECURITY (project-LICHEN-0li1.46): Clear link_ctx_initialized
			 * even though cleanup is incomplete. This ensures the next
			 * enable() will re-initialize link_ctx rather than use stale
			 * state. The link_ctx contents are NOT wiped here (we can't
			 * call lichen_link_cleanup without rx_mutex), but the flag
			 * ensures fresh initialization on next enable().
			 */
			atomic_set(&link_ctx_initialized, 0);
			k_mutex_unlock(&tx_mutex);
			return -EBUSY;
		}
		atomic_set(&link_ctx_initialized, 0);
		lichen_link_cleanup(&link_ctx);
#ifdef CONFIG_LICHEN_LINK_REPLAY_PERSIST
		lichen_replay_settings_close();
#endif
		/*
		 * Clear replay table to prevent stale windows from persisting across
		 * enable/disable cycles.
		 *
		 * Safe on dirty table: lichen_replay_table_init() does memset()
		 * which clears all entries regardless of prior state. No dynamic
		 * allocation in replay table - all entries are POD types.
		 * (project-LICHEN-tvfm.80)
		 */
		lichen_replay_table_init(&replay_table);
		/*
		 * Clear peer table to prevent stale peer keys from persisting across
		 * enable/disable cycles. SECURITY: Use secure_zero on pubkeys.
		 *
		 * CRASH SAFETY (project-LICHEN-tvfm.6): We atomically set
		 * peer_table_valid = 0 BEFORE the clearing loop. If the system
		 * crashes (power failure, watchdog) mid-loop, on restart every
		 * peer_table accessor checks peer_table_valid and treats the
		 * table as empty/invalid, preventing reads of partially-cleared
		 * or zeroed-key-with-active=true entries.
		 *
		 * THREAD SAFETY: This loop is safe without additional IRQ masking:
		 * - Called from net_if_down() which holds iface->lock (a k_mutex)
		 * - We hold both tx_mutex and rx_mutex (acquired above)
		 * - All peer_table accessors (peer_find_locked, peer_try_all_pubkeys,
		 *   lichen_peer_add) require rx_mutex, so they block until we release
		 * - No ISRs access peer_table directly
		 * Preemption by higher-priority threads is harmless since they will
		 * block on the mutex; the loop will resume and complete atomically
		 * from peer_table's perspective.
		 */
		atomic_set(&peer_table_valid, 0);
		for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
			secure_zero(peer_table[i].pubkey, sizeof(peer_table[i].pubkey));
			secure_zero(peer_table[i].eui64, sizeof(peer_table[i].eui64));
			peer_table[i].last_seen = 0;
			peer_table[i].active = false;
		}
		atomic_set(&peer_table_valid, 1);
		k_mutex_unlock(&rx_mutex);
		k_mutex_unlock(&tx_mutex);
#endif
		/*
		 * ret is only assigned in the enable branch; returning it here
		 * was uninitialized-stack garbage. An aborted RX thread
		 * (-ECANCELED) was recovered via deinit above, so it is
		 * success; any other stop() failure propagates.
		 */
		return (stop_ret == -ECANCELED) ? 0 : stop_ret;
	}
}

/**
 * @brief L2 flags handler
 *
 * Returns L2 capability flags without checking interface state.
 * This is intentional: these flags describe static hardware/protocol
 * capabilities (multicast support), not runtime state. Zephyr's net
 * subsystem may query capabilities during interface setup before
 * initialization completes, and the capabilities are constant regardless
 * of whether the interface is currently enabled. (project-LICHEN-tvfm.41)
 */
static enum net_l2_flags lichen_l2_flags(struct net_if *iface)
{
	ARG_UNUSED(iface);

	/*
	 * NET_L2_MULTICAST: Tells Zephyr this L2 can deliver IP multicast frames.
	 * LoRa is inherently broadcast - all transmissions reach all receivers,
	 * so multicast delivery works by default.
	 *
	 * NET_L2_MULTICAST_SKIP_JOIN_SOLICIT_NODE: Skip joining solicited-node
	 * multicast groups (ff02::1:ffXX:XXXX). This relies on LoRa being a true
	 * broadcast medium where every TX reaches every receiver in range. In such
	 * a medium, all nodes receive all Neighbor Solicitation messages regardless
	 * of multicast group membership, making solicited-node optimization pointless.
	 * Skipping the join avoids MLD (Multicast Listener Discovery) report traffic
	 * that would waste precious LoRa airtime for no benefit. OpenThread uses the
	 * same pattern for similar reasons.
	 *
	 * Note: We do NOT set NET_IF_IPV6_NO_MLD or NET_IF_IPV6_NO_ND flags because
	 * LICHEN uses standard IPv6 ND and MLD for all-nodes multicast. Only the
	 * solicited-node optimization is unnecessary.
	 *
	 * DESIGN ASSUMPTION: These flags assume LICHEN operates over standard LoRa
	 * (not LoRaWAN) where all transmissions are true broadcast. This assumption
	 * may NOT hold for:
	 * - LoRa devices with hardware address filtering
	 * - LoRa mesh configurations with selective forwarding
	 * - LoRaWAN Class B/C with directed downlinks
	 * If porting LICHEN to such configurations, re-evaluate whether
	 * NET_L2_MULTICAST_SKIP_JOIN_SOLICIT_NODE is appropriate.
	 */
	return NET_L2_MULTICAST | NET_L2_MULTICAST_SKIP_JOIN_SOLICIT_NODE;
}

/* Register the L2 layer */
NET_L2_INIT(LICHEN_L2, lichen_l2_recv, lichen_l2_send, lichen_l2_enable,
	    lichen_l2_flags);

/*
 * L2 context type for NET_DEVICE_INIT.
 *
 * This struct is intentionally empty: Zephyr's NET_DEVICE_INIT macro requires
 * a context type for the L2 layer, but LICHEN uses module-static state rather
 * than per-interface context. The empty struct satisfies the macro's type
 * requirements while keeping all actual state in static variables above.
 *
 * A dummy field is included to avoid zero-size struct warnings from compilers
 * with -Wpedantic or -Wempty-struct. (project-LICHEN-i1gk.52)
 */
struct lichen_l2_ctx {
	uint8_t unused;  /* Avoid zero-size struct warning */
};

/* Define the context type macro for NET_DEVICE_INIT */
#define NET_L2_GET_CTX_TYPE_LICHEN_L2 struct lichen_l2_ctx

/*
 * Network interface API - provides init callback.
 * We use Zephyr's dummy API structure since we don't have hardware-specific
 * send/recv callbacks (those go through L2 callbacks instead).
 *
 * The iface_api structure provides the init callback. We don't implement
 * start/stop here since L2 enable/disable handles that.
 */
static struct net_if_api lichen_iface_api = {
	.init = lichen_l2_iface_init,
};

/*
 * Register LICHEN as a network device. This creates a net_if and wires
 * it to our L2 layer. The device is a software-defined interface -
 * actual hardware (LoRa radio) is accessed via lora_l2.c.
 *
 * Initialization priority: CONFIG_KERNEL_INIT_PRIORITY_DEFAULT is correct
 * for network interfaces. Zephyr's driver subsystem initializes hardware
 * drivers (the HAL-selected zephyr,lora radio and hwinfo) at earlier
 * priorities (PRE_KERNEL_1/2 or POST_KERNEL with lower priority values),
 * so they are available when lichen_l2_iface_init() runs. If a dependency
 * is missing on a custom board, the init function sets iface_init_failed
 * and logs an error.
 *
 * Ordering contract with lora_l2.c: callers must not start the LoRa L2
 * service before lichen_l2_iface_init() has called lichen_lora_l2_init(),
 * unless they explicitly called lichen_lora_l2_init() themselves first.
 * Direct start from LORA_UNINIT fails with -EINVAL by design.
 * (project-LICHEN-tvfm.62)
 */
NET_DEVICE_INIT(lichen_l2_dev,      /* Device ID */
		"LICHEN",           /* Device name */
		NULL,               /* Init function (NULL = use L2 init) */
		NULL,               /* PM device (none) */
		NULL,               /* Device data (none) */
		NULL,               /* Config (none) */
		CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
		&lichen_iface_api,  /* API */
		LICHEN_L2,          /* L2 layer */
		NET_L2_GET_CTX_TYPE_LICHEN_L2,
		LICHEN_L2_MTU);

/**
 * @brief Initialize the LICHEN L2 network interface
 *
 * Called by Zephyr's network stack during NET_DEVICE_INIT. This function:
 * 1. Initializes the LoRa L2 driver (lichen_lora_l2_init)
 * 2. Retrieves or generates a stable EUI-64 from hardware ID
 * 3. Sets the link-layer address on the net_if
 * 4. Initializes the LICHEN link context for framing/crypto
 * 5. Caches the net_if pointer for RX callback delivery
 * 6. Registers the LoRa RX callback
 *
 * @note lichen_lora_l2_init() is the required first operation. It validates
 * the HAL LoRa device, generates the stable EUI-64, and transitions
 * lora_l2.c from LORA_UNINIT to LORA_STOPPED. The EUI-64 copy below is a runtime
 * invariant check that this ordering completed before any LICHEN link
 * context or net_if state observes the LoRa identity.
 *
 * @note Zephyr's net_if_api.init callback signature is void(*)(struct net_if*),
 * so errors cannot be returned to the caller. Instead, on any failure this
 * function sets the iface_init_failed atomic flag and returns early. All L2
 * operations (send, recv, RX callback) check this flag and fail gracefully.
 *
 * @param iface The network interface being initialized (from NET_DEVICE_INIT)
 */
void lichen_l2_iface_init(struct net_if *iface)
{
	if (iface == NULL) {
		LOG_ERR("lichen_l2: iface is NULL");
		atomic_set(&iface_init_failed, 1);
		return;
	}

	int ret;

	LOG_INF("lichen_l2: initializing interface");
	if (atomic_get(&iface_init_failed)) {
		LOG_ERR("lichen_l2: refusing retry after failed initialization");
		return;
	}

	/*
	 * Do NOT clear iface_init_failed here (project-LICHEN-i1gk.63).
	 *
	 * Clearing optimistically at the start creates confusing control flow:
	 * if a previous init partially succeeded (e.g., lora_l2_init passed but
	 * get_eui64 failed), clearing the flag here and then having lichen_lora_l2_init()
	 * return 0 (idempotent success) would temporarily show success before a later
	 * check re-sets the flag.
	 *
	 * The iface_init_failed flag is:
	 * - Set on any failure path (via atomic_set(&iface_init_failed, 1))
	 * - Never explicitly cleared here; first boot starts at 0 (static init)
	 * - Checked by send/recv/enable to reject operations on half-initialized state
	 *
	 * After a failed init, the check above rejects retry attempts, ensuring
	 * failure is permanent until system restart.
	 * This is fail-safe by design.
	 */

	/* Initialize LoRa driver */
	ret = lichen_lora_l2_init();
	if (ret < 0) {
		LOG_ERR("lichen_l2: LoRa L2 init failed (%d)", ret);
		atomic_set(&iface_init_failed, 1);
		return;
	}

	uint8_t eui64[LICHEN_EUI64_LEN];
	ret = lichen_lora_l2_copy_eui64(eui64);
	if (ret < 0) {
		LOG_ERR("lichen_l2: LoRa L2 init ordering invariant failed, "
			"EUI-64 unavailable after init (%d)", ret);
		atomic_set(&iface_init_failed, 1);
		return;
	}

	/*
	 * Copy EUI-64 to local storage for net_if_set_link_addr().
	 * Zephyr stores the pointer directly; we must not cast away const from
	 * lora_state.eui64 to avoid UB if Zephyr ever writes to it.
	 * (project-LICHEN-ybal.15/.16)
	 */
	memcpy(iface_link_addr, eui64, LICHEN_L2_ADDR_LEN);
	/* NET_LINK_IEEE802154 is closest match for 8-byte EUI-64 addresses */
	ret = net_if_set_link_addr(iface, iface_link_addr, LICHEN_L2_ADDR_LEN,
				   NET_LINK_IEEE802154);
	if (ret < 0) {
		LOG_ERR("lichen_l2: net_if_set_link_addr failed (%d)", ret);
		atomic_set(&iface_init_failed, 1);
		return;
	}

#if HAVE_LICHEN_LINK
	/*
	 * Initialize link context before enabling RX.
	 *
	 * NOTE: This duplicates logic in lichen_l2_enable() intentionally.
	 * See comment there (~line 419) for rationale: boot-time init needs no
	 * mutexes, while re-enable after disable must hold both mutexes and
	 * secure_zero() before re-init.
	 *
	 * replay_table is static, so zero-initialized at boot (C11 6.7.9p10).
	 * lichen_replay_table_init() does memset anyway, which is idempotent
	 * and handles future cases where table might not be zero.
	 * (project-LICHEN-tvfm.80)
	 *
	 * SECURITY (project-LICHEN-tvfm.87): If re-initializing after a previous
	 * init (failed or successful), clean up existing key material before
	 * calling lichen_link_init(). At boot, link_ctx_initialized is 0 (static
	 * init) so cleanup is skipped. On re-init, we hold mutexes and securely
	 * wipe any existing keys to prevent stale key material from persisting.
	 *
	 * Init/cleanup symmetry (project-LICHEN-tvfm.111): The check for
	 * link_ctx_initialized prevents calling lichen_link_init() on an already-
	 * initialized context without cleanup. At boot this is a no-op (flag is 0).
	 * On re-init, we call lichen_link_cleanup() first. The invariant check
	 * at the lichen_iface_read() != NULL check catches double-iface_init attempts,
	 * which is the only path that could bypass this cleanup.
	 */
	if (atomic_get(&link_ctx_initialized)) {
		/*
		 * Re-initialization path: hold both mutexes during cleanup to
		 * synchronize with any in-flight RX/TX. Lock order matches
		 * lichen_l2_enable() and fail_late_init (tx_mutex before rx_mutex).
		 *
		 * SECURITY: Clear peer_table with secure_zero while holding mutexes
		 * to prevent stale entries from being accessed during cleanup window.
		 * (project-LICHEN-i1gk.22)
		 */
		k_mutex_lock(&tx_mutex, K_FOREVER);
		k_mutex_lock(&rx_mutex, K_FOREVER);
		atomic_set(&link_ctx_initialized, 0);
		secure_zero(peer_table, sizeof(peer_table));
		lichen_link_cleanup(&link_ctx);
		k_mutex_unlock(&rx_mutex);
		k_mutex_unlock(&tx_mutex);
	}
	/*
	 * Initialize link_ctx via shared helper. At boot (first call), no mutexes
	 * are needed since no concurrent TX/RX exists. On re-init (after failed init
	 * and cleanup), the re-init block above already held mutexes, but the boot
	 * path also holds no mutexes at this point. The helper's secure_zero + init
	 * is safe without mutex coverage here because no other thread can access
	 * link_ctx before lichen_iface is set and the RX callback is registered.
	 *
	 * peer_table init is done separately from init_link_ctx_locked() because
	 * the enable path intentionally does NOT clear peer_table on re-enable
	 * (only replay table resets). The boot path clears and validates the table.
	 */
	if (init_link_ctx_locked(eui64) < 0) {
		atomic_set(&iface_init_failed, 1);
		return;
	}
	secure_zero(peer_table, sizeof(peer_table));
	atomic_set(&peer_table_valid, 1);
#endif

	/*
	 * Cache interface for RX callback.
	 *
	 * INVARIANT (project-LICHEN-1www.46): lichen_iface is set exactly once
	 * during initialization and never cleared, enforced structurally by
	 * lichen_iface_write() (set-once intent) and lichen_iface_read().
	 * This allows lora_rx_callback() to read it without synchronization.
	 *
	 * Recovery note (project-LICHEN-tvfm.93): If a previous init attempt
	 * failed after setting lichen_iface (e.g., in fail_late_init), the
	 * iface pointer persists intentionally. The failure state is permanent
	 * until reboot - this is fail-safe by design. A retry would reach this
	 * check and fail with the message below, which correctly identifies
	 * the condition (iface already set) even if the original cause was a
	 * late init failure rather than a true invariant violation.
	 */
	if (lichen_iface_read() != NULL) {
		LOG_ERR("lichen_l2: iface already set (init requires reboot after failure)");
		atomic_set(&iface_init_failed, 1);
		return;
	}
	lichen_iface_write(iface);

	/* Register RX callback - must happen AFTER link_ctx is initialized */
	ret = lichen_lora_l2_set_rx_callback(lora_rx_callback, NULL);
	if (ret != 0) {
		LOG_ERR("lichen_l2: failed to set RX callback (%d)", ret);
		atomic_set(&iface_init_failed, 1);
		return;
	}

#if HAVE_LICHEN_LINK
	/*
	 * link_ctx_initialized already set by init_link_ctx_locked() above.
	 * The helper sets it after link_ctx init and replay table init, which
	 * is before RX callback registration. This is safe: no callbacks can
	 * fire before lichen_lora_l2_set_rx_callback() registers the handler.
	 */
#endif

	/* Derive and log link-local address */
	ret = lichen_log_link_local_from_eui64(eui64, NULL);
	if (ret < 0) {
		/* Must undo RX callback registration; see fail_late_init cleanup */
		goto fail_late_init;
	}

	/* Derive and add primary Yggdrasil address (project-LICHEN-p8i6)
	 * as NET_ADDR_PREFERRED. Key may not be loaded yet in all paths;
	 * address added when identity available. */
	uint8_t pubkey[32];
	bool has_key = false;
	ret = lichen_link_copy_identity(&link_ctx, NULL, pubkey, NULL, &has_key);
	if (ret == 0 && has_key) {
		struct in6_addr ygg;
		ret = lichen_yggdrasil_addr(pubkey, &ygg);
		if (ret == 0) {
			char addr_str[LICHEN_IPV6_ADDR_STR_LEN];
			if (lichen_ipv6_addr_to_str(&ygg, addr_str, sizeof(addr_str)) == 0) {
				LOG_INF("lichen_l2: primary yggdrasil %s", addr_str);
			}
			(void)net_if_ipv6_addr_add(iface, &ygg, NET_ADDR_MANUAL, 0);
		}
	}

#if HAVE_LICHEN_LINK
#if IS_ENABLED(CONFIG_STATS)
	lichen_l2_stats_init();
#endif
	/* Warn if peer table is empty — node cannot receive authenticated
	 * traffic until peers are provisioned via lichen_peer_add() or
	 * CONFIG_LICHEN_L2_DEV_PROVISIONING. (project-LICHEN-i1gk.80) */
	{
		bool peer_table_empty = true;
		for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
			if (peer_table[i].active) {
				peer_table_empty = false;
				break;
			}
		}
		if (peer_table_empty) {
			LOG_WRN("lichen_l2: peer table empty — no authenticated RX until peers are provisioned");
		}
	}
	LOG_INF("lichen_l2: initialized (full framing)");
#else
	LOG_WRN("lichen_l2: initialized (RAW MODE - no framing/crypto)");
#endif
	return;

fail_late_init:
	/*
	 * Cleanup on failure after RX callback was registered (project-LICHEN-yw7i.20).
	 * Clear callback and link_ctx state. The iface_init_failed atomic flag prevents
	 * lora_rx_callback() from operating on half-initialized state.
	 *
	 * SECURITY (project-LICHEN-3pun.15): Hold BOTH mutexes during link_ctx cleanup
	 * to synchronize with any in-flight RX callback and maintain consistent lock
	 * ordering with lichen_l2_enable(). The race scenario:
	 * 1. RX callback is registered (line ~898)
	 * 2. link_ctx_initialized is set (line ~910)
	 * 3. lichen_log_link_local_from_eui64() fails -> goto fail_late_init
	 * 4. Meanwhile, an RX callback is in-flight and has passed the
	 *    atomic_get(&link_ctx_initialized) check in lichen_l2_input()
	 * 5. Without mutex, cleanup could race with the in-flight callback
	 *
	 * LOCK ORDER (project-LICHEN-tvfm.56): tx_mutex before rx_mutex, matching
	 * lichen_l2_enable() enable/disable paths. See mutex definition comments
	 * (~line 217) for the canonical ordering rule. Although iface_init runs at
	 * boot with no concurrent TX, maintaining consistent ordering prevents
	 * future deadlock if init/enable sequences ever overlap.
	 *
	 * SECURITY (project-LICHEN-tvfm.36): Set iface_init_failed FIRST, before
	 * unregistering the callback. This ensures any callback invoked between
	 * registration (line ~1106) and cleanup sees the flag and bails out
	 * immediately in lora_rx_callback() (line ~1013). Without this ordering,
	 * a callback could pass the iface_init_failed check before the flag is set
	 * and proceed into lichen_l2_input() while cleanup is in progress.
	 */
	atomic_set(&iface_init_failed, 1);
	(void)lichen_lora_l2_set_rx_callback(NULL, NULL);
#if HAVE_LICHEN_LINK
	k_mutex_lock(&tx_mutex, K_FOREVER);
	k_mutex_lock(&rx_mutex, K_FOREVER);
	atomic_set(&link_ctx_initialized, 0);
	/*
	 * SECURITY (project-LICHEN-i1gk.23): Clear peer_table with secure_zero
	 * to prevent stale peer keys from persisting after init failure. Matches
	 * the disable path (lichen_l2_enable) which also clears peer_table.
	 * Although unlikely, peers could have been added by another thread between
	 * link_ctx_initialized being set and the init failure.
	 */
	secure_zero(peer_table, sizeof(peer_table));
	lichen_link_cleanup(&link_ctx);
	k_mutex_unlock(&rx_mutex);
	k_mutex_unlock(&tx_mutex);
#endif
}

void lichen_l2_reinit_after_abort(void)
{
	/*
	 * SECURITY: DANGEROUS FUNCTION - INTERNAL USE ONLY
	 *
	 * Reinitialize rx_mutex after RX thread abort recovery.
	 * (project-LICHEN-dq6n.22, project-LICHEN-tvfm.16)
	 *
	 * This function reinitializes a mutex that may still be held, which is
	 * UNDEFINED BEHAVIOR per POSIX and Zephyr semantics. If called at the
	 * wrong time, it can corrupt kernel data structures and cause crashes
	 * or deadlocks in subsequent operations.
	 *
	 * PRECONDITIONS (caller MUST ensure):
	 * 1. The lora_l2 module is in DEINITING state (lichen_lora_l2_deinit()
	 *    has been called and is executing)
	 * 2. The RX thread has been joined or forcibly aborted
	 * 3. No concurrent RX operations are possible
	 *
	 * This function is exported only because rx_mutex lives in this module
	 * while deinit lives in lora_l2.c. It MUST ONLY be called from
	 * lichen_lora_l2_deinit(). Any other caller will cause undefined behavior.
	 *
	 * The only truly safe recovery from a thread-abort scenario is a full
	 * system reset (k_sys_reboot). See lora_l2.c:lichen_lora_l2_deinit()
	 * for the complete security analysis.
	 */

	/*
	 * Precondition check: the module must NOT be running (project-LICHEN-i1gk.55).
	 *
	 * ARCHITECTURAL LIMITATION: This check uses is_running() which returns false
	 * for STOPPED, DEINITING, ABORTED, and UNINIT states. Ideally we would verify
	 * specifically that we're in DEINITING state, but:
	 * 1. There's no is_deiniting() API exposed by lora_l2
	 * 2. Adding one would expand the API surface for a single internal caller
	 * 3. This function is INTERNAL-ONLY (called exclusively from deinit())
	 *
	 * The weaker check is acceptable because:
	 * - The dangerous case (RUNNING) is caught and returns early
	 * - STOPPED: Caller made a logic error, but mutex is valid - reinit is harmless
	 * - UNINIT: Mutex was never corrupted - reinit is harmless
	 * - ABORTED: This is the intended state before deinit transitions to DEINITING
	 * - DEINITING: Correct state
	 *
	 * Only RUNNING would corrupt state, and that is rejected.
	 */
	if (lichen_lora_l2_is_running()) {
		LOG_ERR("lichen_l2: reinit_after_abort called while running (caller bug)");
		return;  /* Don't corrupt mutex; caller must stop first */
	}

	/*
	 * Abort recovery is driven from lora_l2.c, but link_ctx_initialized is
	 * local state in this module. Clear it here so the next enable path does
	 * not skip lichen_link_init() after an aborted RX path.
	 */
	atomic_set(&link_ctx_initialized, 0);

	/*
	 * k_mutex_init() cannot fail in kernel mode (only in userspace syscall path).
	 * Cast to void to suppress unused-result warnings.
	 */
	(void)k_mutex_init(&rx_mutex);
	LOG_DBG("lichen_l2: rx_mutex reinitialized after abort recovery");
}
