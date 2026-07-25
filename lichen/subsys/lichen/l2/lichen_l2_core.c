/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2_core.c
 * @brief LICHEN L2 shared state and compile-time assertions
 *
 * Contains static state definitions (buffers, mutexes, link_ctx, replay_table,
 * peer_table, stats atomics) and BUILD_ASSERT macros.
 */

#include "lichen_l2_internal.h"

#ifdef CONFIG_LICHEN_L2_DEV_PROVISIONING
#include <ctype.h>
#include <stdlib.h>
#include "ipv6.h" /* zephyr/subsys/net/ip — net_ipv6_nbr_add() */
#endif

LOG_MODULE_REGISTER(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

/* ─── Compile-time assertions ────────────────────────────────────────────── */

/*
 * Compile-time assertion: MTU constants must match between layers.
 * LICHEN_L2_MTU (lichen_l2.h) is the IPv6 MTU exposed to the network stack.
 * LICHEN_LORA_MTU (lora_l2.h) is the payload capacity after LoRa framing overhead.
 * If these diverge, one layer will reject packets the other accepts, causing
 * silent packet loss or -EMSGSIZE errors with no obvious root cause.
 * (project-LICHEN-9j70.1)
 */
BUILD_ASSERT(LICHEN_L2_MTU == LICHEN_LORA_MTU,
	     "MTU mismatch: LICHEN_L2_MTU and LICHEN_LORA_MTU must be equal");

/*
 * Compile-time assertion: address sizes must match between layers.
 * iface_link_addr uses LICHEN_L2_ADDR_LEN for its buffer, but we copy from
 * lora_state.eui64 which uses LICHEN_LORA_L2_ADDR_LEN. These must be equal
 * to avoid buffer overread in lichen_l2_iface_init(). (project-LICHEN-1www.29)
 */
BUILD_ASSERT(LICHEN_L2_ADDR_LEN == LICHEN_LORA_L2_ADDR_LEN,
	     "Address length mismatch: LICHEN_L2_ADDR_LEN and LICHEN_LORA_L2_ADDR_LEN must be equal");

/*
 * Init-order contract with lora_l2.c (project-LICHEN-d7ub.59):
 * lichen_l2_iface_init() owns the network-interface startup path and calls
 * lichen_lora_l2_init() before copying the EUI-64, registering callbacks, or
 * enabling TX/RX. That init path requires an enabled HAL-owned zephyr,lora
 * chosen node; if the board overlay disables it, no runtime ordering can make
 * start() succeed.
 */
BUILD_ASSERT(LICHEN_HAL_HAS_LORA_DEVICE,
	     "LICHEN L2 requires an enabled devicetree chosen zephyr,lora before "
	     "NET_DEVICE_INIT runs lichen_l2_iface_init()");

#if !HAVE_LICHEN_LINK
#error "CONFIG_LICHEN_LINK is required before lichen_l2.c can use LICHEN link constants"
#endif

/*
 * SECURITY: Require LICHEN_LINK for production builds (project-LICHEN-9j70.16).
 *
 * Without CONFIG_LICHEN_LINK, packets are sent as raw IPv6 over LoRa with:
 * - No MIC/CRC protection (corruption goes undetected)
 * - No SCHC compression (40-byte IPv6 header wastes MTU)
 * - No replay protection
 * - No interoperability with LICHEN-framed nodes
 *
 * The raw mode was useful for early bring-up but is not suitable for any
 * deployment. If you hit this error, enable CONFIG_LICHEN_LINK in your prj.conf.
 */
BUILD_ASSERT(HAVE_LICHEN_LINK,
	     "CONFIG_LICHEN_LINK is required: raw IPv6-over-LoRa provides no "
	     "security, compression, or interoperability. Enable LICHEN_LINK "
	     "in prj.conf or menuconfig.");

/*
 * Compile-time assertion: lichen_peer_add() API array sizes must match constants.
 *
 * The function signature uses array syntax (eui64[8], pubkey[32]) but C arrays
 * decay to pointers, providing no runtime size enforcement. These BUILD_ASSERTs
 * verify the documented sizes match the internal constants used by memcpy().
 * If the constants change, the API documentation and signature must be updated.
 * (project-LICHEN-tvfm.7)
 */
BUILD_ASSERT(LICHEN_EUI64_LEN == 8,
	     "lichen_peer_add() eui64[8] size mismatch: update API if LICHEN_EUI64_LEN changed");
BUILD_ASSERT(LICHEN_L2_PUBKEY_LEN == 32,
	     "lichen_peer_add() pubkey[32] size mismatch: update API if LICHEN_L2_PUBKEY_LEN changed");

BUILD_ASSERT(MAX_LORA_FRAME == 255,
	     "MAX_LORA_FRAME must be 255 if LICHEN_LORA_MAX_PHY_PAYLOAD changes");

/*
 * Validate LICHEN_MIN_FRAME_LEN derivation.
 *
 * These values are defined by the LICHEN spec (section 4) and cannot change
 * without a protocol revision. The BUILD_ASSERTs document the derivation.
 *
 * Uses authoritative constants from link.h to catch drift if the frame format
 * changes (project-LICHEN-1www.41). The MIC and addr fields have no shared
 * constant for the "zero" case (unsigned frames, broadcast), so they remain
 * local.
 */
BUILD_ASSERT(LICHEN_MIN_FRAME_LEN ==
	     LICHEN_FRAME_LEN_FIELD_LEN +
	     LICHEN_FRAME_LLSEC_LEN +
	     LICHEN_FRAME_EPOCH_LEN +
	     LICHEN_FRAME_SEQNUM_LEN +
	     LICHEN_FRAME_MIN_ADDR +
	     LICHEN_FRAME_MIN_MIC,
	     "LICHEN_MIN_FRAME_LEN does not match frame component sizes");

/*
 * Validate LICHEN_FRAME_MAX_OVERHEAD against frame format constants.
 *
 * The overhead (55 bytes) is tuned for MTU = 200 bytes, relying on SCHC
 * compression to shrink IPv6 headers from 40 bytes to ~3-6 bytes. The
 * actual on-air signed frame fits within 255 bytes because SCHC gains
 * more than offset the signature cost.
 *
 * These assertions catch drift if schnorr48.h or frame format constants
 * change without updating LICHEN_FRAME_MAX_OVERHEAD in lora_l2.h.
 *
 * SECURITY: If LICHEN_SIG_LEN increases, review LICHEN_FRAME_MAX_OVERHEAD
 * to ensure signed frames still fit within the LoRa PHY limit.
 */

/*
 * Assert: LICHEN_LORA_FRAME_OVERHEAD derives from frame format constants.
 *
 * Derivation: fixed header (5 bytes) + Schnorr-48 signature (48 bytes)
 * = 53 bytes base signed overhead. The constant adds 2 bytes of headroom
 * for SCHC rule ID and future address field expansion: 53 + 2 = 55.
 *
 * This assertion prevents silent drift when LICHEN_FRAME_FIXED_HEADER_LEN
 * or LICHEN_SIG_LEN change without updating lora_l2.h.
 * (project-LICHEN-gy7h.9)
 */
BUILD_ASSERT(LICHEN_LORA_FRAME_OVERHEAD ==
	     LICHEN_FRAME_FIXED_HEADER_LEN + LICHEN_SIG_LEN + 2,
	     "LICHEN_LORA_FRAME_OVERHEAD derivation stale - update lora_l2.h");

/*
 * Assert: signature length has not changed.
 * LICHEN_FRAME_MAX_OVERHEAD was calculated assuming 48-byte signatures.
 * If this assertion fails, recalculate the overhead constant.
 */
BUILD_ASSERT(LICHEN_SIG_LEN == 48,
	     "LICHEN_SIG_LEN changed - update LICHEN_FRAME_MAX_OVERHEAD in lora_l2.h");

/*
 * Assert: frame header size has not changed.
 * LICHEN_FRAME_MAX_OVERHEAD is independent of the 5-byte unsigned minimum.
 * If this assertion fails, recalculate the overhead constant.
 */
BUILD_ASSERT(LICHEN_FRAME_MIN_HEADER_SIZE == 5,
	     "Frame header size changed - update LICHEN_FRAME_MAX_OVERHEAD in lora_l2.h");

/*
 * Compile-time validation of peer table configuration.
 *
 * CONFIG_LICHEN_LINK_MAX_NEIGHBORS sets the static peer_table size.
 * Constraints (from lichen/subsys/lichen/link/Kconfig):
 * - Range: 4-64 (enforced by Kconfig)
 * - Memory: ~56 bytes per entry (8 EUI-64 + 32 pubkey + 8 last_seen + 1 active + padding)
 *
 * At max (64 neighbors): ~3.6 KB RAM for peer table alone, plus ~1.3 KB
 * for replay windows (CONFIG_LICHEN_LINK_MAX_NEIGHBORS entries in replay_table).
 *
 * The upper bound (64) balances RAM budget against mesh network size.
 * Most deployments need far fewer peers (8-16 is typical for a mesh node).
 * (project-LICHEN-tvfm.33)
 */
BUILD_ASSERT(CONFIG_LICHEN_LINK_MAX_NEIGHBORS >= 4,
	     "CONFIG_LICHEN_LINK_MAX_NEIGHBORS must be at least 4 for basic mesh operation");
BUILD_ASSERT(CONFIG_LICHEN_LINK_MAX_NEIGHBORS <= 64,
	     "CONFIG_LICHEN_LINK_MAX_NEIGHBORS exceeds maximum (64) - reduce to limit RAM usage");

/*
 * PLATFORM CONSTRAINT: This code requires single-core execution.
 * Zephyr's atomic_set()/atomic_get() do NOT provide memory ordering
 * guarantees (no release/acquire semantics). On single-core platforms,
 * program order guarantees visibility.
 * (project-LICHEN-tvfm.112)
 */
#if defined(CONFIG_SMP) || (defined(CONFIG_MP_MAX_NUM_CPUS) && CONFIG_MP_MAX_NUM_CPUS > 1)
BUILD_ASSERT(0, "LICHEN L2 requires single-core: atomic_t usage lacks memory barriers. "
		"Disable CONFIG_SMP or ensure CONFIG_MP_MAX_NUM_CPUS == 1.");
#endif

/* ─── Static state definitions ───────────────────────────────────────────── */

/*
 * TX/RX scratch buffers and their protecting mutexes.
 *
 * Buffer sizing: LICHEN_L2_MTU + IPV6_BASE_HDR_LEN + OSCORE_MAX_OVERHEAD = 264 bytes.
 *
 * LIMITATION (project-LICHEN-tvfm.97): IPv6 extension headers other than OSCORE
 * are NOT supported.
 *
 * PORTABILITY NOTE (project-LICHEN-i1gk.95): These buffers are not cache-line
 * aligned. On Cortex-M0/M3/M4 (no cache) this is fine. On Cortex-M7/M33 with
 * cache, if the LoRa driver uses DMA, these buffers may need cache-line alignment.
 */
uint8_t tx_ipv6_buf[LICHEN_L2_MTU + IPV6_BASE_HDR_LEN + OSCORE_MAX_OVERHEAD];
uint8_t tx_frame_buf[MAX_LORA_FRAME];
K_MUTEX_DEFINE(tx_mutex);  /* Lock order: 1st (before rx_mutex) */

uint8_t rx_ipv6_buf[LICHEN_L2_MTU + IPV6_BASE_HDR_LEN + OSCORE_MAX_OVERHEAD];
K_MUTEX_DEFINE(rx_mutex);  /* Lock order: 2nd (after tx_mutex) */

#if HAVE_LICHEN_LINK
/* Link context for framing */
struct lichen_link_ctx link_ctx;

/*
 * Replay protection table for received frames.
 *
 * SECURITY (project-LICHEN-bbti, replay.h:117): Replay windows allocated ONLY
 * after Schnorr-48 verification succeeds in peer_try_all_pubkeys() (constant-time
 * full scan of peer_table) + authenticate_inner_payload() + commit_replay().
 * No unauthenticated path to lichen_replay_get() or table mutation. Full table
 * fails closed (no LRU eviction of legitimate state). Old LRU poisoning via
 * distinct EUIs + weak MIC fixed by mandatory signatures (project-LICHEN-rg8t).
 */
struct lichen_replay_table replay_table;

/* Peer table */
struct lichen_peer_entry peer_table[CONFIG_LICHEN_LINK_MAX_NEIGHBORS];

/* Peer table validity flag */
atomic_t peer_table_valid;

/* Link context initialization flag */
atomic_t link_ctx_initialized;

#if defined(CONFIG_LICHEN_ADAPTIVE_SF_ENABLED)
struct lichen_gradient_table *sf_gradient_table;
#endif

#ifdef CONFIG_LICHEN_L2_TEST_HOOKS
atomic_t test_tx_packets;
atomic_t test_rx_frames;
atomic_t test_rx_injected_packets;
K_MUTEX_DEFINE(test_stats_mutex);
uint8_t test_last_injected[LICHEN_L2_TEST_CAPTURE_MAX];
size_t test_last_injected_len;
#endif
#endif /* HAVE_LICHEN_LINK */

/*
 * Cached interface pointer for RX callback.
 *
 * INVARIANT (project-LICHEN-ybal.4, project-LICHEN-0zj6.13): Write-once-read-many.
 * Set exactly once in lichen_l2_iface_init(), never cleared.
 */
struct net_if *lichen_iface;

/*
 * Initialization error flag.
 *
 * Set to 1 if lichen_l2_iface_init() failed partway through initialization.
 * Checked by lichen_l2_send(), lichen_l2_enable(), and lora_rx_callback() to
 * prevent operating on a half-initialized interface. (project-LICHEN-1ojj.2)
 */
atomic_t iface_init_failed;

/*
 * Local copy of link-layer address for net_if_set_link_addr().
 *
 * Zephyr's net_if stores the pointer directly without copying, so we must
 * provide storage that persists for the interface lifetime.
 * (project-LICHEN-ybal.15/.16)
 */
uint8_t iface_link_addr[LICHEN_L2_ADDR_LEN];

/*
 * TX/RX outcome counters — cheap ops visibility into the data path (which
 * otherwise fails only into logs). Read via lichen_l2_get_tx_stats() /
 * lichen_l2_get_rx_stats().
 */
atomic_t tx_stat_attempts;
atomic_t tx_stat_errors;
atomic_t tx_stat_last_err;
atomic_t rx_stat_frames;
atomic_t rx_stat_accepted;
atomic_t rx_stat_last_err;

/* ─── Helper functions ───────────────────────────────────────────────────── */

int lichen_l2_to_zephyr_errno(int ret)
{
#if HAVE_LICHEN_ERRNO
	if (ret == -LICHEN_EAUTH) {
		return -EACCES;
	}
#endif
	return ret;
}
