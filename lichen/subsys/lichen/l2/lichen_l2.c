/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2.c
 * @brief LICHEN Zephyr L2 network interface implementation
 *
 * Implements Zephyr's struct net_l2 callbacks to bridge the IPv6 stack
 * to the LoRa radio via SCHC compression and LICHEN link framing.
 */

#include "lichen_l2.h"
#include "lora_l2.h"
#include "ipv6_addr.h"
#include "crash_info.h"

#include <zephyr/kernel.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include <lichen/hal.h>
#include <monocypher.h>
#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
#include <lichen/app_identity/app_identity.h>
#endif

#include <string.h>
#ifdef CONFIG_LICHEN_L2_DEV_PROVISIONING
#include <ctype.h>
#include <stdlib.h>
#include "ipv6.h" /* zephyr/subsys/net/ip — net_ipv6_nbr_add() */
#endif

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

LOG_MODULE_REGISTER(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

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

#include "lichen_util.h"

/*
 * Include LICHEN link layer if available.
 *
 * Required symbols from these headers (must stay inside HAVE_LICHEN_LINK guards):
 *   link.h:     lichen_link_tx(), lichen_link_rx(), lichen_link_frame_overhead(),
 *               struct lichen_link_rx_ctx, struct lichen_link_tx_ctx
 *   link_ctx.h: LICHEN_LINK_KEY_LEN, struct lichen_link_ctx, lichen_link_init(),
 *               lichen_link_cleanup()
 *   schc.h:     lichen_schc_compress(), lichen_schc_decompress() (stateless - no init)
 */
#if defined(CONFIG_LICHEN_LINK)
#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/replay.h>
#include <lichen/schc.h>
#define HAVE_LICHEN_LINK 1
#else
#define HAVE_LICHEN_LINK 0
#endif

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

static int lichen_l2_to_zephyr_errno(int ret)
{
#if HAVE_LICHEN_ERRNO
	if (ret == -LICHEN_EAUTH) {
		return -EACCES;
	}
#endif
	return ret;
}

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

/* Maximum frame size for LoRa */
#define MAX_LORA_FRAME 255

/*
 * Minimum valid LICHEN frame size.
 *
 * Wire format (spec section 4, python/src/lichen/link/frame.py):
 *   Length(1) + LLSec(1) + Epoch(1) + SeqNum(2) + DstAddr(0-8) + Payload + MIC(0/48)
 *
 * Absolute minimum (broadcast, unsigned, empty payload):
 *   1 + 1 + 1 + 2 + 0 + 0 + 0 = 5 bytes
 *
 * Note: source address is NOT in the wire format; it's derived from context
 * (signature verification or out-of-band information).
 *
 * SECURITY: Early rejection of runt frames prevents out-of-bounds reads
 * in lichen_link_rx() before MIC validation can occur.
 *
 * MIC size note: unsigned frames have no MIC. Signed frames carry a
 * 48-byte Schnorr signature, which is validated by lichen_link_rx().
 */
#define LICHEN_MIN_FRAME_LEN 5

/*
 * Validate LICHEN_MIN_FRAME_LEN derivation.
 *
 * These values are defined by the LICHEN spec (section 4) and cannot change
 * without a protocol revision. The BUILD_ASSERTs document the derivation.
 *
 * (project-LICHEN-1www.41): Use authoritative constants from link.h where
 * available (LICHEN_MIC_32_LEN) to catch drift. Header field sizes are
 * protocol-defined with no shared constant, so we define them locally but
 * validate against LICHEN_MIN_FRAME_LEN = 5 per spec.
 */
#define LICHEN_FRAME_LENGTH_FIELD 1
#define LICHEN_FRAME_LLSEC_FIELD  1
#define LICHEN_FRAME_EPOCH_FIELD  1
#define LICHEN_FRAME_SEQNUM_FIELD 2
#define LICHEN_FRAME_MIN_MIC      0
#define LICHEN_FRAME_MIN_ADDR     0  /* broadcast/NONE mode has 0 addr bytes */

BUILD_ASSERT(LICHEN_MIN_FRAME_LEN ==
	     LICHEN_FRAME_LENGTH_FIELD +
	     LICHEN_FRAME_LLSEC_FIELD +
	     LICHEN_FRAME_EPOCH_FIELD +
	     LICHEN_FRAME_SEQNUM_FIELD +
	     LICHEN_FRAME_MIN_ADDR +
	     LICHEN_FRAME_MIN_MIC,
	     "LICHEN_MIN_FRAME_LEN does not match frame component sizes");

/*
 * Validate LICHEN_LORA_FRAME_OVERHEAD against frame format constants.
 *
 * The overhead (55 bytes) is tuned for MTU = 200 bytes, relying on SCHC
 * compression to shrink IPv6 headers from 40 bytes to ~3-6 bytes. The
 * actual on-air signed frame fits within 255 bytes because SCHC gains
 * more than offset the signature cost.
 *
 * These assertions catch drift if schnorr48.h or frame format constants
 * change without updating LICHEN_LORA_FRAME_OVERHEAD in lora_l2.h.
 *
 * SECURITY: If LICHEN_SIG_LEN increases, review LICHEN_LORA_FRAME_OVERHEAD
 * to ensure signed frames still fit within the LoRa PHY limit.
 *
 * Constant naming (project-LICHEN-tvfm.106, project-LICHEN-tvfm.107):
 * - LICHEN_FRAME_BASE_OVERHEAD (5 bytes): Minimum frame size for validation.
 *   Used in LICHEN_MIN_FRAME_LEN to reject malformed runt frames early.
 *   Does NOT include signature (signature is conditional on has_key).
 * - LICHEN_LORA_FRAME_OVERHEAD (55 bytes): Conservative MTU overhead.
 *   Always reserves space for signature even when not used. This is
 *   intentional: a static MTU simplifies buffer sizing and avoids
 *   dynamic MTU changes when signing keys are provisioned. The 50-byte
 *   overhead when unsigned is acceptable for the simplicity benefit.
 */
#define LICHEN_FRAME_BASE_OVERHEAD LICHEN_FRAME_FIXED_HEADER_LEN

/*
 * Assert: signature length has not changed.
 * LICHEN_LORA_FRAME_OVERHEAD was calculated assuming 48-byte signatures.
 * If this assertion fails, recalculate the overhead constant.
 */
BUILD_ASSERT(LICHEN_SIG_LEN == 48,
	     "LICHEN_SIG_LEN changed - update LICHEN_LORA_FRAME_OVERHEAD in lora_l2.h");

/*
 * Assert: frame header size has not changed.
 * LICHEN_LORA_FRAME_OVERHEAD is independent of the 5-byte unsigned minimum.
 * If this assertion fails, recalculate the overhead constant.
 */
BUILD_ASSERT(LICHEN_FRAME_BASE_OVERHEAD == 5,
	     "Frame header size changed - update LICHEN_LORA_FRAME_OVERHEAD in lora_l2.h");

/* IPv6 base header size (RFC 8200). Does NOT include extension headers. */
#define IPV6_BASE_HDR_LEN 40

/*
 * Maximum OSCORE overhead for buffer sizing.
 *
 * OSCORE (RFC 8613) adds an Object-Security option to CoAP requests/responses.
 * The option size varies based on security context parameters:
 *   - Partial IV: 0-5 bytes (typically 5 for freshness)
 *   - kid context: 0-8 bytes (typically 0 for established contexts)
 *   - kid: 0-8 bytes (typically 1-2 bytes for sender ID)
 *   - Option overhead: ~3 bytes (option number + length encoding)
 *
 * Conservative estimate: 24 bytes covers typical deployments with room for
 * larger context identifiers. SCHC compression will reduce this significantly
 * on-air once OSCORE-specific rules are added (spec/schc-rules.py).
 *
 * SECURITY: This affects buffer sizing only, not MTU. The OSCORE overhead
 * is present in the pre-compression IPv6/UDP/CoAP packet but gets compressed
 * by SCHC before transmission.
 */
#define OSCORE_MAX_OVERHEAD 24

/*
 * Scratch buffers for TX/RX processing.
 * Protected by mutexes since multiple threads may call L2 send/recv.
 *
 * Buffer sizing: LICHEN_L2_MTU + IPV6_BASE_HDR_LEN + OSCORE_MAX_OVERHEAD = 264 bytes.
 *
 * LIMITATION (project-LICHEN-tvfm.97): IPv6 extension headers other than OSCORE
 * are NOT supported.
 *
 * These buffers are sized for base IPv6 header (40 bytes) + OSCORE option
 * overhead (24 bytes) + payload. Packets with other extension headers
 * (Hop-by-Hop, Routing, Fragment, Destination, etc.) will be dropped:
 *
 * TX path: Oversized packets fail the pkt_len > sizeof(tx_ipv6_buf) check
 *          in lichen_l2_send() with -EMSGSIZE.
 *
 * RX path: SCHC decompression produces a packet larger than rx_ipv6_buf,
 *          causing lichen_link_rx() to fail or the ipv6_len > sizeof check
 *          to reject the packet.
 *
 * This is by design: LICHEN's SCHC rules (schc/rules.py) are defined for
 * specific protocol stacks (CoAP/UDP, ICMPv6, RPL) with OSCORE support.
 * Packets with unsupported extension headers fall back to SCHC rule 255
 * (uncompressed), which exceeds the 200-byte MTU and gets rejected.
 *
 * To support additional extension headers in the future:
 * 1. Add a dedicated SCHC rule in schc/rules.py for the specific extension
 * 2. Increase buffer sizes here (add extension header size)
 * 3. Potentially update LICHEN_L2_MTU in lora_l2.h
 *
 * OSCORE support (project-LICHEN-v1wq): Buffer sizing includes OSCORE_MAX_OVERHEAD.
 * Remaining integration work:
 * 1. Add OSCORE-specific SCHC rules in schc/rules.py
 * 2. Wire up OSCORE context management
 */
/*
 * TX/RX scratch buffers and their protecting mutexes.
 *
 * LOCK ORDER (project-LICHEN-tvfm.25): When acquiring BOTH mutexes, tx_mutex
 * MUST be acquired before rx_mutex. Violating this order causes ABBA deadlock.
 * This ordering is enforced in lichen_l2_enable() (enable and disable paths)
 * and any future code that needs both locks must follow the same order.
 *
 * Single-mutex acquisitions (e.g., tx_mutex in lichen_l2_send(), rx_mutex in
 * lichen_l2_input()) do not create deadlock risk and are fine on their own.
 */
/*
 * TX/RX buffers for packet linearization and framing.
 *
 * PORTABILITY NOTE (project-LICHEN-i1gk.95): These buffers are not cache-line
 * aligned. On Cortex-M0/M3/M4 (no cache) this is fine. On Cortex-M7/M33 with
 * cache, if the LoRa driver uses DMA, these buffers may need:
 *   - __attribute__((aligned(32))) for cache-line alignment
 *   - Cache maintenance (clean/invalidate) around DMA transfers
 * Currently the LoRa driver abstracts DMA details, so no alignment is needed.
 */
static uint8_t tx_ipv6_buf[LICHEN_L2_MTU + IPV6_BASE_HDR_LEN + OSCORE_MAX_OVERHEAD];
static uint8_t tx_frame_buf[MAX_LORA_FRAME];
static K_MUTEX_DEFINE(tx_mutex);  /* Lock order: 1st (before rx_mutex) */

static uint8_t rx_ipv6_buf[LICHEN_L2_MTU + IPV6_BASE_HDR_LEN + OSCORE_MAX_OVERHEAD];
static K_MUTEX_DEFINE(rx_mutex);  /* Lock order: 2nd (after tx_mutex) */

/* Link context for framing */
#if HAVE_LICHEN_LINK
static struct lichen_link_ctx link_ctx;
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
static struct lichen_replay_table replay_table;

/*
 * Peer table for RX signature verification.
 *
 * Maps EUI-64 addresses to Ed25519 public keys. Used during RX to verify
 * Schnorr-48 signatures from known peers. Populated by EDHOC handshake
 * or announce processing via lichen_peer_add().
 *
 * SECURITY: Frames from unknown peers (not in this table) are REJECTED.
 * This is the security boundary for link-layer authentication.
 *
 * Protected by rx_mutex (same as link_ctx and replay_table).
 *
 * Memory layout note (project-LICHEN-tvfm.105): This struct has no explicit
 * packing attribute. The compiler may insert padding after 'active' (or between
 * fields on some architectures). lichen_peer_remove() zeros eui64 and pubkey
 * individually via secure_zero(), which is sufficient since:
 * 1. Padding bytes are never initialized from security-sensitive sources
 * 2. The key material (pubkey) is explicitly cleared
 * 3. Adding __attribute__((packed)) would hurt performance on ARM Cortex-M
 */
struct lichen_peer_entry {
	uint8_t eui64[LICHEN_EUI64_LEN];
	uint8_t pubkey[LICHEN_L2_PUBKEY_LEN];
	/*
	 * k_uptime_get() timestamp of last verified frame.
	 *
	 * SECURITY (project-LICHEN-i1gk.99): Timing uses k_uptime_get() which relies
	 * on the kernel tick timer. On typical embedded MCUs (STM32WL, nRF52, ESP32),
	 * this timer runs at a fixed frequency independent of CPU frequency scaling.
	 * LICHEN targets single-core Cortex-M devices without DVFS (Dynamic Voltage
	 * and Frequency Scaling), so timing measurements are stable.
	 *
	 * If porting to a platform with aggressive power management (variable CPU
	 * clock, tickless idle), verify that:
	 * 1. k_uptime_get() uses a fixed-frequency timer source (e.g., LPTIM, RTC)
	 * 2. Replay window aging (if implemented) accounts for timer drift
	 */
	int64_t last_seen;
	bool active;
};

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

static struct lichen_peer_entry peer_table[CONFIG_LICHEN_LINK_MAX_NEIGHBORS];

/*
 * Guards access to link_ctx before initialization completes.
 * SECURITY: atomic_t prevents torn reads under aggressive optimization.
 *
 * PLATFORM CONSTRAINT: This code requires single-core execution.
 * Zephyr's atomic_set()/atomic_get() do NOT provide memory ordering
 * guarantees (no release/acquire semantics). On single-core platforms,
 * program order guarantees visibility - stores complete before subsequent
 * instructions execute on the same core. Multi-core requires explicit
 * memory barriers (e.g., __DMB(), atomic_thread_fence) which are not
 * used here.
 *
 * BUILD_ASSERT below enforces this constraint at compile time.
 * (project-LICHEN-tvfm.112)
 */
#if defined(CONFIG_SMP) || (defined(CONFIG_MP_MAX_NUM_CPUS) && CONFIG_MP_MAX_NUM_CPUS > 1)
BUILD_ASSERT(0, "LICHEN L2 requires single-core: atomic_t usage lacks memory barriers. "
		"Disable CONFIG_SMP or ensure CONFIG_MP_MAX_NUM_CPUS == 1.");
#endif
static atomic_t link_ctx_initialized;

#ifdef CONFIG_LICHEN_L2_TEST_HOOKS
static atomic_t test_tx_packets;
static atomic_t test_rx_frames;
static atomic_t test_rx_injected_packets;
K_MUTEX_DEFINE(test_stats_mutex);
static uint8_t test_last_injected[LICHEN_L2_TEST_CAPTURE_MAX];
static size_t test_last_injected_len;
#endif
#endif

/*
 * Cached interface pointer for RX callback.
 *
 * INVARIANT (project-LICHEN-ybal.4, project-LICHEN-0zj6.13): Write-once-read-many.
 * Set exactly once in lichen_l2_iface_init(), never cleared. The net_if is
 * statically allocated with device lifetime. Do NOT clear this pointer.
 *
 * SYNCHRONIZATION: lora_rx_callback() reads this without a mutex. This is safe
 * because:
 * 1. The callback is registered (lichen_lora_l2_set_rx_callback) AFTER the
 *    pointer is written, establishing happens-before via the callback
 *    registration itself (which uses internal synchronization).
 * 2. On single-core Cortex-M (the target platform), store ordering is
 *    naturally guaranteed by program order.
 * 3. The reader also checks atomic_get(&iface_init_failed) which is set AFTER
 *    lichen_iface on the error path, providing additional ordering.
 *
 * For multi-core portability, this could use atomic_ptr_set/get, but Zephyr
 * does not provide atomic pointer operations for all architectures. The current
 * design is correct for the target hardware.
 */
static struct net_if *lichen_iface;

/*
 * Initialization error flag.
 *
 * Set to 1 if lichen_l2_iface_init() failed partway through initialization.
 * Checked by lichen_l2_send(), lichen_l2_enable(), and lora_rx_callback() to
 * prevent operating on a half-initialized interface. (project-LICHEN-1ojj.2)
 *
 * SECURITY: Prevents silent failures where the net_if appears valid to the IPv6
 * stack but the L2 layer cannot actually transmit or receive.
 *
 * atomic_t for safe concurrent access without mutex. (project-LICHEN-rwio.13)
 */
static atomic_t iface_init_failed;

/*
 * Local copy of link-layer address for net_if_set_link_addr().
 *
 * Zephyr's net_if stores the pointer directly without copying, so we must
 * provide storage that persists for the interface lifetime. We copy from
 * lichen_lora_l2_copy_eui64() rather than aliasing internal LoRa L2 state.
 * (project-LICHEN-ybal.15/.16)
 */
static uint8_t iface_link_addr[LICHEN_L2_ADDR_LEN];

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
static struct lichen_peer_entry *peer_find_locked(const uint8_t eui64[8])
{
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
static int peer_find_oldest_locked(void)
{
	int oldest_idx = -1;
	int64_t oldest_time = INT64_MAX;

	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (peer_table[i].active && peer_table[i].last_seen < oldest_time) {
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
static int peer_try_all_pubkeys(struct lichen_link_rx_ctx *ctx,
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

int lichen_peer_add(const uint8_t eui64[LICHEN_EUI64_LEN],
		    const uint8_t pubkey[LICHEN_L2_PUBKEY_LEN])
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

int lichen_peer_remove(const uint8_t eui64[8])
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

int lichen_l2_load_key(const uint8_t seed[32], uint8_t pubkey[32])
{
	int ret;

	if (seed == NULL || pubkey == NULL) {
		return -EINVAL;
	}
	if (atomic_get(&iface_init_failed)) {
		return -ENODEV;
	}
	if (!atomic_get(&link_ctx_initialized)) {
		return -EAGAIN;
	}

	k_mutex_lock(&tx_mutex, K_FOREVER);
	k_mutex_lock(&rx_mutex, K_FOREVER);
	ret = lichen_link_load_key(&link_ctx, seed);
	if (ret == 0) {
		memcpy(pubkey, link_ctx.ed25519_pk, LICHEN_L2_PUBKEY_LEN);
	}
	k_mutex_unlock(&rx_mutex);
	k_mutex_unlock(&tx_mutex);

	return ret;
}

int lichen_l2_load_link_key(const uint8_t link_key[LICHEN_LINK_KEY_LEN])
{
	int ret;

	if (link_key == NULL) {
		return -EINVAL;
	}
	if (atomic_get(&iface_init_failed)) {
		return -ENODEV;
	}
	if (!atomic_get(&link_ctx_initialized)) {
		return -EAGAIN;
	}

	k_mutex_lock(&tx_mutex, K_FOREVER);
	k_mutex_lock(&rx_mutex, K_FOREVER);
	ret = lichen_link_load_link_key(&link_ctx, link_key);
	k_mutex_unlock(&rx_mutex);
	k_mutex_unlock(&tx_mutex);

	return ret;
}

#ifdef CONFIG_LICHEN_L2_DEV_PROVISIONING
/*
 * SECURITY: INSECURE dev-only provisioning. This seed is public (it lives
 * in the source tree) and is shared by every node built with
 * CONFIG_LICHEN_L2_DEV_PROVISIONING, so signatures made with it prove
 * nothing. Bench bring-up only, until announce/EDHOC peer provisioning
 * lands. The Kconfig help text carries the same warning.
 */
static const uint8_t dev_seed[32] = {
	0x4c, 0x49, 0x43, 0x48, 0x45, 0x4e, 0x2d, 0x44, /* "LICHEN-D" */
	0x45, 0x56, 0x2d, 0x53, 0x45, 0x45, 0x44, 0x2d, /* "EV-SEED-" */
	0x30, 0x30, 0x30, 0x31, 0x2d, 0x49, 0x4e, 0x53, /* "0001-INS" */
	0x45, 0x43, 0x55, 0x52, 0x45, 0x21, 0x21, 0x21, /* "ECURE!!!" */
};

/* Parse "aabb..." or "aa:bb:..." into 8 bytes. Returns 0 or -EINVAL. */
static int dev_parse_eui64(const char *s, uint8_t out[LICHEN_EUI64_LEN])
{
	size_t n = 0;

	while (*s != '\0' && n < LICHEN_EUI64_LEN) {
		char hex[3] = { 0 };

		if (*s == ':' || *s == '-') {
			s++;
			continue;
		}
		if (!isxdigit((unsigned char)s[0]) ||
		    !isxdigit((unsigned char)s[1])) {
			return -EINVAL;
		}
		hex[0] = s[0];
		hex[1] = s[1];
		out[n++] = (uint8_t)strtoul(hex, NULL, 16);
		s += 2;
	}

	return (n == LICHEN_EUI64_LEN && *s == '\0') ? 0 : -EINVAL;
}

/* Provision one dev peer: derive its pubkey, pin it, and add a static
 * IPv6 neighbor entry. See lichen_l2_dev_provision() for context. */
static int dev_provision_peer(uint8_t peer_eui64[LICHEN_EUI64_LEN])
{
	uint8_t peer_pubkey[LICHEN_L2_PUBKEY_LEN];
	uint8_t node_seed[LICHEN_SEED_LEN];
	int ret;

	ret = lichen_link_derive_seed(dev_seed, peer_eui64, node_seed);
	if (ret == 0) {
		ret = lichen_link_derive_pubkey(node_seed, peer_pubkey);
	}
	secure_zero(node_seed, sizeof(node_seed));
	if (ret != 0) {
		LOG_ERR("lichen_l2: dev peer key derivation failed (%d)", ret);
		return ret;
	}

	ret = lichen_peer_add(peer_eui64, peer_pubkey);
	if (ret != 0) {
		LOG_ERR("lichen_l2: dev peer add failed (%d)", ret);
		return ret;
	}

	/*
	 * Static IPv6 neighbor entry for the peer. IPv6 ND cannot run over
	 * this link yet — there is no SCHC rule for ICMPv6 NS/NA, so the
	 * solicitation is silently uncompressible and every unicast send
	 * parks forever in the ND queue (bd lora_ipv6_mesh-r002). The dev
	 * peer's link-layer address is knowable from its EUI-64, so resolve
	 * it statically.
	 */
	{
		uint8_t iid[LICHEN_EUI64_LEN];
		struct in6_addr peer_ll;
		struct net_linkaddr lladdr = {
			.addr = peer_eui64,
			.len = LICHEN_EUI64_LEN,
			.type = NET_LINK_IEEE802154,
		};

		ret = lichen_eui64_to_iid(peer_eui64, iid);
		if (ret == 0) {
			ret = lichen_make_link_local(iid, &peer_ll);
		}
		if (ret != 0 || lichen_iface == NULL ||
		    net_ipv6_nbr_add(lichen_iface, &peer_ll, &lladdr, false,
				     NET_IPV6_NBR_STATE_STATIC) == NULL) {
			LOG_ERR("lichen_l2: static neighbor add failed (%d)", ret);
			return ret != 0 ? ret : -ENOMEM;
		}
	}

	LOG_WRN("lichen_l2: INSECURE dev provisioning active (peer %02x%02x..%02x%02x)",
		peer_eui64[0], peer_eui64[1], peer_eui64[6], peer_eui64[7]);
	return 0;
}

int lichen_l2_dev_provision(uint8_t peer_eui64_out[LICHEN_EUI64_LEN])
{
	uint8_t pubkey[LICHEN_L2_PUBKEY_LEN];
	uint8_t self_eui64[LICHEN_EUI64_LEN];
	uint8_t peer_eui64[LICHEN_EUI64_LEN];
	uint8_t node_seed[LICHEN_SEED_LEN];
	const char *s = CONFIG_LICHEN_L2_DEV_PEER_EUI64;
	size_t peers_added = 0;
	int ret;

	/*
	 * SECURITY: Per-node dev keys, derived as SHA-512(dev_seed || EUI-64).
	 * Still INSECURE (dev_seed is public, so anyone can derive any node's
	 * key), but each node now has a DISTINCT keypair so signature
	 * verification attributes frames to the correct peer. With one shared
	 * keypair, every dev node in RF range verified as "the" pinned peer
	 * and all transmitters collapsed into a single replay window per
	 * receiver; the highest random boot epoch then permanently starved
	 * the others (project-LICHEN-wp4o).
	 */
	ret = lichen_lora_l2_copy_eui64(self_eui64);
	if (ret != 0) {
		LOG_ERR("lichen_l2: dev self EUI-64 read failed (%d)", ret);
		return ret;
	}
	ret = lichen_link_derive_seed(dev_seed, self_eui64, node_seed);
	if (ret == 0) {
		ret = lichen_l2_load_key(node_seed, pubkey);
	}
	secure_zero(node_seed, sizeof(node_seed));
	if (ret != 0) {
		LOG_ERR("lichen_l2: dev key load failed (%d)", ret);
		return ret;
	}

	/* CONFIG_LICHEN_L2_DEV_PEER_EUI64 is a comma-separated list of
	 * EUI-64s; each entry is pinned as a dev peer. */
	while (*s != '\0') {
		char token[24]; /* "aa:bb:cc:dd:ee:ff:00:11" = 23 chars */
		size_t n = 0;

		while (*s == ',' || *s == ' ') {
			s++;
		}
		while (*s != '\0' && *s != ',') {
			if (n >= sizeof(token) - 1) {
				LOG_ERR("lichen_l2: bad CONFIG_LICHEN_L2_DEV_PEER_EUI64 '%s'",
					CONFIG_LICHEN_L2_DEV_PEER_EUI64);
				return -EINVAL;
			}
			token[n++] = *s++;
		}
		token[n] = '\0';
		if (n == 0) {
			continue;
		}

		ret = dev_parse_eui64(token, peer_eui64);
		if (ret != 0) {
			LOG_ERR("lichen_l2: bad CONFIG_LICHEN_L2_DEV_PEER_EUI64 '%s'",
				CONFIG_LICHEN_L2_DEV_PEER_EUI64);
			return ret;
		}

		ret = dev_provision_peer(peer_eui64);
		if (ret != 0) {
			return ret;
		}

		if (peers_added == 0 && peer_eui64_out != NULL) {
			memcpy(peer_eui64_out, peer_eui64, LICHEN_EUI64_LEN);
		}
		peers_added++;
	}

	if (peers_added == 0) {
		LOG_ERR("lichen_l2: bad CONFIG_LICHEN_L2_DEV_PEER_EUI64 '%s'",
			CONFIG_LICHEN_L2_DEV_PEER_EUI64);
		return -EINVAL;
	}

	return 0;
}
#endif /* CONFIG_LICHEN_L2_DEV_PROVISIONING */

#ifdef CONFIG_LICHEN_L2_TEST_HOOKS
int lichen_l2_test_load_key(const uint8_t seed[32], uint8_t pubkey[32])
{
	return lichen_l2_load_key(seed, pubkey);
}

int lichen_l2_test_load_link_key(const uint8_t link_key[LICHEN_LINK_KEY_LEN])
{
	return lichen_l2_load_link_key(link_key);
}

void lichen_l2_test_reset_stats(void)
{
	k_mutex_lock(&test_stats_mutex, K_FOREVER);
	atomic_set(&test_tx_packets, 0);
	atomic_set(&test_rx_frames, 0);
	atomic_set(&test_rx_injected_packets, 0);
	memset(test_last_injected, 0, sizeof(test_last_injected));
	test_last_injected_len = 0;
	k_mutex_unlock(&test_stats_mutex);
}

void lichen_l2_test_get_stats(struct lichen_l2_test_stats *stats)
{
	if (stats == NULL) {
		return;
	}

	stats->tx_packets = (uint32_t)atomic_get(&test_tx_packets);
	stats->rx_frames = (uint32_t)atomic_get(&test_rx_frames);
	stats->rx_injected_packets =
		(uint32_t)atomic_get(&test_rx_injected_packets);
	k_mutex_lock(&test_stats_mutex, K_FOREVER);
	stats->last_injected_len = (uint32_t)test_last_injected_len;
	memcpy(stats->last_injected, test_last_injected,
	       sizeof(stats->last_injected));
	k_mutex_unlock(&test_stats_mutex);
}
#endif

/*
 * TX/RX outcome counters — cheap ops visibility into the data path (which
 * otherwise fails only into logs). Read via lichen_l2_get_tx_stats() /
 * lichen_l2_get_rx_stats().
 */
static atomic_t tx_stat_attempts;
static atomic_t tx_stat_errors;
static atomic_t tx_stat_last_err;
static atomic_t rx_stat_frames;
static atomic_t rx_stat_accepted;
static atomic_t rx_stat_last_err;

void lichen_l2_get_tx_stats(uint32_t *attempts, uint32_t *errors, int *last_err)
{
	if (attempts != NULL) {
		*attempts = (uint32_t)atomic_get(&tx_stat_attempts);
	}
	if (errors != NULL) {
		*errors = (uint32_t)atomic_get(&tx_stat_errors);
	}
	if (last_err != NULL) {
		*last_err = (int)atomic_get(&tx_stat_last_err);
	}
}

void lichen_l2_get_rx_stats(uint32_t *frames, uint32_t *accepted, int *last_err)
{
	if (frames != NULL) {
		*frames = (uint32_t)atomic_get(&rx_stat_frames);
	}
	if (accepted != NULL) {
		*accepted = (uint32_t)atomic_get(&rx_stat_accepted);
	}
	if (last_err != NULL) {
		*last_err = (int)atomic_get(&rx_stat_last_err);
	}
}

static inline void tx_stat_result(int ret)
{
	if (ret < 0) {
		atomic_inc(&tx_stat_errors);
		atomic_set(&tx_stat_last_err, ret);
	}
}

/* Forward declarations */
static void lora_rx_callback(const uint8_t *data, size_t len,
                             int16_t rssi, int8_t snr, void *user_data);

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
	 * Use lichen_link_tx() to build the complete frame with proper MIC.
	 * This handles:
	 * - SCHC compression
	 * - Schnorr-48 signature if has_key
	 * - No MIC for unsigned frames
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
	 */
	net_pkt_unref(pkt);
	return (int)pkt_len;
}

/* NET_L2_INIT-facing wrapper: keep the TX outcome counters in one place. */
static int lichen_l2_send(struct net_if *iface, struct net_pkt *pkt)
{
	int ret;

	atomic_inc(&tx_stat_attempts);
	ret = lichen_l2_send_inner(iface, pkt);
	tx_stat_result(ret);
	return ret;
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
		 * This intentionally duplicates lichen_l2_iface_init() initialization
		 * rather than extracting a helper because:
		 * 1. The init path runs once at boot with no concurrency concerns
		 * 2. The enable path must hold both mutexes due to potential races
		 *    with in-flight TX/RX from a concurrent thread
		 * 3. Extracting a helper would require passing mutex-held state or
		 *    adding "already_locked" parameters, obscuring the safety model
		 *
		 * LOCK ORDER: tx_mutex before rx_mutex. See comment at mutex
		 * definitions (~line 217) for rationale and full documentation.
		 */
		k_mutex_lock(&tx_mutex, K_FOREVER);
		k_mutex_lock(&rx_mutex, K_FOREVER);
		if (!atomic_get(&link_ctx_initialized)) {
			/* SECURITY: Defensive zero of any stale key material before re-init
			 * (project-LICHEN-725z.9) */
			secure_zero(&link_ctx, sizeof(link_ctx));
			ret = lichen_link_init(&link_ctx, eui64_copy);
			if (ret < 0) {
				/* Entropy or mutex failure: do not mark initialized.
				 * Unlock and propagate (2auf.35.4.2.2). Context remains
				 * zeroed; next enable will retry. */
				k_mutex_unlock(&rx_mutex);
				k_mutex_unlock(&tx_mutex);
				return ret;
			}
#ifdef CONFIG_LICHEN_LINK_EPOCH_PERSIST
			/* Override the random boot epoch with the persisted,
			 * monotonically-advancing one (lora_ipv6_mesh-3uhb).
			 * Idempotent within a boot. */
			lichen_link_set_epoch(&link_ctx,
					      lichen_link_epoch_advance_for_boot());
#endif
			/*
			 * Re-init replay table to match iface_init() behavior.
			 * Without this, stale replay windows could persist or be
			 * uninitialized after disable/enable cycle.
			 *
			 * Safe on dirty table: lichen_replay_table_init() does memset()
			 * which clears all entries regardless of prior state. No dynamic
			 * allocation in replay table - all entries are POD types.
			 * (project-LICHEN-dq6n.19, project-LICHEN-tvfm.80)
			 *
			 * NOTE (project-LICHEN-i1gk.74): Replay table is cleared here but
			 * peer_table is NOT cleared on enable (only on disable). This is
			 * intentional: replay protection resets for security (peers must
			 * exceed their old sequence numbers), while peer keys persist so
			 * EDHOC re-handshake is not required. Peers that were mid-session
			 * will fail replay checks until their sequence numbers advance.
			 */
			lichen_replay_table_init(&replay_table);
			atomic_set(&link_ctx_initialized, 1);
		}
		k_mutex_unlock(&rx_mutex);
		k_mutex_unlock(&tx_mutex);
#endif
		/*
		 * Re-register RX callback before starting.
		 * lichen_lora_l2_stop() clears the callback (lora_l2.c:324-325),
		 * so we must re-register it on enable. (project-LICHEN-yw7i.28)
		 */
		ret = lichen_lora_l2_set_rx_callback(lora_rx_callback, NULL);
		if (ret != 0) {
			LOG_ERR("lichen_l2: failed to set RX callback (%d)", ret);
#if HAVE_LICHEN_LINK
			k_mutex_lock(&tx_mutex, K_FOREVER);
			k_mutex_lock(&rx_mutex, K_FOREVER);
			if (atomic_get(&link_ctx_initialized)) {
				atomic_set(&link_ctx_initialized, 0);
				lichen_link_cleanup(&link_ctx);
			}
			k_mutex_unlock(&rx_mutex);
			k_mutex_unlock(&tx_mutex);
#endif
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
			k_mutex_lock(&tx_mutex, K_FOREVER);
			k_mutex_lock(&rx_mutex, K_FOREVER);
			if (atomic_get(&link_ctx_initialized)) {
				atomic_set(&link_ctx_initialized, 0);
				lichen_link_cleanup(&link_ctx);
			}
			k_mutex_unlock(&rx_mutex);
			k_mutex_unlock(&tx_mutex);
		}
#endif
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
			}
		}
		/*
		 * Note: We intentionally do NOT clear lichen_iface here.
		 * See the invariant comment at the lichen_iface declaration.
		 */
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
		 * which is correct for the callback path - it must complete processing
		 * before releasing the lock. The difference in timeouts is intentional:
		 * - Callback path (K_FOREVER): Must finish signature verification etc.
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
		 * THREAD SAFETY: This loop is safe without additional IRQ masking:
		 * - Called from net_if_down() which holds iface->lock (a k_mutex)
		 * - We hold both tx_mutex and rx_mutex (acquired above)
		 * - All peer_table accessors (peer_find_locked, peer_try_all_pubkeys,
		 *   lichen_peer_add) require rx_mutex, so they block until we release
		 * - No ISRs access peer_table directly
		 * Preemption by higher-priority threads is harmless since they will
		 * block on the mutex; the loop will resume and complete atomically
		 * from peer_table's perspective. (project-LICHEN-tvfm.6)
		 */
		for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
			secure_zero(peer_table[i].pubkey, sizeof(peer_table[i].pubkey));
			secure_zero(peer_table[i].eui64, sizeof(peer_table[i].eui64));
			peer_table[i].active = false;
		}
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
 * @brief LoRa RX callback - invoked from lora_l2 RX thread
 */
static void lora_rx_callback(const uint8_t *data, size_t len,
			     int16_t rssi, int8_t snr, void *user_data)
{
	ARG_UNUSED(user_data);

	/*
	 * Check both conditions to distinguish init-failure from never-initialized.
	 * (project-LICHEN-rwio.11)
	 */
	if (lichen_iface == NULL || atomic_get(&iface_init_failed)) {
		LOG_WRN("lichen_l2: RX callback ignored (interface not ready)");
		return;
	}

	lichen_l2_input(lichen_iface, data, len, rssi, snr);
}

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
	/* iface guaranteed non-NULL by Zephyr NET_DEVICE_INIT */
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
	 * at lines ~1315 (lichen_iface != NULL) catches double-iface_init attempts,
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
	 * Initialize link_ctx then replay_table. Order is safe: link_ctx does not
	 * depend on replay_table, and no async access occurs before link_ctx_initialized
	 * is set (after RX callback registration). (project-LICHEN-i1gk.81)
	 */
	int init_ret = lichen_link_init(&link_ctx, eui64);
	if (init_ret < 0) {
		/* Entropy failure or mutex failure: fail closed, do not mark
		 * initialized or proceed with RX setup. (2auf.35.4.2) */
		LOG_ERR("lichen_link_init failed (%d)", init_ret);
		atomic_set(&iface_init_failed, 1);
		return;
	}
#ifdef CONFIG_LICHEN_LINK_EPOCH_PERSIST
	/* Override the random boot epoch with the persisted, monotonically-
	 * advancing one so a rebooted node is never seen as a replay
	 * (lora_ipv6_mesh-3uhb). Idempotent within a boot. */
	lichen_link_set_epoch(&link_ctx, lichen_link_epoch_advance_for_boot());
#endif
	lichen_replay_table_init(&replay_table);
	/*
	 * Explicitly initialize peer_table at boot.
	 *
	 * C guarantees static storage is zero-initialized (C11 6.7.9p10), so
	 * peer_table[i].active is already false. However, explicit initialization
	 * is defensive: it documents the invariant, survives any future move to
	 * dynamic allocation, and costs nothing at boot (single memset).
	 * (project-LICHEN-tvfm.66)
	 *
	 * On re-init, peer_table was already cleared with secure_zero above while
	 * holding mutexes. This secure_zero is redundant in that case but harmless.
	 *
	 * SECURITY (project-LICHEN-i1gk.47): Use secure_zero instead of memset for
	 * consistency with other peer_table clearing paths and to prevent compiler
	 * optimization from eliding the clear on re-init after failed init.
	 */
	secure_zero(peer_table, sizeof(peer_table));
#endif

	/*
	 * Cache interface for RX callback.
	 *
	 * INVARIANT (project-LICHEN-1www.46): lichen_iface is set exactly once
	 * during initialization and never cleared. This allows lora_rx_callback()
	 * to read it without synchronization. Enforce with runtime check.
	 *
	 * Recovery note (project-LICHEN-tvfm.93): If a previous init attempt
	 * failed after setting lichen_iface (e.g., in fail_late_init), the
	 * iface pointer persists intentionally. The failure state is permanent
	 * until reboot - this is fail-safe by design. A retry would reach this
	 * check and fail with the message below, which correctly identifies
	 * the condition (iface already set) even if the original cause was a
	 * late init failure rather than a true invariant violation.
	 */
	if (lichen_iface != NULL) {
		LOG_ERR("lichen_l2: iface already set (init requires reboot after failure)");
		atomic_set(&iface_init_failed, 1);
		return;
	}
	lichen_iface = iface;

	/* Register RX callback - must happen AFTER link_ctx is initialized */
	ret = lichen_lora_l2_set_rx_callback(lora_rx_callback, NULL);
	if (ret != 0) {
		LOG_ERR("lichen_l2: failed to set RX callback (%d)", ret);
		atomic_set(&iface_init_failed, 1);
		return;
	}

#if HAVE_LICHEN_LINK
	/*
	 * Mark link_ctx as safe to access.
	 * Note: Zephyr's atomic_set() does NOT provide release semantics.
	 * On single-core Cortex-M, program order suffices since all prior
	 * stores complete before this store executes.
	 *
	 * Set AFTER RX callback registration so the flag truthfully indicates
	 * that the full initialization sequence is complete.
	 * (project-LICHEN-q3iy.24)
	 */
	atomic_set(&link_ctx_initialized, 1);
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
	ret = lichen_link_copy_identity(&link_ctx, NULL, pubkey, &has_key);
	if (ret == 0 && has_key) {
		struct in6_addr ygg;
		ret = lichen_yggdrasil_addr(pubkey, &ygg);
		if (ret == 0) {
			char addr_str[LICHEN_IPV6_ADDR_STR_LEN];
			if (lichen_ipv6_addr_to_str(&ygg, addr_str, sizeof(addr_str)) == 0) {
				LOG_INF("lichen_l2: primary yggdrasil %s", addr_str);
			}
			(void)net_if_ipv6_addr_add(iface, &ygg, NET_ADDR_PREFERRED, 0);
		}
	}

#if HAVE_LICHEN_LINK
#if IS_ENABLED(CONFIG_STATS)
	(void)STATS_INIT_AND_REG(lichen_l2rx_stats, STATS_SIZE_32, "l2rx");
#endif
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
	 * NOTE: Do NOT clear lichen_iface here — it has a set-once invariant
	 * (project-LICHEN-ybal.4) because lora_rx_callback() reads it without mutex.
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
	/*
	 * Guard against access before initialization.
	 * This shouldn't happen in normal operation, but could if a packet
	 * arrives during early startup before lichen_l2_iface_init() completes.
	 */
	if (!atomic_get(&link_ctx_initialized)) {
		LOG_WRN("lichen_l2: RX before link_ctx initialized, dropping");
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
	 * SECURITY: Copy link_key into a local buffer rather than capturing a
	 * pointer to link_ctx.link_key. This ensures rx_ctx remains valid even
	 * if a future refactor moves lichen_link_cleanup() outside the rx_mutex.
	 * The current code is safe (cleanup holds both mutexes), but copying
	 * eliminates a subtle lifetime dependency that could cause use-after-free
	 * if cleanup timing changes. 16-byte copy is cheap. (project-LICHEN-ybal.7)
	 *
	 * INVARIANT: has_link_key is only set by key provisioning functions that
	 * also write valid key material to link_key. If this invariant is violated,
	 * MIC verification will fail (not silently accept).
	 *
	 * The retained link key is copied for API compatibility but current frames
	 * are either unsigned or authenticated by Schnorr-48.
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
