/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2_internal.h
 * @brief Internal declarations for LICHEN L2 implementation
 *
 * This header is for internal use by the lichen_l2_*.c files only.
 * External code should use lichen_l2.h.
 */

#ifndef LICHEN_L2_INTERNAL_H_
#define LICHEN_L2_INTERNAL_H_

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
#include <lichen/routing/gradient.h>
#include <monocypher.h>
#if IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
#include <lichen/app_identity/app_identity.h>
#endif

#include <string.h>

#include "lichen_util.h"

/*
 * Include LICHEN link layer if available.
 */
#if defined(CONFIG_LICHEN_LINK)
#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/replay.h>
#ifdef CONFIG_LICHEN_LINK_REPLAY_PERSIST
#include <lichen/replay_persist.h>
#endif
#include <lichen/schc.h>
#define HAVE_LICHEN_LINK 1
#else
#define HAVE_LICHEN_LINK 0
#endif

/* ─── Constants ──────────────────────────────────────────────────────────── */

/* Maximum frame size for LoRa (derived from lora_l2.h) */
#define MAX_LORA_FRAME LICHEN_LORA_MAX_PHY_PAYLOAD

/*
 * Minimum valid LICHEN frame size.
 * Wire format: Length(1) + LLSec(1) + Epoch(1) + SeqNum(2) = 5 bytes min.
 */
#define LICHEN_MIN_FRAME_LEN 5

/* Frame component sizes for validation */
#define LICHEN_FRAME_MIN_MIC 0   /* unsigned frames have no MIC */
#define LICHEN_FRAME_MIN_ADDR 0  /* broadcast/NONE mode has 0 addr bytes */
#define LICHEN_FRAME_MIN_HEADER_SIZE LICHEN_FRAME_FIXED_HEADER_LEN

/* IPv6 base header size (RFC 8200). Does NOT include extension headers. */
#define IPV6_BASE_HDR_LEN 40

/*
 * Maximum OSCORE overhead for buffer sizing.
 * Conservative estimate: 24 bytes covers typical deployments.
 */
#define OSCORE_MAX_OVERHEAD 24

/* ─── Shared state (defined in lichen_l2_core.c) ─────────────────────────── */

/* TX/RX scratch buffers */
extern uint8_t tx_ipv6_buf[LICHEN_L2_MTU + IPV6_BASE_HDR_LEN + OSCORE_MAX_OVERHEAD];
extern uint8_t tx_frame_buf[MAX_LORA_FRAME];
extern uint8_t rx_ipv6_buf[LICHEN_L2_MTU + IPV6_BASE_HDR_LEN + OSCORE_MAX_OVERHEAD];

/*
 * TX/RX mutex declarations.
 *
 * LOCK ORDER (project-LICHEN-tvfm.25): When acquiring BOTH mutexes, tx_mutex
 * MUST be acquired before rx_mutex. Violating this order causes ABBA deadlock.
 */
extern struct k_mutex tx_mutex;  /* Lock order: 1st (before rx_mutex) */
extern struct k_mutex rx_mutex;  /* Lock order: 2nd (after tx_mutex) */

#if HAVE_LICHEN_LINK
/* Link context for framing */
extern struct lichen_link_ctx link_ctx;

/*
 * Replay protection table for received frames.
 * SECURITY: Replay windows allocated ONLY after Schnorr-48 verification succeeds.
 */
extern struct lichen_replay_table replay_table;

/*
 * Peer table entry for RX signature verification.
 * Maps EUI-64 addresses to Ed25519 public keys.
 */
struct lichen_peer_entry {
	uint8_t eui64[LICHEN_EUI64_LEN];
	uint8_t pubkey[LICHEN_L2_PUBKEY_LEN];
	int64_t last_seen;  /* k_uptime_get() timestamp */
	bool active;
};

extern struct lichen_peer_entry peer_table[CONFIG_LICHEN_LINK_MAX_NEIGHBORS];

/*
 * Atomic flag marking peer_table as fully valid.
 * SECURITY: Set to 0 BEFORE clearing loop, set to 1 AFTER loop completes.
 */
extern atomic_t peer_table_valid;

/*
 * Guards access to link_ctx before initialization completes.
 * SECURITY: atomic_t prevents torn reads under aggressive optimization.
 */
extern atomic_t link_ctx_initialized;

#if defined(CONFIG_LICHEN_ADAPTIVE_SF_ENABLED)
extern struct lichen_gradient_table *sf_gradient_table;
#endif

#ifdef CONFIG_LICHEN_L2_TEST_HOOKS
extern atomic_t test_tx_packets;
extern atomic_t test_rx_frames;
extern atomic_t test_rx_injected_packets;
extern struct k_mutex test_stats_mutex;
extern uint8_t test_last_injected[LICHEN_L2_TEST_CAPTURE_MAX];
extern size_t test_last_injected_len;
#endif
#endif /* HAVE_LICHEN_LINK */

/*
 * Cached interface pointer for RX callback.
 * INVARIANT: Write-once-read-many. Set exactly once in lichen_l2_iface_init().
 */
extern struct net_if *lichen_iface;

/*
 * Initialization error flag.
 * Set to 1 if lichen_l2_iface_init() failed partway through initialization.
 */
extern atomic_t iface_init_failed;

/* Local copy of link-layer address for net_if_set_link_addr(). */
extern uint8_t iface_link_addr[LICHEN_L2_ADDR_LEN];

/* TX/RX outcome counters */
extern atomic_t tx_stat_attempts;
extern atomic_t tx_stat_errors;
extern atomic_t tx_stat_last_err;
extern atomic_t rx_stat_frames;
extern atomic_t rx_stat_accepted;
extern atomic_t rx_stat_last_err;

/* ─── Helper function declarations ───────────────────────────────────────── */

/* Set-once-write: call exactly once during init, never after. */
static inline void lichen_iface_write(struct net_if *iface)
{
	lichen_iface = iface;
}

/* Read-many: safe to call without synchronization after init. */
static inline struct net_if *lichen_iface_read(void)
{
	return lichen_iface;
}

/* Convert LICHEN errno to Zephyr errno (defined in lichen_l2_core.c) */
int lichen_l2_to_zephyr_errno(int ret);

/* Record TX stat result (defined in lichen_l2_stats.c) */
void tx_stat_result(int ret);

#if HAVE_LICHEN_LINK
/* Peer table helpers (defined in lichen_l2_peer.c) */
struct lichen_peer_entry *peer_find_locked(const uint8_t eui64[8]);
int peer_find_oldest_locked(void);
int peer_try_all_pubkeys(struct lichen_link_rx_ctx *ctx,
			 struct lichen_replay_table *replay,
			 const uint8_t *frame, size_t frame_len,
			 uint8_t *out_ipv6, size_t *out_len,
			 uint8_t src_eui64[8]);
#endif

/* Init helper (defined in lichen_l2_init.c) */
int init_link_ctx_locked(const uint8_t eui64[LICHEN_EUI64_LEN]);

/* LoRa RX callback (defined in lichen_l2_rx.c) */
void lora_rx_callback(const uint8_t *data, size_t len,
		      int16_t rssi, int8_t snr, void *user_data);

#endif /* LICHEN_L2_INTERNAL_H_ */
