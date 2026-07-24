/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2.h
 * @brief LICHEN Zephyr L2 network interface
 *
 * Registers LICHEN as a Zephyr network L2 layer so that the IPv6 stack
 * routes packets through the LoRa radio via SCHC compression and LICHEN
 * link framing.
 *
 * TX path: IPv6 packet -> SCHC compress -> LICHEN frame -> LoRa TX
 * RX path: LoRa RX -> LICHEN frame parse -> SCHC decompress -> IPv6 stack
 *
 * Packet ownership (Zephyr net_l2 contract):
 * - TX (L2 send): On success (return 0), L2 takes ownership of net_pkt and
 *   calls net_pkt_unref(). On error (return < 0), caller retains ownership.
 * - RX (lichen_l2_input): Allocates a new net_pkt and passes ownership to
 *   the network stack via net_recv_data().
 */

#ifndef LICHEN_L2_H_
#define LICHEN_L2_H_

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/net/net_pkt.h>

/* Derive MTU from LoRa layer to prevent drift */
#include "lora_l2.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Peer table ─────────────────────────────────────────────────────────── */

/**
 * @brief Maximum number of peers in the peer table.
 *
 * Uses CONFIG_LICHEN_LINK_MAX_NEIGHBORS for consistency with replay table.
 * Defined in lichen/subsys/lichen/link/Kconfig (default 16, range 4-64).
 * LICHEN_L2 depends on LICHEN_LINK, which guarantees this config is set.
 */
/* CONFIG_LICHEN_LINK_MAX_NEIGHBORS provided by Kconfig - no header default */

/**
 * @brief Ed25519 public key length (from schnorr48.h)
 */
#define LICHEN_L2_PUBKEY_LEN 32

/**
 * @brief Add or update a peer in the peer table.
 *
 * Registers a peer's public key for RX signature verification. Once added,
 * frames signed by this peer can be authenticated. If the peer already exists,
 * its public key is updated.
 *
 * Thread-safe: protected by internal mutex.
 *
 * SECURITY: Array size contract (C arrays decay to pointers - no runtime check):
 *   - eui64 MUST point to exactly 8 bytes (LICHEN_EUI64_LEN from link_ctx.h)
 *   - pubkey MUST point to exactly 32 bytes (LICHEN_L2_PUBKEY_LEN)
 * Passing undersized buffers causes undefined behavior (buffer overread).
 * The implementation uses memcpy with these exact sizes.
 *
 * @param eui64  8-byte peer EUI-64 address (must be exactly 8 bytes, or NULL)
 * @param pubkey 32-byte Ed25519 public key (must be exactly 32 bytes, or NULL)
 * @return 0 on success (peer added or updated)
 *         -EINVAL if eui64 or pubkey is NULL
 *         -ENOSPC if peer table is internally inconsistent (should not happen;
 *                 LRU eviction normally prevents table-full condition)
 */
int lichen_peer_add(const uint8_t eui64[8], const uint8_t pubkey[32]);

/**
 * @brief Remove a peer from the peer table.
 *
 * After removal, frames from this peer will be rejected (unknown sender).
 *
 * Thread-safe: protected by internal mutex.
 *
 * SECURITY: Array size contract (C arrays decay to pointers - no runtime check):
 *   - eui64 MUST point to exactly 8 bytes (LICHEN_EUI64_LEN from link_ctx.h)
 * Passing undersized buffers causes undefined behavior (buffer overread).
 *
 * @param eui64 8-byte peer EUI-64 address (must be exactly 8 bytes, or NULL)
 *
 * @return 0 on success
 * @return -EINVAL if eui64 is NULL
 * @return -ENOENT if peer not found
 * @return -ECANCELED if LoRa L2 requires re-initialization
 * @return -ENOTSUP if LICHEN link support is not enabled
 */
int lichen_peer_remove(const uint8_t eui64[8]);

/* ─── MTU and addressing ─────────────────────────────────────────────────── */

/**
 * @brief MTU for LICHEN interface
 *
 * Derived from LICHEN_LORA_MTU in lora_l2.h. This is the maximum IPv6 packet
 * size we can send. After SCHC compression and LICHEN framing, the on-air
 * payload fits within LoRa limits.
 *
 * When to use each constant:
 * - LICHEN_L2_MTU: Use at the Zephyr network stack layer (net_if, net_pkt).
 *   This is the MTU reported to the IPv6 stack and controls fragmentation.
 * - LICHEN_LORA_MTU: Use at the LoRa driver layer (lora_l2.c). The derived
 *   definition here guarantees they stay in sync.
 *
 * Note: Current SCHC rules assume no IPv6 extension headers. Packets with
 * extension headers (Hop-by-Hop, Routing, OSCORE, etc.) exceed the internal
 * buffer size (MTU + 40 for base IPv6 header) and will be rejected. When
 * OSCORE or other extension header support is added, revisit lichen_l2.c
 * buffer sizing and define appropriate SCHC compression rules.
 */
#define LICHEN_L2_MTU LICHEN_LORA_MTU

/**
 * @brief Link-layer address length (EUI-64)
 */
#define LICHEN_L2_ADDR_LEN 8

/**
 * @brief L2 layer name for NET_L2_INIT
 */
#define LICHEN_L2 lichen_l2

/**
 * @brief Initialize the LICHEN L2 layer.
 *
 * Sets up the LoRa driver and link context. Called during network
 * interface initialization.
 *
 * @param iface Network interface
 */
void lichen_l2_iface_init(struct net_if *iface);

/**
 * @brief Process a received LoRa packet.
 *
 * Called from the LoRa RX callback. Parses the LICHEN frame, performs
 * SCHC decompression, and injects the IPv6 packet into the stack.
 *
 * @param iface Network interface
 * @param data  Raw received data
 * @param len   Length of received data
 * @param rssi  RSSI in dBm
 * @param snr   SNR in dB
 */
void lichen_l2_input(struct net_if *iface, const uint8_t *data, size_t len,
		     int16_t rssi, int8_t snr);

/**
 * @brief Reinitialize internal state after RX thread abort recovery.
 *
 * SECURITY: DANGEROUS FUNCTION - INTERNAL USE ONLY (project-LICHEN-tvfm.16)
 *
 * This function reinitializes a mutex that may still be held, which is
 * UNDEFINED BEHAVIOR. Calling it at the wrong time corrupts kernel state.
 *
 * MUST ONLY be called from lichen_lora_l2_deinit() after:
 * 1. The RX thread has been joined or forcibly aborted
 * 2. No concurrent RX operations are possible
 *
 * Exported only because rx_mutex lives in lichen_l2.c while deinit lives in
 * lora_l2.c. Do NOT call from any other context. Will k_panic() if called
 * while the module is running.
 *
 * The only truly safe recovery from thread-abort is k_sys_reboot().
 */
void lichen_l2_reinit_after_abort(void);

/* Declare the L2 struct for external reference */
NET_L2_DECLARE_PUBLIC(LICHEN_L2);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_L2_H_ */
