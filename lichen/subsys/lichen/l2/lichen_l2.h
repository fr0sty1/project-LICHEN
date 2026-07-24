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
 * - TX (L2 send): On success (return >= 0 byte count), L2 takes ownership of
 *   net_pkt and calls net_pkt_unref(). On error (return < 0), caller retains
 *   ownership.
 * - RX (lichen_l2_input): Allocates a new net_pkt and passes ownership to
 *   the network stack via net_recv_data().
 */

#ifndef LICHEN_L2_H_
#define LICHEN_L2_H_

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/net/net_pkt.h>

#include <stdint.h>

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
int lichen_peer_add(const uint8_t *eui64, const uint8_t *pubkey);

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
int lichen_peer_remove(const uint8_t *eui64);

/**
 * @brief Read the L2 TX outcome counters.
 *
 * attempts counts every lichen_l2_send() invocation; errors counts the ones
 * that returned < 0; last_err is the most recent negative return (0 if none).
 * Any pointer may be NULL.
 */
void lichen_l2_get_tx_stats(uint32_t *attempts, uint32_t *errors, int *last_err);

/**
 * @brief Read the L2 RX outcome counters.
 *
 * frames counts every frame handed up by the radio; accepted counts the ones
 * injected into the IPv6 stack; last_err is the most recent RX failure code.
 */
void lichen_l2_get_rx_stats(uint32_t *frames, uint32_t *accepted, int *last_err);

/*
 * Publish the local L2 link identity to the app-identity provider.
 *
 * This snapshots the initialized L2 link context while holding the same
 * mutexes used by key loading. It returns -ENOKEY until a link keypair has
 * been loaded/generated.
 */
int lichen_l2_publish_app_identity(const char *display_name,
				   const char *firmware_name);

/**
 * @brief Load the local Ed25519 signing keypair from a 32-byte seed.
 *
 * Enables Schnorr-48 signing of outgoing frames (link_ctx.has_key). On
 * success, the derived public key is written to pubkey so the caller can
 * publish it (e.g. to peers via announce or out-of-band provisioning).
 *
 * SECURITY: The seed is the long-term signing secret. It MUST come from a
 * CSPRNG or secure storage. Thread-safe (takes both L2 mutexes).
 *
 * @return 0 on success, -EINVAL on NULL args, -ENODEV if iface init failed,
 *         -EAGAIN if the link context is not yet initialized.
 */
int lichen_l2_load_key(const uint8_t seed[32], uint8_t pubkey[32]);

/**
 * @brief Load the shared AES-CCM link key (link_ctx.has_link_key).
 *
 * Retains a provisioned legacy link key. Current framing does not support
 * link encryption; TX remains unsigned or uses Schnorr-48 signing.
 *
 * @return 0 on success, -EINVAL/-ENODEV/-EAGAIN as lichen_l2_load_key().
 */
int lichen_l2_load_link_key(const uint8_t link_key[16]);

#ifdef CONFIG_LICHEN_L2_DEV_PROVISIONING
/**
 * @brief INSECURE bench provisioning: fixed dev keypair + one static peer.
 *
 * Loads the publicly-known development seed (shared by every node built
 * with CONFIG_LICHEN_L2_DEV_PROVISIONING) and registers the peer named by
 * CONFIG_LICHEN_L2_DEV_PEER_EUI64 with that same dev public key.
 *
 * SECURITY: Provides no real authentication — the seed is in the source
 * tree. Exists only so the CoAP/IPv6 path can run on the bench before the
 * announce/EDHOC provisioning path lands. Never enable in production.
 *
 * On success, the parsed peer EUI-64 is written to peer_eui64_out (if not
 * NULL) so callers can derive the peer's link-local address.
 *
 * @return 0 on success, negative errno on failure (including -EINVAL for a
 *         malformed CONFIG_LICHEN_L2_DEV_PEER_EUI64).
 */
int lichen_l2_dev_provision(uint8_t peer_eui64_out[8]);
#endif

#ifdef CONFIG_LICHEN_L2_TEST_HOOKS
#define LICHEN_L2_TEST_CAPTURE_MAX 256

struct lichen_l2_test_stats {
	uint32_t tx_packets;
	uint32_t rx_frames;
	uint32_t rx_injected_packets;
	uint32_t last_injected_len;
	uint8_t last_injected[LICHEN_L2_TEST_CAPTURE_MAX];
};

int lichen_l2_test_load_key(const uint8_t seed[32], uint8_t pubkey[32]);
int lichen_l2_test_load_link_key(const uint8_t link_key[16]);
void lichen_l2_test_reset_stats(void);
void lichen_l2_test_get_stats(struct lichen_l2_test_stats *stats);
#endif

/* ─── MTU and addressing ─────────────────────────────────────────────────── */

/**
 * @brief MTU for LICHEN interface
 *
 * Must match LICHEN_LORA_MTU in lora_l2.h. This is the maximum IPv6 packet
 * size we can send. After SCHC compression and LICHEN framing, the on-air
 * payload fits within LoRa limits.
 *
 * When to use each constant:
 * - LICHEN_L2_MTU: Use at the Zephyr network stack layer (net_if, net_pkt).
 *   This is the MTU reported to the IPv6 stack and controls fragmentation.
 * - LICHEN_LORA_MTU: Use at the LoRa driver layer (lora_l2.c). Identical
 *   value, but defined separately to avoid coupling header dependencies.
 *
 * Duplication note: We duplicate rather than include lora_l2.h to avoid
 * forcing consumers of lichen_l2.h to pull in LoRa driver types.
 *
 * Note: Current SCHC rules assume no IPv6 extension headers. Packets with
 * extension headers (Hop-by-Hop, Routing, OSCORE, etc.) exceed the internal
 * buffer size (MTU + 40 for base IPv6 header) and will be rejected. When
 * OSCORE or other extension header support is added, revisit lichen_l2.c
 * buffer sizing and define appropriate SCHC compression rules.
 */
#define LICHEN_L2_MTU 200

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
