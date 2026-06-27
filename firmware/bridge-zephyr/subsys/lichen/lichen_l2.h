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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief MTU for LICHEN interface
 *
 * Must match LICHEN_LORA_MTU in lora_l2.h. This is the maximum IPv6 packet
 * size we can send. After SCHC compression and LICHEN framing, the on-air
 * payload fits within LoRa limits.
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

/* Declare the L2 struct for external reference */
NET_L2_DECLARE_PUBLIC(LICHEN_L2);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_L2_H_ */
