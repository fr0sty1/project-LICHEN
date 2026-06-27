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

#include <zephyr/kernel.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/logging/log.h>

#include <string.h>

LOG_MODULE_REGISTER(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

/* Include LICHEN link layer if available */
#if defined(CONFIG_LICHEN_LINK)
#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/schc.h>
#define HAVE_LICHEN_LINK 1
#else
#define HAVE_LICHEN_LINK 0
#endif

/* Maximum frame size for LoRa */
#define MAX_LORA_FRAME 255

/*
 * Scratch buffers for TX/RX processing.
 * Protected by mutexes since multiple threads may call L2 send/recv.
 *
 * Note: SCHC compression/decompression is handled internally by lichen_link_tx/rx,
 * so we only need the raw IPv6 and final frame buffers here.
 *
 * Buffer sizing: LICHEN_L2_MTU (200) + 40 (IPv6 base header) = 240 bytes.
 * This assumes no IPv6 extension headers. LICHEN's SCHC rules (schc/rules.py)
 * are defined for specific protocol stacks (CoAP, ICMPv6, RPL) without extension
 * headers; packets with extension headers fall back to rule 255 (uncompressed)
 * and will fail the MTU check. When OSCORE support is added, its headers will
 * need a dedicated SCHC rule, at which point buffer sizing should be revisited.
 */
static uint8_t tx_ipv6_buf[LICHEN_L2_MTU + 40];  /* IPv6 base header + payload */
static uint8_t tx_frame_buf[MAX_LORA_FRAME];     /* LICHEN frame */
static K_MUTEX_DEFINE(tx_mutex);

static uint8_t rx_ipv6_buf[LICHEN_L2_MTU + 40];  /* Decompressed IPv6 (base hdr) */
static K_MUTEX_DEFINE(rx_mutex);

/* Link context for framing */
#if HAVE_LICHEN_LINK
static struct lichen_link_ctx link_ctx;
static bool link_ctx_initialized;  /* Guards access to link_ctx (python-ano.27) */
#endif

/* Cached interface pointer for RX callback */
static struct net_if *lichen_iface;

/**
 * @brief L2 receive handler
 *
 * Called by net_recv_data() to let L2 process the packet before
 * passing it up to the IP layer.
 */
static enum net_verdict lichen_l2_recv(struct net_if *iface,
				       struct net_pkt *pkt)
{
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
 */
static int lichen_l2_send(struct net_if *iface, struct net_pkt *pkt)
{
	int ret;

	if (!lichen_lora_l2_is_running()) {
		LOG_WRN("LoRa L2 not running");
		return -ENETDOWN;
	}

	/* Linearize the packet into our scratch buffer */
	size_t pkt_len = net_pkt_get_len(pkt);

	if (pkt_len > sizeof(tx_ipv6_buf)) {
		LOG_ERR("Packet too large: %zu > %zu", pkt_len, sizeof(tx_ipv6_buf));
		return -EMSGSIZE;
	}

	k_mutex_lock(&tx_mutex, K_FOREVER);

	struct net_buf *frag = pkt->frags;
	size_t offset = 0;

	while (frag && offset < pkt_len) {
		size_t copy_len = frag->len;

		if (offset + copy_len > sizeof(tx_ipv6_buf)) {
			LOG_ERR("Fragment exceeds buffer during linearization: "
				"offset=%zu frag_len=%zu buf_size=%zu",
				offset, frag->len, sizeof(tx_ipv6_buf));
			k_mutex_unlock(&tx_mutex);
			return -EMSGSIZE;
		}
		memcpy(&tx_ipv6_buf[offset], frag->data, copy_len);
		offset += copy_len;
		frag = frag->frags;
	}

	LOG_DBG("TX IPv6 packet: %zu bytes", pkt_len);

#if HAVE_LICHEN_LINK
	/*
	 * Guard against access before initialization (python-t7j5.1).
	 * This mirrors the RX path guard - could happen if IPv6 stack tries
	 * to transmit during early startup before lichen_l2_iface_init() completes.
	 */
	if (!link_ctx_initialized) {
		LOG_WRN("TX attempted before link_ctx initialized");
		k_mutex_unlock(&tx_mutex);
		return -EAGAIN;
	}

	/*
	 * Use lichen_link_tx() to build the complete frame with proper MIC.
	 * This handles:
	 * - SCHC compression
	 * - Schnorr-48 signature if has_key
	 * - AES-CCM-64 MIC if has_link_key, else CRC32 fallback
	 */
	size_t frame_len = sizeof(tx_frame_buf);
	ret = lichen_link_tx(&link_ctx, tx_ipv6_buf, pkt_len, NULL,
			     tx_frame_buf, &frame_len);
	if (ret < 0) {
		LOG_ERR("Frame build failed: %d", ret);
		k_mutex_unlock(&tx_mutex);
		return ret;
	}

	LOG_DBG("LICHEN frame: %zu bytes", frame_len);

	/* Send via LoRa */
	ret = lichen_lora_l2_tx(tx_frame_buf, frame_len);
#else
	/* No LICHEN link layer - send raw IPv6 (for testing) */
	ret = lichen_lora_l2_tx(tx_ipv6_buf, pkt_len);
#endif

	k_mutex_unlock(&tx_mutex);

	if (ret < 0) {
		LOG_ERR("LoRa TX failed: %d", ret);
		return ret;
	}

	/* Return 0 on success (packet was sent) */
	return 0;
}

/**
 * @brief L2 enable/disable handler
 */
static int lichen_l2_enable(struct net_if *iface, bool state)
{
	ARG_UNUSED(iface);
	LOG_INF("LICHEN L2 %s", state ? "enabled" : "disabled");

	if (state) {
		return lichen_lora_l2_start();
	} else {
		int ret = lichen_lora_l2_stop();
#if HAVE_LICHEN_LINK
		/*
		 * Clean up link context: wipe keys, reset sequence state.
		 * Hold rx_mutex to prevent TOCTOU race with lichen_l2_input() -
		 * ensures any in-flight RX completes before we invalidate link_ctx.
		 * (python-t7j5.4)
		 */
		k_mutex_lock(&rx_mutex, K_FOREVER);
		link_ctx_initialized = false;
		lichen_link_cleanup(&link_ctx);
		k_mutex_unlock(&rx_mutex);
#endif
		return ret;
	}
}

/**
 * @brief L2 flags handler
 */
static enum net_l2_flags lichen_l2_flags(struct net_if *iface)
{
	/*
	 * LICHEN is a broadcast medium (all nodes hear all transmissions).
	 * We support multicast at the IP layer.
	 */
	return NET_L2_MULTICAST;
}

/* Register the L2 layer */
NET_L2_INIT(LICHEN_L2, lichen_l2_recv, lichen_l2_send, lichen_l2_enable,
	    lichen_l2_flags);

/*
 * L2 context type - empty since we use static state.
 * Required by NET_DEVICE_INIT.
 */
struct lichen_l2_ctx {
	/* Empty - all state is static in this module */
};

/* Define the context type macro for NET_DEVICE_INIT */
#define NET_L2_GET_CTX_TYPE_LICHEN_L2 struct lichen_l2_ctx

/*
 * Network interface API - provides init callback.
 * We use Zephyr's dummy API structure since we don't have hardware-specific
 * send/recv callbacks (those go through L2 callbacks instead).
 */
static void lichen_dev_iface_init(struct net_if *iface)
{
	lichen_l2_iface_init(iface);
}

/*
 * The iface_api structure provides the init callback. We don't implement
 * start/stop here since L2 enable/disable handles that.
 */
static struct net_if_api lichen_iface_api = {
	.init = lichen_dev_iface_init,
};

/*
 * Register LICHEN as a network device. This creates a net_if and wires
 * it to our L2 layer. The device is a software-defined interface -
 * actual hardware (LoRa radio) is accessed via lora_l2.c.
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

	if (lichen_iface == NULL) {
		LOG_WRN("No interface registered");
		return;
	}

	lichen_l2_input(lichen_iface, data, len, rssi, snr);
}

void lichen_l2_iface_init(struct net_if *iface)
{
	int ret;

	LOG_INF("Initializing LICHEN L2 interface");

	/* Initialize LoRa driver */
	ret = lichen_lora_l2_init();
	if (ret < 0) {
		LOG_ERR("LoRa L2 init failed: %d", ret);
		return;
	}

	/* Get our EUI-64 */
	const uint8_t *eui64 = lichen_lora_l2_get_eui64();
	if (eui64 == NULL) {
		LOG_ERR("Failed to get EUI-64 from LoRa L2");
		return;
	}

	/* Set link-layer address on the interface */
	net_if_set_link_addr(iface, (uint8_t *)eui64, LICHEN_L2_ADDR_LEN,
			     NET_LINK_UNKNOWN);

#if HAVE_LICHEN_LINK
	/* Initialize link context before enabling RX */
	lichen_link_init(&link_ctx, eui64);
	link_ctx_initialized = true;  /* Mark as safe to access (python-ano.27) */
#endif

	/* Cache interface for RX callback */
	lichen_iface = iface;

	/* Register RX callback - must happen AFTER link_ctx is initialized */
	lichen_lora_l2_set_rx_callback(lora_rx_callback, NULL);

	/* Derive and log link-local address */
	uint8_t iid[8];
	struct in6_addr ll_addr;
	char addr_str[LICHEN_IPV6_ADDR_STR_LEN];

	lichen_eui64_to_iid(eui64, iid);
	lichen_make_link_local(iid, &ll_addr);
	lichen_ipv6_addr_to_str(&ll_addr, addr_str, sizeof(addr_str));
	LOG_INF("Link-local: %s", addr_str);

	LOG_INF("LICHEN L2 interface initialized");
}

void lichen_l2_input(struct net_if *iface, const uint8_t *data, size_t len,
		     int16_t rssi, int8_t snr)
{
	int ret;
	size_t ipv6_len;

	LOG_DBG("RX: %zu bytes, RSSI=%d, SNR=%d", len, rssi, snr);

	k_mutex_lock(&rx_mutex, K_FOREVER);

#if HAVE_LICHEN_LINK
	/*
	 * Guard against access before initialization (python-ano.27).
	 * This shouldn't happen in normal operation, but could if a packet
	 * arrives during early startup before lichen_l2_iface_init() completes.
	 */
	if (!link_ctx_initialized) {
		LOG_WRN("RX before link_ctx initialized - dropping frame");
		k_mutex_unlock(&rx_mutex);
		return;
	}

	/*
	 * Use lichen_link_rx() to process the complete frame. This handles:
	 * - Frame parsing
	 * - Replay protection (if replay table provided)
	 * - Schnorr-48 signature verification (if peer_pubkey provided)
	 * - MIC verification (AES-CCM-64 or CRC32)
	 * - SCHC decompression
	 *
	 * For broadcast reception without peer context, we use minimal RX ctx.
	 */
	struct lichen_link_rx_ctx rx_ctx = {
		.peer_pubkey = NULL,  /* Unknown sender - no signature verification */
		.peer_eui64 = NULL,   /* Unknown sender - CRC32 mode only */
		.link_key = link_ctx.has_link_key ? link_ctx.link_key : NULL,
		.current_time = 0,
	};
	uint8_t src_eui64[8];

	ipv6_len = sizeof(rx_ipv6_buf);
	ret = lichen_link_rx(&rx_ctx, NULL, data, len,
			     rx_ipv6_buf, &ipv6_len, src_eui64);
	if (ret < 0) {
		LOG_WRN("Frame RX failed: %d", ret);
		k_mutex_unlock(&rx_mutex);
		return;
	}

	LOG_DBG("Decompressed %zu bytes from %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		ipv6_len,
		src_eui64[0], src_eui64[1], src_eui64[2], src_eui64[3],
		src_eui64[4], src_eui64[5], src_eui64[6], src_eui64[7]);
#else
	/* No LICHEN link layer - treat as raw IPv6 */
	if (len > sizeof(rx_ipv6_buf)) {
		LOG_WRN("Packet too large: %zu", len);
		k_mutex_unlock(&rx_mutex);
		return;
	}
	memcpy(rx_ipv6_buf, data, len);
	ipv6_len = len;
#endif

	/* Allocate net_pkt for the IPv6 packet */
	struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(iface, ipv6_len,
							   AF_INET6,
							   0, K_NO_WAIT);
	if (pkt == NULL) {
		LOG_ERR("Failed to allocate RX packet");
		k_mutex_unlock(&rx_mutex);
		return;
	}

	/* Write IPv6 data into the packet */
	ret = net_pkt_write(pkt, rx_ipv6_buf, ipv6_len);
	if (ret < 0) {
		LOG_ERR("Failed to write packet data: %d", ret);
		net_pkt_unref(pkt);
		k_mutex_unlock(&rx_mutex);
		return;
	}

	k_mutex_unlock(&rx_mutex);

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
		LOG_ERR("net_recv_data failed: %d", ret);
		net_pkt_unref(pkt);
		return;
	}

	/* pkt ownership transferred to network stack - do not access */
	LOG_DBG("Injected %zu byte IPv6 packet into stack", ipv6_len);
}
