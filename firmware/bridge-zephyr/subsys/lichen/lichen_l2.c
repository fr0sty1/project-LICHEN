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

/*
 * SECURITY: Secure memset that won't be optimized away.
 * Standard memset() on dead buffers can be removed by the compiler.
 * The volatile pointer forces each store to actually execute.
 */
static inline void secure_zero(void *ptr, size_t len)
{
	volatile uint8_t *p = ptr;
	while (len--) {
		*p++ = 0;
	}
}

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

/* IPv6 base header size (RFC 8200). Does NOT include extension headers. */
#define IPV6_BASE_HDR_LEN 40

/*
 * Scratch buffers for TX/RX processing.
 * Protected by mutexes since multiple threads may call L2 send/recv.
 *
 * Note: SCHC compression/decompression is handled internally by lichen_link_tx/rx,
 * so we only need the raw IPv6 and final frame buffers here.
 *
 * Buffer sizing: LICHEN_L2_MTU + IPV6_BASE_HDR_LEN = 240 bytes.
 * This assumes no IPv6 extension headers. LICHEN's SCHC rules (schc/rules.py)
 * are defined for specific protocol stacks (CoAP, ICMPv6, RPL) without extension
 * headers; packets with extension headers fall back to rule 255 (uncompressed)
 * and will fail the MTU check. When OSCORE support is added, its headers will
 * need a dedicated SCHC rule, at which point buffer sizing should be revisited.
 */
static uint8_t tx_ipv6_buf[LICHEN_L2_MTU + IPV6_BASE_HDR_LEN];
static uint8_t tx_frame_buf[MAX_LORA_FRAME];
static K_MUTEX_DEFINE(tx_mutex);

static uint8_t rx_ipv6_buf[LICHEN_L2_MTU + IPV6_BASE_HDR_LEN];
static K_MUTEX_DEFINE(rx_mutex);

/* Link context for framing */
#if HAVE_LICHEN_LINK
static struct lichen_link_ctx link_ctx;
/*
 * Guards access to link_ctx before initialization completes.
 * SECURITY: atomic_t prevents torn reads under aggressive optimization.
 * atomic_set() provides release semantics (stores to link_ctx complete first),
 * atomic_get() provides acquire semantics (link_ctx reads happen after).
 */
static atomic_t link_ctx_initialized;
#endif

/*
 * Cached interface pointer for RX callback.
 *
 * Thread-safety invariant (project-LICHEN-ybal.4): This pointer is set exactly
 * once in lichen_l2_iface_init() and is NEVER cleared. The underlying net_if
 * structure is statically allocated by NET_DEVICE_INIT and has device lifetime.
 * DO NOT add code to clear this pointer in lichen_l2_enable(false) or elsewhere
 * - doing so would race with lora_rx_callback() which reads it without a mutex.
 *
 * This is consistent with Zephyr's network interface model: once a net_if is
 * registered, it remains valid until the system is powered down.
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
 * lichen_lora_l2_get_eui64() rather than casting away const to avoid UB
 * if Zephyr ever writes to this buffer. (project-LICHEN-ybal.15/.16)
 */
static uint8_t iface_link_addr[LICHEN_L2_ADDR_LEN];

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
 *
 * Ownership: Per Zephyr net_l2 contract, on success (return 0) this function
 * takes ownership of @p pkt and calls net_pkt_unref(). On error (return < 0),
 * caller retains ownership and is responsible for cleanup.
 */
static int lichen_l2_send(struct net_if *iface, struct net_pkt *pkt)
{
	int ret;

	/* SECURITY: Reject TX if interface initialization failed (project-LICHEN-1ojj.2) */
	if (atomic_get(&iface_init_failed)) {
		LOG_ERR("TX rejected: interface initialization failed");
		return -ENODEV;
	}

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

	/* Linearize packet into scratch buffer using Zephyr's cursor API */
	net_pkt_cursor_init(pkt);
	ret = net_pkt_read(pkt, tx_ipv6_buf, pkt_len);
	if (ret < 0) {
		LOG_ERR("Failed to linearize packet: %d", ret);
		k_mutex_unlock(&tx_mutex);
		return ret;
	}

	LOG_DBG("TX IPv6 packet: %zu bytes", pkt_len);

#if HAVE_LICHEN_LINK
	/*
	 * Guard against access before initialization.
	 * This mirrors the RX path guard - could happen if IPv6 stack tries
	 * to transmit during early startup before lichen_l2_iface_init() completes.
	 */
	if (!atomic_get(&link_ctx_initialized)) {
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

	/*
	 * Per Zephyr net_l2 contract: when L2 returns 0, it took ownership
	 * of the packet and must free it. The caller (IPv6 stack) will not
	 * free it on success.
	 */
	net_pkt_unref(pkt);
	return 0;
}

/**
 * @brief L2 enable/disable handler
 */
static int lichen_l2_enable(struct net_if *iface, bool state)
{
	ARG_UNUSED(iface);

	/* SECURITY: Reject enable if interface initialization failed (project-LICHEN-1ojj.2) */
	if (atomic_get(&iface_init_failed)) {
		LOG_ERR("Enable rejected: interface initialization failed");
		return -ENODEV;
	}

	LOG_INF("LICHEN L2 %s", state ? "enabled" : "disabled");

	if (state) {
#if HAVE_LICHEN_LINK
		/*
		 * Re-initialize link_ctx if it was cleaned up by a prior disable.
		 * This mirrors lichen_l2_iface_init() initialization.
		 * (project-LICHEN-rwio.1)
		 */
		if (!atomic_get(&link_ctx_initialized)) {
			const uint8_t *eui64 = lichen_lora_l2_get_eui64();
			if (eui64 == NULL) {
				LOG_ERR("Failed to get EUI-64 for link_ctx re-init");
				return -ENODEV;
			}
			lichen_link_init(&link_ctx, eui64);
			atomic_set(&link_ctx_initialized, 1);
		}
#endif
		return lichen_lora_l2_start();
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
		int ret = lichen_lora_l2_stop();
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
		 * Lock order: tx_mutex first to avoid deadlock (consistent ordering).
		 *
		 * SECURITY: lichen_l2_input() copies link_key into a local buffer
		 * before use, but the copy happens under rx_mutex. Cleanup MUST
		 * acquire rx_mutex to ensure any in-flight RX completes first.
		 */
		k_mutex_lock(&tx_mutex, K_FOREVER);
		k_mutex_lock(&rx_mutex, K_FOREVER);
		atomic_set(&link_ctx_initialized, 0);
		lichen_link_cleanup(&link_ctx);
		k_mutex_unlock(&rx_mutex);
		k_mutex_unlock(&tx_mutex);
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

	/*
	 * Check both conditions to distinguish init-failure from never-initialized.
	 * (project-LICHEN-rwio.11)
	 */
	if (lichen_iface == NULL || atomic_get(&iface_init_failed)) {
		LOG_WRN("Interface not ready");
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
 * On failure, sets iface_init_failed flag and returns early. The L2 send/recv
 * paths check this flag to reject operations on a half-initialized interface.
 *
 * @param iface The network interface being initialized (from NET_DEVICE_INIT)
 */
void lichen_l2_iface_init(struct net_if *iface)
{
	int ret;

	LOG_INF("Initializing LICHEN L2 interface");

	/* Initialize LoRa driver */
	ret = lichen_lora_l2_init();
	if (ret < 0) {
		LOG_ERR("LoRa L2 init failed: %d", ret);
		atomic_set(&iface_init_failed, 1);
		return;
	}

	/* Get our EUI-64 */
	const uint8_t *eui64 = lichen_lora_l2_get_eui64();
	if (eui64 == NULL) {
		LOG_ERR("Failed to get EUI-64 from LoRa L2");
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
	net_if_set_link_addr(iface, iface_link_addr, LICHEN_L2_ADDR_LEN,
			     NET_LINK_UNKNOWN);

#if HAVE_LICHEN_LINK
	/* Initialize link context before enabling RX */
	lichen_link_init(&link_ctx, eui64);
	/*
	 * Mark link_ctx as safe to access.
	 * atomic_set() provides release semantics - all stores to link_ctx
	 * are visible before the flag becomes true.
	 */
	atomic_set(&link_ctx_initialized, 1);
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

	/* Validate required parameters (project-LICHEN-ybal.28) */
	if (iface == NULL) {
		LOG_ERR("lichen_l2_input: iface is NULL");
		return;
	}
	if (data == NULL) {
		LOG_ERR("lichen_l2_input: data is NULL");
		return;
	}
	/* Reject empty frames before taking mutex (project-LICHEN-1ojj.7) */
	if (len == 0) {
		LOG_DBG("RX: empty frame ignored");
		return;
	}

	LOG_DBG("RX: %zu bytes, RSSI=%d, SNR=%d", len, rssi, snr);

	k_mutex_lock(&rx_mutex, K_FOREVER);

#if HAVE_LICHEN_LINK
	/*
	 * Guard against access before initialization.
	 * This shouldn't happen in normal operation, but could if a packet
	 * arrives during early startup before lichen_l2_iface_init() completes.
	 */
	if (!atomic_get(&link_ctx_initialized)) {
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
	 *
	 * SECURITY: Copy link_key into a local buffer rather than capturing a
	 * pointer to link_ctx.link_key. This ensures rx_ctx remains valid even
	 * if a future refactor moves lichen_link_cleanup() outside the rx_mutex.
	 * The current code is safe (cleanup holds both mutexes), but copying
	 * eliminates a subtle lifetime dependency that could cause use-after-free
	 * if cleanup timing changes. 16-byte copy is cheap. (project-LICHEN-ybal.7)
	 */
	uint8_t rx_link_key[LICHEN_LINK_KEY_LEN];
	const uint8_t *rx_link_key_ptr = NULL;
	if (link_ctx.has_link_key) {
		memcpy(rx_link_key, link_ctx.link_key, LICHEN_LINK_KEY_LEN);
		rx_link_key_ptr = rx_link_key;
	}

	struct lichen_link_rx_ctx rx_ctx = {
		.peer_pubkey = NULL,  /* Unknown sender - no signature verification */
		.peer_eui64 = NULL,   /* Unknown sender - CRC32 mode only */
		.link_key = rx_link_key_ptr,
		.current_time = 0,
	};
	uint8_t src_eui64[8];

	ipv6_len = sizeof(rx_ipv6_buf);
	ret = lichen_link_rx(&rx_ctx, NULL, data, len,
			     rx_ipv6_buf, &ipv6_len, src_eui64);
	if (ret < 0) {
		LOG_WRN("Frame RX failed: %d", ret);
		secure_zero(rx_link_key, sizeof(rx_link_key));
		k_mutex_unlock(&rx_mutex);
		return;
	}

	LOG_DBG("Decompressed %zu bytes from %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		ipv6_len,
		src_eui64[0], src_eui64[1], src_eui64[2], src_eui64[3],
		src_eui64[4], src_eui64[5], src_eui64[6], src_eui64[7]);

	/* SECURITY: Zero local key copy before any exit (project-LICHEN-1ojj.28) */
	secure_zero(rx_link_key, sizeof(rx_link_key));
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
