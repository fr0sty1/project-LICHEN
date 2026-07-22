/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file slip_transport.c
 * @brief SLIP transport for LCI (Local Client Interface)
 *
 * Implements RFC 1055 SLIP framing over UART/USB-CDC for IPv6 packet transport.
 * This module creates a Zephyr network interface that can be used with standard
 * networking APIs.
 *
 * The implementation uses Zephyr's UART API for portability across targets:
 * - Real hardware: UART or USB-CDC device
 * - native_sim: Serial PTY for testing with slattach/tunslip6
 *
 * Per LCI spec 17.3.1:
 * - SLIP framing: END=0xC0, ESC=0xDB, ESC_END=0xDC, ESC_ESC=0xDD
 * - Node address: fe80::1
 * - MTU: 1280 (IPv6 minimum)
 */

#include <lichen/transport/slip_transport.h>

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/dummy.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/ring_buffer.h>

LOG_MODULE_REGISTER(slip_transport, CONFIG_SLIP_TRANSPORT_LOG_LEVEL);

/* Configuration from Kconfig */
#define RX_RING_SIZE CONFIG_SLIP_TRANSPORT_RX_RING_SIZE
#define RX_THREAD_STACK_SIZE CONFIG_SLIP_TRANSPORT_RX_THREAD_STACK_SIZE
#define RX_THREAD_PRIORITY CONFIG_SLIP_TRANSPORT_RX_THREAD_PRIORITY

/* SLIP framing state machine */
enum slip_rx_state {
	SLIP_STATE_IDLE,    /* Waiting for first byte or END */
	SLIP_STATE_DATA,    /* Receiving packet data */
	SLIP_STATE_ESC,     /* Previous byte was ESC */
};

/* Transport context */
struct slip_transport_ctx {
	const struct device *uart_dev;
	bool initialized;

	/* TX state */
	struct k_mutex tx_mutex;
	uint8_t tx_frame[SLIP_LCI_MTU * 2u + 2u]; /* Worst case: all escaped + 2 END */
#ifdef CONFIG_ZTEST
	uint8_t last_tx[SLIP_LCI_MTU * 2u + 2u];
	size_t last_tx_len;
#endif

	/* RX state - protected by rx_mutex */
	struct k_mutex rx_mutex;
	enum slip_rx_state rx_state;
	uint8_t rx_pkt[SLIP_LCI_MTU];
	size_t rx_len;
	bool rx_overflow;

	/* RX ring buffer for interrupt-to-thread transfer */
	uint8_t rx_ring_buf[RX_RING_SIZE];
	struct ring_buf rx_ring;
	struct k_sem rx_sem;

	/* Statistics - protected by stats_mutex */
	struct k_mutex stats_mutex;
	struct slip_transport_stats stats;

	/* Link address (8 bytes for consistency with other LCI interfaces) */
	uint8_t link_addr[8];
};

static struct slip_transport_ctx s_ctx = {
	/* Node IID: produces fe80::1 */
	.link_addr = SLIP_LCI_NODE_IID,
};

/* Forward declarations */
static void slip_rx_thread_fn(void *p1, void *p2, void *p3);

/* RX thread */
static K_THREAD_STACK_DEFINE(s_rx_stack, RX_THREAD_STACK_SIZE);
static struct k_thread s_rx_thread;
static K_MUTEX_DEFINE(s_init_mutex);

/* --------------------------------------------------------------------------
 * IPv6 helpers
 * -------------------------------------------------------------------------- */

#define IPV6_VERSION_VALUE  6u
#define IPV6_VERSION_SHIFT  4u
#define IPV6_PAYLOAD_OFFSET 4u
#define IPV6_HDR_LEN        40u

static uint8_t ipv6_version(const uint8_t *pkt)
{
	return pkt[0] >> IPV6_VERSION_SHIFT;
}

static uint16_t ipv6_payload_len(const uint8_t *pkt)
{
	return sys_get_be16(&pkt[IPV6_PAYLOAD_OFFSET]);
}

static int validate_ipv6_packet(const uint8_t *pkt, size_t len)
{
	size_t expected;

	if (pkt == NULL) {
		return -EINVAL;
	}

	if (len < IPV6_HDR_LEN) {
		LOG_WRN("SLIP RX: packet too short (%zu < %u)", len, IPV6_HDR_LEN);
		return -EMSGSIZE;
	}

	if (len > SLIP_LCI_MTU) {
		LOG_WRN("SLIP RX: packet exceeds MTU (%zu > %u)", len, SLIP_LCI_MTU);
		return -EMSGSIZE;
	}

	if (ipv6_version(pkt) != IPV6_VERSION_VALUE) {
		LOG_WRN("SLIP RX: invalid IP version %u", ipv6_version(pkt));
		return -EPROTONOSUPPORT;
	}

	expected = IPV6_HDR_LEN + ipv6_payload_len(pkt);
	if (expected != len) {
		LOG_WRN("SLIP RX: length mismatch (header says %zu, got %zu)",
			expected, len);
		return -EINVAL;
	}

	return 0;
}

/* --------------------------------------------------------------------------
 * SLIP framing
 * -------------------------------------------------------------------------- */

/**
 * @brief Encode a packet with SLIP framing
 *
 * @param ipv6   Input IPv6 packet
 * @param ipv6_len Length of input packet
 * @param frame  Output buffer for SLIP frame
 * @param frame_max Maximum output buffer size
 * @param frame_len Output: actual frame length
 * @return 0 on success, negative errno on failure
 */
static int slip_encode(const uint8_t *ipv6, size_t ipv6_len,
		       uint8_t *frame, size_t frame_max, size_t *frame_len)
{
	size_t fi = 0;

	/* Start with END byte */
	if (fi >= frame_max) {
		return -ENOMEM;
	}
	frame[fi++] = SLIP_END;

	/* Encode packet with escaping */
	for (size_t i = 0; i < ipv6_len; i++) {
		uint8_t b = ipv6[i];

		if (b == SLIP_END) {
			if (fi + 2u > frame_max - 1u) {
				return -ENOMEM;
			}
			frame[fi++] = SLIP_ESC;
			frame[fi++] = SLIP_ESC_END;
		} else if (b == SLIP_ESC) {
			if (fi + 2u > frame_max - 1u) {
				return -ENOMEM;
			}
			frame[fi++] = SLIP_ESC;
			frame[fi++] = SLIP_ESC_ESC;
		} else {
			if (fi + 1u > frame_max - 1u) {
				return -ENOMEM;
			}
			frame[fi++] = b;
		}
	}

	/* End with END byte */
	frame[fi++] = SLIP_END;

	*frame_len = fi;
	return 0;
}

/**
 * @brief Process one received byte through the SLIP state machine
 *
 * @param ctx Transport context
 * @param b   Received byte
 * @return 1 if a complete packet is ready, 0 otherwise
 */
static int slip_decode_byte(struct slip_transport_ctx *ctx, uint8_t b)
{
	if (ctx == NULL) {
		return 0;
	}
	switch (ctx->rx_state) {
	case SLIP_STATE_IDLE:
		if (b == SLIP_END) {
			/* Empty frame or frame delimiter - stay idle */
			ctx->rx_len = 0;
			ctx->rx_overflow = false;
		} else if (b == SLIP_ESC) {
			ctx->rx_len = 0;
			ctx->rx_overflow = false;
			ctx->rx_state = SLIP_STATE_ESC;
		} else {
			/* First data byte */
			ctx->rx_state = SLIP_STATE_DATA;
			ctx->rx_len = 0;
			ctx->rx_overflow = false;
			if (ctx->rx_len < sizeof(ctx->rx_pkt)) {
				ctx->rx_pkt[ctx->rx_len++] = b;
			} else {
				ctx->rx_overflow = true;
			}
		}
		break;

	case SLIP_STATE_DATA:
		if (b == SLIP_END) {
			/* Frame complete */
			ctx->rx_state = SLIP_STATE_IDLE;
			if (ctx->rx_len > 0 && !ctx->rx_overflow) {
				return 1;
			}
			/* Empty or overflow frame - discard */
			if (ctx->rx_overflow) {
				k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
				ctx->stats.rx_overflow++;
				k_mutex_unlock(&ctx->stats_mutex);
			}
			ctx->rx_len = 0;
			ctx->rx_overflow = false;
		} else if (b == SLIP_ESC) {
			ctx->rx_state = SLIP_STATE_ESC;
		} else {
			if (ctx->rx_len < sizeof(ctx->rx_pkt)) {
				ctx->rx_pkt[ctx->rx_len++] = b;
			} else {
				ctx->rx_overflow = true;
			}
		}
		break;

	case SLIP_STATE_ESC:
		if (b == SLIP_ESC_END) {
			b = SLIP_END;
		} else if (b == SLIP_ESC_ESC) {
			b = SLIP_ESC;
		} else {
			/* Invalid escape sequence - discard entire frame per RFC 1055 */
			LOG_WRN("SLIP RX: invalid escape sequence 0x%02x, discarding frame", b);
			k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
			ctx->stats.slip_frame_errors++;
			k_mutex_unlock(&ctx->stats_mutex);
			ctx->rx_state = SLIP_STATE_IDLE;
			ctx->rx_len = 0;
			ctx->rx_overflow = false;
			break;
		}

		ctx->rx_state = SLIP_STATE_DATA;
		if (ctx->rx_len < sizeof(ctx->rx_pkt)) {
			ctx->rx_pkt[ctx->rx_len++] = b;
		} else {
			ctx->rx_overflow = true;
		}
		break;
	}

	return 0;
}

/* --------------------------------------------------------------------------
 * Packet dispatch
 * -------------------------------------------------------------------------- */

static void slip_dispatch_packet(struct slip_transport_ctx *ctx)
{
	struct net_if *iface;
	struct net_pkt *pkt;
	int ret;

	if (ctx->rx_overflow) {
		LOG_WRN("SLIP RX: frame dropped (overflow)");
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.rx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		return;
	}

	ret = validate_ipv6_packet(ctx->rx_pkt, ctx->rx_len);
	if (ret < 0) {
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.rx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		return;
	}

	iface = slip_transport_iface_get();
	if (iface == NULL) {
		LOG_WRN("SLIP RX: no interface available");
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.rx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		return;
	}

	pkt = net_pkt_rx_alloc_with_buffer(iface, ctx->rx_len, AF_INET6,
					   IPPROTO_RAW, K_NO_WAIT);
	if (pkt == NULL) {
		LOG_WRN("SLIP RX: failed to allocate packet buffer");
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.rx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		return;
	}

	ret = net_pkt_write(pkt, ctx->rx_pkt, ctx->rx_len);
	if (ret < 0) {
		LOG_WRN("SLIP RX: failed to write packet data: %d", ret);
		net_pkt_unref(pkt);
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.rx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		return;
	}

	ret = net_recv_data(iface, pkt);
	if (ret < 0) {
		LOG_WRN("SLIP RX: net_recv_data failed: %d", ret);
		net_pkt_unref(pkt);
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.rx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		return;
	}

	k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
	ctx->stats.rx_packets++;
	ctx->stats.rx_bytes += ctx->rx_len;
	k_mutex_unlock(&ctx->stats_mutex);
	LOG_DBG("SLIP RX: %zu bytes delivered to network stack", ctx->rx_len);
}

/* --------------------------------------------------------------------------
 * UART callbacks and RX thread
 * -------------------------------------------------------------------------- */

static void uart_rx_callback(const struct device *dev, void *user_data)
{
	struct slip_transport_ctx *ctx = user_data;
	uint8_t c;

	ARG_UNUSED(dev);

	while (uart_irq_update(ctx->uart_dev) &&
	       uart_irq_rx_ready(ctx->uart_dev)) {
		int n = uart_fifo_read(ctx->uart_dev, &c, 1);

		if (n == 1) {
			uint32_t written = ring_buf_put(&ctx->rx_ring, &c, 1);

			if (written == 0) {
				/* Ring buffer full - drop byte */
				LOG_WRN("SLIP RX: ring buffer overflow");
			}
			k_sem_give(&ctx->rx_sem);
		}
	}
}

static void slip_rx_thread_fn(void *p1, void *p2, void *p3)
{
	struct slip_transport_ctx *ctx = p1;
	uint8_t buf[32];
	uint32_t n;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("SLIP RX thread started");

	while (true) {
		k_sem_take(&ctx->rx_sem, K_FOREVER);

		k_mutex_lock(&ctx->rx_mutex, K_FOREVER);

		/* Drain the ring buffer */
		while ((n = ring_buf_get(&ctx->rx_ring, buf, sizeof(buf))) > 0) {
			for (uint32_t i = 0; i < n; i++) {
				if (slip_decode_byte(ctx, buf[i])) {
					slip_dispatch_packet(ctx);
					ctx->rx_len = 0;
					ctx->rx_overflow = false;
				}
			}
		}

		k_mutex_unlock(&ctx->rx_mutex);
	}
}

/* --------------------------------------------------------------------------
 * Network interface callbacks
 * -------------------------------------------------------------------------- */

static void slip_make_link_local(const uint8_t iid[8], struct in6_addr *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->s6_addr[0] = 0xfe;
	addr->s6_addr[1] = 0x80;
	memcpy(&addr->s6_addr[8], iid, 8);
}

static void slip_iface_init(struct net_if *iface)
{
	struct slip_transport_ctx *ctx = net_if_get_device(iface)->data;
	struct net_if_addr *ifaddr;
	struct in6_addr ll_addr;
	int ret;

	LOG_DBG("SLIP interface init");

	/* Configure interface as point-to-point, no ND */
	net_if_flag_set(iface, NET_IF_POINTOPOINT);
	net_if_flag_set(iface, NET_IF_IPV6_NO_ND);

	/* Set link address */
	net_if_set_link_addr(iface, ctx->link_addr, sizeof(ctx->link_addr),
			     NET_LINK_IEEE802154);

	/* Add link-local address (fe80::1 for node) */
	slip_make_link_local(ctx->link_addr, &ll_addr);
	ifaddr = net_if_ipv6_addr_add(iface, &ll_addr, NET_ADDR_MANUAL, 0);
	if (ifaddr == NULL) {
		LOG_WRN("SLIP: failed to add link-local address");
	} else {
		LOG_INF("SLIP: link-local address added");
	}

	/* Bring interface up */
	ret = net_if_up(iface);
	if (ret < 0 && ret != -EALREADY) {
		LOG_WRN("SLIP: failed to bring interface up: %d", ret);
	}
}

static int slip_iface_send(const struct device *dev, struct net_pkt *pkt)
{
	struct slip_transport_ctx *ctx = dev->data;
	size_t pkt_len = net_pkt_get_len(pkt);
	uint8_t pkt_buf[SLIP_LCI_MTU];
	size_t frame_len;
	int ret;

	if (pkt_len > sizeof(pkt_buf)) {
		LOG_WRN("SLIP TX: packet too large (%zu > %zu)", pkt_len, sizeof(pkt_buf));
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.tx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		return -EMSGSIZE;
	}

	k_mutex_lock(&ctx->tx_mutex, K_FOREVER);

	/* Extract packet data */
	net_pkt_cursor_init(pkt);
	ret = net_pkt_read(pkt, pkt_buf, pkt_len);
	if (ret < 0) {
		LOG_WRN("SLIP TX: failed to read packet: %d", ret);
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.tx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		k_mutex_unlock(&ctx->tx_mutex);
		return ret;
	}

	/* Encode with SLIP framing */
	ret = slip_encode(pkt_buf, pkt_len, ctx->tx_frame, sizeof(ctx->tx_frame),
			  &frame_len);
	if (ret < 0) {
		LOG_WRN("SLIP TX: encode failed: %d", ret);
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.tx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		k_mutex_unlock(&ctx->tx_mutex);
		return ret;
	}

#ifdef CONFIG_ZTEST
	memcpy(ctx->last_tx, ctx->tx_frame, frame_len);
	ctx->last_tx_len = frame_len;
#endif

	/* Transmit over UART */
	if (ctx->uart_dev != NULL) {
		for (size_t i = 0; i < frame_len; i++) {
			uart_poll_out(ctx->uart_dev, ctx->tx_frame[i]);
		}
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.tx_packets++;
		ctx->stats.tx_bytes += (uint32_t)pkt_len;
		k_mutex_unlock(&ctx->stats_mutex);
	} else {
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.tx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		ret = -ENODEV;
	}

	k_mutex_unlock(&ctx->tx_mutex);

	LOG_DBG("SLIP TX: %zu bytes IPv6 -> %zu bytes framed", pkt_len, frame_len);
	return ret;
}

static const struct dummy_api s_slip_api = {
	.iface_api.init = slip_iface_init,
	.send = slip_iface_send,
};

/* --------------------------------------------------------------------------
 * Device definition
 * -------------------------------------------------------------------------- */

/*
 * NET_DEVICE_INIT defines the network device and calls slip_init at boot.
 * We use NULL for the init function because actual UART setup happens in
 * slip_transport_init(), which should be called after the UART device is ready.
 */
NET_DEVICE_INIT(slip_lci, "slip_lci",
		NULL, NULL, &s_ctx, NULL,
		CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
		&s_slip_api, DUMMY_L2, NET_L2_GET_CTX_TYPE(DUMMY_L2),
		SLIP_LCI_MTU);

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

struct net_if *slip_transport_iface_get(void)
{
	return net_if_lookup_by_dev(DEVICE_GET(slip_lci));
}

int slip_transport_send(const uint8_t *ipv6, size_t len)
{
	struct slip_transport_ctx *ctx = &s_ctx;
	size_t frame_len;
	int ret = 0;

	if (ipv6 == NULL && len > 0) {
		return -EINVAL;
	}

	if (len > SLIP_LCI_MTU) {
		return -EMSGSIZE;
	}
	if (!ctx->initialized) {
		return -ENODEV;
	}

	k_mutex_lock(&ctx->tx_mutex, K_FOREVER);

	ret = slip_encode(ipv6, len, ctx->tx_frame, sizeof(ctx->tx_frame),
			  &frame_len);
	if (ret < 0) {
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.tx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		k_mutex_unlock(&ctx->tx_mutex);
		return ret;
	}

#ifdef CONFIG_ZTEST
	memcpy(ctx->last_tx, ctx->tx_frame, frame_len);
	ctx->last_tx_len = frame_len;
#endif

	if (ctx->uart_dev != NULL) {
		for (size_t i = 0; i < frame_len; i++) {
			uart_poll_out(ctx->uart_dev, ctx->tx_frame[i]);
		}
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.tx_packets++;
		ctx->stats.tx_bytes += (uint32_t)len;
		k_mutex_unlock(&ctx->stats_mutex);
	} else {
		k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
		ctx->stats.tx_errors++;
		k_mutex_unlock(&ctx->stats_mutex);
		ret = -ENODEV;
	}

	k_mutex_unlock(&ctx->tx_mutex);
	return ret;
}

int slip_transport_get_stats(struct slip_transport_stats *stats)
{
	struct slip_transport_ctx *ctx = &s_ctx;

	if (stats == NULL) {
		return -EINVAL;
	}
	if (!ctx->initialized) {
		memset(stats, 0, sizeof(*stats));
		return 0;
	}

	k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
	*stats = ctx->stats;
	k_mutex_unlock(&ctx->stats_mutex);
	return 0;
}

void slip_transport_reset_stats(void)
{
	struct slip_transport_ctx *ctx = &s_ctx;

	if (!ctx->initialized) {
		return;
	}

	k_mutex_lock(&ctx->stats_mutex, K_FOREVER);
	memset(&ctx->stats, 0, sizeof(ctx->stats));
	k_mutex_unlock(&ctx->stats_mutex);
}

bool slip_transport_is_ready(void)
{
	struct slip_transport_ctx *ctx = &s_ctx;

	return ctx->initialized;
}

int slip_transport_init(void)
{
	struct slip_transport_ctx *ctx = &s_ctx;
	const struct device *uart_dev;

	k_mutex_lock(&s_init_mutex, K_FOREVER);
	if (ctx->initialized) {
		k_mutex_unlock(&s_init_mutex);
		return -EALREADY;
	}

	k_mutex_init(&ctx->tx_mutex);
	k_mutex_init(&ctx->rx_mutex);
	k_mutex_init(&ctx->stats_mutex);
	k_sem_init(&ctx->rx_sem, 0, K_SEM_MAX_LIMIT);
	ring_buf_init(&ctx->rx_ring, sizeof(ctx->rx_ring_buf), ctx->rx_ring_buf);

	ctx->rx_state = SLIP_STATE_IDLE;
	ctx->rx_len = 0;
	ctx->rx_overflow = false;

	memset(&ctx->stats, 0, sizeof(ctx->stats));

#if DT_HAS_CHOSEN(lichen_slip_uart)
	uart_dev = DEVICE_DT_GET(DT_CHOSEN(lichen_slip_uart));
#else
	uart_dev = NULL;
#endif

	if (uart_dev != NULL && device_is_ready(uart_dev)) {
		ctx->uart_dev = uart_dev;

		uart_irq_callback_user_data_set(uart_dev, uart_rx_callback, ctx);
		uart_irq_rx_enable(uart_dev);

		LOG_INF("SLIP transport: UART %s ready", uart_dev->name);
	} else {
		LOG_WRN("SLIP transport: no UART device available");
		ctx->uart_dev = NULL;
	}

	k_tid_t tid = k_thread_create(&s_rx_thread, s_rx_stack, K_THREAD_STACK_SIZEOF(s_rx_stack),
			slip_rx_thread_fn, ctx, NULL, NULL,
			RX_THREAD_PRIORITY, 0, K_NO_WAIT);
	if (tid == NULL) {
		k_mutex_unlock(&s_init_mutex);
		LOG_ERR("slip_transport: k_thread_create failed");
		return -ENOMEM;
	}
	k_thread_name_set(&s_rx_thread, "slip_rx");

	ctx->initialized = true;
	k_mutex_unlock(&s_init_mutex);
	LOG_INF("SLIP transport initialized");

	return 0;
}

/* --------------------------------------------------------------------------
 * Test helpers
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_ZTEST
int slip_transport_test_inject_rx(const uint8_t *data, size_t len)
{
	struct slip_transport_ctx *ctx = &s_ctx;
	int packets = 0;

	k_mutex_lock(&ctx->rx_mutex, K_FOREVER);

	for (size_t i = 0; i < len; i++) {
		if (slip_decode_byte(ctx, data[i])) {
			slip_dispatch_packet(ctx);
			ctx->rx_len = 0;
			ctx->rx_overflow = false;
			packets++;
		}
	}

	k_mutex_unlock(&ctx->rx_mutex);

	return packets;
}

int slip_transport_test_get_last_tx(uint8_t *buf, size_t max, size_t *len)
{
	struct slip_transport_ctx *ctx = &s_ctx;
	size_t copy_len;

	if (buf == NULL || len == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&ctx->tx_mutex, K_FOREVER);

	copy_len = MIN(ctx->last_tx_len, max);
	if (copy_len > 0) {
		memcpy(buf, ctx->last_tx, copy_len);
	}
	*len = ctx->last_tx_len;

	k_mutex_unlock(&ctx->tx_mutex);

	return 0;
}

void slip_transport_test_reset(void)
{
	struct slip_transport_ctx *ctx = &s_ctx;

	k_mutex_lock(&ctx->tx_mutex, K_FOREVER);
	k_mutex_lock(&ctx->rx_mutex, K_FOREVER);
	k_mutex_lock(&ctx->stats_mutex, K_FOREVER);

	ctx->rx_state = SLIP_STATE_IDLE;
	ctx->rx_len = 0;
	ctx->rx_overflow = false;
	ctx->last_tx_len = 0;
	ring_buf_reset(&ctx->rx_ring);
	memset(&ctx->stats, 0, sizeof(ctx->stats));

	k_mutex_unlock(&ctx->stats_mutex);
	k_mutex_unlock(&ctx->rx_mutex);
	k_mutex_unlock(&ctx->tx_mutex);
}
#endif /* CONFIG_ZTEST */
