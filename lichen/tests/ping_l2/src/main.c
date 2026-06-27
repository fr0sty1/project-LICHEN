/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief ICMPv6 ping test over LICHEN L2 loopback
 *
 * This test verifies ICMPv6 Echo Request/Reply works over a loopback
 * L2 interface that simulates the LICHEN link layer. The test:
 *
 * 1. Initializes a loopback network interface
 * 2. Configures a link-local IPv6 address
 * 3. Sends an ICMPv6 Echo Request to itself
 * 4. Verifies the Echo Reply is received
 *
 * This validates the IPv6/ICMPv6 stack integration path that LICHEN L2
 * will use, without requiring actual LoRa hardware.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/logging/log.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/dummy.h>
#include <zephyr/net/icmp.h>

LOG_MODULE_REGISTER(ping_l2_test, LOG_LEVEL_INF);

#define PKT_WAIT_TIME  K_SECONDS(1)
#define SEM_WAIT_TIME  K_SECONDS(2)
#define PING_DATA      "LICHEN"
#define PING_DATA_SIZE (sizeof(PING_DATA) - 1)

/**
 * Test context structure
 */
struct ping_test_ctx {
	uint8_t mac_addr[8];           /* EUI-64 style address */
	struct net_if *iface;
	struct k_sem reply_sem;
	bool reply_received;
	uint16_t reply_id;
	uint16_t reply_seq;
};

static struct ping_test_ctx s_test_ctx;

/**
 * Link-local IPv6 address for testing
 * fe80::1 - simple link-local address
 */
static struct in6_addr s_test_ll_addr = {
	.s6_addr = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }
};

/**
 * @brief Initialize the test interface
 */
static void test_iface_init(struct net_if *iface)
{
	struct ping_test_ctx *ctx = net_if_get_device(iface)->data;

	/* Generate EUI-64 style address */
	ctx->mac_addr[0] = 0x02;  /* Locally administered */
	ctx->mac_addr[1] = 0x00;
	ctx->mac_addr[2] = 0x5e;  /* IANA OUI for documentation */
	ctx->mac_addr[3] = 0x00;
	ctx->mac_addr[4] = 0x53;
	ctx->mac_addr[5] = 0x00;
	ctx->mac_addr[6] = 0x00;
	ctx->mac_addr[7] = 0x01;

	net_if_set_link_addr(iface, ctx->mac_addr, sizeof(ctx->mac_addr),
			     NET_LINK_IEEE802154);

	ctx->iface = iface;

	LOG_INF("Test interface initialized");
}

/**
 * @brief Loopback send function
 *
 * When a packet is sent, loop it back to the receive path.
 * This simulates the LICHEN L2 loopback behavior.
 */
static int test_loopback_send(const struct device *dev, struct net_pkt *pkt)
{
	struct ping_test_ctx *ctx = dev->data;
	struct net_pkt *clone;

	LOG_DBG("Loopback TX: %zu bytes", net_pkt_get_len(pkt));

	/* Clone the packet for receive processing */
	clone = net_pkt_clone(pkt, PKT_WAIT_TIME);
	if (!clone) {
		LOG_ERR("Failed to clone packet");
		net_pkt_unref(pkt);
		return -ENOMEM;
	}

	/* Set the interface for the cloned packet */
	net_pkt_set_iface(clone, ctx->iface);

	/* Inject into the receive path */
	if (net_recv_data(ctx->iface, clone) < 0) {
		LOG_ERR("net_recv_data failed");
		net_pkt_unref(clone);
	}

	/* Free the original packet */
	net_pkt_unref(pkt);

	return 0;
}

/* Dummy L2 API for loopback testing */
static struct dummy_api s_test_dummy_api = {
	.iface_api.init = test_iface_init,
	.send = test_loopback_send,
};

/*
 * Register the test network device with DUMMY L2
 * MTU of 200 matches LICHEN L2 MTU
 */
NET_DEVICE_INIT(lichen_loopback, "lichen_loopback",
		NULL, NULL,
		&s_test_ctx, NULL,
		CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
		&s_test_dummy_api,
		DUMMY_L2, NET_L2_GET_CTX_TYPE(DUMMY_L2),
		200);

/**
 * @brief ICMPv6 Echo Reply handler
 */
static int icmp_reply_handler(struct net_icmp_ctx *ctx,
			      struct net_pkt *pkt,
			      struct net_icmp_ip_hdr *ip_hdr,
			      struct net_icmp_hdr *icmp_hdr,
			      void *user_data)
{
	struct ping_test_ctx *test = user_data;
	struct net_ipv6_hdr *ipv6 = ip_hdr->ipv6;
	char src_str[NET_IPV6_ADDR_LEN];
	char dst_str[NET_IPV6_ADDR_LEN];

	net_addr_ntop(AF_INET6, &ipv6->src, src_str, sizeof(src_str));
	net_addr_ntop(AF_INET6, &ipv6->dst, dst_str, sizeof(dst_str));

	LOG_INF("Received Echo Reply: %s -> %s", src_str, dst_str);

	test->reply_received = true;
	k_sem_give(&test->reply_sem);

	return 0;
}

/**
 * Test: Verify interface initialization
 */
ZTEST(ping_l2, test_interface_init)
{
	struct net_if *iface;

	iface = net_if_lookup_by_dev(DEVICE_GET(lichen_loopback));
	zassert_not_null(iface, "Failed to find loopback interface");
	zassert_equal(iface, s_test_ctx.iface,
		      "Interface mismatch (expected %p, got %p)",
		      s_test_ctx.iface, iface);

	LOG_INF("Interface initialization: PASS");
}

/**
 * Test: Configure IPv6 link-local address
 */
ZTEST(ping_l2, test_ipv6_addr_config)
{
	struct net_if *iface = s_test_ctx.iface;
	struct net_if_addr *ifaddr;

	zassert_not_null(iface, "Interface not initialized");

	/* Add link-local address if not already present */
	ifaddr = net_if_ipv6_addr_lookup(&test_ll_addr, NULL);
	if (ifaddr == NULL) {
		ifaddr = net_if_ipv6_addr_add(iface, &test_ll_addr,
					      NET_ADDR_MANUAL, 0);
	}
	zassert_not_null(ifaddr, "Failed to add/find IPv6 address");

	/* Verify address was added */
	zassert_true(net_if_ipv6_addr_lookup(&s_s_test_ll_addr, NULL) != NULL,
		     "IPv6 address not found after add");

	LOG_INF("IPv6 address configuration: PASS");
}

/**
 * Test: ICMPv6 Echo Request/Reply (ping)
 *
 * This is the core test - send a ping to our own link-local address
 * and verify we receive the reply.
 */
ZTEST(ping_l2, test_icmpv6_ping)
{
	struct net_icmp_ctx icmp_ctx;
	struct net_icmp_ping_params params;
	struct sockaddr_in6 dst = { 0 };
	int ret;

	zassert_not_null(s_test_ctx.iface, "Interface not initialized");

	/* Initialize semaphore */
	k_sem_init(&s_s_test_ctx.reply_sem, 0, 1);
	s_test_ctx.reply_received = false;

	/* Register for Echo Reply */
	ret = net_icmp_init_ctx(&icmp_ctx, NET_ICMPV6_ECHO_REPLY, 0,
				icmp_reply_handler);
	zassert_equal(ret, 0, "Failed to init ICMP context: %d", ret);

	/* Set up destination (our own link-local address) */
	dst.sin6_family = AF_INET6;
	memcpy(&dst.sin6_addr, &s_s_test_ll_addr, sizeof(test_ll_addr));

	/* Set up ping parameters */
	params.identifier = 0x4C49;  /* "LI" */
	params.sequence = 1;
	params.tc_tos = 0;
	params.priority = 0;
	params.data = PING_DATA;
	params.data_size = PING_DATA_SIZE;

	LOG_INF("Sending ICMPv6 Echo Request...");

	/* Send ping */
	ret = net_icmp_send_echo_request(&icmp_ctx, s_test_ctx.iface,
					 (struct sockaddr *)&dst,
					 &params, &s_test_ctx);
	zassert_equal(ret, 0, "Failed to send Echo Request: %d", ret);

	/* Wait for reply */
	ret = k_sem_take(&s_s_test_ctx.reply_sem, SEM_WAIT_TIME);
	zassert_equal(ret, 0, "Timeout waiting for Echo Reply");

	zassert_true(s_test_ctx.reply_received, "Echo Reply not received");

	/* Cleanup */
	ret = net_icmp_cleanup_ctx(&icmp_ctx);
	zassert_equal(ret, 0, "Failed to cleanup ICMP context: %d", ret);

	LOG_INF("ICMPv6 ping test: PASS");
}

/**
 * Test setup - called before each test
 */
static void *ping_l2_setup(void)
{
	struct net_if *iface;

	/* Set thread priority for cooperative scheduling */
	if (IS_ENABLED(CONFIG_NET_TC_THREAD_COOPERATIVE)) {
		k_thread_priority_set(k_current_get(),
				      K_PRIO_COOP(CONFIG_NUM_COOP_PRIORITIES - 1));
	} else {
		k_thread_priority_set(k_current_get(), K_PRIO_PREEMPT(9));
	}

	/* Get interface and add IPv6 address */
	iface = net_if_lookup_by_dev(DEVICE_GET(lichen_loopback));
	if (iface && s_test_ctx.iface == NULL) {
		s_test_ctx.iface = iface;
	}

	if (iface) {
		/* Add the link-local address if not already present */
		if (net_if_ipv6_addr_lookup(&s_s_test_ll_addr, NULL) == NULL) {
			net_if_ipv6_addr_add(iface, &s_s_test_ll_addr,
					     NET_ADDR_MANUAL, 0);
		}
	}

	return NULL;
}

ZTEST_SUITE(ping_l2, NULL, ping_l2_setup, NULL, NULL, NULL);
