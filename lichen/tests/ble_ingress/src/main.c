/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "ble_ingress.h"

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/dummy.h>
#include <zephyr/net/icmp.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_l2.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/ztest.h>

LOG_MODULE_REGISTER(ble_ingress_test, LOG_LEVEL_INF);

#define SEM_WAIT_TIME K_SECONDS(2)
#define TEST_MTU      1280

#define ICMPV6_TYPE_OFFSET (NET_IPV6H_LEN)
#define ICMPV6_ID_OFFSET   (ICMPV6_TYPE_OFFSET + 4u)
#define ICMPV6_SEQ_OFFSET  (ICMPV6_TYPE_OFFSET + 6u)

struct ble_ingress_test_ctx {
	uint8_t mac_addr[8];
	struct net_if *iface;
	struct k_sem reply_sem;
	uint16_t reply_id;
	uint16_t reply_seq;
};

static struct ble_ingress_test_ctx s_test_ctx;

static struct in6_addr s_local_addr = {
	.s6_addr = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }
};

static const uint8_t s_echo_request[] = {
	0x60, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x3a, 0x40,
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x80, 0x00, 0xb9, 0x1b, 0x42, 0x4c, 0x00, 0x01,
	0x42, 0x4c, 0x45
};

static uint16_t read_be16(const uint8_t *buf, size_t offset)
{
	return ((uint16_t)buf[offset] << 8) | buf[offset + 1u];
}

static void test_iface_init(struct net_if *iface)
{
	struct ble_ingress_test_ctx *ctx = net_if_get_device(iface)->data;

	ctx->mac_addr[0] = 0x02;
	ctx->mac_addr[1] = 0x00;
	ctx->mac_addr[2] = 0x5e;
	ctx->mac_addr[3] = 0x00;
	ctx->mac_addr[4] = 0x53;
	ctx->mac_addr[5] = 0x00;
	ctx->mac_addr[6] = 0x00;
	ctx->mac_addr[7] = 0x14;

	net_if_set_link_addr(iface, ctx->mac_addr, sizeof(ctx->mac_addr),
			     NET_LINK_IEEE802154);
	ctx->iface = iface;
}

static int test_l2_send(const struct device *dev, struct net_pkt *pkt)
{
	struct ble_ingress_test_ctx *ctx = dev->data;
	uint8_t buf[sizeof(s_echo_request)];
	size_t len = net_pkt_get_len(pkt);
	int ret;

	if (len <= sizeof(buf)) {
		net_pkt_cursor_init(pkt);
		ret = net_pkt_read(pkt, buf, len);
	} else {
		ret = -EMSGSIZE;
	}

	if (ret == 0 && len >= sizeof(s_echo_request) &&
	    buf[ICMPV6_TYPE_OFFSET] == NET_ICMPV6_ECHO_REPLY) {
		ctx->reply_id = read_be16(buf, ICMPV6_ID_OFFSET);
		ctx->reply_seq = read_be16(buf, ICMPV6_SEQ_OFFSET);
		k_sem_give(&ctx->reply_sem);
	}

	net_pkt_unref(pkt);
	return 0;
}

static struct dummy_api s_dummy_api = {
	.iface_api.init = test_iface_init,
	.send = test_l2_send,
};

NET_DEVICE_INIT(ble_ingress_loopback, "ble_ingress_loopback",
		NULL, NULL,
		&s_test_ctx, NULL,
		CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
		&s_dummy_api,
		DUMMY_L2, NET_L2_GET_CTX_TYPE(DUMMY_L2),
		TEST_MTU);

static void configure_iface(void)
{
	struct net_if_addr *ifaddr;
	int ret;

	if (s_test_ctx.iface == NULL) {
		s_test_ctx.iface = net_if_lookup_by_dev(DEVICE_GET(ble_ingress_loopback));
	}

	zassert_not_null(s_test_ctx.iface, "test interface not found");

	ifaddr = net_if_ipv6_addr_lookup(&s_local_addr, NULL);
	if (ifaddr == NULL) {
		ifaddr = net_if_ipv6_addr_add(s_test_ctx.iface, &s_local_addr,
					      NET_ADDR_MANUAL, 0);
	}

	zassert_not_null(ifaddr, "failed to configure local IPv6 address");

	ret = net_if_up(s_test_ctx.iface);
	zassert_true(ret == 0 || ret == -EALREADY,
		     "failed to bring test interface up: %d", ret);
}

ZTEST(ble_ingress, test_rejects_malformed_ipv6)
{
	uint8_t bad_version[NET_IPV6H_LEN] = { 0x40 };
	uint8_t bad_length[NET_IPV6H_LEN] = { 0x60 };

	bad_length[5] = 1u;

	zassert_equal(ble_ingress_ipv6(s_test_ctx.iface, NULL, sizeof(bad_version)),
		      -EINVAL, "null packet should be rejected");
	zassert_equal(ble_ingress_ipv6(s_test_ctx.iface, bad_version, sizeof(bad_version)),
		      -EPROTONOSUPPORT, "non-IPv6 packet should be rejected");
	zassert_equal(ble_ingress_ipv6(s_test_ctx.iface, bad_length, sizeof(bad_length)),
		      -EINVAL, "payload length mismatch should be rejected");
	zassert_equal(ble_ingress_ipv6(NULL, s_echo_request, sizeof(s_echo_request)),
		      -ENODEV, "missing interface should be rejected");
}

ZTEST(ble_ingress, test_injects_ipv6_to_rx_path)
{
	int ret;

	k_sem_reset(&s_test_ctx.reply_sem);
	s_test_ctx.reply_id = 0u;
	s_test_ctx.reply_seq = 0u;

	ret = ble_ingress_ipv6(s_test_ctx.iface, s_echo_request, sizeof(s_echo_request));
	zassert_equal(ret, 0, "BLE IPv6 injection failed: %d", ret);

	ret = k_sem_take(&s_test_ctx.reply_sem, SEM_WAIT_TIME);
	zassert_equal(ret, 0, "timeout waiting for ICMPv6 echo reply");
	zassert_equal(s_test_ctx.reply_id, 0x424c, "unexpected echo reply id");
	zassert_equal(s_test_ctx.reply_seq, 1u, "unexpected echo reply seq");
}

static void *ble_ingress_setup(void)
{
	if (IS_ENABLED(CONFIG_NET_TC_THREAD_COOPERATIVE)) {
		k_thread_priority_set(k_current_get(),
				      K_PRIO_COOP(CONFIG_NUM_COOP_PRIORITIES - 1));
	} else {
		k_thread_priority_set(k_current_get(), K_PRIO_PREEMPT(9));
	}

	k_sem_init(&s_test_ctx.reply_sem, 0, 1);
	configure_iface();

	return NULL;
}

ZTEST_SUITE(ble_ingress, NULL, ble_ingress_setup, NULL, NULL, NULL);
