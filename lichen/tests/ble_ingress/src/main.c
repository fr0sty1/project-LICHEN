/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "ble_ingress.h"
#include "ble_lci_netif.h"

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
#define IPV6_NEXT_HEADER_OFFSET 6u
#define IPV6_SRC_OFFSET 8u
#define IPV6_DST_OFFSET 24u
#define IPV6_ADDR_LEN 16u

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

void ble_uart_stub_reset(int return_value);
int ble_uart_stub_wait(void);
uint32_t ble_uart_stub_send_count(void);
size_t ble_uart_stub_last_len(void);
int ble_uart_stub_copy_last(uint8_t *buf, size_t cap);

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

static int move_local_addr_to_iface(struct net_if *iface)
{
	struct net_if_addr *ifaddr;
	struct net_if *current_iface = NULL;
	int ret;

	ifaddr = net_if_ipv6_addr_lookup(&s_local_addr, &current_iface);
	if (ifaddr != NULL && current_iface != iface) {
		net_if_ipv6_addr_rm(current_iface, &s_local_addr);
		ifaddr = NULL;
	}

	if (ifaddr == NULL) {
		ifaddr = net_if_ipv6_addr_add(iface, &s_local_addr,
					      NET_ADDR_MANUAL, 0);
	}
	if (ifaddr == NULL) {
		return -ENOMEM;
	}

	ret = net_if_up(iface);
	if (ret < 0 && ret != -EALREADY) {
		return ret;
	}

	return 0;
}

static void configure_iface(void)
{
	int ret;

	if (s_test_ctx.iface == NULL) {
		s_test_ctx.iface = net_if_lookup_by_dev(DEVICE_GET(ble_ingress_loopback));
	}

	zassert_not_null(s_test_ctx.iface, "test interface not found");

	ret = move_local_addr_to_iface(s_test_ctx.iface);
	zassert_equal(ret, 0,
		     "failed to bring interface up: %d", ret);
}

ZTEST(ble_ingress, test_rejects_malformed_ipv6)
{
	uint8_t bad_version[NET_IPV6H_LEN] = { 0x40 };
	uint8_t bad_length[NET_IPV6H_LEN] = { 0x60 };
	uint8_t short_udp[48] = { 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 17, 64 };
	uint8_t short_icmp[44] = { 0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 58, 64 };
	uint8_t bad_udp_len[48] = { 0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 17, 64 };

	bad_length[5] = 1u;
	/* short_udp has payload_len=0 < UDP 8 */
	/* short_icmp has payload_len=4 but test for <4 case covered by logic */
	/* bad_udp_len has UDP length field set to invalid */

	zassert_equal(ble_ingress_ipv6(s_test_ctx.iface, NULL, sizeof(bad_version)),
		      -EINVAL, "null packet should be rejected");
	zassert_equal(ble_ingress_ipv6(s_test_ctx.iface, bad_version, sizeof(bad_version)),
		      -EPROTONOSUPPORT, "non-IPv6 packet should be rejected");
	zassert_equal(ble_ingress_ipv6(s_test_ctx.iface, bad_length, sizeof(bad_length)),
		      -EINVAL, "payload length mismatch should be rejected");
	zassert_equal(ble_ingress_ipv6(s_test_ctx.iface, short_udp, 40),
		      -EMSGSIZE, "short UDP packet should be rejected");
	zassert_equal(ble_ingress_ipv6(s_test_ctx.iface, short_icmp, 44),
		      -EMSGSIZE, "short ICMPv6 packet should be rejected");
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

ZTEST(ble_ingress, test_ble_lci_iface_is_configured_for_slip_link)
{
	struct net_if *ble_iface = ble_lci_netif_get();

	zassert_not_null(ble_iface, "BLE LCI interface not found");
	zassert_true(net_if_flag_is_set(ble_iface, NET_IF_POINTOPOINT),
		     "BLE LCI interface must be point-to-point");
	zassert_true(net_if_flag_is_set(ble_iface, NET_IF_IPV6_NO_ND),
		     "BLE LCI interface must bypass IPv6 ND");
	zassert_true(net_if_is_up(ble_iface),
		     "BLE LCI interface should be up after init");
}

ZTEST(ble_ingress, test_reply_exits_ble_lci_egress_path)
{
	struct net_if *ble_iface = ble_lci_netif_get();
	uint8_t reply[128];
	int ret;

	zassert_not_null(ble_iface, "BLE LCI interface not found");
	ret = move_local_addr_to_iface(ble_iface);
	zassert_equal(ret, 0, "failed to configure BLE LCI address: %d", ret);
	ble_uart_stub_reset(0);

	ret = ble_ingress_ipv6(ble_iface, s_echo_request, sizeof(s_echo_request));
	zassert_equal(ret, 0, "BLE IPv6 injection failed: %d", ret);

	ret = ble_uart_stub_wait();
	zassert_equal(ret, 0, "timeout waiting for BLE LCI egress");
	zassert_equal(ble_uart_stub_send_count(), 1U);
	zassert_equal(ble_uart_stub_last_len(), sizeof(s_echo_request));
	zassert_ok(ble_uart_stub_copy_last(reply, sizeof(reply)));
	zassert_equal(reply[0] >> 4, 6U);
	zassert_equal(reply[IPV6_NEXT_HEADER_OFFSET], IPPROTO_ICMPV6);
	zassert_mem_equal(&reply[IPV6_SRC_OFFSET], &s_echo_request[IPV6_DST_OFFSET],
			  IPV6_ADDR_LEN);
	zassert_mem_equal(&reply[IPV6_DST_OFFSET], &s_echo_request[IPV6_SRC_OFFSET],
			  IPV6_ADDR_LEN);
	zassert_equal(reply[ICMPV6_TYPE_OFFSET], NET_ICMPV6_ECHO_REPLY);
	zassert_equal(read_be16(reply, ICMPV6_ID_OFFSET), 0x424c);
	zassert_equal(read_be16(reply, ICMPV6_SEQ_OFFSET), 1U);
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

static void ble_ingress_after(void *fixture)
{
	ARG_UNUSED(fixture);

	if (s_test_ctx.iface != NULL) {
		(void)move_local_addr_to_iface(s_test_ctx.iface);
	}
}

ZTEST_SUITE(ble_ingress, NULL, ble_ingress_setup, NULL, ble_ingress_after, NULL);
