/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief ICMPv6 packet-path proof over real LICHEN_L2 and LoRa loopback.
 */

#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/icmp.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include <string.h>

#include "lichen_l2.h"
#include "lora_l2.h"
#include "lora_loopback_test.h"

LOG_MODULE_REGISTER(ping_l2_test, LOG_LEVEL_INF);

#define PING_DATA      "LICHEN"
#define PING_DATA_SIZE (sizeof(PING_DATA) - 1)
#define UDP_TEST_PORT  56830

static const uint8_t coap_test_payload[] = {
	0x50, 0x02, 0x4c, 0x32, 0xff, 'o', 'k'
};

static const uint8_t test_seed[32] = {
	0x4c, 0x49, 0x43, 0x48, 0x45, 0x4e, 0x2d, 0x4c,
	0x32, 0x2d, 0x6c, 0x6f, 0x6f, 0x70, 0x62, 0x61,
	0x63, 0x6b, 0x2d, 0x70, 0x61, 0x74, 0x68, 0x2d,
	0x74, 0x65, 0x73, 0x74, 0x2d, 0x30, 0x30, 0x31,
};
static const uint8_t test_link_key[16] = {
	0x4c, 0x32, 0x2d, 0x6c, 0x69, 0x6e, 0x6b, 0x2d,
	0x6c, 0x6f, 0x6f, 0x70, 0x62, 0x61, 0x63, 0x6b,
};

static const struct device *const lora_dev = DEVICE_DT_GET(DT_ALIAS(lora0));
static struct net_if *test_iface;
static struct in6_addr test_ll_addr;
static struct in6_addr peer_ll_addr;
static uint8_t expected_packet[sizeof(struct net_ipv6_hdr) + 8 + PING_DATA_SIZE];
static size_t expected_packet_len;
static uint8_t expected_udp_packet[sizeof(struct net_ipv6_hdr) + 8 + sizeof(coap_test_payload)];
static size_t expected_udp_packet_len;

static void build_ping_packet(uint8_t *packet, size_t *packet_len);
static void build_udp_packet(uint8_t *packet, size_t *packet_len);

static void make_link_local_from_eui64(const uint8_t eui64[8],
				       struct in6_addr *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->s6_addr[0] = 0xfe;
	addr->s6_addr[1] = 0x80;
	memcpy(&addr->s6_addr[8], eui64, 8);
	addr->s6_addr[8] ^= 0x02;
}

static uint32_t checksum_add(const uint8_t *data, size_t len)
{
	uint32_t sum = 0;

	while (len > 1) {
		sum += ((uint16_t)data[0] << 8) | data[1];
		data += 2;
		len -= 2;
	}

	if (len > 0) {
		sum += (uint16_t)data[0] << 8;
	}

	return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
	while ((sum >> 16) != 0) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return (uint16_t)~sum;
}

static uint16_t icmpv6_checksum(const struct net_ipv6_hdr *ipv6,
				const uint8_t *icmp,
				size_t icmp_len)
{
	uint8_t pseudo[8] = {
		(uint8_t)(icmp_len >> 24),
		(uint8_t)(icmp_len >> 16),
		(uint8_t)(icmp_len >> 8),
		(uint8_t)icmp_len,
		0,
		0,
		0,
		IPPROTO_ICMPV6,
	};
	uint32_t sum = 0;

	sum += checksum_add(ipv6->src, sizeof(ipv6->src));
	sum += checksum_add(ipv6->dst, sizeof(ipv6->dst));
	sum += checksum_add(pseudo, sizeof(pseudo));
	sum += checksum_add(icmp, icmp_len);

	return checksum_finish(sum);
}

static uint16_t udp_checksum(const struct net_ipv6_hdr *ipv6,
			     const uint8_t *udp,
			     size_t udp_len)
{
	uint8_t pseudo[8] = {
		(uint8_t)(udp_len >> 24),
		(uint8_t)(udp_len >> 16),
		(uint8_t)(udp_len >> 8),
		(uint8_t)udp_len,
		0,
		0,
		0,
		IPPROTO_UDP,
	};
	uint32_t sum = 0;
	uint16_t checksum;

	sum += checksum_add(ipv6->src, sizeof(ipv6->src));
	sum += checksum_add(ipv6->dst, sizeof(ipv6->dst));
	sum += checksum_add(pseudo, sizeof(pseudo));
	sum += checksum_add(udp, udp_len);

	checksum = checksum_finish(sum);
	return checksum == 0 ? 0xffff : checksum;
}

static void *ping_l2_setup(void)
{
	uint8_t eui64[8];
	uint8_t pubkey[32];
	int ret;

	zassert_true(IS_ENABLED(CONFIG_LICHEN_L2), "CONFIG_LICHEN_L2 is disabled");
	zassert_false(IS_ENABLED(CONFIG_NET_L2_DUMMY), "dummy L2 bypass is enabled");
	zassert_true(device_is_ready(lora_dev), "lora0 loopback device is not ready");

	test_iface = net_if_get_first_by_type(&NET_L2_GET_NAME(lichen_l2));
	zassert_not_null(test_iface, "no default LICHEN interface");

	ret = lichen_lora_l2_copy_eui64(eui64);
	zassert_equal(ret, 0, "failed to copy L2 EUI-64: %d", ret);

	ret = lichen_l2_test_load_key(test_seed, pubkey);
	zassert_equal(ret, 0, "failed to load deterministic test key: %d", ret);

	ret = lichen_l2_test_load_link_key(test_link_key);
	zassert_equal(ret, 0, "failed to load deterministic link key: %d", ret);

	ret = lichen_peer_add(eui64, pubkey);
	zassert_equal(ret, 0, "failed to add self peer: %d", ret);

	make_link_local_from_eui64(eui64, &test_ll_addr);
	memcpy(&peer_ll_addr, &test_ll_addr, sizeof(peer_ll_addr));
	peer_ll_addr.s6_addr[15] ^= 0x01;

	if (net_if_ipv6_addr_lookup(&test_ll_addr, NULL) == NULL) {
		struct net_if_addr *ifaddr;

		ifaddr = net_if_ipv6_addr_add(test_iface, &test_ll_addr,
					      NET_ADDR_MANUAL, 0);
		zassert_not_null(ifaddr, "failed to add LICHEN link-local address");
	}

	ret = net_if_up(test_iface);
	zassert_true(ret == 0 || ret == -EALREADY, "failed to bring iface up: %d", ret);

	build_ping_packet(expected_packet, &expected_packet_len);
	build_udp_packet(expected_udp_packet, &expected_udp_packet_len);

	return NULL;
}

static void build_ping_packet(uint8_t *packet, size_t *packet_len)
{
	struct net_ipv6_hdr *ipv6 = (struct net_ipv6_hdr *)packet;
	uint8_t *icmp = packet + sizeof(struct net_ipv6_hdr);
	size_t icmp_len = 8 + PING_DATA_SIZE;

	memset(packet, 0, sizeof(struct net_ipv6_hdr) + icmp_len);
	ipv6->vtc = 0x60;
	ipv6->len = sys_cpu_to_be16((uint16_t)icmp_len);
	ipv6->nexthdr = IPPROTO_ICMPV6;
	ipv6->hop_limit = 64;
	memcpy(ipv6->src, test_ll_addr.s6_addr, sizeof(ipv6->src));
	memcpy(ipv6->dst, peer_ll_addr.s6_addr, sizeof(ipv6->dst));

	icmp[0] = NET_ICMPV6_ECHO_REQUEST;
	icmp[1] = 0;
	icmp[2] = 0;
	icmp[3] = 0;
	icmp[4] = 0x4c;
	icmp[5] = 0x49;
	icmp[6] = 0;
	icmp[7] = 1;
	memcpy(&icmp[8], PING_DATA, PING_DATA_SIZE);
	sys_put_be16(icmpv6_checksum(ipv6, icmp, icmp_len), &icmp[2]);

	*packet_len = sizeof(struct net_ipv6_hdr) + icmp_len;
}

static void build_udp_packet(uint8_t *packet, size_t *packet_len)
{
	struct net_ipv6_hdr *ipv6 = (struct net_ipv6_hdr *)packet;
	uint8_t *udp = packet + sizeof(struct net_ipv6_hdr);
	size_t udp_len = 8 + sizeof(coap_test_payload);

	memset(packet, 0, sizeof(struct net_ipv6_hdr) + udp_len);
	ipv6->vtc = 0x60;
	ipv6->len = sys_cpu_to_be16((uint16_t)udp_len);
	ipv6->nexthdr = IPPROTO_UDP;
	ipv6->hop_limit = 64;
	memcpy(ipv6->src, peer_ll_addr.s6_addr, sizeof(ipv6->src));
	memcpy(ipv6->dst, test_ll_addr.s6_addr, sizeof(ipv6->dst));

	sys_put_be16(UDP_TEST_PORT, &udp[0]);
	sys_put_be16(UDP_TEST_PORT, &udp[2]);
	sys_put_be16((uint16_t)udp_len, &udp[4]);
	udp[6] = 0;
	udp[7] = 0;
	memcpy(&udp[8], coap_test_payload, sizeof(coap_test_payload));
	sys_put_be16(udp_checksum(ipv6, udp, udp_len), &udp[6]);

	*packet_len = sizeof(struct net_ipv6_hdr) + udp_len;
}

static int send_l2_packet(const uint8_t *packet, size_t packet_len,
			  uint8_t next_header)
{
	struct net_pkt *pkt;

	pkt = net_pkt_alloc_with_buffer(test_iface, packet_len, AF_INET6,
					next_header, K_SECONDS(1));
	if (pkt == NULL) {
		return -ENOMEM;
	}

	if (net_pkt_write(pkt, packet, packet_len) < 0) {
		goto drop;
	}

	net_pkt_cursor_init(pkt);

	if (net_if_l2(test_iface)->send(test_iface, pkt) < 0) {
		goto drop;
	}

	return 0;

drop:
	net_pkt_unref(pkt);
	return -EIO;
}

static int bind_udp_observer(void)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(UDP_TEST_PORT),
		.sin6_scope_id = net_if_get_by_iface(test_iface),
	};
	struct timeval timeout = {
		.tv_sec = 1,
		.tv_usec = 0,
	};
	int sock;
	int ret;

	memcpy(&addr.sin6_addr, &test_ll_addr, sizeof(addr.sin6_addr));
	sock = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		return -errno;
	}

	ret = zsock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
			       &timeout, sizeof(timeout));
	if (ret < 0) {
		ret = -errno;
		goto fail;
	}

	ret = zsock_bind(sock, (const struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		ret = -errno;
		goto fail;
	}

	return sock;

fail:
	(void)zsock_close(sock);
	return ret;
}

static int recv_udp_observer(int sock, uint8_t *buf, size_t buf_len)
{
	struct sockaddr_in6 src;
	socklen_t src_len = sizeof(src);
	int ret;

	ret = zsock_recvfrom(sock, buf, buf_len, 0,
			     (struct sockaddr *)&src, &src_len);
	if (ret < 0) {
		return -errno;
	}

	if (src.sin6_port != htons(UDP_TEST_PORT)) {
		return -EPROTO;
	}

	if (memcmp(&src.sin6_addr, &peer_ll_addr, sizeof(peer_ll_addr)) != 0) {
		return -EADDRNOTAVAIL;
	}

	return ret;
}

static bool packet_path_observed(const struct lichen_l2_test_stats *l2_before,
				 const struct lora_loopback_test_stats *loop_before,
				 const uint8_t *expected,
				 size_t expected_len)
{
	struct lichen_l2_test_stats l2_now;
	struct lora_loopback_test_stats loop_now;

	lichen_l2_test_get_stats(&l2_now);
	lora_loopback_test_get_stats(lora_dev, &loop_now);

	return l2_now.tx_packets > l2_before->tx_packets &&
	       l2_now.rx_frames > l2_before->rx_frames &&
	       l2_now.rx_injected_packets > l2_before->rx_injected_packets &&
	       loop_now.sent_packets > loop_before->sent_packets &&
	       loop_now.received_packets > loop_before->received_packets &&
	       l2_now.last_injected_len == expected_len &&
	       memcmp(l2_now.last_injected, expected, expected_len) == 0;
}

static bool wait_for_packet_path(const struct lichen_l2_test_stats *l2_before,
				 const struct lora_loopback_test_stats *loop_before,
				 const uint8_t *expected,
				 size_t expected_len)
{
	for (int i = 0; i < 500; i++) {
		if (packet_path_observed(l2_before, loop_before, expected,
					 expected_len)) {
			return true;
		}
		k_msleep(10);
	}

	return false;
}

ZTEST(ping_l2, test_full_l2_loopback_ping)
{
	struct lichen_l2_test_stats l2_before;
	struct lora_loopback_test_stats loop_before;
	int ret;

	/* Let startup MLD/ND frames drain before measuring the packet under test. */
	k_sleep(K_MSEC(100));

	lichen_l2_test_reset_stats();
	lora_loopback_test_reset(lora_dev);

	lichen_l2_test_get_stats(&l2_before);
	lora_loopback_test_get_stats(lora_dev, &loop_before);

	ret = send_l2_packet(expected_packet, expected_packet_len, IPPROTO_ICMPV6);
	zassert_equal(ret, 0, "failed to send Echo Request packet: %d", ret);

	zassert_true(wait_for_packet_path(&l2_before, &loop_before,
					  expected_packet, expected_packet_len),
		     "full LICHEN_L2 loopback packet path was not observed");
}

ZTEST(ping_l2, test_udp_payload_reaches_socket_after_l2_injection)
{
	struct lichen_l2_test_stats l2_before;
	struct lora_loopback_test_stats loop_before;
	uint8_t rx_buf[sizeof(coap_test_payload)];
	int sock;
	int ret;

	k_sleep(K_MSEC(100));

	sock = bind_udp_observer();
	zassert_true(sock >= 0, "failed to bind UDP observer: %d", sock);

	lichen_l2_test_reset_stats();
	lora_loopback_test_reset(lora_dev);

	lichen_l2_test_get_stats(&l2_before);
	lora_loopback_test_get_stats(lora_dev, &loop_before);

	ret = send_l2_packet(expected_udp_packet, expected_udp_packet_len,
			     IPPROTO_UDP);
	if (ret != 0) {
		(void)zsock_close(sock);
	}
	zassert_equal(ret, 0, "failed to send UDP packet: %d", ret);

	ret = recv_udp_observer(sock, rx_buf, sizeof(rx_buf));
	(void)zsock_close(sock);

	zassert_equal(ret, sizeof(coap_test_payload),
		      "UDP observer did not receive payload: %d", ret);
	zassert_mem_equal(rx_buf, coap_test_payload, sizeof(coap_test_payload));
	zassert_true(wait_for_packet_path(&l2_before, &loop_before,
					  expected_udp_packet,
					  expected_udp_packet_len),
		     "UDP packet was not observed through full L2 injection path");
}

ZTEST_SUITE(ping_l2, NULL, ping_l2_setup, NULL, NULL, NULL);
