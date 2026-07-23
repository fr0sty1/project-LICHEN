/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "ble_ingress.h"

#include <errno.h>
#include <stddef.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(ble_ingress, LOG_LEVEL_INF);

#define IPV6_VERSION_VALUE       6u
#define IPV6_VERSION_SHIFT       4u
#define IPV6_PAYLOAD_LEN_OFFSET  offsetof(struct net_ipv6_hdr, len)
#define IPV6_MIN_PACKET_LEN      NET_IPV6H_LEN
#define IPV6_MAX_PACKET_LEN      1280u

static uint8_t ipv6_version(const uint8_t *ipv6)
{
	return ipv6[0] >> IPV6_VERSION_SHIFT;
}

static uint16_t ipv6_payload_len(const uint8_t *ipv6)
{
	return sys_get_be16(&ipv6[IPV6_PAYLOAD_LEN_OFFSET]);
}

static int validate_ipv6_packet(const uint8_t *ipv6, size_t len)
{
	uint16_t payload_len;
	size_t expected_len;
	uint8_t nexthdr;

	if (ipv6 == NULL) {
		LOG_WRN("BLE ingress rejected null IPv6 packet");
		return -EINVAL;
	}

	if (len < IPV6_MIN_PACKET_LEN) {
		LOG_WRN("BLE ingress rejected %zu B packet: shorter than IPv6 header", len);
		return -EMSGSIZE;
	}

	if (len > IPV6_MAX_PACKET_LEN) {
		LOG_WRN("BLE ingress rejected %zu B packet: exceeds IPv6 minimum MTU", len);
		return -EMSGSIZE;
	}

	if (ipv6_version(ipv6) != IPV6_VERSION_VALUE) {
		LOG_WRN("BLE ingress rejected packet with IP version %u", ipv6_version(ipv6));
		return -EPROTONOSUPPORT;
	}

	payload_len = ipv6_payload_len(ipv6);
	expected_len = IPV6_MIN_PACKET_LEN + (size_t)payload_len;
	if (expected_len != len) {
		LOG_WRN("BLE ingress rejected IPv6 packet: payload length %u implies %zu B, got %zu B",
			payload_len, expected_len, len);
		return -EINVAL;
	}

	nexthdr = ipv6[6];
	if (nexthdr == IPPROTO_UDP) {
		if (payload_len < 8) {
			LOG_WRN("BLE ingress rejected short UDP packet: payload %u < 8", payload_len);
			return -EMSGSIZE;
		}
		if (len >= IPV6_MIN_PACKET_LEN + 8) {
			uint16_t udp_len = sys_get_be16(&ipv6[IPV6_MIN_PACKET_LEN + 4]);
			if (udp_len < 8 || udp_len > payload_len) {
				LOG_WRN("BLE ingress rejected malformed UDP length %u (payload %u)", udp_len, payload_len);
				return -EINVAL;
			}
		}
	} else if (nexthdr == IPPROTO_ICMPV6) {
		if (payload_len < 4) {
			LOG_WRN("BLE ingress rejected short ICMPv6 packet: payload %u < 4", payload_len);
			return -EMSGSIZE;
		}
	}

	return 0;
}

int ble_ingress_ipv6(struct net_if *iface, const uint8_t *ipv6, size_t len)
{
	struct net_pkt *pkt;
	int ret;

	ret = validate_ipv6_packet(ipv6, len);
	if (ret < 0) {
		return ret;
	}

	if (iface == NULL) {
		LOG_WRN("BLE ingress rejected IPv6 packet: no network interface");
		return -ENODEV;
	}

	pkt = net_pkt_rx_alloc_with_buffer(iface, len, AF_INET6, IPPROTO_RAW,
					   K_NO_WAIT);
	if (pkt == NULL) {
		LOG_WRN("BLE ingress could not allocate %zu B RX packet", len);
		return -ENOMEM;
	}

	ret = net_pkt_write(pkt, ipv6, len);
	if (ret < 0) {
		LOG_WRN("BLE ingress failed to write %zu B RX packet: %d", len, ret);
		net_pkt_unref(pkt);
		return ret;
	}

	ret = net_recv_data(iface, pkt);
	if (ret < 0) {
		LOG_WRN("BLE ingress net_recv_data failed: %d", ret);
		net_pkt_unref(pkt);
		return ret;
	}

	return 0;
}

int ble_ingress_ipv6_default(const uint8_t *ipv6, size_t len)
{
	return ble_ingress_ipv6(net_if_get_default(), ipv6, len);
}
