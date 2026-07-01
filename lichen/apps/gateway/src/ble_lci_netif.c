/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "ble_lci_netif.h"

#include "ble_uart.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/dummy.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(ble_lci_netif, LOG_LEVEL_INF);

#define BLE_LCI_MTU 1280U

struct ble_lci_context {
	uint8_t link_addr[8];
	struct k_mutex tx_mutex;
	uint8_t tx_ipv6[BLE_LCI_MTU];
#ifdef CONFIG_ZTEST
	uint8_t last_ipv6[BLE_LCI_MTU];
	size_t last_len;
	uint32_t send_count;
#endif
};

static struct ble_lci_context s_ctx = {
	.link_addr = { 0x02, 0x00, 0x5e, 0x00, 0x53, 0x00, 0x00, 0xb1 },
};

static void ble_lci_make_link_local(const uint8_t iid[8], struct in6_addr *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->s6_addr[0] = 0xfe;
	addr->s6_addr[1] = 0x80;
	memcpy(&addr->s6_addr[8], iid, 8);
	addr->s6_addr[8] ^= 0x02;
}

static void ble_lci_iface_init(struct net_if *iface)
{
	struct ble_lci_context *ctx = net_if_get_device(iface)->data;
	struct net_if_addr *ifaddr;
	struct in6_addr ll_addr;
	int ret;

	k_mutex_init(&ctx->tx_mutex);

	net_if_flag_set(iface, NET_IF_POINTOPOINT);
	net_if_flag_set(iface, NET_IF_IPV6_NO_ND);

	net_if_set_link_addr(iface, ctx->link_addr, sizeof(ctx->link_addr),
				     NET_LINK_IEEE802154);
	ble_lci_make_link_local(ctx->link_addr, &ll_addr);
	ifaddr = net_if_ipv6_addr_add(iface, &ll_addr, NET_ADDR_MANUAL, 0);
	if (ifaddr == NULL) {
		LOG_WRN("failed to add BLE LCI link-local address");
	}

	ret = net_if_up(iface);
	if (ret < 0 && ret != -EALREADY) {
		LOG_WRN("failed to bring BLE LCI interface up: %d", ret);
	}
}

static int ble_lci_send(const struct device *dev, struct net_pkt *pkt)
{
	struct ble_lci_context *ctx = dev->data;
	size_t len = net_pkt_get_len(pkt);
	int ret;

	if (len > sizeof(ctx->tx_ipv6)) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&ctx->tx_mutex, K_FOREVER);
	net_pkt_cursor_init(pkt);
	ret = net_pkt_read(pkt, ctx->tx_ipv6, len);
	if (ret < 0) {
		goto out;
	}

	ret = ble_lci_netif_send_ipv6(ctx->tx_ipv6, len);

out:
	k_mutex_unlock(&ctx->tx_mutex);
	return ret;
}

static const struct dummy_api s_ble_lci_api = {
	.iface_api.init = ble_lci_iface_init,
	.send = ble_lci_send,
};

NET_DEVICE_INIT(ble_lci, "ble_lci",
		NULL, NULL, &s_ctx, NULL,
		CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
		&s_ble_lci_api, DUMMY_L2, NET_L2_GET_CTX_TYPE(DUMMY_L2),
		BLE_LCI_MTU);

struct net_if *ble_lci_netif_get(void)
{
	return net_if_lookup_by_dev(DEVICE_GET(ble_lci));
}

int ble_lci_netif_send_ipv6(const uint8_t *ipv6, size_t len)
{
	if (ipv6 == NULL && len > 0U) {
		return -EINVAL;
	}

#ifdef CONFIG_ZTEST
	s_ctx.send_count++;
	s_ctx.last_len = MIN(len, sizeof(s_ctx.last_ipv6));
	if (s_ctx.last_len > 0U) {
		memcpy(s_ctx.last_ipv6, ipv6, s_ctx.last_len);
	}
#endif

	return ble_uart_send_slip(ipv6, len);
}

#ifdef CONFIG_ZTEST
int ble_lci_netif_test_send_ipv6(const uint8_t *ipv6, size_t len)
{
	return ble_lci_netif_send_ipv6(ipv6, len);
}
#endif
