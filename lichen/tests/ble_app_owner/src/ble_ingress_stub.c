/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/util.h>

struct net_if;

static uint8_t s_last_ipv6[1280];
static size_t s_last_len;
static uint32_t s_call_count;
static int s_return_value = -ENODEV;
static uint8_t s_fake_netif;

struct net_if *ble_lci_netif_get(void)
{
	return (struct net_if *)&s_fake_netif;
}

void ble_ingress_stub_reset(int return_value)
{
	memset(s_last_ipv6, 0, sizeof(s_last_ipv6));
	s_last_len = 0U;
	s_call_count = 0U;
	s_return_value = return_value;
}

uint32_t ble_ingress_stub_call_count(void)
{
	return s_call_count;
}

size_t ble_ingress_stub_last_len(void)
{
	return s_last_len;
}

int ble_ingress_stub_copy_last(uint8_t *buf, size_t cap)
{
	if (buf == NULL && cap > 0U) {
		return -EINVAL;
	}
	if (cap < s_last_len) {
		return -ENOMEM;
	}
	memcpy(buf, s_last_ipv6, s_last_len);
	return 0;
}

int ble_ingress_ipv6(struct net_if *iface, const uint8_t *ipv6, size_t len)
{
	ARG_UNUSED(iface);

	s_call_count++;
	s_last_len = MIN(len, sizeof(s_last_ipv6));
	memcpy(s_last_ipv6, ipv6, s_last_len);
	return s_return_value;
}

int ble_ingress_ipv6_default(const uint8_t *ipv6, size_t len)
{
	return ble_ingress_ipv6(ble_lci_netif_get(), ipv6, len);
}
