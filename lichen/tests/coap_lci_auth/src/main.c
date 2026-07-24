/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>

#include <lichen/coap_server.h>
#include <lichen/transport/slip_transport.h>

#include <string.h>

/*
 * Test helpers
 */

static void make_loopback_sockaddr(struct sockaddr_in6 *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr.s6_addr[0] = 0U;
	addr->sin6_addr.s6_addr[15] = 1U;
}

static void make_link_local_sockaddr(struct sockaddr_in6 *addr,
				     uint32_t scope_id)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr.s6_addr[0] = 0xfe;
	addr->sin6_addr.s6_addr[1] = 0x80;
	addr->sin6_addr.s6_addr[15] = 1U;
	addr->sin6_scope_id = scope_id;
}

static void make_ula_sockaddr(struct sockaddr_in6 *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr.s6_addr[0] = 0xfd;
	addr->sin6_addr.s6_addr[15] = 1U;
}

static void make_gua_sockaddr(struct sockaddr_in6 *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr.s6_addr[0] = 0x20;
	addr->sin6_addr.s6_addr[1] = 0x01;
	addr->sin6_addr.s6_addr[2] = 0x0d;
	addr->sin6_addr.s6_addr[3] = 0xb8;
	addr->sin6_addr.s6_addr[15] = 1U;
}

/*
 * is_local_admin unit tests
 */

ZTEST(coap_lci_auth, test_loopback_is_admin)
{
	struct sockaddr_in6 addr;

	make_loopback_sockaddr(&addr);
	zassert_true(lichen_coap_is_local_admin((struct sockaddr *)&addr,
						sizeof(addr)));
}

ZTEST(coap_lci_auth, test_null_addr_is_admin_in_ztest)
{
	zassert_true(lichen_coap_is_local_admin(NULL, 0));
}

ZTEST(coap_lci_auth, test_slip_link_local_is_admin)
{
	struct net_if *slip_iface = slip_transport_iface_get();

	zassert_not_null(slip_iface, "SLIP interface must be available");

	struct sockaddr_in6 addr;
	uint32_t slip_idx = (uint32_t)net_if_get_by_iface(slip_iface);

	make_link_local_sockaddr(&addr, slip_idx);
	zassert_true(lichen_coap_is_local_admin((struct sockaddr *)&addr,
						sizeof(addr)));
}

ZTEST(coap_lci_auth, test_mesh_link_local_is_forbidden)
{
	struct sockaddr_in6 addr;

	make_link_local_sockaddr(&addr, 0U);
	zassert_false(lichen_coap_is_local_admin((struct sockaddr *)&addr,
						 sizeof(addr)));
}

ZTEST(coap_lci_auth, test_wrong_interface_link_local_is_forbidden)
{
	struct sockaddr_in6 addr;

	make_link_local_sockaddr(&addr, 999U);
	zassert_false(lichen_coap_is_local_admin((struct sockaddr *)&addr,
						 sizeof(addr)));
}

ZTEST(coap_lci_auth, test_ula_is_forbidden)
{
	struct sockaddr_in6 addr;

	make_ula_sockaddr(&addr);
	zassert_false(lichen_coap_is_local_admin((struct sockaddr *)&addr,
						 sizeof(addr)));
}

ZTEST(coap_lci_auth, test_gua_is_forbidden)
{
	struct sockaddr_in6 addr;

	make_gua_sockaddr(&addr);
	zassert_false(lichen_coap_is_local_admin((struct sockaddr *)&addr,
						 sizeof(addr)));
}

ZTEST(coap_lci_auth, test_short_addr_is_forbidden)
{
	struct sockaddr_storage short_addr;

	memset(&short_addr, 0, sizeof(short_addr));
	short_addr.ss_family = AF_INET6;
	zassert_false(lichen_coap_is_local_admin(
		(struct sockaddr *)&short_addr,
		sizeof(struct sockaddr_in6) - 1));
}

ZTEST(coap_lci_auth, test_non_ipv6_family_is_forbidden)
{
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = 0x7f000001;
	zassert_false(lichen_coap_is_local_admin((struct sockaddr *)&addr,
						 sizeof(addr)));
}

ZTEST_SUITE(coap_lci_auth, NULL, NULL, NULL, NULL, NULL);
