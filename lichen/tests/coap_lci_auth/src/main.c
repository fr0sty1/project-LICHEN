/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <string.h>

#include <zephyr/net/net_if.h>
#include <zephyr/ztest.h>

#include <lichen/coap_keys.h>
#include <lichen/coap_server.h>
#include <lichen/transport/slip_transport.h>

/*
 * is_local_admin address test helpers
 */

static void make_sockaddr_loopback(struct sockaddr_in6 *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	/* ::1 */
	addr->sin6_addr.s6_addr[15] = 1U;
}

static void make_sockaddr_link_local(struct sockaddr_in6 *addr,
				     uint32_t scope_id)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr.s6_addr[0] = 0xfe;
	addr->sin6_addr.s6_addr[1] = 0x80;
	addr->sin6_addr.s6_addr[15] = 1U;
	addr->sin6_scope_id = scope_id;
}

static void make_sockaddr_global(struct sockaddr_in6 *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr.s6_addr[0] = 0x20;
	addr->sin6_addr.s6_addr[1] = 0x01;
	addr->sin6_addr.s6_addr[15] = 1U;
}

/*
 * lichen_coap_is_local_admin tests
 */

ZTEST(coap_lci_auth, test_null_addr_is_admin_in_ztest)
{
	zassert_true(lichen_coap_is_local_admin(NULL, 0),
		     "NULL addr must be admin in ztest context");
}

ZTEST(coap_lci_auth, test_loopback_local_admin)
{
	struct sockaddr_in6 addr;

	make_sockaddr_loopback(&addr);
	zassert_true(lichen_coap_is_local_admin(
			     (struct sockaddr *)&addr, sizeof(addr)),
		     "loopback must be local admin");
}

ZTEST(coap_lci_auth, test_link_local_wrong_iface_rejected)
{
	struct sockaddr_in6 addr;

	make_sockaddr_link_local(&addr, 999U);
	zassert_false(lichen_coap_is_local_admin(
			      (struct sockaddr *)&addr, sizeof(addr)),
		      "link-local from wrong scope must be rejected");
}

ZTEST(coap_lci_auth, test_global_address_rejected)
{
	struct sockaddr_in6 addr;

	make_sockaddr_global(&addr);
	zassert_false(lichen_coap_is_local_admin(
			      (struct sockaddr *)&addr, sizeof(addr)),
		      "global address must be rejected");
}

ZTEST(coap_lci_auth, test_non_ipv6_address_rejected)
{
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	zassert_false(lichen_coap_is_local_admin(
			      (struct sockaddr *)&addr, sizeof(addr)),
		      "IPv4 address must be rejected");
}

ZTEST(coap_lci_auth, test_short_addr_len_rejected)
{
	struct sockaddr_in6 addr;

	make_sockaddr_loopback(&addr);
	zassert_false(lichen_coap_is_local_admin(
			      (struct sockaddr *)&addr, 1),
		      "addr_len < sizeof(sockaddr_in6) must be rejected");
}

ZTEST(coap_lci_auth, test_zero_scope_id_link_local_rejected)
{
	struct sockaddr_in6 addr;

	make_sockaddr_link_local(&addr, 0U);
	zassert_false(lichen_coap_is_local_admin(
			      (struct sockaddr *)&addr, sizeof(addr)),
		      "link-local with scope_id=0 must be rejected");
}

/*
 * If SLIP transport is available, verify that the correct scope_id
 * passes the admin check.
 */
ZTEST(coap_lci_auth, test_slip_scope_id_passes_when_available)
{
	struct sockaddr_in6 addr;
	struct net_if *slip_iface = slip_transport_iface_get();

	if (slip_iface == NULL) {
		ztest_test_skip();
		return;
	}

	make_sockaddr_link_local(&addr, net_if_get_by_iface(slip_iface));
	zassert_true(lichen_coap_is_local_admin(
			     (struct sockaddr *)&addr, sizeof(addr)),
		     "link-local from SLIP iface must be admin");
}

/*
 * When SLIP is unavailable, all link-local addresses must be rejected.
 */
ZTEST(coap_lci_auth, test_slip_unavailable_rejects_link_local)
{
	struct sockaddr_in6 addr;

	/* Simulate SLIP unavailable by not initializing SLIP, or by
	 * using a scope_id that definitely won't match.
	 */
	make_sockaddr_link_local(&addr, 1U);

	/*
	 * We cannot force slip_transport_iface_get() to return NULL from
	 * a unit test without building without SLIP. Instead, verify that
	 * a plausible-bogus scope_id is rejected.
	 */
	zassert_false(lichen_coap_is_local_admin(
			      (struct sockaddr *)&addr, sizeof(addr)),
		      "link-local with non-matching scope must be rejected");
}

/*
 * Verify that is_local_admin rejects link-local from the mesh radio interface
 * (anything that is NOT the SLIP interface).
 */
ZTEST(coap_lci_auth, test_link_local_from_wrong_interface_rejected)
{
	struct sockaddr_in6 addr;
	struct net_if *slip_iface = slip_transport_iface_get();
	int slip_idx;

	slip_idx = (slip_iface != NULL)
			   ? net_if_get_by_iface(slip_iface)
			   : -1;

	/* Use a scope_id that is != slip_idx. If no SLIP iface, any
	 * non-zero scope_id is wrong.
	 */
	uint32_t test_scope = (slip_idx > 0) ? (uint32_t)(slip_idx + 1) : 42U;

	make_sockaddr_link_local(&addr, test_scope);
	zassert_false(lichen_coap_is_local_admin(
			      (struct sockaddr *)&addr, sizeof(addr)),
		      "link-local from wrong interface must be rejected");
}

/*
 * Boundary tests: near-maximum scope_id value.
 */
ZTEST(coap_lci_auth, test_link_local_max_scope_id_rejected)
{
	struct sockaddr_in6 addr;

	make_sockaddr_link_local(&addr, 0xFFFFFFFFU);
	zassert_false(lichen_coap_is_local_admin(
			      (struct sockaddr *)&addr, sizeof(addr)),
		      "link-local with max scope_id must be rejected");
}

static void reset_state(void *fixture)
{
	ARG_UNUSED(fixture);
}

ZTEST_SUITE(coap_lci_auth, NULL, NULL, reset_state, NULL, NULL);
