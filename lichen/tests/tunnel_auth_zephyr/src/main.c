/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/ztest.h>
#include <lichen/gateway/tunnel_auth.h>

static struct lichen_tunnel_auth_ctx fresh_with(const uint8_t root[8], const uint8_t pubkey[32]);
static struct lichen_tunnel_result receive_as(struct lichen_tunnel_auth_ctx *ctx,
	const uint8_t *wire, size_t len, bool authenticated, const uint8_t sender[8], uint64_t now);
static void check_result(const char *name, struct lichen_tunnel_result result,
	bool allowed, enum lichen_tunnel_denial denial, uint16_t code);
static void fixture_assert(bool condition);

#include "tunnel_auth_vectors.h"

static struct lichen_tunnel_auth_ctx fresh_with(const uint8_t root[8], const uint8_t pubkey[32])
{
	struct lichen_tunnel_auth_ctx ctx;
	struct lichen_tunnel_crypto crypto;
	zassert_ok(lichen_tunnel_auth_default_crypto(&crypto));
	zassert_ok(lichen_tunnel_auth_init(&ctx, egress_iid, root, pubkey, &crypto));
	return ctx;
}

static struct lichen_tunnel_result receive_as(struct lichen_tunnel_auth_ctx *ctx,
	const uint8_t *wire, size_t len, bool authenticated, const uint8_t sender[8], uint64_t now)
{ return lichen_tunnel_auth_receive(ctx, wire, len, authenticated, sender, now); }

static void check_result(const char *name, struct lichen_tunnel_result result,
	bool allowed, enum lichen_tunnel_denial denial, uint16_t code)
{
	zassert_equal(result.allowed, allowed, "%s allowed", name);
	zassert_equal(result.denial, denial, "%s denial", name);
	zassert_equal(result.coap_code, code, "%s CoAP code", name);
}

static void fixture_assert(bool condition) { zassert_true(condition); }

ZTEST(tunnel_auth, test_complete_shared_decision_corpus)
{
	run_fixture_post_cases();
	run_fixture_decap_cases();
}

ZTEST(tunnel_auth, test_canonical_vector_and_data_plane)
{
	struct lichen_tunnel_crypto crypto;
	struct lichen_tunnel_auth_ctx ctx;
	struct lichen_tunnel_result result;
	uint8_t source[16] = { 0x02, 0x00, 0x12, 0x34, 0x56, [15] = 1 };
	uint8_t destination[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 1 };

	zassert_ok(lichen_tunnel_auth_default_crypto(&crypto));
	zassert_ok(lichen_tunnel_auth_init(&ctx, egress_iid, root_iid, root_pubkey, &crypto));
	result = lichen_tunnel_auth_receive(&ctx, wire_valid, sizeof(wire_valid), true,
					    root_iid, UINT64_C(1900000000));
	zassert_true(result.allowed);
	result = lichen_tunnel_auth_decapsulate(&ctx, source, destination, valid_route, 2,
						LICHEN_TUNNEL_MESH_TO_EXTERNAL,
						UINT64_C(1900000001));
	zassert_true(result.allowed);
}

ZTEST(tunnel_auth, test_fail_closed_boundaries)
{
	struct lichen_tunnel_crypto crypto;
	struct lichen_tunnel_auth_ctx ctx;
	struct lichen_tunnel_result result;

	zassert_ok(lichen_tunnel_auth_default_crypto(&crypto));
	zassert_ok(lichen_tunnel_auth_init(&ctx, egress_iid, root_iid, root_pubkey, &crypto));
	result = lichen_tunnel_auth_receive(&ctx, wire_valid, sizeof(wire_valid), false,
					    root_iid, UINT64_C(1900000000));
	zassert_equal(result.denial, LICHEN_TUNNEL_DENIAL_OSCORE_REQUIRED);
	result = lichen_tunnel_auth_receive(&ctx, wire_noncanonical_outer,
					    sizeof(wire_noncanonical_outer), true,
					    root_iid, UINT64_C(1900000000));
	zassert_equal(result.denial, LICHEN_TUNNEL_DENIAL_MALFORMED);
	result = lichen_tunnel_auth_receive(&ctx, wire_wrong_signer,
					    sizeof(wire_wrong_signer), true,
					    root_iid, UINT64_C(1900000000));
	zassert_equal(result.denial, LICHEN_TUNNEL_DENIAL_SIGNATURE);
}

ZTEST_SUITE(tunnel_auth, NULL, NULL, NULL, NULL, NULL);
