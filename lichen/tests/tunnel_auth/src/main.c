/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <assert.h>
#include <errno.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lichen/gateway/tunnel_auth.h>
#include <lichen/schnorr48.h>
#include <monocypher.h>

static struct lichen_tunnel_auth_ctx fresh_with(const uint8_t root[8], const uint8_t pubkey[32]);
static struct lichen_tunnel_result receive_as(struct lichen_tunnel_auth_ctx *ctx,
	const uint8_t *wire, size_t len, bool authenticated, const uint8_t sender[8], uint64_t now);
static void check_result(const char *name, struct lichen_tunnel_result result,
	bool allowed, enum lichen_tunnel_denial denial, uint16_t code);
static void fixture_assert(bool condition);

#include "tunnel_auth_vectors.h"

static int hash256(const uint8_t *input, size_t len, uint8_t out[32])
{
	return SHA256(input, len, out) == NULL ? -EIO : 0;
}

static int iid(const uint8_t pubkey[32], uint8_t out[8])
{
	uint8_t hash[64];
	if (SHA512(pubkey, 32, hash) == NULL) return -EIO;
	memcpy(out, hash, 8); out[0] &= (uint8_t)~0x02U;
	crypto_wipe(hash, sizeof(hash)); return 0;
}

static int sign_digest(const uint8_t sk[32], const uint8_t pk[32], const uint8_t d[32], uint8_t s[48])
{ return schnorr48_sign(sk, pk, d, 32, s); }

static bool verify_digest(const uint8_t pk[32], const uint8_t d[32], const uint8_t s[48])
{ return schnorr48_verify(pk, d, 32, s, 48); }

static const struct lichen_tunnel_crypto crypto = { hash256, iid, sign_digest, verify_digest };

struct post_capture { bool called; uint8_t peer[8]; size_t len; int result; };

static int capture_post(const uint8_t peer[8], const char *resource, const char *content_format,
			const uint8_t *body, size_t body_len, bool require_oscore, void *user)
{
	struct post_capture *capture = user;
	assert(strcmp(resource, LICHEN_TUNNEL_AUTH_RESOURCE) == 0 && require_oscore);
	assert(strcmp(content_format, LICHEN_TUNNEL_AUTH_CONTENT_FORMAT) == 0);
	assert(body_len == sizeof(wire_valid) && memcmp(body, wire_valid, body_len) == 0);
	capture->called = true; memcpy(capture->peer, peer, 8); capture->len = body_len;
	return capture->result;
}

static struct lichen_tunnel_auth_ctx fresh_with(const uint8_t root[8], const uint8_t pubkey[32])
{
	struct lichen_tunnel_auth_ctx ctx;
	assert(lichen_tunnel_auth_init(&ctx, egress_iid, root, pubkey, &crypto) == 0);
	return ctx;
}

static struct lichen_tunnel_auth_ctx fresh(void) { return fresh_with(root_iid, root_pubkey); }

static struct lichen_tunnel_result receive_as(struct lichen_tunnel_auth_ctx *ctx,
	const uint8_t *wire, size_t len, bool authenticated, const uint8_t sender[8], uint64_t now)
{ return lichen_tunnel_auth_receive(ctx, wire, len, authenticated, sender, now); }

static void check_result(const char *name, struct lichen_tunnel_result result,
	bool allowed, enum lichen_tunnel_denial denial, uint16_t code)
{
	if (result.allowed != allowed || result.denial != denial || result.coap_code != code) {
		fprintf(stderr, "%s: got allowed=%d denial=%d code=%u, expected %d/%d/%u\n",
			name, result.allowed, result.denial, result.coap_code, allowed, denial, code);
		abort();
	}
}

static void fixture_assert(bool condition) { assert(condition); }

static struct lichen_tunnel_result receive(struct lichen_tunnel_auth_ctx *ctx,
					   const uint8_t *wire, size_t len, uint64_t now)
{ return lichen_tunnel_auth_receive(ctx, wire, len, true, root_iid, now); }

static void test_shared_vectors(void)
{
	struct lichen_tunnel_auth_ctx ctx = fresh();
	struct lichen_tunnel_result r;
	r = receive(&ctx, wire_valid, sizeof(wire_valid), UINT64_C(1900000000)); assert(r.allowed && r.coap_code == 204);
	r = receive(&ctx, wire_valid, sizeof(wire_valid), UINT64_C(1900000000)); assert(!r.allowed && r.denial == LICHEN_TUNNEL_DENIAL_REPLAY);
	ctx = fresh(); r = receive(&ctx, wire_expired, sizeof(wire_expired), UINT64_C(1900000000)); assert(r.denial == LICHEN_TUNNEL_DENIAL_EXPIRED);
	ctx = fresh(); r = receive(&ctx, wire_wrong_kid, sizeof(wire_wrong_kid), UINT64_C(1900000000)); assert(r.denial == LICHEN_TUNNEL_DENIAL_WRONG_ROOT);
	ctx = fresh(); r = receive(&ctx, wire_wrong_signer, sizeof(wire_wrong_signer), UINT64_C(1900000000)); assert(r.denial == LICHEN_TUNNEL_DENIAL_SIGNATURE);
	ctx = fresh(); r = receive(&ctx, wire_wrong_egress, sizeof(wire_wrong_egress), UINT64_C(1900000000)); assert(r.denial == LICHEN_TUNNEL_DENIAL_WRONG_EGRESS);
	ctx = fresh(); r = receive(&ctx, wire_noncanonical_outer, sizeof(wire_noncanonical_outer), UINT64_C(1900000000)); assert(r.denial == LICHEN_TUNNEL_DENIAL_MALFORMED);
	ctx = fresh(); r = receive(&ctx, wire_trailing_data, sizeof(wire_trailing_data), UINT64_C(1900000000)); assert(r.denial == LICHEN_TUNNEL_DENIAL_MALFORMED);
}

static void test_auth_and_policy(void)
{
	struct lichen_tunnel_auth_ctx ctx = fresh();
	uint8_t source[16] = {0x02,0x00,0x12,0x34,0x56,0,0,0,0,0,0,0,0,0,0,1};
	uint8_t outside[16] = {0x02,0x00,0x12,0x35};
	uint8_t external[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
	uint8_t mesh_dst[16] = {0x02,0x55};
	struct lichen_tunnel_result r;
	assert(receive(&ctx, wire_valid, sizeof(wire_valid), UINT64_C(1900000000)).allowed);
	r = lichen_tunnel_auth_decapsulate(&ctx, source, external, valid_route, 2,
					    LICHEN_TUNNEL_MESH_TO_EXTERNAL, UINT64_C(1900000001)); assert(r.allowed);
	r = lichen_tunnel_auth_decapsulate(&ctx, outside, external, valid_route, 2,
					    LICHEN_TUNNEL_MESH_TO_EXTERNAL, UINT64_C(1900000001)); assert(r.denial == LICHEN_TUNNEL_DENIAL_NO_AUTHORIZATION);
	r = lichen_tunnel_auth_decapsulate(&ctx, source, mesh_dst, valid_route, 2,
					    LICHEN_TUNNEL_MESH_TO_EXTERNAL, UINT64_C(1900000001)); assert(r.denial == LICHEN_TUNNEL_DENIAL_DESTINATION_SCOPE);
	r = lichen_tunnel_auth_decapsulate(&ctx, source, external, valid_route, 2,
					    LICHEN_TUNNEL_EXTERNAL_TO_MESH, UINT64_C(1900000001)); assert(r.denial == LICHEN_TUNNEL_DENIAL_WRONG_DIRECTION);
	r = lichen_tunnel_auth_decapsulate(&ctx, source, external, valid_route, 2,
					    LICHEN_TUNNEL_MESH_TO_EXTERNAL, UINT64_C(1899999999)); assert(r.denial == LICHEN_TUNNEL_DENIAL_CLOCK_REGRESSION);
	r = lichen_tunnel_auth_decapsulate(&ctx, source, external, valid_route, 2,
					    LICHEN_TUNNEL_MESH_TO_EXTERNAL, UINT64_C(1900000002)); assert(r.denial == LICHEN_TUNNEL_DENIAL_NO_AUTHORIZATION);
}

static void test_revocation_rotation_and_atomicity(void)
{
	struct lichen_tunnel_auth_ctx ctx = fresh(), before;
	struct lichen_tunnel_result r;
	assert(receive(&ctx, wire_valid, sizeof(wire_valid), UINT64_C(1900000000)).allowed);
	assert(lichen_tunnel_auth_revoke(&ctx, valid_prefix, 40, valid_route_hash, 9) == 0);
	r = receive(&ctx, wire_seq_9, sizeof(wire_seq_9), UINT64_C(1900000000)); assert(r.denial == LICHEN_TUNNEL_DENIAL_REVOKED);
	r = receive(&ctx, wire_seq_10, sizeof(wire_seq_10), UINT64_C(1900000000)); assert(r.allowed);
	before = ctx; r = lichen_tunnel_auth_receive(&ctx, wire_valid, sizeof(wire_valid), false, root_iid, UINT64_C(1900000000));
	assert(r.denial == LICHEN_TUNNEL_DENIAL_OSCORE_REQUIRED);
	assert(memcmp(ctx.entries, before.entries, sizeof(ctx.entries)) == 0 && memcmp(ctx.history, before.history, sizeof(ctx.history)) == 0);
	assert(lichen_tunnel_auth_change_root(&ctx, other_root_iid, other_root_pubkey) == 0);
	r = lichen_tunnel_auth_receive(&ctx, wire_valid, sizeof(wire_valid), true, root_iid, UINT64_C(1900000000)); assert(r.denial == LICHEN_TUNNEL_DENIAL_WRONG_ROOT);
}

static void test_encoder_exact_vector(void)
{
	uint8_t private_key[32], public_key[32], out[LICHEN_TUNNEL_AUTH_MAX_WIRE_SIZE], guard[8];
	struct lichen_tunnel_claims claims = { .prefix_len = 40, .path_seq = 7, .expiry = UINT64_C(1900000300) };
	size_t len = 0;
	schnorr48_derive_keypair(root_seed, private_key, public_key);
	assert(memcmp(public_key, root_pubkey, 32) == 0);
	memcpy(claims.prefix, valid_prefix, 16); memcpy(claims.route_hash, valid_route_hash, 16); memcpy(claims.egress_iid, egress_iid, 8);
	assert(lichen_tunnel_auth_encode(&crypto, private_key, public_key, root_iid, &claims,
					 valid_route, 2, out, sizeof(out), &len) == 0);
	assert(len == sizeof(wire_valid) && memcmp(out, wire_valid, len) == 0);
	memset(guard, 0xa5, sizeof(guard)); len = 99;
	assert(lichen_tunnel_auth_encode(&crypto, private_key, public_key, root_iid, &claims,
					 valid_route, 2, guard, sizeof(guard), &len) == -ENOBUFS);
	assert(len == 99); for (size_t i = 0; i < sizeof(guard); i++) assert(guard[i] == 0xa5);
	struct post_capture capture = { 0 };
	struct lichen_tunnel_result result = lichen_tunnel_auth_route_installed(
		&crypto, private_key, public_key, root_iid, &claims, valid_route, 2,
		true, capture_post, &capture);
	assert(result.allowed && capture.called && memcmp(capture.peer, egress_iid, 8) == 0);
	capture.called = false; capture.result = -EIO;
	result = lichen_tunnel_auth_route_installed(&crypto, private_key, public_key,
		root_iid, &claims, valid_route, 2, true, capture_post, &capture);
	assert(!result.allowed && result.denial == LICHEN_TUNNEL_DENIAL_DELIVERY_FAILED);
	capture.called = false;
	result = lichen_tunnel_auth_route_installed(&crypto, private_key, public_key,
		root_iid, &claims, valid_route, 2, false, capture_post, &capture);
	assert(!result.allowed && !capture.called && result.denial == LICHEN_TUNNEL_DENIAL_DESTINATION_SCOPE);
	crypto_wipe(private_key, sizeof(private_key));
}

int main(void)
{
	test_shared_vectors(); test_auth_and_policy(); test_revocation_rotation_and_atomicity(); test_encoder_exact_vector();
	run_fixture_post_cases(); run_fixture_decap_cases();
	puts("tunnel_auth: all tests passed"); return 0;
}
