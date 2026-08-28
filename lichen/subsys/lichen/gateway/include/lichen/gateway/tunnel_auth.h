/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_TUNNEL_AUTH_H_
#define LICHEN_GATEWAY_TUNNEL_AUTH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_TUNNEL_AUTH_RESOURCE "/.well-known/tunnel-auth"
#define LICHEN_TUNNEL_AUTH_CONTENT_FORMAT "application/cose; cose-type=\"cose-sign1\""
#define LICHEN_TUNNEL_AUTH_COSE_ALG (-65537)
#define LICHEN_TUNNEL_AUTH_MAX_ROUTE_HOPS 8U
#define LICHEN_TUNNEL_AUTH_MAX_WIRE_SIZE 192U

#ifndef CONFIG_LICHEN_TUNNEL_AUTH_MAX_ENTRIES
#define CONFIG_LICHEN_TUNNEL_AUTH_MAX_ENTRIES 8
#endif
#ifndef CONFIG_LICHEN_TUNNEL_AUTH_MAX_HISTORY
#define CONFIG_LICHEN_TUNNEL_AUTH_MAX_HISTORY 32
#endif
#if CONFIG_LICHEN_TUNNEL_AUTH_MAX_HISTORY < CONFIG_LICHEN_TUNNEL_AUTH_MAX_ENTRIES
#error "LICHEN tunnel replay history must be at least as large as its active table"
#endif

enum lichen_tunnel_direction {
	LICHEN_TUNNEL_MESH_TO_EXTERNAL,
	LICHEN_TUNNEL_EXTERNAL_TO_MESH,
	LICHEN_TUNNEL_MESH_TRANSIT,
};

enum lichen_tunnel_denial {
	LICHEN_TUNNEL_DENIAL_NONE,
	LICHEN_TUNNEL_DENIAL_MALFORMED,
	LICHEN_TUNNEL_DENIAL_OSCORE_REQUIRED,
	LICHEN_TUNNEL_DENIAL_WRONG_ROOT,
	LICHEN_TUNNEL_DENIAL_KEY_BINDING,
	LICHEN_TUNNEL_DENIAL_ALGORITHM,
	LICHEN_TUNNEL_DENIAL_SIGNATURE,
	LICHEN_TUNNEL_DENIAL_WRONG_EGRESS,
	LICHEN_TUNNEL_DENIAL_EXPIRED,
	LICHEN_TUNNEL_DENIAL_REPLAY,
	LICHEN_TUNNEL_DENIAL_REVOKED,
	LICHEN_TUNNEL_DENIAL_CAPACITY,
	LICHEN_TUNNEL_DENIAL_CLOCK_REGRESSION,
	LICHEN_TUNNEL_DENIAL_WRONG_DIRECTION,
	LICHEN_TUNNEL_DENIAL_INVALID_ROUTE,
	LICHEN_TUNNEL_DENIAL_ROUTE_MISMATCH,
	LICHEN_TUNNEL_DENIAL_SOURCE_SCOPE,
	LICHEN_TUNNEL_DENIAL_DESTINATION_SCOPE,
	LICHEN_TUNNEL_DENIAL_NO_AUTHORIZATION,
	LICHEN_TUNNEL_DENIAL_DELIVERY_FAILED,
};

struct lichen_tunnel_result {
	bool allowed;
	enum lichen_tunnel_denial denial;
	uint16_t coap_code;
};

struct lichen_tunnel_crypto {
	int (*sha256)(const uint8_t *input, size_t input_len, uint8_t out[32]);
	int (*derive_iid)(const uint8_t pubkey[32], uint8_t iid[8]);
	int (*sign)(const uint8_t private_key[32], const uint8_t public_key[32],
		    const uint8_t digest[32], uint8_t signature[48]);
	bool (*verify)(const uint8_t public_key[32], const uint8_t digest[32],
		       const uint8_t signature[48]);
};

struct lichen_tunnel_claims {
	uint8_t prefix[16];
	uint8_t prefix_len;
	uint8_t route_hash[16];
	uint64_t path_seq;
	uint64_t expiry;
	uint8_t egress_iid[8];
};

struct lichen_tunnel_entry {
	bool used;
	struct lichen_tunnel_claims claims;
	uint64_t age;
};

struct lichen_tunnel_history {
	bool used;
	bool revoked;
	uint8_t prefix[16];
	uint8_t prefix_len;
	uint8_t route_hash[16];
	uint64_t floor;
};

struct lichen_tunnel_auth_ctx {
	uint8_t egress_iid[8];
	uint8_t root_iid[8];
	uint8_t root_pubkey[32];
	struct lichen_tunnel_crypto crypto;
	struct lichen_tunnel_entry entries[CONFIG_LICHEN_TUNNEL_AUTH_MAX_ENTRIES];
	struct lichen_tunnel_history history[CONFIG_LICHEN_TUNNEL_AUTH_MAX_HISTORY];
	uint64_t last_now;
	uint64_t age;
	bool have_time;
	atomic_flag lock;
};

typedef int (*lichen_tunnel_post_fn)(const uint8_t peer_iid[8],
	const char *resource, const char *content_format,
	const uint8_t *body, size_t body_len,
	bool require_oscore, void *user_data);

int lichen_tunnel_auth_init(struct lichen_tunnel_auth_ctx *ctx,
			    const uint8_t egress_iid[8],
			    const uint8_t root_iid[8],
			    const uint8_t root_pubkey[32],
			    const struct lichen_tunnel_crypto *crypto);

int lichen_tunnel_auth_default_crypto(struct lichen_tunnel_crypto *crypto);

int lichen_tunnel_route_hash(const struct lichen_tunnel_crypto *crypto,
			     const uint8_t *route_iids, size_t route_hops,
			     uint8_t route_hash[16]);

int lichen_tunnel_auth_encode(const struct lichen_tunnel_crypto *crypto,
			      const uint8_t root_private_key[32],
			      const uint8_t root_public_key[32],
			      const uint8_t root_iid[8],
			      const struct lichen_tunnel_claims *claims,
			      const uint8_t *route_iids, size_t route_hops,
			      uint8_t *output, size_t output_size,
			      size_t *output_len);

struct lichen_tunnel_result lichen_tunnel_auth_route_installed(
	const struct lichen_tunnel_crypto *crypto,
	const uint8_t root_private_key[32], const uint8_t root_public_key[32],
	const uint8_t root_iid[8], const struct lichen_tunnel_claims *claims,
	const uint8_t *route_iids, size_t route_hops, bool egress_capable,
	lichen_tunnel_post_fn post, void *user_data);

struct lichen_tunnel_result lichen_tunnel_auth_receive(
	struct lichen_tunnel_auth_ctx *ctx, const uint8_t *body, size_t body_len,
	bool oscore_authenticated, const uint8_t oscore_sender_iid[8], uint64_t now);

int lichen_tunnel_auth_change_root(struct lichen_tunnel_auth_ctx *ctx,
				   const uint8_t root_iid[8],
				   const uint8_t root_pubkey[32]);

int lichen_tunnel_auth_revoke(struct lichen_tunnel_auth_ctx *ctx,
			      const uint8_t prefix[16], uint8_t prefix_len,
			      const uint8_t route_hash[16], uint64_t through_seq);

struct lichen_tunnel_result lichen_tunnel_auth_decapsulate(
	struct lichen_tunnel_auth_ctx *ctx, const uint8_t source[16],
	const uint8_t destination[16], const uint8_t *route_iids, size_t route_hops,
	enum lichen_tunnel_direction direction, uint64_t now);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_GATEWAY_TUNNEL_AUTH_H_ */
