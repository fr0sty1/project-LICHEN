/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <lichen/gateway/tunnel_auth.h>

#ifdef __ZEPHYR__
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#include <lichen/link_ctx.h>
#include <lichen/schnorr48.h>
#endif

static const uint8_t protected_header[] = { 0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00 };

struct cursor {
	const uint8_t *p;
	size_t left;
};

static struct lichen_tunnel_result deny(enum lichen_tunnel_denial reason)
{
	return (struct lichen_tunnel_result){ false, reason, 403 };
}

static struct lichen_tunnel_result permit(void)
{
	return (struct lichen_tunnel_result){ true, LICHEN_TUNNEL_DENIAL_NONE, 204 };
}

static void lock_ctx(struct lichen_tunnel_auth_ctx *ctx)
{
	while (atomic_flag_test_and_set_explicit(&ctx->lock, memory_order_acquire)) {
	}
}

static void unlock_ctx(struct lichen_tunnel_auth_ctx *ctx)
{
	atomic_flag_clear_explicit(&ctx->lock, memory_order_release);
}

static bool crypto_valid(const struct lichen_tunnel_crypto *c)
{
	return c != NULL && c->sha256 != NULL && c->derive_iid != NULL &&
	       c->sign != NULL && c->verify != NULL;
}

static bool prefix_valid(const uint8_t prefix[16], uint8_t bits)
{
	uint8_t rem;
	size_t first;

	if (bits > 128U) {
		return false;
	}
	first = (size_t)((bits + 7U) / 8U);
	rem = bits & 7U;
	if (rem != 0U && first != 0U && (prefix[first - 1U] & ((1U << (8U - rem)) - 1U)) != 0U) {
		return false;
	}
	for (size_t i = first; i < 16U; i++) {
		if (prefix[i] != 0U) {
			return false;
		}
	}
	return true;
}

static size_t put_uint(uint8_t *out, uint8_t major, uint64_t value)
{
	if (value < 24U) {
		out[0] = (uint8_t)(((uint32_t)major << 5) | value);
		return 1;
	}
	if (value <= UINT8_MAX) {
		out[0] = (uint8_t)(((uint32_t)major << 5) | 24U); out[1] = (uint8_t)value;
		return 2;
	}
	if (value <= UINT16_MAX) {
		out[0] = (uint8_t)(((uint32_t)major << 5) | 25U);
		out[1] = (uint8_t)(value >> 8); out[2] = (uint8_t)value;
		return 3;
	}
	if (value <= UINT32_MAX) {
		out[0] = (uint8_t)(((uint32_t)major << 5) | 26U);
		for (size_t i = 0; i < 4; i++) out[1 + i] = (uint8_t)(value >> (24U - 8U * i));
		return 5;
	}
	out[0] = (uint8_t)(((uint32_t)major << 5) | 27U);
	for (size_t i = 0; i < 8; i++) out[1 + i] = (uint8_t)(value >> (56U - 8U * i));
	return 9;
}

static size_t put_bstr(uint8_t *out, const uint8_t *data, size_t len)
{
	size_t n = put_uint(out, 2, len);
	memcpy(out + n, data, len);
	return n + len;
}

static bool take(struct cursor *c, uint8_t expected)
{
	if (c->left == 0U || *c->p != expected) return false;
	c->p++; c->left--;
	return true;
}

static bool get_uint(struct cursor *c, uint8_t major, uint64_t *value)
{
	uint8_t ai;
	size_t bytes;
	uint64_t v = 0;

	if (c->left == 0U || (*c->p >> 5) != major) return false;
	ai = *c->p++ & 31U; c->left--;
	if (ai < 24U) { *value = ai; return true; }
	if (ai == 24U) bytes = 1; else if (ai == 25U) bytes = 2;
	else if (ai == 26U) bytes = 4; else if (ai == 27U) bytes = 8; else return false;
	if (c->left < bytes) return false;
	for (size_t i = 0; i < bytes; i++) v = (v << 8) | c->p[i];
	if ((bytes == 1 && v < 24U) || (bytes == 2 && v <= UINT8_MAX) ||
	    (bytes == 4 && v <= UINT16_MAX) || (bytes == 8 && v <= UINT32_MAX)) return false;
	c->p += bytes; c->left -= bytes; *value = v;
	return true;
}

static bool get_bstr(struct cursor *c, const uint8_t **data, size_t *len)
{
	uint64_t n;
	if (!get_uint(c, 2, &n) || n > SIZE_MAX || c->left < (size_t)n) return false;
	*data = c->p; *len = (size_t)n; c->p += (size_t)n; c->left -= (size_t)n;
	return true;
}

static size_t encode_payload(const struct lichen_tunnel_claims *claims, uint8_t out[80])
{
	size_t n = 0;
	size_t prefix_bytes = (claims->prefix_len + 7U) / 8U;
	out[n++] = 0xa6;
	out[n++] = 0x01; n += put_bstr(out + n, claims->prefix, prefix_bytes);
	out[n++] = 0x02; n += put_uint(out + n, 0, claims->prefix_len);
	out[n++] = 0x03; n += put_bstr(out + n, claims->route_hash, 16);
	out[n++] = 0x04; n += put_uint(out + n, 0, claims->path_seq);
	out[n++] = 0x05; n += put_uint(out + n, 0, claims->expiry);
	out[n++] = 0x06; n += put_bstr(out + n, claims->egress_iid, 8);
	return n;
}

static bool decode_payload(const uint8_t *data, size_t len, struct lichen_tunnel_claims *claims)
{
	struct cursor c = { data, len };
	const uint8_t *p;
	size_t n;
	uint64_t v;
	struct lichen_tunnel_claims tmp = { 0 };

	if (!take(&c, 0xa6) || !take(&c, 0x01) || !get_bstr(&c, &p, &n) || n > 16U) return false;
	memcpy(tmp.prefix, p, n);
	if (!take(&c, 0x02) || !get_uint(&c, 0, &v) || v > 128U || n != (v + 7U) / 8U) return false;
	tmp.prefix_len = (uint8_t)v;
	if (!prefix_valid(tmp.prefix, tmp.prefix_len)) return false;
	if (!take(&c, 0x03) || !get_bstr(&c, &p, &n) || n != 16U) return false;
	memcpy(tmp.route_hash, p, 16);
	if (!take(&c, 0x04) || !get_uint(&c, 0, &tmp.path_seq)) return false;
	if (!take(&c, 0x05) || !get_uint(&c, 0, &tmp.expiry)) return false;
	if (!take(&c, 0x06) || !get_bstr(&c, &p, &n) || n != 8U || c.left != 0U) return false;
	memcpy(tmp.egress_iid, p, 8); *claims = tmp;
	return true;
}

static int signature_digest(const struct lichen_tunnel_crypto *crypto,
			    const uint8_t *payload, size_t payload_len, uint8_t digest[32])
{
	uint8_t structure[112];
	size_t n = 0;
	static const uint8_t context[] = "Signature1";

	structure[n++] = 0x84;
	n += put_uint(structure + n, 3, sizeof(context) - 1U);
	memcpy(structure + n, context, sizeof(context) - 1U);
	n += sizeof(context) - 1U;
	n += put_bstr(structure + n, protected_header, sizeof(protected_header));
	structure[n++] = 0x40;
	n += put_bstr(structure + n, payload, payload_len);
	return crypto->sha256(structure, n, digest);
}

int lichen_tunnel_route_hash(const struct lichen_tunnel_crypto *crypto,
			     const uint8_t *route_iids, size_t route_hops,
			     uint8_t route_hash[16])
{
	uint8_t digest[32];
	if (!crypto_valid(crypto) || route_iids == NULL || route_hash == NULL ||
	    route_hops == 0U || route_hops > LICHEN_TUNNEL_AUTH_MAX_ROUTE_HOPS) return -EINVAL;
	for (size_t i = 0; i < route_hops; i++) {
		for (size_t j = 0; j < i; j++) {
			if (memcmp(route_iids + 8U * i, route_iids + 8U * j, 8) == 0) return -ELOOP;
		}
	}
	if (crypto->sha256(route_iids, route_hops * 8U, digest) != 0) return -EIO;
	memcpy(route_hash, digest, 16); memset(digest, 0, sizeof(digest));
	return 0;
}

int lichen_tunnel_auth_encode(const struct lichen_tunnel_crypto *crypto,
			      const uint8_t root_private_key[32], const uint8_t root_public_key[32],
			      const uint8_t root_iid[8], const struct lichen_tunnel_claims *claims,
			      const uint8_t *route_iids, size_t route_hops,
			      uint8_t *output, size_t output_size, size_t *output_len)
{
	uint8_t tmp[LICHEN_TUNNEL_AUTH_MAX_WIRE_SIZE], payload[80], digest[32], sig[48], iid[8], rh[16];
	size_t n = 0, payload_len;
	int rc = -EINVAL;
	if (!crypto_valid(crypto) || root_private_key == NULL || root_public_key == NULL || root_iid == NULL ||
	    claims == NULL || route_iids == NULL || output == NULL || output_len == NULL ||
	    !prefix_valid(claims->prefix, claims->prefix_len)) return -EINVAL;
	if (crypto->derive_iid(root_public_key, iid) != 0 || memcmp(iid, root_iid, 8) != 0) return -EACCES;
	if (lichen_tunnel_route_hash(crypto, route_iids, route_hops, rh) != 0 ||
	    memcmp(rh, claims->route_hash, 16) != 0 ||
	    memcmp(route_iids + (route_hops - 1U) * 8U, claims->egress_iid, 8) != 0) return -EINVAL;
	payload_len = encode_payload(claims, payload);
	if (signature_digest(crypto, payload, payload_len, digest) != 0 ||
	    crypto->sign(root_private_key, root_public_key, digest, sig) != 0) { rc = -EIO; goto out; }
	tmp[n++] = 0x84; n += put_bstr(tmp + n, protected_header, sizeof(protected_header));
	tmp[n++] = 0xa1; tmp[n++] = 0x04; n += put_bstr(tmp + n, root_iid, 8);
	n += put_bstr(tmp + n, payload, payload_len); n += put_bstr(tmp + n, sig, 48);
	if (n > output_size) { rc = -ENOBUFS; goto out; }
	memcpy(output, tmp, n); *output_len = n; rc = 0;
out:
	memset(tmp, 0, sizeof(tmp)); memset(payload, 0, sizeof(payload));
	memset(digest, 0, sizeof(digest)); memset(sig, 0, sizeof(sig));
	return rc;
}

struct lichen_tunnel_result lichen_tunnel_auth_route_installed(
	const struct lichen_tunnel_crypto *crypto, const uint8_t root_private_key[32],
	const uint8_t root_public_key[32], const uint8_t root_iid[8],
	const struct lichen_tunnel_claims *claims, const uint8_t *route_iids,
	size_t route_hops, bool egress_capable, lichen_tunnel_post_fn post,
	void *user_data)
{
	uint8_t body[LICHEN_TUNNEL_AUTH_MAX_WIRE_SIZE];
	size_t body_len = 0;
	int rc;

	if (!egress_capable) {
		return deny(LICHEN_TUNNEL_DENIAL_DESTINATION_SCOPE);
	}
	if (post == NULL || claims == NULL ||
	    lichen_tunnel_auth_encode(crypto, root_private_key, root_public_key,
				      root_iid, claims, route_iids, route_hops,
				      body, sizeof(body), &body_len) != 0) {
		return deny(LICHEN_TUNNEL_DENIAL_INVALID_ROUTE);
	}
	rc = post(claims->egress_iid, LICHEN_TUNNEL_AUTH_RESOURCE,
		  LICHEN_TUNNEL_AUTH_CONTENT_FORMAT, body, body_len, true, user_data);
	memset(body, 0, sizeof(body));
	return rc == 0 ? permit() : deny(LICHEN_TUNNEL_DENIAL_DELIVERY_FAILED);
}

static bool decode_sign1(const uint8_t *body, size_t len, struct lichen_tunnel_claims *claims,
			 uint8_t kid[8], const uint8_t **payload, size_t *payload_len,
			 const uint8_t **signature, enum lichen_tunnel_denial *why)
{
	struct cursor c = { body, len };
	const uint8_t *p; size_t n;
	if (!take(&c, 0x84) || !get_bstr(&c, &p, &n)) return false;
	if (n != sizeof(protected_header) || memcmp(p, protected_header, n) != 0) {
		/* A canonical one-entry alg map with another value is an unsupported
		 * algorithm.  All other encodings (including duplicate alg keys) are
		 * malformed rather than an algorithm oracle. */
		if (n >= 2U && p[0] == 0xa1U && p[1] == 0x01U) {
			*why = LICHEN_TUNNEL_DENIAL_ALGORITHM;
		}
		return false;
	}
	if (!take(&c, 0xa1) || !take(&c, 0x04) || !get_bstr(&c, &p, &n) || n != 8U) return false;
	memcpy(kid, p, 8);
	if (!get_bstr(&c, payload, payload_len) || !decode_payload(*payload, *payload_len, claims)) return false;
	if (!get_bstr(&c, signature, &n) || n != 48U || c.left != 0U) return false;
	return true;
}

static bool key_equal(const struct lichen_tunnel_history *h, const struct lichen_tunnel_claims *c)
{
	return h->used && h->prefix_len == c->prefix_len && memcmp(h->prefix, c->prefix, 16) == 0 &&
	       memcmp(h->route_hash, c->route_hash, 16) == 0;
}

static int history_find(struct lichen_tunnel_auth_ctx *ctx, const struct lichen_tunnel_claims *c)
{
	for (size_t i = 0; i < CONFIG_LICHEN_TUNNEL_AUTH_MAX_HISTORY; i++) if (key_equal(&ctx->history[i], c)) return (int)i;
	return -1;
}

static int history_free(struct lichen_tunnel_auth_ctx *ctx)
{
	for (size_t i = 0; i < CONFIG_LICHEN_TUNNEL_AUTH_MAX_HISTORY; i++) if (!ctx->history[i].used) return (int)i;
	return -1;
}

static void purge_entries(struct lichen_tunnel_auth_ctx *ctx)
{
	memset(ctx->entries, 0, sizeof(ctx->entries));
}

static bool observe_time(struct lichen_tunnel_auth_ctx *ctx, uint64_t now)
{
	if (ctx->have_time && now < ctx->last_now) { purge_entries(ctx); return false; }
	ctx->last_now = now; ctx->have_time = true; return true;
}

int lichen_tunnel_auth_init(struct lichen_tunnel_auth_ctx *ctx, const uint8_t egress_iid[8],
			    const uint8_t root_iid[8], const uint8_t root_pubkey[32],
			    const struct lichen_tunnel_crypto *crypto)
{
	uint8_t derived[8];
	if (ctx == NULL || egress_iid == NULL || root_iid == NULL || root_pubkey == NULL || !crypto_valid(crypto)) return -EINVAL;
	if (crypto->derive_iid(root_pubkey, derived) != 0 || memcmp(derived, root_iid, 8) != 0) return -EACCES;
	memset(ctx, 0, sizeof(*ctx)); memcpy(ctx->egress_iid, egress_iid, 8);
	memcpy(ctx->root_iid, root_iid, 8); memcpy(ctx->root_pubkey, root_pubkey, 32); ctx->crypto = *crypto;
	atomic_flag_clear(&ctx->lock); return 0;
}

struct lichen_tunnel_result lichen_tunnel_auth_receive(struct lichen_tunnel_auth_ctx *ctx,
	const uint8_t *body, size_t body_len, bool oscore_authenticated,
	const uint8_t oscore_sender_iid[8], uint64_t now)
{
	struct lichen_tunnel_claims claims; uint8_t kid[8], digest[32];
	const uint8_t *payload, *signature; enum lichen_tunnel_denial why = LICHEN_TUNNEL_DENIAL_MALFORMED;
	int hi, ei = -1, free_slot = -1, oldest_slot = -1; uint64_t oldest = UINT64_MAX;
	if (ctx == NULL || body == NULL || oscore_sender_iid == NULL) return deny(LICHEN_TUNNEL_DENIAL_MALFORMED);
	if (!oscore_authenticated) return deny(LICHEN_TUNNEL_DENIAL_OSCORE_REQUIRED);
	lock_ctx(ctx);
	if (memcmp(oscore_sender_iid, ctx->root_iid, 8) != 0) { unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_WRONG_ROOT); }
	if (!decode_sign1(body, body_len, &claims, kid, &payload, &body_len, &signature, &why)) { unlock_ctx(ctx); return deny(why); }
	if (memcmp(kid, ctx->root_iid, 8) != 0) { unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_WRONG_ROOT); }
	if (signature_digest(&ctx->crypto, payload, body_len, digest) != 0 || !ctx->crypto.verify(ctx->root_pubkey, digest, signature)) {
		unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_SIGNATURE);
	}
	if (memcmp(claims.egress_iid, ctx->egress_iid, 8) != 0) { unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_WRONG_EGRESS); }
	if (!observe_time(ctx, now)) { unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_CLOCK_REGRESSION); }
	if (claims.expiry <= now) { unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_EXPIRED); }
	hi = history_find(ctx, &claims);
	if (hi >= 0 && claims.path_seq <= ctx->history[hi].floor) {
		why = ctx->history[hi].revoked ? LICHEN_TUNNEL_DENIAL_REVOKED : LICHEN_TUNNEL_DENIAL_REPLAY;
		unlock_ctx(ctx); return deny(why);
	}
	if (hi < 0) { hi = history_free(ctx); if (hi < 0) { unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_CAPACITY); } }
	for (size_t i = 0; i < CONFIG_LICHEN_TUNNEL_AUTH_MAX_ENTRIES; i++) {
		if (ctx->entries[i].used && ctx->entries[i].claims.prefix_len == claims.prefix_len &&
		    memcmp(ctx->entries[i].claims.prefix, claims.prefix, 16) == 0 &&
		    memcmp(ctx->entries[i].claims.route_hash, claims.route_hash, 16) == 0) { ei = (int)i; break; }
		if (!ctx->entries[i].used && free_slot < 0) free_slot = (int)i;
		else if (ctx->entries[i].used && ctx->entries[i].age < oldest) {
			oldest = ctx->entries[i].age; oldest_slot = (int)i;
		}
	}
	if (ei < 0) ei = free_slot >= 0 ? free_slot : oldest_slot;
	ctx->history[hi].used = true; ctx->history[hi].revoked = false;
	memcpy(ctx->history[hi].prefix, claims.prefix, 16); ctx->history[hi].prefix_len = claims.prefix_len;
	memcpy(ctx->history[hi].route_hash, claims.route_hash, 16); ctx->history[hi].floor = claims.path_seq;
	ctx->entries[ei].used = true; ctx->entries[ei].claims = claims; ctx->entries[ei].age = ++ctx->age;
	unlock_ctx(ctx); return permit();
}

int lichen_tunnel_auth_change_root(struct lichen_tunnel_auth_ctx *ctx, const uint8_t root_iid[8],
				   const uint8_t root_pubkey[32])
{
	uint8_t derived[8];
	if (ctx == NULL || root_iid == NULL || root_pubkey == NULL ||
	    ctx->crypto.derive_iid(root_pubkey, derived) != 0 || memcmp(derived, root_iid, 8) != 0) return -EACCES;
	lock_ctx(ctx);
	if (memcmp(root_iid, ctx->root_iid, 8) != 0 || memcmp(root_pubkey, ctx->root_pubkey, 32) != 0) {
		memcpy(ctx->root_iid, root_iid, 8); memcpy(ctx->root_pubkey, root_pubkey, 32);
		purge_entries(ctx); memset(ctx->history, 0, sizeof(ctx->history)); ctx->have_time = false; ctx->age = 0;
	}
	unlock_ctx(ctx); return 0;
}

int lichen_tunnel_auth_revoke(struct lichen_tunnel_auth_ctx *ctx, const uint8_t prefix[16], uint8_t prefix_len,
			      const uint8_t route_hash[16], uint64_t through_seq)
{
	struct lichen_tunnel_claims c = { 0 }; int hi;
	if (ctx == NULL || prefix == NULL || route_hash == NULL) return -EINVAL;
	memcpy(c.prefix, prefix, 16); c.prefix_len = prefix_len; memcpy(c.route_hash, route_hash, 16);
	if (!prefix_valid(c.prefix, c.prefix_len)) return -EINVAL;
	lock_ctx(ctx); hi = history_find(ctx, &c); if (hi < 0) hi = history_free(ctx);
	if (hi < 0) { unlock_ctx(ctx); return -ENOSPC; }
	ctx->history[hi].used = true; ctx->history[hi].revoked = true;
	memcpy(ctx->history[hi].prefix, prefix, 16); ctx->history[hi].prefix_len = prefix_len;
	memcpy(ctx->history[hi].route_hash, route_hash, 16);
	if (through_seq > ctx->history[hi].floor) ctx->history[hi].floor = through_seq;
	for (size_t i = 0; i < CONFIG_LICHEN_TUNNEL_AUTH_MAX_ENTRIES; i++)
		if (ctx->entries[i].used && ctx->entries[i].claims.prefix_len == prefix_len &&
		    memcmp(ctx->entries[i].claims.prefix, prefix, 16) == 0 && memcmp(ctx->entries[i].claims.route_hash, route_hash, 16) == 0)
			ctx->entries[i].used = false;
	unlock_ctx(ctx); return 0;
}

static bool prefix_match(const uint8_t addr[16], const uint8_t prefix[16], uint8_t bits)
{
	size_t n = bits / 8U; uint8_t rem = bits & 7U;
	if (memcmp(addr, prefix, n) != 0) return false;
	return rem == 0U || ((addr[n] ^ prefix[n]) & (uint8_t)(0xffU << (8U - rem))) == 0U;
}

static bool unsafe_addr(const uint8_t a[16])
{
	bool zero = true; for (size_t i = 0; i < 16; i++) if (a[i] != 0U) zero = false;
	return zero || (memcmp(a, (uint8_t[16]){ [15] = 1 }, 16) == 0) || a[0] == 0xffU;
}

struct lichen_tunnel_result lichen_tunnel_auth_decapsulate(struct lichen_tunnel_auth_ctx *ctx,
	const uint8_t source[16], const uint8_t destination[16], const uint8_t *route_iids,
	size_t route_hops, enum lichen_tunnel_direction direction, uint64_t now)
{
	uint8_t hash[16]; int best = -1; uint8_t best_bits = 0;
	if (ctx == NULL || source == NULL || destination == NULL || route_iids == NULL) return deny(LICHEN_TUNNEL_DENIAL_MALFORMED);
	if (direction != LICHEN_TUNNEL_MESH_TO_EXTERNAL) return deny(LICHEN_TUNNEL_DENIAL_WRONG_DIRECTION);
	if (lichen_tunnel_route_hash(&ctx->crypto, route_iids, route_hops, hash) != 0 ||
	    memcmp(route_iids + (route_hops - 1U) * 8U, ctx->egress_iid, 8) != 0) return deny(LICHEN_TUNNEL_DENIAL_INVALID_ROUTE);
	lock_ctx(ctx);
	if (!observe_time(ctx, now)) { unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_CLOCK_REGRESSION); }
	for (size_t i = 0; i < CONFIG_LICHEN_TUNNEL_AUTH_MAX_ENTRIES; i++)
		if (ctx->entries[i].used && memcmp(ctx->entries[i].claims.route_hash, hash, 16) == 0 &&
		    prefix_match(source, ctx->entries[i].claims.prefix, ctx->entries[i].claims.prefix_len) &&
		    (best < 0 || ctx->entries[i].claims.prefix_len > best_bits)) { best = (int)i; best_bits = ctx->entries[i].claims.prefix_len; }
	if (best < 0) { unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_NO_AUTHORIZATION); }
	if (ctx->entries[best].claims.expiry <= now) { ctx->entries[best].used = false; unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_EXPIRED); }
	if (unsafe_addr(source) || (source[0] == 0xfeU && (source[1] & 0xc0U) == 0x80U)) { unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_SOURCE_SCOPE); }
	if (unsafe_addr(destination) || (destination[0] == 0xfeU && (destination[1] & 0xc0U) == 0x80U) || destination[0] == 0x02U) {
		unlock_ctx(ctx); return deny(LICHEN_TUNNEL_DENIAL_DESTINATION_SCOPE);
	}
	ctx->entries[best].age = ++ctx->age; unlock_ctx(ctx); return permit();
}

#ifdef __ZEPHYR__
static int default_sha256(const uint8_t *input, size_t len, uint8_t out[32])
{
	struct tc_sha256_state_struct s;
	return tc_sha256_init(&s) == TC_CRYPTO_SUCCESS && tc_sha256_update(&s, input, len) == TC_CRYPTO_SUCCESS &&
	       tc_sha256_final(out, &s) == TC_CRYPTO_SUCCESS ? 0 : -EIO;
}
static int default_sign(const uint8_t sk[32], const uint8_t pk[32], const uint8_t d[32], uint8_t s[48])
{ return schnorr48_sign(sk, pk, d, 32, s); }
static bool default_verify(const uint8_t pk[32], const uint8_t d[32], const uint8_t s[48])
{ return schnorr48_verify(pk, d, 32, s, 48); }
int lichen_tunnel_auth_default_crypto(struct lichen_tunnel_crypto *crypto)
{
	if (crypto == NULL) return -EINVAL;
	*crypto = (struct lichen_tunnel_crypto){ default_sha256, lichen_key_pubkey_to_iid, default_sign, default_verify };
	return 0;
}
#else
int lichen_tunnel_auth_default_crypto(struct lichen_tunnel_crypto *crypto)
{ (void)crypto; return -ENOTSUP; }
#endif
