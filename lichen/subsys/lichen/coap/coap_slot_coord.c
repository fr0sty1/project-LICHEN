/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_slot_coord.c
 * @brief Slot Coordination protocol implementation (GCP-6)
 *
 * Implements GCP-6 per spec/08-gateway-coordination.md Section 6:
 * - Superframe synchronization (GPS epoch, time master election)
 * - Slot allocation (interleaved and contiguous modes)
 * - Conflict resolution (lowest IID wins, signature validation)
 * - CoAP resources (/info, /slots, /channels)
 *
 * SECURITY: All slot claims MUST be signed with Schnorr48. Claims with
 * invalid or missing signatures are silently discarded per GCP-6.3.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>

#include <lichen/coap_slot_coord.h>
#include <lichen/coap_server.h>
#include <lichen/coap_keys.h>
#include <lichen/schnorr48.h>

LOG_MODULE_REGISTER(lichen_slot_coord, CONFIG_LICHEN_COAP_SLOT_COORD_LOG_LEVEL);

/* --------------------------------------------------------------------------
 * CBOR key definitions (matching test vectors)
 * -------------------------------------------------------------------------- */

/* Slot claim keys (sorted by encoded length per RFC 8949 Section 4.2.1) */
#define KEY_SLOTS           "slots"
#define KEY_ORDINAL         "ordinal"
#define KEY_GATEWAY_IID     "gateway_iid"
#define KEY_GATEWAY_COUNT   "gateway_count"
#define KEY_SUPERFRAME_ID   "superframe_id"
#define KEY_SLOT_START      "slot_start"
#define KEY_SLOT_COUNT      "slot_count"

/* Slot grant keys */
#define KEY_GRANTED_SLOTS   "granted_slots"
#define KEY_VALID_UNTIL     "valid_until"

/* Gateway info keys */
#define KEY_TIME_SOURCE     "time_source"
#define KEY_SLOTS_TOTAL     "slots_total"
#define KEY_ALLOCATED_SLOTS "allocated_slots"
#define KEY_SUPERFRAME_EPOCH "superframe_epoch"
#define KEY_SUPERFRAME_DURATION "superframe_duration_s"

/* Allocation map keys */
#define KEY_ALLOCATION_MODE "allocation_mode"
#define KEY_ALLOCATIONS     "allocations"

/* CBOR content-format */
#define CBOR_CONTENT_FORMAT 60

/* --------------------------------------------------------------------------
 * Internal state
 * -------------------------------------------------------------------------- */

static struct lichen_slot_coord_ctx s_ctx;
static K_MUTEX_DEFINE(s_coord_lock);

/* --------------------------------------------------------------------------
 * IID comparison (big-endian unsigned 64-bit)
 * -------------------------------------------------------------------------- */

int lichen_iid_compare(const uint8_t iid_a[LICHEN_IID_LEN],
		       const uint8_t iid_b[LICHEN_IID_LEN])
{
	/* Compare as unsigned big-endian 64-bit integers */
	for (int i = 0; i < LICHEN_IID_LEN; i++) {
		if (iid_a[i] < iid_b[i]) {
			return -1;
		}
		if (iid_a[i] > iid_b[i]) {
			return 1;
		}
	}
	return 0;
}

/* --------------------------------------------------------------------------
 * Initialization
 * -------------------------------------------------------------------------- */

int lichen_slot_coord_init(struct lichen_slot_coord_ctx *ctx,
			   const uint8_t local_iid[LICHEN_IID_LEN])
{
	if (ctx == NULL || local_iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->local_iid, local_iid, LICHEN_IID_LEN);

	/* Default superframe configuration */
	ctx->superframe.time_source = LICHEN_TIME_SOURCE_NONE;
	ctx->superframe.duration_s = LICHEN_SUPERFRAME_DURATION_S;
	ctx->superframe.slots_per_superframe = LICHEN_SLOTS_PER_SUPERFRAME;
	ctx->superframe.slot_duration_ms = LICHEN_SLOT_DURATION_MS;
	ctx->superframe.synced = false;

	/* Default allocation mode */
	ctx->alloc_mode = LICHEN_SLOT_ALLOC_INTERLEAVED;
	ctx->gateway_count = 0;
	ctx->local_ordinal = 0;
	ctx->local_slot_count = 0;
	ctx->initialized = true;

	k_mutex_unlock(&s_coord_lock);

	LOG_INF("Slot coordination initialized");
	return 0;
}

/* --------------------------------------------------------------------------
 * Superframe timing
 * -------------------------------------------------------------------------- */

uint32_t lichen_slot_coord_superframe_id(const struct lichen_slot_coord_ctx *ctx,
					 uint64_t unix_time)
{
	if (ctx == NULL || ctx->superframe.duration_s == 0) {
		return 0;
	}
	return (uint32_t)(unix_time / ctx->superframe.duration_s);
}

uint8_t lichen_slot_coord_current_slot(const struct lichen_slot_coord_ctx *ctx,
				       uint64_t unix_time)
{
	if (ctx == NULL || ctx->superframe.duration_s == 0) {
		return 0;
	}

	uint64_t superframe_start = (unix_time / ctx->superframe.duration_s) *
				    ctx->superframe.duration_s;
	uint64_t offset = unix_time - superframe_start;

	return (uint8_t)(offset % ctx->superframe.slots_per_superframe);
}

int lichen_slot_coord_elect_time_master(struct lichen_slot_coord_ctx *ctx,
					uint8_t master_iid[LICHEN_IID_LEN])
{
	if (ctx == NULL || master_iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	if (ctx->gateway_count == 0) {
		/* No other gateways, we are the master */
		memcpy(master_iid, ctx->local_iid, LICHEN_IID_LEN);
		memcpy(ctx->superframe.time_master_iid, ctx->local_iid, LICHEN_IID_LEN);
		k_mutex_unlock(&s_coord_lock);
		return 0;
	}

	/* Find lowest IID among all gateways including ourselves */
	memcpy(master_iid, ctx->local_iid, LICHEN_IID_LEN);

	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!ctx->gateways[i].valid) {
			continue;
		}
		if (lichen_iid_compare(ctx->gateways[i].iid, master_iid) < 0) {
			memcpy(master_iid, ctx->gateways[i].iid, LICHEN_IID_LEN);
		}
	}

	memcpy(ctx->superframe.time_master_iid, master_iid, LICHEN_IID_LEN);

	k_mutex_unlock(&s_coord_lock);
	return 0;
}

/* --------------------------------------------------------------------------
 * Slot allocation computation
 * -------------------------------------------------------------------------- */

int lichen_slot_coord_interleaved(uint8_t ordinal, uint8_t gateway_count,
				  uint8_t num_slots, uint8_t *slots,
				  size_t max_slots)
{
	if (slots == NULL || gateway_count == 0) {
		return -EINVAL;
	}

	size_t count = 0;
	for (uint8_t s = ordinal; s < num_slots && count < max_slots; s += gateway_count) {
		slots[count++] = s;
	}

	return (int)count;
}

int lichen_slot_coord_contiguous(uint8_t ordinal, uint8_t gateway_count,
				 uint8_t num_slots, uint8_t *slot_start,
				 uint8_t *slot_count)
{
	if (slot_start == NULL || slot_count == NULL || gateway_count == 0) {
		return -EINVAL;
	}

	uint8_t slots_per_gw = num_slots / gateway_count;
	*slot_start = ordinal * slots_per_gw;
	*slot_count = slots_per_gw;

	return 0;
}

bool lichen_slot_coord_validate_interleaved(const uint8_t *slots,
					    uint8_t slot_count,
					    uint8_t ordinal,
					    uint8_t gateway_count)
{
	if (slots == NULL || gateway_count == 0) {
		return false;
	}

	for (uint8_t i = 0; i < slot_count; i++) {
		uint8_t expected = ordinal + i * gateway_count;
		if (slots[i] != expected) {
			return false;
		}
	}

	return true;
}

bool lichen_slot_coord_tx_allowed(const struct lichen_slot_coord_ctx *ctx,
				  uint8_t current_slot)
{
	if (ctx == NULL || !ctx->initialized) {
		return false;
	}

	for (uint8_t i = 0; i < ctx->local_slot_count; i++) {
		if (ctx->local_slots[i] == current_slot) {
			return true;
		}
	}

	return false;
}

/* --------------------------------------------------------------------------
 * Conflict resolution
 * -------------------------------------------------------------------------- */

const struct lichen_slot_claim *lichen_slot_coord_resolve_conflict(
	const struct lichen_slot_claim *claim_a, bool sig_a_valid,
	const struct lichen_slot_claim *claim_b, bool sig_b_valid)
{
	if (claim_a == NULL || claim_b == NULL) {
		return NULL;
	}

	/* Per GCP-6.3: If one signature fails, valid claim wins */
	if (sig_a_valid && !sig_b_valid) {
		return claim_a;
	}
	if (sig_b_valid && !sig_a_valid) {
		return claim_b;
	}
	if (!sig_a_valid && !sig_b_valid) {
		return NULL; /* Both invalid */
	}

	/* Both valid: lowest IID wins */
	if (lichen_iid_compare(claim_a->gateway_iid, claim_b->gateway_iid) <= 0) {
		return claim_a;
	}
	return claim_b;
}

enum lichen_claim_result lichen_slot_coord_process_claim(
	struct lichen_slot_coord_ctx *ctx,
	const struct lichen_slot_claim *claim,
	struct lichen_slot_grant *grant)
{
	if (ctx == NULL || claim == NULL || grant == NULL) {
		return LICHEN_CLAIM_REJECT_INVALID_SLOTS;
	}

	/* SECURITY: Claims without signature MUST be silently discarded */
	if (!claim->has_signature) {
		LOG_DBG("Discarding claim without signature");
		return LICHEN_CLAIM_REJECT_NO_SIG;
	}

	/* SECURITY: Verify Schnorr48 signature on slot claim (GCP-6.3) */
#ifdef CONFIG_LICHEN_LINK_SCHNORR
	{
		/* Fetch gateway public key from key store */
		struct lichen_key_entry key_entry;
		int ret = lichen_key_store_get(claim->gateway_iid, &key_entry);
		if (ret != 0) {
			LOG_DBG("Discarding claim: gateway key not found");
			return LICHEN_CLAIM_REJECT_INVALID_SIG;
		}

		/* Reconstruct signed message: SLOT_CLAIM:XX:IIIIIIIIIIIIIIII:XXXXXXXX
		 * XX = ordinal (2 hex chars)
		 * IIIIIIIIIIIIIIII = gateway_iid (16 hex chars)
		 * XXXXXXXX = superframe_id (8 hex chars)
		 */
		char msg_buf[48];
		int msg_len = snprintf(msg_buf, sizeof(msg_buf),
				       "SLOT_CLAIM:%02X:", claim->ordinal);
		for (int i = 0; i < LICHEN_IID_LEN; i++) {
			snprintf(&msg_buf[msg_len + i * 2], 3, "%02X",
				 claim->gateway_iid[i]);
		}
		msg_len += LICHEN_IID_LEN * 2;
		msg_len += snprintf(&msg_buf[msg_len], sizeof(msg_buf) - msg_len,
				    ":%08X", claim->superframe_id);

		if (!schnorr48_verify(key_entry.pubkey, (const uint8_t *)msg_buf,
				      (size_t)msg_len, claim->signature,
				      LICHEN_SCHNORR48_LEN)) {
			LOG_DBG("Discarding claim: invalid signature");
			return LICHEN_CLAIM_REJECT_INVALID_SIG;
		}
	}
#endif

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	/* Check for conflicts with existing allocations */
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!ctx->gateways[i].valid) {
			continue;
		}

		/* Check for overlapping slots */
		for (uint8_t cs = 0; cs < claim->slot_count; cs++) {
			for (uint8_t gs = 0; gs < ctx->gateways[i].slot_count; gs++) {
				if (claim->slots[cs] == ctx->gateways[i].slots[gs]) {
					/* Conflict detected: compare IIDs */
					if (lichen_iid_compare(claim->gateway_iid,
							       ctx->gateways[i].iid) > 0) {
						/* Existing allocation has lower IID, reject */
						k_mutex_unlock(&s_coord_lock);
						LOG_DBG("Claim rejected: conflict with lower IID");
						return LICHEN_CLAIM_REJECT_CONFLICT;
					}
					/* Claim has lower IID, will override */
				}
			}
		}
	}

	/* Accept claim and update grant */
	memcpy(grant->granted_slots, claim->slots, claim->slot_count);
	grant->granted_count = claim->slot_count;
	grant->superframe_id = claim->superframe_id;
	grant->valid_until = 0; /* Caller should set expiration */

	/* Register the gateway allocation */
	lichen_slot_coord_register_gateway(ctx, claim->gateway_iid, claim->ordinal,
					   claim->slots, claim->slot_count,
					   claim->superframe_id);

	k_mutex_unlock(&s_coord_lock);
	LOG_INF("Slot claim accepted");
	return LICHEN_CLAIM_ACCEPTED;
}

int lichen_slot_coord_find_available(const struct lichen_slot_coord_ctx *ctx,
				     uint8_t slot_count, uint8_t *available_slots,
				     size_t max_slots)
{
	if (ctx == NULL || available_slots == NULL) {
		return -EINVAL;
	}

	/* Build a bitmap of occupied slots */
	uint64_t occupied = 0;

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!ctx->gateways[i].valid) {
			continue;
		}
		for (uint8_t s = 0; s < ctx->gateways[i].slot_count; s++) {
			if (ctx->gateways[i].slots[s] < 64) {
				occupied |= (1ULL << ctx->gateways[i].slots[s]);
			}
		}
	}

	k_mutex_unlock(&s_coord_lock);

	/* Find available slots */
	uint8_t found = 0;
	for (uint8_t s = 0; s < ctx->superframe.slots_per_superframe &&
			    found < slot_count && found < max_slots; s++) {
		if (s < 64 && !(occupied & (1ULL << s))) {
			available_slots[found++] = s;
		}
	}

	return found;
}

int lichen_slot_coord_register_gateway(struct lichen_slot_coord_ctx *ctx,
				       const uint8_t iid[LICHEN_IID_LEN],
				       uint8_t ordinal, const uint8_t *slots,
				       uint8_t slot_count, uint32_t superframe_id)
{
	if (ctx == NULL || iid == NULL || slots == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	/* Check if gateway already exists */
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (ctx->gateways[i].valid &&
		    memcmp(ctx->gateways[i].iid, iid, LICHEN_IID_LEN) == 0) {
			/* Update existing entry */
			ctx->gateways[i].ordinal = ordinal;
			memcpy(ctx->gateways[i].slots, slots, slot_count);
			ctx->gateways[i].slot_count = slot_count;
			ctx->gateways[i].superframe_id = superframe_id;
			k_mutex_unlock(&s_coord_lock);
			return 0;
		}
	}

	/* Find free slot */
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!ctx->gateways[i].valid) {
			memcpy(ctx->gateways[i].iid, iid, LICHEN_IID_LEN);
			ctx->gateways[i].ordinal = ordinal;
			memcpy(ctx->gateways[i].slots, slots, slot_count);
			ctx->gateways[i].slot_count = slot_count;
			ctx->gateways[i].superframe_id = superframe_id;
			ctx->gateways[i].valid = true;
			ctx->gateway_count++;
			k_mutex_unlock(&s_coord_lock);
			return 0;
		}
	}

	k_mutex_unlock(&s_coord_lock);
	return -ENOMEM;
}

/* --------------------------------------------------------------------------
 * CBOR encoding context
 * -------------------------------------------------------------------------- */

struct cbor_enc_ctx {
	uint8_t *buf;
	size_t off;
	size_t size;
	bool overflow;
};

static void cbor_enc_init(struct cbor_enc_ctx *e, uint8_t *buf, size_t size)
{
	e->buf = buf;
	e->off = 0;
	e->size = size;
	e->overflow = false;
}

static bool cbor_enc_check(struct cbor_enc_ctx *e, size_t n)
{
	if (e->overflow || e->off + n > e->size) {
		e->overflow = true;
		return false;
	}
	return true;
}

static void cbor_enc_uint(struct cbor_enc_ctx *e, uint8_t major, uint64_t val)
{
	if (val < 24) {
		if (!cbor_enc_check(e, 1)) return;
		e->buf[e->off++] = (major << 5) | (uint8_t)val;
	} else if (val <= UINT8_MAX) {
		if (!cbor_enc_check(e, 2)) return;
		e->buf[e->off++] = (major << 5) | 24;
		e->buf[e->off++] = (uint8_t)val;
	} else if (val <= UINT16_MAX) {
		if (!cbor_enc_check(e, 3)) return;
		e->buf[e->off++] = (major << 5) | 25;
		e->buf[e->off++] = (uint8_t)(val >> 8);
		e->buf[e->off++] = (uint8_t)val;
	} else if (val <= UINT32_MAX) {
		if (!cbor_enc_check(e, 5)) return;
		e->buf[e->off++] = (major << 5) | 26;
		e->buf[e->off++] = (uint8_t)(val >> 24);
		e->buf[e->off++] = (uint8_t)(val >> 16);
		e->buf[e->off++] = (uint8_t)(val >> 8);
		e->buf[e->off++] = (uint8_t)val;
	} else {
		if (!cbor_enc_check(e, 9)) return;
		e->buf[e->off++] = (major << 5) | 27;
		e->buf[e->off++] = (uint8_t)(val >> 56);
		e->buf[e->off++] = (uint8_t)(val >> 48);
		e->buf[e->off++] = (uint8_t)(val >> 40);
		e->buf[e->off++] = (uint8_t)(val >> 32);
		e->buf[e->off++] = (uint8_t)(val >> 24);
		e->buf[e->off++] = (uint8_t)(val >> 16);
		e->buf[e->off++] = (uint8_t)(val >> 8);
		e->buf[e->off++] = (uint8_t)val;
	}
}

static void cbor_enc_bstr(struct cbor_enc_ctx *e, const uint8_t *data, size_t len)
{
	cbor_enc_uint(e, 2, len);
	if (!cbor_enc_check(e, len)) return;
	memcpy(&e->buf[e->off], data, len);
	e->off += len;
}

static void cbor_enc_tstr(struct cbor_enc_ctx *e, const char *str)
{
	size_t len = str ? strlen(str) : 0;
	cbor_enc_uint(e, 3, len);
	if (!cbor_enc_check(e, len)) return;
	memcpy(&e->buf[e->off], str, len);
	e->off += len;
}

static void cbor_enc_map_header(struct cbor_enc_ctx *e, size_t count)
{
	cbor_enc_uint(e, 5, count);
}

static void cbor_enc_array_header(struct cbor_enc_ctx *e, size_t count)
{
	cbor_enc_uint(e, 4, count);
}

/* --------------------------------------------------------------------------
 * CBOR encoding
 * -------------------------------------------------------------------------- */

int lichen_slot_coord_encode_claim(const struct lichen_slot_claim *claim,
				   uint8_t *buf, size_t buf_len)
{
	if (claim == NULL || buf == NULL) {
		return -EINVAL;
	}

	struct cbor_enc_ctx e;
	cbor_enc_init(&e, buf, buf_len);

	/* Count fields: slots, ordinal, gateway_iid, gateway_count, superframe_id */
	int count = 5;
	if (claim->slot_start > 0) {
		count += 2; /* slot_start, slot_count */
	}

	cbor_enc_map_header(&e, count);

	/* Keys sorted by encoded length per RFC 8949 Section 4.2.1 */
	cbor_enc_tstr(&e, KEY_SLOTS);
	cbor_enc_array_header(&e, claim->slot_count);
	for (uint8_t i = 0; i < claim->slot_count; i++) {
		cbor_enc_uint(&e, 0, claim->slots[i]);
	}

	cbor_enc_tstr(&e, KEY_ORDINAL);
	cbor_enc_uint(&e, 0, claim->ordinal);

	cbor_enc_tstr(&e, KEY_GATEWAY_IID);
	cbor_enc_bstr(&e, claim->gateway_iid, LICHEN_IID_LEN);

	cbor_enc_tstr(&e, KEY_GATEWAY_COUNT);
	cbor_enc_uint(&e, 0, claim->gateway_count);

	cbor_enc_tstr(&e, KEY_SUPERFRAME_ID);
	cbor_enc_uint(&e, 0, claim->superframe_id);

	if (claim->slot_start > 0) {
		cbor_enc_tstr(&e, KEY_SLOT_START);
		cbor_enc_uint(&e, 0, claim->slot_start);

		cbor_enc_tstr(&e, KEY_SLOT_COUNT);
		cbor_enc_uint(&e, 0, claim->slot_count);
	}

	if (e.overflow) {
		return -ENOBUFS;
	}

	return (int)e.off;
}

int lichen_slot_coord_encode_grant(const struct lichen_slot_grant *grant,
				   uint8_t *buf, size_t buf_len)
{
	if (grant == NULL || buf == NULL) {
		return -EINVAL;
	}

	struct cbor_enc_ctx e;
	cbor_enc_init(&e, buf, buf_len);

	cbor_enc_map_header(&e, 3);

	cbor_enc_tstr(&e, KEY_VALID_UNTIL);
	cbor_enc_uint(&e, 0, grant->valid_until);

	cbor_enc_tstr(&e, KEY_GRANTED_SLOTS);
	cbor_enc_array_header(&e, grant->granted_count);
	for (uint8_t i = 0; i < grant->granted_count; i++) {
		cbor_enc_uint(&e, 0, grant->granted_slots[i]);
	}

	cbor_enc_tstr(&e, KEY_SUPERFRAME_ID);
	cbor_enc_uint(&e, 0, grant->superframe_id);

	if (e.overflow) {
		return -ENOBUFS;
	}

	return (int)e.off;
}

/* --------------------------------------------------------------------------
 * CBOR decoding helpers
 * -------------------------------------------------------------------------- */

struct cbor_dec_ctx {
	const uint8_t *buf;
	size_t off;
	size_t size;
	bool error;
};

static void cbor_dec_init(struct cbor_dec_ctx *d, const uint8_t *buf, size_t size)
{
	d->buf = buf;
	d->off = 0;
	d->size = size;
	d->error = false;
}

static bool cbor_dec_check(struct cbor_dec_ctx *d, size_t n)
{
	if (d->error || d->off + n > d->size) {
		d->error = true;
		return false;
	}
	return true;
}

static uint64_t cbor_dec_uint_arg(struct cbor_dec_ctx *d, uint8_t info)
{
	if (info < 24) {
		return info;
	} else if (info == 24) {
		if (!cbor_dec_check(d, 1)) return 0;
		return d->buf[d->off++];
	} else if (info == 25) {
		if (!cbor_dec_check(d, 2)) return 0;
		uint64_t val = ((uint64_t)d->buf[d->off] << 8) | d->buf[d->off + 1];
		d->off += 2;
		return val;
	} else if (info == 26) {
		if (!cbor_dec_check(d, 4)) return 0;
		uint64_t val = ((uint64_t)d->buf[d->off] << 24) |
			       ((uint64_t)d->buf[d->off + 1] << 16) |
			       ((uint64_t)d->buf[d->off + 2] << 8) |
			       d->buf[d->off + 3];
		d->off += 4;
		return val;
	} else if (info == 27) {
		if (!cbor_dec_check(d, 8)) return 0;
		uint64_t val = ((uint64_t)d->buf[d->off] << 56) |
			       ((uint64_t)d->buf[d->off + 1] << 48) |
			       ((uint64_t)d->buf[d->off + 2] << 40) |
			       ((uint64_t)d->buf[d->off + 3] << 32) |
			       ((uint64_t)d->buf[d->off + 4] << 24) |
			       ((uint64_t)d->buf[d->off + 5] << 16) |
			       ((uint64_t)d->buf[d->off + 6] << 8) |
			       d->buf[d->off + 7];
		d->off += 8;
		return val;
	}
	d->error = true;
	return 0;
}

static uint64_t cbor_dec_uint(struct cbor_dec_ctx *d)
{
	if (!cbor_dec_check(d, 1)) return 0;
	uint8_t initial = d->buf[d->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 0) {
		d->error = true;
		return 0;
	}
	return cbor_dec_uint_arg(d, info);
}

static size_t cbor_dec_bstr(struct cbor_dec_ctx *d, uint8_t *out, size_t max_len)
{
	if (!cbor_dec_check(d, 1)) return 0;
	uint8_t initial = d->buf[d->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 2) {
		d->error = true;
		return 0;
	}

	uint64_t len = cbor_dec_uint_arg(d, info);
	if (len > max_len || !cbor_dec_check(d, len)) {
		d->error = true;
		return 0;
	}

	memcpy(out, &d->buf[d->off], len);
	d->off += len;
	return (size_t)len;
}

static size_t cbor_dec_tstr(struct cbor_dec_ctx *d, char *out, size_t max_len)
{
	if (!cbor_dec_check(d, 1)) return 0;
	uint8_t initial = d->buf[d->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 3) {
		d->error = true;
		return 0;
	}

	uint64_t len = cbor_dec_uint_arg(d, info);
	if (len >= max_len || !cbor_dec_check(d, len)) {
		d->error = true;
		return 0;
	}

	memcpy(out, &d->buf[d->off], len);
	out[len] = '\0';
	d->off += len;
	return (size_t)len;
}

static size_t cbor_dec_map_header(struct cbor_dec_ctx *d)
{
	if (!cbor_dec_check(d, 1)) return 0;
	uint8_t initial = d->buf[d->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 5) {
		d->error = true;
		return 0;
	}
	return (size_t)cbor_dec_uint_arg(d, info);
}

static size_t cbor_dec_array_header(struct cbor_dec_ctx *d)
{
	if (!cbor_dec_check(d, 1)) return 0;
	uint8_t initial = d->buf[d->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 4) {
		d->error = true;
		return 0;
	}
	return (size_t)cbor_dec_uint_arg(d, info);
}

/* --------------------------------------------------------------------------
 * CBOR decoding
 * -------------------------------------------------------------------------- */

int lichen_slot_coord_decode_claim(const uint8_t *buf, size_t buf_len,
				   struct lichen_slot_claim *claim)
{
	if (buf == NULL || claim == NULL) {
		return -EINVAL;
	}

	memset(claim, 0, sizeof(*claim));

	struct cbor_dec_ctx d;
	cbor_dec_init(&d, buf, buf_len);

	size_t map_count = cbor_dec_map_header(&d);
	if (d.error) {
		return -EBADMSG;
	}

	char key[32];
	for (size_t i = 0; i < map_count && !d.error; i++) {
		cbor_dec_tstr(&d, key, sizeof(key));
		if (d.error) break;

		if (strcmp(key, KEY_SLOTS) == 0) {
			size_t arr_len = cbor_dec_array_header(&d);
			if (arr_len > CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS) {
				d.error = true;
				break;
			}
			for (size_t j = 0; j < arr_len; j++) {
				claim->slots[j] = (uint8_t)cbor_dec_uint(&d);
			}
			claim->slot_count = (uint8_t)arr_len;
		} else if (strcmp(key, KEY_ORDINAL) == 0) {
			claim->ordinal = (uint8_t)cbor_dec_uint(&d);
		} else if (strcmp(key, KEY_GATEWAY_IID) == 0) {
			cbor_dec_bstr(&d, claim->gateway_iid, LICHEN_IID_LEN);
		} else if (strcmp(key, KEY_GATEWAY_COUNT) == 0) {
			claim->gateway_count = (uint8_t)cbor_dec_uint(&d);
		} else if (strcmp(key, KEY_SUPERFRAME_ID) == 0) {
			claim->superframe_id = (uint32_t)cbor_dec_uint(&d);
		} else if (strcmp(key, KEY_SLOT_START) == 0) {
			claim->slot_start = (uint8_t)cbor_dec_uint(&d);
		} else if (strcmp(key, KEY_SLOT_COUNT) == 0) {
			/* Already captured in slots array count */
			(void)cbor_dec_uint(&d);
		} else {
			/* Skip unknown keys */
			d.error = true;
		}
	}

	if (d.error) {
		return -EBADMSG;
	}

	return 0;
}

int lichen_slot_coord_decode_grant(const uint8_t *buf, size_t buf_len,
				   struct lichen_slot_grant *grant)
{
	if (buf == NULL || grant == NULL) {
		return -EINVAL;
	}

	memset(grant, 0, sizeof(*grant));

	struct cbor_dec_ctx d;
	cbor_dec_init(&d, buf, buf_len);

	size_t map_count = cbor_dec_map_header(&d);
	if (d.error) {
		return -EBADMSG;
	}

	char key[32];
	for (size_t i = 0; i < map_count && !d.error; i++) {
		cbor_dec_tstr(&d, key, sizeof(key));
		if (d.error) break;

		if (strcmp(key, KEY_GRANTED_SLOTS) == 0) {
			size_t arr_len = cbor_dec_array_header(&d);
			if (arr_len > CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS) {
				d.error = true;
				break;
			}
			for (size_t j = 0; j < arr_len; j++) {
				grant->granted_slots[j] = (uint8_t)cbor_dec_uint(&d);
			}
			grant->granted_count = (uint8_t)arr_len;
		} else if (strcmp(key, KEY_SUPERFRAME_ID) == 0) {
			grant->superframe_id = (uint32_t)cbor_dec_uint(&d);
		} else if (strcmp(key, KEY_VALID_UNTIL) == 0) {
			grant->valid_until = cbor_dec_uint(&d);
		} else {
			d.error = true;
		}
	}

	if (d.error) {
		return -EBADMSG;
	}

	return 0;
}

/* --------------------------------------------------------------------------
 * CoAP resource handlers
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LICHEN_COAP_SLOT_COORD_RESOURCE

static int slots_get(struct coap_resource *resource,
		     struct coap_packet *request,
		     struct sockaddr *addr, socklen_t addr_len)
{
	static uint8_t resp_buf[256];
	struct cbor_enc_ctx e;
	cbor_enc_init(&e, resp_buf, sizeof(resp_buf));

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	/* Build allocation map response */
	cbor_enc_map_header(&e, 4);

	cbor_enc_tstr(&e, KEY_ALLOCATION_MODE);
	cbor_enc_tstr(&e, s_ctx.alloc_mode == LICHEN_SLOT_ALLOC_INTERLEAVED ?
			  "interleaved" : "contiguous");

	cbor_enc_tstr(&e, KEY_GATEWAY_COUNT);
	cbor_enc_uint(&e, 0, s_ctx.gateway_count);

	cbor_enc_tstr(&e, KEY_SUPERFRAME_ID);
	cbor_enc_uint(&e, 0, s_ctx.superframe.current_superframe_id);

	cbor_enc_tstr(&e, KEY_ALLOCATIONS);
	/* Count valid gateways */
	uint8_t valid_count = 0;
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (s_ctx.gateways[i].valid) valid_count++;
	}
	cbor_enc_map_header(&e, valid_count);

	/* Encode each gateway's slots keyed by IID hex string */
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!s_ctx.gateways[i].valid) continue;

		/* IID as hex string key */
		char iid_hex[17];
		for (int j = 0; j < LICHEN_IID_LEN; j++) {
			snprintf(&iid_hex[j*2], 3, "%02x", s_ctx.gateways[i].iid[j]);
		}
		cbor_enc_tstr(&e, iid_hex);

		/* Slots array */
		cbor_enc_array_header(&e, s_ctx.gateways[i].slot_count);
		for (uint8_t s = 0; s < s_ctx.gateways[i].slot_count; s++) {
			cbor_enc_uint(&e, 0, s_ctx.gateways[i].slots[s]);
		}
	}

	k_mutex_unlock(&s_coord_lock);

	if (e.overflow) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT,
				   CBOR_CONTENT_FORMAT, resp_buf, e.off);
}

static int slots_post(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	const uint8_t *payload;
	uint16_t payload_len;

	payload = coap_packet_get_payload(request, &payload_len);
	if (payload == NULL || payload_len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST,
					   0, NULL, 0);
	}

	/* Decode claim */
	struct lichen_slot_claim claim;
	int ret = lichen_slot_coord_decode_claim(payload, payload_len, &claim);
	if (ret < 0) {
		LOG_WRN("Failed to decode slot claim: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST,
					   0, NULL, 0);
	}

	/* Process claim */
	struct lichen_slot_grant grant;
	enum lichen_claim_result result = lichen_slot_coord_process_claim(&s_ctx, &claim, &grant);

	if (result != LICHEN_CLAIM_ACCEPTED) {
		uint8_t code = COAP_RESPONSE_CODE_BAD_REQUEST;
		if (result == LICHEN_CLAIM_REJECT_CONFLICT) {
			code = COAP_RESPONSE_CODE_CONFLICT;
		}
		return lichen_coap_respond(resource, request, addr, addr_len,
					   code, 0, NULL, 0);
	}

	/* Encode grant response */
	static uint8_t resp_buf[128];
	ret = lichen_slot_coord_encode_grant(&grant, resp_buf, sizeof(resp_buf));
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CREATED,
				   CBOR_CONTENT_FORMAT, resp_buf, ret);
}

static int info_get(struct coap_resource *resource,
		    struct coap_packet *request,
		    struct sockaddr *addr, socklen_t addr_len)
{
	static uint8_t resp_buf[256];
	struct cbor_enc_ctx e;
	cbor_enc_init(&e, resp_buf, sizeof(resp_buf));

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	cbor_enc_map_header(&e, 6);

	cbor_enc_tstr(&e, KEY_GATEWAY_IID);
	cbor_enc_bstr(&e, s_ctx.local_iid, LICHEN_IID_LEN);

	cbor_enc_tstr(&e, KEY_SLOTS_TOTAL);
	cbor_enc_uint(&e, 0, s_ctx.superframe.slots_per_superframe);

	cbor_enc_tstr(&e, KEY_TIME_SOURCE);
	const char *ts_str;
	switch (s_ctx.superframe.time_source) {
	case LICHEN_TIME_SOURCE_GPS:      ts_str = "gps"; break;
	case LICHEN_TIME_SOURCE_BACKBONE: ts_str = "backbone"; break;
	case LICHEN_TIME_SOURCE_LOCAL:    ts_str = "local"; break;
	default:                          ts_str = "none"; break;
	}
	cbor_enc_tstr(&e, ts_str);

	cbor_enc_tstr(&e, KEY_ALLOCATED_SLOTS);
	cbor_enc_array_header(&e, s_ctx.local_slot_count);
	for (uint8_t i = 0; i < s_ctx.local_slot_count; i++) {
		cbor_enc_uint(&e, 0, s_ctx.local_slots[i]);
	}

	cbor_enc_tstr(&e, KEY_SUPERFRAME_EPOCH);
	cbor_enc_uint(&e, 0, s_ctx.superframe.epoch_unix);

	cbor_enc_tstr(&e, KEY_SUPERFRAME_DURATION);
	cbor_enc_uint(&e, 0, s_ctx.superframe.duration_s);

	k_mutex_unlock(&s_coord_lock);

	if (e.overflow) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT,
				   CBOR_CONTENT_FORMAT, resp_buf, e.off);
}

static int channels_get(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	static uint8_t resp_buf[128];
	struct cbor_enc_ctx e;
	cbor_enc_init(&e, resp_buf, sizeof(resp_buf));

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	/* Channel ownership map: channel_id (int) -> gateway IID (bstr) */
	uint8_t valid_count = 0;
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (s_ctx.gateways[i].valid) valid_count++;
	}

	cbor_enc_map_header(&e, valid_count);

	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!s_ctx.gateways[i].valid) continue;
		cbor_enc_uint(&e, 0, i); /* Channel ID = ordinal */
		cbor_enc_bstr(&e, s_ctx.gateways[i].iid, LICHEN_IID_LEN);
	}

	k_mutex_unlock(&s_coord_lock);

	if (e.overflow) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT,
				   CBOR_CONTENT_FORMAT, resp_buf, e.off);
}

/* Path: /.well-known/lichen-gw/info */
static const char * const info_path[] = {
	".well-known", "lichen-gw", "info", NULL
};

static const char * const info_attrs[] = {
	"rt=\"gcp.info\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_gw_info, lichen_coap_server, {
	.get = info_get,
	.path = info_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = info_attrs,
	}),
});

/* Path: /.well-known/lichen-gw/slots */
static const char * const slots_path[] = {
	".well-known", "lichen-gw", "slots", NULL
};

static const char * const slots_attrs[] = {
	"rt=\"gcp.slots\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_gw_slots, lichen_coap_server, {
	.get = slots_get,
	.post = slots_post,
	.path = slots_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = slots_attrs,
	}),
});

/* Path: /.well-known/lichen-gw/channels */
static const char * const channels_path[] = {
	".well-known", "lichen-gw", "channels", NULL
};

static const char * const channels_attrs[] = {
	"rt=\"gcp.channels\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_gw_channels, lichen_coap_server, {
	.get = channels_get,
	.path = channels_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = channels_attrs,
	}),
});

#endif /* CONFIG_LICHEN_COAP_SLOT_COORD_RESOURCE */
