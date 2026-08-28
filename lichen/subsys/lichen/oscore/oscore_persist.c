/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/oscore_persist.h>

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <monocypher.h>

#define OSCORE_PERSIST_MAGIC UINT32_C(0x50534f4c)
#define REVISION_OFFSET 8U
#define RECORD_COUNT_OFFSET 16U
#define FIRST_RECORD_OFFSET OSCORE_PERSIST_HEADER_LEN

static const uint8_t auth_context[] = "LICHEN-OSCORE-STATE-AUTH-v1";

static int callback_result(int ret)
{
	return ret > 0 ? -EIO : ret;
}

static void put_le32(uint8_t out[4], uint32_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> 8);
	out[2] = (uint8_t)(value >> 16);
	out[3] = (uint8_t)(value >> 24);
}

static uint32_t get_le32(const uint8_t in[4])
{
	return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
	       ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static void put_le64(uint8_t out[8], uint64_t value)
{
	for (size_t i = 0U; i < 8U; ++i) {
		out[i] = (uint8_t)(value >> (i * 8U));
	}
}

static uint64_t get_le64(const uint8_t in[8])
{
	uint64_t value = 0U;

	for (size_t i = 0U; i < 8U; ++i) {
		value |= (uint64_t)in[i] << (i * 8U);
	}
	return value;
}

static enum oscore_persist_blob_slot slot_for(uint64_t revision)
{
	return (revision & 1U) != 0U ? OSCORE_PERSIST_BLOB_B :
					      OSCORE_PERSIST_BLOB_A;
}

static void digest_blob(const uint8_t *blob, size_t length,
			uint8_t digest[OSCORE_PERSIST_TAG_LEN])
{
	crypto_blake2b(digest, OSCORE_PERSIST_TAG_LEN, blob, length);
}

static bool window_advances(bool old_initialized, uint64_t old_seq,
			    uint32_t old_window, bool new_initialized,
			    uint64_t new_seq, uint32_t new_window)
{
	if (!old_initialized) {
		return true;
	}
	if (!new_initialized || new_seq < old_seq) {
		return false;
	}
	if (new_seq == old_seq && (new_window & old_window) != old_window) {
		return false;
	}
	return true;
}

static bool state_advances(const struct oscore_persist_state *old,
			   const struct oscore_persist_state *next)
{
	if (old->sender_seq_valid &&
	    (!next->sender_seq_valid || next->sender_seq < old->sender_seq)) {
		return false;
	}
	return window_advances(old->recipient_window_initialized,
			       old->recipient_seq, old->replay_window,
			       next->recipient_window_initialized,
			       next->recipient_seq, next->replay_window) &&
	       window_advances(old->response_piv_window_initialized,
			       old->response_piv_seq, old->response_piv_window,
			       next->response_piv_window_initialized,
			       next->response_piv_seq,
			       next->response_piv_window) &&
	       window_advances(old->received_response_window_initialized,
			       old->received_response_seq,
			       old->received_response_window,
			       next->received_response_window_initialized,
			       next->received_response_seq,
			       next->received_response_window) &&
	       window_advances(old->sent_response_window_initialized,
			       old->sent_response_seq,
			       old->sent_response_window,
			       next->sent_response_window_initialized,
			       next->sent_response_seq,
			       next->sent_response_window);
}

static void encode_state(uint8_t out[64],
			 const struct oscore_persist_state *state)
{
	uint8_t flags = 0U;

	memset(out, 0, 64U);
	put_le64(&out[0], state->sender_seq);
	put_le64(&out[8], state->recipient_seq);
	put_le64(&out[16], state->response_piv_seq);
	put_le64(&out[24], state->received_response_seq);
	put_le64(&out[32], state->sent_response_seq);
	put_le32(&out[40], state->replay_window);
	put_le32(&out[44], state->response_piv_window);
	put_le32(&out[48], state->received_response_window);
	put_le32(&out[52], state->sent_response_window);
	flags |= state->sender_seq_valid ? BIT(0) : 0U;
	flags |= state->recipient_window_initialized ? BIT(1) : 0U;
	flags |= state->response_piv_window_initialized ? BIT(2) : 0U;
	flags |= state->received_response_window_initialized ? BIT(3) : 0U;
	flags |= state->sent_response_window_initialized ? BIT(4) : 0U;
	out[56] = flags;
}

static int decode_state(const uint8_t in[64], struct oscore_persist_state *state)
{
	if ((in[56] & 0xe0U) != 0U) {
		return -EBADMSG;
	}
	for (size_t i = 57U; i < 64U; ++i) {
		if (in[i] != 0U) {
			return -EBADMSG;
		}
	}
	memset(state, 0, sizeof(*state));
	state->sender_seq = get_le64(&in[0]);
	state->recipient_seq = get_le64(&in[8]);
	state->response_piv_seq = get_le64(&in[16]);
	state->received_response_seq = get_le64(&in[24]);
	state->sent_response_seq = get_le64(&in[32]);
	state->replay_window = get_le32(&in[40]);
	state->response_piv_window = get_le32(&in[44]);
	state->received_response_window = get_le32(&in[48]);
	state->sent_response_window = get_le32(&in[52]);
	state->sender_seq_valid = (in[56] & BIT(0)) != 0U;
	state->recipient_window_initialized = (in[56] & BIT(1)) != 0U;
	state->response_piv_window_initialized = (in[56] & BIT(2)) != 0U;
	state->received_response_window_initialized = (in[56] & BIT(3)) != 0U;
	state->sent_response_window_initialized = (in[56] & BIT(4)) != 0U;
	return 0;
}

static size_t encode_blob(struct oscore_persist *ctx, uint64_t revision)
{
	size_t offset = FIRST_RECORD_OFFSET;
	uint8_t count = 0U;

	memset(ctx->blob, 0, sizeof(ctx->blob));
	put_le32(ctx->blob, OSCORE_PERSIST_MAGIC);
	ctx->blob[4] = OSCORE_PERSIST_FORMAT_VERSION;
	put_le64(&ctx->blob[REVISION_OFFSET], revision);
	for (size_t i = 0U; i < CONFIG_LICHEN_OSCORE_MAX_CONTEXTS; ++i) {
		if (!ctx->records[i].active) {
			continue;
		}
		memcpy(&ctx->blob[offset], ctx->records[i].binding,
		       OSCORE_PERSIST_BINDING_LEN);
		encode_state(&ctx->blob[offset + OSCORE_PERSIST_BINDING_LEN],
			     &ctx->records[i].state);
		offset += OSCORE_PERSIST_RECORD_LEN;
		++count;
	}
	ctx->blob[RECORD_COUNT_OFFSET] = count;
	crypto_blake2b_keyed(&ctx->blob[offset], OSCORE_PERSIST_TAG_LEN,
			     ctx->auth_key, sizeof(ctx->auth_key), ctx->blob,
			     offset);
	return offset + OSCORE_PERSIST_TAG_LEN;
}

static int decode_blob(struct oscore_persist *ctx, size_t length,
		       uint64_t expected_revision)
{
	uint8_t expected_tag[OSCORE_PERSIST_TAG_LEN];
	uint8_t count;
	size_t prefix_len;

	if (length < OSCORE_PERSIST_HEADER_LEN + OSCORE_PERSIST_TAG_LEN) {
		return -EBADMSG;
	}
	count = ctx->blob[RECORD_COUNT_OFFSET];
	prefix_len = FIRST_RECORD_OFFSET +
		     ((size_t)count * OSCORE_PERSIST_RECORD_LEN);
	if (get_le32(ctx->blob) != OSCORE_PERSIST_MAGIC ||
	    ctx->blob[4] != OSCORE_PERSIST_FORMAT_VERSION ||
	    ctx->blob[5] != 0U || ctx->blob[6] != 0U || ctx->blob[7] != 0U ||
	    get_le64(&ctx->blob[REVISION_OFFSET]) != expected_revision ||
	    count > CONFIG_LICHEN_OSCORE_MAX_CONTEXTS ||
	    prefix_len + OSCORE_PERSIST_TAG_LEN != length) {
		return -EBADMSG;
	}
	for (size_t i = 17U; i < OSCORE_PERSIST_HEADER_LEN; ++i) {
		if (ctx->blob[i] != 0U) {
			return -EBADMSG;
		}
	}
	crypto_blake2b_keyed(expected_tag, sizeof(expected_tag), ctx->auth_key,
			     sizeof(ctx->auth_key), ctx->blob, prefix_len);
	if (crypto_verify32(expected_tag, &ctx->blob[prefix_len]) != 0) {
		crypto_wipe(expected_tag, sizeof(expected_tag));
		return -EKEYREJECTED;
	}
	crypto_wipe(expected_tag, sizeof(expected_tag));
	memset(ctx->records, 0, sizeof(ctx->records));
	for (size_t i = 0U, offset = FIRST_RECORD_OFFSET; i < count;
	     ++i, offset += OSCORE_PERSIST_RECORD_LEN) {
		struct oscore_persist_record *record = &ctx->records[i];
		int ret;

		for (size_t prior = 0U; prior < i; ++prior) {
			if (crypto_verify32(ctx->records[prior].binding,
					    &ctx->blob[offset]) == 0) {
				return -EBADMSG;
			}
		}
		memcpy(record->binding, &ctx->blob[offset],
		       OSCORE_PERSIST_BINDING_LEN);
		ret = decode_state(&ctx->blob[offset + OSCORE_PERSIST_BINDING_LEN],
				   &record->state);
		if (ret != 0) {
			return ret;
		}
		record->active = true;
	}
	return 0;
}

static int load_slot(struct oscore_persist *ctx,
		     enum oscore_persist_blob_slot slot, size_t *length)
{
	int ret;

	*length = 0U;
	ret = callback_result(ctx->store_ops->load(ctx->store_user, slot,
						 ctx->blob, sizeof(ctx->blob), length));
	if (ret == 0 && *length > sizeof(ctx->blob)) {
		return -EOVERFLOW;
	}
	return ret;
}

static int persist_locked(struct oscore_persist *ctx, bool virgin)
{
	struct oscore_persist_authority_state next = {0};
	const struct oscore_persist_authority_state *expected =
		virgin ? NULL : &ctx->authority;
	size_t length;
	int ret;

	if ((!virgin && ctx->authority.revision == UINT64_MAX) ||
	    (virgin && ctx->authority.revision != 0U)) {
		return -EOVERFLOW;
	}
	next.revision = virgin ? 1U : ctx->authority.revision + 1U;
	length = encode_blob(ctx, next.revision);
	digest_blob(ctx->blob, length, next.digest);
	ret = callback_result(ctx->store_ops->save(ctx->store_user,
						 slot_for(next.revision),
						 ctx->blob, length));
	if (ret == 0) {
		ret = callback_result(ctx->protection_ops->commit(
			ctx->protection_user, expected, &next));
	}
	if (ret == 0) {
		ctx->authority = next;
	}
	crypto_wipe(&next, sizeof(next));
	crypto_wipe(ctx->blob, sizeof(ctx->blob));
	return ret;
}

static int find_record(const struct oscore_persist *ctx,
		       const uint8_t binding[OSCORE_PERSIST_BINDING_LEN],
		       size_t *free_slot)
{
	*free_slot = CONFIG_LICHEN_OSCORE_MAX_CONTEXTS;
	for (size_t i = 0U; i < CONFIG_LICHEN_OSCORE_MAX_CONTEXTS; ++i) {
		if (ctx->records[i].active) {
			if (crypto_verify32(ctx->records[i].binding, binding) == 0) {
				return (int)i;
			}
		} else if (*free_slot == CONFIG_LICHEN_OSCORE_MAX_CONTEXTS) {
			*free_slot = i;
		}
	}
	return -ENOENT;
}

int oscore_persist_open(
	struct oscore_persist *ctx,
	const struct oscore_persist_store_ops *store_ops, void *store_user,
	const struct oscore_persist_protection_ops *protection_ops,
	void *protection_user)
{
	struct oscore_persist_authority_state authority = {0};
	uint8_t digest[OSCORE_PERSIST_TAG_LEN] = {0};
	size_t length = 0U;
	int ret;
	int a_ret;
	int b_ret;

	if (ctx == NULL || store_ops == NULL || store_ops->load == NULL ||
	    store_ops->save == NULL || protection_ops == NULL ||
	    protection_ops->derive_key == NULL || protection_ops->load == NULL ||
	    protection_ops->commit == NULL) {
		return -EINVAL;
	}
	memset(ctx, 0, sizeof(*ctx));
	k_mutex_init(&ctx->lock);
	ctx->store_ops = store_ops;
	ctx->store_user = store_user;
	ctx->protection_ops = protection_ops;
	ctx->protection_user = protection_user;
	ret = callback_result(protection_ops->derive_key(
		protection_user, auth_context, sizeof(auth_context) - 1U,
		ctx->auth_key));
	if (ret != 0) {
		goto fail;
	}
	ret = callback_result(protection_ops->load(protection_user, &authority));
	if (ret == -ENOENT) {
		a_ret = load_slot(ctx, OSCORE_PERSIST_BLOB_A, &length);
		b_ret = load_slot(ctx, OSCORE_PERSIST_BLOB_B, &length);
		if (a_ret != -ENOENT || b_ret != -ENOENT) {
			ret = a_ret != -ENOENT && a_ret != 0 ? a_ret :
			      b_ret != -ENOENT && b_ret != 0 ? b_ret : -EBADMSG;
			goto fail;
		}
		ret = persist_locked(ctx, true);
	} else if (ret == 0) {
		if (authority.revision == 0U) {
			ret = -EBADMSG;
			goto fail;
		}
		ctx->authority = authority;
		ret = load_slot(ctx, slot_for(authority.revision), &length);
		if (ret == -ENOENT) {
			ret = -EBADMSG;
		}
		if (ret != 0) {
			goto fail;
		}
		digest_blob(ctx->blob, length, digest);
		if (crypto_verify32(digest, authority.digest) != 0) {
			ret = -ESTALE;
			goto fail;
		}
		ret = decode_blob(ctx, length, authority.revision);
	} else {
		goto fail;
	}
	if (ret != 0) {
		goto fail;
	}
	ctx->ready = true;
	crypto_wipe(ctx->blob, sizeof(ctx->blob));
	crypto_wipe(&authority, sizeof(authority));
	crypto_wipe(digest, sizeof(digest));
	return 0;

fail:
	crypto_wipe(&authority, sizeof(authority));
	crypto_wipe(digest, sizeof(digest));
	oscore_persist_close(ctx);
	return ret;
}

int oscore_persist_restore(
	struct oscore_persist *ctx,
	const uint8_t binding[OSCORE_PERSIST_BINDING_LEN],
	struct oscore_persist_state *state)
{
	size_t free_slot;
	int index;
	int ret = 0;

	if (ctx == NULL || binding == NULL || state == NULL || !ctx->ready) {
		return -EINVAL;
	}
	k_mutex_lock(&ctx->lock, K_FOREVER);
	index = find_record(ctx, binding, &free_slot);
	if (index < 0) {
		ret = -ENOENT;
	} else {
		*state = ctx->records[index].state;
	}
	k_mutex_unlock(&ctx->lock);
	return ret;
}

int oscore_persist_commit(
	struct oscore_persist *ctx,
	const uint8_t binding[OSCORE_PERSIST_BINDING_LEN],
	const struct oscore_persist_state *state)
{
	struct oscore_persist_record old = {0};
	size_t free_slot;
	int index;
	int ret;

	if (ctx == NULL || binding == NULL || state == NULL || !ctx->ready) {
		return -EINVAL;
	}
	k_mutex_lock(&ctx->lock, K_FOREVER);
	index = find_record(ctx, binding, &free_slot);
	if (index < 0) {
		if (free_slot == CONFIG_LICHEN_OSCORE_MAX_CONTEXTS) {
			ret = -ENOSPC;
			goto done;
		}
		index = (int)free_slot;
	} else if (!state_advances(&ctx->records[index].state, state)) {
		ret = -ESTALE;
		goto done;
	}
	old = ctx->records[index];
	memcpy(ctx->records[index].binding, binding,
	       OSCORE_PERSIST_BINDING_LEN);
	ctx->records[index].state = *state;
	ctx->records[index].active = true;
	ret = persist_locked(ctx, false);
	if (ret != 0) {
		ctx->records[index] = old;
	}

done:
	k_mutex_unlock(&ctx->lock);
	crypto_wipe(&old, sizeof(old));
	return ret;
}

void oscore_persist_close(struct oscore_persist *ctx)
{
	if (ctx == NULL) {
		return;
	}
	crypto_wipe(ctx->auth_key, sizeof(ctx->auth_key));
	crypto_wipe(ctx->blob, sizeof(ctx->blob));
	crypto_wipe(ctx->records, sizeof(ctx->records));
	crypto_wipe(&ctx->authority, sizeof(ctx->authority));
	ctx->ready = false;
}
