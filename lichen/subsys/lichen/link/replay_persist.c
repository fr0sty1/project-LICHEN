/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/replay_persist.h>

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <monocypher.h>

#define REPLAY_MAGIC UINT32_C(0x50524c4c)
#define HEADER_LEN 52U
#define PEER_LEN 36U
#define REVISION_OFFSET 8U
#define LOCAL_KEY_OFFSET 16U
#define TX_EPOCH_OFFSET 48U
#define PEER_COUNT_OFFSET 49U
#define FIRST_PEER_OFFSET HEADER_LEN

static const uint8_t auth_context[] = "LICHEN-LINK-REPLAY-AUTH-v1";

static void put_le16(uint8_t out[2], uint16_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> 8);
}

static uint16_t get_le16(const uint8_t in[2])
{
	return (uint16_t)in[0] | ((uint16_t)in[1] << 8);
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
		out[i] = (uint8_t)(value >> (8U * i));
	}
}

static uint64_t get_le64(const uint8_t in[8])
{
	uint64_t value = 0U;

	for (size_t i = 0U; i < 8U; ++i) {
		value |= (uint64_t)in[i] << (8U * i);
	}
	return value;
}

static int callback_result(int ret)
{
	return ret > 0 ? -EIO : ret;
}

static enum lichen_replay_blob_slot slot_for(uint64_t revision)
{
	return (revision & 1U) != 0U ? LICHEN_REPLAY_BLOB_B :
				      LICHEN_REPLAY_BLOB_A;
}

static void digest_blob(const uint8_t *blob, size_t length,
			uint8_t out[LICHEN_REPLAY_PERSIST_TAG_LEN])
{
	crypto_blake2b(out, LICHEN_REPLAY_PERSIST_TAG_LEN, blob, length);
}

static size_t encode_blob(struct lichen_replay_persist *ctx, uint64_t revision)
{
	uint8_t count = 0U;
	size_t offset = FIRST_PEER_OFFSET;

	memset(ctx->blob, 0, sizeof(ctx->blob));
	put_le32(ctx->blob, REPLAY_MAGIC);
	ctx->blob[4] = LICHEN_REPLAY_PERSIST_FORMAT_VERSION;
	put_le64(&ctx->blob[REVISION_OFFSET], revision);
	memcpy(&ctx->blob[LOCAL_KEY_OFFSET], ctx->local_public_key,
	       LICHEN_PK_LEN);
	ctx->blob[TX_EPOCH_OFFSET] = ctx->tx_epoch;
	for (size_t i = 0U; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; ++i) {
		const struct lichen_replay_floor *floor = &ctx->floors[i];

		if (!floor->active) {
			continue;
		}
		memcpy(&ctx->blob[offset], floor->public_key, LICHEN_PK_LEN);
		ctx->blob[offset + 32U] = floor->epoch;
		put_le16(&ctx->blob[offset + 33U], floor->seq_floor);
		offset += PEER_LEN;
		++count;
	}
	ctx->blob[PEER_COUNT_OFFSET] = count;
	crypto_blake2b_keyed(&ctx->blob[offset], LICHEN_REPLAY_PERSIST_TAG_LEN,
			     ctx->auth_key, sizeof(ctx->auth_key), ctx->blob,
			     offset);
	return offset + LICHEN_REPLAY_PERSIST_TAG_LEN;
}

static int decode_blob(struct lichen_replay_persist *ctx, size_t length,
		       uint64_t expected_revision)
{
	uint8_t expected_tag[LICHEN_REPLAY_PERSIST_TAG_LEN];
	uint8_t count;
	size_t prefix_len;

	if (length < HEADER_LEN + LICHEN_REPLAY_PERSIST_TAG_LEN) {
		return -EBADMSG;
	}
	count = ctx->blob[PEER_COUNT_OFFSET];
	prefix_len = FIRST_PEER_OFFSET + ((size_t)count * PEER_LEN);
	if (get_le32(ctx->blob) != REPLAY_MAGIC ||
	    ctx->blob[4] != LICHEN_REPLAY_PERSIST_FORMAT_VERSION ||
	    ctx->blob[5] != 0U || ctx->blob[6] != 0U || ctx->blob[7] != 0U ||
	    ctx->blob[50] != 0U || ctx->blob[51] != 0U ||
	    count > CONFIG_LICHEN_LINK_MAX_NEIGHBORS ||
	    prefix_len + LICHEN_REPLAY_PERSIST_TAG_LEN != length ||
	    get_le64(&ctx->blob[REVISION_OFFSET]) != expected_revision ||
	    ctx->blob[TX_EPOCH_OFFSET] < 128U) {
		return -EBADMSG;
	}
	if (crypto_verify32(&ctx->blob[LOCAL_KEY_OFFSET],
			    ctx->local_public_key) != 0) {
		return -EKEYREJECTED;
	}
	crypto_blake2b_keyed(expected_tag, sizeof(expected_tag), ctx->auth_key,
			     sizeof(ctx->auth_key), ctx->blob, prefix_len);
	if (crypto_verify32(expected_tag, &ctx->blob[prefix_len]) != 0) {
		crypto_wipe(expected_tag, sizeof(expected_tag));
		return -EKEYREJECTED;
	}
	crypto_wipe(expected_tag, sizeof(expected_tag));
	memset(ctx->floors, 0, sizeof(ctx->floors));
	lichen_replay_table_init(ctx->table);
	for (size_t i = 0U, offset = FIRST_PEER_OFFSET; i < count;
	     ++i, offset += PEER_LEN) {
		struct lichen_replay_floor *floor = &ctx->floors[i];
		struct lichen_replay_entry *entry = &ctx->table->peers[i];

		if (ctx->blob[offset + 35U] != 0U) {
			return -EBADMSG;
		}
		for (size_t prior = 0U; prior < i; ++prior) {
			if (crypto_verify32(ctx->floors[prior].public_key,
					    &ctx->blob[offset]) == 0) {
				return -EBADMSG;
			}
		}
		memcpy(floor->public_key, &ctx->blob[offset], LICHEN_PK_LEN);
		floor->epoch = ctx->blob[offset + 32U];
		floor->seq_floor = get_le16(&ctx->blob[offset + 33U]);
		floor->active = true;
		memcpy(entry->public_key, floor->public_key, LICHEN_PK_LEN);
		entry->window.epoch = floor->epoch;
		entry->window.last_seq = floor->seq_floor;
		entry->window.bitmap = UINT32_MAX;
		entry->window.initialised = true;
		entry->active = true;
	}
	ctx->tx_epoch = ctx->blob[TX_EPOCH_OFFSET];
	return 0;
}

static int persist_locked(struct lichen_replay_persist *ctx, bool virgin)
{
	struct lichen_replay_authority_state next = {0};
	const struct lichen_replay_authority_state *expected =
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
						 slot_for(next.revision), ctx->blob,
						 length));
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

static int load_slot(struct lichen_replay_persist *ctx,
		     enum lichen_replay_blob_slot slot, size_t *length)
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

static int find_floor(const struct lichen_replay_persist *ctx,
		      const uint8_t public_key[LICHEN_PK_LEN], size_t *free_slot)
{
	*free_slot = CONFIG_LICHEN_LINK_MAX_NEIGHBORS;
	for (size_t i = 0U; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; ++i) {
		if (ctx->floors[i].active) {
			if (crypto_verify32(ctx->floors[i].public_key, public_key) == 0) {
				return (int)i;
			}
		} else if (*free_slot == CONFIG_LICHEN_LINK_MAX_NEIGHBORS) {
			*free_slot = i;
		}
	}
	return -ENOENT;
}

static int persistent_commit(void *user, struct lichen_replay_table *table,
			     const uint8_t public_key[LICHEN_PK_LEN],
			     uint8_t epoch, uint16_t seq)
{
	struct lichen_replay_persist *ctx = user;
	struct lichen_replay_window candidate;
	struct lichen_replay_window *live = NULL;
	struct lichen_replay_floor old_floor = {0};
	size_t free_slot;
	int floor_index;
	int ret = 0;
	bool must_persist = false;

	if (ctx == NULL || table != ctx->table || !ctx->ready) {
		return -EACCES;
	}
	k_mutex_lock(&ctx->lock, K_FOREVER);
	floor_index = find_floor(ctx, public_key, &free_slot);
	for (size_t i = 0U; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; ++i) {
		if (table->peers[i].active &&
		    crypto_verify32(table->peers[i].public_key, public_key) == 0) {
			live = &table->peers[i].window;
			break;
		}
	}
	if (live != NULL) {
		candidate = *live;
	} else {
		lichen_replay_init(&candidate);
	}
	if (!lichen_replay_check(&candidate, epoch, seq)) {
		ret = -EALREADY;
		goto done;
	}
	if (floor_index < 0) {
		if (free_slot == CONFIG_LICHEN_LINK_MAX_NEIGHBORS) {
			ret = -ENOSPC;
			goto done;
		}
		floor_index = (int)free_slot;
		must_persist = true;
	} else {
		const struct lichen_replay_floor *floor = &ctx->floors[floor_index];

		must_persist = epoch > floor->epoch ||
			(epoch == floor->epoch && seq > floor->seq_floor);
	}
	if (must_persist) {
		struct lichen_replay_floor *floor = &ctx->floors[floor_index];
		const uint32_t reserved = (uint32_t)seq + 31U;

		old_floor = *floor;
		memcpy(floor->public_key, public_key, LICHEN_PK_LEN);
		floor->epoch = epoch;
		floor->seq_floor = reserved > UINT16_MAX ? UINT16_MAX :
							      (uint16_t)reserved;
		floor->active = true;
		ret = persist_locked(ctx, false);
		if (ret != 0) {
			*floor = old_floor;
			goto done;
		}
	}
	if (live != NULL) {
		*live = candidate;
	} else {
		struct lichen_replay_window *created =
			lichen_replay_get(table, public_key);

		if (created == NULL) {
			ret = -EFAULT;
			goto done;
		}
		*created = candidate;
	}

done:
	k_mutex_unlock(&ctx->lock);
	crypto_wipe(&old_floor, sizeof(old_floor));
	return ret;
}

static int persistent_remove(void *user, struct lichen_replay_table *table,
			     const uint8_t public_key[LICHEN_PK_LEN])
{
	struct lichen_replay_persist *ctx = user;
	struct lichen_replay_floor old_floor = {0};
	size_t free_slot;
	int index;
	int ret = 0;

	if (ctx == NULL || table != ctx->table || !ctx->ready) {
		return -EACCES;
	}
	k_mutex_lock(&ctx->lock, K_FOREVER);
	index = find_floor(ctx, public_key, &free_slot);
	if (index < 0) {
		goto done;
	}
	old_floor = ctx->floors[index];
	memset(&ctx->floors[index], 0, sizeof(ctx->floors[index]));
	ret = persist_locked(ctx, false);
	if (ret != 0) {
		ctx->floors[index] = old_floor;
		goto done;
	}
	for (size_t i = 0U; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; ++i) {
		if (table->peers[i].active &&
		    crypto_verify32(table->peers[i].public_key, public_key) == 0) {
			memset(&table->peers[i], 0, sizeof(table->peers[i]));
			break;
		}
	}

done:
	k_mutex_unlock(&ctx->lock);
	crypto_wipe(&old_floor, sizeof(old_floor));
	return ret;
}

static const struct lichen_replay_backend persistent_backend = {
	.commit = persistent_commit,
	.remove = persistent_remove,
};

int lichen_replay_persist_open(
	struct lichen_replay_persist *ctx, struct lichen_replay_table *table,
	const uint8_t local_public_key[LICHEN_PK_LEN], uint8_t fallback_epoch,
	const struct lichen_replay_store_ops *store_ops, void *store_user,
	const struct lichen_replay_protection_ops *protection_ops,
	void *protection_user, uint8_t *boot_epoch)
{
	struct lichen_replay_authority_state authority = {0};
	uint8_t digest[LICHEN_REPLAY_PERSIST_TAG_LEN] = {0};
	size_t length = 0U;
	int ret;
	int a_ret;
	int b_ret;

	if (ctx == NULL || table == NULL || local_public_key == NULL ||
	    boot_epoch == NULL || fallback_epoch < 128U || store_ops == NULL ||
	    store_ops->load == NULL || store_ops->save == NULL ||
	    protection_ops == NULL || protection_ops->derive_key == NULL ||
	    protection_ops->load == NULL || protection_ops->commit == NULL) {
		return -EINVAL;
	}
	memset(ctx, 0, sizeof(*ctx));
	k_mutex_init(&ctx->lock);
	ctx->table = table;
	ctx->store_ops = store_ops;
	ctx->store_user = store_user;
	ctx->protection_ops = protection_ops;
	ctx->protection_user = protection_user;
	memcpy(ctx->local_public_key, local_public_key, LICHEN_PK_LEN);
	ret = callback_result(protection_ops->derive_key(
		protection_user, auth_context, sizeof(auth_context) - 1U,
		ctx->auth_key));
	if (ret != 0) {
		goto fail;
	}
	ret = callback_result(protection_ops->load(protection_user, &authority));
	if (ret == -ENOENT) {
		a_ret = load_slot(ctx, LICHEN_REPLAY_BLOB_A, &length);
		b_ret = load_slot(ctx, LICHEN_REPLAY_BLOB_B, &length);
		if (a_ret != -ENOENT || b_ret != -ENOENT) {
			ret = a_ret != -ENOENT && a_ret != 0 ? a_ret :
			      b_ret != -ENOENT && b_ret != 0 ? b_ret : -EBADMSG;
			goto fail;
		}
		lichen_replay_table_init(table);
		ctx->tx_epoch = fallback_epoch;
		ret = persist_locked(ctx, true);
		if (ret != 0) {
			goto fail;
		}
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
		if (ret != 0) {
			goto fail;
		}
		if (ctx->tx_epoch == UINT8_MAX) {
			ret = -EOVERFLOW;
			goto fail;
		}
		++ctx->tx_epoch;
		ret = persist_locked(ctx, false);
		if (ret != 0) {
			--ctx->tx_epoch;
			goto fail;
		}
	} else {
		goto fail;
	}
	ctx->ready = true;
	table->backend = &persistent_backend;
	table->backend_user = ctx;
	*boot_epoch = ctx->tx_epoch;
	crypto_wipe(ctx->blob, sizeof(ctx->blob));
	crypto_wipe(&authority, sizeof(authority));
	crypto_wipe(digest, sizeof(digest));
	return 0;

fail:
	lichen_replay_table_init(table);
	crypto_wipe(&authority, sizeof(authority));
	crypto_wipe(digest, sizeof(digest));
	lichen_replay_persist_close(ctx);
	return ret;
}

int lichen_replay_persist_reserve_tx_epoch(
	struct lichen_replay_persist *ctx, uint8_t current_epoch,
	uint8_t *next_epoch)
{
	int ret;

	if (ctx == NULL || next_epoch == NULL || !ctx->ready) {
		return -EINVAL;
	}
	k_mutex_lock(&ctx->lock, K_FOREVER);
	if (current_epoch != ctx->tx_epoch) {
		ret = -ESTALE;
	} else if (current_epoch == UINT8_MAX) {
		ret = -EOVERFLOW;
	} else {
		++ctx->tx_epoch;
		ret = persist_locked(ctx, false);
		if (ret == 0) {
			*next_epoch = ctx->tx_epoch;
		} else {
			--ctx->tx_epoch;
		}
	}
	k_mutex_unlock(&ctx->lock);
	return ret;
}

void lichen_replay_persist_close(struct lichen_replay_persist *ctx)
{
	if (ctx == NULL) {
		return;
	}
	if (ctx->table != NULL && ctx->table->backend_user == ctx) {
		ctx->table->backend = NULL;
		ctx->table->backend_user = NULL;
	}
	crypto_wipe(ctx->auth_key, sizeof(ctx->auth_key));
	crypto_wipe(ctx->blob, sizeof(ctx->blob));
	crypto_wipe(ctx->floors, sizeof(ctx->floors));
	crypto_wipe(ctx->local_public_key, sizeof(ctx->local_public_key));
	crypto_wipe(&ctx->authority, sizeof(ctx->authority));
	ctx->ready = false;
}
