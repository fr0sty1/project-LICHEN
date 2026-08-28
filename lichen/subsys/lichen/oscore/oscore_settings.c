/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/oscore_persist.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

#include <monocypher.h>

#include "oscore_internal.h"

#define SETTINGS_ROOT "lichen/oscore"
#define SETTINGS_SLOT_A SETTINGS_ROOT "/a"
#define SETTINGS_SLOT_B SETTINGS_ROOT "/b"

struct staged_slot {
	uint8_t value[OSCORE_PERSIST_BLOB_MAX];
	size_t length;
	bool present;
};

static struct staged_slot s_slots[2];
static struct oscore_persist s_persistence;
static const struct oscore_persist_protection_ops *s_protection_ops;
static void *s_protection_user;
static bool s_registration_attempted;
static K_MUTEX_DEFINE(s_settings_lock);

static int oscore_settings_set(const char *name, size_t len,
			       settings_read_cb read_cb, void *cb_arg)
{
	const char *next;
	enum oscore_persist_blob_slot slot;
	bool is_slot_a;
	bool is_slot_b;
	ssize_t ret;

	is_slot_a = settings_name_steq(name, "a", &next) && next == NULL;
	is_slot_b = settings_name_steq(name, "b", &next) && next == NULL;
	if (!is_slot_a && !is_slot_b) {
		return -ENOENT;
	}
	slot = is_slot_a ? OSCORE_PERSIST_BLOB_A : OSCORE_PERSIST_BLOB_B;
	if (len == 0U || len > sizeof(s_slots[slot].value)) {
		return -EOVERFLOW;
	}
	ret = read_cb(cb_arg, s_slots[slot].value, len);
	if (ret < 0) {
		return (int)ret;
	}
	if ((size_t)ret != len) {
		return -EBADMSG;
	}
	s_slots[slot].length = len;
	s_slots[slot].present = true;
	return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(lichen_oscore, SETTINGS_ROOT, NULL,
			      oscore_settings_set, NULL, NULL);

static int store_load(void *user, enum oscore_persist_blob_slot slot,
		      uint8_t *out, size_t capacity, size_t *length)
{
	ARG_UNUSED(user);
	if (slot > OSCORE_PERSIST_BLOB_B || !s_slots[slot].present) {
		return -ENOENT;
	}
	if (capacity < s_slots[slot].length) {
		return -ENOSPC;
	}
	memcpy(out, s_slots[slot].value, s_slots[slot].length);
	*length = s_slots[slot].length;
	return 0;
}

static int store_save(void *user, enum oscore_persist_blob_slot slot,
		      const uint8_t *value, size_t length)
{
	const char *key;
	int ret;

	ARG_UNUSED(user);
	if (slot > OSCORE_PERSIST_BLOB_B || value == NULL || length == 0U ||
	    length > sizeof(s_slots[slot].value)) {
		return -EINVAL;
	}
	key = slot == OSCORE_PERSIST_BLOB_A ? SETTINGS_SLOT_A : SETTINGS_SLOT_B;
	ret = settings_save_one(key, value, length);
	if (ret == 0) {
		memcpy(s_slots[slot].value, value, length);
		s_slots[slot].length = length;
		s_slots[slot].present = true;
	}
	return ret;
}

static const struct oscore_persist_store_ops settings_store_ops = {
	.load = store_load,
	.save = store_save,
};

static void context_binding(const struct oscore_ctx *ctx,
			    uint8_t binding[OSCORE_PERSIST_BINDING_LEN])
{
	static const uint8_t domain[] = "LICHEN-OSCORE-CONTEXT-v1";
	uint8_t material[sizeof(domain) - 1U + 6U +
			 OSCORE_ID_MAX_LEN * 2U + OSCORE_ID_CONTEXT_MAX_LEN +
			 OSCORE_KEY_LEN * 2U + OSCORE_NONCE_LEN];
	size_t offset = 0U;

	memcpy(&material[offset], domain, sizeof(domain) - 1U);
	offset += sizeof(domain) - 1U;
	material[offset++] = ctx->sender_id_len;
	memcpy(&material[offset], ctx->sender_id, ctx->sender_id_len);
	offset += ctx->sender_id_len;
	material[offset++] = ctx->recipient_id_len;
	memcpy(&material[offset], ctx->recipient_id, ctx->recipient_id_len);
	offset += ctx->recipient_id_len;
	material[offset++] = ctx->has_id_context ? 1U : 0U;
	material[offset++] = ctx->id_context_len;
	memcpy(&material[offset], ctx->id_context, ctx->id_context_len);
	offset += ctx->id_context_len;
	material[offset++] = OSCORE_ALG_AEAD;
	material[offset++] = CONFIG_LICHEN_OSCORE_REPLAY_WINDOW;
	memcpy(&material[offset], ctx->sender_key, sizeof(ctx->sender_key));
	offset += sizeof(ctx->sender_key);
	memcpy(&material[offset], ctx->recipient_key, sizeof(ctx->recipient_key));
	offset += sizeof(ctx->recipient_key);
	memcpy(&material[offset], ctx->common_iv, sizeof(ctx->common_iv));
	offset += sizeof(ctx->common_iv);
	crypto_blake2b(binding, OSCORE_PERSIST_BINDING_LEN, material, offset);
	crypto_wipe(material, sizeof(material));
}

static void state_from_context(const struct oscore_ctx *ctx,
			       bool sender_seq_valid,
			       struct oscore_persist_state *state)
{
	*state = (struct oscore_persist_state) {
		.sender_seq = ctx->sender_seq,
		.recipient_seq = ctx->recipient_seq,
		.response_piv_seq = ctx->response_piv_seq,
		.received_response_seq = ctx->received_response_seq,
		.sent_response_seq = ctx->sent_response_seq,
		.replay_window = ctx->replay_window,
		.response_piv_window = ctx->response_piv_window,
		.received_response_window = ctx->received_response_window,
		.sent_response_window = ctx->sent_response_window,
		.sender_seq_valid = sender_seq_valid,
		.recipient_window_initialized = ctx->replay_window != 0U,
		.response_piv_window_initialized =
			ctx->response_piv_window_initialized,
		.received_response_window_initialized =
			ctx->received_response_window_initialized,
		.sent_response_window_initialized =
			ctx->sent_response_window_initialized,
	};
}

int oscore_settings_register_protection(
	const struct oscore_persist_protection_ops *ops, void *user)
{
	int ret;

	if (ops == NULL || ops->derive_key == NULL || ops->load == NULL ||
	    ops->commit == NULL) {
		return -EINVAL;
	}
	k_mutex_lock(&s_settings_lock, K_FOREVER);
	if (s_registration_attempted) {
		ret = s_persistence.ready && s_protection_ops == ops &&
		      s_protection_user == user ? 0 : -EALREADY;
		goto unlock;
	}
	s_registration_attempted = true;
	s_protection_ops = ops;
	s_protection_user = user;
	memset(s_slots, 0, sizeof(s_slots));
	ret = settings_subsys_init();
	if (ret == 0) {
		ret = settings_load_subtree(SETTINGS_ROOT);
	}
	if (ret == 0) {
		ret = oscore_persist_open(&s_persistence, &settings_store_ops, NULL,
					  ops, user);
	}

unlock:
	k_mutex_unlock(&s_settings_lock);
	return ret;
}

bool oscore_settings_ready(void)
{
	bool ready;

	k_mutex_lock(&s_settings_lock, K_FOREVER);
	ready = s_persistence.ready;
	k_mutex_unlock(&s_settings_lock);
	return ready;
}

int oscore_settings_restore_context_locked(struct oscore_ctx *ctx, int ctx_idx)
{
	struct oscore_persist_state state = {0};
	uint8_t binding[OSCORE_PERSIST_BINDING_LEN];
	int ret;

	if (ctx == NULL || ctx_idx < 0 ||
	    ctx_idx >= CONFIG_LICHEN_OSCORE_MAX_CONTEXTS) {
		return -EACCES;
	}
	k_mutex_lock(&s_settings_lock, K_FOREVER);
	if (!s_persistence.ready) {
		ret = -EACCES;
		goto out_unlock;
	}
	context_binding(ctx, binding);
	ret = oscore_persist_restore(&s_persistence, binding, &state);
	if (ret == -ENOENT) {
		ret = 0;
		goto out;
	}
	if (ret != 0 || state.sender_seq > OSCORE_SSN_MAX + 1U ||
	    state.recipient_seq > OSCORE_SSN_MAX ||
	    state.response_piv_seq > OSCORE_SSN_MAX ||
	    state.received_response_seq > OSCORE_SSN_MAX ||
	    state.sent_response_seq > OSCORE_SSN_MAX) {
		ret = ret != 0 ? ret : -EBADMSG;
		goto out;
	}
	ctx->sender_seq = state.sender_seq;
	ctx->recipient_seq = state.recipient_seq;
	ctx->replay_window = state.replay_window;
	ctx->response_piv_seq = state.response_piv_seq;
	ctx->response_piv_window = state.response_piv_window;
	ctx->received_response_seq = state.received_response_seq;
	ctx->received_response_window = state.received_response_window;
	ctx->sent_response_seq = state.sent_response_seq;
	ctx->sent_response_window = state.sent_response_window;
	ctx->response_piv_window_initialized =
		state.response_piv_window_initialized;
	ctx->received_response_window_initialized =
		state.received_response_window_initialized;
	ctx->sent_response_window_initialized =
		state.sent_response_window_initialized;
	s_seq_initialized[ctx_idx] = state.sender_seq_valid;

out:
	crypto_wipe(binding, sizeof(binding));
	crypto_wipe(&state, sizeof(state));
out_unlock:
	k_mutex_unlock(&s_settings_lock);
	return ret;
}

int oscore_settings_commit_context_locked(const struct oscore_ctx *ctx,
					  bool sender_seq_valid)
{
	struct oscore_persist_state state;
	uint8_t binding[OSCORE_PERSIST_BINDING_LEN];
	int ret;

	if (ctx == NULL) {
		return -EACCES;
	}
	k_mutex_lock(&s_settings_lock, K_FOREVER);
	if (!s_persistence.ready) {
		ret = -EACCES;
		goto out_unlock;
	}
	context_binding(ctx, binding);
	state_from_context(ctx, sender_seq_valid, &state);
	ret = oscore_persist_commit(&s_persistence, binding, &state);
	crypto_wipe(binding, sizeof(binding));
	crypto_wipe(&state, sizeof(state));
out_unlock:
	k_mutex_unlock(&s_settings_lock);
	return ret;
}

void oscore_settings_close(void)
{
	k_mutex_lock(&s_settings_lock, K_FOREVER);
	oscore_persist_close(&s_persistence);
	s_protection_ops = NULL;
	s_protection_user = NULL;
	s_registration_attempted = false;
	memset(s_slots, 0, sizeof(s_slots));
	k_mutex_unlock(&s_settings_lock);
}
