/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/settings/settings.h>
#include <zephyr/ztest.h>

#include <lichen/oscore.h>
#include <lichen/oscore_persist.h>

struct memory_item {
	char name[24];
	uint8_t value[OSCORE_PERSIST_BLOB_MAX];
	size_t length;
	bool present;
};

struct memory_settings {
	struct settings_store store;
	struct memory_item items[2];
};

struct mock_authority {
	bool present;
	struct oscore_persist_authority_state state;
	uint8_t root_key[32];
	int load_error;
	int commit_error;
	unsigned commits;
};

static struct memory_settings memory_store;
static struct mock_authority authority;

struct core_backend {
	uint8_t slots[2][OSCORE_PERSIST_BLOB_MAX];
	size_t lengths[2];
	struct mock_authority authority;
	int load_error;
	int save_error;
};

static struct core_backend core;
static struct oscore_persist core_persistence;

static int core_load(void *user, enum oscore_persist_blob_slot slot,
		     uint8_t *out, size_t capacity, size_t *length)
{
	struct core_backend *backend = user;

	if (backend->load_error != 0) {
		return backend->load_error;
	}
	if (backend->lengths[slot] == 0U) {
		return -ENOENT;
	}
	if (capacity < backend->lengths[slot]) {
		return -ENOSPC;
	}
	memcpy(out, backend->slots[slot], backend->lengths[slot]);
	*length = backend->lengths[slot];
	return 0;
}

static int core_save(void *user, enum oscore_persist_blob_slot slot,
		     const uint8_t *value, size_t length)
{
	struct core_backend *backend = user;

	if (backend->save_error != 0) {
		return backend->save_error;
	}
	if (length > sizeof(backend->slots[slot])) {
		return -ENOSPC;
	}
	memcpy(backend->slots[slot], value, length);
	backend->lengths[slot] = length;
	return 0;
}

static const struct oscore_persist_store_ops core_store_ops = {
	.load = core_load,
	.save = core_save,
};

static ssize_t memory_read(void *arg, void *data, size_t len)
{
	struct memory_item *item = arg;
	size_t copied = MIN(len, item->length);

	memcpy(data, item->value, copied);
	return (ssize_t)copied;
}

static int memory_load(struct settings_store *store,
		       const struct settings_load_arg *arg)
{
	struct memory_settings *backend =
		CONTAINER_OF(store, struct memory_settings, store);

	for (size_t i = 0U; i < ARRAY_SIZE(backend->items); ++i) {
		struct memory_item *item = &backend->items[i];

		if (item->present) {
			int ret = settings_call_set_handler(item->name, item->length,
						    memory_read, item, arg);
			if (ret != 0) {
				return ret;
			}
		}
	}
	return 0;
}

static int memory_save(struct settings_store *store, const char *name,
		       const char *value, size_t length)
{
	struct memory_settings *backend =
		CONTAINER_OF(store, struct memory_settings, store);
	struct memory_item *item = NULL;

	for (size_t i = 0U; i < ARRAY_SIZE(backend->items); ++i) {
		if (backend->items[i].present &&
		    strcmp(backend->items[i].name, name) == 0) {
			item = &backend->items[i];
			break;
		}
		if (item == NULL && !backend->items[i].present) {
			item = &backend->items[i];
		}
	}
	if (item == NULL || length > sizeof(item->value)) {
		return -ENOSPC;
	}
	if (length == 0U) {
		memset(item, 0, sizeof(*item));
		return 0;
	}
	strncpy(item->name, name, sizeof(item->name) - 1U);
	memcpy(item->value, value, length);
	item->length = length;
	item->present = true;
	return 0;
}

static const struct settings_store_itf memory_itf = {
	.csi_load = memory_load,
	.csi_save = memory_save,
};

static int derive_key(void *user, const uint8_t *context, size_t context_len,
		      uint8_t out[32])
{
	const struct mock_authority *mock = user;
	static const char expected[] = "LICHEN-OSCORE-STATE-AUTH-v1";

	zassert_equal(context_len, sizeof(expected) - 1U);
	zassert_mem_equal(context, expected, sizeof(expected) - 1U);
	memcpy(out, mock->root_key, 32U);
	return 0;
}

static int authority_load(void *user,
			  struct oscore_persist_authority_state *state)
{
	const struct mock_authority *mock = user;

	if (mock->load_error != 0) {
		return mock->load_error;
	}
	if (!mock->present) {
		return -ENOENT;
	}
	*state = mock->state;
	return 0;
}

static int authority_commit(
	void *user, const struct oscore_persist_authority_state *expected,
	const struct oscore_persist_authority_state *next)
{
	struct mock_authority *mock = user;

	++mock->commits;
	if (mock->commit_error != 0) {
		return mock->commit_error;
	}
	if (!mock->present) {
		if (expected != NULL || next->revision != 1U) {
			return -ESTALE;
		}
	} else if (expected == NULL ||
		   expected->revision != mock->state.revision ||
		   memcmp(expected->digest, mock->state.digest, 32U) != 0 ||
		   next->revision != expected->revision + 1U) {
		return -ESTALE;
	}
	mock->state = *next;
	mock->present = true;
	return 0;
}

static const struct oscore_persist_protection_ops protection_ops = {
	.derive_key = derive_key,
	.load = authority_load,
	.commit = authority_commit,
};

static int core_open(void)
{
	return oscore_persist_open(&core_persistence, &core_store_ops, &core,
				   &protection_ops, &core.authority);
}

static void reset_core(void)
{
	memset(&core, 0, sizeof(core));
	memset(&core_persistence, 0, sizeof(core_persistence));
	memset(core.authority.root_key, 0x6c,
	       sizeof(core.authority.root_key));
}

static void create_pair(struct oscore_ctx **sender, struct oscore_ctx **receiver)
{
	static const uint8_t secret[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	static const uint8_t client_id[] = {0x01};
	static const uint8_t server_id[] = {0x02};
	uint8_t sender_secret[sizeof(secret)];
	uint8_t receiver_secret[sizeof(secret)];

	memcpy(sender_secret, secret, sizeof(secret));
	memcpy(receiver_secret, secret, sizeof(secret));
	zassert_equal(oscore_ctx_create(sender_secret, NULL, 0U, client_id,
					sizeof(client_id), server_id,
					sizeof(server_id), sender), OSCORE_OK);
	zassert_equal(oscore_ctx_create(receiver_secret, NULL, 0U, server_id,
					sizeof(server_id), client_id,
					sizeof(client_id), receiver), OSCORE_OK);
}

ZTEST(oscore_persist, test_authority_registration_is_required)
{
	static const uint8_t sender_id[] = {0x01};
	static const uint8_t recipient_id[] = {0x02};
	uint8_t secret[16] = {0x42};
	struct oscore_ctx *ctx = NULL;

	zassert_ok(oscore_init());
	zassert_equal(oscore_ctx_create(secret, NULL, 0U, sender_id,
					sizeof(sender_id), recipient_id,
					sizeof(recipient_id), &ctx),
		      OSCORE_ERR_NVM_FAILED);
	zassert_is_null(ctx);
}

ZTEST(oscore_persist, test_settings_reboot_replay_and_atomic_failures)
{
	struct oscore_ctx *sender = NULL;
	struct oscore_ctx *receiver = NULL;
	uint8_t ciphertext[64];
	uint8_t option[32];
	uint8_t code = 0U;
	uint8_t options[8] = {0};
	uint8_t payload[8] = {0};
	uint8_t response_ciphertext[64];
	uint8_t response_option[16];
	const uint8_t request_piv[] = {7U};
	size_t ciphertext_len = sizeof(ciphertext);
	size_t option_len = sizeof(option);
	size_t options_len = sizeof(options);
	size_t payload_len = sizeof(payload);
	size_t response_ciphertext_len = sizeof(response_ciphertext);
	size_t response_option_len = sizeof(response_option);
	uint64_t restored_sender;

	zassert_ok(settings_subsys_init());
	memory_store.store.cs_itf = &memory_itf;
	settings_src_register(&memory_store.store);
	settings_dst_register(&memory_store.store);
	memset(authority.root_key, 0x5a, sizeof(authority.root_key));
	zassert_ok(oscore_settings_register_protection(&protection_ops, &authority));
	zassert_ok(oscore_init());
	create_pair(&sender, &receiver);
	zassert_equal(oscore_ctx_set_sender_seq(sender, 7U), OSCORE_OK);
	zassert_equal(oscore_protect_request(sender, 1U, NULL, 0U, NULL, 0U,
					ciphertext, &ciphertext_len, option,
					&option_len), OSCORE_OK);

	/* A failed protected-authority commit cannot publish plaintext or replay. */
	authority.commit_error = -EIO;
	zassert_equal(oscore_unprotect_request(receiver, option, option_len,
					  ciphertext, ciphertext_len, &code,
					  options, &options_len, payload,
					  &payload_len), OSCORE_ERR_NVM_FAILED);
	zassert_equal(code, 0U);
	authority.commit_error = 0;
	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(receiver, option, option_len,
					  ciphertext, ciphertext_len, &code,
					  options, &options_len, payload,
					  &payload_len), OSCORE_OK);
	zassert_equal(code, 1U);
	memset(response_ciphertext, 0xa5, sizeof(response_ciphertext));
	authority.commit_error = -EIO;
	zassert_equal(oscore_protect_response(
			receiver, request_piv, sizeof(request_piv), 69U, NULL, 0U,
			NULL, 0U, response_ciphertext, &response_ciphertext_len,
			response_option, &response_option_len), OSCORE_ERR_NVM_FAILED);
	for (size_t i = 0U; i < sizeof(response_ciphertext); ++i) {
		zassert_equal(response_ciphertext[i], 0xa5U,
			      "response output changed before durable commit");
	}
	authority.commit_error = 0;
	response_ciphertext_len = sizeof(response_ciphertext);
	response_option_len = sizeof(response_option);
	zassert_equal(oscore_protect_response(
			receiver, request_piv, sizeof(request_piv), 69U, NULL, 0U,
			NULL, 0U, response_ciphertext, &response_ciphertext_len,
			response_option, &response_option_len), OSCORE_OK);
	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_response(
			sender, request_piv, sizeof(request_piv), response_option,
			response_option_len, response_ciphertext,
			response_ciphertext_len, &code, options, &options_len,
			payload, &payload_len), OSCORE_OK);
	zassert_equal(code, 69U);

	oscore_ctx_free(sender);
	oscore_ctx_free(receiver);
	oscore_settings_close();
	int reopen_ret = oscore_settings_register_protection(&protection_ops,
						      &authority);
	zassert_ok(reopen_ret, "reopen failed: %d", reopen_ret);
	create_pair(&sender, &receiver);
	zassert_ok(oscore_ctx_get_sender_seq(sender, &restored_sender));
	zassert_true(restored_sender > 7U, "sender nonce floor did not survive reboot");
	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(receiver, option, option_len,
					  ciphertext, ciphertext_len, &code,
					  options, &options_len, payload,
					  &payload_len), OSCORE_ERR_REPLAY);
	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_response(
			sender, request_piv, sizeof(request_piv), response_option,
			response_option_len, response_ciphertext,
			response_ciphertext_len, &code, options, &options_len,
			payload, &payload_len), OSCORE_ERR_REPLAY);

	/* Deleting the authority-selected Settings generation is not virgin. */
	oscore_ctx_free(sender);
	oscore_ctx_free(receiver);
	oscore_settings_close();
	for (size_t i = 0U; i < ARRAY_SIZE(memory_store.items); ++i) {
		if (memory_store.items[i].present &&
		    ((authority.state.revision & 1U) != 0U) ==
			(strstr(memory_store.items[i].name, "/b") != NULL)) {
			memory_store.items[i].present = false;
			break;
		}
	}
	zassert_equal(oscore_settings_register_protection(&protection_ops, &authority),
		      -EBADMSG);
}

ZTEST(oscore_persist, test_corruption_rollback_wrong_root_and_stray_state)
{
	uint8_t binding[OSCORE_PERSIST_BINDING_LEN] = {0x11};
	struct oscore_persist_state state = {
		.sender_seq = 100U,
		.sender_seq_valid = true,
	};
	enum oscore_persist_blob_slot selected;

	reset_core();
	zassert_ok(core_open());
	zassert_ok(oscore_persist_commit(&core_persistence, binding, &state));
	oscore_persist_close(&core_persistence);
	selected = (core.authority.state.revision & 1U) != 0U ?
		   OSCORE_PERSIST_BLOB_B : OSCORE_PERSIST_BLOB_A;
	core.slots[selected][24] ^= 0x80U;
	zassert_true(core_open() < 0, "corrupt authenticated state was accepted");
	core.slots[selected][24] ^= 0x80U;
	core.lengths[selected] = 0U;
	zassert_equal(core_open(), -EBADMSG);

	reset_core();
	zassert_ok(core_open());
	zassert_ok(oscore_persist_commit(&core_persistence, binding, &state));
	oscore_persist_close(&core_persistence);
	core.authority.root_key[0] ^= 1U;
	zassert_equal(core_open(), -EKEYREJECTED);

	reset_core();
	zassert_ok(core_open());
	oscore_persist_close(&core_persistence);
	core.authority.present = false;
	zassert_equal(core_open(), -EBADMSG,
		      "ordinary snapshot without authority was treated as virgin");
}

ZTEST(oscore_persist, test_monotonic_atomic_and_bounded_records)
{
	uint8_t binding[OSCORE_PERSIST_BINDING_LEN];
	struct oscore_persist_state state = {
		.sender_seq = 100U,
		.recipient_seq = 10U,
		.replay_window = 3U,
		.sender_seq_valid = true,
		.recipient_window_initialized = true,
	};
	struct oscore_persist_state restored;

	reset_core();
	zassert_ok(core_open());
	memset(binding, 1, sizeof(binding));
	zassert_ok(oscore_persist_commit(&core_persistence, binding, &state));
	state.sender_seq = 99U;
	zassert_equal(oscore_persist_commit(&core_persistence, binding, &state),
		      -ESTALE);
	state.sender_seq = 100U;
	state.replay_window = 1U;
	zassert_equal(oscore_persist_commit(&core_persistence, binding, &state),
		      -ESTALE);
	state.replay_window = 7U;
	core.authority.commit_error = -EIO;
	zassert_equal(oscore_persist_commit(&core_persistence, binding, &state),
		      -EIO);
	core.authority.commit_error = 0;
	zassert_ok(oscore_persist_restore(&core_persistence, binding, &restored));
	zassert_equal(restored.replay_window, 3U,
		      "failed authority commit mutated live state");
	oscore_persist_close(&core_persistence);
	zassert_ok(core_open());
	zassert_ok(oscore_persist_restore(&core_persistence, binding, &restored));
	zassert_equal(restored.replay_window, 3U,
		      "torn alternate snapshot replaced authority-selected state");

	for (uint8_t i = 2U; i <= CONFIG_LICHEN_OSCORE_MAX_CONTEXTS; ++i) {
		memset(binding, i, sizeof(binding));
		zassert_ok(oscore_persist_commit(&core_persistence, binding, &state));
	}
	memset(binding, 0xee, sizeof(binding));
	zassert_equal(oscore_persist_commit(&core_persistence, binding, &state),
		      -ENOSPC);
}

ZTEST_SUITE(oscore_persist, NULL, NULL, NULL, NULL, NULL);
