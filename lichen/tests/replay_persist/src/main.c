/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <lichen/replay_persist.h>

struct mock_backend {
	uint8_t slots[2][LICHEN_REPLAY_PERSIST_BLOB_MAX];
	size_t lengths[2];
	bool authority_present;
	struct lichen_replay_authority_state authority;
	uint8_t root_key[32];
	int load_error;
	int save_error;
	int authority_load_error;
	int authority_commit_error;
	unsigned saves;
	unsigned commits;
};

static struct mock_backend mock;
static struct lichen_replay_persist persistence;
static struct lichen_replay_table table;
static uint8_t local_key[32];
static uint8_t peer_key[32];

static int mock_load(void *user, enum lichen_replay_blob_slot slot,
		     uint8_t *out, size_t capacity, size_t *length)
{
	struct mock_backend *backend = user;

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

static int mock_save(void *user, enum lichen_replay_blob_slot slot,
		     const uint8_t *value, size_t length)
{
	struct mock_backend *backend = user;

	++backend->saves;
	if (backend->save_error != 0) {
		return backend->save_error;
	}
	zassert_true(length <= sizeof(backend->slots[slot]));
	memcpy(backend->slots[slot], value, length);
	backend->lengths[slot] = length;
	return 0;
}

static int mock_derive(void *user, const uint8_t *context, size_t context_len,
		       uint8_t out[32])
{
	struct mock_backend *backend = user;
	static const char expected_context[] = "LICHEN-LINK-REPLAY-AUTH-v1";

	zassert_not_null(context);
	zassert_equal(context_len, sizeof(expected_context) - 1U);
	zassert_mem_equal(context, expected_context, sizeof(expected_context) - 1U);
	memcpy(out, backend->root_key, 32U);
	return 0;
}

static int mock_authority_load(void *user,
			       struct lichen_replay_authority_state *state)
{
	struct mock_backend *backend = user;

	if (backend->authority_load_error != 0) {
		return backend->authority_load_error;
	}
	if (!backend->authority_present) {
		return -ENOENT;
	}
	*state = backend->authority;
	return 0;
}

static int mock_authority_commit(
	void *user, const struct lichen_replay_authority_state *expected,
	const struct lichen_replay_authority_state *next)
{
	struct mock_backend *backend = user;

	++backend->commits;
	if (backend->authority_commit_error != 0) {
		return backend->authority_commit_error;
	}
	if (!backend->authority_present) {
		if (expected != NULL || next->revision != 1U) {
			return -ESTALE;
		}
	} else if (expected == NULL ||
		   expected->revision != backend->authority.revision ||
		   memcmp(expected->digest, backend->authority.digest, 32U) != 0 ||
		   next->revision != expected->revision + 1U) {
		return -ESTALE;
	}
	backend->authority = *next;
	backend->authority_present = true;
	return 0;
}

static const struct lichen_replay_store_ops store_ops = {
	.load = mock_load,
	.save = mock_save,
};

static const struct lichen_replay_protection_ops protection_ops = {
	.derive_key = mock_derive,
	.load = mock_authority_load,
	.commit = mock_authority_commit,
};

static void reset_fixture(void *unused)
{
	ARG_UNUSED(unused);
	memset(&mock, 0, sizeof(mock));
	memset(&persistence, 0, sizeof(persistence));
	memset(&table, 0, sizeof(table));
	memset(local_key, 0x11, sizeof(local_key));
	memset(peer_key, 0x22, sizeof(peer_key));
	memset(mock.root_key, 0x5a, sizeof(mock.root_key));
}

static int open_store(uint8_t fallback, uint8_t *epoch)
{
	return lichen_replay_persist_open(
		&persistence, &table, local_key, fallback, &store_ops, &mock,
		&protection_ops, &mock, epoch);
}

ZTEST(replay_persist, test_first_boot_and_reboot_reserve_before_publish)
{
	uint8_t epoch = 0U;

	zassert_ok(open_store(200U, &epoch));
	zassert_equal(epoch, 200U);
	zassert_equal(mock.authority.revision, 1U);
	zassert_equal(mock.saves, 1U);
	zassert_equal(mock.commits, 1U);
	lichen_replay_persist_close(&persistence);
	zassert_ok(open_store(130U, &epoch));
	zassert_equal(epoch, 201U);
	zassert_equal(mock.authority.revision, 2U);
	zassert_equal(mock.saves, 2U);
	zassert_equal(mock.commits, 2U);
}

ZTEST(replay_persist, test_rx_floor_is_committed_before_live_state)
{
	uint8_t epoch;
	unsigned saves;

	zassert_ok(open_store(180U, &epoch));
	zassert_ok(lichen_replay_commit(&table, peer_key, 4U, 10U));
	zassert_equal(mock.authority.revision, 2U);
	zassert_equal(persistence.floors[0].seq_floor, 41U);
	saves = mock.saves;
	zassert_ok(lichen_replay_commit(&table, peer_key, 4U, 11U));
	zassert_equal(mock.saves, saves,
		      "reserved tuples must not wear flash on every packet");
	zassert_equal(lichen_replay_commit(&table, peer_key, 4U, 11U),
		      -EALREADY);
}

ZTEST(replay_persist, test_reboot_rejects_every_reserved_capture)
{
	uint8_t epoch;

	zassert_ok(open_store(180U, &epoch));
	zassert_ok(lichen_replay_commit(&table, peer_key, 4U, 10U));
	lichen_replay_persist_close(&persistence);
	zassert_ok(open_store(180U, &epoch));
	zassert_equal(lichen_replay_commit(&table, peer_key, 4U, 10U),
		      -EALREADY);
	zassert_equal(lichen_replay_commit(&table, peer_key, 4U, 41U),
		      -EALREADY);
	zassert_ok(lichen_replay_commit(&table, peer_key, 4U, 42U));
}

ZTEST(replay_persist, test_store_and_authority_failures_are_atomic)
{
	uint8_t epoch;
	struct lichen_replay_authority_state old_authority;

	zassert_ok(open_store(180U, &epoch));
	old_authority = mock.authority;
	mock.save_error = -EIO;
	zassert_equal(lichen_replay_commit(&table, peer_key, 1U, 1U), -EIO);
	zassert_false(table.peers[0].active);
	zassert_mem_equal(&mock.authority, &old_authority, sizeof(old_authority));
	mock.save_error = 0;
	mock.authority_commit_error = -EAGAIN;
	zassert_equal(lichen_replay_commit(&table, peer_key, 1U, 1U), -EAGAIN);
	zassert_false(table.peers[0].active);
	zassert_mem_equal(&mock.authority, &old_authority, sizeof(old_authority));
	mock.authority_commit_error = 0;
	lichen_replay_persist_close(&persistence);
	zassert_ok(open_store(180U, &epoch),
		   "uncommitted alternate slot must not replace authority-selected state");
}

ZTEST(replay_persist, test_corruption_deletion_and_wrong_identity_fail_closed)
{
	uint8_t epoch;
	enum lichen_replay_blob_slot selected;

	zassert_ok(open_store(180U, &epoch));
	lichen_replay_persist_close(&persistence);
	selected = (mock.authority.revision & 1U) != 0U ?
		   LICHEN_REPLAY_BLOB_B : LICHEN_REPLAY_BLOB_A;
	mock.slots[selected][20] ^= 0x80U;
	zassert_true(open_store(180U, &epoch) < 0);
	mock.slots[selected][20] ^= 0x80U;
	mock.lengths[selected] = 0U;
	zassert_equal(open_store(180U, &epoch), -EBADMSG);
	reset_fixture(NULL);
	zassert_ok(open_store(180U, &epoch));
	lichen_replay_persist_close(&persistence);
	local_key[0] ^= 1U;
	zassert_equal(open_store(180U, &epoch), -EKEYREJECTED);
	reset_fixture(NULL);
	zassert_ok(open_store(180U, &epoch));
	lichen_replay_persist_close(&persistence);
	mock.root_key[0] ^= 1U;
	zassert_equal(open_store(180U, &epoch), -EKEYREJECTED);
}

ZTEST(replay_persist, test_stray_snapshot_without_authority_is_not_virgin)
{
	uint8_t epoch;

	zassert_ok(open_store(180U, &epoch));
	lichen_replay_persist_close(&persistence);
	mock.authority_present = false;
	zassert_equal(open_store(180U, &epoch), -EBADMSG);
}

ZTEST(replay_persist, test_persistent_remove_is_atomic)
{
	uint8_t epoch;

	zassert_ok(open_store(180U, &epoch));
	zassert_ok(lichen_replay_commit(&table, peer_key, 1U, 5U));
	mock.authority_commit_error = -EIO;
	zassert_equal(lichen_replay_remove(&table, peer_key), -EIO);
	zassert_true(table.peers[0].active);
	mock.authority_commit_error = 0;
	zassert_ok(lichen_replay_remove(&table, peer_key));
	zassert_false(table.peers[0].active);
	lichen_replay_persist_close(&persistence);
	zassert_ok(open_store(180U, &epoch));
	zassert_false(table.peers[0].active);
}

ZTEST(replay_persist, test_tx_wrap_reservation_and_exhaustion)
{
	uint8_t epoch;
	uint8_t next = 0U;

	zassert_ok(open_store(253U, &epoch));
	zassert_ok(lichen_replay_persist_reserve_tx_epoch(&persistence, 253U,
							 &next));
	zassert_equal(next, 254U);
	zassert_equal(lichen_replay_persist_reserve_tx_epoch(&persistence, 253U,
							       &next),
		      -ESTALE);
	zassert_ok(lichen_replay_persist_reserve_tx_epoch(&persistence, 254U,
							 &next));
	zassert_equal(next, 255U);
	zassert_equal(lichen_replay_persist_reserve_tx_epoch(&persistence, 255U,
							       &next),
		      -EOVERFLOW);
}

ZTEST(replay_persist, test_capacity_fails_closed_without_eviction)
{
	uint8_t epoch;
	uint8_t key[32];

	zassert_ok(open_store(180U, &epoch));
	for (uint8_t i = 0U; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; ++i) {
		memset(key, (int)i + 1, sizeof(key));
		zassert_ok(lichen_replay_commit(&table, key, 1U, 1U));
	}
	memset(key, 0xee, sizeof(key));
	zassert_equal(lichen_replay_commit(&table, key, 1U, 1U), -ENOSPC);
	for (uint8_t i = 0U; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; ++i) {
		zassert_true(table.peers[i].active);
	}
}

ZTEST_SUITE(replay_persist, NULL, NULL, reset_fixture, NULL, NULL);
