/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lichen/rpl_short_assignment.h>

#include "short_assignment_vectors.h"

#define CHECK(expr) do {                                                        \
	if (!(expr)) {                                                            \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);     \
		return 1;                                                           \
	}                                                                          \
} while (0)

struct fake_backend {
	uint8_t record[LICHEN_RPL_SHORT_ASSIGNMENT_RECORD_LEN];
	size_t record_len;
	uint16_t iface_short;
	unsigned int loads;
	unsigned int restores;
	unsigned int commits;
	bool iface_assigned;
	bool fail_commit;
};

static int fake_load(void *ctx, uint8_t *record, size_t capacity, size_t *record_len)
{
	struct fake_backend *backend = ctx;

	backend->loads++;
	if (backend->record_len == 0U) {
		return -ENOENT;
	}
	if (capacity < backend->record_len) {
		return -ENOSPC;
	}
	memcpy(record, backend->record, backend->record_len);
	*record_len = backend->record_len;
	return 0;
}

static int fake_restore(void *ctx, bool assigned, uint16_t short_addr)
{
	struct fake_backend *backend = ctx;

	backend->restores++;
	backend->iface_assigned = assigned;
	backend->iface_short = short_addr;
	return 0;
}

static int fake_commit(void *ctx, const uint8_t *old_record, size_t old_record_len,
		       const uint8_t *new_record, size_t new_record_len,
		       bool old_assigned, uint16_t old_short,
		       bool new_assigned, uint16_t new_short)
{
	struct fake_backend *backend = ctx;

	backend->commits++;
	if (old_record_len != backend->record_len ||
	    (old_record_len != 0U && memcmp(old_record, backend->record, old_record_len) != 0) ||
	    old_assigned != backend->iface_assigned ||
	    (old_assigned && old_short != backend->iface_short)) {
		return -ESTALE;
	}
	if (backend->fail_commit) {
		return -EIO;
	}
	if (new_record_len != sizeof(backend->record)) {
		return -EINVAL;
	}
	memcpy(backend->record, new_record, new_record_len);
	backend->record_len = new_record_len;
	backend->iface_assigned = new_assigned;
	backend->iface_short = new_short;
	return 0;
}

static struct lichen_rpl_short_assignment_backend backend_ops(struct fake_backend *backend)
{
	const struct lichen_rpl_short_assignment_backend ops = {
		.ctx = backend,
		.load = fake_load,
		.restore = fake_restore,
		.commit = fake_commit,
	};

	return ops;
}

static int test_lifecycle_and_restart(void)
{
	static const uint8_t eui64[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
	static const uint8_t dodag_id[16] = {
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	};
	struct fake_backend fake = {.iface_short = LICHEN_RPL_SHORT_ASSIGNMENT_NONE};
	struct lichen_rpl_short_assignment_backend ops = backend_ops(&fake);
	struct lichen_rpl_short_assignment_client client;
	uint8_t malformed[sizeof(allocate_ack) + 1U];
	uint8_t conflict[sizeof(allocate_ack)];
	unsigned int commits;

	CHECK(lichen_rpl_short_assignment_init(&client, eui64, 0, dodag_id, &ops) == 0);
	CHECK(fake.loads == 1U && !client.assigned);
	CHECK(lichen_rpl_short_assignment_expect(&client, 7,
			LICHEN_RPL_SHORT_ASSIGN_ALLOCATE) == 0);
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, allocate_ack,
			sizeof(allocate_ack), false) == -EACCES);
	CHECK(fake.commits == 0U && !fake.iface_assigned);

	/* Ownership is the exact outstanding DAO sequence and operation. */
	CHECK(lichen_rpl_short_assignment_expect(&client, 8,
			LICHEN_RPL_SHORT_ASSIGN_ALLOCATE) == 0);
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, allocate_ack,
			sizeof(allocate_ack), true) == LICHEN_RPL_SHORT_ASSIGN_IGNORED);
	CHECK(!fake.iface_assigned);
	CHECK(lichen_rpl_short_assignment_expect(&client, 7,
			LICHEN_RPL_SHORT_ASSIGN_ALLOCATE) == 0);

	/* Reject malformed/status/EUI/options input before either state changes. */
	memcpy(malformed, allocate_ack, sizeof(allocate_ack));
	malformed[3] = 1U;
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, malformed,
			sizeof(allocate_ack), true) == -EBADMSG);
	memcpy(malformed, allocate_ack, sizeof(allocate_ack));
	malformed[10] ^= 1U;
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, malformed,
			sizeof(allocate_ack), true) == -EBADMSG);
	memcpy(malformed, allocate_ack, sizeof(allocate_ack));
	malformed[sizeof(allocate_ack)] = 0U;
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, malformed,
			sizeof(malformed), true) == -EBADMSG);
	memcpy(malformed, allocate_ack, sizeof(allocate_ack));
	malformed[sizeof(allocate_ack) - 2U] = 0xffU;
	malformed[sizeof(allocate_ack) - 1U] = 0xfeU;
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, malformed,
			sizeof(allocate_ack), true) == -EBADMSG);
	CHECK(fake.commits == 0U && !fake.iface_assigned);

	/* A canonical root rejection is not an assignment and remains retryable. */
	memcpy(malformed, allocate_ack, sizeof(allocate_ack));
	malformed[3] = 1U;
	malformed[9] = 1U;
	malformed[sizeof(allocate_ack) - 2U] = 0xffU;
	malformed[sizeof(allocate_ack) - 1U] = 0xffU;
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, malformed,
			sizeof(allocate_ack), true) == LICHEN_RPL_SHORT_ASSIGN_IGNORED);
	CHECK(fake.commits == 0U && !fake.iface_assigned && client.pending);

	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, allocate_ack,
			sizeof(allocate_ack), true) == LICHEN_RPL_SHORT_ASSIGN_APPLIED);
	CHECK(client.assigned && client.assigned_short == UINT16_C(0x1234));
	CHECK(fake.iface_assigned && fake.iface_short == UINT16_C(0x1234));
	CHECK(fake.record_len == LICHEN_RPL_SHORT_ASSIGNMENT_RECORD_LEN);
	commits = fake.commits;

	/* An exact retransmission is idempotent even after pending state cleared. */
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, allocate_ack,
			sizeof(allocate_ack), true) == LICHEN_RPL_SHORT_ASSIGN_DUPLICATE);
	CHECK(fake.commits == commits);
	memcpy(conflict, allocate_ack, sizeof(conflict));
	conflict[sizeof(conflict) - 1U] ^= 1U;
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, conflict,
			sizeof(conflict), true) == -EBADMSG);
	CHECK(fake.commits == commits && fake.iface_short == UINT16_C(0x1234));

	/* Reboot restores the durable assignment before processing new ACKs. */
	fake.iface_assigned = false;
	fake.iface_short = LICHEN_RPL_SHORT_ASSIGNMENT_NONE;
	memset(&client, 0xa5, sizeof(client));
	CHECK(lichen_rpl_short_assignment_init(&client, eui64, 0, dodag_id, &ops) == 0);
	CHECK(fake.restores == 1U && fake.iface_assigned &&
	      fake.iface_short == UINT16_C(0x1234));
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, allocate_ack,
			sizeof(allocate_ack), true) == LICHEN_RPL_SHORT_ASSIGN_DUPLICATE);

	/* A failed transactional release leaves durable and interface state intact. */
	CHECK(lichen_rpl_short_assignment_expect(&client, 8,
			LICHEN_RPL_SHORT_ASSIGN_RELEASE) == 0);
	fake.fail_commit = true;
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, release_ack,
			sizeof(release_ack), true) == -EIO);
	CHECK(client.assigned && fake.iface_assigned &&
	      fake.iface_short == UINT16_C(0x1234));
	fake.fail_commit = false;
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, release_ack,
			sizeof(release_ack), true) == LICHEN_RPL_SHORT_ASSIGN_APPLIED);
	CHECK(!client.assigned && !fake.iface_assigned &&
	      client.assigned_short == LICHEN_RPL_SHORT_ASSIGNMENT_NONE);

	/* Release itself is persisted and restored as unassigned after reboot. */
	fake.iface_assigned = true;
	fake.iface_short = UINT16_C(0x1234);
	memset(&client, 0, sizeof(client));
	CHECK(lichen_rpl_short_assignment_init(&client, eui64, 0, dodag_id, &ops) == 0);
	CHECK(!client.assigned && !fake.iface_assigned &&
	      fake.iface_short == LICHEN_RPL_SHORT_ASSIGNMENT_NONE);
	return 0;
}

static int test_dodag_and_corrupt_persistence(void)
{
	static const uint8_t eui64[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
	static const uint8_t dodag_id[16] = {0};
	struct fake_backend fake = {.iface_short = LICHEN_RPL_SHORT_ASSIGNMENT_NONE};
	struct lichen_rpl_short_assignment_backend ops = backend_ops(&fake);
	struct lichen_rpl_short_assignment_client client;
	uint8_t d_ack[4U + 16U + 16U] = {0};

	CHECK(lichen_rpl_short_assignment_init(&client, eui64, 0, dodag_id, &ops) == 0);
	CHECK(lichen_rpl_short_assignment_expect(&client, 7,
			LICHEN_RPL_SHORT_ASSIGN_ALLOCATE) == 0);
	d_ack[1] = 0x80U;
	d_ack[2] = 7U;
	memcpy(&d_ack[20], &allocate_ack[4], sizeof(allocate_ack) - 4U);
	d_ack[4] = 1U;
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, d_ack,
			sizeof(d_ack), true) == -EBADMSG);
	d_ack[4] = 0U;
	CHECK(lichen_rpl_short_assignment_apply_dao_ack(&client, d_ack,
			sizeof(d_ack), true) == LICHEN_RPL_SHORT_ASSIGN_APPLIED);

	/* Corrupt durable data fails closed without publishing an address. */
	fake.record[10] ^= 0x80U;
	fake.iface_assigned = false;
	fake.iface_short = LICHEN_RPL_SHORT_ASSIGNMENT_NONE;
	memset(&client, 0, sizeof(client));
	CHECK(lichen_rpl_short_assignment_init(&client, eui64, 0, dodag_id, &ops) == -EBADMSG);
	CHECK(!fake.iface_assigned && fake.iface_short == LICHEN_RPL_SHORT_ASSIGNMENT_NONE);
	return 0;
}

int main(void)
{
	CHECK(test_lifecycle_and_restart() == 0);
	CHECK(test_dodag_and_corrupt_persistence() == 0);
	puts("rpl_short_assignment: all tests passed");
	return 0;
}
