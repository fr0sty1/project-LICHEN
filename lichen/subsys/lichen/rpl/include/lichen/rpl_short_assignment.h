/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_RPL_SHORT_ASSIGNMENT_H_
#define LICHEN_RPL_SHORT_ASSIGNMENT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_RPL_SHORT_ASSIGNMENT_OPT 252U
#define LICHEN_RPL_SHORT_ASSIGNMENT_VERSION 1U
#define LICHEN_RPL_SHORT_ASSIGNMENT_NONE UINT16_C(0xffff)
#define LICHEN_RPL_SHORT_ASSIGNMENT_MAX_ACK 40U
#define LICHEN_RPL_SHORT_ASSIGNMENT_RECORD_LEN 79U

enum lichen_rpl_short_assignment_operation {
	LICHEN_RPL_SHORT_ASSIGN_ALLOCATE = 0,
	LICHEN_RPL_SHORT_ASSIGN_RELEASE = 1,
};

enum lichen_rpl_short_assignment_result {
	LICHEN_RPL_SHORT_ASSIGN_IGNORED = 0,
	LICHEN_RPL_SHORT_ASSIGN_APPLIED = 1,
	LICHEN_RPL_SHORT_ASSIGN_DUPLICATE = 2,
};

/**
 * Backend trust boundary for assignment publication.
 *
 * commit() MUST durably store @p new_record and publish the corresponding
 * net-interface short address as one transaction. On failure it MUST leave
 * both the old durable record and old interface address unchanged. restore()
 * publishes a previously validated durable assignment during initialization.
 */
struct lichen_rpl_short_assignment_backend {
	void *ctx;
	int (*load)(void *ctx, uint8_t *record, size_t capacity, size_t *record_len);
	int (*restore)(void *ctx, bool assigned, uint16_t short_addr);
	int (*commit)(void *ctx,
		      const uint8_t *old_record, size_t old_record_len,
		      const uint8_t *new_record, size_t new_record_len,
		      bool old_assigned, uint16_t old_short,
		      bool new_assigned, uint16_t new_short);
};

struct lichen_rpl_short_assignment_client {
	uint8_t eui64[8];
	uint8_t dodag_id[16];
	uint8_t last_ack[LICHEN_RPL_SHORT_ASSIGNMENT_MAX_ACK];
	struct lichen_rpl_short_assignment_backend backend;
	uint16_t assigned_short;
	uint8_t rpl_instance_id;
	uint8_t pending_sequence;
	uint8_t pending_operation;
	uint8_t last_sequence;
	uint8_t last_ack_len;
	bool assigned;
	bool pending;
	bool have_last_ack;
	bool have_record;
};

int lichen_rpl_short_assignment_init(
	struct lichen_rpl_short_assignment_client *client,
	const uint8_t eui64[8], uint8_t rpl_instance_id,
	const uint8_t dodag_id[16],
	const struct lichen_rpl_short_assignment_backend *backend);

int lichen_rpl_short_assignment_expect(
	struct lichen_rpl_short_assignment_client *client, uint8_t dao_sequence,
	enum lichen_rpl_short_assignment_operation operation);

int lichen_rpl_short_assignment_apply_dao_ack(
	struct lichen_rpl_short_assignment_client *client,
	const uint8_t *ack_bytes, size_t ack_len, bool root_authenticated);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_SHORT_ASSIGNMENT_H_ */
