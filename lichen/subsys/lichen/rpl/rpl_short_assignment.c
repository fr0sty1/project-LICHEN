/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <lichen/rpl_messages.h>
#include <lichen/rpl_short_assignment.h>

#define ASSIGNMENT_ACK_DATA_LEN 14U
#define ASSIGNMENT_ACK_KIND 1U
#define RECORD_CRC_OFFSET (LICHEN_RPL_SHORT_ASSIGNMENT_RECORD_LEN - 4U)

static uint32_t crc32_ieee(const uint8_t *data, size_t len)
{
	uint32_t crc = UINT32_MAX;

	for (size_t i = 0; i < len; i++) {
		crc ^= data[i];
		for (int bit = 0; bit < 8; bit++) {
			crc = (crc >> 1U) ^ ((crc & 1U) != 0U ? UINT32_C(0xedb88320) : 0U);
		}
	}
	return crc ^ UINT32_MAX;
}

static void put_be32(uint8_t out[4], uint32_t value)
{
	out[0] = (uint8_t)(value >> 24U);
	out[1] = (uint8_t)(value >> 16U);
	out[2] = (uint8_t)(value >> 8U);
	out[3] = (uint8_t)value;
}

static uint32_t get_be32(const uint8_t in[4])
{
	return ((uint32_t)in[0] << 24U) | ((uint32_t)in[1] << 16U) |
	       ((uint32_t)in[2] << 8U) | (uint32_t)in[3];
}

static bool short_usable(uint16_t short_addr)
{
	return short_addr >= 1U && short_addr <= UINT16_C(0xfffd);
}

static int parse_assignment_ack(const struct lichen_rpl_short_assignment_client *client,
				const uint8_t *wire, size_t wire_len,
				struct lichen_rpl_dao_ack *ack,
				uint8_t *operation, uint8_t *status,
				bool *assigned, uint16_t *short_addr);

static void encode_record(const struct lichen_rpl_short_assignment_client *client,
			  bool assigned, uint16_t short_addr,
			  const uint8_t *ack, size_t ack_len, uint8_t sequence,
			  uint8_t out[LICHEN_RPL_SHORT_ASSIGNMENT_RECORD_LEN])
{
	memset(out, 0, LICHEN_RPL_SHORT_ASSIGNMENT_RECORD_LEN);
	memcpy(out, "SAC1", 4);
	out[4] = 1U;
	memcpy(&out[5], client->eui64, 8);
	out[13] = client->rpl_instance_id;
	memcpy(&out[14], client->dodag_id, 16);
	out[30] = assigned ? 1U : 0U;
	out[31] = (uint8_t)(short_addr >> 8U);
	out[32] = (uint8_t)short_addr;
	out[33] = sequence;
	out[34] = (uint8_t)ack_len;
	memcpy(&out[35], ack, ack_len);
	put_be32(&out[RECORD_CRC_OFFSET], crc32_ieee(out, RECORD_CRC_OFFSET));
}

static int restore_record(struct lichen_rpl_short_assignment_client *client,
			  const uint8_t record[LICHEN_RPL_SHORT_ASSIGNMENT_RECORD_LEN])
{
	struct lichen_rpl_dao_ack ack;
	uint8_t operation;
	uint8_t status;
	uint16_t parsed_short;
	bool parsed_assigned;
	uint16_t short_addr;
	int ret;

	if (memcmp(record, "SAC1", 4) != 0 || record[4] != 1U ||
	    memcmp(&record[5], client->eui64, 8) != 0 ||
	    record[13] != client->rpl_instance_id ||
	    memcmp(&record[14], client->dodag_id, 16) != 0 ||
	    record[30] > 1U || record[34] == 0U ||
	    record[34] > LICHEN_RPL_SHORT_ASSIGNMENT_MAX_ACK ||
	    get_be32(&record[RECORD_CRC_OFFSET]) != crc32_ieee(record, RECORD_CRC_OFFSET)) {
		return -EBADMSG;
	}
	short_addr = (uint16_t)(((uint16_t)record[31] << 8U) | record[32]);
	if ((record[30] != 0U && !short_usable(short_addr)) ||
	    (record[30] == 0U && short_addr != LICHEN_RPL_SHORT_ASSIGNMENT_NONE)) {
		return -EBADMSG;
	}
	ret = parse_assignment_ack(client, &record[35], record[34], &ack,
				   &operation, &status, &parsed_assigned, &parsed_short);
	if (ret < 0 || status != 0U || ack.dao_sequence != record[33] ||
	    parsed_assigned != (record[30] != 0U) || parsed_short != short_addr) {
		return -EBADMSG;
	}
	if (client->backend.restore != NULL) {
		ret = client->backend.restore(client->backend.ctx, record[30] != 0U, short_addr);
		if (ret < 0) {
			return ret;
		}
	}
	client->assigned = record[30] != 0U;
	client->assigned_short = short_addr;
	client->last_sequence = record[33];
	client->last_ack_len = record[34];
	memcpy(client->last_ack, &record[35], client->last_ack_len);
	client->have_last_ack = true;
	client->have_record = true;
	return 0;
}

int lichen_rpl_short_assignment_init(
	struct lichen_rpl_short_assignment_client *client,
	const uint8_t eui64[8], uint8_t rpl_instance_id,
	const uint8_t dodag_id[16],
	const struct lichen_rpl_short_assignment_backend *backend)
{
	if (client == NULL || eui64 == NULL || dodag_id == NULL || backend == NULL ||
	    backend->commit == NULL) {
		return -EINVAL;
	}
	memset(client, 0, sizeof(*client));
	memcpy(client->eui64, eui64, 8);
	memcpy(client->dodag_id, dodag_id, 16);
	client->rpl_instance_id = rpl_instance_id;
	client->assigned_short = LICHEN_RPL_SHORT_ASSIGNMENT_NONE;
	client->backend = *backend;
	if (backend->load == NULL) {
		return 0;
	}
	uint8_t record[LICHEN_RPL_SHORT_ASSIGNMENT_RECORD_LEN];
	size_t record_len = 0;
	int ret = backend->load(backend->ctx, record, sizeof(record), &record_len);
	if (ret == -ENOENT) {
		return 0;
	}
	if (ret < 0) {
		return ret;
	}
	if (record_len != sizeof(record)) {
		return -EBADMSG;
	}
	return restore_record(client, record);
}

int lichen_rpl_short_assignment_expect(
	struct lichen_rpl_short_assignment_client *client, uint8_t dao_sequence,
	enum lichen_rpl_short_assignment_operation operation)
{
	if (client == NULL || (operation != LICHEN_RPL_SHORT_ASSIGN_ALLOCATE &&
			       operation != LICHEN_RPL_SHORT_ASSIGN_RELEASE)) {
		return -EINVAL;
	}
	client->pending_sequence = dao_sequence;
	client->pending_operation = (uint8_t)operation;
	client->pending = true;
	return 0;
}

static int parse_assignment_ack(const struct lichen_rpl_short_assignment_client *client,
				const uint8_t *wire, size_t wire_len,
				struct lichen_rpl_dao_ack *ack,
				uint8_t *operation, uint8_t *status,
				bool *assigned, uint16_t *short_addr)
{
	if (lichen_rpl_dao_ack_parse(ack, wire, wire_len) != LICHEN_RPL_OK ||
	    ack->rpl_instance_id != client->rpl_instance_id ||
	    (ack->has_dodag_id && memcmp(ack->dodag_id, client->dodag_id, 16) != 0)) {
		return -EBADMSG;
	}
	const uint8_t *options = lichen_rpl_dao_ack_options(wire, wire_len);
	size_t options_len = lichen_rpl_dao_ack_options_len_ex(wire, wire_len);
	struct lichen_rpl_opt_iter it;
	struct lichen_rpl_raw_opt opt;
	bool found = false;
	int ret;

	/* The assignment ACK is exactly one 2-byte TLV header plus 14 data bytes. */
	if (options == NULL || options_len != ASSIGNMENT_ACK_DATA_LEN + 2U) {
		return -EBADMSG;
	}
	lichen_rpl_opt_iter_init(&it, options, options_len);
	while ((ret = lichen_rpl_opt_iter_next(&it, &opt)) == LICHEN_RPL_OK) {
		if (found || opt.opt_type != LICHEN_RPL_SHORT_ASSIGNMENT_OPT ||
		    opt.data_len != ASSIGNMENT_ACK_DATA_LEN) {
			return -EBADMSG;
		}
		found = true;
		if (opt.data[0] != LICHEN_RPL_SHORT_ASSIGNMENT_VERSION ||
		    opt.data[1] != ASSIGNMENT_ACK_KIND || opt.data[2] > 1U ||
		    opt.data[3] > 2U || memcmp(&opt.data[4], client->eui64, 8) != 0) {
			return -EBADMSG;
		}
		*operation = opt.data[2];
		*status = opt.data[3];
		*short_addr = (uint16_t)(((uint16_t)opt.data[12] << 8U) | opt.data[13]);
		*assigned = *operation == LICHEN_RPL_SHORT_ASSIGN_ALLOCATE && *status == 0U;
		if ((*assigned && !short_usable(*short_addr)) ||
		    (!*assigned && *short_addr != LICHEN_RPL_SHORT_ASSIGNMENT_NONE) ||
		    ack->status != *status) {
			return -EBADMSG;
		}
	}
	return ret == 1 && found ? 0 : -EBADMSG;
}

int lichen_rpl_short_assignment_apply_dao_ack(
	struct lichen_rpl_short_assignment_client *client,
	const uint8_t *ack_bytes, size_t ack_len, bool root_authenticated)
{
	if (client == NULL || ack_bytes == NULL) {
		return -EINVAL;
	}
	if (!root_authenticated) {
		return -EACCES;
	}
	if (ack_len > LICHEN_RPL_SHORT_ASSIGNMENT_MAX_ACK) {
		return -EMSGSIZE;
	}
	struct lichen_rpl_dao_ack ack;
	uint8_t operation;
	uint8_t status;
	uint16_t short_addr;
	bool assigned;
	int ret = parse_assignment_ack(client, ack_bytes, ack_len, &ack, &operation,
				       &status, &assigned, &short_addr);
	if (ret < 0) {
		return ret;
	}
	if (client->have_last_ack && ack.dao_sequence == client->last_sequence) {
		if (client->last_ack_len == ack_len &&
		    memcmp(client->last_ack, ack_bytes, ack_len) == 0) {
			return LICHEN_RPL_SHORT_ASSIGN_DUPLICATE;
		}
		return -EBADMSG;
	}
	if (!client->pending || ack.dao_sequence != client->pending_sequence ||
	    operation != client->pending_operation) {
		return LICHEN_RPL_SHORT_ASSIGN_IGNORED;
	}
	if (status != 0U) {
		return LICHEN_RPL_SHORT_ASSIGN_IGNORED;
	}

	uint8_t old_record[LICHEN_RPL_SHORT_ASSIGNMENT_RECORD_LEN] = {0};
	uint8_t new_record[LICHEN_RPL_SHORT_ASSIGNMENT_RECORD_LEN];
	size_t old_len = client->have_record ? sizeof(old_record) : 0U;
	if (client->have_record) {
		encode_record(client, client->assigned, client->assigned_short,
			      client->last_ack, client->last_ack_len,
			      client->last_sequence, old_record);
	}
	encode_record(client, assigned, short_addr, ack_bytes, ack_len,
		      ack.dao_sequence, new_record);
	ret = client->backend.commit(client->backend.ctx,
				     client->have_record ? old_record : NULL, old_len,
				     new_record, sizeof(new_record), client->assigned,
				     client->assigned_short, assigned, short_addr);
	if (ret < 0) {
		return ret;
	}
	client->assigned = assigned;
	client->assigned_short = short_addr;
	client->last_sequence = ack.dao_sequence;
	client->last_ack_len = (uint8_t)ack_len;
	memcpy(client->last_ack, ack_bytes, ack_len);
	client->have_last_ack = true;
	client->have_record = true;
	client->pending = false;
	return LICHEN_RPL_SHORT_ASSIGN_APPLIED;
}
