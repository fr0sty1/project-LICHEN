/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file messages.c
 * @brief RPL control message codecs implementation
 *
 * Ported from rust/lichen-rpl/src/messages.rs
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <zephyr/sys/byteorder.h>

#include <lichen/rpl_messages.h>

/* ── Helpers ───────────────────────────────────────────────────────────────── */

/* Division rounding up */
static size_t div_ceil(size_t a, size_t b)
{
	return (a + b - 1) / b;
}

/* ── DIO ───────────────────────────────────────────────────────────────────── */

int lichen_rpl_dio_parse(struct lichen_rpl_dio *dio,
			 const uint8_t *data, size_t len)
{
	if (dio == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_DIO_BASE_LEN) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	uint8_t gmop = data[4];

	dio->rpl_instance_id = data[0];
	dio->version = data[1];
	dio->rank = sys_get_be16(&data[2]);
	dio->grounded = (gmop >> 7) & 1;
	dio->mode_of_operation = (gmop >> 3) & 0x7;
	dio->preference = gmop & 0x7;
	dio->dtsn = data[5];
	dio->flags = data[6];
	memcpy(dio->dodag_id, &data[8], 16);

	return LICHEN_RPL_OK;
}

int lichen_rpl_dio_write(const struct lichen_rpl_dio *dio,
			 uint8_t *buf, size_t len)
{
	if (dio == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_DIO_BASE_LEN) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	uint8_t gmop = ((dio->grounded ? 1 : 0) << 7)
		     | ((dio->mode_of_operation & 0x7) << 3)
		     | (dio->preference & 0x7);

	buf[0] = dio->rpl_instance_id;
	buf[1] = dio->version;
	sys_put_be16(dio->rank, &buf[2]);
	buf[4] = gmop;
	buf[5] = dio->dtsn;
	buf[6] = dio->flags;
	buf[7] = 0; /* reserved */
	memcpy(&buf[8], dio->dodag_id, 16);

	return LICHEN_RPL_DIO_BASE_LEN;
}

const uint8_t *lichen_rpl_dio_options(const uint8_t *data, size_t len)
{
	if (data == NULL) {
		return NULL;
	}
	if (len > LICHEN_RPL_DIO_BASE_LEN) {
		return &data[LICHEN_RPL_DIO_BASE_LEN];
	}
	return NULL;
}

/* ── DAO ───────────────────────────────────────────────────────────────────── */

/** DAO base without DODAGID (D=0) is 4 bytes */
#define DAO_BASE_NO_DODAGID  4

int lichen_rpl_dao_parse(struct lichen_rpl_dao *dao,
			 const uint8_t *data, size_t len)
{
	if (dao == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	/* Minimum: 4 bytes base without DODAGID */
	if (len < DAO_BASE_NO_DODAGID) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	uint8_t kd = data[1];
	bool d_flag = (kd >> 6) & 1;

	/* If D-flag set, DODAGID is present (16 bytes more) */
	if (d_flag && len < LICHEN_RPL_DAO_BASE_LEN) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	dao->rpl_instance_id = data[0];
	dao->ack_requested = (kd >> 7) & 1;
	dao->flags = kd & 0x3F;
	dao->dao_sequence = data[3];

	if (d_flag) {
		memcpy(dao->dodag_id, &data[4], 16);
	} else {
		memset(dao->dodag_id, 0, 16);
	}

	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_write(const struct lichen_rpl_dao *dao,
			 uint8_t *buf, size_t len)
{
	if (dao == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_DAO_BASE_LEN) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	/* K=ack_requested, D=1 (always include DODAGID) */
	uint8_t kd = ((dao->ack_requested ? 1 : 0) << 7)
		   | (1 << 6)  /* D-flag always set */
		   | (dao->flags & 0x3F);

	buf[0] = dao->rpl_instance_id;
	buf[1] = kd;
	buf[2] = 0; /* reserved */
	buf[3] = dao->dao_sequence;
	memcpy(&buf[4], dao->dodag_id, 16);

	return LICHEN_RPL_DAO_BASE_LEN;
}

const uint8_t *lichen_rpl_dao_options(const uint8_t *data, size_t len)
{
	if (data == NULL) {
		return NULL;
	}

	/* Check D-flag (bit 6 of byte 1) to determine base length */
	if (len < DAO_BASE_NO_DODAGID) {
		return NULL;
	}

	uint8_t kd = data[1];
	bool d_flag = (kd >> 6) & 1;
	size_t base_len = d_flag ? LICHEN_RPL_DAO_BASE_LEN : DAO_BASE_NO_DODAGID;

	if (len > base_len) {
		return &data[base_len];
	}
	return NULL;
}

/* ── DODAG Configuration option ────────────────────────────────────────────── */

void lichen_rpl_dodag_config_init(struct lichen_rpl_dodag_config *cfg)
{
	cfg->min_hop_rank_increase = 256;
	cfg->max_rank_increase = 2048;
	cfg->ocp = 1;  /* MRHOF */
	cfg->def_lifetime = 0xFF;
	cfg->lifetime_unit = 60;
	cfg->dio_int_min = 3;
	cfg->dio_int_doublings = 8;
	cfg->dio_redundancy_const = 10;
}

int lichen_rpl_dodag_config_parse(struct lichen_rpl_dodag_config *cfg,
				  const uint8_t *data, size_t len)
{
	if (len < LICHEN_RPL_DODAG_CONFIG_DATA_LEN) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	/* data[0] = A/PCS flags, skipped */
	cfg->dio_int_doublings = data[1];
	cfg->dio_int_min = data[2];
	cfg->dio_redundancy_const = data[3];
	cfg->max_rank_increase = sys_get_be16(&data[4]);
	cfg->min_hop_rank_increase = sys_get_be16(&data[6]);
	cfg->ocp = sys_get_be16(&data[8]);
	/* data[10] = reserved */
	cfg->def_lifetime = data[11];
	cfg->lifetime_unit = sys_get_be16(&data[12]);

	return LICHEN_RPL_OK;
}

int lichen_rpl_dodag_config_write(const struct lichen_rpl_dodag_config *cfg,
				  uint8_t *buf, size_t len)
{
	size_t needed = 2 + LICHEN_RPL_DODAG_CONFIG_DATA_LEN;
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = LICHEN_RPL_OPT_DODAG_CONFIG;
	buf[1] = LICHEN_RPL_DODAG_CONFIG_DATA_LEN;
	buf[2] = 0;  /* A/PCS flags */
	buf[3] = cfg->dio_int_doublings;
	buf[4] = cfg->dio_int_min;
	buf[5] = cfg->dio_redundancy_const;
	sys_put_be16(cfg->max_rank_increase, &buf[6]);
	sys_put_be16(cfg->min_hop_rank_increase, &buf[8]);
	sys_put_be16(cfg->ocp, &buf[10]);
	buf[12] = 0;  /* reserved */
	buf[13] = cfg->def_lifetime;
	sys_put_be16(cfg->lifetime_unit, &buf[14]);

	return (int)needed;
}

/* ── RPL Target option ─────────────────────────────────────────────────────── */

int lichen_rpl_target_parse(struct lichen_rpl_target *target,
			    const uint8_t *data, size_t len)
{
	if (target == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < 2) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	/* data[0] = flags, skipped */
	uint8_t prefix_len = data[1];

	/*
	 * IPv6 prefix must be 1-128 bits. prefix_len=0 would mean no target,
	 * which is invalid for routing purposes (RFC 6550 does not define
	 * a "default route" semantic for RPL Target options).
	 */
	if (prefix_len == 0 || prefix_len > 128) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}

	size_t nbytes = div_ceil(prefix_len, 8);
	if (len < 2 + nbytes) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	target->prefix_len = prefix_len;
	memset(target->prefix, 0, 16);
	memcpy(target->prefix, &data[2], nbytes);

	return LICHEN_RPL_OK;
}

int lichen_rpl_target_write(const struct lichen_rpl_target *target,
			    uint8_t *buf, size_t len)
{
	if (target->prefix_len == 0 || target->prefix_len > 128) {
		return LICHEN_RPL_ERR_INVALID;
	}

	size_t nbytes = div_ceil(target->prefix_len, 8);
	size_t data_len = 2 + nbytes;
	size_t needed = 2 + data_len;

	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = LICHEN_RPL_OPT_RPL_TARGET;
	buf[1] = (uint8_t)data_len;
	buf[2] = 0;  /* flags */
	buf[3] = target->prefix_len;
	memcpy(&buf[4], target->prefix, nbytes);

	return (int)needed;
}

/* ── Transit Information option ────────────────────────────────────────────── */

int lichen_rpl_transit_info_parse(struct lichen_rpl_transit_info *ti,
				  const uint8_t *data, size_t len)
{
	if (ti == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_TRANSIT_INFO_DATA_LEN) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	/* data[0] = E flag, skipped */
	ti->path_control = data[1];
	ti->path_sequence = data[2];
	ti->path_lifetime = data[3];
	memcpy(ti->parent_address, &data[4], 16);

	return LICHEN_RPL_OK;
}

int lichen_rpl_transit_info_write(const struct lichen_rpl_transit_info *ti,
				  uint8_t *buf, size_t len)
{
	size_t needed = 2 + LICHEN_RPL_TRANSIT_INFO_DATA_LEN;
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = LICHEN_RPL_OPT_TRANSIT_INFO;
	buf[1] = LICHEN_RPL_TRANSIT_INFO_DATA_LEN;
	buf[2] = 0;  /* E flag = 0 for internal target */
	buf[3] = ti->path_control;
	buf[4] = ti->path_sequence;
	buf[5] = ti->path_lifetime;
	memcpy(&buf[6], ti->parent_address, 16);

	return (int)needed;
}

/* ── TLV option iterator ───────────────────────────────────────────────────── */

void lichen_rpl_opt_iter_init(struct lichen_rpl_opt_iter *it,
			      const uint8_t *data, size_t len)
{
	it->data = data;
	it->len = len;
	it->pos = 0;
}

int lichen_rpl_opt_iter_next(struct lichen_rpl_opt_iter *it,
			     struct lichen_rpl_raw_opt *out)
{
	while (it->pos < it->len) {
		uint8_t opt_type = it->data[it->pos];

		/* PAD1 is a single byte with no length */
		if (opt_type == LICHEN_RPL_OPT_PAD1) {
			it->pos++;
			continue;
		}

		/* All other options have type + length */
		if (it->pos + 2 > it->len) {
			return LICHEN_RPL_ERR_TOO_SHORT;
		}

		uint8_t opt_len = it->data[it->pos + 1];
		if (it->pos + 2 + opt_len > it->len) {
			return LICHEN_RPL_ERR_OVERRUN;
		}

		out->opt_type = opt_type;
		out->data = &it->data[it->pos + 2];
		out->data_len = opt_len;

		it->pos += 2 + opt_len;
		return LICHEN_RPL_OK;
	}

	/* Exhausted */
	return 1;
}
