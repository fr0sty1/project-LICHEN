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
#include <limits.h>
#include <string.h>
#include <zephyr/sys/byteorder.h>

#include <lichen/rpl_messages.h>

/* ── Helpers ───────────────────────────────────────────────────────────────── */

/* Division rounding up */
/* ── DIS ───────────────────────────────────────────────────────────────────── */

int lichen_rpl_solicited_info_parse(struct lichen_rpl_solicited_info *info,
				    const uint8_t *data, size_t len)
{
	if (info == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len != LICHEN_RPL_SOLICITED_INFO_DATA_LEN) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}

	struct lichen_rpl_solicited_info parsed = {
		.rpl_instance_id = data[0],
		.flags = data[1],
		.version = data[18],
	};
	memcpy(parsed.dodag_id, &data[2], sizeof(parsed.dodag_id));
	*info = parsed;
	return LICHEN_RPL_OK;
}

int lichen_rpl_solicited_info_write(
	const struct lichen_rpl_solicited_info *info, uint8_t *buf, size_t len)
{
	if (info == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_SOLICITED_INFO_LEN) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	uint8_t encoded[LICHEN_RPL_SOLICITED_INFO_LEN];
	encoded[0] = LICHEN_RPL_OPT_SOLICITED_INFO;
	encoded[1] = LICHEN_RPL_SOLICITED_INFO_DATA_LEN;
	encoded[2] = info->rpl_instance_id;
	encoded[3] = info->flags;
	memcpy(&encoded[4], info->dodag_id, sizeof(info->dodag_id));
	encoded[20] = info->version;
	memcpy(buf, encoded, sizeof(encoded));
	return LICHEN_RPL_SOLICITED_INFO_LEN;
}

static int validate_dis_options(const uint8_t *options, size_t options_len)
{
	struct lichen_rpl_opt_iter it;
	struct lichen_rpl_raw_opt opt;
	struct lichen_rpl_solicited_info info;
	bool have_solicited_info = false;
	int ret;

	if (options == NULL && options_len != 0U) {
		return LICHEN_RPL_ERR_INVALID;
	}
	lichen_rpl_opt_iter_init(&it, options, options_len);
	while ((ret = lichen_rpl_opt_iter_next(&it, &opt)) == LICHEN_RPL_OK) {
		if (opt.opt_type == LICHEN_RPL_OPT_SOLICITED_INFO) {
			if (have_solicited_info ||
			    lichen_rpl_solicited_info_parse(&info, opt.data,
						      opt.data_len) != LICHEN_RPL_OK) {
				return LICHEN_RPL_ERR_BAD_OPT;
			}
			have_solicited_info = true;
		}
	}
	return ret == 1 ? LICHEN_RPL_OK : ret;
}

int lichen_rpl_dis_parse(struct lichen_rpl_dis *dis,
			 const uint8_t *data, size_t len)
{
	if (dis == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_DIS_BASE_LEN) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}
	if (data[1] != 0 ||
	    validate_dis_options(len > LICHEN_RPL_DIS_BASE_LEN ?
				 &data[LICHEN_RPL_DIS_BASE_LEN] : NULL,
				 len - LICHEN_RPL_DIS_BASE_LEN) != LICHEN_RPL_OK) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}

	struct lichen_rpl_dis parsed = {
		.flags = data[0],
		.reserved = data[1],
	};
	*dis = parsed;
	return LICHEN_RPL_OK;
}

int lichen_rpl_dis_write_with_options(const struct lichen_rpl_dis *dis,
				      const uint8_t *options,
				      size_t options_len,
				      uint8_t *buf, size_t len)
{
	if (dis == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (dis->reserved != 0 ||
	    options_len > (size_t)INT_MAX - LICHEN_RPL_DIS_BASE_LEN) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}
	int ret = validate_dis_options(options, options_len);
	if (ret != LICHEN_RPL_OK) {
		return ret;
	}
	size_t needed = LICHEN_RPL_DIS_BASE_LEN + options_len;
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	if (options_len != 0U) {
		memmove(&buf[LICHEN_RPL_DIS_BASE_LEN], options, options_len);
	}
	buf[0] = dis->flags;
	buf[1] = 0U;
	return (int)needed;
}

int lichen_rpl_dis_write(const struct lichen_rpl_dis *dis,
			 uint8_t *buf, size_t len)
{
	return lichen_rpl_dis_write_with_options(dis, NULL, 0U, buf, len);
}

const uint8_t *lichen_rpl_dis_options(const uint8_t *data, size_t len)
{
	if (data == NULL) {
		return NULL;
	}
	if (len > LICHEN_RPL_DIS_BASE_LEN) {
		return &data[LICHEN_RPL_DIS_BASE_LEN];
	}
	return NULL;
}

/* ── DIO ───────────────────────────────────────────────────────────────────── */

static int validate_dio_options(const uint8_t *options, size_t options_len)
{
	struct lichen_rpl_opt_iter it;
	struct lichen_rpl_raw_opt opt;
	struct lichen_rpl_dodag_config config;
	struct lichen_rpl_schc_rule_version version;
	bool have_config = false;
	bool have_schc_version = false;
	int ret;

	if (options == NULL && options_len != 0U) {
		return LICHEN_RPL_ERR_INVALID;
	}
	lichen_rpl_opt_iter_init(&it, options, options_len);
	while ((ret = lichen_rpl_opt_iter_next(&it, &opt)) == LICHEN_RPL_OK) {
		switch (opt.opt_type) {
		case LICHEN_RPL_OPT_DODAG_CONFIG:
			if (have_config ||
			    lichen_rpl_dodag_config_parse(&config, opt.data,
						   opt.data_len) != LICHEN_RPL_OK) {
				return LICHEN_RPL_ERR_BAD_OPT;
			}
			have_config = true;
			break;
		case LICHEN_RPL_OPT_SCHC_RULE_VERSION:
			if (have_schc_version ||
			    lichen_rpl_schc_rule_version_parse(&version, opt.data,
							 opt.data_len) != LICHEN_RPL_OK) {
				return LICHEN_RPL_ERR_BAD_OPT;
			}
			have_schc_version = true;
			break;
		default:
			break;
		}
	}
	return ret == 1 ? LICHEN_RPL_OK : LICHEN_RPL_ERR_BAD_OPT;
}

static int validate_dio_fields(const struct lichen_rpl_dio *dio)
{
	if (dio->rpl_instance_id >= 0xc0U || dio->mode_of_operation > 7U ||
	    dio->preference > 7U ||
	    (dio->flags & ~LICHEN_RPL_DIO_FLAG_GATEWAY_CENTRIC) != 0U) {
		return LICHEN_RPL_ERR_INVALID;
	}
	return LICHEN_RPL_OK;
}

int lichen_rpl_dio_parse(struct lichen_rpl_dio *dio,
			 const uint8_t *data, size_t len)
{
	if (dio == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_DIO_BASE_LEN) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	uint8_t gmop = data[4];
	if (data[0] >= 0xc0U || (gmop & 0x40U) != 0U ||
	    (data[6] & ~LICHEN_RPL_DIO_FLAG_GATEWAY_CENTRIC) != 0U ||
	    data[7] != 0U ||
	    validate_dio_options(len > LICHEN_RPL_DIO_BASE_LEN ?
				 &data[LICHEN_RPL_DIO_BASE_LEN] : NULL,
				 len - LICHEN_RPL_DIO_BASE_LEN) != LICHEN_RPL_OK) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}

	struct lichen_rpl_dio parsed = {
		.rpl_instance_id = data[0],
		.version = data[1],
		.rank = sys_get_be16(&data[2]),
		.grounded = ((gmop >> 7) & 1U) != 0U,
		.mode_of_operation = (gmop >> 3) & 0x7U,
		.preference = gmop & 0x7U,
		.dtsn = data[5],
		.flags = data[6],
	};
	memcpy(parsed.dodag_id, &data[8], sizeof(parsed.dodag_id));
	*dio = parsed;

	return LICHEN_RPL_OK;
}

int lichen_rpl_dio_write_with_options(const struct lichen_rpl_dio *dio,
				      const uint8_t *options, size_t options_len,
				      uint8_t *buf, size_t len)
{
	if (dio == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (validate_dio_fields(dio) != LICHEN_RPL_OK ||
	    options_len > (size_t)INT_MAX - LICHEN_RPL_DIO_BASE_LEN) {
		return LICHEN_RPL_ERR_INVALID;
	}
	int ret = validate_dio_options(options, options_len);
	if (ret != LICHEN_RPL_OK) {
		return ret;
	}
	size_t needed = LICHEN_RPL_DIO_BASE_LEN + options_len;
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	uint8_t base[LICHEN_RPL_DIO_BASE_LEN];
	base[0] = dio->rpl_instance_id;
	base[1] = dio->version;
	sys_put_be16(dio->rank, &base[2]);
	base[4] = (uint8_t)(((dio->grounded ? 1U : 0U) << 7U) |
			    (dio->mode_of_operation << 3U) | dio->preference);
	base[5] = dio->dtsn;
	base[6] = dio->flags;
	base[7] = 0U;
	memcpy(&base[8], dio->dodag_id, sizeof(dio->dodag_id));

	if (options_len != 0U) {
		memmove(&buf[LICHEN_RPL_DIO_BASE_LEN], options, options_len);
	}
	memcpy(buf, base, sizeof(base));
	return (int)needed;
}

int lichen_rpl_dio_write(const struct lichen_rpl_dio *dio,
			 uint8_t *buf, size_t len)
{
	return lichen_rpl_dio_write_with_options(dio, NULL, 0U, buf, len);
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

static int validate_dao_options(const uint8_t *data, size_t len, size_t base_len)
{
	bool have_signature = false;
	size_t pos = base_len;

	while (pos < len) {
		uint8_t type = data[pos];

		if (type == LICHEN_RPL_OPT_PAD1) {
			if (have_signature) {
				return LICHEN_RPL_ERR_BAD_OPT;
			}
			pos++;
			continue;
		}
		if (pos + 2U > len) {
			return LICHEN_RPL_ERR_BAD_OPT;
		}
		size_t data_len = data[pos + 1U];
		size_t end = pos + 2U + data_len;
		if (end > len || have_signature) {
			return LICHEN_RPL_ERR_BAD_OPT;
		}

		switch (type) {
		case LICHEN_RPL_OPT_RPL_TARGET:
			if (data_len != LICHEN_RPL_TARGET_DATA_LEN || data[pos + 2U] != 0U) {
				return LICHEN_RPL_ERR_BAD_OPT;
			}
			break;
		case LICHEN_RPL_OPT_TRANSIT_INFO:
			if (data_len != LICHEN_RPL_TRANSIT_INFO_DATA_LEN ||
			    (data[pos + 2U] & 0x7fU) != 0U) {
				return LICHEN_RPL_ERR_BAD_OPT;
			}
			break;
		case LICHEN_RPL_OPT_RPL_TARGET_DESCRIPTOR:
			if (data_len != 4U) {
				return LICHEN_RPL_ERR_BAD_OPT;
			}
			break;
		case LICHEN_RPL_OPT_DAO_ORIGIN_SIGNATURE:
			if (data_len != LICHEN_RPL_DAO_ORIGIN_SIGNATURE_DATA_LEN || end != len) {
				return LICHEN_RPL_ERR_BAD_OPT;
			}
			have_signature = true;
			break;
		default:
			return LICHEN_RPL_ERR_BAD_OPT;
		}
		pos = end;
	}
	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_parse(struct lichen_rpl_dao *dao,
			 const uint8_t *data, size_t len)
{
	if (dao == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	/* Minimum: 4 bytes base without DODAGID */
	if (len < LICHEN_RPL_DAO_BASE_NO_DODAGID_LEN) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	uint8_t kd = data[1];
	bool d_flag = (kd >> 6) & 1;
	if ((kd & 0x3fU) != 0 || data[2] != 0) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}

	/* If D-flag set, DODAGID is present (16 bytes more) */
	if (d_flag && len < LICHEN_RPL_DAO_BASE_LEN) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	size_t base_len = d_flag ? LICHEN_RPL_DAO_BASE_LEN :
		LICHEN_RPL_DAO_BASE_NO_DODAGID_LEN;
	if (validate_dao_options(data, len, base_len) != LICHEN_RPL_OK) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}
	struct lichen_rpl_dao parsed = {
		.rpl_instance_id = data[0],
		.ack_requested = (kd >> 7) & 1,
		.has_dodag_id = d_flag,
		.flags = 0,
		.dao_sequence = data[3],
	};

	if (d_flag) {
		memcpy(parsed.dodag_id, &data[4], sizeof(parsed.dodag_id));
	}
	*dao = parsed;

	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_write(const struct lichen_rpl_dao *dao,
			 uint8_t *buf, size_t len)
{
	if (dao == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (dao->flags != 0) {
		return LICHEN_RPL_ERR_INVALID;
	}
	size_t base_len = dao->has_dodag_id ? LICHEN_RPL_DAO_BASE_LEN :
		LICHEN_RPL_DAO_BASE_NO_DODAGID_LEN;
	if (len < base_len) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	/* K=ack_requested; D follows the explicit DODAGID presence bit. */
	uint8_t kd = ((dao->ack_requested ? 1 : 0) << 7)
		   | ((dao->has_dodag_id ? 1 : 0) << 6)
		   | (dao->flags & 0x3F);

	buf[0] = dao->rpl_instance_id;
	buf[1] = kd;
	buf[2] = 0; /* reserved */
	buf[3] = dao->dao_sequence;
	if (dao->has_dodag_id) {
		memcpy(&buf[4], dao->dodag_id, sizeof(dao->dodag_id));
	}

	return (int)base_len;
}

const uint8_t *lichen_rpl_dao_options(const uint8_t *data, size_t len)
{
	if (data == NULL) {
		return NULL;
	}

	if (len < LICHEN_RPL_DAO_BASE_NO_DODAGID_LEN) {
		return NULL;
	}

	uint8_t kd = data[1];
	bool d_flag = (kd >> 6) & 1;
	size_t base_len = d_flag ? LICHEN_RPL_DAO_BASE_LEN :
		LICHEN_RPL_DAO_BASE_NO_DODAGID_LEN;

	if (len > base_len) {
		return &data[base_len];
	}
	return NULL;
}

int lichen_rpl_dao_ack_parse(struct lichen_rpl_dao_ack *ack,
			 const uint8_t *data, size_t len)
{
	if (ack == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < 4) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	uint8_t d_byte = data[1];
	bool d_flag = (d_byte & 0x80U) != 0U;
	size_t expected_len = d_flag ? 20U : 4U;

	if (len < expected_len) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}
	if ((d_byte & 0x7fU) != 0U) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}

	struct lichen_rpl_opt_iter it;
	struct lichen_rpl_raw_opt raw;
	lichen_rpl_opt_iter_init(&it, &data[expected_len], len - expected_len);
	int opt_ret;
	do {
		opt_ret = lichen_rpl_opt_iter_next(&it, &raw);
	} while (opt_ret == LICHEN_RPL_OK);
	if (opt_ret != 1) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}

	struct lichen_rpl_dao_ack parsed = {
		.rpl_instance_id = data[0],
		.flags = 0,
		.dao_sequence = data[2],
		.status = data[3],
		.has_dodag_id = d_flag,
	};
	if (d_flag) {
		memcpy(parsed.dodag_id, &data[4], sizeof(parsed.dodag_id));
	}
	*ack = parsed;

	return LICHEN_RPL_OK;
}

int lichen_rpl_dao_ack_write(const struct lichen_rpl_dao_ack *ack,
			 uint8_t *buf, size_t len)
{
	if (ack == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (ack->flags != 0U) {
		return LICHEN_RPL_ERR_INVALID;
	}
	bool d_flag = ack->has_dodag_id;
	size_t base_len = d_flag ? 20U : 4U;
	if (len < base_len) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	uint8_t d_byte = d_flag ? 0x80U : 0U;

	buf[0] = ack->rpl_instance_id;
	buf[1] = d_byte;
	buf[2] = ack->dao_sequence;
	buf[3] = ack->status;
	if (d_flag) {
		memcpy(&buf[4], ack->dodag_id, 16);
	}

	return (int)base_len;
}

const uint8_t *lichen_rpl_dao_ack_options(const uint8_t *data, size_t len)
{
	if (data == NULL || len < 4U) {
		return NULL;
	}
	size_t base_len = (data[1] & 0x80U) != 0U ? 20U : 4U;
	if (len > base_len) {
		return &data[base_len];
	}
	return NULL;
}

/* ── DODAG Configuration option ────────────────────────────────────────────── */

void lichen_rpl_dodag_config_init(struct lichen_rpl_dodag_config *cfg)
{
	if (cfg == NULL) {
		return;
	}
	cfg->min_hop_rank_increase = 256;
	cfg->pcs = 0;
	cfg->authentication_enabled = false;
	cfg->max_rank_increase = 2048;
	cfg->ocp = 1;  /* MRHOF */
	cfg->def_lifetime = 0xFF;
	cfg->lifetime_unit = 60;
	cfg->dio_int_min = 12;
	cfg->dio_int_doublings = 8;
	cfg->dio_redundancy_const = 10;
	cfg->gateway_centric = false;
}

int lichen_rpl_dodag_config_parse(struct lichen_rpl_dodag_config *cfg,
				  const uint8_t *data, size_t len)
{
	if (cfg == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len != LICHEN_RPL_DODAG_CONFIG_DATA_LEN) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}
	if ((data[0] & 0x70U) != 0U || data[10] != 0U) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}

	cfg->pcs = data[0] & 0x07U;
	cfg->authentication_enabled = (data[0] & 0x08U) != 0U;
	cfg->gateway_centric = (data[0] & 0x80) != 0;
	cfg->dio_int_doublings = data[1];
	cfg->dio_int_min = data[2];
	cfg->dio_redundancy_const = data[3];
	cfg->max_rank_increase = sys_get_be16(&data[4]);
	cfg->min_hop_rank_increase = sys_get_be16(&data[6]);
	cfg->ocp = sys_get_be16(&data[8]);
	cfg->def_lifetime = data[11];
	cfg->lifetime_unit = sys_get_be16(&data[12]);

	return LICHEN_RPL_OK;
}

int lichen_rpl_dodag_config_write(const struct lichen_rpl_dodag_config *cfg,
				  uint8_t *buf, size_t len)
{
	size_t needed = 2 + LICHEN_RPL_DODAG_CONFIG_DATA_LEN;
	if (cfg == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (cfg->pcs > 7U) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = LICHEN_RPL_OPT_DODAG_CONFIG;
	buf[1] = LICHEN_RPL_DODAG_CONFIG_DATA_LEN;
	buf[2] = (cfg->gateway_centric ? 0x80U : 0U) |
		 (cfg->authentication_enabled ? 0x08U : 0U) | cfg->pcs;
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
	if (target == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len != LICHEN_RPL_TARGET_DATA_LEN) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}
	if (data[0] != 0 || data[1] != 128U) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}

	target->prefix_len = 128U;
	memcpy(target->prefix, &data[2], sizeof(target->prefix));

	return LICHEN_RPL_OK;
}

int lichen_rpl_target_write(const struct lichen_rpl_target *target,
			    uint8_t *buf, size_t len)
{
	if (target == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (target->prefix_len != 128U) {
		return LICHEN_RPL_ERR_INVALID;
	}

	size_t needed = 2U + LICHEN_RPL_TARGET_DATA_LEN;

	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = LICHEN_RPL_OPT_RPL_TARGET;
	buf[1] = LICHEN_RPL_TARGET_DATA_LEN;
	buf[2] = 0;  /* flags */
	buf[3] = target->prefix_len;
	memcpy(&buf[4], target->prefix, sizeof(target->prefix));

	return (int)needed;
}

/* ── Transit Information option ────────────────────────────────────────────── */

int lichen_rpl_transit_info_parse(struct lichen_rpl_transit_info *ti,
				  const uint8_t *data, size_t len)
{
	if (ti == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len != LICHEN_RPL_TRANSIT_INFO_DATA_LEN) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}
	if ((data[0] & 0x7fU) != 0U) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}
	ti->external = (data[0] & 0x80U) != 0U;
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
	if (ti == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = LICHEN_RPL_OPT_TRANSIT_INFO;
	buf[1] = LICHEN_RPL_TRANSIT_INFO_DATA_LEN;
	buf[2] = ti->external ? 0x80U : 0U;
	buf[3] = ti->path_control;
	buf[4] = ti->path_sequence;
	buf[5] = ti->path_lifetime;
	memcpy(&buf[6], ti->parent_address, 16);

	return (int)needed;
}

/* ── DIO Time Option ───────────────────────────────────────────────────────── */

int lichen_rpl_dio_time_parse(struct lichen_rpl_dio_time *dt,
			      const uint8_t *data, size_t len)
{
	if (dt == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < LICHEN_RPL_DIO_TIME_DATA_LEN) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}

	dt->stratum = data[0];
	/* data[1] = reserved, ignored */
	dt->timestamp = sys_get_be32(&data[2]);

	return LICHEN_RPL_OK;
}

int lichen_rpl_dio_time_write(const struct lichen_rpl_dio_time *dt,
			      uint8_t *buf, size_t len)
{
	size_t needed = 2 + LICHEN_RPL_DIO_TIME_DATA_LEN;
	if (dt == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = LICHEN_RPL_OPT_DIO_TIME;
	buf[1] = LICHEN_RPL_DIO_TIME_DATA_LEN;
	buf[2] = dt->stratum;
	buf[3] = 0;  /* reserved */
	sys_put_be32(dt->timestamp, &buf[4]);

	return (int)needed;
}

/* ── SCHC Rule Version Option ──────────────────────────────────────────────── */

int lichen_rpl_schc_rule_version_parse(struct lichen_rpl_schc_rule_version *_Nonnull rv,
				       const uint8_t *_Nonnull data, size_t len)
{
	if (rv == NULL || data == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	/* Expect payload data only (after Type/Length header) */
	if (len < LICHEN_RPL_SCHC_RULE_VERSION_DATA_LEN) {
		return LICHEN_RPL_ERR_TOO_SHORT;
	}
	/* Reject trailing bytes per spec: parser returns no consumed length */
	if (len > LICHEN_RPL_SCHC_RULE_VERSION_DATA_LEN) {
		return LICHEN_RPL_ERR_BAD_OPT;
	}

	rv->version = data[0];
	return LICHEN_RPL_OK;
}

int lichen_rpl_schc_rule_version_write(const struct lichen_rpl_schc_rule_version *rv,
				       uint8_t *buf, size_t len)
{
	size_t needed = 2 + LICHEN_RPL_SCHC_RULE_VERSION_DATA_LEN;
	if (rv == NULL || buf == NULL) {
		return LICHEN_RPL_ERR_INVALID;
	}
	if (len < needed) {
		return LICHEN_RPL_ERR_BUF_SMALL;
	}

	buf[0] = LICHEN_RPL_OPT_SCHC_RULE_VERSION;
	buf[1] = LICHEN_RPL_SCHC_RULE_VERSION_DATA_LEN;
	buf[2] = rv->version;

	return (int)needed;
}

/* ── TLV option iterator ───────────────────────────────────────────────────── */

void lichen_rpl_opt_iter_init(struct lichen_rpl_opt_iter *it,
			      const uint8_t *data, size_t len)
{
	if (it == NULL) {
		return;
	}
	if (data == NULL) {
		len = 0;
	}
	it->data = data;
	it->len = len;
	it->pos = 0;
}

int lichen_rpl_opt_iter_next(struct lichen_rpl_opt_iter *it,
			     struct lichen_rpl_raw_opt *out)
{
	if (it == NULL || out == NULL || (it->data == NULL && it->len > 0)) {
		return LICHEN_RPL_ERR_INVALID;
	}
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
