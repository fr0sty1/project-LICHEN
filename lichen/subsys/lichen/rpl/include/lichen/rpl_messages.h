/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/rpl_messages.h
 * @brief RPL control message codecs - DIO / DAO / DIS / DAO-ACK (RFC 6550)
 *
 * Wire layout matches RFC 6550. All integer fields are big-endian.
 * No allocation - all parsing operates on caller-provided buffers.
 */

#ifndef LICHEN_RPL_MESSAGES_H_
#define LICHEN_RPL_MESSAGES_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef LICHEN_WARN_UNUSED_RESULT
#if defined(__GNUC__) || defined(__clang__)
#define LICHEN_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define LICHEN_WARN_UNUSED_RESULT
#endif
#endif

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ───────────────────────────────────────────────────────────── */

#define LICHEN_RPL_OK              0
#define LICHEN_RPL_ERR_TOO_SHORT  -1
#define LICHEN_RPL_ERR_OVERRUN    -2
#define LICHEN_RPL_ERR_BAD_OPT    -3
#define LICHEN_RPL_ERR_BAD_RT     -4
#define LICHEN_RPL_ERR_BUF_SMALL  -5
#define LICHEN_RPL_ERR_INVALID    -6  /**< NULL pointer or invalid argument */
#define LICHEN_RPL_ERR_FULL       -7  /**< Table or buffer is full */
#define LICHEN_RPL_ERR_NOT_FOUND  -8  /**< Requested entry does not exist */

/* ── Option type bytes ─────────────────────────────────────────────────────── */

#define LICHEN_RPL_OPT_PAD1          0
#define LICHEN_RPL_OPT_PADN          1
#define LICHEN_RPL_OPT_DAG_METRIC    2
#define LICHEN_RPL_OPT_DODAG_CONFIG  4
#define LICHEN_RPL_OPT_RPL_TARGET    5
#define LICHEN_RPL_OPT_TRANSIT_INFO  6
#define LICHEN_RPL_OPT_PREFIX_INFO   8
#define LICHEN_RPL_OPT_RPL_TARGET_DESCRIPTOR 9

/* ── ICMPv6 codes for RPL messages ────────────────────────────────────────── */

#define LICHEN_RPL_CODE_DIS      0
#define LICHEN_RPL_CODE_DIO      1
#define LICHEN_RPL_CODE_DAO      2
#define LICHEN_RPL_CODE_DAO_ACK  3

/* ── DIO ───────────────────────────────────────────────────────────────────── */

/** DIO base object size (24 bytes) */
#define LICHEN_RPL_DIO_BASE_LEN  24

/**
 * @brief DIO base object (RFC 6550 section 6.3)
 *
 * Decoded from the ICMPv6 body after the 4-byte ICMPv6 type/code/checksum.
 * In a full IPv6 packet, DIO base starts at offset 44 (40 IPv6 + 4 ICMPv6).
 */
struct lichen_rpl_dio {
	uint8_t rpl_instance_id;
	uint8_t version;
	uint16_t rank;
	bool grounded;
	uint8_t mode_of_operation;
	uint8_t preference;
	uint8_t dtsn;
	uint8_t flags;
	uint8_t dodag_id[16];
};

/**
 * @brief Parse a DIO from wire bytes.
 *
 * @param dio  Output structure
 * @param data Wire bytes (DIO base, at least 24 bytes)
 * @param len  Length of data
 * @return 0 on success, negative error code on failure
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_dio_parse(struct lichen_rpl_dio *_Nonnull dio,
			 const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Serialize a DIO to wire bytes.
 *
 * @param dio  DIO to serialize
 * @param buf  Output buffer (at least 24 bytes)
 * @param len  Buffer size
 * @return Number of bytes written (24), or negative error code
 */
int lichen_rpl_dio_write(const struct lichen_rpl_dio *_Nonnull dio,
			 uint8_t *_Nonnull buf, size_t len);

/**
 * @brief Get pointer to options following DIO base.
 *
 * @param data The DIO message buffer. MUST be valid for at least @p len bytes.
 *             Caller is responsible for ensuring data/len consistency.
 * @param len  Total length of the DIO message.
 * @return Pointer to options, or NULL if no options present.
 */
const uint8_t *_Nullable lichen_rpl_dio_options(const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Get length of options following DIO base.
 */
static inline size_t lichen_rpl_dio_options_len(size_t total_len)
{
	return (total_len > LICHEN_RPL_DIO_BASE_LEN)
		? (total_len - LICHEN_RPL_DIO_BASE_LEN)
		: 0;
}

/* ── DAO ───────────────────────────────────────────────────────────────────── */

/** DAO base object size with DODAGID present (20 bytes) */
#define LICHEN_RPL_DAO_BASE_LEN  20

/**
 * @brief DAO base object (RFC 6550 section 6.4)
 *
 * DODAGID is populated when the D flag is set. For D=0 wire messages, callers
 * supply the active DODAG context separately and this field is zeroed.
 */
struct lichen_rpl_dao {
	uint8_t rpl_instance_id;
	bool ack_requested;
	uint8_t flags;
	uint8_t dao_sequence;
	uint8_t dodag_id[16];
};

/**
 * @brief Parse a DAO from wire bytes.
 *
 * @param dao  Output structure
 * @param data Wire bytes (4-byte base, plus 16-byte DODAGID when D=1)
 * @param len  Length of data
 * @return 0 on success, negative error code on failure
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_dao_parse(struct lichen_rpl_dao *_Nonnull dao,
			 const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Serialize a DAO to wire bytes.
 *
 * @param dao  DAO to serialize
 * @param buf  Output buffer (at least 20 bytes)
 * @param len  Buffer size
 * @return Number of bytes written (20), or negative error code
 */
int lichen_rpl_dao_write(const struct lichen_rpl_dao *_Nonnull dao,
			 uint8_t *_Nonnull buf, size_t len);

/**
 * @brief Get pointer to options following DAO base.
 */
const uint8_t *_Nullable lichen_rpl_dao_options(const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Get length of options following DAO base.
 *
 * @param data      DAO message bytes (needed to check D-flag)
 * @param total_len Total length of DAO message
 * @return Length of options, or 0 if none
 *
 * @note The D-flag (bit 6 of byte 1) determines whether DODAGID is present:
 *       D=1: base is 20 bytes (with DODAGID)
 *       D=0: base is 4 bytes (no DODAGID)
 */
static inline size_t lichen_rpl_dao_options_len_ex(const uint8_t *_Nullable data,
						   size_t total_len)
{
	if (data == NULL || total_len < 4) {
		return 0;
	}
	/* D-flag is bit 6 of byte 1 */
	bool d_flag = (data[1] >> 6) & 1;
	size_t base_len = d_flag ? LICHEN_RPL_DAO_BASE_LEN : 4;
	return (total_len > base_len) ? (total_len - base_len) : 0;
}

/**
 * @brief Get length of options following DAO base (legacy, assumes D=1).
 * @deprecated Use lichen_rpl_dao_options_len_ex() for D-flag aware calculation.
 */
static inline size_t lichen_rpl_dao_options_len(size_t total_len)
{
	return (total_len > LICHEN_RPL_DAO_BASE_LEN)
		? (total_len - LICHEN_RPL_DAO_BASE_LEN)
		: 0;
}

#define LICHEN_RPL_DAO_ACK_BASE_LEN 4

struct lichen_rpl_dao_ack {
	uint8_t rpl_instance_id;
	uint8_t flags;
	uint8_t dao_sequence;
	uint8_t status;
	uint8_t dodag_id[16];
};

LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_dao_ack_parse(struct lichen_rpl_dao_ack *_Nonnull ack,
			 const uint8_t *_Nonnull data, size_t len);

int lichen_rpl_dao_ack_write(const struct lichen_rpl_dao_ack *_Nonnull ack,
			 uint8_t *_Nonnull buf, size_t len);

const uint8_t *_Nullable lichen_rpl_dao_ack_options(const uint8_t *_Nonnull data, size_t len);

static inline size_t lichen_rpl_dao_ack_options_len_ex(const uint8_t *_Nullable data,
						   size_t total_len)
{
	if (data == NULL || total_len < 4) {
		return 0;
	}
	bool d_flag = (data[1] >> 7) & 1;
	size_t base_len = d_flag ? 20 : 4;
	return (total_len > base_len) ? (total_len - base_len) : 0;
}

/* ── DODAG Configuration option (type 4) ──────────────────────────────────── */

/** DODAG Config option data length (excluding type/length bytes) */
#define LICHEN_RPL_DODAG_CONFIG_DATA_LEN  14

/**
 * @brief DODAG Configuration option (RFC 6550 section 6.7.6)
 */
struct lichen_rpl_dodag_config {
	uint16_t min_hop_rank_increase;
	uint16_t max_rank_increase;
	uint16_t ocp;               /**< Objective Code Point */
	uint8_t def_lifetime;
	uint16_t lifetime_unit;
	uint8_t dio_int_min;
	uint8_t dio_int_doublings;
	uint8_t dio_redundancy_const;
	bool gateway_centric;
};

/**
 * @brief Initialize DODAG config with defaults.
 */
void lichen_rpl_dodag_config_init(struct lichen_rpl_dodag_config *_Nonnull cfg);

/**
 * @brief Parse DODAG config from option data (after type/length bytes).
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_dodag_config_parse(struct lichen_rpl_dodag_config *_Nonnull cfg,
				  const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Serialize DODAG config as a complete TLV option.
 *
 * @return Bytes written (16 = 2 + 14), or negative error code
 */
int lichen_rpl_dodag_config_write(const struct lichen_rpl_dodag_config *_Nonnull cfg,
				  uint8_t *_Nonnull buf, size_t len);

/* ── RPL Target option (type 5) ────────────────────────────────────────────── */

/**
 * @brief RPL Target option (RFC 6550 section 6.7.7)
 *
 * Advertises a /128 target address in a DAO.
 */
struct lichen_rpl_target {
	uint8_t prefix_len;
	uint8_t prefix[16];
};

/**
 * @brief Parse RPL Target from option data (after type/length bytes).
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_target_parse(struct lichen_rpl_target *_Nonnull target,
			    const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Serialize RPL Target as a complete TLV option.
 *
 * @return Bytes written, or negative error code
 */
int lichen_rpl_target_write(const struct lichen_rpl_target *_Nonnull target,
			    uint8_t *_Nonnull buf, size_t len);

/* ── Transit Information option (type 6) ──────────────────────────────────── */

/** Transit Info option data length (with parent address) */
#define LICHEN_RPL_TRANSIT_INFO_DATA_LEN  20

/**
 * @brief Transit Information option (RFC 6550 6.7.8).
 *
 * E flag (bit 7 of first byte after length) = 1 when Parent Address present.
 * LICHEN always uses E=1; aligned with Python/Rust and corrected vectors.
 */
struct lichen_rpl_transit_info {
	uint8_t path_control;
	uint8_t path_sequence;
	uint8_t path_lifetime;
	uint8_t parent_address[16];
};

/**
 * @brief Parse Transit Info from option data (after type/length bytes).
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_transit_info_parse(struct lichen_rpl_transit_info *_Nonnull ti,
				  const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Serialize Transit Info as a complete TLV option.
 *
 * @return Bytes written (22 = 2 + 20), or negative error code
 */
int lichen_rpl_transit_info_write(const struct lichen_rpl_transit_info *_Nonnull ti,
				  uint8_t *_Nonnull buf, size_t len);

/* ── TLV option iterator ───────────────────────────────────────────────────── */

/**
 * @brief Iterator state for parsing RPL TLV options.
 */
struct lichen_rpl_opt_iter {
	const uint8_t *data;
	size_t len;
	size_t pos;
};

/**
 * @brief Single parsed option reference.
 */
struct lichen_rpl_raw_opt {
	uint8_t opt_type;
	const uint8_t *data;  /**< Points into original buffer (after type/len) */
	size_t data_len;
};

/**
 * @brief Initialize an option iterator.
 */
void lichen_rpl_opt_iter_init(struct lichen_rpl_opt_iter *_Nonnull it,
			      const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Get the next option from the iterator.
 *
 * @param it  Iterator
 * @param out Option to populate
 * @return 0 on success, 1 when exhausted, negative error code on parse error
 */
int lichen_rpl_opt_iter_next(struct lichen_rpl_opt_iter *_Nonnull it,
			     struct lichen_rpl_raw_opt *_Nonnull out);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_MESSAGES_H_ */
