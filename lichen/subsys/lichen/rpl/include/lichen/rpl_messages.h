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
#define LICHEN_RPL_OPT_SOLICITED_INFO 7
#define LICHEN_RPL_OPT_PREFIX_INFO   8
#define LICHEN_RPL_OPT_RPL_TARGET_DESCRIPTOR 9
#define LICHEN_RPL_OPT_DIO_TIME      0x12  /**< DIO Time Option (experimental) */
#define LICHEN_RPL_OPT_SCHC_RULE_VERSION 0x13  /**< SCHC Rule Version Option (spec 5.7) */

/* ── SCHC Rule Set Version ─────────────────────────────────────────────────── */

/**
 * Current SCHC Rule Set Version (spec section 5.7):
 *   0 - Reserved (never operational)
 *   1 - Legacy experimental (not interoperable)
 *   2 - RFC 8724 fragmentation profile
 *   3 - Canonical specialized Rule 7 MQTT-SN residue (current)
 */
#define LICHEN_SCHC_RULE_SET_VERSION 3

/* ── ICMPv6 codes for RPL messages ────────────────────────────────────────── */

#define LICHEN_RPL_CODE_DIS      0
#define LICHEN_RPL_CODE_DIO      1
#define LICHEN_RPL_CODE_DAO      2
#define LICHEN_RPL_CODE_DAO_ACK  3

/* ── DIS ───────────────────────────────────────────────────────────────────── */

/** DIS base object size (2 bytes) */
#define LICHEN_RPL_DIS_BASE_LEN  2
/** Solicited Information option payload and complete TLV sizes. */
#define LICHEN_RPL_SOLICITED_INFO_DATA_LEN 19
#define LICHEN_RPL_SOLICITED_INFO_LEN \
	(2U + LICHEN_RPL_SOLICITED_INFO_DATA_LEN)
/** RFC 6550 Section 6.7.9 predicate flags. */
#define LICHEN_RPL_SOLICITED_VERSION_PREDICATE  0x80U
#define LICHEN_RPL_SOLICITED_INSTANCE_PREDICATE 0x40U
#define LICHEN_RPL_SOLICITED_DODAG_PREDICATE    0x20U
#define LICHEN_RPL_SOLICITED_PREDICATE_MASK     0xe0U

/**
 * @brief DIS base object (RFC 6550 section 6.2)
 *
 * Flags are unused on the wire: senders MUST zero them and receivers MUST
 * ignore them. The reserved byte MUST be zero on transmit and is rejected
 * if nonzero on receive.
 */
struct lichen_rpl_dis {
	uint8_t flags;
	uint8_t reserved;
};

/** RFC 6550 Section 6.7.9 Solicited Information option payload. */
struct lichen_rpl_solicited_info {
	uint8_t rpl_instance_id;
	uint8_t flags;
	uint8_t dodag_id[16];
	uint8_t version;
};

/**
 * @brief Parse a DIS from wire bytes.
 *
 * @param dis  Output structure
 * @param data Wire bytes (DIS base and complete option chain)
 * @param len  Length of data
 *
 * The complete option chain is framing-validated. A Solicited Information
 * option must have exactly 19 data bytes and may occur at most once. As RFC
 * 6550 requires, unused base and Solicited Information flag bits are accepted
 * on receive and preserved/ignored rather than interpreted. On every error,
 * @p dis is unchanged.
 * @return 0 on success, negative error code on failure
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_dis_parse(struct lichen_rpl_dis *_Nonnull dis,
			 const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Serialize a DIS to wire bytes.
 *
 * @param dis  DIS to serialize
 * @param buf  Output buffer (at least 2 bytes)
 * @param len  Buffer size
 * @return Number of bytes written (2), or negative error code
 */
int lichen_rpl_dis_write(const struct lichen_rpl_dis *_Nonnull dis,
			 uint8_t *_Nonnull buf, size_t len);

/**
 * Atomically serialize a DIS base plus a pre-encoded option chain.
 *
 * The option chain receives the same strict validation as decode. All input
 * and capacity checks complete before @p buf is changed. @p options may alias
 * @p buf; a nonzero @p options_len requires a non-NULL pointer.
 */
int lichen_rpl_dis_write_with_options(
	const struct lichen_rpl_dis *_Nonnull dis,
	const uint8_t *_Nullable options, size_t options_len,
	uint8_t *_Nonnull buf, size_t len);

/** Parse one 19-byte Solicited Information option payload atomically. */
LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_solicited_info_parse(
	struct lichen_rpl_solicited_info *_Nonnull info,
	const uint8_t *_Nonnull data, size_t len);

/** Serialize one complete Type/Length/Value Solicited Information option. */
int lichen_rpl_solicited_info_write(
	const struct lichen_rpl_solicited_info *_Nonnull info,
	uint8_t *_Nonnull buf, size_t len);

/**
 * @brief Get pointer to options following DIS base.
 *
 * @return Pointer to options, or NULL if no options present.
 */
const uint8_t *_Nullable lichen_rpl_dis_options(const uint8_t *_Nonnull data, size_t len);

/* ── DIO ───────────────────────────────────────────────────────────────────── */

/** DIO base object size (24 bytes) */
#define LICHEN_RPL_DIO_BASE_LEN  24
/** Defined LICHEN extension bit in the DIO Flags octet. */
#define LICHEN_RPL_DIO_FLAG_GATEWAY_CENTRIC 0x01U

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
 * The complete trailing option chain is framing-validated. Known typed
 * options are validated strictly, and duplicate singleton options are
 * rejected. On every error, @p dio is left unchanged.
 *
 * @param data Wire bytes (DIO base and any options, at least 24 bytes)
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
 * @brief Atomically serialize a DIO base and a pre-encoded option chain.
 *
 * The option chain receives the same strict validation as decode. All input
 * and capacity checks complete before @p buf is changed. @p options may alias
 * @p buf; a nonzero @p options_len requires a non-NULL pointer.
 *
 * @return Total bytes written, or a negative error code.
 */
int lichen_rpl_dio_write_with_options(
	const struct lichen_rpl_dio *_Nonnull dio,
	const uint8_t *_Nullable options, size_t options_len,
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
/** DAO base object size without DODAGID (4 bytes). */
#define LICHEN_RPL_DAO_BASE_NO_DODAGID_LEN 4
/** Temporary DAO Origin Signature option type. */
#define LICHEN_RPL_OPT_DAO_ORIGIN_SIGNATURE 0x12
/** DAO Origin Sequence (8) plus Schnorr48 (48). */
#define LICHEN_RPL_DAO_ORIGIN_SIGNATURE_DATA_LEN 56

/**
 * @brief DAO base object (RFC 6550 section 6.4)
 *
 * DODAGID is populated when the D flag is set. For D=0 wire messages, callers
 * supply the active DODAG context separately and this field is zeroed.
 */
struct lichen_rpl_dao {
	uint8_t rpl_instance_id;
	bool ack_requested;
	bool has_dodag_id;
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
 * @param buf  Output buffer (at least 4 bytes for D=0 or 20 bytes for D=1)
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
	size_t base_len = d_flag ? LICHEN_RPL_DAO_BASE_LEN :
		LICHEN_RPL_DAO_BASE_NO_DODAGID_LEN;
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
	bool has_dodag_id;
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
	if (data == NULL || total_len < 4U) {
		return 0;
	}
	size_t base_len = (data[1] & 0x80U) != 0U ? 20U : 4U;
	return total_len > base_len ? total_len - base_len : 0U;
}

/* ── DODAG Configuration option (type 4) ──────────────────────────────────── */

/** DODAG Config option data length (excluding type/length bytes) */
#define LICHEN_RPL_DODAG_CONFIG_DATA_LEN  14

/**
 * @brief DODAG Configuration option (RFC 6550 section 6.7.6)
 */
struct lichen_rpl_dodag_config {
	uint8_t pcs;              /**< Path Control Size (0..7) */
	bool authentication_enabled; /**< RFC 6550 A flag */
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

/** Canonical LICHEN RPL Target Data Length: flags + prefix length + /128. */
#define LICHEN_RPL_TARGET_DATA_LEN 18U

/**
 * @brief RPL Target option (RFC 6550 section 6.7.7)
 *
 * Advertises a /128 target address in a DAO. The LICHEN profile accepts only
 * Data Length 18, zero flags, and Prefix Length 128.
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

/** Canonical LICHEN Transit Information Data Length (with Parent Address). */
#define LICHEN_RPL_TRANSIT_INFO_DATA_LEN  20

/**
 * @brief Transit Information option (RFC 6550 6.7.8).
 *
 * E (bit 7) marks external reachability; it is not a parent-presence bit.
 * The exact Data Length always conveys the mandatory Parent Address. All
 * remaining flag bits are reserved and must be zero.
 */
struct lichen_rpl_transit_info {
	bool external;
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

/* ── DIO Time Option (type TBD) ────────────────────────────────────────────── */

/** DIO Time Option data length (excluding type/length bytes) */
#define LICHEN_RPL_DIO_TIME_DATA_LEN  6

/**
 * @brief DIO Time Option for time synchronization.
 *
 * Wire format: Type(1) + Length(1) + Stratum(1) + Reserved(1) + Timestamp(4).
 * Total 8 bytes. Timestamp is Unix epoch seconds (big-endian).
 */
struct lichen_rpl_dio_time {
	uint8_t stratum;      /**< Time stratum (0=no sync, 4=GNSS) */
	uint32_t timestamp;   /**< Unix epoch seconds */
};

/**
 * @brief Parse DIO Time Option from option data (after type/length bytes).
 *
 * @param dt   Output structure
 * @param data Option data (6 bytes: stratum + reserved + timestamp)
 * @param len  Length of data
 * @return 0 on success, negative error code on failure
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_dio_time_parse(struct lichen_rpl_dio_time *_Nonnull dt,
			      const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Serialize DIO Time Option as a complete TLV option.
 *
 * @param dt  DIO Time Option to serialize
 * @param buf Output buffer (at least 8 bytes)
 * @param len Buffer size
 * @return Bytes written (8 = 2 + 6), or negative error code
 */
int lichen_rpl_dio_time_write(const struct lichen_rpl_dio_time *_Nonnull dt,
			      uint8_t *_Nonnull buf, size_t len);

/* ── SCHC Rule Version Option (type 0x13) ──────────────────────────────────── */

/** SCHC Rule Version Option data length (excluding type/length bytes) */
#define LICHEN_RPL_SCHC_RULE_VERSION_DATA_LEN 1

/**
 * @brief SCHC Rule Version Option for DIO messages (spec section 5.7).
 *
 * Advertises the sender's SCHC rule set version. Nodes should only join
 * a DODAG if their rule set version matches the advertised version.
 *
 * Wire format: Type(1B) + Length(1B) + Version(1B) = 3 bytes total.
 */
struct lichen_rpl_schc_rule_version {
	uint8_t version;  /**< Rule set version (0 reserved, 3 current) */
};

/**
 * @brief Parse SCHC Rule Version Option from wire bytes.
 *
 * @param rv   Output structure
 * @param data Wire bytes starting with Type field (3 bytes required)
 * @param len  Length of data
 * @return 0 on success, negative error code on failure
 *
 * @note Returns LICHEN_RPL_ERR_TOO_SHORT if len < 3
 * @note Returns LICHEN_RPL_ERR_BAD_OPT if type != 0x13 or length != 1
 */
LICHEN_WARN_UNUSED_RESULT
int lichen_rpl_schc_rule_version_parse(struct lichen_rpl_schc_rule_version *_Nonnull rv,
				       const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Serialize SCHC Rule Version Option as a complete TLV option.
 *
 * @param rv  SCHC Rule Version Option to serialize
 * @param buf Output buffer (at least 3 bytes)
 * @param len Buffer size
 * @return Bytes written (3 = Type + Length + Version), or negative error code
 */
int lichen_rpl_schc_rule_version_write(const struct lichen_rpl_schc_rule_version *_Nonnull rv,
				       uint8_t *_Nonnull buf, size_t len);

/**
 * @brief Check if two SCHC rule set versions are compatible.
 *
 * Per spec section 5.7, versions are compatible only if:
 * 1. They are equal
 * 2. Both are operationally supported (currently only version 3)
 *
 * @param local  Local rule set version
 * @param remote Remote rule set version
 * @return true if compatible, false otherwise
 */
static inline bool lichen_schc_versions_compatible(uint8_t local, uint8_t remote)
{
	/* Only version 3 is operationally supported */
	return local == remote && local == LICHEN_SCHC_RULE_SET_VERSION;
}

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
