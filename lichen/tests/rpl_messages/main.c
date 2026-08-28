/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Consume test/vectors/rpl_messages.json through the C RPL codecs.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lichen/rpl_messages.h>

#include "rpl_messages_vectors.h"

static int tests_run;
static int tests_passed;

#define ASSERT_TRUE(cond, msg) do { \
	if (!(cond)) { \
		printf("  FAIL: %s\n", msg); \
		return 0; \
	} \
} while (0)

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", \
		       msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

static int schc_option_valid(const uint8_t *options, size_t options_len)
{
	struct lichen_rpl_opt_iter it;
	struct lichen_rpl_raw_opt opt;
	int ret;
	unsigned int schc_count = 0U;

	lichen_rpl_opt_iter_init(&it, options, options_len);
	while ((ret = lichen_rpl_opt_iter_next(&it, &opt)) == LICHEN_RPL_OK) {
		if (opt.opt_type == LICHEN_RPL_OPT_SCHC_RULE_VERSION) {
			if (opt.data_len != LICHEN_RPL_SCHC_RULE_VERSION_DATA_LEN) {
				return 0;
			}
			schc_count++;
		}
	}
	if (ret < 0) {
		return 0;
	}
	return schc_count == 1U;
}

static int consume_dio(const struct rpl_message_vector *v)
{
	struct lichen_rpl_dio dio;
	struct lichen_rpl_dio parsed;
	uint8_t buf[64];
	uint8_t option[3];
	const uint8_t *options;
	size_t options_len;
	int n;
	int m;
	struct lichen_rpl_schc_rule_version rv;

	memset(&dio, 0, sizeof(dio));
	dio.rpl_instance_id = v->rpl_instance_id;
	dio.version = v->version;
	dio.rank = v->rank;
	dio.grounded = v->grounded;
	dio.mode_of_operation = v->mode_of_operation;
	dio.preference = v->preference;
	dio.dtsn = v->dtsn;
	dio.flags = v->flags;
	memcpy(dio.dodag_id, v->dodag_id, 16);

	if (v->expect_error != NULL) {
		ASSERT_TRUE(strcmp(v->expect_error, "invalid_schc_version_option") == 0,
			    "dio expect_error");
		ASSERT_TRUE(!schc_option_valid(v->options, v->options_len),
			    "malformed SCHC option accepted");
		memset(buf, 0xa5, sizeof(buf));
		ASSERT_EQ(lichen_rpl_dio_write_with_options(&dio, v->options,
				v->options_len, buf, sizeof(buf)),
			  LICHEN_RPL_ERR_BAD_OPT, "malformed DIO encode");
		for (size_t i = 0; i < sizeof(buf); i++) {
			ASSERT_EQ(buf[i], 0xa5, "malformed DIO changed output");
		}
		n = lichen_rpl_dio_write(&dio, buf, sizeof(buf));
		ASSERT_EQ(n, LICHEN_RPL_DIO_BASE_LEN, "DIO base for malformed decode");
		memcpy(&buf[n], v->options, v->options_len);
		memset(&parsed, 0xa5, sizeof(parsed));
		dio = parsed;
		ASSERT_EQ(lichen_rpl_dio_parse(&parsed, buf,
			  (size_t)n + v->options_len), LICHEN_RPL_ERR_BAD_OPT,
			  "malformed DIO options decoded");
		ASSERT_TRUE(memcmp(&parsed, &dio, sizeof(parsed)) == 0,
			    "malformed DIO decode changed output");
		return 1;
	}

	ASSERT_TRUE(v->encoded_len >= LICHEN_RPL_DIO_BASE_LEN, "dio encoded length");
	ASSERT_EQ(lichen_rpl_dio_parse(&parsed, v->encoded, v->encoded_len),
		  LICHEN_RPL_OK, "dio parse");
	ASSERT_EQ(parsed.rpl_instance_id, v->rpl_instance_id, "dio instance");
	ASSERT_EQ(parsed.version, v->version, "dio version");
	ASSERT_EQ(parsed.rank, v->rank, "dio rank");
	ASSERT_EQ(parsed.grounded, v->grounded, "dio grounded");
	ASSERT_EQ(parsed.mode_of_operation, v->mode_of_operation, "dio mop");
	ASSERT_EQ(parsed.preference, v->preference, "dio preference");
	ASSERT_EQ(parsed.dtsn, v->dtsn, "dio dtsn");
	ASSERT_EQ(parsed.flags, v->flags, "dio flags");
	ASSERT_TRUE(memcmp(parsed.dodag_id, v->dodag_id, 16) == 0, "dio dodag_id");

	if (v->schc_version_mode != NULL &&
	    strcmp(v->schc_version_mode, "insert_current") == 0) {
		rv.version = LICHEN_SCHC_RULE_SET_VERSION;
		m = lichen_rpl_schc_rule_version_write(&rv, option, sizeof(option));
		ASSERT_TRUE(m == 3, "SCHC option write");
		options = option;
		options_len = sizeof(option);
	} else {
		ASSERT_TRUE(v->options_len == 3U, "explicit SCHC option length");
		ASSERT_EQ(v->options[0], LICHEN_RPL_OPT_SCHC_RULE_VERSION, "SCHC type");
		ASSERT_EQ(v->options[1], 1, "SCHC length");
		options = v->options;
		options_len = v->options_len;
	}
	n = lichen_rpl_dio_write_with_options(&dio, options, options_len,
					      buf, sizeof(buf));
	ASSERT_EQ((size_t)n, v->encoded_len, "dio encoded size");
	ASSERT_TRUE(memcmp(buf, v->encoded, v->encoded_len) == 0, "dio encode");
	return 1;
}

static int test_dio_strict_atomicity(void)
{
	static const uint8_t valid[] = {
		0x00, 0x01, 0x01, 0x00, 0x91, 0x00, 0x00, 0x00,
		0x02, 0x7d, 0xd5, 0xcf, 0xc6, 0x79, 0xab, 0x63,
		0x7d, 0xd5, 0xcf, 0xc6, 0x79, 0xab, 0x63, 0x42,
		0x13, 0x01, 0x03,
	};
	static const uint8_t config[] = {
		0x04, 0x0e, 0x00, 0x08, 0x0c, 0x0a, 0x08, 0x00,
		0x01, 0x00, 0x00, 0x01, 0x00, 0xff, 0x00, 0x3c,
	};
	struct lichen_rpl_dio expected;
	struct lichen_rpl_dio parsed;
	uint8_t wire[80];
	uint8_t before[sizeof(wire)];
	int ret;

	ASSERT_EQ(lichen_rpl_dio_parse(&expected, valid, sizeof(valid)),
		  LICHEN_RPL_OK, "strict DIO baseline");

#define ASSERT_PARSE_ATOMIC(mutator, length, message) do {                    \
	memcpy(wire, valid, sizeof(valid));                                      \
	mutator;                                                                 \
	memset(&parsed, 0xa5, sizeof(parsed));                                   \
	struct lichen_rpl_dio snapshot = parsed;                                \
	ASSERT_TRUE(lichen_rpl_dio_parse(&parsed, wire, (length)) < 0, message); \
	ASSERT_TRUE(memcmp(&parsed, &snapshot, sizeof(parsed)) == 0,             \
		    "failed DIO parse changed output");                            \
} while (0)

	ASSERT_PARSE_ATOMIC((void)0, LICHEN_RPL_DIO_BASE_LEN - 1U,
			    "short DIO accepted");
	ASSERT_PARSE_ATOMIC(wire[4] |= 0x40U, sizeof(valid),
			    "reserved G/MOP bit accepted");
	ASSERT_PARSE_ATOMIC(wire[6] = 0x80U, sizeof(valid),
			    "reserved flags accepted");
	ASSERT_PARSE_ATOMIC(wire[7] = 1U, sizeof(valid),
			    "reserved octet accepted");
	ASSERT_PARSE_ATOMIC(wire[0] = 0xc0U, sizeof(valid),
			    "local RPLInstanceID accepted");
	ASSERT_PARSE_ATOMIC(wire[25] = 2U, sizeof(valid),
			    "truncated option accepted");

	memcpy(wire, valid, LICHEN_RPL_DIO_BASE_LEN);
	memcpy(&wire[LICHEN_RPL_DIO_BASE_LEN], config, sizeof(config));
	ASSERT_EQ(lichen_rpl_dio_parse(&parsed, wire,
		  LICHEN_RPL_DIO_BASE_LEN + sizeof(config)), LICHEN_RPL_OK,
		  "canonical DODAG Config rejected");
	memcpy(&wire[LICHEN_RPL_DIO_BASE_LEN + sizeof(config)], config,
	       sizeof(config));
	memset(&parsed, 0xa5, sizeof(parsed));
	expected = parsed;
	ASSERT_EQ(lichen_rpl_dio_parse(&parsed, wire,
		  LICHEN_RPL_DIO_BASE_LEN + 2U * sizeof(config)),
		  LICHEN_RPL_ERR_BAD_OPT, "duplicate DODAG Config accepted");
	ASSERT_TRUE(memcmp(&parsed, &expected, sizeof(parsed)) == 0,
		    "duplicate config changed DIO output");
	wire[LICHEN_RPL_DIO_BASE_LEN + 2U] = 0x10U;
	ASSERT_EQ(lichen_rpl_dio_parse(&parsed, wire,
		  LICHEN_RPL_DIO_BASE_LEN + sizeof(config)),
		  LICHEN_RPL_ERR_BAD_OPT, "reserved config flag accepted");

	/* Semantic, option, and capacity errors leave serialized output intact. */
	memset(wire, 0xa5, sizeof(wire));
	memcpy(before, wire, sizeof(wire));
	expected.rpl_instance_id = 0xc0U;
	ret = lichen_rpl_dio_write_with_options(&expected, &valid[24], 3U,
						wire, sizeof(wire));
	ASSERT_EQ(ret, LICHEN_RPL_ERR_INVALID, "invalid instance encoded");
	ASSERT_TRUE(memcmp(wire, before, sizeof(wire)) == 0,
		    "invalid fields changed output");
	ASSERT_EQ(lichen_rpl_dio_parse(&expected, valid, sizeof(valid)),
		  LICHEN_RPL_OK, "restore baseline DIO");
	ret = lichen_rpl_dio_write_with_options(&expected, &valid[24], 3U,
						wire, sizeof(valid) - 1U);
	ASSERT_EQ(ret, LICHEN_RPL_ERR_BUF_SMALL, "short output accepted");
	ASSERT_TRUE(memcmp(wire, before, sizeof(wire)) == 0,
		    "short output changed buffer");

	/* Rank boundaries and the defined flags bit round-trip exactly. */
	for (unsigned int rank_case = 0U; rank_case < 2U; rank_case++) {
		expected.rank = rank_case == 0U ? 0U : UINT16_MAX;
		expected.flags = LICHEN_RPL_DIO_FLAG_GATEWAY_CENTRIC;
		ret = lichen_rpl_dio_write_with_options(&expected, &valid[24], 3U,
						wire, sizeof(wire));
		ASSERT_EQ(ret, (int)sizeof(valid), "rank boundary encode");
		ASSERT_EQ(lichen_rpl_dio_parse(&parsed, wire, (size_t)ret),
			  LICHEN_RPL_OK, "rank boundary parse");
		ASSERT_EQ(parsed.rank, expected.rank, "rank boundary changed");
		ASSERT_EQ(parsed.flags, expected.flags, "defined DIO flag changed");
	}

	/* Options may alias the output without corrupting the option chain. */
	memcpy(wire, &valid[24], 3U);
	ret = lichen_rpl_dio_write_with_options(&expected, wire, 3U,
						wire, sizeof(wire));
	ASSERT_EQ(ret, (int)sizeof(valid), "aliased options encode");
	ASSERT_TRUE(memcmp(&wire[24], &valid[24], 3U) == 0,
		    "aliased option changed");

#undef ASSERT_PARSE_ATOMIC
	return 1;
}

static int consume_dao(const struct rpl_message_vector *v)
{
	struct lichen_rpl_dao parsed;
	struct lichen_rpl_dao dao;
	uint8_t buf[64];
	int n;

	ASSERT_EQ(lichen_rpl_dao_parse(&parsed, v->encoded, v->encoded_len),
		  LICHEN_RPL_OK, "dao parse");
	ASSERT_EQ(parsed.rpl_instance_id, v->rpl_instance_id, "dao instance");
	ASSERT_EQ(parsed.ack_requested, v->ack_requested, "dao ack");
	ASSERT_EQ(parsed.has_dodag_id, v->has_dodag_id, "dao D flag");
	ASSERT_EQ(parsed.dao_sequence, v->dao_sequence, "dao sequence");
	if (!v->has_dodag_id) {
		static const uint8_t zeros[16];

		ASSERT_TRUE(memcmp(parsed.dodag_id, zeros, 16) == 0,
			    "dao D=0 dodag_id zeroed");
	} else {
		ASSERT_TRUE(memcmp(parsed.dodag_id, v->dodag_id, 16) == 0,
			    "dao dodag_id");
	}
	dao = parsed;
	memset(buf, 0xa5, sizeof(buf));
	n = lichen_rpl_dao_write(&dao, buf, sizeof(buf));
	ASSERT_EQ(n, v->has_dodag_id ? LICHEN_RPL_DAO_BASE_LEN :
		  LICHEN_RPL_DAO_BASE_NO_DODAGID_LEN, "dao write base");
	ASSERT_TRUE(memcmp(buf, v->encoded, (size_t)n) == 0, "dao encode");
	ASSERT_EQ(buf[n], 0xa5, "dao write overrun");
	return 1;
}

static int test_dao_boundaries(void)
{
	static const uint8_t short_base[] = { 0, 0, 0 };
	static const uint8_t missing_dodag[] = { 0, 0x40, 0, 1 };
	static const uint8_t reserved_flags[] = { 0, 0x01, 0, 1 };
	static const uint8_t reserved_octet[] = { 0, 0, 1, 1 };
	static const uint8_t truncated_option[] = { 0, 0, 0, 1, 5 };
	static const uint8_t unknown_option[] = { 0, 0, 0, 1, 0xee, 0 };
	struct lichen_rpl_dao parsed;
	struct lichen_rpl_dao before;
	struct lichen_rpl_dao dao = {
		.rpl_instance_id = 1,
		.ack_requested = true,
		.has_dodag_id = false,
		.dao_sequence = 9,
	};
	uint8_t wire[128];
	uint8_t short_out[19];
	int ret;

	memset(&before, 0xa5, sizeof(before));
	parsed = before;
	ASSERT_EQ(lichen_rpl_dao_parse(&parsed, short_base, sizeof(short_base)),
		  LICHEN_RPL_ERR_TOO_SHORT, "dao short base");
	ASSERT_TRUE(memcmp(&parsed, &before, sizeof(parsed)) == 0,
		    "short DAO mutated output");
	parsed = before;
	ASSERT_EQ(lichen_rpl_dao_parse(&parsed, missing_dodag, sizeof(missing_dodag)),
		  LICHEN_RPL_ERR_TOO_SHORT, "dao missing DODAGID");
	ASSERT_TRUE(memcmp(&parsed, &before, sizeof(parsed)) == 0,
		    "missing DODAGID mutated output");
	parsed = before;
	ASSERT_EQ(lichen_rpl_dao_parse(&parsed, reserved_flags, sizeof(reserved_flags)),
		  LICHEN_RPL_ERR_BAD_OPT, "dao reserved flags");
	ASSERT_TRUE(memcmp(&parsed, &before, sizeof(parsed)) == 0,
		    "reserved flags mutated output");
	parsed = before;
	ASSERT_EQ(lichen_rpl_dao_parse(&parsed, reserved_octet, sizeof(reserved_octet)),
		  LICHEN_RPL_ERR_BAD_OPT, "dao reserved octet");
	ASSERT_TRUE(memcmp(&parsed, &before, sizeof(parsed)) == 0,
		    "reserved octet mutated output");
	parsed = before;
	ASSERT_EQ(lichen_rpl_dao_parse(&parsed, truncated_option, sizeof(truncated_option)),
		  LICHEN_RPL_ERR_BAD_OPT, "dao truncated option");
	ASSERT_TRUE(memcmp(&parsed, &before, sizeof(parsed)) == 0,
		    "truncated option mutated output");
	parsed = before;
	ASSERT_EQ(lichen_rpl_dao_parse(&parsed, unknown_option, sizeof(unknown_option)),
		  LICHEN_RPL_ERR_BAD_OPT, "dao unknown option");
	ASSERT_TRUE(memcmp(&parsed, &before, sizeof(parsed)) == 0,
		    "unknown option mutated output");

	/* A framed signature is accepted only as the final exact-length option. */
	memset(wire, 0, sizeof(wire));
	wire[3] = 1;
	wire[4] = LICHEN_RPL_OPT_DAO_ORIGIN_SIGNATURE;
	wire[5] = LICHEN_RPL_DAO_ORIGIN_SIGNATURE_DATA_LEN;
	ASSERT_EQ(lichen_rpl_dao_parse(&parsed, wire,
		  4U + 2U + LICHEN_RPL_DAO_ORIGIN_SIGNATURE_DATA_LEN),
		  LICHEN_RPL_OK, "dao terminal signature");
	wire[4U + 2U + LICHEN_RPL_DAO_ORIGIN_SIGNATURE_DATA_LEN] = LICHEN_RPL_OPT_PAD1;
	ASSERT_EQ(lichen_rpl_dao_parse(&parsed, wire,
		  4U + 3U + LICHEN_RPL_DAO_ORIGIN_SIGNATURE_DATA_LEN),
		  LICHEN_RPL_ERR_BAD_OPT, "dao nonterminal signature");
	wire[5]--;
	ASSERT_EQ(lichen_rpl_dao_parse(&parsed, wire,
		  4U + 2U + LICHEN_RPL_DAO_ORIGIN_SIGNATURE_DATA_LEN - 1U),
		  LICHEN_RPL_ERR_BAD_OPT, "dao short signature");

	memset(wire, 0xa5, sizeof(wire));
	ret = lichen_rpl_dao_write(&dao, wire, LICHEN_RPL_DAO_BASE_NO_DODAGID_LEN);
	ASSERT_EQ(ret, LICHEN_RPL_DAO_BASE_NO_DODAGID_LEN, "dao exact D=0 write");
	ASSERT_EQ(wire[1], 0x80, "dao D=0 K flag");
	ASSERT_EQ(wire[4], 0xa5, "dao D=0 write overrun");
	dao.has_dodag_id = true;
	memset(short_out, 0xa5, sizeof(short_out));
	ASSERT_EQ(lichen_rpl_dao_write(&dao, short_out, sizeof(short_out)),
		  LICHEN_RPL_ERR_BUF_SMALL, "dao short D=1 write");
	for (size_t i = 0; i < sizeof(short_out); i++) {
		ASSERT_EQ(short_out[i], 0xa5, "short DAO write mutated output");
	}
	return 1;
}

static int consume_dis(const struct rpl_message_vector *v)
{
	struct lichen_rpl_dis parsed;
	struct lichen_rpl_dis dis;
	struct lichen_rpl_solicited_info info;
	uint8_t buf[64];
	int n;
	int ret;

	memset(&parsed, 0xa5, sizeof(parsed));
	ret = lichen_rpl_dis_parse(&parsed, v->encoded, v->encoded_len);
	if (v->expect_error != NULL) {
		if (strcmp(v->expect_error, "too_short") == 0) {
			ASSERT_EQ(ret, LICHEN_RPL_ERR_TOO_SHORT, "dis too_short");
		} else if (strcmp(v->expect_error, "nonzero_reserved") == 0) {
			ASSERT_EQ(ret, LICHEN_RPL_ERR_BAD_OPT, "dis reserved");
		} else {
			printf("  FAIL: unknown dis expect_error %s\n", v->expect_error);
			return 0;
		}
		return 1;
	}

	ASSERT_EQ(ret, LICHEN_RPL_OK, "dis parse");
	ASSERT_EQ(parsed.flags, v->flags, "dis flags");
	ASSERT_EQ(parsed.reserved, v->reserved, "dis reserved");
	if (v->has_solicited_information) {
		ASSERT_EQ(v->options_len, LICHEN_RPL_SOLICITED_INFO_LEN,
			  "solicited option length");
		ASSERT_EQ(v->options[0], LICHEN_RPL_OPT_SOLICITED_INFO,
			  "solicited option type");
		ASSERT_EQ(v->options[1], LICHEN_RPL_SOLICITED_INFO_DATA_LEN,
			  "solicited data length");
		ASSERT_EQ(lichen_rpl_solicited_info_parse(
				  &info, &v->options[2], v->options[1]),
			  LICHEN_RPL_OK, "solicited parse");
		ASSERT_EQ(info.rpl_instance_id, v->solicited_rpl_instance_id,
			  "solicited instance");
		ASSERT_EQ(info.flags, v->solicited_flags, "solicited flags");
		ASSERT_TRUE(memcmp(info.dodag_id, v->solicited_dodag_id, 16) == 0,
			    "solicited DODAGID");
		ASSERT_EQ(info.version, v->solicited_version,
			  "solicited version");
	}

	memset(&dis, 0, sizeof(dis));
	dis.flags = v->flags;
	dis.reserved = v->reserved;
	n = lichen_rpl_dis_write_with_options(
		&dis, v->options, v->options_len, buf, sizeof(buf));
	ASSERT_TRUE(n == (int)v->encoded_len, "dis write");
	ASSERT_TRUE(memcmp(buf, v->encoded, v->encoded_len) == 0,
		    "dis encode");
	return 1;
}

static int test_dis_strict_atomicity(void)
{
	struct lichen_rpl_solicited_info info = {
		.rpl_instance_id = 7,
		.flags = 0xff,
		.version = 9,
	};
	struct lichen_rpl_solicited_info parsed_info;
	struct lichen_rpl_solicited_info before_info;
	struct lichen_rpl_dis dis = { .flags = 0, .reserved = 0 };
	struct lichen_rpl_dis parsed;
	struct lichen_rpl_dis before;
	uint8_t option[LICHEN_RPL_SOLICITED_INFO_LEN];
	uint8_t wire[LICHEN_RPL_DIS_BASE_LEN + LICHEN_RPL_SOLICITED_INFO_LEN];
	uint8_t duplicate[LICHEN_RPL_DIS_BASE_LEN +
			  2U * LICHEN_RPL_SOLICITED_INFO_LEN];
	uint8_t short_option[2U + 2U + 18U] = { 0 };
	uint8_t unknown[] = { 0, 0, LICHEN_RPL_OPT_PAD1, 0xee, 1, 0xaa };
	uint8_t short_out[LICHEN_RPL_SOLICITED_INFO_LEN - 1U];
	int ret;

	memset(info.dodag_id, 0x22, sizeof(info.dodag_id));
	ASSERT_EQ(lichen_rpl_solicited_info_write(&info, option, sizeof(option)),
		  LICHEN_RPL_SOLICITED_INFO_LEN, "solicited encode");
	ASSERT_EQ(option[0], LICHEN_RPL_OPT_SOLICITED_INFO, "solicited type");
	ASSERT_EQ(option[1], LICHEN_RPL_SOLICITED_INFO_DATA_LEN,
		  "solicited length");
	ASSERT_EQ(lichen_rpl_solicited_info_parse(
			  &parsed_info, &option[2], option[1]),
		  LICHEN_RPL_OK, "solicited decode");
	ASSERT_EQ(parsed_info.flags, 0xff, "unused solicited flags preserved");
	ASSERT_TRUE(memcmp(&parsed_info, &info, sizeof(info)) == 0,
		    "solicited round trip");

	memset(&parsed_info, 0xa5, sizeof(parsed_info));
	before_info = parsed_info;
	ASSERT_EQ(lichen_rpl_solicited_info_parse(
			  &parsed_info, &option[2], 18),
		  LICHEN_RPL_ERR_BAD_OPT, "short solicited payload rejected");
	ASSERT_TRUE(memcmp(&parsed_info, &before_info, sizeof(parsed_info)) == 0,
		    "failed solicited parse mutated output");
	memset(short_out, 0xa5, sizeof(short_out));
	ASSERT_EQ(lichen_rpl_solicited_info_write(
			  &info, short_out, sizeof(short_out)),
		  LICHEN_RPL_ERR_BUF_SMALL, "short solicited output rejected");
	for (size_t i = 0; i < sizeof(short_out); i++) {
		ASSERT_EQ(short_out[i], 0xa5, "short solicited output mutated");
	}

	ret = lichen_rpl_dis_write_with_options(
		&dis, option, sizeof(option), wire, sizeof(wire));
	ASSERT_EQ(ret, (int)sizeof(wire), "DIS with solicited option encoded");
	ASSERT_EQ(lichen_rpl_dis_parse(&parsed, wire, sizeof(wire)),
		  LICHEN_RPL_OK, "DIS with solicited option decoded");

	/* RFC reserved/unused flags are ignored on receive, but Reserved byte is
	 * always rejected. All failures leave caller-owned output unchanged. */
	memset(&parsed, 0xa5, sizeof(parsed));
	before = parsed;
	wire[1] = 1;
	ASSERT_EQ(lichen_rpl_dis_parse(&parsed, wire, sizeof(wire)),
		  LICHEN_RPL_ERR_BAD_OPT, "nonzero DIS Reserved rejected");
	ASSERT_TRUE(memcmp(&parsed, &before, sizeof(parsed)) == 0,
		    "Reserved rejection mutated DIS output");
	wire[1] = 0;

	short_option[2] = LICHEN_RPL_OPT_SOLICITED_INFO;
	short_option[3] = 18;
	ASSERT_EQ(lichen_rpl_dis_parse(&parsed, short_option, sizeof(short_option)),
		  LICHEN_RPL_ERR_BAD_OPT, "18-byte solicited option rejected");
	ASSERT_TRUE(memcmp(&parsed, &before, sizeof(parsed)) == 0,
		    "short option rejection mutated DIS output");

	duplicate[0] = 0;
	duplicate[1] = 0;
	memcpy(&duplicate[2], option, sizeof(option));
	memcpy(&duplicate[2 + sizeof(option)], option, sizeof(option));
	ASSERT_EQ(lichen_rpl_dis_parse(&parsed, duplicate, sizeof(duplicate)),
		  LICHEN_RPL_ERR_BAD_OPT, "duplicate solicited option rejected");
	ASSERT_TRUE(memcmp(&parsed, &before, sizeof(parsed)) == 0,
		    "duplicate rejection mutated DIS output");
	ASSERT_EQ(lichen_rpl_dis_parse(&parsed, unknown, sizeof(unknown)),
		  LICHEN_RPL_OK, "padding and unknown option accepted");

	memset(short_out, 0xa5, sizeof(short_out));
	ASSERT_EQ(lichen_rpl_dis_write_with_options(
			  &dis, option, sizeof(option), short_out,
			  sizeof(short_out)),
		  LICHEN_RPL_ERR_BUF_SMALL, "short DIS output rejected");
	for (size_t i = 0; i < sizeof(short_out); i++) {
		ASSERT_EQ(short_out[i], 0xa5, "short DIS output mutated");
	}

	/* Alias safety: an option already at the output base is shifted only
	 * after complete validation and capacity checks. */
	memcpy(wire, option, sizeof(option));
	ASSERT_EQ(lichen_rpl_dis_write_with_options(
			  &dis, wire, sizeof(option), wire, sizeof(wire)),
		  (int)sizeof(wire), "aliased DIS output encoded");
	ASSERT_EQ(wire[0], 0, "aliased DIS flags");
	ASSERT_EQ(wire[1], 0, "aliased DIS Reserved");
	ASSERT_TRUE(memcmp(&wire[2], option, sizeof(option)) == 0,
		    "aliased option preserved");
	return 1;
}

static int consume_dao_ack(const struct rpl_message_vector *v)
{
	struct lichen_rpl_dao_ack parsed;
	struct lichen_rpl_dao_ack ack;
	uint8_t buf[32];
	int n;
	int ret;

	memset(&parsed, 0xa5, sizeof(parsed));
	ret = lichen_rpl_dao_ack_parse(&parsed, v->encoded, v->encoded_len);
	if (v->expect_error != NULL) {
		if (strcmp(v->expect_error, "too_short") == 0 ||
		    strcmp(v->expect_error, "missing_dodagid") == 0) {
			ASSERT_EQ(ret, LICHEN_RPL_ERR_TOO_SHORT, "dao-ack error");
		} else if (strcmp(v->expect_error, "nonzero_reserved_flags") == 0 ||
			   strcmp(v->expect_error, "malformed_options") == 0) {
			ASSERT_EQ(ret, LICHEN_RPL_ERR_BAD_OPT, "dao-ack malformed");
		} else {
			printf("  FAIL: unknown dao_ack expect_error %s\n",
			       v->expect_error);
			return 0;
		}
		for (size_t i = 0; i < sizeof(parsed); i++) {
			ASSERT_EQ(((const uint8_t *)&parsed)[i], 0xa5,
				  "invalid DAO-ACK mutated output");
		}
		if (strcmp(v->expect_error, "nonzero_reserved_flags") == 0) {
			memset(&ack, 0, sizeof(ack));
			memset(buf, 0xa5, sizeof(buf));
			ack.flags = 1U;
			ASSERT_EQ(lichen_rpl_dao_ack_write(&ack, buf, sizeof(buf)),
				  LICHEN_RPL_ERR_INVALID, "DAO-ACK writer accepted flags");
			for (size_t i = 0; i < sizeof(buf); i++) {
				ASSERT_EQ(buf[i], 0xa5, "invalid DAO-ACK write mutated output");
			}
		}
		return 1;
	}

	ASSERT_EQ(ret, LICHEN_RPL_OK, "dao-ack parse");
	ASSERT_EQ(parsed.rpl_instance_id, v->rpl_instance_id, "dao-ack instance");
	ASSERT_EQ(parsed.dao_sequence, v->dao_sequence, "dao-ack sequence");
	ASSERT_EQ(parsed.status, v->status, "dao-ack status");
	ASSERT_EQ(parsed.has_dodag_id, v->has_dodag_id, "dao-ack D flag");
	memset(&ack, 0, sizeof(ack));
	ack.rpl_instance_id = v->rpl_instance_id;
	ack.flags = v->flags;
	ack.dao_sequence = v->dao_sequence;
	ack.status = v->status;
	ack.has_dodag_id = v->has_dodag_id;
	if (v->has_dodag_id) {
		ASSERT_TRUE(memcmp(parsed.dodag_id, v->dodag_id, 16) == 0,
			    "dao-ack dodag_id");
		memcpy(ack.dodag_id, v->dodag_id, 16);
	} else {
		static const uint8_t zeros[16];

		ASSERT_TRUE(memcmp(parsed.dodag_id, zeros, 16) == 0,
			    "dao-ack D=0 dodag_id zeroed");
	}
	n = lichen_rpl_dao_ack_write(&ack, buf, sizeof(buf));
	ASSERT_EQ((size_t)n, v->encoded_len, "dao-ack encoded size");
	ASSERT_TRUE(memcmp(buf, v->encoded, v->encoded_len) == 0,
		    "dao-ack encode");
	buf[n] = LICHEN_RPL_OPT_PAD1;
	ASSERT_EQ(lichen_rpl_dao_ack_parse(&parsed, buf, (size_t)n + 1U),
		  LICHEN_RPL_OK, "dao-ack Pad1 option parse");
	ASSERT_TRUE(lichen_rpl_dao_ack_options(buf, (size_t)n + 1U) == &buf[n],
		    "dao-ack options pointer");
	ASSERT_EQ(lichen_rpl_dao_ack_options_len_ex(buf, (size_t)n + 1U), 1U,
		  "dao-ack options length");
	return 1;
}

static int consume_dodag_config_option(const struct rpl_message_vector *v)
{
	struct lichen_rpl_dodag_config config;
	uint8_t encoded[16];
	int ret;

	memset(&config, 0xa5, sizeof(config));
	ret = lichen_rpl_dodag_config_parse(&config, &v->encoded[2],
					    v->encoded_len - 2U);
	if (v->expect_error != NULL) {
		ASSERT_TRUE(strcmp(v->expect_error, "invalid_length") == 0 ||
			    strcmp(v->expect_error, "nonzero_reserved_flags") == 0 ||
			    strcmp(v->expect_error, "nonzero_reserved_octet") == 0,
			    "DODAG config expect_error");
		ASSERT_EQ(ret, LICHEN_RPL_ERR_BAD_OPT, "invalid DODAG config accepted");
		/* Parse validation precedes writes to the caller's output. */
		for (size_t i = 0; i < sizeof(config); i++) {
			ASSERT_EQ(((const uint8_t *)&config)[i], 0xa5,
				  "invalid DODAG config mutated output");
		}
		return 1;
	}

	ASSERT_EQ(ret, LICHEN_RPL_OK, "DODAG config parse");
	ASSERT_EQ(config.pcs, v->pcs, "DODAG config PCS");
	ASSERT_EQ(config.authentication_enabled, v->authentication_enabled,
		  "DODAG config A");
	ASSERT_EQ(config.gateway_centric, v->gateway_centric, "DODAG config gateway");
	ASSERT_EQ(config.dio_int_doublings, v->dio_int_doublings, "DODAG config doublings");
	ASSERT_EQ(config.dio_int_min, v->dio_int_min, "DODAG config minimum");
	ASSERT_EQ(config.dio_redundancy_const, v->dio_redundancy_const,
		  "DODAG config redundancy");
	ASSERT_EQ(config.max_rank_increase, v->max_rank_increase, "DODAG config max rank");
	ASSERT_EQ(config.min_hop_rank_increase, v->min_hop_rank_increase,
		  "DODAG config min rank");
	ASSERT_EQ(config.ocp, v->ocp, "DODAG config OCP");
	ASSERT_EQ(config.def_lifetime, v->default_lifetime, "DODAG config lifetime");
	ASSERT_EQ(config.lifetime_unit, v->lifetime_unit, "DODAG config lifetime unit");
	ret = lichen_rpl_dodag_config_write(&config, encoded, sizeof(encoded));
	ASSERT_EQ(ret, (int)v->encoded_len, "DODAG config encode length");
	ASSERT_TRUE(memcmp(encoded, v->encoded, v->encoded_len) == 0,
		    "DODAG config encode");
	return 1;
}

static int consume_target_option(const struct rpl_message_vector *v)
{
	struct lichen_rpl_target target;
	uint8_t encoded[20];
	int ret;

	ret = lichen_rpl_target_parse(&target, &v->encoded[2], v->encoded_len - 2U);
	if (v->expect_error != NULL) {
		ASSERT_TRUE(strcmp(v->expect_error, "invalid_length") == 0 ||
			    strcmp(v->expect_error, "nonzero_flags") == 0 ||
			    strcmp(v->expect_error, "invalid_prefix_length") == 0,
			    "target expect_error");
		ASSERT_EQ(ret, LICHEN_RPL_ERR_BAD_OPT, "invalid target accepted");
		return 1;
	}

	ASSERT_EQ(ret, LICHEN_RPL_OK, "target parse");
	ASSERT_EQ(target.prefix_len, v->prefix_length, "target prefix length");
	ASSERT_TRUE(memcmp(target.prefix, v->prefix, sizeof(target.prefix)) == 0,
		    "target prefix");
	ret = lichen_rpl_target_write(&target, encoded, sizeof(encoded));
	ASSERT_EQ(ret, (int)v->encoded_len, "target encode length");
	ASSERT_TRUE(memcmp(encoded, v->encoded, v->encoded_len) == 0,
		    "target encode");
	return 1;
}

static int consume_transit_option(const struct rpl_message_vector *v)
{
	struct lichen_rpl_transit_info transit;
	uint8_t encoded[22];
	int ret;

	ret = lichen_rpl_transit_info_parse(&transit, &v->encoded[2],
					    v->encoded_len - 2U);
	if (v->expect_error != NULL) {
		ASSERT_TRUE(strcmp(v->expect_error, "invalid_length") == 0 ||
			    strcmp(v->expect_error, "nonzero_reserved_flags") == 0,
			    "transit expect_error");
		ASSERT_EQ(ret, LICHEN_RPL_ERR_BAD_OPT, "invalid transit accepted");
		return 1;
	}

	ASSERT_EQ(ret, LICHEN_RPL_OK, "transit parse");
	ASSERT_EQ(transit.external, v->external, "transit external");
	ASSERT_EQ(transit.path_control, v->path_control, "transit path control");
	ASSERT_EQ(transit.path_sequence, v->path_sequence, "transit path sequence");
	ASSERT_EQ(transit.path_lifetime, v->path_lifetime, "transit path lifetime");
	ASSERT_TRUE(memcmp(transit.parent_address, v->parent_address, 16) == 0,
		    "transit parent address");
	ret = lichen_rpl_transit_info_write(&transit, encoded, sizeof(encoded));
	ASSERT_EQ(ret, (int)v->encoded_len, "transit encode length");
	ASSERT_TRUE(memcmp(encoded, v->encoded, v->encoded_len) == 0,
		    "transit encode");
	return 1;
}

static int consume_option(const struct rpl_message_vector *v)
{
	ASSERT_TRUE(v->encoded_len >= 2U, "option TLV length");
	ASSERT_EQ(v->encoded[0], v->option_type, "option wire type");
	ASSERT_EQ(v->encoded[1], v->encoded_len - 2U, "option wire length");
	if (v->option_type == LICHEN_RPL_OPT_DODAG_CONFIG) {
		return consume_dodag_config_option(v);
	}
	if (v->option_type == LICHEN_RPL_OPT_RPL_TARGET) {
		return consume_target_option(v);
	}
	if (v->option_type == LICHEN_RPL_OPT_TRANSIT_INFO) {
		return consume_transit_option(v);
	}
	printf("  FAIL: unsupported option type %u\n", v->option_type);
	return 0;
}

static int consume_one(const struct rpl_message_vector *v)
{
	switch (v->kind) {
	case RPL_VEC_DIO:
		return consume_dio(v);
	case RPL_VEC_DAO:
		return consume_dao(v);
	case RPL_VEC_DIS:
		return consume_dis(v);
	case RPL_VEC_DAO_ACK:
		return consume_dao_ack(v);
	case RPL_VEC_OPTION:
		return consume_option(v);
	default:
		printf("  FAIL: unknown kind\n");
		return 0;
	}
}

int main(void)
{
	unsigned int i;
	unsigned int dio = 0;
	unsigned int dao = 0;
	unsigned int dis = 0;
	unsigned int dao_ack = 0;
	unsigned int option = 0;

	printf("RPL message vector tests\n");
	printf("========================\n\n");
	tests_run++;
	printf("  dio_strict_atomicity...");
	if (test_dio_strict_atomicity()) {
		tests_passed++;
		printf(" OK\n");
	} else {
		printf(" FAIL\n");
	}
	tests_run++;
	printf("  dis_strict_atomicity...");
	if (test_dis_strict_atomicity()) {
		tests_passed++;
		printf(" OK\n");
	} else {
		printf(" FAIL\n");
	}

	if (RPL_MESSAGE_VECTOR_COUNT !=
	    (sizeof(rpl_message_vectors) / sizeof(rpl_message_vectors[0]))) {
		printf("FAIL: vector count mismatch\n");
		return 1;
	}

	for (i = 0; i < RPL_MESSAGE_VECTOR_COUNT; i++) {
		const struct rpl_message_vector *v = &rpl_message_vectors[i];

		printf("  %s...", v->name);
		tests_run++;
		if (!consume_one(v)) {
			printf(" FAIL\n");
			continue;
		}
		printf(" OK\n");
		tests_passed++;
		switch (v->kind) {
		case RPL_VEC_DIO:
			dio++;
			break;
		case RPL_VEC_DAO:
			dao++;
			break;
		case RPL_VEC_DIS:
			dis++;
			break;
		case RPL_VEC_DAO_ACK:
			dao_ack++;
			break;
		case RPL_VEC_OPTION:
			option++;
			break;
		}
	}
	printf("  dao_codec_boundaries...");
	tests_run++;
	if (test_dao_boundaries()) {
		printf(" OK\n");
		tests_passed++;
	} else {
		printf(" FAIL\n");
	}

	printf("\n%d/%d tests passed (dio=%u dao=%u dis=%u dao_ack=%u option=%u)\n",
	       tests_passed, tests_run, dio, dao, dis, dao_ack, option);

	if (dio < 6U || dao < 1U || dis < 5U || dao_ack < 5U || option < 17U) {
		printf("FAIL: incomplete corpus coverage\n");
		return 1;
	}
	return (tests_passed == tests_run) ? 0 : 1;
}
