/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lichen/rpl_dis.h>

static int tests_run;
static int tests_passed;

#define ASSERT_TRUE(condition, message) do { \
	if (!(condition)) { \
		printf("  FAIL: %s\n", (message)); \
		return 0; \
	} \
} while (0)

#define ASSERT_EQ(actual, expected, message) do { \
	if ((actual) != (expected)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", (message), \
		       (int)(actual), (int)(expected)); \
		return 0; \
	} \
} while (0)

static void set_addr(uint8_t addr[16], uint8_t first, uint8_t last)
{
	memset(addr, 0, 16);
	addr[0] = first;
	addr[15] = last;
}

static int setup(struct lichen_rpl_dis_handler *handler,
		 struct lichen_trickle *trickle,
		 struct lichen_rpl_dis_context *context)
{
	ASSERT_EQ(lichen_rpl_dis_handler_init(handler, 4000),
		  LICHEN_RPL_OK, "handler init");
	ASSERT_EQ(lichen_trickle_init_profile(trickle), 0, "Trickle init");
	ASSERT_TRUE(lichen_trickle_start(trickle, 0, 0), "Trickle start");
	ASSERT_TRUE(lichen_trickle_fire_transmit(trickle), "Trickle transmit");
	ASSERT_TRUE(lichen_trickle_expire(trickle, 4000, 0), "Trickle expand");
	lichen_trickle_heard_consistent(trickle);
	memset(context, 0, sizeof(*context));
	context->rpl_instance_id = 7;
	context->version = 9;
	memset(context->dodag_id, 0x22, sizeof(context->dodag_id));
	return 1;
}

static int make_solicited(uint8_t wire[23], uint8_t flags,
			  uint8_t instance, const uint8_t dodag_id[16],
			  uint8_t version)
{
	struct lichen_rpl_solicited_info info = {
		.rpl_instance_id = instance,
		.flags = flags,
		.version = version,
	};
	struct lichen_rpl_dis dis = { 0 };
	uint8_t option[LICHEN_RPL_SOLICITED_INFO_LEN];
	int ret;

	memcpy(info.dodag_id, dodag_id, sizeof(info.dodag_id));
	ret = lichen_rpl_solicited_info_write(&info, option, sizeof(option));
	if (ret != LICHEN_RPL_SOLICITED_INFO_LEN) {
		return ret;
	}
	return lichen_rpl_dis_write_with_options(
		&dis, option, sizeof(option), wire, 23);
}

static int test_auth_replay_and_malformed_are_atomic(void)
{
	static const uint8_t wildcard[] = { 0, 0 };
	static const uint8_t malformed[] = { 0, 0, LICHEN_RPL_OPT_SOLICITED_INFO };
	struct lichen_rpl_dis_handler handler;
	struct lichen_rpl_dis_handler before_handler;
	struct lichen_trickle trickle;
	struct lichen_trickle before_trickle;
	struct lichen_rpl_dis_context context;
	uint8_t sender[16];
	uint8_t targeted[23];
	uint8_t duplicate[44];

	if (!setup(&handler, &trickle, &context)) {
		return 0;
	}
	set_addr(sender, 0xfe, 1);
	ASSERT_EQ(make_solicited(targeted, LICHEN_RPL_SOLICITED_PREDICATE_MASK,
				  context.rpl_instance_id, context.dodag_id,
				  context.version),
		  (int)sizeof(targeted), "targeted DIS encoded");
	duplicate[0] = 0;
	duplicate[1] = 0;
	memcpy(&duplicate[2], &targeted[2], LICHEN_RPL_SOLICITED_INFO_LEN);
	memcpy(&duplicate[2 + LICHEN_RPL_SOLICITED_INFO_LEN], &targeted[2],
	       LICHEN_RPL_SOLICITED_INFO_LEN);
	before_handler = handler;
	before_trickle = trickle;
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, malformed, sizeof(malformed), true,
					&context, sender, false, true, &trickle, 5000, 0),
		  LICHEN_RPL_DIS_IGNORE, "unauthenticated malformed DIS ignored");
	ASSERT_TRUE(memcmp(&handler, &before_handler, sizeof(handler)) == 0,
		    "authentication rejection mutated handler");
	ASSERT_TRUE(memcmp(&trickle, &before_trickle, sizeof(trickle)) == 0,
		    "authentication rejection mutated Trickle");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wildcard, sizeof(wildcard), true,
					&context, sender, true, false, &trickle, 5000, 0),
		  LICHEN_RPL_DIS_IGNORE, "replay-rejected DIS ignored");
	ASSERT_TRUE(memcmp(&handler, &before_handler, sizeof(handler)) == 0,
		    "replay rejection mutated handler");
	ASSERT_TRUE(memcmp(&trickle, &before_trickle, sizeof(trickle)) == 0,
		    "replay rejection mutated Trickle");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, malformed, sizeof(malformed), true,
					&context, sender, true, true, &trickle, 5000, 0),
		  LICHEN_RPL_ERR_BAD_OPT, "authenticated malformed DIS rejected");
	ASSERT_TRUE(memcmp(&handler, &before_handler, sizeof(handler)) == 0,
		    "parse error mutated handler");
	ASSERT_TRUE(memcmp(&trickle, &before_trickle, sizeof(trickle)) == 0,
		    "parse error mutated Trickle");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, duplicate, sizeof(duplicate), true,
					&context, sender, true, true, &trickle, 5000, 0),
		  LICHEN_RPL_ERR_BAD_OPT, "duplicate Solicited Information rejected");
	ASSERT_TRUE(memcmp(&handler, &before_handler, sizeof(handler)) == 0,
		    "duplicate option mutated handler");
	ASSERT_TRUE(memcmp(&trickle, &before_trickle, sizeof(trickle)) == 0,
		    "duplicate option mutated Trickle");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wildcard, sizeof(wildcard), true,
					&context, sender, true, true, &trickle, 5000,
					trickle.imin),
		  LICHEN_RPL_ERR_INVALID, "invalid Trickle offset rejected");
	ASSERT_TRUE(memcmp(&handler, &before_handler, sizeof(handler)) == 0,
		    "Trickle error mutated handler");
	ASSERT_TRUE(memcmp(&trickle, &before_trickle, sizeof(trickle)) == 0,
		    "Trickle error mutated timer");
	return 1;
}

static int test_multicast_wildcard_coalesces_and_resets(void)
{
	static const uint8_t wildcard[] = { 0xa5, 0 };
	struct lichen_rpl_dis_handler handler;
	struct lichen_rpl_dis_handler before_handler;
	struct lichen_trickle trickle;
	struct lichen_trickle before_trickle;
	struct lichen_rpl_dis_context context;
	uint8_t sender[16];

	if (!setup(&handler, &trickle, &context)) {
		return 0;
	}
	set_addr(sender, 0xfe, 1);
	ASSERT_EQ(trickle.interval, 8000, "precondition expanded interval");
	ASSERT_EQ(trickle.counter, 1, "precondition consistency count");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wildcard, sizeof(wildcard), true,
					&context, sender, true, true, &trickle, 10000, 0),
		  LICHEN_RPL_DIS_RESET_TRICKLE, "wildcard multicast resets");
	ASSERT_EQ(trickle.interval, trickle.imin, "reset to Imin");
	ASSERT_EQ(trickle.interval_start, 10000, "reset timestamp");
	ASSERT_EQ(trickle.counter, 0, "reset consistency count");
	before_handler = handler;
	before_trickle = trickle;
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wildcard, sizeof(wildcard), true,
					&context, sender, true, true, &trickle, 13999, 0),
		  LICHEN_RPL_DIS_COALESCED, "duplicate multicast coalesced");
	ASSERT_TRUE(memcmp(&handler, &before_handler, sizeof(handler)) == 0,
		    "coalescing mutated handler");
	ASSERT_TRUE(memcmp(&trickle, &before_trickle, sizeof(trickle)) == 0,
		    "coalescing restarted Trickle");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wildcard, sizeof(wildcard), true,
					&context, sender, true, true, &trickle, 14000, 0),
		  LICHEN_RPL_DIS_RESET_TRICKLE, "deadline admits next multicast");
	ASSERT_EQ(trickle.interval_start, 14000, "deadline reset timestamp");
	return 1;
}

static int test_targeted_predicates_and_reserved_flags(void)
{
	struct lichen_rpl_dis_handler handler;
	struct lichen_rpl_dis_handler before_handler;
	struct lichen_trickle trickle;
	struct lichen_trickle before_trickle;
	struct lichen_rpl_dis_context context;
	uint8_t sender[16];
	uint8_t other_dodag[16];
	uint8_t wire[23];

	if (!setup(&handler, &trickle, &context)) {
		return 0;
	}
	set_addr(sender, 0xfe, 1);
	memset(other_dodag, 0x33, sizeof(other_dodag));
	ASSERT_EQ(make_solicited(wire, LICHEN_RPL_SOLICITED_INSTANCE_PREDICATE,
				  8, context.dodag_id, context.version),
		  (int)sizeof(wire), "instance-targeted DIS encoded");
	before_handler = handler;
	before_trickle = trickle;
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wire, sizeof(wire), true,
					&context, sender, true, true, &trickle, 10000, 0),
		  LICHEN_RPL_DIS_IGNORE, "instance mismatch ignored");
	ASSERT_TRUE(memcmp(&handler, &before_handler, sizeof(handler)) == 0,
		    "target mismatch mutated handler");
	ASSERT_TRUE(memcmp(&trickle, &before_trickle, sizeof(trickle)) == 0,
		    "target mismatch mutated Trickle");
	ASSERT_EQ(make_solicited(wire, LICHEN_RPL_SOLICITED_DODAG_PREDICATE,
				  context.rpl_instance_id, other_dodag, context.version),
		  (int)sizeof(wire), "DODAG-targeted DIS encoded");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wire, sizeof(wire), true,
					&context, sender, true, true, &trickle, 10000, 0),
		  LICHEN_RPL_DIS_IGNORE, "DODAG mismatch ignored");
	ASSERT_EQ(make_solicited(wire, LICHEN_RPL_SOLICITED_VERSION_PREDICATE,
				  context.rpl_instance_id, context.dodag_id,
				  (uint8_t)(context.version + 1U)),
		  (int)sizeof(wire), "version-targeted DIS encoded");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wire, sizeof(wire), true,
					&context, sender, true, true, &trickle, 10000, 0),
		  LICHEN_RPL_DIS_IGNORE, "version mismatch ignored");

	/* Reserved low flag bits are receiver-ignored. With no predicate bits,
	 * deliberately unrelated carried fields form a wildcard. */
	ASSERT_EQ(make_solicited(wire, 0x1f, 255, other_dodag, 255),
		  (int)sizeof(wire), "reserved-flag wildcard encoded");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wire, sizeof(wire), true,
					&context, sender, true, true, &trickle, 10000, 0),
		  LICHEN_RPL_DIS_RESET_TRICKLE, "reserved flags ignored");
	return 1;
}

static int test_unicast_rate_limit_and_coalescing(void)
{
	struct lichen_rpl_dis_handler handler;
	struct lichen_rpl_dis_handler before_handler;
	struct lichen_trickle trickle;
	struct lichen_trickle before_trickle;
	struct lichen_rpl_dis_context context;
	uint8_t sender1[16];
	uint8_t sender2[16];
	uint8_t wire[23];

	if (!setup(&handler, &trickle, &context)) {
		return 0;
	}
	set_addr(sender1, 0xfe, 1);
	set_addr(sender2, 0xfe, 2);
	ASSERT_EQ(make_solicited(wire, LICHEN_RPL_SOLICITED_PREDICATE_MASK,
				  context.rpl_instance_id, context.dodag_id,
				  context.version),
		  (int)sizeof(wire), "fully targeted DIS encoded");
	before_trickle = trickle;
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wire, sizeof(wire), false,
					&context, sender1, true, true, &trickle, 10000, 0),
		  LICHEN_RPL_DIS_UNICAST_DIO_WITH_CONFIG,
		  "targeted unicast requests configured DIO");
	ASSERT_TRUE(memcmp(&trickle, &before_trickle, sizeof(trickle)) == 0,
		    "unicast request changed Trickle");
	before_handler = handler;
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wire, sizeof(wire), false,
					&context, sender1, true, true, &trickle, 10001, 0),
		  LICHEN_RPL_DIS_COALESCED, "same peer unicast coalesced");
	ASSERT_TRUE(memcmp(&handler, &before_handler, sizeof(handler)) == 0,
		    "unicast coalescing extended window");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wire, sizeof(wire), false,
					&context, sender2, true, true, &trickle, 10002, 0),
		  LICHEN_RPL_DIS_RATE_LIMITED, "other peer unicast rate limited");
	ASSERT_TRUE(memcmp(&handler, &before_handler, sizeof(handler)) == 0,
		    "rate limit changed selected peer");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wire, sizeof(wire), false,
					&context, sender2, true, true, &trickle, 14000, 0),
		  LICHEN_RPL_DIS_UNICAST_DIO_WITH_CONFIG,
		  "deadline admits other peer");
	ASSERT_TRUE(memcmp(handler.unicast_peer, sender2, 16) == 0,
		    "new peer becomes coalescing owner");
	return 1;
}

static int test_wraparound_and_initialization_boundaries(void)
{
	static const uint8_t wildcard[] = { 0, 0 };
	struct lichen_rpl_dis_handler handler;
	struct lichen_trickle trickle;
	struct lichen_rpl_dis_context context;
	uint8_t sender[16];

	memset(&handler, 0xa5, sizeof(handler));
	ASSERT_EQ(lichen_rpl_dis_handler_init(NULL, 1), LICHEN_RPL_ERR_INVALID,
		  "NULL handler rejected");
	ASSERT_EQ(lichen_rpl_dis_handler_init(&handler, 0), LICHEN_RPL_ERR_INVALID,
		  "zero interval rejected");
	ASSERT_EQ(lichen_rpl_dis_handler_init(&handler, (uint32_t)INT32_MAX + 1U),
		  LICHEN_RPL_ERR_INVALID, "ambiguous interval rejected");
	if (!setup(&handler, &trickle, &context)) {
		return 0;
	}
	set_addr(sender, 0xfe, 1);
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wildcard, sizeof(wildcard), false,
					&context, sender, true, true, &trickle,
					UINT32_MAX - 1000U, 0),
		  LICHEN_RPL_DIS_UNICAST_DIO_WITH_CONFIG, "pre-wrap request admitted");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wildcard, sizeof(wildcard), false,
					&context, sender, true, true, &trickle, 2998, 0),
		  LICHEN_RPL_DIS_COALESCED, "wrapped tick before deadline coalesced");
	ASSERT_EQ(lichen_rpl_dis_handle(&handler, wildcard, sizeof(wildcard), false,
					&context, sender, true, true, &trickle, 2999, 0),
		  LICHEN_RPL_DIS_UNICAST_DIO_WITH_CONFIG,
		  "wrapped exact deadline admitted");
	return 1;
}

int main(void)
{
	static const struct {
		const char *name;
		int (*run)(void);
	} tests[] = {
		{ "auth/replay/malformed atomicity", test_auth_replay_and_malformed_are_atomic },
		{ "multicast wildcard coalescing", test_multicast_wildcard_coalesces_and_resets },
		{ "targeted predicates", test_targeted_predicates_and_reserved_flags },
		{ "unicast rate limit/coalescing", test_unicast_rate_limit_and_coalescing },
		{ "wrap/init boundaries", test_wraparound_and_initialization_boundaries },
	};

	printf("RPL DIS solicitation handler\n");
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		tests_run++;
		printf("  %s: ", tests[i].name);
		if (tests[i].run()) {
			printf("PASS\n");
			tests_passed++;
		}
	}
	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
