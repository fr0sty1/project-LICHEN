/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Consume loadng.json and loadng_messages.json through the C codecs.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lichen/routing/loadng.h>

#include "loadng_vectors.h"

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

static int consume_seq(const struct loadng_seq_vector *v)
{
	bool got = lichen_loadng_seq_is_fresher(v->a, v->b);

	ASSERT_EQ(got, v->b_fresher, "seq freshness");
	return 1;
}

static int consume_rreq(const struct loadng_msg_vector *v)
{
	struct lichen_loadng_rreq parsed;
	struct lichen_loadng_rreq built;
	uint8_t buf[64];
	int n;

	ASSERT_TRUE(v->encoded_len >= LICHEN_LOADNG_RREQ_RREP_LEN, "rreq length");
	ASSERT_EQ(lichen_loadng_rreq_parse(v->encoded, v->encoded_len, &parsed),
		  0, "rreq parse");
	ASSERT_EQ(parsed.flags, v->flags, "rreq flags");
	ASSERT_EQ(parsed.hop_limit, v->hop, "rreq hop_limit");
	ASSERT_EQ(parsed.seq_num, v->seq_num, "rreq seq");
	ASSERT_TRUE(memcmp(parsed.originator, v->addr_a, 16) == 0, "rreq orig");
	ASSERT_TRUE(memcmp(parsed.destination, v->addr_b, 16) == 0, "rreq dest");

	memset(&built, 0, sizeof(built));
	built.flags = v->flags;
	built.hop_limit = v->hop;
	built.seq_num = v->seq_num;
	memcpy(built.originator, v->addr_a, 16);
	memcpy(built.destination, v->addr_b, 16);
	n = lichen_loadng_rreq_write(&built, buf, sizeof(buf));
	ASSERT_TRUE(n == (int)LICHEN_LOADNG_RREQ_RREP_LEN, "rreq write");
	ASSERT_TRUE(memcmp(buf, v->encoded, LICHEN_LOADNG_RREQ_RREP_LEN) == 0,
		    "rreq encode");
	return 1;
}

static int consume_rrep(const struct loadng_msg_vector *v)
{
	struct lichen_loadng_rrep parsed;
	struct lichen_loadng_rrep built;
	uint8_t buf[64];
	int n;

	ASSERT_TRUE(v->encoded_len >= LICHEN_LOADNG_RREQ_RREP_LEN, "rrep length");
	ASSERT_EQ(lichen_loadng_rrep_parse(v->encoded, v->encoded_len, &parsed),
		  0, "rrep parse");
	ASSERT_EQ(parsed.flags, v->flags, "rrep flags");
	ASSERT_EQ(parsed.hop_count, v->hop, "rrep hop_count");
	ASSERT_EQ(parsed.seq_num, v->seq_num, "rrep seq");
	ASSERT_TRUE(memcmp(parsed.originator, v->addr_a, 16) == 0, "rrep orig");
	ASSERT_TRUE(memcmp(parsed.destination, v->addr_b, 16) == 0, "rrep dest");

	memset(&built, 0, sizeof(built));
	built.flags = v->flags;
	built.hop_count = v->hop;
	built.seq_num = v->seq_num;
	memcpy(built.originator, v->addr_a, 16);
	memcpy(built.destination, v->addr_b, 16);
	n = lichen_loadng_rrep_write(&built, buf, sizeof(buf));
	ASSERT_TRUE(n == (int)LICHEN_LOADNG_RREQ_RREP_LEN, "rrep write");
	ASSERT_TRUE(memcmp(buf, v->encoded, LICHEN_LOADNG_RREQ_RREP_LEN) == 0,
		    "rrep encode");
	return 1;
}

static int consume_rerr(const struct loadng_msg_vector *v)
{
	struct lichen_loadng_rerr parsed;
	struct lichen_loadng_rerr built;
	uint8_t buf[32];
	int n;

	ASSERT_TRUE(v->encoded_len >= LICHEN_LOADNG_RERR_LEN, "rerr length");
	ASSERT_EQ(lichen_loadng_rerr_parse(v->encoded, v->encoded_len, &parsed),
		  0, "rerr parse");
	ASSERT_EQ(parsed.flags, v->flags, "rerr flags");
	ASSERT_EQ(parsed.error_code, v->error_code, "rerr code");
	ASSERT_TRUE(memcmp(parsed.unreachable, v->addr_a, 16) == 0, "rerr dest");

	memset(&built, 0, sizeof(built));
	built.flags = v->flags;
	built.error_code = v->error_code;
	memcpy(built.unreachable, v->addr_a, 16);
	n = lichen_loadng_rerr_write(&built, buf, sizeof(buf));
	ASSERT_TRUE(n == (int)LICHEN_LOADNG_RERR_LEN, "rerr write");
	ASSERT_TRUE(memcmp(buf, v->encoded, LICHEN_LOADNG_RERR_LEN) == 0,
		    "rerr encode");
	return 1;
}

int main(void)
{
	unsigned int i;
	unsigned int rreq = 0;
	unsigned int rrep = 0;
	unsigned int rerr = 0;

	printf("LOADng vector tests\n");
	printf("===================\n\n");

	if (LOADNG_SEQ_VECTOR_COUNT !=
	    (sizeof(loadng_seq_vectors) / sizeof(loadng_seq_vectors[0]))) {
		printf("FAIL: seq vector count mismatch\n");
		return 1;
	}
	if (LOADNG_MSG_VECTOR_COUNT !=
	    (sizeof(loadng_msg_vectors) / sizeof(loadng_msg_vectors[0]))) {
		printf("FAIL: msg vector count mismatch\n");
		return 1;
	}

	for (i = 0; i < LOADNG_SEQ_VECTOR_COUNT; i++) {
		const struct loadng_seq_vector *v = &loadng_seq_vectors[i];

		printf("  seq %s...", v->name);
		tests_run++;
		if (!consume_seq(v)) {
			printf(" FAIL\n");
			continue;
		}
		printf(" OK\n");
		tests_passed++;
	}

	for (i = 0; i < LOADNG_MSG_VECTOR_COUNT; i++) {
		const struct loadng_msg_vector *v = &loadng_msg_vectors[i];
		int ok;

		printf("  %s...", v->name);
		tests_run++;
		switch (v->kind) {
		case LOADNG_VEC_RREQ:
			ok = consume_rreq(v);
			rreq++;
			break;
		case LOADNG_VEC_RREP:
			ok = consume_rrep(v);
			rrep++;
			break;
		case LOADNG_VEC_RERR:
			ok = consume_rerr(v);
			rerr++;
			break;
		default:
			ok = 0;
			break;
		}
		if (!ok) {
			printf(" FAIL\n");
			continue;
		}
		printf(" OK\n");
		tests_passed++;
	}

	printf("\n%d/%d tests passed (rreq=%u rrep=%u rerr=%u)\n",
	       tests_passed, tests_run, rreq, rrep, rerr);
	if (rreq < 7U || rrep < 5U || rerr < 5U ||
	    LOADNG_SEQ_VECTOR_COUNT < 16U) {
		printf("FAIL: incomplete corpus coverage\n");
		return 1;
	}
	return (tests_passed == tests_run) ? 0 : 1;
}
