/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief LOADng codec tests (spec section 10, appendix B2)
 *
 * Tests the RREQ, RREP, RERR parse/write functions against known test vectors.
 * These are pure codec functions that don't require Zephyr kernel features.
 */

#include <lichen/routing/loadng.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* Test framework */
static int tests_run;
static int tests_passed;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
	if (memcmp(a, b, len) != 0) { \
		printf("  FAIL: %s (memory mismatch)\n", msg); \
		return 0; \
	} \
} while (0)

/* Codec implementations for native testing (no Zephyr dependencies) */

static int loadng_rreq_parse(const uint8_t *data, size_t len,
			     struct lichen_loadng_rreq *rreq)
{
	if (data == NULL || rreq == NULL) {
		return -EINVAL;
	}
	if (len < LICHEN_LOADNG_RREQ_RREP_LEN) {
		return -EMSGSIZE;
	}

	rreq->flags = data[0];
	rreq->hop_limit = data[1];
	rreq->seq_num = ((uint16_t)data[2] << 8) | data[3];
	memcpy(rreq->originator, &data[4], 16);
	memcpy(rreq->destination, &data[20], 16);

	return 0;
}

static int loadng_rreq_write(const struct lichen_loadng_rreq *rreq,
			     uint8_t *buf, size_t buf_len)
{
	if (rreq == NULL || buf == NULL) {
		return -EINVAL;
	}
	if (buf_len < LICHEN_LOADNG_RREQ_RREP_LEN) {
		return -ENOMEM;
	}

	buf[0] = rreq->flags;
	buf[1] = rreq->hop_limit;
	buf[2] = (uint8_t)(rreq->seq_num >> 8);
	buf[3] = (uint8_t)rreq->seq_num;
	memcpy(&buf[4], rreq->originator, 16);
	memcpy(&buf[20], rreq->destination, 16);

	return LICHEN_LOADNG_RREQ_RREP_LEN;
}

static int loadng_rrep_parse(const uint8_t *data, size_t len,
			     struct lichen_loadng_rrep *rrep)
{
	if (data == NULL || rrep == NULL) {
		return -EINVAL;
	}
	if (len < LICHEN_LOADNG_RREQ_RREP_LEN) {
		return -EMSGSIZE;
	}

	rrep->flags = data[0];
	rrep->hop_count = data[1];
	rrep->seq_num = ((uint16_t)data[2] << 8) | data[3];
	memcpy(rrep->originator, &data[4], 16);
	memcpy(rrep->destination, &data[20], 16);

	return 0;
}

static int loadng_rrep_write(const struct lichen_loadng_rrep *rrep,
			     uint8_t *buf, size_t buf_len)
{
	if (rrep == NULL || buf == NULL) {
		return -EINVAL;
	}
	if (buf_len < LICHEN_LOADNG_RREQ_RREP_LEN) {
		return -ENOMEM;
	}

	buf[0] = rrep->flags;
	buf[1] = rrep->hop_count;
	buf[2] = (uint8_t)(rrep->seq_num >> 8);
	buf[3] = (uint8_t)rrep->seq_num;
	memcpy(&buf[4], rrep->originator, 16);
	memcpy(&buf[20], rrep->destination, 16);

	return LICHEN_LOADNG_RREQ_RREP_LEN;
}

static int loadng_rerr_parse(const uint8_t *data, size_t len,
			     struct lichen_loadng_rerr *rerr)
{
	if (data == NULL || rerr == NULL) {
		return -EINVAL;
	}
	if (len < LICHEN_LOADNG_RERR_LEN) {
		return -EMSGSIZE;
	}

	rerr->flags = data[0];
	rerr->error_code = data[1];
	memcpy(rerr->unreachable, &data[2], 16);

	return 0;
}

static int loadng_rerr_write(const struct lichen_loadng_rerr *rerr,
			     uint8_t *buf, size_t buf_len)
{
	if (rerr == NULL || buf == NULL) {
		return -EINVAL;
	}
	if (buf_len < LICHEN_LOADNG_RERR_LEN) {
		return -ENOMEM;
	}

	buf[0] = rerr->flags;
	buf[1] = rerr->error_code;
	memcpy(&buf[2], rerr->unreachable, 16);

	return LICHEN_LOADNG_RERR_LEN;
}

/* Helper: create link-local address from IID byte */
static void make_ll(uint8_t iid, uint8_t addr[16])
{
	memset(addr, 0, 16);
	addr[0] = 0xfe;
	addr[1] = 0x80;
	addr[8] = 0x02;
	addr[15] = iid;
}

/* Freshness helper test: wraps the inline function so we can test it directly. */
static int test_seq_freshness(void)
{
	ASSERT_EQ(false, lichen_loadng_seq_is_fresher(0, 0), "equal seq");
	ASSERT_EQ(true, lichen_loadng_seq_is_fresher(0, 1), "0->1 fresher");
	ASSERT_EQ(true, lichen_loadng_seq_is_fresher(0, 100), "0->100 fresher");
	ASSERT_EQ(false, lichen_loadng_seq_is_fresher(100, 0), "100->0 diff=65436 >= 32768, not fresher");
	ASSERT_EQ(false, lichen_loadng_seq_is_fresher(1, 0), "1->0 is stale (wrap backward)");
	ASSERT_EQ(true, lichen_loadng_seq_is_fresher(65530, 5), "65530->5 wrapped forward, fresher");
	ASSERT_EQ(false, lichen_loadng_seq_is_fresher(5, 65530), "5->65530 is stale (> half space)");
	ASSERT_EQ(false, lichen_loadng_seq_is_fresher(0, 32768), "0->32768 at boundary -> not fresher");
	ASSERT_EQ(true, lichen_loadng_seq_is_fresher(0, 32767), "0->32767 within half, fresher");
	return 1;
}

/* Route cache freshness: stale seq_num rejected even with better metric. */
static int test_cache_add_rejects_stale_seq_num(void)
{
	uint8_t dest[16], next_hop[16];
	make_ll(10, dest);
	make_ll(20, next_hop);

	struct lichen_loadng_route r1 = {0}, r2 = {0};
	memcpy(r1.destination, dest, 16);
	memcpy(r1.next_hop, next_hop, 16);
	r1.seq_num = 100;
	r1.metric = 200;
	r1.hop_count = 4;
	r1.valid_until_ms = 10000;
	r1.active = true;

	memcpy(r2.destination, dest, 16);
	memcpy(r2.next_hop, next_hop, 16);
	r2.seq_num = 50;
	r2.metric = 50;
	r2.hop_count = 2;
	r2.valid_until_ms = 10000;
	r2.active = true;

	lichen_loadng_cache_init();
	lichen_loadng_cache_add(&r1);
	lichen_loadng_cache_add(&r2);

	struct lichen_loadng_route result;
	int ret = lichen_loadng_cache_lookup(dest, 0, &result);
	ASSERT_EQ(0, ret, "route found");
	ASSERT_EQ(100, result.seq_num, "existing seq_num preserved");
	ASSERT_EQ(200, result.metric, "existing metric preserved");
	return 1;
}

/* Route cache freshness: fresher seq_num accepted even with worse metric. */
static int test_cache_add_accepts_fresher_seq_num(void)
{
	uint8_t dest[16], next_hop[16];
	make_ll(10, dest);
	make_ll(20, next_hop);

	struct lichen_loadng_route r1 = {0}, r2 = {0};
	memcpy(r1.destination, dest, 16);
	memcpy(r1.next_hop, next_hop, 16);
	r1.seq_num = 50;
	r1.metric = 50;
	r1.hop_count = 2;
	r1.valid_until_ms = 10000;

	memcpy(r2.destination, dest, 16);
	memcpy(r2.next_hop, next_hop, 16);
	r2.seq_num = 100;
	r2.metric = 200;
	r2.hop_count = 4;
	r2.valid_until_ms = 10000;

	lichen_loadng_cache_init();
	lichen_loadng_cache_add(&r1);
	lichen_loadng_cache_add(&r2);

	struct lichen_loadng_route result;
	int ret = lichen_loadng_cache_lookup(dest, 0, &result);
	ASSERT_EQ(0, ret, "route found");
	ASSERT_EQ(100, result.seq_num, "fresher seq_num accepted");
	ASSERT_EQ(200, result.metric, "worse metric accepted with fresher seq");
	return 1;
}

/* Route cache freshness: same seq_num, better metric accepted. */
static int test_cache_add_same_seq_better_metric(void)
{
	uint8_t dest[16], next_hop[16];
	make_ll(10, dest);
	make_ll(20, next_hop);

	struct lichen_loadng_route r1 = {0}, r2 = {0};
	memcpy(r1.destination, dest, 16);
	memcpy(r1.next_hop, next_hop, 16);
	r1.seq_num = 100;
	r1.metric = 200;
	r1.hop_count = 4;
	r1.valid_until_ms = 10000;

	memcpy(r2.destination, dest, 16);
	memcpy(r2.next_hop, next_hop, 16);
	r2.seq_num = 100;
	r2.metric = 150;
	r2.hop_count = 3;
	r2.valid_until_ms = 10000;

	lichen_loadng_cache_init();
	lichen_loadng_cache_add(&r1);
	lichen_loadng_cache_add(&r2);

	struct lichen_loadng_route result;
	int ret = lichen_loadng_cache_lookup(dest, 0, &result);
	ASSERT_EQ(0, ret, "route found");
	ASSERT_EQ(150, result.metric, "better metric accepted with same seq");
	return 1;
}

/* Route cache freshness: same seq_num, worse or equal metric rejected. */
static int test_cache_add_same_seq_worse_metric(void)
{
	uint8_t dest[16], next_hop[16];
	make_ll(10, dest);
	make_ll(20, next_hop);

	struct lichen_loadng_route r1 = {0}, r2 = {0};
	memcpy(r1.destination, dest, 16);
	memcpy(r1.next_hop, next_hop, 16);
	r1.seq_num = 100;
	r1.metric = 100;
	r1.hop_count = 2;
	r1.valid_until_ms = 10000;

	memcpy(r2.destination, dest, 16);
	memcpy(r2.next_hop, next_hop, 16);
	r2.seq_num = 100;
	r2.metric = 200;
	r2.hop_count = 4;
	r2.valid_until_ms = 10000;

	lichen_loadng_cache_init();
	lichen_loadng_cache_add(&r1);
	lichen_loadng_cache_add(&r2);

	struct lichen_loadng_route result;
	int ret = lichen_loadng_cache_lookup(dest, 0, &result);
	ASSERT_EQ(0, ret, "route found");
	ASSERT_EQ(100, result.metric, "worse metric rejected with same seq");
	return 1;
}

/* Route cache freshness: seq_num wraparound (65530 -> 5 is fresher). */
static int test_cache_add_seq_wraparound_forward(void)
{
	uint8_t dest[16], next_hop[16];
	make_ll(10, dest);
	make_ll(20, next_hop);

	struct lichen_loadng_route r1 = {0}, r2 = {0};
	memcpy(r1.destination, dest, 16);
	memcpy(r1.next_hop, next_hop, 16);
	r1.seq_num = 65530;
	r1.metric = 100;
	r1.hop_count = 2;
	r1.valid_until_ms = 10000;

	memcpy(r2.destination, dest, 16);
	memcpy(r2.next_hop, next_hop, 16);
	r2.seq_num = 5;
	r2.metric = 200;
	r2.hop_count = 4;
	r2.valid_until_ms = 10000;

	lichen_loadng_cache_init();
	lichen_loadng_cache_add(&r1);
	lichen_loadng_cache_add(&r2);

	struct lichen_loadng_route result;
	int ret = lichen_loadng_cache_lookup(dest, 0, &result);
	ASSERT_EQ(0, ret, "route found");
	ASSERT_EQ(5, result.seq_num, "wrapped seq_num 5 is fresher than 65530");
	ASSERT_EQ(200, result.metric, "worse metric accepted with wrapped fresher seq");
	return 1;
}

/* Route cache freshness: seq_num wraparound (5 -> 65530 is stale). */
static int test_cache_add_seq_wraparound_backward(void)
{
	uint8_t dest[16], next_hop[16];
	make_ll(10, dest);
	make_ll(20, next_hop);

	struct lichen_loadng_route r1 = {0}, r2 = {0};
	memcpy(r1.destination, dest, 16);
	memcpy(r1.next_hop, next_hop, 16);
	r1.seq_num = 5;
	r1.metric = 100;
	r1.hop_count = 2;
	r1.valid_until_ms = 10000;

	memcpy(r2.destination, dest, 16);
	memcpy(r2.next_hop, next_hop, 16);
	r2.seq_num = 65530;
	r2.metric = 200;
	r2.hop_count = 4;
	r2.valid_until_ms = 10000;

	lichen_loadng_cache_init();
	lichen_loadng_cache_add(&r1);
	lichen_loadng_cache_add(&r2);

	struct lichen_loadng_route result;
	int ret = lichen_loadng_cache_lookup(dest, 0, &result);
	ASSERT_EQ(0, ret, "route found");
	ASSERT_EQ(5, result.seq_num, "original seq_num 5 preserved, 65530 rejected as stale");
	ASSERT_EQ(100, result.metric, "original metric preserved");
	return 1;
}

/* Tests */

static int test_rreq_roundtrip(void)
{
	struct lichen_loadng_rreq rreq = {0};
	struct lichen_loadng_rreq parsed = {0};
	uint8_t buf[64];
	int ret;

	make_ll(1, rreq.originator);
	make_ll(2, rreq.destination);
	rreq.seq_num = 0x1234;
	rreq.hop_limit = 8;
	rreq.flags = 0;

	ret = loadng_rreq_write(&rreq, buf, sizeof(buf));
	ASSERT_EQ(ret, 36, "write returns 36 bytes");

	ret = loadng_rreq_parse(buf, ret, &parsed);
	ASSERT_EQ(ret, 0, "parse succeeds");
	ASSERT_MEM_EQ(parsed.originator, rreq.originator, 16, "originator matches");
	ASSERT_MEM_EQ(parsed.destination, rreq.destination, 16, "destination matches");
	ASSERT_EQ(parsed.seq_num, 0x1234, "seq_num matches");
	ASSERT_EQ(parsed.hop_limit, 8, "hop_limit matches");

	return 1;
}

static int test_rrep_roundtrip(void)
{
	struct lichen_loadng_rrep rrep = {0};
	struct lichen_loadng_rrep parsed = {0};
	uint8_t buf[64];
	int ret;

	make_ll(2, rrep.originator);
	make_ll(1, rrep.destination);
	rrep.seq_num = 0x5678;
	rrep.hop_count = 3;
	rrep.flags = 0;

	ret = loadng_rrep_write(&rrep, buf, sizeof(buf));
	ASSERT_EQ(ret, 36, "write returns 36 bytes");

	ret = loadng_rrep_parse(buf, ret, &parsed);
	ASSERT_EQ(ret, 0, "parse succeeds");
	ASSERT_MEM_EQ(parsed.originator, rrep.originator, 16, "originator matches");
	ASSERT_MEM_EQ(parsed.destination, rrep.destination, 16, "destination matches");
	ASSERT_EQ(parsed.seq_num, 0x5678, "seq_num matches");
	ASSERT_EQ(parsed.hop_count, 3, "hop_count matches");

	return 1;
}

static int test_rerr_roundtrip(void)
{
	struct lichen_loadng_rerr rerr = {0};
	struct lichen_loadng_rerr parsed = {0};
	uint8_t buf[32];
	int ret;

	make_ll(3, rerr.unreachable);
	rerr.error_code = 1;
	rerr.flags = 0;

	ret = loadng_rerr_write(&rerr, buf, sizeof(buf));
	ASSERT_EQ(ret, 18, "write returns 18 bytes");

	ret = loadng_rerr_parse(buf, ret, &parsed);
	ASSERT_EQ(ret, 0, "parse succeeds");
	ASSERT_MEM_EQ(parsed.unreachable, rerr.unreachable, 16, "unreachable matches");
	ASSERT_EQ(parsed.error_code, 1, "error_code matches");

	return 1;
}

static int test_rreq_parse_rejects_short(void)
{
	struct lichen_loadng_rreq rreq;
	uint8_t data[35] = {0}; /* 35 < 36 required */
	int ret;

	ret = loadng_rreq_parse(data, sizeof(data), &rreq);
	ASSERT_EQ(ret, -EMSGSIZE, "parse rejects short buffer");

	return 1;
}

static int test_rrep_parse_rejects_short(void)
{
	struct lichen_loadng_rrep rrep;
	uint8_t data[35] = {0};
	int ret;

	ret = loadng_rrep_parse(data, sizeof(data), &rrep);
	ASSERT_EQ(ret, -EMSGSIZE, "parse rejects short buffer");

	return 1;
}

static int test_rerr_parse_rejects_short(void)
{
	struct lichen_loadng_rerr rerr;
	uint8_t data[17] = {0}; /* 17 < 18 required */
	int ret;

	ret = loadng_rerr_parse(data, sizeof(data), &rerr);
	ASSERT_EQ(ret, -EMSGSIZE, "parse rejects short buffer");

	return 1;
}

static int test_rreq_write_rejects_null(void)
{
	uint8_t buf[64];
	struct lichen_loadng_rreq rreq = {0};
	int ret;

	ret = loadng_rreq_write(NULL, buf, sizeof(buf));
	ASSERT_EQ(ret, -EINVAL, "write rejects NULL rreq");

	ret = loadng_rreq_write(&rreq, NULL, 64);
	ASSERT_EQ(ret, -EINVAL, "write rejects NULL buf");

	return 1;
}

static int test_rreq_write_rejects_small_buffer(void)
{
	struct lichen_loadng_rreq rreq = {0};
	uint8_t buf[35]; /* 35 < 36 required */
	int ret;

	ret = loadng_rreq_write(&rreq, buf, sizeof(buf));
	ASSERT_EQ(ret, -ENOMEM, "write rejects small buffer");

	return 1;
}

static int test_constants(void)
{
	ASSERT_EQ(LICHEN_LOADNG_ICMPV6_TYPE, 158, "ICMPv6 type is 158");
	ASSERT_EQ(LICHEN_LOADNG_CODE_RREQ, 0, "RREQ code is 0");
	ASSERT_EQ(LICHEN_LOADNG_CODE_RREP, 1, "RREP code is 1");
	ASSERT_EQ(LICHEN_LOADNG_CODE_RERR, 2, "RERR code is 2");
	ASSERT_EQ(LICHEN_LOADNG_INITIAL_HOP_LIMIT, 4, "initial hop limit is 4");
	ASSERT_EQ(LICHEN_LOADNG_MAX_HOP_LIMIT, 15, "max hop limit is 15");
	ASSERT_EQ(LICHEN_LOADNG_RREQ_RREP_LEN, 36, "RREQ/RREP length is 36");
	ASSERT_EQ(LICHEN_LOADNG_RERR_LEN, 18, "RERR length is 18");

	return 1;
}

static int test_expanding_ring_constants(void)
{
	ASSERT_EQ(LICHEN_LOADNG_EXPANDING_RING_0, 4, "ring 0 is 4");
	ASSERT_EQ(LICHEN_LOADNG_EXPANDING_RING_1, 8, "ring 1 is 8");
	ASSERT_EQ(LICHEN_LOADNG_EXPANDING_RING_2, 15, "ring 2 is 15");
	ASSERT_EQ(LICHEN_LOADNG_EXPANDING_RING_COUNT, 3, "ring count is 3");

	return 1;
}

static int test_wire_format_seq_num_big_endian(void)
{
	struct lichen_loadng_rreq rreq = {0};
	uint8_t buf[64];
	int ret;

	rreq.seq_num = 0xABCD;

	ret = loadng_rreq_write(&rreq, buf, sizeof(buf));
	ASSERT_EQ(ret, 36, "write succeeds");
	ASSERT_EQ(buf[2], 0xAB, "seq_num high byte");
	ASSERT_EQ(buf[3], 0xCD, "seq_num low byte");

	return 1;
}

#define RUN_TEST(fn) do { \
	printf("  %s...", #fn); \
	tests_run++; \
	if (fn()) { \
		printf(" OK\n"); \
		tests_passed++; \
	} \
} while (0)

int main(void)
{
	printf("LOADng Codec Tests\n");
	printf("==================\n\n");

	RUN_TEST(test_constants);
	RUN_TEST(test_expanding_ring_constants);
	RUN_TEST(test_rreq_roundtrip);
	RUN_TEST(test_rrep_roundtrip);
	RUN_TEST(test_rerr_roundtrip);
	RUN_TEST(test_rreq_parse_rejects_short);
	RUN_TEST(test_rrep_parse_rejects_short);
	RUN_TEST(test_rerr_parse_rejects_short);
	RUN_TEST(test_rreq_write_rejects_null);
	RUN_TEST(test_rreq_write_rejects_small_buffer);
	RUN_TEST(test_wire_format_seq_num_big_endian);
	RUN_TEST(test_seq_freshness);
	RUN_TEST(test_cache_add_rejects_stale_seq_num);
	RUN_TEST(test_cache_add_accepts_fresher_seq_num);
	RUN_TEST(test_cache_add_same_seq_better_metric);
	RUN_TEST(test_cache_add_same_seq_worse_metric);
	RUN_TEST(test_cache_add_seq_wraparound_forward);
	RUN_TEST(test_cache_add_seq_wraparound_backward);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
