/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief RFC 6550 Section 7.2 lollipop and DIO version/identity tests
 *
 * Lollipop expected values are copied from RFC 6550 Section 7.2 worked
 * examples and an independent all-pairs transcription of rules 3.1/3.2.
 * In particular, the absolute difference is checked before RFC 1982
 * ordering, so distant same-region values are incomparable. process_dio
 * policy expected values match python python/tests/rpl/test_dodag.py and rust
 * foreign_and_incomparable_dios_do_not_change_state. They are not derived
 * from the C implementation under test.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lichen/rpl_dodag.h>

/* Encoding for RFC incomparable / Rust None / Python None. Independent of
 * the C helper's internal constant; both use 2 by convention. */
#define LOLLIPOP_INCOMPARABLE 2

static int tests_run;
static int tests_passed;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", \
		       msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_TRUE(cond, msg) do { \
	if (!(cond)) { \
		printf("  FAIL: %s\n", msg); \
		return 0; \
	} \
} while (0)

#define ASSERT_FALSE(cond, msg) ASSERT_TRUE(!(cond), msg)

/*
 * rust/lichen-rpl version_lollipop_semantics + python _RFC_LOLLIPOP_CASES.
 * expected: 1 = a newer, -1 = a older, 0 = equal, 2 = incomparable.
 */
static const struct {
	uint8_t a;
	uint8_t b;
	int expected;
} rfc_lollipop_cases[] = {
	{0, 0, 0},
	{128, 128, 0},
	{16, 0, 1},
	{17, 0, LOLLIPOP_INCOMPARABLE},
	{0, 16, -1},
	{0, 17, LOLLIPOP_INCOMPARABLE},
	/* Absolute same-region gaps above SEQUENCE_WINDOW are incomparable. */
	{0, 127, LOLLIPOP_INCOMPARABLE},
	{127, 0, LOLLIPOP_INCOMPARABLE},
	{120, 5, LOLLIPOP_INCOMPARABLE},
	{5, 100, LOLLIPOP_INCOMPARABLE},
	{100, 5, LOLLIPOP_INCOMPARABLE},
	{255, 239, 1},
	{255, 238, LOLLIPOP_INCOMPARABLE},
	{5, 250, 1},
	{5, 240, -1},
	{0, 240, 1},
	{0, 239, -1},
	{240, 5, 1},
	{250, 5, -1},
};

/*
 * rust lollipop_sequence_window_boundaries_is_inclusive_per_rfc_6550_7_2.
 */
static const struct {
	uint8_t a;
	uint8_t b;
	int expected;
} rfc_window_boundary_cases[] = {
	{16, 0, 1},
	{15, 0, 1},
	{17, 0, LOLLIPOP_INCOMPARABLE},
	{255, 239, 1},
	{255, 240, 1},
	{255, 238, LOLLIPOP_INCOMPARABLE},
	{0, 240, 1},
	{0, 241, 1},
	{0, 239, -1},
	{250, 10, -1},
	{250, 9, -1},
	{250, 11, 1},
};

static int test_lollipop_cmp_rfc_table(void)
{
	size_t i;

	for (i = 0; i < sizeof(rfc_lollipop_cases) / sizeof(rfc_lollipop_cases[0]); i++) {
		uint8_t a = rfc_lollipop_cases[i].a;
		uint8_t b = rfc_lollipop_cases[i].b;
		int expected = rfc_lollipop_cases[i].expected;
		int got = lichen_rpl_lollipop_cmp(a, b);
		char msg[64];

		(void)snprintf(msg, sizeof(msg), "lollipop_cmp(%u, %u)", a, b);
		ASSERT_EQ(got, expected, msg);
	}
	return 1;
}

static int test_lollipop_cmp_window_boundaries(void)
{
	size_t i;

	for (i = 0; i < sizeof(rfc_window_boundary_cases) / sizeof(rfc_window_boundary_cases[0]); i++) {
		uint8_t a = rfc_window_boundary_cases[i].a;
		uint8_t b = rfc_window_boundary_cases[i].b;
		int expected = rfc_window_boundary_cases[i].expected;
		int got = lichen_rpl_lollipop_cmp(a, b);
		char msg[64];

		(void)snprintf(msg, sizeof(msg), "window lollipop_cmp(%u, %u)", a, b);
		ASSERT_EQ(got, expected, msg);
	}
	return 1;
}

static int rfc_lollipop_oracle(uint8_t a, uint8_t b)
{
	bool same_region = (a < 128u) == (b < 128u);
	uint8_t magnitude;

	if (a == b) {
		return 0;
	}
	if (same_region) {
		magnitude = a > b ? a - b : b - a;
		if (magnitude > 16u) {
			return LOLLIPOP_INCOMPARABLE;
		}
		return a > b ? 1 : -1;
	}
	if (a < 128u) {
		return 256u - b + a <= 16u ? 1 : -1;
	}
	return 256u - a + b <= 16u ? -1 : 1;
}

static int test_lollipop_cmp_exhaustive_rfc_oracle(void)
{
	unsigned int a;
	unsigned int b;

	for (a = 0; a <= UINT8_MAX; a++) {
		for (b = 0; b <= UINT8_MAX; b++) {
			int expected = rfc_lollipop_oracle((uint8_t)a, (uint8_t)b);
			int actual = lichen_rpl_lollipop_cmp((uint8_t)a, (uint8_t)b);

			if (actual != expected) {
				(void)fprintf(stderr,
					      "lollipop_cmp(%u, %u): got %d expected %d\n",
					      a, b, actual, expected);
				return 0;
			}
		}
	}
	return 1;
}

static int test_version_is_newer_rfc_and_special_wrap(void)
{
	/* The DODAG state machine explicitly preserves its adjacent 127->0
	 * restart policy; other distant circular pairs remain incomparable. */
	ASSERT_TRUE(lichen_rpl_version_is_newer(0, 127), "0 newer than 127");
	ASSERT_FALSE(lichen_rpl_version_is_newer(127, 0), "127 not newer than 0");
	ASSERT_FALSE(lichen_rpl_version_is_newer(5, 120), "5 incomparable with 120");
	ASSERT_FALSE(lichen_rpl_version_is_newer(120, 5), "120 not newer than 5");
	ASSERT_TRUE(lichen_rpl_version_is_newer(255, 239), "255 newer than 239");
	ASSERT_FALSE(lichen_rpl_version_is_newer(5, 240), "5 not newer than 240");
	ASSERT_TRUE(lichen_rpl_version_is_newer(240, 5), "240 newer than 5 (RFC)");
	ASSERT_TRUE(lichen_rpl_version_is_newer(5, 250), "5 newer than 250 (RFC)");
	ASSERT_FALSE(lichen_rpl_version_is_newer(250, 5), "250 not newer than 5 (RFC)");
	ASSERT_TRUE(lichen_rpl_version_is_newer(0, 240), "0 newer than 240 (wrap=16)");
	ASSERT_FALSE(lichen_rpl_version_is_newer(1, 1), "equal is not newer");
	return 1;
}

static int test_incomparable_both_directions_false(void)
{
	/* Same-region pairs 17 serial steps apart are incomparable in both
	 * directions; the restart pair (0, 127) is one-way newer. */
	ASSERT_FALSE(lichen_rpl_version_is_newer(17, 0), "17 vs 0");
	ASSERT_FALSE(lichen_rpl_version_is_newer(0, 17), "0 vs 17");
	ASSERT_FALSE(lichen_rpl_version_is_newer(255, 238), "255 vs 238");
	ASSERT_FALSE(lichen_rpl_version_is_newer(238, 255), "238 vs 255");
	ASSERT_TRUE(lichen_rpl_version_is_newer(0, 127), "restart wrap 0 vs 127");
	ASSERT_FALSE(lichen_rpl_version_is_newer(127, 0), "127 vs 0 still not newer");
	return 1;
}

static int test_cross_region_always_comparable(void)
{
	/* 240 vs 5: wrap=21 > 16, unwrapped (circular 240) newer. */
	ASSERT_EQ(lichen_rpl_lollipop_cmp(240, 5), 1, "240 vs 5");
	ASSERT_EQ(lichen_rpl_lollipop_cmp(5, 240), -1, "5 vs 240");
	/* 250 vs 5: wrap=11 <= 16, wrapped (linear 5) newer. */
	ASSERT_EQ(lichen_rpl_lollipop_cmp(250, 5), -1, "250 vs 5");
	ASSERT_EQ(lichen_rpl_lollipop_cmp(5, 250), 1, "5 vs 250");
	ASSERT_TRUE(lichen_rpl_version_is_newer(240, 5), "version 240 vs 5");
	ASSERT_TRUE(lichen_rpl_version_is_newer(5, 250), "version 5 vs 250");
	return 1;
}

/* python/tests/rpl/test_dodag.py DODAG_ID = fd00::1, P1/P2 = fe80::1 / ::2 */
static void set_addr(uint8_t addr[16], uint8_t b0, uint8_t b1, uint8_t last)
{
	memset(addr, 0, 16);
	addr[0] = b0;
	addr[1] = b1;
	addr[15] = last;
}

static void make_dio(struct lichen_rpl_dio *dio, uint8_t instance, uint8_t version,
		     uint16_t rank, uint8_t dtsn, const uint8_t dodag_id[16])
{
	memset(dio, 0, sizeof(*dio));
	dio->rpl_instance_id = instance;
	dio->version = version;
	dio->rank = rank;
	dio->grounded = true;
	dio->mode_of_operation = 1;
	dio->dtsn = dtsn;
	memcpy(dio->dodag_id, dodag_id, 16);
}

static int feed_dio(struct lichen_rpl_dodag *d, const struct lichen_rpl_dio *dio,
		    const uint8_t *nbr)
{
	return lichen_rpl_dodag_process_dio(d, dio, NULL, nbr, 256, 0, 1, true);
}

static int feed_dio_authorized(struct lichen_rpl_dodag *d,
			       const struct lichen_rpl_dio *dio,
			       const uint8_t *nbr)
{
	return lichen_rpl_dodag_process_dio_authorized(
		d, dio, NULL, nbr, 256, 0, 1, true, true);
}

static int feed_dio_cfg(struct lichen_rpl_dodag *d,
			const struct lichen_rpl_dio *dio,
			const struct lichen_rpl_dodag_config *cfg,
			const uint8_t *nbr)
{
	return lichen_rpl_dodag_process_dio(d, dio, cfg, nbr, 256, 0, 1, true);
}

struct dodag_snap {
	uint8_t rpl_instance_id;
	uint8_t dodag_id[16];
	uint8_t version;
	uint8_t dtsn;
	enum lichen_rpl_role role;
	uint16_t rank;
	bool has_preferred_parent;
	uint8_t preferred_parent[16];
	int parent_count;
};

static void snap_dodag(const struct lichen_rpl_dodag *d, struct dodag_snap *s)
{
	s->rpl_instance_id = d->rpl_instance_id;
	memcpy(s->dodag_id, d->dodag_id, 16);
	s->version = d->version;
	s->dtsn = d->dtsn;
	s->role = d->role;
	s->rank = d->rank;
	s->has_preferred_parent = d->has_preferred_parent;
	memcpy(s->preferred_parent, d->preferred_parent, 16);
	s->parent_count = lichen_rpl_dodag_parent_count(d);
}

static int snap_unchanged(const struct dodag_snap *before, const struct lichen_rpl_dodag *d,
			  const char *msg)
{
	struct dodag_snap after;

	snap_dodag(d, &after);
	ASSERT_EQ(after.rpl_instance_id, before->rpl_instance_id, msg);
	ASSERT_EQ(memcmp(after.dodag_id, before->dodag_id, 16), 0, msg);
	ASSERT_EQ(after.version, before->version, msg);
	ASSERT_EQ(after.dtsn, before->dtsn, msg);
	ASSERT_EQ((int)after.role, (int)before->role, msg);
	ASSERT_EQ(after.rank, before->rank, msg);
	ASSERT_EQ((int)after.has_preferred_parent, (int)before->has_preferred_parent, msg);
	ASSERT_EQ(memcmp(after.preferred_parent, before->preferred_parent, 16), 0, msg);
	ASSERT_EQ(after.parent_count, before->parent_count, msg);
	return 1;
}

static int join_on_p1(struct lichen_rpl_dodag *d, const uint8_t dodag_id[16],
		      uint8_t version, uint8_t dtsn, const uint8_t p1[16])
{
	struct lichen_rpl_dio dio;

	ASSERT_EQ(lichen_rpl_dodag_init(d, 0, dodag_id, version), 0, "init");
	make_dio(&dio, 0, version, LICHEN_RPL_ROOT_RANK, dtsn, dodag_id);
	(void)feed_dio(d, &dio, p1);
	ASSERT_EQ((int)d->role, (int)LICHEN_RPL_JOINED, "joined");
	ASSERT_EQ(d->version, version, "join version");
	ASSERT_EQ(d->dtsn, dtsn, "join dtsn");
	ASSERT_EQ(lichen_rpl_dodag_parent_count(d), 1, "one parent");
	ASSERT_TRUE(d->has_preferred_parent, "has parent");
	ASSERT_EQ(memcmp(d->preferred_parent, p1, 16), 0, "parent p1");
	return 1;
}

static int test_joined_incomparable_version_ignored(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	struct dodag_snap before;
	uint8_t dodag_id[16];
	uint8_t p1[16];
	uint8_t p2[16];

	/* RFC 7.2: |18-1| = 17 > SEQUENCE_WINDOW, same linear region. */
	ASSERT_EQ(lichen_rpl_lollipop_cmp(18, 1), LOLLIPOP_INCOMPARABLE, "18 vs 1");
	ASSERT_FALSE(lichen_rpl_version_is_newer(18, 1), "18 not newer than 1");
	ASSERT_FALSE(lichen_rpl_version_is_newer(1, 18), "1 not newer than 18");

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);
	set_addr(p2, 0xfe, 0x80, 0x02);
	if (!join_on_p1(&d, dodag_id, 1, 7, p1)) {
		return 0;
	}
	snap_dodag(&d, &before);

	make_dio(&dio, 0, 18, 10, 9, dodag_id);
	ASSERT_EQ(feed_dio(&d, &dio, p2), 0, "incomparable ret");
	if (!snap_unchanged(&before, &d, "joined incomparable")) {
		return 0;
	}
	return 1;
}

static int test_unjoined_incomparable_same_dodag_not_adopted(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	uint8_t dodag_id[16];
	uint8_t p1[16];

	/* RFC 7.2 / python test_incomparable_version_is_ignored_not_mixed */
	ASSERT_EQ(lichen_rpl_lollipop_cmp(17, 0), LOLLIPOP_INCOMPARABLE, "17 vs 0");
	ASSERT_FALSE(lichen_rpl_version_is_newer(17, 0), "17 not newer than 0");
	ASSERT_FALSE(lichen_rpl_version_is_newer(0, 17), "0 not newer than 17");

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);
	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "init");
	make_dio(&dio, 0, 17, LICHEN_RPL_ROOT_RANK, 3, dodag_id);
	ASSERT_EQ(feed_dio(&d, &dio, p1), 0, "unjoined incomparable ret");
	ASSERT_EQ((int)d.role, (int)LICHEN_RPL_UNJOINED, "still unjoined");
	ASSERT_EQ(d.version, 0, "version unchanged");
	ASSERT_EQ(d.dtsn, 0, "dtsn unchanged");
	ASSERT_EQ(lichen_rpl_dodag_parent_count(&d), 0, "no parent");
	return 1;
}

static int test_unjoined_older_same_dodag_not_adopted(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	uint8_t dodag_id[16];
	uint8_t p1[16];

	ASSERT_TRUE(lichen_rpl_version_is_newer(5, 0), "5 newer than 0");
	ASSERT_FALSE(lichen_rpl_version_is_newer(0, 5), "0 not newer than 5");

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);
	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 5), 0, "init");
	make_dio(&dio, 0, 0, LICHEN_RPL_ROOT_RANK, 1, dodag_id);
	ASSERT_EQ(feed_dio(&d, &dio, p1), 0, "older ret");
	ASSERT_EQ((int)d.role, (int)LICHEN_RPL_UNJOINED, "still unjoined");
	ASSERT_EQ(d.version, 5, "version unchanged");
	ASSERT_EQ(d.dtsn, 0, "dtsn unchanged");
	ASSERT_EQ(lichen_rpl_dodag_parent_count(&d), 0, "no parent");
	return 1;
}

static int test_joined_foreign_instance_ignored(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	struct dodag_snap before;
	uint8_t dodag_id[16];
	uint8_t p1[16];
	uint8_t p2[16];

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);
	set_addr(p2, 0xfe, 0x80, 0x02);
	if (!join_on_p1(&d, dodag_id, 1, 4, p1)) {
		return 0;
	}
	snap_dodag(&d, &before);

	make_dio(&dio, 1, 2, 10, 8, dodag_id);
	ASSERT_EQ(feed_dio(&d, &dio, p2), 0, "foreign instance ret");
	if (!snap_unchanged(&before, &d, "foreign instance")) {
		return 0;
	}
	return 1;
}

static int test_joined_foreign_dodagid_ignored(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	struct dodag_snap before;
	uint8_t dodag_id[16];
	uint8_t foreign_id[16];
	uint8_t p1[16];
	uint8_t p2[16];

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(foreign_id, 0xfd, 0x00, 0x99);
	set_addr(p1, 0xfe, 0x80, 0x01);
	set_addr(p2, 0xfe, 0x80, 0x02);
	if (!join_on_p1(&d, dodag_id, 1, 4, p1)) {
		return 0;
	}
	snap_dodag(&d, &before);

	make_dio(&dio, 0, 2, 10, 8, foreign_id);
	ASSERT_EQ(feed_dio(&d, &dio, p2), 0, "foreign dodag ret");
	if (!snap_unchanged(&before, &d, "foreign dodagid")) {
		return 0;
	}
	return 1;
}

static int test_unjoined_foreign_dodag_rejected(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	struct dodag_snap before;
	uint8_t dodag_id[16];
	uint8_t foreign_id[16];
	uint8_t p1[16];

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(foreign_id, 0xfd, 0x00, 0x99);
	set_addr(p1, 0xfe, 0x80, 0x01);
	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 5), 0, "init");
	snap_dodag(&d, &before);
	make_dio(&dio, 0, 0, LICHEN_RPL_ROOT_RANK, 2, foreign_id);
	ASSERT_EQ(feed_dio_authorized(&d, &dio, p1), 0, "foreign DODAG ret");
	if (!snap_unchanged(&before, &d, "unjoined foreign DODAG")) {
		return 0;
	}
	return 1;
}

static int test_root_ignores_all_dios(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	struct dodag_snap before;
	uint8_t dodag_id[16];
	uint8_t foreign_id[16];
	uint8_t p1[16];

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(foreign_id, 0xfd, 0x00, 0x99);
	set_addr(p1, 0xfe, 0x80, 0x01);
	ASSERT_EQ(lichen_rpl_dodag_init_root(&d, 0, dodag_id, 1), 0, "init root");
	snap_dodag(&d, &before);

	make_dio(&dio, 0, 2, LICHEN_RPL_ROOT_RANK, 9, dodag_id);
	ASSERT_EQ(feed_dio(&d, &dio, p1), 0, "root newer ret");
	if (!snap_unchanged(&before, &d, "root newer same dodag")) {
		return 0;
	}

	make_dio(&dio, 1, 2, LICHEN_RPL_ROOT_RANK, 9, dodag_id);
	ASSERT_EQ(feed_dio(&d, &dio, p1), 0, "root foreign instance ret");
	if (!snap_unchanged(&before, &d, "root foreign instance")) {
		return 0;
	}

	make_dio(&dio, 0, 2, LICHEN_RPL_ROOT_RANK, 9, foreign_id);
	ASSERT_EQ(feed_dio(&d, &dio, p1), 0, "root foreign dodag ret");
	if (!snap_unchanged(&before, &d, "root foreign dodag")) {
		return 0;
	}
	return 1;
}

static int test_same_version_still_joins_and_updates_dtsn(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	uint8_t dodag_id[16];
	uint8_t p1[16];
	uint8_t p2[16];

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);
	set_addr(p2, 0xfe, 0x80, 0x02);
	if (!join_on_p1(&d, dodag_id, 1, 4, p1)) {
		return 0;
	}

	make_dio(&dio, 0, 1, LICHEN_RPL_ROOT_RANK, 5, dodag_id);
	ASSERT_EQ(feed_dio(&d, &dio, p2), 1, "dtsn change ret");
	ASSERT_EQ(d.dtsn, 5, "dtsn updated");
	ASSERT_EQ(d.version, 1, "version unchanged");
	ASSERT_EQ((int)d.role, (int)LICHEN_RPL_JOINED, "still joined");
	ASSERT_EQ(lichen_rpl_dodag_parent_count(&d), 2, "second parent");
	return 1;
}

/*
 * gateway_centric is root-authoritative: only a DIO whose sender is the
 * adopted root (sender address == DODAGID) may set it; every DIO without
 * an authoritative option restores the last-known-good root value.
 */
static int test_gateway_centric_root_authoritative(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	struct lichen_rpl_dodag_config cfg_on;
	struct lichen_rpl_dodag_config cfg_off;
	uint8_t dodag_id[16];
	uint8_t root[16];
	uint8_t p1[16];
	uint8_t p2[16];

	/* The DODAGID doubles as the root's address. */
	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(root, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);
	set_addr(p2, 0xfe, 0x80, 0x02);
	lichen_rpl_dodag_config_init(&cfg_on);
	lichen_rpl_dodag_config_init(&cfg_off);
	cfg_on.gateway_centric = true;

	if (!join_on_p1(&d, dodag_id, 1, 4, p1)) {
		return 0;
	}
	ASSERT_FALSE(d.gateway_centric, "default not gateway-centric");
	ASSERT_FALSE(d.last_gateway_centric, "default last-known-good off");

	/* A joined peer's config option must be ignored (no mode flapping). */
	make_dio(&dio, 0, 1, LICHEN_RPL_ROOT_RANK, 4, dodag_id);
	(void)feed_dio_cfg(&d, &dio, &cfg_on, p2);
	ASSERT_FALSE(d.gateway_centric, "peer option ignored");
	ASSERT_FALSE(d.last_gateway_centric, "peer option not stored as good");

	/* The adopted root's config option is accepted. */
	(void)feed_dio_cfg(&d, &dio, &cfg_on, root);
	ASSERT_TRUE(d.gateway_centric, "root option accepted");
	ASSERT_TRUE(d.last_gateway_centric, "root option remembered");

	/* A peer cannot flip it back off... */
	(void)feed_dio_cfg(&d, &dio, &cfg_off, p2);
	ASSERT_TRUE(d.gateway_centric, "peer cannot clear root setting");

	/* ...and DIos without the option keep the last-known-good value. */
	(void)feed_dio(&d, &dio, p2);
	(void)feed_dio(&d, &dio, root);
	ASSERT_TRUE(d.gateway_centric, "last-known-good persists");

	/* Only the root lowers it again. */
	(void)feed_dio_cfg(&d, &dio, &cfg_off, root);
	ASSERT_FALSE(d.gateway_centric, "root cleared flag");
	ASSERT_FALSE(d.last_gateway_centric, "last-known-good follows root");

	/* Absence of the option keeps the restored value instead of a
	 * stale one. */
	(void)feed_dio(&d, &dio, root);
	ASSERT_FALSE(d.gateway_centric, "reset semantics without option");
	return 1;
}

static int test_gateway_centric_resets_on_version_adoption(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	uint8_t dodag_id[16];
	uint8_t p1[16];

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 5), 0, "init");
	d.gateway_centric = true;
	d.last_gateway_centric = true;

	make_dio(&dio, 0, 6, LICHEN_RPL_ROOT_RANK, 2, dodag_id);
	ASSERT_EQ(feed_dio(&d, &dio, p1), 0, "unauthorized version ignored");
	ASSERT_EQ(d.version, 5, "unauthorized version unchanged");
	ASSERT_TRUE(d.gateway_centric, "unauthorized version kept working flag");
	ASSERT_EQ(feed_dio_authorized(&d, &dio, p1), 1, "authorized version adopted");
	ASSERT_EQ((int)d.role, (int)LICHEN_RPL_JOINED, "rejoined authorized version");
	ASSERT_EQ(d.version, 6, "authorized version committed");
	ASSERT_FALSE(d.gateway_centric, "adoption clears working flag");
	ASSERT_FALSE(d.last_gateway_centric, "adoption clears last-known-good");
	return 1;
}

static int test_mrhof_path_cost_and_admission_edges(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	uint8_t dodag_id[16];
	uint8_t p1[16];

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);
	make_dio(&dio, 0, 0, LICHEN_RPL_ROOT_RANK, 0, dodag_id);

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "init");
	(void)lichen_rpl_dodag_process_dio(&d, &dio, NULL, p1,
					   256, 3, 1, true);
	ASSERT_EQ(d.rank, 536, "ETX plus bounded load cost");

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "reinit");
	(void)lichen_rpl_dodag_process_dio(&d, &dio, NULL, p1,
					   255, 0, 1, true);
	ASSERT_EQ((int)d.role, (int)LICHEN_RPL_UNJOINED,
		  "same-DAGRank path rejected");
	ASSERT_EQ(lichen_rpl_dodag_parent_count(&d), 0, "invalid ETX not cached");

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "reinit overflow");
	(void)lichen_rpl_dodag_process_dio(&d, &dio, NULL, p1,
					   UINT16_MAX, UINT8_MAX, 1, true);
	ASSERT_EQ((int)d.role, (int)LICHEN_RPL_UNJOINED, "saturated path rejected");
	ASSERT_EQ(d.rank, LICHEN_RPL_INFINITE_RANK, "saturated rank remains infinite");

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "reinit zero MHRI");
	d.min_hop_rank_increase = 0;
	(void)feed_dio(&d, &dio, p1);
	ASSERT_EQ((int)d.role, (int)LICHEN_RPL_UNJOINED, "zero MHRI rejected");
	return 1;
}

static int test_mrhof_hysteresis_boundary_and_tie(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	uint8_t dodag_id[16];
	uint8_t p1[16];
	uint8_t p2[16];

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);
	set_addr(p2, 0xfe, 0x80, 0x02);
	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "init");
	make_dio(&dio, 0, 0, 768, 0, dodag_id);
	(void)feed_dio(&d, &dio, p1); /* cost 1024 */
	ASSERT_EQ(memcmp(d.preferred_parent, p1, 16), 0, "initial parent");

	/* RFC 6719 3.2: equality reaches the threshold and switches. */
	make_dio(&dio, 0, 0, 576, 0, dodag_id);
	(void)feed_dio(&d, &dio, p2); /* cost 832, improvement exactly 192 */
	ASSERT_EQ(memcmp(d.preferred_parent, p2, 16), 0, "switch at threshold");
	ASSERT_EQ(d.rank, 832, "threshold switch cost");

	/* With no established parent, equal costs use address order rather than
	 * candidate insertion order, making selection deterministic. */
	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "tie reinit");
	memcpy(d.parents[0].addr, p2, 16);
	d.parents[0].rank = 256;
	d.parents[0].link_etx = 256;
	d.parents[0].valid = true;
	memcpy(d.parents[1].addr, p1, 16);
	d.parents[1].rank = 256;
	d.parents[1].link_etx = 256;
	d.parents[1].valid = true;
	lichen_rpl_dodag_select_parent(&d);
	ASSERT_EQ(memcmp(d.preferred_parent, p1, 16), 0, "lexicographic tie-break");
	return 1;
}

static int test_mrhof_rank_bound_and_reprune(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	uint8_t dodag_id[16];
	uint8_t p1[16];
	uint8_t p2[16];
	uint8_t p3[16];

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);
	set_addr(p2, 0xfe, 0x80, 0x02);
	set_addr(p3, 0xfe, 0x80, 0x03);
	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "init");
	d.max_rank_increase = 0; /* RFC 6550 6.7.6: disabled, not zero headroom */
	make_dio(&dio, 0, 0, 256, 0, dodag_id);
	(void)feed_dio(&d, &dio, p1); /* cost 512 */
	make_dio(&dio, 0, 0, 450, 0, dodag_id);
	(void)lichen_rpl_dodag_process_dio(&d, &dio, NULL, p2, 2048, 0, 2, true);
	ASSERT_EQ(lichen_rpl_dodag_parent_count(&d), 2, "unbounded backup retained");
	lichen_rpl_dodag_remove_parent(&d, p1);
	ASSERT_EQ(memcmp(d.preferred_parent, p2, 16), 0, "unbounded backup selected");
	ASSERT_EQ(d.rank, 2498, "unbounded backup cost");

	/* Selecting a substantially better parent tightens the rank ceiling and
	 * immediately removes cached parents that are now unusable. */
	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "reprune reinit");
	make_dio(&dio, 0, 0, 768, 0, dodag_id);
	(void)feed_dio(&d, &dio, p1); /* 1024 */
	(void)lichen_rpl_dodag_process_dio(&d, &dio, NULL, p2, 1024, 0, 2, true); /* 1792 */
	ASSERT_EQ(lichen_rpl_dodag_parent_count(&d), 2, "backup initially admissible");
	make_dio(&dio, 0, 0, 256, 0, dodag_id);
	(void)feed_dio(&d, &dio, p3); /* 512 */
	ASSERT_EQ(memcmp(d.preferred_parent, p3, 16), 0, "better parent selected");
	ASSERT_EQ(lichen_rpl_dodag_parent_count(&d), 1, "old parents re-pruned");
	return 1;
}

static int test_mrhof_parent_expiry_boundaries(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	uint8_t dodag_id[16];
	uint8_t p1[16];

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(p1, 0xfe, 0x80, 0x01);
	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "init");
	make_dio(&dio, 0, 0, 256, 0, dodag_id);
	(void)lichen_rpl_dodag_process_dio(&d, &dio, NULL, p1, 256, 0,
					   UINT32_MAX - 5, true);
	ASSERT_EQ(lichen_rpl_dodag_expire_parents(&d, 4, 10), 0,
		  "exact wrapped deadline remains fresh");
	ASSERT_EQ(lichen_rpl_dodag_expire_parents(&d, 5, 10), 1,
		  "first tick after wrapped deadline expires");
	ASSERT_EQ((int)d.role, (int)LICHEN_RPL_UNJOINED, "expiry leaves DODAG");
	return 1;
}

static int test_null_arguments_rejected(void)
{
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dio dio;
	uint8_t addr[16] = { 0 };

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, addr, 1), 0, "init");
	make_dio(&dio, 0, 1, LICHEN_RPL_ROOT_RANK, 0, addr);

	ASSERT_EQ(lichen_rpl_dodag_process_dio(NULL, &dio, NULL, addr,
					       256, 0, 1, true),
		  LICHEN_RPL_ERR_INVALID, "NULL dodag rejected");
	ASSERT_EQ(lichen_rpl_dodag_process_dio(&d, NULL, NULL, addr,
					       256, 0, 1, true),
		  LICHEN_RPL_ERR_INVALID, "NULL dio rejected");
	ASSERT_EQ(lichen_rpl_dodag_process_dio(&d, &dio, NULL, NULL,
					       256, 0, 1, true),
		  LICHEN_RPL_ERR_INVALID, "NULL neighbor rejected");

	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes(NULL, addr, sizeof(addr), addr,
						     256, 0, 1, true),
		  LICHEN_RPL_ERR_INVALID, "wire NULL dodag rejected");
	return 1;
}

static int test_wire_receive_is_atomic_and_drives_trickle(void)
{
	static const uint8_t schc_option[] = {
		LICHEN_RPL_OPT_SCHC_RULE_VERSION,
		LICHEN_RPL_SCHC_RULE_VERSION_DATA_LEN,
		LICHEN_SCHC_RULE_SET_VERSION,
	};
	struct lichen_rpl_dodag d;
	struct lichen_rpl_dodag before;
	struct lichen_rpl_dio dio;
	uint8_t dodag_id[16];
	uint8_t parent[16];
	uint8_t wire[LICHEN_RPL_DIO_BASE_LEN + sizeof(schc_option)];
	uint8_t base[LICHEN_RPL_DIO_BASE_LEN];
	int wire_len;

	set_addr(dodag_id, 0xfd, 0x00, 0x01);
	set_addr(parent, 0xfe, 0x80, 0x01);
	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, dodag_id, 0), 0, "init");
	make_dio(&dio, 0, 0, LICHEN_RPL_ROOT_RANK, 5, dodag_id);
	wire_len = lichen_rpl_dio_write_with_options(
		&dio, schc_option, sizeof(schc_option), wire, sizeof(wire));
	ASSERT_EQ(wire_len, (int)sizeof(wire), "canonical wire DIO encoded");

	before = d;
	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes(
			  &d, wire, sizeof(wire), parent, 256, 0, 100, false),
		  0, "unauthenticated DIO ignored");
	ASSERT_EQ(memcmp(&d, &before, sizeof(d)), 0,
		  "authentication rejection is atomic");

	ASSERT_EQ(lichen_rpl_dio_write(&dio, base, sizeof(base)),
		  LICHEN_RPL_DIO_BASE_LEN, "base DIO encoded");
	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes(
			  &d, base, sizeof(base), parent, 256, 0, 100, true),
		  LICHEN_RPL_ERR_BAD_OPT, "missing SCHC version rejected");
	ASSERT_EQ(memcmp(&d, &before, sizeof(d)), 0,
		  "option rejection is atomic");

	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes(
			  &d, wire, sizeof(wire), parent, 256, 0, 100, true),
		  1, "authenticated current DIO joins");
	ASSERT_EQ((int)d.role, (int)LICHEN_RPL_JOINED, "joined from wire DIO");
	ASSERT_TRUE(d.trickle.active, "join starts Trickle");
	ASSERT_EQ(d.trickle.interval, d.trickle.imin,
		  "join resets Trickle to Imin");
	ASSERT_EQ(d.trickle.counter, 0, "join clears consistency counter");

	/* An exact duplicate is consistent: it refreshes the candidate without
	 * changing route state and increments Trickle's redundancy counter. */
	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes(
			  &d, wire, sizeof(wire), parent, 256, 0, 101, true),
		  0, "duplicate DIO processed");
	ASSERT_EQ(d.trickle.counter, 1, "duplicate increments Trickle counter");
	ASSERT_EQ(d.version, 0, "duplicate preserves version");
	ASSERT_EQ(d.dtsn, 5, "duplicate preserves DTSN");

	/* Older DTSN is a replay for sequence purposes, even though the parent
	 * observation can still be refreshed. */
	dio.dtsn = 4;
	wire_len = lichen_rpl_dio_write_with_options(
		&dio, schc_option, sizeof(schc_option), wire, sizeof(wire));
	ASSERT_EQ(wire_len, (int)sizeof(wire), "stale DTSN DIO encoded");
	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes(
			  &d, wire, sizeof(wire), parent, 256, 0, 102, true),
		  0, "stale DTSN ignored for sequence advancement");
	ASSERT_EQ(d.dtsn, 5, "stale DTSN cannot roll state back");
	ASSERT_EQ(d.trickle.counter, 2, "same-version replay is consistent");

	/* A newer DODAG version is state-changing and must carry separately
	 * verified root authorization. The ordinary receive path is atomic. */
	dio.version = 1;
	dio.dtsn = 6;
	wire_len = lichen_rpl_dio_write_with_options(
		&dio, schc_option, sizeof(schc_option), wire, sizeof(wire));
	ASSERT_EQ(wire_len, (int)sizeof(wire), "new-version DIO encoded");
	before = d;
	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes(
			  &d, wire, sizeof(wire), parent, 256, 0, 103, true),
		  0, "unauthorized newer version ignored");
	ASSERT_EQ(memcmp(&d, &before, sizeof(d)), 0,
		  "unauthorized version rejection is atomic");
	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes_authorized(
			  &d, wire, sizeof(wire), parent, 256, 0, 103, true, true),
		  1, "authorized newer version adopted");
	ASSERT_EQ(d.version, 1, "authorized version committed");
	ASSERT_EQ(d.dtsn, 6, "authorized DTSN committed");
	ASSERT_EQ(d.trickle.interval, d.trickle.imin,
		  "version inconsistency resets Trickle");
	ASSERT_EQ(d.trickle.counter, 0, "version reset clears counter");
	return 1;
}

int main(void)
{
	struct {
		const char *name;
		int (*fn)(void);
	} tests[] = {
		{"lollipop_cmp RFC 6550 7.2 table", test_lollipop_cmp_rfc_table},
		{"lollipop_cmp window boundaries", test_lollipop_cmp_window_boundaries},
		{"lollipop_cmp exhaustive RFC oracle", test_lollipop_cmp_exhaustive_rfc_oracle},
		{"version_is_newer RFC + 0 vs 127", test_version_is_newer_rfc_and_special_wrap},
		{"incomparable both directions false", test_incomparable_both_directions_false},
		{"cross-region always comparable", test_cross_region_always_comparable},
		{"joined incomparable version ignored", test_joined_incomparable_version_ignored},
		{"unjoined incomparable same DODAG not adopted", test_unjoined_incomparable_same_dodag_not_adopted},
		{"unjoined older same DODAG not adopted", test_unjoined_older_same_dodag_not_adopted},
		{"joined foreign instance ignored", test_joined_foreign_instance_ignored},
		{"joined foreign DODAGID ignored", test_joined_foreign_dodagid_ignored},
		{"unjoined foreign DODAG rejected", test_unjoined_foreign_dodag_rejected},
		{"root ignores all DIOs", test_root_ignores_all_dios},
		{"same-version still joins and updates DTSN", test_same_version_still_joins_and_updates_dtsn},
		{"gateway_centric is root-authoritative", test_gateway_centric_root_authoritative},
		{"gateway_centric resets on version adoption", test_gateway_centric_resets_on_version_adoption},
		{"MRHOF path cost and admission edges", test_mrhof_path_cost_and_admission_edges},
		{"MRHOF hysteresis boundary and deterministic tie", test_mrhof_hysteresis_boundary_and_tie},
		{"MRHOF rank bound and immediate re-prune", test_mrhof_rank_bound_and_reprune},
		{"MRHOF parent expiry boundaries", test_mrhof_parent_expiry_boundaries},
		{"NULL arguments rejected", test_null_arguments_rejected},
		{"wire receive is atomic and drives Trickle", test_wire_receive_is_atomic_and_drives_trickle},
	};
	size_t i;

	printf("RPL DODAG lollipop + DIO version/identity (RFC 6550)\n");

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		tests_run++;
		printf("  %s: ", tests[i].name);
		if (tests[i].fn() != 0) {
			printf("PASS\n");
			tests_passed++;
		}
	}

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
