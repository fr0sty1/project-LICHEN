/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file sweep.c
 * @brief Exhaustive RFC 6550 Section 7.2 lollipop comparator cross-check
 *
 * Sweeps every (incoming, current) uint8_t pair - all 65536 - through the
 * C comparators and compares against two independent Python-generated golden
 * matrices: DAO replay sequencing uses modulo-128 serial arithmetic, while
 * DODAG version comparison applies RFC 6550 rule 3.2's absolute-distance
 * window before ordering.  Neither matrix is derived from the C under test.
 *
 * Three C entry points are checked against their applicable relation matrix:
 * - lichen_rpl_sequence_compare  (rpl_dao_build.c)
 * - lichen_rpl_lollipop_cmp      (dodag.c host-test hook)
 * - lichen_rpl_version_is_newer  (dodag.c host-test hook; bool, so only
 *   N/S appear - it never reports equal/incomparable)
 *
 * Usage:
 *   rpl_dao_sequence_sweep --dump OUTFILE   write the C relation matrix
 *   rpl_dao_sequence_sweep DAO_GOLDEN DODAG_GOLDEN
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lichen/rpl_dodag.h>
#include <lichen/rpl_routing.h>

#define PAIRS 256

static char compare_char(uint8_t incoming, uint8_t current)
{
	static const char rel[] = { 'E', 'N', 'S', 'I' };

	return rel[lichen_rpl_sequence_compare(incoming, current)];
}

static char lollipop_char(uint8_t a, uint8_t b)
{
	switch (lichen_rpl_lollipop_cmp(a, b)) {
	case 0:
		return 'E';
	case 1:
		return 'N';
	case -1:
		return 'S';
	default:
		return 'I';
	}
}

typedef char (*pair_fn)(uint8_t a, uint8_t b);

static void dump_row(FILE *out, uint8_t incoming, pair_fn fn)
{
	for (uint16_t current = 0; current < PAIRS; current++) {
		if (fputc(fn(incoming, (uint8_t)current), out) == EOF) {
			fprintf(stderr, "write failed\n");
			exit(2);
		}
	}
	if (fputc('\n', out) == EOF) {
		fprintf(stderr, "write failed\n");
		exit(2);
	}
}

static int run_dump(const char *path)
{
	FILE *out = fopen(path, "w");

	if (out == NULL) {
		perror(path);
		return 2;
	}
	for (uint16_t incoming = 0; incoming < PAIRS; incoming++) {
		dump_row(out, (uint8_t)incoming, compare_char);
	}
	fclose(out);
	printf("dumped %u x %u relation matrix to %s\n", PAIRS, PAIRS, path);
	return 0;
}

static int read_golden(const char *path, char rows[PAIRS][PAIRS])
{
	char line[PAIRS + 2];
	FILE *in = fopen(path, "r");

	if (in == NULL) {
		perror(path);
		return 2;
	}

	for (uint16_t incoming = 0; incoming < PAIRS; incoming++) {
		if (fgets(line, sizeof(line), in) == NULL) {
			fprintf(stderr, "golden file short at row %u\n", incoming);
			fclose(in);
			return 2;
		}
		if (strlen(line) != PAIRS + 1 || line[PAIRS] != '\n') {
			fprintf(stderr, "golden row %u malformed (%zu chars)\n",
				incoming, strlen(line));
			fclose(in);
			return 2;
		}
		memcpy(rows[incoming], line, PAIRS);
	}
	fclose(in);
	return 0;
}

static int verify_files(const char *dao_path, const char *dodag_path)
{
	static char dao[PAIRS][PAIRS];
	static char dodag[PAIRS][PAIRS];
	unsigned int mismatches_seq = 0;
	unsigned int mismatches_lol = 0;
	unsigned int mismatches_ver = 0;
	int ret;

	ret = read_golden(dao_path, dao);
	if (ret != 0) {
		return ret;
	}
	ret = read_golden(dodag_path, dodag);
	if (ret != 0) {
		return ret;
	}

	for (uint16_t incoming = 0; incoming < PAIRS; incoming++) {
		for (uint16_t current = 0; current < PAIRS; current++) {
			uint8_t a = (uint8_t)incoming;
			uint8_t b = (uint8_t)current;
			bool expect_newer = dodag[incoming][current] == 'N' ||
				(a == 0u && b == 127u);

			if (compare_char(a, b) != dao[incoming][current]) {
				mismatches_seq++;
			}
			if (lollipop_char(a, b) != dodag[incoming][current]) {
				mismatches_lol++;
			}
			if (lichen_rpl_version_is_newer(a, b) != expect_newer) {
				mismatches_ver++;
			}
		}
	}

	(void)printf("exhaustive lollipop sweep over %u rows x %u pairs\n", PAIRS, PAIRS);
	(void)printf("sequence_compare mismatches: %u\n", mismatches_seq);
	(void)printf("lollipop_cmp mismatches:     %u\n", mismatches_lol);
	(void)printf("version_is_newer mismatches: %u\n", mismatches_ver);

	return (mismatches_seq == 0 && mismatches_lol == 0 && mismatches_ver == 0) ? 0 : 1;
}

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "--dump") == 0) {
		return run_dump(argv[2]);
	}
	if (argc == 3) {
		return verify_files(argv[1], argv[2]);
	}
	fprintf(stderr, "usage: %s DAO_GOLDEN DODAG_GOLDEN | %s --dump OUTFILE\n",
		argv[0], argv[0]);
	return 2;
}
