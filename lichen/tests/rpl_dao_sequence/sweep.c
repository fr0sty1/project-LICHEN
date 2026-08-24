/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file sweep.c
 * @brief Exhaustive RFC 6550 Section 7.2 lollipop comparator cross-check
 *
 * Sweeps every (incoming, current) uint8_t pair - all 65536 - through the
 * C comparators and compares against golden_lollipop_sweep.txt, produced
 * by gen_golden_sweep.py: an independent Python transcription of
 * rust/lichen-rpl/src/routing.rs seq_is_newer() (lines 63-89). The golden
 * file is never derived from the C code under test.
 *
 * Three C entry points are checked against the same relation matrix:
 * - lichen_rpl_sequence_compare  (rpl_dao_build.c)
 * - lichen_rpl_lollipop_cmp      (dodag.c host-test hook)
 * - lichen_rpl_version_is_newer  (dodag.c host-test hook; bool, so only
 *   N/S appear - it never reports equal/incomparable)
 *
 * Usage:
 *   rpl_dao_sequence_sweep --dump OUTFILE   write the C relation matrix
 *   rpl_dao_sequence_sweep GOLDENFILE       verify; exit 1 on any mismatch
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

static char version_char(uint8_t a, uint8_t b)
{
	return lichen_rpl_version_is_newer(a, b) ? 'N' : 'S';
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

static int verify_file(const char *path)
{
	char line[PAIRS + 2];
	unsigned int mismatches_seq = 0;
	unsigned int mismatches_lol = 0;
	unsigned int mismatches_ver = 0;
	unsigned int counts[4] = { 0, 0, 0, 0 };
	unsigned int rows = 0;

	static const char rel[] = { 'E', 'N', 'S', 'I' };

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
		rows++;
		if (strlen(line) != PAIRS + 1 || line[PAIRS] != '\n') {
			fprintf(stderr, "golden row %u malformed (%zu chars)\n",
				incoming, strlen(line));
			fclose(in);
			return 2;
		}
		for (uint16_t current = 0; current < PAIRS; current++) {
			uint8_t a = (uint8_t)incoming;
			uint8_t b = (uint8_t)current;
			char expect = line[current];
			char c;

			c = compare_char(a, b);
			if (c != expect) {
				mismatches_seq++;
				fprintf(stderr,
					"sequence_compare(%u, %u): got %c expected %c\n",
					a, b, c, expect);
			}
			c = lollipop_char(a, b);
			if (c != expect) {
				mismatches_lol++;
				fprintf(stderr,
					"lollipop_cmp(%u, %u): got %c expected %c\n",
					a, b, c, expect);
			}
			c = version_char(a, b);
			if (c != expect) {
				mismatches_ver++;
				if (expect != 'E' && expect != 'I') {
					fprintf(stderr,
						"version_is_newer(%u, %u): got %c expected %c\n",
						a, b, c, expect);
				}
			}
			for (unsigned int i = 0; i < 4; i++) {
				if (rel[i] == expect) {
					counts[i]++;
					break;
				}
			}
		}
	}
	fclose(in);

	(void)printf("exhaustive lollipop sweep over %u rows x %u pairs\n", rows, PAIRS);
	(void)printf("sequence_compare mismatches: %u\n", mismatches_seq);
	(void)printf("lollipop_cmp mismatches:     %u\n", mismatches_lol);
	(void)printf("version_is_newer mismatches: %u (N/S vs E/I rows)\n", mismatches_ver);
	(void)printf("golden relation counts: E=%u N=%u S=%u I=%u\n",
		     counts[0], counts[1], counts[2], counts[3]);

	/* version_is_newer is bool-valued: E/I rows legitimately differ. */
	return (mismatches_seq == 0 && mismatches_lol == 0 &&
		mismatches_ver == counts[0] + counts[3]) ? 0 : 1;
}

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "--dump") == 0) {
		return run_dump(argv[2]);
	}
	if (argc == 2) {
		return verify_file(argv[1]);
	}
	fprintf(stderr, "usage: %s GOLDENFILE | %s --dump OUTFILE\n",
		argv[0], argv[0]);
	return 2;
}
