/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Independent offline checker for dao_origin_signature.json. */

#include <lichen/schnorr48.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t domain[] = "LICHEN-DAO-ORIGIN-v1";

static const char *field(const char *start, const char *end, const char *name)
{
	char pattern[64];
	int length = snprintf(pattern, sizeof(pattern), "\"%s\": ", name);
	const char *found = strstr(start, pattern);

	return length > 0 && found != NULL && found < end ? found + length : NULL;
}

static bool hex_nibble(char value, uint8_t *out)
{
	if (value >= '0' && value <= '9') {
		*out = (uint8_t)(value - '0');
		return true;
	}
	if (value >= 'a' && value <= 'f') {
		*out = (uint8_t)(value - 'a' + 10);
		return true;
	}
	return false;
}

static bool fixed_hex(const char *value, uint8_t *out, size_t length)
{
	if (value == NULL || *value++ != '"') {
		return false;
	}
	for (size_t i = 0; i < length; i++) {
		uint8_t high;
		uint8_t low;

		if (!hex_nibble(value[2 * i], &high) || !hex_nibble(value[2 * i + 1], &low)) {
			return false;
		}
		out[i] = (uint8_t)((high << 4) | low);
	}
	return value[2 * length] == '"';
}

static bool variable_hex(const char *value, uint8_t *out, size_t capacity, size_t *length)
{
	const char *close;

	if (value == NULL || *value++ != '"') {
		return false;
	}
	close = strchr(value, '"');
	if (close == NULL || (size_t)(close - value) % 2 != 0) {
		return false;
	}
	*length = (size_t)(close - value) / 2;
	return *length <= capacity && fixed_hex(value - 1, out, *length);
}

static bool string_is(const char *value, const char *expected)
{
	size_t length = strlen(expected);

	return value != NULL && value[0] == '"' && strncmp(value + 1, expected, length) == 0 &&
	       value[length + 1] == '"';
}

struct target_summary {
	size_t count;
	bool all_self_128;
	bool distinct;
	bool any_non_128;
};

static struct target_summary summarize_targets(const uint8_t *dao, size_t length,
						const uint8_t source[16])
{
	struct target_summary summary = {0, true, false, false};
	uint8_t first[16] = {0};
	size_t offset;

	if (length < 4) {
		return summary;
	}
	offset = (dao[1] & 0x40) != 0 ? 20 : 4;
	while (offset + 2 <= length) {
		uint8_t type = dao[offset];
		size_t option_length = dao[offset + 1];
		size_t end = offset + 2 + option_length;

		if (end > length) {
			break;
		}
		if (type == 5 && option_length == 18) {
			const uint8_t *target = dao + offset + 4;
			bool self_128 = dao[offset + 3] == 128 && memcmp(target, source, 16) == 0;

			if (summary.count == 0) {
				memcpy(first, target, sizeof(first));
			} else if (memcmp(first, target, sizeof(first)) != 0) {
				summary.distinct = true;
			}
			summary.count++;
			summary.all_self_128 &= self_128;
			summary.any_non_128 |= dao[offset + 3] != 128;
		}
		offset = end;
	}
	return summary;
}

static bool check_vector(const char *start, const char *end)
{
	uint8_t seed[32];
	uint8_t private_key[32];
	uint8_t public_key[32];
	uint8_t derived_public_key[32];
	uint8_t source[16];
	uint8_t dodag[16];
	uint8_t unsigned_dao[1024];
	uint8_t expected_digest[64];
	uint8_t digest[64];
	uint8_t option[58];
	uint8_t generated_signature[48];
	uint8_t sequence_be[8];
	size_t unsigned_length;
	char *number_end;
	const char *sequence_field = field(start, end, "sequence");
	const char *valid_field = field(start, end, "signature_valid");
	const char *reason_field = field(start, end, "reason");
	const char *coverage_field = field(start, end, "coverage");
	uint64_t sequence;
	crypto_sha512_ctx hash;
	bool expected_valid;
	bool actual_valid;
	struct target_summary targets;

	if (!fixed_hex(field(start, end, "signing_seed"), seed, sizeof(seed)) ||
	    !fixed_hex(field(start, end, "public_key"), public_key, sizeof(public_key)) ||
	    !fixed_hex(field(start, end, "source_ipv6"), source, sizeof(source)) ||
	    !fixed_hex(field(start, end, "effective_dodag_id"), dodag, sizeof(dodag)) ||
	    !variable_hex(field(start, end, "unsigned_dao"), unsigned_dao,
			  sizeof(unsigned_dao), &unsigned_length) ||
	    !fixed_hex(field(start, end, "digest"), expected_digest, sizeof(expected_digest)) ||
	    !fixed_hex(field(start, end, "signature_option"), option, sizeof(option)) ||
	    sequence_field == NULL || valid_field == NULL) {
		return false;
	}
	sequence = strtoull(sequence_field, &number_end, 10);
	if (number_end == sequence_field || option[0] != 0x12) {
		return false;
	}
	for (size_t i = 0; i < sizeof(sequence_be); i++) {
		sequence_be[sizeof(sequence_be) - 1 - i] = (uint8_t)(sequence >> (8 * i));
	}
	if (memcmp(option + 2, sequence_be, sizeof(sequence_be)) != 0) {
		return false;
	}

	crypto_sha512_init(&hash);
	crypto_sha512_update(&hash, domain, sizeof(domain) - 1);
	crypto_sha512_update(&hash, source, sizeof(source));
	crypto_sha512_update(&hash, dodag, sizeof(dodag));
	crypto_sha512_update(&hash, sequence_be, sizeof(sequence_be));
	crypto_sha512_update(&hash, unsigned_dao, unsigned_length);
	crypto_sha512_final(&hash, digest);
	if (memcmp(digest, expected_digest, sizeof(digest)) != 0) {
		return false;
	}

	expected_valid = strncmp(valid_field, "true", 4) == 0;
	actual_valid = schnorr48_verify(public_key, digest, sizeof(digest), option + 10, SCHNORR48_SIG_LEN);
	if (actual_valid != expected_valid) {
		return false;
	}
	if (actual_valid) {
		schnorr48_derive_keypair(seed, private_key, derived_public_key);
		if (memcmp(public_key, derived_public_key, sizeof(public_key)) != 0 ||
		    schnorr48_sign(private_key, public_key, digest, sizeof(digest),
				   generated_signature) != 0 ||
		    memcmp(generated_signature, option + 10, sizeof(generated_signature)) != 0) {
			return false;
		}
	}

	targets = summarize_targets(unsigned_dao, unsigned_length, source);
	if ((string_is(reason_field, "accepted") || string_is(reason_field, "idempotent") ||
	     string_is(reason_field, "reconciled")) &&
	    (targets.count != 1 || !targets.all_self_128)) {
		return false;
	}
	if (string_is(reason_field, "target_mismatch") &&
	    (targets.count != 1 || targets.all_self_128 || targets.any_non_128)) {
		return false;
	}
	if (string_is(reason_field, "multiple_target") &&
	    (targets.count < 2 || !targets.distinct)) {
		return false;
	}
	if (string_is(reason_field, "duplicate_target") &&
	    (targets.count < 2 || targets.distinct)) {
		return false;
	}
	if ((string_is(reason_field, "non128_target") ||
	     string_is(coverage_field, "replay_non128_target")) &&
	    (targets.count != 1 || !targets.any_non_128)) {
		return false;
	}
	return true;
}

int main(int argc, char **argv)
{
	FILE *input;
	char *json;
	long file_length;
	const char *cursor;
	unsigned int count = 0;

	if (argc != 2 || (input = fopen(argv[1], "rb")) == NULL ||
	    fseek(input, 0, SEEK_END) != 0 || (file_length = ftell(input)) < 0 ||
	    fseek(input, 0, SEEK_SET) != 0) {
		fprintf(stderr, "usage: %s dao_origin_signature.json\n", argv[0]);
		return 2;
	}
	json = malloc((size_t)file_length + 1);
	if (json == NULL || fread(json, 1, (size_t)file_length, input) != (size_t)file_length) {
		fclose(input);
		free(json);
		return 2;
	}
	fclose(input);
	json[file_length] = '\0';

	cursor = json;
	while ((cursor = strstr(cursor, "\"name\": ")) != NULL) {
		const char *next = strstr(cursor + 1, "\"name\": ");
		const char *end = next == NULL ? json + file_length : next;

		if (!check_vector(cursor, end)) {
			fprintf(stderr, "oracle mismatch at vector %u\n", count + 1);
			free(json);
			return 1;
		}
		count++;
		cursor = end;
	}
	free(json);
	printf("C/Monocypher verified %u DAO origin vectors\n", count);
	return count > 0 ? 0 : 1;
}
