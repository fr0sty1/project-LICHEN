/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/schc.h>

#include <stdio.h>
#include <string.h>

#include "schc_parity_vectors.h"

#define MAX_COMPRESSED_SIZE 22555u
#define MAX_PACKET_SIZE 22582u
#define SENTINEL 0xa5u

static uint8_t compressed_buffer[MAX_COMPRESSED_SIZE];
static uint8_t packet_buffer[MAX_PACKET_SIZE];

#define CHECK_VECTOR(vector, condition) do { \
	if (!(condition)) { \
		printf("FAIL %s line %d: %s\n", (vector)->name, __LINE__, #condition); \
		return 1; \
	} \
} while (0)

static bool is_unchanged(const uint8_t *buffer, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		if (buffer[i] != SENTINEL) {
			return false;
		}
	}
	return true;
}

static int check_round_trip(const struct schc_parity_vector *vector)
{
	memset(compressed_buffer, SENTINEL, sizeof(compressed_buffer));
	int length = lichen_schc_compress(vector->packet, vector->packet_len,
					 compressed_buffer, sizeof(compressed_buffer));
	CHECK_VECTOR(vector, length == (int)vector->compressed_len);
	CHECK_VECTOR(vector, memcmp(compressed_buffer, vector->compressed,
				    vector->compressed_len) == 0);

	memset(packet_buffer, SENTINEL, sizeof(packet_buffer));
	length = lichen_schc_decompress(vector->compressed, vector->compressed_len,
				       packet_buffer, sizeof(packet_buffer));
	CHECK_VECTOR(vector, length == (int)vector->packet_len);
	CHECK_VECTOR(vector, memcmp(packet_buffer, vector->packet,
				    vector->packet_len) == 0);

	/* Both directions must reject an undersized output atomically. */
	memset(compressed_buffer, SENTINEL, sizeof(compressed_buffer));
	length = lichen_schc_compress(vector->packet, vector->packet_len,
					 compressed_buffer,
					 vector->compressed_len - 1u);
	CHECK_VECTOR(vector, length < 0);
	CHECK_VECTOR(vector, is_unchanged(compressed_buffer,
					  vector->compressed_len - 1u));
	memset(packet_buffer, SENTINEL, sizeof(packet_buffer));
	length = lichen_schc_decompress(vector->compressed, vector->compressed_len,
				       packet_buffer, vector->packet_len - 1u);
	CHECK_VECTOR(vector, length < 0);
	CHECK_VECTOR(vector, is_unchanged(packet_buffer, vector->packet_len - 1u));
	return 0;
}

static int check_malformed_input(const struct schc_parity_vector *vector)
{
	memset(compressed_buffer, SENTINEL, sizeof(compressed_buffer));
	int length = lichen_schc_compress(vector->packet, vector->packet_len,
					 compressed_buffer, sizeof(compressed_buffer));
	CHECK_VECTOR(vector, length < 0);
	CHECK_VECTOR(vector, is_unchanged(compressed_buffer, sizeof(compressed_buffer)));
	return 0;
}

static int check_malformed_compressed(const struct schc_parity_vector *vector)
{
	memset(packet_buffer, SENTINEL, sizeof(packet_buffer));
	int length = lichen_schc_decompress(vector->compressed, vector->compressed_len,
				       packet_buffer, sizeof(packet_buffer));
	CHECK_VECTOR(vector, length < 0);
	CHECK_VECTOR(vector, is_unchanged(packet_buffer, sizeof(packet_buffer)));
	return 0;
}

static int check_size_boundary(const struct schc_parity_vector *vector)
{
	size_t compressed_len = vector->compressed_len + vector->tail_len;
	CHECK_VECTOR(vector, compressed_len <= sizeof(compressed_buffer));
	memcpy(compressed_buffer, vector->compressed, vector->compressed_len);
	memset(&compressed_buffer[vector->compressed_len], vector->tail_byte,
	       vector->tail_len);
	memset(packet_buffer, SENTINEL, sizeof(packet_buffer));
	int length = lichen_schc_decompress(compressed_buffer, compressed_len,
				       packet_buffer, sizeof(packet_buffer));
	if (vector->expect_error) {
		CHECK_VECTOR(vector, length < 0);
		CHECK_VECTOR(vector, is_unchanged(packet_buffer, sizeof(packet_buffer)));
	} else {
		CHECK_VECTOR(vector, length == (int)vector->expected_packet_size);
	}
	return 0;
}

int main(void)
{
	for (size_t i = 0; i < sizeof(schc_parity_vectors) /
				     sizeof(schc_parity_vectors[0]); i++) {
		const struct schc_parity_vector *vector = &schc_parity_vectors[i];
		int result;

		switch (vector->kind) {
		case SCHC_PARITY_ROUND_TRIP:
			result = check_round_trip(vector);
			break;
		case SCHC_PARITY_MALFORMED_INPUT:
			result = check_malformed_input(vector);
			break;
		case SCHC_PARITY_MALFORMED_COMPRESSED:
			result = check_malformed_compressed(vector);
			break;
		case SCHC_PARITY_SIZE_BOUNDARY:
			result = check_size_boundary(vector);
			break;
		default:
			result = 1;
			break;
		}
		if (result != 0) {
			return result;
		}
	}
	printf("PASS: %zu canonical SCHC vectors\n",
	       sizeof(schc_parity_vectors) / sizeof(schc_parity_vectors[0]));
	return 0;
}
