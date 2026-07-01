/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <schc/bitstream.h>

#include <string.h>

void schc_bit_writer_init(struct schc_bit_writer *writer,
			  uint8_t *buf, size_t len)
{
	memset(buf, 0, len);
	writer->buf = buf;
	writer->buf_len = len;
	writer->nbits = 0;
}

int schc_bit_writer_write(struct schc_bit_writer *writer,
			  uint64_t value, int nbits)
{
	if (nbits < 0 || nbits > 64) {
		return -1;
	}

	size_t bytes_needed = (writer->nbits + (size_t)nbits + 7) / 8;
	if (bytes_needed > writer->buf_len) {
		return -1;
	}

	int remaining = nbits;
	int bit_offset = writer->nbits % 8;

	if (bit_offset != 0) {
		int bits_to_align = 8 - bit_offset;

		if (bits_to_align > remaining) {
			bits_to_align = remaining;
		}

		int shift = remaining - bits_to_align;
		uint8_t partial = (value >> shift) & ((1 << bits_to_align) - 1);

		writer->buf[writer->nbits / 8] |=
			partial << (8 - bit_offset - bits_to_align);
		writer->nbits += bits_to_align;
		remaining -= bits_to_align;
	}

	while (remaining >= 8) {
		remaining -= 8;
		writer->buf[writer->nbits / 8] = (value >> remaining) & 0xff;
		writer->nbits += 8;
	}

	if (remaining > 0) {
		uint8_t partial = value & ((1 << remaining) - 1);

		writer->buf[writer->nbits / 8] = partial << (8 - remaining);
		writer->nbits += remaining;
	}

	return 0;
}

int schc_bit_writer_write128(struct schc_bit_writer *writer,
			     const uint8_t value[16], int nbits)
{
	if (nbits < 0 || nbits > 128) {
		return -1;
	}

	size_t bytes_needed = (writer->nbits + (size_t)nbits + 7) / 8;
	if (bytes_needed > writer->buf_len) {
		return -1;
	}

	int remaining = nbits;
	int src_bit = 0;
	int bit_offset = writer->nbits % 8;

	if (bit_offset != 0) {
		int bits_to_align = 8 - bit_offset;

		if (bits_to_align > remaining) {
			bits_to_align = remaining;
		}

		for (int i = 0; i < bits_to_align; i++) {
			int byte_idx = src_bit / 8;
			int bit_idx = 7 - (src_bit % 8);
			uint8_t bit = (value[byte_idx] >> bit_idx) & 1;

			writer->buf[writer->nbits / 8] |=
				bit << (7 - (writer->nbits % 8));
			writer->nbits++;
			src_bit++;
		}
		remaining -= bits_to_align;
	}

	if (remaining >= 8 && (src_bit % 8) == 0) {
		int full_bytes = remaining / 8;

		memcpy(&writer->buf[writer->nbits / 8],
		       &value[src_bit / 8], full_bytes);
		writer->nbits += full_bytes * 8;
		src_bit += full_bytes * 8;
		remaining -= full_bytes * 8;
	}

	for (int i = 0; i < remaining; i++) {
		int byte_idx = src_bit / 8;
		int bit_idx = 7 - (src_bit % 8);
		uint8_t bit = (value[byte_idx] >> bit_idx) & 1;

		writer->buf[writer->nbits / 8] |=
			bit << (7 - (writer->nbits % 8));
		writer->nbits++;
		src_bit++;
	}

	return 0;
}

size_t schc_bit_writer_byte_len(const struct schc_bit_writer *writer)
{
	return (writer->nbits + 7) / 8;
}

void schc_bit_reader_init(struct schc_bit_reader *reader,
			  const uint8_t *buf, size_t len)
{
	reader->buf = buf;
	reader->buf_len = len;
	reader->pos = 0;
}

int schc_bit_reader_read(struct schc_bit_reader *reader,
			 int nbits, uint64_t *out)
{
	if (nbits < 0 || nbits > 64 ||
	    reader->pos + (size_t)nbits > reader->buf_len * 8) {
		return -1;
	}

	uint64_t value = 0;
	int remaining = nbits;
	int bit_offset = reader->pos % 8;

	if (bit_offset != 0) {
		int bits_to_align = 8 - bit_offset;

		if (bits_to_align > remaining) {
			bits_to_align = remaining;
		}

		for (int i = 0; i < bits_to_align; i++) {
			uint8_t byte = reader->buf[reader->pos / 8];
			uint8_t bit = (byte >> (7 - (reader->pos % 8))) & 1;

			value = (value << 1) | bit;
			reader->pos++;
		}
		remaining -= bits_to_align;
	}

	while (remaining >= 8) {
		value = (value << 8) | reader->buf[reader->pos / 8];
		reader->pos += 8;
		remaining -= 8;
	}

	for (int i = 0; i < remaining; i++) {
		uint8_t byte = reader->buf[reader->pos / 8];
		uint8_t bit = (byte >> (7 - (reader->pos % 8))) & 1;

		value = (value << 1) | bit;
		reader->pos++;
	}

	*out = value;
	return 0;
}

int schc_bit_reader_read_bytes(struct schc_bit_reader *reader,
			       int nbits, uint8_t *out, size_t out_size)
{
	if (nbits < 0) {
		return -1;
	}

	size_t bytes_needed = ((size_t)nbits + 7) / 8;

	if (bytes_needed > out_size ||
	    reader->pos + (size_t)nbits > reader->buf_len * 8) {
		return -1;
	}

	if ((reader->pos % 8) == 0 && (nbits % 8) == 0) {
		int full_bytes = nbits / 8;

		memcpy(out, &reader->buf[reader->pos / 8], full_bytes);
		reader->pos += nbits;
		return 0;
	}

	memset(out, 0, bytes_needed);
	for (int i = 0; i < nbits; i++) {
		uint8_t byte = reader->buf[reader->pos / 8];
		uint8_t bit = (byte >> (7 - (reader->pos % 8))) & 1;
		int byte_idx = i / 8;
		int bit_idx = 7 - (i % 8);

		out[byte_idx] |= bit << bit_idx;
		reader->pos++;
	}

	return 0;
}

size_t schc_bit_reader_residue_byte_end(const struct schc_bit_reader *reader)
{
	return (reader->pos + 7) / 8;
}
