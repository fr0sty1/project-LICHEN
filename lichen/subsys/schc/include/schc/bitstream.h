/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc/bitstream.h
 * @brief MSB-first bitstream helpers for SCHC residues.
 */

#ifndef SCHC_BITSTREAM_H_
#define SCHC_BITSTREAM_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct schc_bit_writer {
	uint8_t *buf;
	size_t buf_len;
	size_t nbits;
};

void schc_bit_writer_init(struct schc_bit_writer *writer,
			  uint8_t *buf, size_t len);
int schc_bit_writer_write(struct schc_bit_writer *writer,
			  uint64_t value, int nbits);
int schc_bit_writer_write128(struct schc_bit_writer *writer,
			     const uint8_t value[16], int nbits);
size_t schc_bit_writer_byte_len(const struct schc_bit_writer *writer);

struct schc_bit_reader {
	const uint8_t *buf;
	size_t buf_len;
	size_t pos;
};

void schc_bit_reader_init(struct schc_bit_reader *reader,
			  const uint8_t *buf, size_t len);
int schc_bit_reader_read(struct schc_bit_reader *reader,
			 int nbits, uint64_t *out);
int schc_bit_reader_read_bytes(struct schc_bit_reader *reader,
			       int nbits, uint8_t *out, size_t out_size);
size_t schc_bit_reader_residue_byte_end(const struct schc_bit_reader *reader);

#ifdef __cplusplus
}
#endif

#endif /* SCHC_BITSTREAM_H_ */
