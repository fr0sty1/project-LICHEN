/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file oscore_nonce.c
 * @brief OSCORE nonce computation and PIV encoding
 *
 * Implements nonce construction per RFC 8613 Section 5.2 and
 * Partial IV encoding/decoding.
 */

#include <string.h>

#include <lichen/oscore.h>
#include "oscore_internal.h"

/*
 * Compute nonce from Partial IV and Common IV per RFC 8613 Section 5.2.
 *
 * Nonce structure (13 bytes for AES-CCM-16-64-128):
 *   Byte 0-5:   zeros (padding)
 *   Byte 6:     sender_id_len (1 byte)
 *   Byte 7-12:  left-padded sender_id (6 bytes max, but 7th byte overlaps len)
 *   Then XOR with PIV (left-padded in last 5 bytes) and common_iv.
 *
 * For sender_id_len == 7, the first byte of sender_id occupies position 6,
 * which is the same position as sender_id_len. Per RFC 8613, this is XORed:
 *   nonce[6] = sender_id_len XOR sender_id[0]
 *
 * Note: sender_id may be NULL when sender_id_len == 0, and piv may be NULL
 * when piv_len == 0. The function does not dereference these pointers when
 * their lengths are zero.
 */
void compute_nonce(const uint8_t *sender_id, size_t sender_id_len,
		   const uint8_t *piv, size_t piv_len,
		   const uint8_t *common_iv,
		   uint8_t nonce[OSCORE_NONCE_LEN])
{
	memset(nonce, 0, OSCORE_NONCE_LEN);
	if (sender_id == NULL) sender_id_len = 0;
	if (piv == NULL) piv_len = 0;

	/*
	 * RFC 8613 Section 5.2: The nonce is constructed as:
	 *   - First byte: left-pad zeros such that ID ends at byte NONCE_LEN-1
	 *   - s (sender_id_len) is placed at byte (NONCE_LEN - 6 - 1) = byte 6
	 *   - sender_id is right-aligned in the last 6 bytes (positions 7-12)
	 *   - For sender_id_len == 7, the first byte of sender_id is XORed
	 *     with the s field at position 6
	 */

	/* Encode sender_id_len at position OSCORE_NONCE_S_POS per RFC 8613 */
	nonce[OSCORE_NONCE_S_POS] = (uint8_t)sender_id_len;

	/* Place sender_id right-aligned in the last bytes, up to 7 bytes */
	if (sender_id_len > 0 && sender_id_len <= 7) {
		/* sender_id ends at position NONCE_LEN-1 (byte 12) */
		size_t start = OSCORE_NONCE_LEN - sender_id_len;
		for (size_t i = 0; i < sender_id_len; i++) {
			nonce[start + i] ^= sender_id[i];
		}
	}

	/* Left-padded PIV in last 5 bytes (positions 8-12) */
	if (piv_len > 0 && piv_len <= 5) {
		size_t piv_start = OSCORE_NONCE_LEN - piv_len;
		for (size_t i = 0; i < piv_len; i++) {
			nonce[piv_start + i] ^= piv[i];
		}
	}

	/* XOR with common IV */
	for (size_t i = 0; i < OSCORE_NONCE_LEN; i++) {
		nonce[i] ^= common_iv[i];
	}
}

/*
 * Encode PIV (sequence number) as variable-length big-endian.
 */
size_t encode_piv(uint32_t seq, uint8_t piv[OSCORE_PIV_MAX_LEN])
{
	if (seq == 0) {
		piv[0] = 0;
		return 1;
	}

	/* Find number of bytes needed */
	size_t len = 0;
	uint32_t tmp = seq;
	while (tmp > 0) {
		len++;
		tmp >>= 8;
	}

	/* Encode big-endian */
	for (size_t i = 0; i < len; i++) {
		piv[len - 1 - i] = (uint8_t)(seq & 0xFF);
		seq >>= 8;
	}

	return len;
}

/*
 * Decode PIV to sequence number.
 */
uint32_t decode_piv(const uint8_t *piv, size_t piv_len)
{
	uint32_t seq = 0;
	for (size_t i = 0; i < piv_len; i++) {
		seq = (seq << 8) | piv[i];
	}
	return seq;
}
