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
 *   Byte 0:      sender_id_len (S)
 *   Byte 1-7:    left-padded sender_id (7 bytes)
 *   Byte 8-12:   left-padded PIV (5 bytes)
 *   The complete structure is XORed with common_iv.
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

	/* RFC 8613 Section 5.2: S is byte zero. */
	nonce[0] = (uint8_t)sender_id_len;

	/* Place sender_id right-aligned in the seven-byte ID field (bytes 1-7). */
	if (sender_id_len > 0 && sender_id_len <= 7) {
		size_t start = 8 - sender_id_len;
		memcpy(nonce + start, sender_id, sender_id_len);
	}

	/* Left-padded PIV in last 5 bytes (positions 8-12) */
	if (piv_len > 0 && piv_len <= 5) {
		size_t piv_start = OSCORE_NONCE_LEN - piv_len;
		memcpy(nonce + piv_start, piv, piv_len);
	}

	/* XOR with common IV */
	for (size_t i = 0; i < OSCORE_NONCE_LEN; i++) {
		nonce[i] ^= common_iv[i];
	}
}

/*
 * Encode PIV (sequence number) as variable-length big-endian.
 * Supports up to 40-bit sequence numbers per RFC 8613 (5-byte PIV max).
 */
size_t encode_piv(uint64_t seq, uint8_t piv[OSCORE_PIV_MAX_LEN])
{
	if (seq == 0) {
		piv[0] = 0;
		return 1;
	}

	/* Find number of bytes needed */
	size_t len = 0;
	uint64_t tmp = seq;
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
 * Supports up to 40-bit sequence numbers per RFC 8613 (5-byte PIV max).
 */
uint64_t decode_piv(const uint8_t *piv, size_t piv_len)
{
	uint64_t seq = 0;
	for (size_t i = 0; i < piv_len; i++) {
		seq = (seq << 8) | piv[i];
	}
	return seq;
}
