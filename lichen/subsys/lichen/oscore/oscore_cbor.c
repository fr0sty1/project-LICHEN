/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file oscore_cbor.c
 * @brief OSCORE CBOR encoding for HKDF info and AAD structures
 *
 * Implements CBOR encoding for RFC 8613 info and AAD structures.
 */

#include <limits.h>
#include <string.h>

#include <lichen/oscore.h>
#include "oscore_internal.h"

/*
 * OSCORE info structure for HKDF (RFC 8613 Section 3.2.1):
 *
 * info = [
 *   id : bstr,
 *   id_context : bstr / nil,
 *   alg_aead : int,
 *   type : tstr,
 *   L : uint
 * ]
 *
 * We encode this as a minimal CBOR array.
 */

/*
 * Build OSCORE HKDF info structure in CBOR format (RFC 8613 Section 3.2.1):
 *   info = [id : bstr, id_context : bstr / nil, alg_aead : int, type : tstr, L : uint]
 * Returns encoded length, or negative on error.
 *
 * Note: This function contains inline CBOR encoding rather than using a
 * shared CBOR library. This is intentional - OSCORE info encoding is a
 * simple, fixed-format structure (5-element array with known types), and
 * pulling in a general CBOR encoder would add code size for no benefit.
 * The encoding here matches RFC 8613 Section 3.2.1 exactly.
 *
 * CBOR encoding reference (RFC 8949 Section 3.1 - Major Types):
 *   Major type 0 (uint):   0x00-0x17 = value 0-23 inline
 *                          0x18 = 1-byte uint follows
 *   Major type 2 (bstr):   0x40-0x57 = bstr length 0-23 inline
 *                          0x58 = 1-byte length follows
 *   Major type 3 (tstr):   0x60-0x77 = tstr length 0-23 inline
 *   Major type 4 (array):  0x80-0x97 = array of 0-23 items
 *   Major type 7 (simple): 0xf6 = null
 */
int build_info_cbor(const uint8_t *id, size_t id_len,
		    const uint8_t *id_context, size_t id_context_len,
		    const char *type, size_t out_len,
		    uint8_t *buf, size_t buf_len)
{
	size_t off = 0;

	/*
	 * CBOR array header: major type 4 (0x80) + 5 items = 0x85
	 * RFC 8949 Section 3.1: array(n) = 0x80 | n for n <= 23
	 */
	if (off >= buf_len) return -1;
	buf[off++] = 0x85;

	/*
	 * id: bstr (RFC 8613 Section 3.2.1, first element)
	 * CBOR bstr: major type 2 (0x40) + length
	 *   0x40-0x57: length 0-23 inline (0x40 | len)
	 *   0x58: 1-byte length follows
	 */
	if (id_len <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = 0x40 | (uint8_t)id_len;
	} else {
		if (off + 1 >= buf_len) return -1;
		buf[off++] = 0x58;
		buf[off++] = (uint8_t)id_len;
	}
	if (off + id_len > buf_len) return -1;
	/* id may be NULL for an empty kid (valid per RFC 8613); memcpy with a
	 * NULL source is UB even for zero length, so guard it. */
	if (id_len > 0) {
		memcpy(buf + off, id, id_len);
	}
	off += id_len;

	/*
	 * id_context: bstr or null (RFC 8613 Section 3.2.1, second element)
	 * Encode as CBOR null (0xf6) when absent, bstr otherwise.
	 * RFC 8949 Section 3.3: simple value 22 (null) = 0xf6
	 */
	if (id_context_len == 0) {
		if (off >= buf_len) return -1;
		buf[off++] = 0xf6;
	} else {
		if (id_context_len <= 23) {
			if (off >= buf_len) return -1;
			buf[off++] = 0x40 | (uint8_t)id_context_len;
		} else {
			if (off + 1 >= buf_len) return -1;
			buf[off++] = 0x58;
			buf[off++] = (uint8_t)id_context_len;
		}
		if (off + id_context_len > buf_len) return -1;
		memcpy(buf + off, id_context, id_context_len);
		off += id_context_len;
	}

	/*
	 * alg_aead: int (RFC 8613 Section 3.2.1, third element)
	 * Value 10 = AES-CCM-16-64-128 (COSE Algorithm ID from RFC 9053)
	 * CBOR uint: major type 0, values 0-23 encode directly (no prefix)
	 */
	if (off >= buf_len) return -1;
	buf[off++] = OSCORE_ALG_AEAD;

	/*
	 * type: tstr (RFC 8613 Section 3.2.1, fourth element)
	 * One of "Key", "IV", or "Info"
	 * CBOR tstr: major type 3 (0x60) + length
	 *   0x60-0x77: length 0-23 inline (0x60 | len)
	 */
	size_t type_len = strlen(type);
	if (type_len <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = 0x60 | (uint8_t)type_len;
	} else {
		return -1; /* type shouldn't be > 23 chars */
	}
	if (off + type_len > buf_len) return -1;
	memcpy(buf + off, type, type_len);
	off += type_len;

	/*
	 * L: uint (RFC 8613 Section 3.2.1, fifth element)
	 * Output length in bytes (16 for Key, 13 for IV)
	 * CBOR uint: major type 0
	 *   0x00-0x17: value 0-23 inline
	 *   0x18: 1-byte value follows
	 */
	if (out_len <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = (uint8_t)out_len;
	} else if (out_len <= 255) {
		if (off + 1 >= buf_len) return -1;
		buf[off++] = 0x18;
		buf[off++] = (uint8_t)out_len;
	} else {
		return -1; /* L shouldn't be > 255 for OSCORE */
	}

	/* Guard against unlikely overflow before int cast (python-ano.118) */
	if (off > (size_t)INT_MAX) {
		return -1;
	}

	return (int)off;
}

/*
 * Build OSCORE external AAD per RFC 8613 Section 5.4.
 *
 * external_aad = bstr .cbor aad_array
 * aad_array = [
 *   oscore_version : uint,        (1 for OSCORE v1)
 *   algorithms : [alg_aead : int], (array containing algorithm ID)
 *   request_kid : bstr,
 *   request_piv : bstr,
 *   options : bstr                (Class I options, empty for now)
 * ]
 *
 * Then wrapped in Enc_structure (RFC 9052 Section 5.3):
 * Enc_structure = [
 *   "Encrypt0",
 *   h'',  (empty protected header)
 *   external_aad
 * ]
 *
 * Returns encoded length, or negative on error.
 *
 * CBOR encoding reference (RFC 8949 Section 3.1 - Major Types):
 *   Major type 0 (uint):   0x00-0x17 = value 0-23 inline
 *   Major type 2 (bstr):   0x40-0x57 = bstr length 0-23 inline (0x40 | len)
 *                          0x58 = 1-byte length follows
 *   Major type 3 (tstr):   0x60-0x77 = tstr length 0-23 inline (0x60 | len)
 *   Major type 4 (array):  0x80-0x97 = array of 0-23 items (0x80 | count)
 */
int build_oscore_aad(const uint8_t *request_kid, size_t request_kid_len,
		     const uint8_t *request_piv, size_t request_piv_len,
		     uint8_t *buf, size_t buf_len)
{
	size_t off = 0;

	/*
	 * First build the aad_array (RFC 8613 Section 5.4), then wrap it.
	 * We build the inner structure in a temp buffer, then encode it
	 * as a bstr inside the Enc_structure.
	 */
	uint8_t inner[64];
	size_t inner_off = 0;

	/*
	 * aad_array: 5-element array
	 * CBOR array: major type 4 (0x80) + 5 items = 0x85
	 */
	inner[inner_off++] = 0x85;

	/*
	 * oscore_version: uint = 1 (RFC 8613 Section 5.4, first element)
	 * CBOR uint: values 0-23 encode directly
	 */
	inner[inner_off++] = 0x01;

	/*
	 * algorithms: 1-element array containing alg_aead (second element)
	 * 0x81 = array of 1 item (0x80 | 1)
	 * Value 10 = AES-CCM-16-64-128 (COSE Algorithm ID from RFC 9053)
	 */
	inner[inner_off++] = 0x81;
	inner[inner_off++] = OSCORE_ALG_AEAD;

	/*
	 * request_kid: bstr (RFC 8613 Section 5.4, third element)
	 * CBOR bstr: 0x40 | len for len <= 23
	 */
	if (request_kid_len <= 23) {
		inner[inner_off++] = 0x40 | (uint8_t)request_kid_len;
	} else {
		return -1; /* shouldn't happen with OSCORE_ID_MAX_LEN */
	}
	if (request_kid_len > 0) {
		if (inner_off + request_kid_len > sizeof(inner)) {
			return -1;
		}
		memcpy(inner + inner_off, request_kid, request_kid_len);
		inner_off += request_kid_len;
	}

	/*
	 * request_piv: bstr (RFC 8613 Section 5.4, fourth element)
	 * CBOR bstr: 0x40 | len for len <= 23
	 */
	if (request_piv_len <= 23) {
		inner[inner_off++] = 0x40 | (uint8_t)request_piv_len;
	} else {
		return -1;
	}
	if (request_piv_len > 0) {
		if (inner_off + request_piv_len > sizeof(inner)) {
			return -1;
		}
		memcpy(inner + inner_off, request_piv, request_piv_len);
		inner_off += request_piv_len;
	}
	/*
	 * options: empty bstr (RFC 8613 Section 5.4, fifth element)
	 * Class I options - not used in this implementation
	 * 0x40 = bstr of length 0
	 */
	inner[inner_off++] = 0x40;

	/*
	 * Now build Enc_structure (RFC 9052 Section 5.3):
	 *   ["Encrypt0", h'', external_aad]
	 * where external_aad = bstr .cbor aad_array (the inner buffer)
	 */

	/*
	 * 3-element array
	 * CBOR array: 0x83 = 0x80 | 3
	 */
	if (off >= buf_len) return -1;
	buf[off++] = 0x83;

	/*
	 * "Encrypt0" as tstr (8 chars)
	 * CBOR tstr: 0x68 = 0x60 | 8 (tstr of length 8)
	 */
	if (off >= buf_len) return -1;
	buf[off++] = 0x68;
	if (off + 8 > buf_len) return -1;
	memcpy(buf + off, "Encrypt0", 8);
	off += 8;

	/*
	 * empty bstr (protected header per RFC 9052 Section 5.3)
	 * 0x40 = bstr of length 0
	 */
	if (off >= buf_len) return -1;
	buf[off++] = 0x40;

	/*
	 * external_aad as bstr wrapping the inner CBOR
	 * CBOR bstr: 0x40 | len for len <= 23, 0x58 + len for len 24-255
	 */
	if (inner_off <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = 0x40 | (uint8_t)inner_off;
	} else {
		if (off + 1 >= buf_len) return -1;
		buf[off++] = 0x58;
		buf[off++] = (uint8_t)inner_off;
	}
	if (off + inner_off > buf_len) return -1;
	memcpy(buf + off, inner, inner_off);
	off += inner_off;

	/* Guard against unlikely overflow before int cast (python-ano.118) */
	if (off > (size_t)INT_MAX) {
		return -1;
	}

	return (int)off;
}
