/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file edhoc_kdf.c
 * @brief EDHOC key derivation functions
 *
 * Transcript hash computation, EDHOC-KDF, COSE structure builders.
 */

#include <errno.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <monocypher.h>
#include <zcbor_common.h>
#include <zcbor_decode.h>
#include <zcbor_encode.h>

#include "edhoc_internal.h"

LOG_MODULE_DECLARE(edhoc, CONFIG_LICHEN_EDHOC_LOG_LEVEL);

/*
 * Compute transcript hash per RFC 9528 Section 4.1.2
 * TH = H(CBOR(bstr1) || CBOR(bstr2) || CBOR(bstr3))
 * All inputs are CBOR-encoded as byte strings before hashing.
 * Returns 0 on success, negative on error.
 */
int compute_th(uint8_t out[32],
	       const uint8_t *b1, size_t b1_len,
	       const uint8_t *b2, size_t b2_len,
	       const uint8_t *b3, size_t b3_len)
{
	uint8_t cbor_buf[256];
	ZCBOR_STATE_E(zse, 0, cbor_buf, sizeof(cbor_buf), 0);

	if (!zcbor_bstr_encode_ptr(zse, b1, b1_len) ||
	    !zcbor_bstr_encode_ptr(zse, b2, b2_len)) {
		return -ENOMEM;
	}
	if (b3 != NULL && b3_len > 0 &&
	    !zcbor_bstr_encode_ptr(zse, b3, b3_len)) {
		return -ENOMEM;
	}

	size_t cbor_len = zse->payload - cbor_buf;
	return sha256_hash(cbor_buf, cbor_len, out);
}

/*
 * EDHOC-KDF (RFC 9528 Section 4.1.2)
 * info = CBOR(length) || CBOR(th) || CBOR(label) || CBOR(context)
 */
/*
 * EDHOC-KDF with integer label for OSCORE export (RFC 9528 Section 4.1.2).
 * info = CBOR(label) || CBOR(context) || CBOR(length)
 */
int edhoc_kdf_int(const uint8_t prk[32],
		  int32_t label,
		  const uint8_t *context, size_t context_len,
		  uint8_t *out, size_t out_len)
{
	uint8_t info[CBOR_BUF_SIZE];
	size_t info_len = 0;
	int ret;

	ZCBOR_STATE_E(zse, 0, info, sizeof(info), 0);

	if (!zcbor_int32_put(zse, label)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse, context, context_len)) {
		return -EINVAL;
	}
	if (!zcbor_uint32_put(zse, (uint32_t)out_len)) {
		return -EINVAL;
	}

	info_len = zse->payload - info;

	ret = hkdf_expand(prk, info, info_len, out, out_len);
	crypto_wipe(info, sizeof(info));
	return ret;
}

int edhoc_encode_identifier(const uint8_t *cid, size_t cid_len,
			    uint8_t *out, size_t out_size, size_t *out_len)
{
	if (cid == NULL || out == NULL || out_len == NULL ||
	    cid_len > EDHOC_CID_MAX_LEN) {
		return -EINVAL;
	}
	ZCBOR_STATE_E(zse, 0, out, out_size, 0);
	bool ok;
	if (cid_len == 1 && cid[0] <= 23) {
		ok = zcbor_int32_put(zse, cid[0]);
	} else if (cid_len == 1 && cid[0] >= 232) {
		ok = zcbor_int32_put(zse, (int32_t)cid[0] - 256);
	} else {
		ok = zcbor_bstr_encode_ptr(zse, cid, cid_len);
	}
	if (!ok) {
		return -ENOMEM;
	}
	*out_len = zse->payload - out;
	return 0;
}

int edhoc_decode_identifier(const uint8_t *in, size_t in_len,
			    uint8_t *cid, size_t *cid_len, size_t *consumed)
{
	if (in == NULL || cid == NULL || cid_len == NULL || consumed == NULL) {
		return -EINVAL;
	}
	ZCBOR_STATE_D(zsd, 0, in, in_len, 2, 0);
	int32_t value;
	struct zcbor_string bytes;
	if (zcbor_int32_decode(zsd, &value)) {
		if (value < -24 || value > 23) {
			return -EINVAL;
		}
		cid[0] = (uint8_t)(value < 0 ? value + 256 : value);
		*cid_len = 1;
	} else if (zcbor_bstr_decode(zsd, &bytes)) {
		if (bytes.len > EDHOC_CID_MAX_LEN) {
			return -EINVAL;
		}
		memcpy(cid, bytes.value, bytes.len);
		*cid_len = bytes.len;
	} else {
		return -EINVAL;
	}
	*consumed = zsd->payload - in;
	return 0;
}

int edhoc_encode_id_cred(const uint8_t pubkey[32], uint8_t out[11])
{
	uint8_t digest[32];
	int ret = sha256_hash(pubkey, 32, digest);
	if (ret != 0) {
		return ret;
	}
	out[0] = 0xa1; /* map(1) */
	out[1] = 0x04; /* kid */
	out[2] = 0x48; /* bstr(8) */
	memcpy(out + 3, digest, 8);
	crypto_wipe(digest, sizeof(digest));
	return 0;
}

int edhoc_encode_credential(const uint8_t pubkey[32], uint8_t out[40])
{
	static const uint8_t prefix[8] = {0xa3, 0x01, 0x01, 0x20,
					 0x06, 0x21, 0x58, 0x20};
	memcpy(out, prefix, sizeof(prefix));
	memcpy(out + sizeof(prefix), pubkey, 32);
	return 0;
}

int edhoc_compute_th2(const uint8_t g_y[32], const uint8_t *msg1,
		      size_t msg1_len, uint8_t out[32])
{
	uint8_t h_msg1[32];
	uint8_t sequence[68];
	int ret = sha256_hash(msg1, msg1_len, h_msg1);
	if (ret != 0) {
		return ret;
	}
	ZCBOR_STATE_E(zse, 0, sequence, sizeof(sequence), 0);
	if (!zcbor_bstr_encode_ptr(zse, g_y, 32) ||
	    !zcbor_bstr_encode_ptr(zse, h_msg1, 32)) {
		crypto_wipe(h_msg1, sizeof(h_msg1));
		return -ENOMEM;
	}
	ret = sha256_hash(sequence, zse->payload - sequence, out);
	crypto_wipe(h_msg1, sizeof(h_msg1));
	crypto_wipe(sequence, sizeof(sequence));
	return ret;
}

int edhoc_compute_transcript(const uint8_t th[32],
			     const uint8_t *plaintext, size_t plaintext_len,
			     const uint8_t *credential, size_t credential_len,
			     uint8_t out[32])
{
	uint8_t sequence[256];
	ZCBOR_STATE_E(zse, 0, sequence, sizeof(sequence), 0);
	if (!zcbor_bstr_encode_ptr(zse, th, 32) ||
	    !zcbor_bstr_encode_ptr(zse, plaintext, plaintext_len)) {
		return -ENOMEM;
	}
	size_t sequence_len = (size_t)(zse->payload - sequence);
	if (sizeof(sequence) - sequence_len < credential_len) {
		return -ENOMEM;
	}
	memcpy(sequence + sequence_len, credential, credential_len);
	sequence_len += credential_len;
	int ret = sha256_hash(sequence, sequence_len, out);
	crypto_wipe(sequence, sizeof(sequence));
	return ret;
}

/*
 * Build COSE Sig_structure per RFC 9052 Section 4.4.
 * Sig_structure = ["Signature1", body_protected, external_aad, payload]
 *
 * For EDHOC Suite 0:
 * - body_protected = << ID_CRED >> (bstr-wrapped)
 * - external_aad = << TH, CRED >> (CBOR sequence as bstr)
 * - payload = MAC (from EDHOC-KDF)
 *
 * SECURITY: All CBOR encoding return values must be checked. If encoding
 * fails (e.g., buffer overflow), operating on corrupted data could cause
 * signature verification to fail or potentially accept invalid signatures.
 */
int build_sig_structure(const uint8_t *id_cred, size_t id_cred_len,
			const uint8_t *th,
			const uint8_t *cred, size_t cred_len,
			const uint8_t *mac, size_t mac_len,
			uint8_t *out, size_t out_size, size_t *out_len)
{
	if (id_cred == NULL || th == NULL || cred == NULL || mac == NULL ||
	    out == NULL || out_len == NULL) {
		return -EINVAL;
	}
	/* Deterministic CBOR requires a definite array (0x84).  zcbor's generic
	 * streaming list API intentionally emits an indefinite array, which is
	 * valid CBOR but not the byte-exact EDHOC Sig_structure. */
	/* The public LICHEN API accepts raw Ed25519 keys and therefore produces a
	 * 40-byte CCS.  Keep modest headroom without putting a certificate-sized
	 * temporary on constrained-node stacks. */
	uint8_t ext_aad[192];
	ZCBOR_STATE_E(zse_ext, 0, ext_aad, sizeof(ext_aad), 0);
	if (!zcbor_bstr_encode_ptr(zse_ext, th, 32)) {
		return -ENOMEM;
	}
	size_t ext_aad_len = (size_t)(zse_ext->payload - ext_aad);
	if (sizeof(ext_aad) - ext_aad_len < cred_len) {
		return -ENOMEM;
	}
	memcpy(ext_aad + ext_aad_len, cred, cred_len); ext_aad_len += cred_len;
	if (out_size < 12) {
		return -ENOMEM;
	}
	out[0] = 0x84;
	out[1] = 0x6a;
	memcpy(out + 2, "Signature1", 10);
	ZCBOR_STATE_E(zse, 0, out + 12, out_size - 12, 0);
	if (!zcbor_bstr_encode_ptr(zse, id_cred, id_cred_len) ||
	    !zcbor_bstr_encode_ptr(zse, ext_aad, ext_aad_len) ||
	    !zcbor_bstr_encode_ptr(zse, mac, mac_len)) {
		return -ENOMEM;
	}
	*out_len = 12 + (size_t)(zse->payload - (out + 12));
	return 0;
}

int build_enc_structure(uint8_t *out, size_t out_size, size_t *out_len,
			const uint8_t th[32])
{
	if (out == NULL || out_len == NULL || th == NULL || out_size < 45) {
		return -EINVAL;
	}
	out[0] = 0x83;
	out[1] = 0x68;
	memcpy(out + 2, "Encrypt0", 8);
	out[10] = 0x40;
	out[11] = 0x58; out[12] = 0x20;
	memcpy(out + 13, th, 32);
	*out_len = 45;
	return 0;
}
