/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file edhoc_kdf.c
 * @brief EDHOC key derivation functions
 *
 * Transcript hash computation, EDHOC-KDF, COSE structure builders.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <monocypher.h>
#include <zcbor_common.h>
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
int edhoc_kdf(const uint8_t prk[32],
	      const uint8_t th[32],
	      const char *label,
	      const uint8_t *context, size_t context_len,
	      uint8_t *out, size_t out_len)
{
	uint8_t info[CBOR_BUF_SIZE];
	size_t info_len = 0;
	int ret;

	/* Encode info as CBOR sequence */
	ZCBOR_STATE_E(zse, 0, info, sizeof(info), 0);

	if (!zcbor_uint32_put(zse, (uint32_t)out_len)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse, th, 32)) {
		return -EINVAL;
	}
	size_t label_len = strlen(label);
	if (!zcbor_tstr_encode_ptr(zse, label, label_len)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse, context, context_len)) {
		return -EINVAL;
	}

	info_len = zse->payload - info;

	ret = hkdf_expand(prk, info, info_len, out, out_len);
	crypto_wipe(info, sizeof(info));
	return ret;
}

/*
 * EDHOC-KDF with integer label for OSCORE export (matches Python edhoc.py
 * PRK_out=7, PRK_exporter=10, master_secret=0, master_salt=1 and RFC 9528 Section 7.2.1).
 * info = CBOR(length) || CBOR(TH) || CBOR(label) || CBOR(context)
 */
int edhoc_kdf_int(const uint8_t prk[32],
		  const uint8_t th[32],
		  int32_t label,
		  const uint8_t *context, size_t context_len,
		  uint8_t *out, size_t out_len)
{
	uint8_t info[CBOR_BUF_SIZE];
	size_t info_len = 0;
	int ret;

	ZCBOR_STATE_E(zse, 0, info, sizeof(info), 0);

	if (!zcbor_uint32_put(zse, (uint32_t)out_len)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse, th, 32)) {
		return -EINVAL;
	}
	if (!zcbor_int32_put(zse, label)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse, context, context_len)) {
		return -EINVAL;
	}

	info_len = zse->payload - info;

	ret = hkdf_expand(prk, info, info_len, out, out_len);
	crypto_wipe(info, sizeof(info));
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
	/* external_aad = << TH, CRED >> */
	/* Buffer large enough for TH (32 bytes + ~3 CBOR header) plus
	 * credentials up to 1024 bytes (~1027 with CBOR header).
	 * Callers with larger credentials (e.g. full X.509 certs per RFC 9528)
	 * must use the non-stack alternative; zcbor will fail gracefully
	 * if ext_aad overflows.
	 */
	uint8_t ext_aad[1056];
	ZCBOR_STATE_E(zse_ext, 0, ext_aad, sizeof(ext_aad), 0);
	if (!zcbor_bstr_encode_ptr(zse_ext, th, 32)) {
		return -EINVAL;
	}
	if (!zcbor_bstr_encode_ptr(zse_ext, cred, cred_len)) {
		return -EINVAL;
	}
	size_t ext_aad_len = zse_ext->payload - ext_aad;

	/* body_protected = << ID_CRED >> */
	uint8_t body_prot[48];
	ZCBOR_STATE_E(zse_bp, 0, body_prot, sizeof(body_prot), 0);
	if (!zcbor_bstr_encode_ptr(zse_bp, id_cred, id_cred_len)) {
		return -EINVAL;
	}
	size_t body_prot_len = zse_bp->payload - body_prot;

	/* Sig_structure = ["Signature1", body_protected, external_aad, MAC] */
	ZCBOR_STATE_E(zse, 0, out, out_size, 0);
	if (!zcbor_list_start_encode(zse, 4) ||
	    !zcbor_tstr_put_lit(zse, "Signature1") ||
	    !zcbor_bstr_encode_ptr(zse, body_prot, body_prot_len) ||
	    !zcbor_bstr_encode_ptr(zse, ext_aad, ext_aad_len) ||
	    !zcbor_bstr_encode_ptr(zse, mac, mac_len) ||
	    !zcbor_list_end_encode(zse, 4)) {
		return -EINVAL;
	}

	*out_len = zse->payload - out;
	return 0;
}

int build_enc_structure(uint8_t *out, size_t out_size, size_t *out_len,
			const uint8_t *th, const uint8_t *cred)
{
	uint8_t ext_aad[64];
	memcpy(ext_aad, th, 32);
	memcpy(ext_aad + 32, cred, 32);
	ZCBOR_STATE_E(zse, 0, out, out_size, 0);
	if (!zcbor_list_start_encode(zse, 3) ||
	    !zcbor_tstr_put_lit(zse, "Encrypt0") ||
	    !zcbor_bstr_encode_ptr(zse, NULL, 0) ||
	    !zcbor_bstr_encode_ptr(zse, ext_aad, 64) ||
	    !zcbor_list_end_encode(zse, 3)) {
		return -ENOMEM;
	}

	*out_len = zse->payload - out;
	return 0;
}
