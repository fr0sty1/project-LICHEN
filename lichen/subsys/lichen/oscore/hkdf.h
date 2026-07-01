/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file hkdf.h
 * @brief HKDF-SHA256 key derivation (RFC 5869)
 *
 * Stack Requirements:
 *   lichen_hkdf_expand() uses ~350 bytes of stack (289-byte working buffer
 *   plus local variables). OSCORE key derivation calls this function, so
 *   the call chain oscore_ctx_create() -> derive_key() -> hkdf_expand()
 *   requires approximately 500 bytes of stack.
 *
 *   Minimum recommended stack for OSCORE-enabled tasks: 1KB.
 */

#ifndef LICHEN_OSCORE_HKDF_H_
#define LICHEN_OSCORE_HKDF_H_

#include <stdint.h>
#include <stddef.h>
#include <errno.h>

/**
 * @brief HKDF-Extract: derive PRK from salt and IKM
 *
 * @param[in]  salt     Optional salt (may be NULL)
 * @param[in]  salt_len Salt length
 * @param[in]  ikm      Input keying material
 * @param[in]  ikm_len  IKM length
 * @param[out] prk      32-byte pseudorandom key
 * @return 0 on success, negative errno on failure
 */
int lichen_hkdf_extract(const uint8_t *salt, size_t salt_len,
		 const uint8_t *ikm, size_t ikm_len,
		 uint8_t prk[32]);

/**
 * @brief HKDF-Expand: derive OKM from PRK and info
 *
 * @param[in]  prk      32-byte pseudorandom key
 * @param[in]  info     Context info (may be NULL)
 * @param[in]  info_len Info length
 * @param[out] okm      Output keying material
 * @param[in]  okm_len  Desired output length (max 255*32)
 * @return 0 on success, -EINVAL for invalid params, -EMSGSIZE if okm_len too large
 */
int lichen_hkdf_expand(const uint8_t prk[32],
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len);

/**
 * @brief HKDF-SHA256: full extract-then-expand
 *
 * @param[in]  salt     Optional salt (may be NULL)
 * @param[in]  salt_len Salt length
 * @param[in]  ikm      Input keying material
 * @param[in]  ikm_len  IKM length
 * @param[in]  info     Context info (may be NULL)
 * @param[in]  info_len Info length
 * @param[out] okm      Output keying material
 * @param[in]  okm_len  Desired output length
 * @return 0 on success, negative errno on failure
 */
int lichen_hkdf_sha256(const uint8_t *salt, size_t salt_len,
		const uint8_t *ikm, size_t ikm_len,
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len);

#endif /* LICHEN_OSCORE_HKDF_H_ */
