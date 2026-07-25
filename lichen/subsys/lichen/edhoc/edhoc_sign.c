/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file edhoc_sign.c
 * @brief EDHOC signing and verification
 *
 * Schnorr48 signature operations for EDHOC authentication.
 */

#include <zephyr/kernel.h>

#include <monocypher.h>
#include <lichen/schnorr48.h>

#include "edhoc_internal.h"

int edhoc_sign(uint8_t sig[EDHOC_SIG_LEN],
	       const uint8_t *seed,
	       const uint8_t *pubkey,
	       const uint8_t *msg, size_t msg_len)
{
	uint8_t privkey[SCHNORR48_PRIVKEY_LEN];
	uint8_t computed_pub[SCHNORR48_PUBKEY_LEN];
	schnorr48_derive_keypair(seed, privkey, computed_pub);
	if (crypto_verify32(pubkey, computed_pub) != 0) {
		crypto_wipe(privkey, sizeof(privkey));
		crypto_wipe(computed_pub, sizeof(computed_pub));
		return -EINVAL;
	}
	int ret = schnorr48_sign(privkey, pubkey, msg, msg_len, sig);
	crypto_wipe(privkey, sizeof(privkey));
	crypto_wipe(computed_pub, sizeof(computed_pub));
	return ret;
}

int edhoc_verify(const uint8_t *pubkey,
		 const uint8_t *sig,
		 const uint8_t *msg, size_t msg_len)
{
	return schnorr48_verify(pubkey, msg, msg_len, sig, EDHOC_SIG_LEN) ? 0 : -1;
}
