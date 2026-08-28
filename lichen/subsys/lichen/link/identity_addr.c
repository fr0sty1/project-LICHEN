/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file identity_addr.c
 * @brief Key-derived LICHEN identity address helpers
 *
 * Defined in the link module so they are built for every LICHEN image,
 * independent of CONFIG_LICHEN_IPV6 (whose l2/ipv6_addr.c hosted one
 * definition) and CONFIG_LICHEN_COAP_KEYS (whose coap_keys_format.c
 * hosted the other). App identity and similar non-CoAP, non-IPv6 images
 * link these derivations without either optional subsystem.
 *
 * Prototypes are repeated locally instead of including <lichen/link_ctx.h>
 * or <lichen/coap_keys.h>, per the hash32.c pattern: keep this TU buildable
 * with only Monocypher on the include path.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <monocypher.h>
#include <monocypher-ed25519.h>

int lichen_key_pubkey_to_iid(const uint8_t pubkey[32], uint8_t iid[8]);

int lichen_key_pubkey_to_iid(const uint8_t pubkey[32], uint8_t iid[8])
{
	uint8_t hash[64];

	if (pubkey == NULL || iid == NULL) {
		return -EINVAL;
	}

	/* IID = SHA-512(pubkey)[0:8], with the U/L bit cleared.  This is the
	 * canonical LICHEN/Yggdrasil identity derivation from spec 8.5/8.7 and
	 * test/vectors/yggdrasil-derivation.json.  It must not silently fall back
	 * to raw key bytes or SHA-256 when a crypto Kconfig option is absent.
	 */
	crypto_sha512(hash, pubkey, 32);
	memcpy(iid, hash, 8);
	iid[0] &= (uint8_t)~0x02U;
	crypto_wipe(hash, sizeof(hash));

	return 0;
}

int lichen_identity_ygg_addr_from_ed25519(const uint8_t *pubkey,
					  uint8_t ygg_addr[16]);

int lichen_identity_ygg_addr_from_ed25519(const uint8_t *pubkey,
					  uint8_t ygg_addr[16])
{
	uint8_t hash[64];

	if (pubkey == NULL || ygg_addr == NULL) {
		return -EINVAL;
	}

	crypto_sha512(hash, pubkey, 32);
	ygg_addr[0] = 0x02;
	memcpy(&ygg_addr[1], hash, 7);
	memcpy(&ygg_addr[8], hash, 8);
	ygg_addr[8] &= (uint8_t)~0x02U;
	crypto_wipe(hash, sizeof(hash));
	return 0;
}
