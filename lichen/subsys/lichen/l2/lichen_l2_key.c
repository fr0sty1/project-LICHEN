/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2_key.c
 * @brief LICHEN L2 key loading functions
 *
 * Contains lichen_l2_load_key(), lichen_l2_load_link_key(),
 * and lichen_l2_set_gradient_table().
 */

#include "lichen_l2_internal.h"

LOG_MODULE_DECLARE(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

#if defined(CONFIG_LICHEN_ADAPTIVE_SF_ENABLED)
void lichen_l2_set_gradient_table(struct lichen_gradient_table *table)
{
	sf_gradient_table = table;
}
#endif

int lichen_l2_load_key(const uint8_t seed[32], uint8_t pubkey[32])
{
	int ret;

	if (seed == NULL || pubkey == NULL) {
		return -EINVAL;
	}
	if (atomic_get(&iface_init_failed)) {
		return -ENODEV;
	}
	if (!atomic_get(&link_ctx_initialized)) {
		return -EAGAIN;
	}

	k_mutex_lock(&tx_mutex, K_FOREVER);
	k_mutex_lock(&rx_mutex, K_FOREVER);
	ret = lichen_link_load_key(&link_ctx, seed);
	if (ret == 0) {
		memcpy(pubkey, link_ctx.ed25519_pk, LICHEN_L2_PUBKEY_LEN);
	}
	k_mutex_unlock(&rx_mutex);
	k_mutex_unlock(&tx_mutex);

	return ret;
}

int lichen_l2_load_link_key(const uint8_t link_key[LICHEN_LINK_KEY_LEN])
{
	int ret;

	if (link_key == NULL) {
		return -EINVAL;
	}
	if (atomic_get(&iface_init_failed)) {
		return -ENODEV;
	}
	if (!atomic_get(&link_ctx_initialized)) {
		return -EAGAIN;
	}

	k_mutex_lock(&tx_mutex, K_FOREVER);
	k_mutex_lock(&rx_mutex, K_FOREVER);
	ret = lichen_link_load_link_key(&link_ctx, link_key);
	k_mutex_unlock(&rx_mutex);
	k_mutex_unlock(&tx_mutex);

	return ret;
}
