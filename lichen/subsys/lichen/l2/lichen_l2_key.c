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

/*
 * Install the primary address before committing a new identity so an
 * exhausted net_if address table cannot leave the link context keyed but
 * unreachable.  The caller holds both L2 mutexes, which serializes identity
 * changes.  `added` lets the caller undo only this invocation's allocation if
 * the subsequent key/replay transaction fails.
 */
static int prepare_primary_addr(const uint8_t pubkey[LICHEN_L2_PUBKEY_LEN],
				struct in6_addr *addr, bool *added)
{
	struct net_if *iface = lichen_iface_read();
	struct net_if_addr *ifaddr;
	int ret;

	if (iface == NULL || addr == NULL || added == NULL) {
		return -ENODEV;
	}

	ret = lichen_yggdrasil_addr(pubkey, addr);
	if (ret != 0) {
		return ret;
	}

	*added = false;
	ifaddr = net_if_ipv6_addr_lookup_by_iface(iface, addr);
	if (ifaddr != NULL) {
		return 0;
	}

	ifaddr = net_if_ipv6_addr_add(iface, addr, NET_ADDR_MANUAL, 0);
	if (ifaddr == NULL) {
		LOG_ERR("lichen_l2: no IPv6 slot for primary address");
		return -ENOMEM;
	}

	*added = true;
	return 0;
}

static void rollback_primary_addr(const struct in6_addr *addr, bool added)
{
	struct net_if *iface = lichen_iface_read();

	if (added && iface != NULL && !net_if_ipv6_addr_rm(iface, addr)) {
		LOG_ERR("lichen_l2: failed to roll back primary address");
	}
}

static void retire_previous_primary_addr(const uint8_t old_pubkey[LICHEN_L2_PUBKEY_LEN],
					 const uint8_t new_pubkey[LICHEN_L2_PUBKEY_LEN])
{
	struct net_if *iface = lichen_iface_read();
	struct in6_addr old_addr;

	if (iface == NULL || memcmp(old_pubkey, new_pubkey, LICHEN_L2_PUBKEY_LEN) == 0) {
		return;
	}
	if (lichen_yggdrasil_addr(old_pubkey, &old_addr) != 0) {
		LOG_ERR("lichen_l2: failed to derive retired primary address");
		return;
	}
	if (net_if_ipv6_addr_lookup_by_iface(iface, &old_addr) != NULL &&
	    !net_if_ipv6_addr_rm(iface, &old_addr)) {
		LOG_ERR("lichen_l2: failed to retire previous primary address");
	}
}

#if defined(CONFIG_LICHEN_ADAPTIVE_SF_ENABLED)
void lichen_l2_set_gradient_table(struct lichen_gradient_table *table)
{
	sf_gradient_table = table;
}
#endif

int lichen_l2_load_key(const uint8_t seed[32], uint8_t pubkey[32])
{
	int ret;
	uint8_t candidate_pubkey[LICHEN_PK_LEN];
	uint8_t old_pubkey[LICHEN_PK_LEN];
	struct in6_addr candidate_addr;
	bool had_key;
	bool primary_added = false;
#ifdef CONFIG_LICHEN_LINK_REPLAY_PERSIST
	uint8_t boot_epoch;
	bool replay_opened = false;
#endif

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
	had_key = link_ctx.has_key;
	if (had_key) {
		memcpy(old_pubkey, link_ctx.ed25519_pk, sizeof(old_pubkey));
	}
#ifdef CONFIG_LICHEN_LINK_REPLAY_PERSIST
	if (link_ctx.has_key) {
		ret = -EALREADY;
	} else {
		ret = lichen_link_derive_pubkey(seed, candidate_pubkey);
	}
	if (ret == 0) {
		ret = lichen_replay_settings_open(&replay_table, candidate_pubkey,
						  link_ctx.epoch, &boot_epoch);
		replay_opened = ret == 0;
	}
	if (ret == 0) {
		ret = prepare_primary_addr(candidate_pubkey, &candidate_addr,
					   &primary_added);
	}
	if (ret == 0) {
		ret = lichen_link_load_key(&link_ctx, seed);
	}
	if (ret == 0) {
		ret = lichen_link_set_epoch(&link_ctx, boot_epoch);
	}
	if (ret != 0 && replay_opened) {
		lichen_replay_settings_close();
	}
#else
	ret = lichen_link_derive_pubkey(seed, candidate_pubkey);
	if (ret == 0) {
		ret = prepare_primary_addr(candidate_pubkey, &candidate_addr,
					   &primary_added);
	}
	if (ret == 0) {
		ret = lichen_link_load_key(&link_ctx, seed);
	}
#endif
	if (ret == 0) {
		memcpy(pubkey, candidate_pubkey, LICHEN_L2_PUBKEY_LEN);
		if (had_key) {
			retire_previous_primary_addr(old_pubkey, candidate_pubkey);
		}
	} else {
		rollback_primary_addr(&candidate_addr, primary_added);
	}
	secure_zero(old_pubkey, sizeof(old_pubkey));
	secure_zero(candidate_pubkey, sizeof(candidate_pubkey));
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
