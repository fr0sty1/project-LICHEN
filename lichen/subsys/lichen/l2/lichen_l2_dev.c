/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2_dev.c
 * @brief LICHEN L2 dev provisioning (CONFIG_LICHEN_L2_DEV_PROVISIONING only)
 *
 * Contains dev_seed, dev_parse_eui64(), dev_provision_peer(),
 * and lichen_l2_dev_provision().
 */

#include "lichen_l2_internal.h"

#ifdef CONFIG_LICHEN_L2_DEV_PROVISIONING
#include <ctype.h>
#include <stdlib.h>
#include "ipv6.h" /* zephyr/subsys/net/ip — net_ipv6_nbr_add() */

LOG_MODULE_DECLARE(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

/*
 * SECURITY: INSECURE dev-only provisioning. This seed is public (it lives
 * in the source tree) and is shared by every node built with
 * CONFIG_LICHEN_L2_DEV_PROVISIONING, so signatures made with it prove
 * nothing. Bench bring-up only, until announce/EDHOC peer provisioning
 * lands. The Kconfig help text carries the same warning.
 */
static const uint8_t dev_seed[32] = {
	0x4c, 0x49, 0x43, 0x48, 0x45, 0x4e, 0x2d, 0x44, /* "LICHEN-D" */
	0x45, 0x56, 0x2d, 0x53, 0x45, 0x45, 0x44, 0x2d, /* "EV-SEED-" */
	0x30, 0x30, 0x30, 0x31, 0x2d, 0x49, 0x4e, 0x53, /* "0001-INS" */
	0x45, 0x43, 0x55, 0x52, 0x45, 0x21, 0x21, 0x21, /* "ECURE!!!" */
};

/* Parse "aabb..." or "aa:bb:..." into 8 bytes. Returns 0 or -EINVAL. */
static int dev_parse_eui64(const char *s, uint8_t out[LICHEN_EUI64_LEN])
{
	size_t n = 0;

	while (*s != '\0' && n < LICHEN_EUI64_LEN) {
		char hex[3] = { 0 };

		if (*s == ':' || *s == '-') {
			s++;
			continue;
		}
		if (!isxdigit((unsigned char)s[0]) ||
		    !isxdigit((unsigned char)s[1])) {
			return -EINVAL;
		}
		hex[0] = s[0];
		hex[1] = s[1];
		out[n++] = (uint8_t)strtoul(hex, NULL, 16);
		s += 2;
	}

	return (n == LICHEN_EUI64_LEN && *s == '\0') ? 0 : -EINVAL;
}

/* Provision one dev peer: derive its pubkey, pin it, and add a static
 * IPv6 neighbor entry. See lichen_l2_dev_provision() for context. */
static int dev_provision_peer(uint8_t peer_eui64[LICHEN_EUI64_LEN])
{
	uint8_t peer_pubkey[LICHEN_L2_PUBKEY_LEN];
	uint8_t node_seed[LICHEN_SEED_LEN];
	int ret;

	ret = lichen_link_derive_seed(dev_seed, peer_eui64, node_seed);
	if (ret == 0) {
		ret = lichen_link_derive_pubkey(node_seed, peer_pubkey);
	}
	secure_zero(node_seed, sizeof(node_seed));
	if (ret != 0) {
		LOG_ERR("lichen_l2: dev peer key derivation failed (%d)", ret);
		return ret;
	}

	ret = lichen_peer_add(peer_eui64, peer_pubkey);
	if (ret != 0) {
		LOG_ERR("lichen_l2: dev peer add failed (%d)", ret);
		return ret;
	}

	/*
	 * Static IPv6 neighbor entry for the peer. IPv6 ND cannot run over
	 * this link yet — there is no SCHC rule for ICMPv6 NS/NA, so the
	 * solicitation is silently uncompressible and every unicast send
	 * parks forever in the ND queue (bd lora_ipv6_mesh-r002). The dev
	 * peer's link-layer address is knowable from its EUI-64, so resolve
	 * it statically.
	 */
	{
		uint8_t iid[LICHEN_EUI64_LEN];
		struct in6_addr peer_ll;
		struct net_linkaddr lladdr = {
			.addr = peer_eui64,
			.len = LICHEN_EUI64_LEN,
			.type = NET_LINK_IEEE802154,
		};

		ret = lichen_eui64_to_iid(peer_eui64, iid);
		if (ret == 0) {
			ret = lichen_make_link_local(iid, &peer_ll);
		}
		if (ret != 0 || lichen_iface_read() == NULL ||
		    net_ipv6_nbr_add(lichen_iface_read(), &peer_ll, &lladdr, false,
				     NET_IPV6_NBR_STATE_STATIC) == NULL) {
			LOG_ERR("lichen_l2: static neighbor add failed (%d)", ret);
			return ret != 0 ? ret : -ENOMEM;
		}
	}

	LOG_WRN("lichen_l2: INSECURE dev provisioning active (peer %02x%02x..%02x%02x)",
		peer_eui64[0], peer_eui64[1], peer_eui64[6], peer_eui64[7]);
	return 0;
}

int lichen_l2_dev_provision(uint8_t peer_eui64_out[LICHEN_EUI64_LEN])
{
	uint8_t pubkey[LICHEN_L2_PUBKEY_LEN];
	uint8_t self_eui64[LICHEN_EUI64_LEN];
	uint8_t peer_eui64[LICHEN_EUI64_LEN];
	uint8_t node_seed[LICHEN_SEED_LEN];
	const char *s = CONFIG_LICHEN_L2_DEV_PEER_EUI64;
	size_t peers_added = 0;
	int ret;

	/*
	 * SECURITY: Per-node dev keys, derived as SHA-512(dev_seed || EUI-64).
	 * Still INSECURE (dev_seed is public, so anyone can derive any node's
	 * key), but each node now has a DISTINCT keypair so signature
	 * verification attributes frames to the correct peer. With one shared
	 * keypair, every dev node in RF range verified as "the" pinned peer
	 * and all transmitters collapsed into a single replay window per
	 * receiver; the highest random boot epoch then permanently starved
	 * the others (project-LICHEN-wp4o).
	 */
	ret = lichen_lora_l2_copy_eui64(self_eui64);
	if (ret != 0) {
		LOG_ERR("lichen_l2: dev self EUI-64 read failed (%d)", ret);
		return ret;
	}
	ret = lichen_link_derive_seed(dev_seed, self_eui64, node_seed);
	if (ret == 0) {
		ret = lichen_l2_load_key(node_seed, pubkey);
	}
	secure_zero(node_seed, sizeof(node_seed));
	if (ret != 0) {
		LOG_ERR("lichen_l2: dev key load failed (%d)", ret);
		return ret;
	}

	/* CONFIG_LICHEN_L2_DEV_PEER_EUI64 is a comma-separated list of
	 * EUI-64s; each entry is pinned as a dev peer. */
	while (*s != '\0') {
		char token[24]; /* "aa:bb:cc:dd:ee:ff:00:11" = 23 chars */
		size_t n = 0;

		while (*s == ',' || *s == ' ') {
			s++;
		}
		while (*s != '\0' && *s != ',') {
			if (n >= sizeof(token) - 1) {
				LOG_ERR("lichen_l2: bad CONFIG_LICHEN_L2_DEV_PEER_EUI64 '%s'",
					CONFIG_LICHEN_L2_DEV_PEER_EUI64);
				return -EINVAL;
			}
			token[n++] = *s++;
		}
		token[n] = '\0';
		if (n == 0) {
			continue;
		}

		ret = dev_parse_eui64(token, peer_eui64);
		if (ret != 0) {
			LOG_ERR("lichen_l2: bad CONFIG_LICHEN_L2_DEV_PEER_EUI64 '%s'",
				CONFIG_LICHEN_L2_DEV_PEER_EUI64);
			return ret;
		}

		ret = dev_provision_peer(peer_eui64);
		if (ret != 0) {
			return ret;
		}

		if (peers_added == 0 && peer_eui64_out != NULL) {
			memcpy(peer_eui64_out, peer_eui64, LICHEN_EUI64_LEN);
		}
		peers_added++;
	}

	if (peers_added == 0) {
		LOG_ERR("lichen_l2: bad CONFIG_LICHEN_L2_DEV_PEER_EUI64 '%s'",
			CONFIG_LICHEN_L2_DEV_PEER_EUI64);
		return -EINVAL;
	}

	return 0;
}
#endif /* CONFIG_LICHEN_L2_DEV_PROVISIONING */
