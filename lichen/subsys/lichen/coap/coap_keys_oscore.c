/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_keys_oscore.c
 * @brief OSCORE context derivation from stored peer keys
 *
 * Requires CONFIG_LICHEN_OSCORE for the low-level OSCORE API.
 */

#include <errno.h>

#include <zephyr/logging/log.h>

#include <lichen/coap_keys.h>
#include "coap_keys_internal.h"

#ifdef CONFIG_LICHEN_OSCORE
#include <lichen/oscore.h>
#endif

LOG_MODULE_DECLARE(lichen_coap_keys, CONFIG_LICHEN_COAP_KEYS_LOG_LEVEL);

/* --------------------------------------------------------------------------
 * OSCORE context derivation from stored peer keys
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LICHEN_OSCORE

int lichen_key_store_get_oscore_ctx(
	const uint8_t peer_iid[_Nonnull LICHEN_KEY_IID_LEN],
	const uint8_t peer_eui64[_Nonnull 8],
	const uint8_t *_Nonnull sender_id, size_t sender_id_len,
	const uint8_t *_Nonnull recipient_id, size_t recipient_id_len,
	struct oscore_ctx *_Nullable *_Nonnull ctx)
{
	struct lichen_key_entry entry;
	int ret;

	if (peer_iid == NULL || peer_eui64 == NULL || ctx == NULL) {
		return -EINVAL;
	}

	/* Look up the peer's public key from the key store */
	ret = lichen_key_store_get(peer_iid, &entry);
	if (ret < 0) {
		LOG_DBG("No key for peer IID, cannot derive OSCORE context");
		return -ENOENT;
	}

	/*
	 * Derive an OSCORE master secret from the peer's public key using
	 * HKDF-SHA256 with domain separation. The master secret is ephemeral
	 * and wiped by oscore_ctx_create_from_peer_key after context creation.
	 */
	ret = oscore_ctx_create_from_peer_key(entry.pubkey, peer_eui64,
					      sender_id, sender_id_len,
					      recipient_id, recipient_id_len,
					      ctx);
	if (ret != OSCORE_OK) {
		LOG_ERR("Failed to derive OSCORE context from peer key: %d", ret);
		return -EIO;
	}

	LOG_DBG("Derived OSCORE context from stored peer key");
	return 0;
}

/* --------------------------------------------------------------------------
 * Group key management
 *
 * Wraps the oscore_group_ctx API for use from CoAP resource handlers.
 * Group keys are stored in the OSCORE subsystem's group context table;
 * the coap_keys module provides the CoAP-facing CRUD interface.
 * -------------------------------------------------------------------------- */

int lichen_key_store_group_put(const char *_Nonnull group_name,
			       const uint8_t master_secret[_Nonnull 16],
			       uint8_t member_index,
			       enum lichen_group_key_trust trust)
{
	struct oscore_group_ctx *gctx = NULL;
	enum oscore_group_trust oscore_trust;

	if (group_name == NULL || master_secret == NULL) {
		return -EINVAL;
	}

	/* Map group_key_trust -> oscore_group_trust */
	switch (trust) {
	case LICHEN_GROUP_KEY_TRUST_UNKNOWN:
		oscore_trust = OSCORE_GROUP_TRUST_UNKNOWN;
		break;
	case LICHEN_GROUP_KEY_TRUST_PROVISIONED:
		oscore_trust = OSCORE_GROUP_TRUST_PROVISIONED;
		break;
	case LICHEN_GROUP_KEY_TRUST_ESTABLISHED:
		oscore_trust = OSCORE_GROUP_TRUST_ESTABLISHED;
		break;
	case LICHEN_GROUP_KEY_TRUST_VERIFIED:
		oscore_trust = OSCORE_GROUP_TRUST_VERIFIED;
		break;
	default:
		LOG_ERR("Invalid group key trust level: %d", (int)trust);
		return -EINVAL;
	}

	int ret = oscore_group_ctx_create(group_name, master_secret,
					  member_index, oscore_trust, &gctx);
	if (ret != OSCORE_OK) {
		LOG_ERR("Failed to create group OSCORE context: %d", ret);
		return -ENOSPC;
	}

	LOG_INF("Registered group key '%s' member=%u trust=%d",
		group_name, member_index, (int)trust);
	return 0;
}

int lichen_key_store_group_get_ctx(const char *_Nonnull group_name,
				   struct oscore_ctx *_Nullable *_Nonnull ctx)
{
	struct oscore_group_ctx *gctx = NULL;
	int ret;

	if (group_name == NULL || ctx == NULL) {
		return -EINVAL;
	}

	ret = oscore_group_ctx_get_by_name(group_name, &gctx);
	if (ret != OSCORE_OK) {
		return -ENOENT;
	}

	ret = oscore_group_ctx_get_member_ctx(gctx, ctx);
	if (ret != OSCORE_OK) {
		return -ENOENT;
	}

	return 0;
}

int lichen_key_store_group_get_trust(const char *_Nonnull group_name,
				     enum lichen_group_key_trust *_Nonnull trust)
{
	struct oscore_group_ctx *gctx = NULL;
	enum oscore_group_trust oscore_trust;
	int ret;

	if (group_name == NULL || trust == NULL) {
		return -EINVAL;
	}

	ret = oscore_group_ctx_get_by_name(group_name, &gctx);
	if (ret != OSCORE_OK) {
		return -ENOENT;
	}

	ret = oscore_group_ctx_get_trust(gctx, &oscore_trust);
	if (ret != OSCORE_OK) {
		return -ENOENT;
	}

	/* Map oscore_group_trust -> group_key_trust */
	switch (oscore_trust) {
	case OSCORE_GROUP_TRUST_UNKNOWN:
		*trust = LICHEN_GROUP_KEY_TRUST_UNKNOWN;
		break;
	case OSCORE_GROUP_TRUST_PROVISIONED:
		*trust = LICHEN_GROUP_KEY_TRUST_PROVISIONED;
		break;
	case OSCORE_GROUP_TRUST_ESTABLISHED:
		*trust = LICHEN_GROUP_KEY_TRUST_ESTABLISHED;
		break;
	case OSCORE_GROUP_TRUST_VERIFIED:
		*trust = LICHEN_GROUP_KEY_TRUST_VERIFIED;
		break;
	default:
		return -ENOENT;
	}

	return 0;
}

int lichen_key_store_group_set_trust(const char *_Nonnull group_name,
				     enum lichen_group_key_trust trust)
{
	struct oscore_group_ctx *gctx = NULL;
	enum oscore_group_trust oscore_trust;
	int ret;

	if (group_name == NULL) {
		return -EINVAL;
	}

	/* Map group_key_trust -> oscore_group_trust */
	switch (trust) {
	case LICHEN_GROUP_KEY_TRUST_UNKNOWN:
		oscore_trust = OSCORE_GROUP_TRUST_UNKNOWN;
		break;
	case LICHEN_GROUP_KEY_TRUST_PROVISIONED:
		oscore_trust = OSCORE_GROUP_TRUST_PROVISIONED;
		break;
	case LICHEN_GROUP_KEY_TRUST_ESTABLISHED:
		oscore_trust = OSCORE_GROUP_TRUST_ESTABLISHED;
		break;
	case LICHEN_GROUP_KEY_TRUST_VERIFIED:
		oscore_trust = OSCORE_GROUP_TRUST_VERIFIED;
		break;
	default:
		return -EINVAL;
	}

	ret = oscore_group_ctx_get_by_name(group_name, &gctx);
	if (ret != OSCORE_OK) {
		return -ENOENT;
	}

	ret = oscore_group_ctx_set_trust(gctx, oscore_trust);
	if (ret != OSCORE_OK) {
		return -EPERM;
	}

	return 0;
}

int lichen_key_store_group_delete(const char *_Nonnull group_name)
{
	struct oscore_group_ctx *gctx = NULL;
	int ret;

	if (group_name == NULL) {
		return -EINVAL;
	}

	ret = oscore_group_ctx_get_by_name(group_name, &gctx);
	if (ret != OSCORE_OK) {
		return -ENOENT;
	}

	oscore_group_ctx_free(gctx);

	LOG_INF("Deleted group key '%s'", group_name);
	return 0;
}

#endif /* CONFIG_LICHEN_OSCORE */
