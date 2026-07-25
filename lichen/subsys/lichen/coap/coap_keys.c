/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_keys.c
 * @brief LCI /keys CoAP resource handlers
 *
 * Implements the key store resource per LCI spec section 17.5.5.
 * Keys are stored in memory with trust levels and timestamps.
 *
 * SECURITY: Write operations (PUT/DELETE) require local admin access.
 * The access check verifies the request comes from a local client
 * (loopback or SLIP LCI interface only - NOT the LoRa mesh interface).
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>

#include <lichen/coap_keys.h>
#include <lichen/coap_server.h>
#include <lichen/transport/slip_transport.h>
#include "coap_keys_internal.h"

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
#include <lichen/oscore.h>
#endif

LOG_MODULE_REGISTER(lichen_coap_keys, CONFIG_LICHEN_COAP_KEYS_LOG_LEVEL);

/* --------------------------------------------------------------------------
 * Access control
 * -------------------------------------------------------------------------- */

/*
 * SECURITY: Check if request comes from a local admin client.
 * Write operations (PUT/DELETE) require local access.
 *
 * Link-local addresses are only accepted from the SLIP LCI interface,
 * NOT from the LoRa mesh interface. This prevents mesh neighbors from
 * modifying the key store via PUT/DELETE /keys/{iid}.
 */
bool lichen_coap_is_local_admin(const struct sockaddr *addr, socklen_t addr_len)
{
	if (addr == NULL) {
		/* Unit test context */
		return IS_ENABLED(CONFIG_ZTEST);
	}

	if (addr_len < sizeof(struct sockaddr_in6) || addr->sa_family != AF_INET6) {
		return false;
	}

	const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;

	/* Loopback is always local admin */
	if (net_ipv6_is_addr_loopback((struct in6_addr *)&in6->sin6_addr)) {
		return true;
	}

	/*
	 * SECURITY: Link-local addresses require interface verification.
	 * Only accept from SLIP LCI interface - reject LoRa mesh traffic.
	 */
	if (net_ipv6_is_ll_addr(&in6->sin6_addr)) {
		struct net_if *slip_iface = slip_transport_iface_get();

		if (slip_iface == NULL) {
			/* SLIP not available - reject link-local admin access */
			LOG_WRN("Admin rejected: SLIP interface not available");
			return false;
		}

		int slip_idx = net_if_get_by_iface(slip_iface);

		/*
		 * sin6_scope_id holds the interface index for link-local.
		 * Only accept if it matches the SLIP LCI interface.
		 */
		if (in6->sin6_scope_id != (uint32_t)slip_idx) {
			LOG_WRN("Admin rejected: link-local from wrong interface "
				"(scope_id=%u, slip_idx=%d)",
				in6->sin6_scope_id, slip_idx);
			return false;
		}

		return true;
	}
	return false;
}

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
/*
 * Protected OSCORE response helper for /keys handlers.
 * Symmetric with deaddrop_oscore_respond in coap_dtn.c.
 * Uses coap_oscore_protect_response and falls back on error.
 */
static int keys_oscore_respond(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len,
			       struct oscore_ctx *ctx,
			       const uint8_t *piv, size_t piv_len,
			       uint8_t code)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	int ret = coap_oscore_protect_response(ctx, piv, piv_len, request, code,
					       NULL, 0, &resp, buf, sizeof(buf));
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}
	ret = coap_resource_send(resource, &resp, addr, addr_len, NULL);
	return ret;
}
#endif /* CONFIG_LICHEN_COAP_SERVER_OSCORE */

/* --------------------------------------------------------------------------
 * CoAP resource handlers
 * --------------------------------------------------------------------------
 */

/*
 * GET /keys - List all keys with fingerprints and trust levels
 */
static int keys_list_get(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[KEYS_LIST_CBOR_MAX_SIZE];
	size_t len = encode_keys_list_cbor(cbor_buf, sizeof(cbor_buf));

	if (len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, len);
}


/*
 * GET /keys/{iid} - Get single key with full pubkey
 */
static int keys_single_get(struct coap_resource *resource,
			   struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_option options[4];
	int opt_count;
	uint8_t iid[LICHEN_KEY_IID_LEN];
	struct lichen_key_entry entry;
	uint8_t cbor_buf[KEY_SINGLE_CBOR_MAX_SIZE];
	size_t len;
	int ret;

	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));
	if (opt_count < 2) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	char iid_str[LICHEN_KEY_IID_STR_LEN];

	if (options[1].len >= LICHEN_KEY_IID_STR_LEN) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	memcpy(iid_str, options[1].value, options[1].len);
	iid_str[options[1].len] = '\0';

	ret = lichen_key_str_to_iid(iid_str, iid);
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	ret = lichen_key_store_get(iid, &entry);
	if (ret == -ENOENT) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}
	if (ret < 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	len = encode_key_single_cbor(&entry, cbor_buf, sizeof(cbor_buf));
	if (len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, CBOR_CONTENT_FORMAT, cbor_buf, len);
}

/*
 * PUT /keys/{iid} - Add/update key (requires admin)
 */
static int keys_single_put(struct coap_resource *resource,
			   struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_option options[4];
	int opt_count;
	uint8_t iid[LICHEN_KEY_IID_LEN];
	uint8_t pubkey[LICHEN_KEY_PUBKEY_LEN];
	enum lichen_key_trust trust;
	uint16_t payload_len = 0;
	const uint8_t *payload = NULL;
	int ret;

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	struct oscore_ctx *ctx = NULL;
	uint8_t peer_eui64[8] = {0};
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = sizeof(piv);
	bool is_protected = coap_oscore_is_protected(request);
	if (is_protected) {
		if (addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
			const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
			memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
			lichen_eui64_to_iid(peer_eui64, peer_eui64);
		}
		if (oscore_ctx_get_by_eui64(peer_eui64, &ctx) != OSCORE_OK || ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		uint8_t plain[LICHEN_COAP_SERVER_MAX_PAYLOAD];
		size_t plain_len = sizeof(plain);
		int r = coap_oscore_unprotect_request(ctx, request, &orig_code, opts, &opt_len,
						      plain, &plain_len, piv, &piv_len);
		if (r != OSCORE_OK) {
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
		if (orig_code != COAP_METHOD_PUT) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
		payload = plain;
		payload_len = (uint16_t)plain_len;
	}
#endif

	/* SECURITY: Require local admin access for write operations */
	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		LOG_WRN("PUT /keys rejected: not local admin");
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_UNAUTHORIZED);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
	}

	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));
	if (opt_count < 2) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	char iid_str[LICHEN_KEY_IID_STR_LEN];

	if (options[1].len >= LICHEN_KEY_IID_STR_LEN) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	memcpy(iid_str, options[1].value, options[1].len);
	iid_str[options[1].len] = '\0';

	ret = lichen_key_str_to_iid(iid_str, iid);
	if (ret < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	/* Parse payload - from unprotect if OSCORE-protected, else from CoAP packet */
	if (payload == NULL) {
		payload = coap_packet_get_payload(request, &payload_len);
	}
	if (payload == NULL || payload_len == 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	ret = decode_key_put_cbor(payload, payload_len, pubkey, &trust);
	if (ret < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	/* Store key */
	ret = lichen_key_store_put(iid, pubkey, trust);
	if (ret == -EEXIST) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_CONFLICT);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_CONFLICT, 0, NULL, 0);
	}
	if (ret == -ENOSPC) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0, NULL, 0);
	}
	if (ret < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_INTERNAL_ERROR);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	LOG_INF("Key added/updated for IID %s", iid_str);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && ctx != NULL && piv_len > 0) {
		return keys_oscore_respond(resource, request, addr, addr_len,
					   ctx, piv, piv_len, COAP_RESPONSE_CODE_CHANGED);
	}
#endif
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CHANGED, 0, NULL, 0);
}

static int keys_single_delete(struct coap_resource *resource,
			      struct coap_packet *request,
			      struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_option options[4];
	int opt_count;
	uint8_t iid[LICHEN_KEY_IID_LEN];
	int ret;

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	struct oscore_ctx *ctx = NULL;
	uint8_t peer_eui64[8] = {0};
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len = sizeof(piv);
	bool is_protected = coap_oscore_is_protected(request);
	if (is_protected) {
		if (addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
			const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
			memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
			lichen_eui64_to_iid(peer_eui64, peer_eui64);
		}
		if (oscore_ctx_get_by_eui64(peer_eui64, &ctx) != OSCORE_OK || ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		uint8_t plain[16]; /* DELETE has no payload */
		size_t plain_len = sizeof(plain);
		int r = coap_oscore_unprotect_request(ctx, request, &orig_code, opts, &opt_len,
						      plain, &plain_len, piv, &piv_len);
		if (r != OSCORE_OK) {
			return COAP_RESPONSE_CODE_BAD_REQUEST;
		}
		if (orig_code != COAP_METHOD_DELETE) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
	}
#endif

	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		LOG_WRN("DELETE /keys rejected: not local admin");
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_UNAUTHORIZED);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_UNAUTHORIZED, 0, NULL, 0);
	}

	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));
	if (opt_count < 2) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	char iid_str[LICHEN_KEY_IID_STR_LEN];

	if (options[1].len >= LICHEN_KEY_IID_STR_LEN) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}
	memcpy(iid_str, options[1].value, options[1].len);
	iid_str[options[1].len] = '\0';

	ret = lichen_key_str_to_iid(iid_str, iid);
	if (ret < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_BAD_REQUEST);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, 0, NULL, 0);
	}

	ret = lichen_key_store_delete(iid);
	if (ret == -ENOENT) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_NOT_FOUND);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, 0, NULL, 0);
	}
	if (ret < 0) {
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
		if (is_protected && ctx != NULL && piv_len > 0) {
			return keys_oscore_respond(resource, request, addr, addr_len,
						   ctx, piv, piv_len, COAP_RESPONSE_CODE_INTERNAL_ERROR);
		}
#endif
		return lichen_coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, 0, NULL, 0);
	}

	LOG_INF("Key deleted for IID %s", iid_str);
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (is_protected && ctx != NULL && piv_len > 0) {
		return keys_oscore_respond(resource, request, addr, addr_len,
					   ctx, piv, piv_len, COAP_RESPONSE_CODE_DELETED);
	}
#endif
	return lichen_coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_DELETED, 0, NULL, 0);
}

/* --------------------------------------------------------------------------
 * CoAP resource definitions
 * -------------------------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LICHEN_COAP_KEYS)

static const char * const keys_path[] = { "keys", NULL };
COAP_RESOURCE_DEFINE(keys_list, lichen_coap_server, {
	.get = keys_list_get,
	.path = keys_path,
});

/*
 * Wildcard path for /keys/{iid}
 * Requires CONFIG_COAP_URI_WILDCARD=y
 */
static const char * const keys_single_path[] = { "keys", "+", NULL };
COAP_RESOURCE_DEFINE(keys_single, lichen_coap_server, {
	.get = keys_single_get,
	.put = keys_single_put,
	.del = keys_single_delete,
	.path = keys_single_path,
});

#endif /* CONFIG_LICHEN_COAP_KEYS */
