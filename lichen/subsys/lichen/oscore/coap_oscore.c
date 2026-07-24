/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_oscore.c
 * @brief CoAP-OSCORE integration
 *
 * Middleware functions to integrate OSCORE protection with Zephyr's CoAP server.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>

#include <lichen/oscore.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_server.h>
#include <lichen/l2/ipv6_addr.h>

LOG_MODULE_REGISTER(coap_oscore, CONFIG_LICHEN_OSCORE_LOG_LEVEL);

/* Static buffer for OSCORE ciphertext to avoid large stack usage on constrained
 * devices (fixes project-LICHEN-zg2d). Size matches CONFIG + tag. */
static uint8_t coap_response_ciphertext[CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX + OSCORE_TAG_LEN];

/**
 * @brief Translate Zephyr CoAP errno to OSCORE error space.
 */
static inline int coap_err_to_oscore(int err)
{
	if (err >= 0) {
		return OSCORE_OK;
	}
	switch (err) {
	case -ENOMEM:
		return OSCORE_ERR_BUFFER_TOO_SMALL;
	default:
		return OSCORE_ERR_INVALID_PARAM;
	}
}

int coap_oscore_unprotect_resource_request(struct coap_resource *resource,
					   struct coap_packet *request,
					   struct sockaddr *addr, socklen_t addr_len,
					   uint8_t expected_method,
					   struct coap_oscore_unprotect_result *result)
{
	memset(result, 0, sizeof(*result));

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	result->is_protected = coap_oscore_is_protected(request);
	if (result->is_protected) {
		uint8_t peer_eui64[8] = {0};
		if (addr_len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
			const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
			memcpy(peer_eui64, &in6->sin6_addr.s6_addr[8], 8);
			lichen_eui64_to_iid(peer_eui64, peer_eui64);
		}
		if (oscore_ctx_get_by_eui64(peer_eui64, &result->ctx) != OSCORE_OK ||
		    result->ctx == NULL) {
			return coap_oscore_send_unauthorized(resource, request, addr, addr_len);
		}
		uint8_t orig_code;
		uint8_t opts[32];
		size_t opt_len = sizeof(opts);
		size_t plain_len = sizeof(result->plainbuf);
		result->piv_len = sizeof(result->piv);
		int r = coap_oscore_unprotect_request(result->ctx, request, &orig_code,
						      opts, &opt_len, result->plainbuf, &plain_len,
						      result->piv, &result->piv_len);
		if (r != OSCORE_OK) {
			return COAP_RESPONSE_CODE_UNAUTHORIZED;
		}
		if (orig_code != expected_method) {
			return COAP_RESPONSE_CODE_NOT_ALLOWED;
		}
		result->payload = result->plainbuf;
		result->payload_len = (uint16_t)plain_len;
		return 0;
	}
#endif
	result->payload = (uint8_t *)coap_packet_get_payload(request,
							     &result->payload_len);
	return 0;
}

int coap_oscore_respond_resource(struct coap_resource *resource,
				 struct coap_packet *request,
				 struct sockaddr *addr, socklen_t addr_len,
				 const struct coap_oscore_unprotect_result *result,
				 uint8_t resp_code, uint16_t content_format,
				 const uint8_t *payload, size_t payload_len)
{
#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (result->is_protected && result->ctx != NULL && result->piv_len > 0) {
		uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
		struct coap_packet resp;
		int ret = coap_oscore_protect_response(result->ctx, result->piv,
						       result->piv_len, request,
						       resp_code, payload, payload_len,
						       &resp, buf, sizeof(buf));
		if (ret < 0) {
			return lichen_coap_respond(resource, request, addr, addr_len,
						   COAP_RESPONSE_CODE_INTERNAL_ERROR,
						   0, NULL, 0);
		}
		return coap_resource_send(resource, &resp, addr, addr_len, NULL);
	}
#endif
	return lichen_coap_respond(resource, request, addr, addr_len,
				   resp_code, content_format, payload, payload_len);
}

bool coap_oscore_is_protected(const struct coap_packet *request)
{
	struct coap_option opt;
	int ret;

	ret = coap_find_options(request, COAP_OPTION_OSCORE, &opt, 1);
	return ret > 0;
}

/**
 * @brief Get the OSCORE option from a CoAP request.
 *
 * @return 0 on success, OSCORE_ERR_NO_CONTEXT if option not present,
 *         OSCORE_ERR_BUFFER_TOO_SMALL if buffer insufficient
 */
int coap_oscore_get_option(const struct coap_packet *request,
			   uint8_t *opt_data, size_t *opt_len)
{
	struct coap_option opt;
	int ret;

	/*
	 * Note: We trust Zephyr's coap_find_options to return valid
	 * opt.value and opt.len from the parsed packet. If processing
	 * untrusted network packets, Zephyr's CoAP parser provides the
	 * first line of defense against malformed packets.
	 */
	ret = coap_find_options(request, COAP_OPTION_OSCORE, &opt, 1);
	if (ret < 1) {
		return OSCORE_ERR_NO_CONTEXT;
	}

	if (opt.len > *opt_len) {
		return OSCORE_ERR_BUFFER_TOO_SMALL;
	}

	memcpy(opt_data, opt.value, opt.len);
	*opt_len = opt.len;
	return OSCORE_OK;
}

int coap_oscore_unprotect_request(struct oscore_ctx *ctx,
				  const struct coap_packet *request,
				  uint8_t *original_code,
				  uint8_t *options, size_t *options_len,
				  uint8_t *payload, size_t *payload_len,
				  uint8_t *request_piv, size_t *request_piv_len)
{
	uint8_t oscore_opt[32];
	size_t oscore_opt_len = sizeof(oscore_opt);
	const uint8_t *ciphertext;
	uint16_t ciphertext_len;
	struct oscore_option opt;
	int ret;

	/* Validate all output pointers (defensive despite _Nonnull) */
	if (original_code == NULL || options_len == NULL ||
	    payload_len == NULL || request_piv == NULL ||
	    request_piv_len == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Get OSCORE option */
	ret = coap_oscore_get_option(request, oscore_opt, &oscore_opt_len);
	if (ret != 0) {
		return ret;
	}

	/* Parse OSCORE option to extract PIV */
	ret = oscore_option_parse(oscore_opt, oscore_opt_len, &opt);
	if (ret != OSCORE_OK) {
		return ret;
	}

	/* Save request PIV for response */
	if (opt.has_piv && opt.piv_len > 0) {
		if (*request_piv_len < opt.piv_len) {
			return OSCORE_ERR_BUFFER_TOO_SMALL;
		}
		memcpy(request_piv, opt.piv, opt.piv_len);
		*request_piv_len = opt.piv_len;
	} else {
		*request_piv_len = 0;
	}

	/* Get encrypted payload */
	ciphertext = coap_packet_get_payload(request, &ciphertext_len);
	if (ciphertext == NULL || ciphertext_len == 0) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Unprotect */
	ret = oscore_unprotect_request(ctx,
				       oscore_opt, oscore_opt_len,
				       ciphertext, ciphertext_len,
				       original_code,
				       options, options_len,
				       payload, payload_len);
	if (ret != OSCORE_OK) {
		LOG_WRN("OSCORE unprotect failed: %d", ret);
		return ret;
	}

	LOG_DBG("Unprotected OSCORE request: code=0x%02x, payload=%zu",
		*original_code, *payload_len);
	return OSCORE_OK;
}

int coap_oscore_protect_response(struct oscore_ctx *ctx,
				 const uint8_t *request_piv, size_t request_piv_len,
				 const struct coap_packet *original_request,
				 uint8_t response_code,
				 const uint8_t *payload, size_t payload_len,
				 struct coap_packet *response,
				 uint8_t *resp_buf, size_t resp_buf_len)
{
	uint8_t *ciphertext = coap_response_ciphertext;
	size_t ciphertext_len = sizeof(coap_response_ciphertext);
	uint8_t oscore_opt[16];
	size_t oscore_opt_len = sizeof(oscore_opt);
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl;
	uint8_t type;
	int ret;
	if (resp_buf_len > 0xffffu) return -EINVAL;

	/* Protect the response */
	ret = oscore_protect_response(ctx,
				      request_piv, request_piv_len,
				      response_code,
				      NULL, 0,  /* No Class E options for now */
				      payload, payload_len,
				      ciphertext, &ciphertext_len,
				      oscore_opt, &oscore_opt_len);
	if (ret != OSCORE_OK) {
		LOG_ERR("OSCORE protect_response failed: %d", ret);
		return ret;
	}

	/* Build CoAP response packet */
	tkl = coap_header_get_token(original_request, token);
	type = (coap_header_get_type(original_request) == COAP_TYPE_CON)
	       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;

	ret = coap_packet_init(response, resp_buf, (uint16_t)resp_buf_len,
			       COAP_VERSION_1, type, tkl, token,
			       COAP_RESPONSE_CODE_CHANGED, /* Outer code for OSCORE */
			       coap_header_get_id(original_request));
	if (ret < 0) {
		return coap_err_to_oscore(ret);
	}

	/* Add OSCORE option */
	ret = coap_packet_append_option(response, COAP_OPTION_OSCORE,
					oscore_opt, oscore_opt_len);
	if (ret < 0) {
		return coap_err_to_oscore(ret);
	}

	/* Add payload marker and ciphertext */
	ret = coap_packet_append_payload_marker(response);
	if (ret < 0) {
		return coap_err_to_oscore(ret);
	}

	ret = coap_packet_append_payload(response, ciphertext, (uint16_t)ciphertext_len);
	if (ret < 0) {
		return coap_err_to_oscore(ret);
	}

	LOG_DBG("Protected OSCORE response: ct_len=%zu", ciphertext_len);
	return 0;
}

int coap_oscore_send_unauthorized(struct coap_resource *resource,
				  struct coap_packet *request,
				  struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t buf[64];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
		       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int ret;

	ret = coap_packet_init(&resp, buf, (uint16_t)sizeof(buf),
			       COAP_VERSION_1, type, tkl, token,
			       COAP_RESPONSE_CODE_UNAUTHORIZED,
			       coap_header_get_id(request));
	if (ret < 0) {
		return coap_err_to_oscore(ret);
	}

	ret = coap_resource_send(resource, &resp, addr, addr_len, NULL);
	return coap_err_to_oscore(ret);
}
