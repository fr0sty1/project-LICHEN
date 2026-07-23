/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_client.c
 * @brief CoAP client for mesh requests
 *
 * Implements asynchronous CoAP client using Zephyr's coap_client APIs.
 *
 * Design note: Single global socket
 * ---------------------------------
 * This module uses a single UDP socket (s_sock) shared across all requests.
 * The socket is created once at init and never recreated. This simplifies
 * resource management for embedded targets where sockets are scarce.
 *
 * Known limitation: if the socket enters an error state (ICMP unreachable
 * caching, interface down, etc.), all subsequent requests fail until the
 * module is reinitialized via device reset. Zephyr's coap_client API does
 * support per-request sockets, but implementing reconnect logic was deferred
 * as YAGNI for the current use cases.
 *
 * If you hit "CoAP stopped working after network blip" in the field, the
 * workaround is device reset. A future enhancement could add a
 * lichen_coap_client_reconnect() function if this becomes a real problem.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_client.h>

#include <lichen/coap_client.h>

#ifdef CONFIG_LICHEN_COAP_CLIENT_OSCORE
#include <lichen/oscore.h>
#endif

LOG_MODULE_REGISTER(lichen_coap_client, LOG_LEVEL_INF);

/* CBOR content-format code */
#define CBOR_CONTENT_FORMAT 60

/* Maximum URI path length (all components joined with '/') */
#define COAP_MAX_PATH_LEN 64

/* Maximum number of URI path components (defense against unterminated arrays) */
#define COAP_MAX_PATH_COMPONENTS LICHEN_COAP_MAX_PATH_COMPONENTS

/* Fallback timeout is scheduled at 2x the request timeout. */
#define COAP_MAX_REQUEST_TIMEOUT_MS (UINT32_MAX / 2U)

static inline k_timeout_t safe_fallback_timeout(uint32_t ms)
{
	/* Use k_timeout_t with safe 64-bit conversion to avoid tick
	 * overflow on systems with high CONFIG_SYS_CLOCK_TICKS_PER_SEC.
	 * Race (h115): atomic completed flag + timeout_ref_held ensures
	 * exactly one owner for ctx cleanup; loser bails early. The
	 * double-timeout allows Zephyr coap_client internal timeout to fire
	 * first.
	 */
	if (ms == 0 || ms > COAP_MAX_REQUEST_TIMEOUT_MS) {
		return K_FOREVER;
	}
	return K_MSEC(ms * 2U);
}

/* CoAP client socket - protected by s_mutex for thread safety */
static int s_sock = -1;
static struct coap_client s_client;
static bool s_initialized;
static K_MUTEX_DEFINE(s_mutex);

int lichen_coap_client_init(void)
{
	int ret;

	k_mutex_lock(&s_mutex, K_FOREVER);

	if (s_initialized) {
		k_mutex_unlock(&s_mutex);
		return 0;
	}

	/* Create UDP socket for CoAP */
	s_sock = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (s_sock < 0) {
		LOG_ERR("Failed to create socket: %d", errno);
		k_mutex_unlock(&s_mutex);
		return -errno;
	}

	/* Initialize CoAP client */
	ret = coap_client_init(&s_client, NULL);
	if (ret < 0) {
		LOG_ERR("CoAP client init failed: %d", ret);
		zsock_close(s_sock);
		s_sock = -1;
		k_mutex_unlock(&s_mutex);
		return ret;
	}

	s_initialized = true;
	k_mutex_unlock(&s_mutex);
	LOG_INF("CoAP client initialized");
	return 0;
}

/*
 * Internal response handler that maps to user callback.
 *
 * The timeout_work ensures cleanup if the CoAP layer never calls back
 * (e.g., socket error before request is sent).
 *
 * Race prevention: completed flag is set atomically. Whichever path
 * (callback or timeout) sets it first owns the ctx and frees it.
 */
struct request_ctx {
	lichen_coap_response_cb callback;
	void *user_data;
	struct k_work_delayable timeout_work;
	atomic_t refs;       /* Context lifetime across submitter/callback/work */
	atomic_t completed;  /* Set atomically; first setter owns cleanup */
	atomic_t timeout_ref_held;
	char path_buf[COAP_MAX_PATH_LEN];  /* Joined URI path for Zephyr */
	uint8_t response_buf[LICHEN_COAP_MAX_PAYLOAD];  /* Accumulated response */
	size_t response_len;  /* Current accumulated length */
	bool response_oversized;  /* True if any block exceeds response_buf */
	uint32_t timeout_ms;  /* Per-request timeout, for blockwise re-arm */
#ifdef CONFIG_LICHEN_COAP_CLIENT_OSCORE
	struct oscore_ctx *oscore_ctx;  /* OSCORE context for response decryption */
	uint8_t request_piv[OSCORE_PIV_MAX_LEN];  /* Request PIV for response */
	uint8_t request_piv_len;  /* PIV length */
#endif
};

static void request_ctx_get(struct request_ctx *ctx)
{
	atomic_inc(&ctx->refs);
}

static void request_ctx_put(struct request_ctx *ctx)
{
	if (atomic_dec(&ctx->refs) == 1) {
		k_free(ctx);
	}
}

static void request_ctx_release_timeout_ref(struct request_ctx *ctx)
{
	if (atomic_cas(&ctx->timeout_ref_held, 1, 0)) {
		request_ctx_put(ctx);
	}
}

static void request_ctx_cancel_timeout_sync(struct request_ctx *ctx)
{
	struct k_work_sync sync;

	k_work_cancel_delayable_sync(&ctx->timeout_work, &sync);
	request_ctx_release_timeout_ref(ctx);
}

static void request_ctx_cancel_coap_slot(struct request_ctx *ctx)
{
	/* WARNING: Internal Zephyr coap_client access (v3.7.0).
	 * Relies on struct coap_client { ... struct k_mutex send_mutex; ... struct coap_client_request_state requests[CONFIG_COAP_CLIENT_MAX_INSTANCES]; ... } layout,
	 * including request_ongoing, coap_request.cb/user_data, and is_observe fields.
	 * Used to neuter pending callback after timeout to avoid use-after-free on ctx.
	 * Update or replace with public API if Zephyr changes internals. See net/coap_client.c.
	 * Pinned to Zephyr v3.7.0 per AGENTS.md initialization graph.
	 */
	k_mutex_lock(&s_client.send_mutex, K_FOREVER);
	for (size_t i = 0; i < ARRAY_SIZE(s_client.requests); i++) {
		if (s_client.requests[i].request_ongoing &&
		    s_client.requests[i].coap_request.user_data == ctx) {
			s_client.requests[i].coap_request.cb = NULL;
			s_client.requests[i].coap_request.user_data = NULL;
			s_client.requests[i].request_ongoing = false;
			s_client.requests[i].is_observe = false;
		}
	}
	k_mutex_unlock(&s_client.send_mutex);
}

static int validate_path_components(const char * const *path, size_t *component_count)
{
	if (path == NULL || component_count == NULL) {
		return LICHEN_COAP_ERR_INVALID_PARAM;
	}

	for (size_t i = 0; i < COAP_MAX_PATH_COMPONENTS; i++) {
		if (path[i] == NULL) {
			*component_count = i;
			return LICHEN_COAP_OK;
		}
	}

	return LICHEN_COAP_ERR_INVALID_PARAM;
}

static void request_timeout_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct request_ctx *ctx = CONTAINER_OF(dwork, struct request_ctx, timeout_work);

	/* Atomically check and set completed flag; if already set, exit */
	if (atomic_set(&ctx->completed, 1) != 0) {
		/* Callback already fired; it owns completion cleanup */
		request_ctx_release_timeout_ref(ctx);
		return;
	}

	LOG_WRN("CoAP request timeout - no callback received");

	request_ctx_cancel_coap_slot(ctx);

	/* Notify user of timeout */
	if (ctx->callback != NULL) {
		ctx->callback(ctx->user_data, LICHEN_COAP_ERR_TIMEOUT, 0, NULL, 0);
	}

	request_ctx_put(ctx);
	request_ctx_release_timeout_ref(ctx);
}

static void coap_response_handler(int16_t code, size_t offset, const uint8_t *payload,
				  size_t len, bool last_block, void *user_data)
{
	struct request_ctx *ctx = user_data;

	if (ctx == NULL) {
		return;
	}

	/*
	 * Check if timeout handler already claimed ownership.
	 * We don't set completed here for intermediate blocks - only on last_block
	 * or error do we claim ownership and clean up.
	 */
	if (atomic_get(&ctx->completed) != 0) {
		/* Timeout handler owns cleanup */
		return;
	}

	/*
	 * Negative codes indicate transport errors (e.g., -ETIMEDOUT, -ECANCELED).
	 * In error cases, Zephyr sets last_block=true, but call callback with
	 * error indication regardless.
	 */
	if (code < 0) {
		if (atomic_set(&ctx->completed, 1) != 0) {
			return;  /* Lost race to timeout */
		}
		request_ctx_cancel_timeout_sync(ctx);
		if (ctx->callback != NULL) {
			ctx->callback(ctx->user_data, LICHEN_COAP_ERR_TRANSPORT, 0, NULL, 0);
		}
		request_ctx_put(ctx);
		return;
	}

	/*
	 * Accumulate blockwise response payload.
	 * Each block arrives with its offset; copy into response_buf.
	 * On last_block, deliver the complete accumulated response.
	 */
	if (payload != NULL && len > 0) {
		size_t copy_len = len;
		if (offset > sizeof(ctx->response_buf) ||
		    len > sizeof(ctx->response_buf) - offset) {
			ctx->response_oversized = true;
			if (offset < sizeof(ctx->response_buf)) {
				copy_len = sizeof(ctx->response_buf) - offset;
			} else {
				copy_len = 0;
			}
			LOG_WRN("Response too large: %zu bytes at offset %zu exceeds buffer",
				len, offset);
		}
		if (copy_len > 0) {
			memcpy(ctx->response_buf + offset, payload, copy_len);
			if (offset + copy_len > ctx->response_len) {
				ctx->response_len = offset + copy_len;
			}
		}
	}

	if (!last_block) {
		/*
		 * Intermediate block of a blockwise transfer: the exchange is
		 * making progress, so push the fallback timeout out by a full
		 * window. A multi-block response over a slow link (e.g. four
		 * 64-byte blocks at ~3 s per round trip on SF10 LoRa) is
		 * otherwise killed by a timeout that only ever measured the
		 * first request. Timeout thus means "no progress", not
		 * "not finished yet".
		 */
		if (atomic_get(&ctx->completed) == 0 &&
		    atomic_get(&ctx->timeout_ref_held) == 1) {
			k_work_reschedule(&ctx->timeout_work,
					  safe_fallback_timeout(ctx->timeout_ms));
		}
		return;
	}

	{
		/* Claim ownership and clean up */
		if (atomic_set(&ctx->completed, 1) != 0) {
			return;  /* Lost race to timeout */
		}
		request_ctx_cancel_timeout_sync(ctx);

		if (ctx->callback != NULL) {
			if (ctx->response_oversized) {
				ctx->callback(ctx->user_data, LICHEN_COAP_ERR_INVALID_RESPONSE,
					      0, NULL, 0);
			} else {
#ifdef CONFIG_LICHEN_COAP_CLIENT_OSCORE
				if (ctx->oscore_ctx != NULL) {
					/*
					 * SECURITY: Unprotect OSCORE response before delivery.
					 * The accumulated response_buf contains the OSCORE ciphertext.
					 */
					uint8_t plain_code;
					uint8_t plaintext[LICHEN_COAP_MAX_PAYLOAD];
					size_t plaintext_len = sizeof(plaintext);
					uint8_t options[64];
					size_t options_len = sizeof(options);
					int ret;

					/*
					 * Response OSCORE option (typically empty per RFC 8613 8.4).
					 * Uses request_piv for nonce/KID binding (checkpoint fixed in oscore.c).
					 */
					uint8_t oscore_opt[1] = {0};
					size_t oscore_opt_len = 0;

					ret = oscore_unprotect_response(ctx->oscore_ctx,
									ctx->request_piv,
									ctx->request_piv_len,
									oscore_opt, oscore_opt_len,
									ctx->response_buf,
									ctx->response_len,
									&plain_code,
									options, &options_len,
									plaintext, &plaintext_len);
					if (ret != OSCORE_OK) {
						LOG_WRN("OSCORE unprotect response failed: %d", ret);
						ctx->callback(ctx->user_data,
							      LICHEN_COAP_ERR_OSCORE_UNPROTECT,
							      0, NULL, 0);
					} else {
						ctx->callback(ctx->user_data, LICHEN_COAP_OK,
							      plain_code, plaintext, plaintext_len);
					}
				} else {
#endif
					ctx->callback(ctx->user_data, LICHEN_COAP_OK, (uint8_t)code,
						      ctx->response_buf, ctx->response_len);
#ifdef CONFIG_LICHEN_COAP_CLIENT_OSCORE
				}
#endif
			}
		}
		request_ctx_put(ctx);
	}
}

int lichen_coap_request(const struct lichen_coap_request *req)
{
	/* Designated initializer: method must start as a valid enum value
	 * (0 is outside enum coap_method); it is overwritten below. */
	struct coap_client_request client_req = { .method = COAP_METHOD_GET };
	struct request_ctx *ctx;
	int ret;
	int sock;
	size_t path_components;
	uint32_t timeout_ms;
#ifdef CONFIG_LICHEN_COAP_CLIENT_OSCORE
	uint8_t ciphertext[LICHEN_COAP_MAX_PAYLOAD + OSCORE_TAG_LEN];
	size_t ciphertext_len = sizeof(ciphertext);
	uint8_t oscore_opt_buf[16];
	size_t oscore_opt_len = sizeof(oscore_opt_buf);
	struct coap_client_option oscore_option;
#endif

	if (req == NULL) {
		return LICHEN_COAP_ERR_INVALID_PARAM;
	}

	if (req->payload == NULL && req->payload_len > 0) {
		return LICHEN_COAP_ERR_INVALID_PARAM;
	}

	ret = validate_path_components(req->path, &path_components);
	if (ret < 0) {
		return ret;
	}

	timeout_ms = req->timeout_ms > 0 ? req->timeout_ms : LICHEN_COAP_TIMEOUT_MS;
	if (timeout_ms > COAP_MAX_REQUEST_TIMEOUT_MS) {
		return LICHEN_COAP_ERR_INVALID_PARAM;
	}

	if (!s_initialized) {
		ret = lichen_coap_client_init();
		if (ret < 0) {
			return ret;
		}
	}

	/* Snapshot socket under lock - callbacks run without lock held */
	k_mutex_lock(&s_mutex, K_FOREVER);
	sock = s_sock;
	k_mutex_unlock(&s_mutex);

	/* Allocate context for callback */
	ctx = k_malloc(sizeof(*ctx));
	if (ctx == NULL) {
		return LICHEN_COAP_ERR_NO_MEMORY;
	}
	ctx->callback = req->callback;
	ctx->user_data = req->user_data;
	ctx->response_len = 0;
	ctx->response_oversized = false;
	ctx->timeout_ms = timeout_ms;
	atomic_set(&ctx->refs, 2);  /* CoAP callback path + submitter path */
	atomic_set(&ctx->completed, 0);
	atomic_set(&ctx->timeout_ref_held, 0);
	k_work_init_delayable(&ctx->timeout_work, request_timeout_handler);
#ifdef CONFIG_LICHEN_COAP_CLIENT_OSCORE
	ctx->oscore_ctx = req->oscore_ctx;
	ctx->request_piv_len = 0;
#endif

	/*
	 * Join path components into a single URI path string.
	 * Zephyr's coap_client expects a single path string like "sensors/temp".
	 */
	size_t path_pos = 0;
	for (size_t i = 0; i < path_components; i++) {
		size_t comp_len = strlen(req->path[i]);
		if (i > 0) {
			/* Add separator between components */
			if (path_pos + 1 >= sizeof(ctx->path_buf)) {
				k_free(ctx);
				return LICHEN_COAP_ERR_NO_MEMORY;
			}
			ctx->path_buf[path_pos++] = '/';
		}
		if (path_pos + comp_len >= sizeof(ctx->path_buf)) {
			k_free(ctx);
			return LICHEN_COAP_ERR_NO_MEMORY;
		}
		memcpy(ctx->path_buf + path_pos, req->path[i], comp_len);
		path_pos += comp_len;
	}
	ctx->path_buf[path_pos] = '\0';

#ifdef CONFIG_LICHEN_COAP_CLIENT_OSCORE
	/*
	 * SECURITY: Protect request payload with OSCORE if context is provided.
	 * The outer CoAP message will carry the OSCORE option and ciphertext.
	 */
	if (req->oscore_ctx != NULL) {
		ret = oscore_protect_request(req->oscore_ctx,
					     req->method,
					     NULL, 0,  /* No Class E options for now */
					     req->payload, req->payload_len,
					     ciphertext, &ciphertext_len,
					     oscore_opt_buf, &oscore_opt_len);
		if (ret != OSCORE_OK) {
			LOG_ERR("OSCORE protect request failed: %d", ret);
			k_free(ctx);
			return LICHEN_COAP_ERR_OSCORE_PROTECT;
		}

		/*
		 * Extract PIV from the OSCORE option for response decryption.
		 * The PIV is the sender sequence number used for this request.
		 */
		struct oscore_option opt;
		ret = oscore_option_parse(oscore_opt_buf, oscore_opt_len, &opt);
		if (ret != OSCORE_OK) {
			LOG_ERR("OSCORE option parse failed: %d", ret);
			k_free(ctx);
			return LICHEN_COAP_ERR_OSCORE_PROTECT;
		}
		if (opt.has_piv && opt.piv_len > 0) {
			memcpy(ctx->request_piv, opt.piv, opt.piv_len);
			ctx->request_piv_len = opt.piv_len;
		}

		/* Build OSCORE option for coap_client */
		oscore_option.code = COAP_OPTION_OSCORE;
		oscore_option.len = oscore_opt_len;
		if (oscore_opt_len > sizeof(oscore_option.value)) {
			LOG_ERR("OSCORE option too large: %zu", oscore_opt_len);
			k_free(ctx);
			return LICHEN_COAP_ERR_OSCORE_PROTECT;
		}
		memcpy(oscore_option.value, oscore_opt_buf, oscore_opt_len);

		LOG_DBG("OSCORE protected request: ct_len=%zu, opt_len=%zu",
			ciphertext_len, oscore_opt_len);
	}
#endif

	/* Build request */
	client_req.method = req->method;
	client_req.confirmable = req->confirmable;
	client_req.path = ctx->path_buf;
#ifdef CONFIG_LICHEN_COAP_CLIENT_OSCORE
	if (req->oscore_ctx != NULL) {
		/* Use protected payload */
		client_req.payload = ciphertext;
		client_req.len = ciphertext_len;
	} else {
		client_req.payload = (uint8_t *)req->payload;
		client_req.len = req->payload_len;
	}
#else
	client_req.payload = (uint8_t *)req->payload;
	client_req.len = req->payload_len;
#endif
	client_req.cb = coap_response_handler;
	client_req.user_data = ctx;

	if (req->content_format != LICHEN_COAP_FMT_UNSET) {
		client_req.fmt = req->content_format;
	}

#ifdef CONFIG_LICHEN_COAP_CLIENT_OSCORE
	/* Add OSCORE option to protected requests */
	if (req->oscore_ctx != NULL) {
		client_req.options = &oscore_option;
		client_req.num_options = 1;
		/*
		 * For OSCORE requests, outer code is always FETCH (0.05) per RFC 8613.
		 * The actual method is encrypted in the payload.
		 */
		client_req.method = COAP_METHOD_FETCH;
	}
#endif

	/* Send request using snapshotted socket */
	atomic_set(&ctx->timeout_ref_held, 1);
	request_ctx_get(ctx);
	k_work_schedule(&ctx->timeout_work, safe_fallback_timeout(timeout_ms));
	ret = coap_client_req(&s_client, sock,
			      (const struct sockaddr *)&req->addr,
			      &client_req, NULL);
	if (ret < 0) {
		LOG_WRN("CoAP request failed: %d", ret);
		if (atomic_set(&ctx->completed, 1) == 0) {
			request_ctx_cancel_coap_slot(ctx);
			request_ctx_cancel_timeout_sync(ctx);
			request_ctx_put(ctx);
		}
		request_ctx_put(ctx);
		return LICHEN_COAP_ERR_SEND_FAILED;
	}

	request_ctx_put(ctx);
	return LICHEN_COAP_OK;
}

int lichen_coap_get(const struct sockaddr_in6 *addr,
		    const char * const *path,
		    lichen_coap_response_cb callback,
		    void *user_data)
{
	if (addr == NULL || path == NULL) {
		return LICHEN_COAP_ERR_INVALID_PARAM;
	}

	struct lichen_coap_request req = {
		.method = COAP_METHOD_GET,
		.path = path,
		.content_format = LICHEN_COAP_FMT_UNSET,
		.confirmable = true,
		.callback = callback,
		.user_data = user_data,
		.timeout_ms = LICHEN_COAP_TIMEOUT_MS,
	};

	memcpy(&req.addr, addr, sizeof(req.addr));

	return lichen_coap_request(&req);
}

int lichen_coap_post_cbor(const struct sockaddr_in6 *addr,
			  const char * const *path,
			  const uint8_t *payload, size_t payload_len,
			  lichen_coap_response_cb callback,
			  void *user_data)
{
	if (addr == NULL || path == NULL || (payload == NULL && payload_len > 0)) {
		return LICHEN_COAP_ERR_INVALID_PARAM;
	}

	struct lichen_coap_request req = {
		.method = COAP_METHOD_POST,
		.path = path,
		.payload = payload,
		.payload_len = payload_len,
		.content_format = CBOR_CONTENT_FORMAT,
		.confirmable = true,
		.callback = callback,
		.user_data = user_data,
		.timeout_ms = LICHEN_COAP_TIMEOUT_MS,
	};

	memcpy(&req.addr, addr, sizeof(req.addr));

	return lichen_coap_request(&req);
}
