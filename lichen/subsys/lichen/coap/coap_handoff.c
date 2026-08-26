/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_handoff.c
 * @brief Node handoff protocol implementation (GCP-7)
 *
 * Implements the handoff protocol for multi-gateway coordination per
 * spec/08-gateway-coordination.md GCP-7.
 *
 * CBOR encoding uses integer keys for compact wire format, matching the
 * Python reference implementation:
 *
 * Request keys:
 *   1 = node_address (bytes)
 *   2 = dao_sequence (int)
 *   3 = path_sequence (int)
 *   4 = oscore_params (map)
 *   5 = oscore_sender_seq (int)
 *   6 = oscore_replay (array: [index, bitfield])
 *   7 = freshness (map)
 *   8 = parents (array of bytes)
 *   9 = rssi (int, dBm)
 *  10 = timestamp (int, Unix seconds)
 *
 * Response keys (100+ to avoid collision):
 * 100 = status (HandoffRejectReason)
 * 101 = message (text)
 *
 * OSCORE subkeys:
 *   1 = master_secret (bytes)
 *   2 = master_salt (bytes)
 *   3 = sender_id (bytes)
 *   4 = recipient_id (bytes)
 *   5 = algorithm (int)
 *   6 = hashfun (text)
 *   7 = window_size (int)
 *   8 = id_context (bytes or null)
 */

#include <errno.h>
#include <string.h>
#include <limits.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>

#include <lichen/coap_handoff.h>
#include <lichen/coap_server.h>
#include <lichen/coap_oscore.h>
#include <lichen_util.h>

LOG_MODULE_REGISTER(lichen_handoff, CONFIG_LICHEN_COAP_HANDOFF_LOG_LEVEL);

/* --------------------------------------------------------------------------
 * CBOR key definitions (matching Python reference)
 * -------------------------------------------------------------------------- */

/* Request keys */
#define KEY_NODE_ADDR       1
#define KEY_DAO_SEQ         2
#define KEY_PATH_SEQ        3
#define KEY_OSCORE_PARAMS   4
#define KEY_OSCORE_SENDER_SEQ 5
#define KEY_OSCORE_REPLAY   6
#define KEY_FRESHNESS       7
#define KEY_PARENTS         8
#define KEY_RSSI            9
#define KEY_TIMESTAMP       10

/* Response keys (100+) */
#define KEY_STATUS          100
#define KEY_MESSAGE         101

/* OSCORE subkeys */
#define KEY_OSCORE_SECRET   1
#define KEY_OSCORE_SALT     2
#define KEY_OSCORE_SENDER_ID 3
#define KEY_OSCORE_RECIPIENT_ID 4
#define KEY_OSCORE_ALG      5
#define KEY_OSCORE_HASHFUN  6
#define KEY_OSCORE_WINDOW   7
#define KEY_OSCORE_ID_CTX   8

/* Freshness subkeys (string keys per Python) */
#define KEY_FRESH_SEQ       "seq"
#define KEY_FRESH_RETAIN    "retain"
#define KEY_FRESH_UPDATED   "updated"
#define KEY_FRESH_ACTIVE    "active"

/* CBOR content-format */
#define CBOR_CONTENT_FORMAT 60

/* --------------------------------------------------------------------------
 * Node registry
 * -------------------------------------------------------------------------- */

static struct lichen_node_entry s_nodes[CONFIG_LICHEN_COAP_HANDOFF_MAX_NODES];
static K_MUTEX_DEFINE(s_registry_lock);

static struct lichen_node_entry *find_node(const uint8_t *address)
{
	for (int i = 0; i < CONFIG_LICHEN_COAP_HANDOFF_MAX_NODES; i++) {
		if (s_nodes[i].valid &&
		    memcmp(s_nodes[i].address, address, LICHEN_IPV6_ADDR_LEN) == 0) {
			return &s_nodes[i];
		}
	}
	return NULL;
}

static struct lichen_node_entry *find_free_slot(void)
{
	for (int i = 0; i < CONFIG_LICHEN_COAP_HANDOFF_MAX_NODES; i++) {
		if (!s_nodes[i].valid) {
			return &s_nodes[i];
		}
	}
	return NULL;
}

int lichen_handoff_init(void)
{
	k_mutex_lock(&s_registry_lock, K_FOREVER);
	memset(s_nodes, 0, sizeof(s_nodes));
	k_mutex_unlock(&s_registry_lock);

	LOG_INF("Handoff subsystem initialized (max %d nodes)",
		CONFIG_LICHEN_COAP_HANDOFF_MAX_NODES);
	return 0;
}

int lichen_handoff_register_node(const uint8_t *address,
				 uint32_t dao_seq, uint32_t path_seq)
{
	if (address == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_registry_lock, K_FOREVER);

	/* Check if already registered */
	struct lichen_node_entry *entry = find_node(address);
	if (entry != NULL) {
		/* Update existing entry */
		entry->dao_sequence = dao_seq;
		entry->path_sequence = path_seq;
		entry->last_seen = k_uptime_get();
		k_mutex_unlock(&s_registry_lock);
		LOG_DBG("Updated existing node entry");
		return 0;
	}

	/* Find free slot */
	entry = find_free_slot();
	if (entry == NULL) {
		k_mutex_unlock(&s_registry_lock);
		LOG_WRN("Node registry full");
		return -ENOMEM;
	}

	/* Initialize entry */
	memset(entry, 0, sizeof(*entry));
	memcpy(entry->address, address, LICHEN_IPV6_ADDR_LEN);
	entry->dao_sequence = dao_seq;
	entry->path_sequence = path_seq;
	entry->last_seen = k_uptime_get();
	entry->valid = true;

	k_mutex_unlock(&s_registry_lock);
	LOG_DBG("Registered new node");
	return 0;
}

int lichen_handoff_unregister_node(const uint8_t *address)
{
	if (address == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_registry_lock, K_FOREVER);

	struct lichen_node_entry *entry = find_node(address);
	if (entry == NULL) {
		k_mutex_unlock(&s_registry_lock);
		return -ENOENT;
	}

	/* SECURITY: Wipe sensitive data before invalidating */
	secure_zero(entry->oscore.master_secret, sizeof(entry->oscore.master_secret));
	entry->valid = false;

	k_mutex_unlock(&s_registry_lock);
	LOG_DBG("Unregistered node");
	return 0;
}

int lichen_handoff_get_node(const uint8_t *address,
			    struct lichen_node_entry *out)
{
	if (address == NULL || out == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_registry_lock, K_FOREVER);

	struct lichen_node_entry *entry = find_node(address);
	if (entry == NULL) {
		k_mutex_unlock(&s_registry_lock);
		return -ENOENT;
	}

	memcpy(out, entry, sizeof(*out));
	k_mutex_unlock(&s_registry_lock);
	return 0;
}

int lichen_handoff_set_oscore(const uint8_t *address,
			      const struct lichen_handoff_oscore_state *oscore)
{
	if (address == NULL || oscore == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_registry_lock, K_FOREVER);

	struct lichen_node_entry *entry = find_node(address);
	if (entry == NULL) {
		k_mutex_unlock(&s_registry_lock);
		return -ENOENT;
	}

	memcpy(&entry->oscore, oscore, sizeof(entry->oscore));
	k_mutex_unlock(&s_registry_lock);
	return 0;
}

int lichen_handoff_set_freshness(const uint8_t *address,
				 const struct lichen_handoff_freshness *freshness)
{
	if (address == NULL || freshness == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_registry_lock, K_FOREVER);

	struct lichen_node_entry *entry = find_node(address);
	if (entry == NULL) {
		k_mutex_unlock(&s_registry_lock);
		return -ENOENT;
	}

	memcpy(&entry->freshness, freshness, sizeof(entry->freshness));
	k_mutex_unlock(&s_registry_lock);
	return 0;
}

int lichen_handoff_set_busy(const uint8_t *address, bool busy)
{
	if (address == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_registry_lock, K_FOREVER);

	struct lichen_node_entry *entry = find_node(address);
	if (entry == NULL) {
		k_mutex_unlock(&s_registry_lock);
		return -ENOENT;
	}

	entry->busy = busy;
	k_mutex_unlock(&s_registry_lock);
	return 0;
}

size_t lichen_handoff_list_nodes(uint8_t (*addresses)[LICHEN_IPV6_ADDR_LEN],
				 size_t max_count)
{
	size_t count = 0;

	k_mutex_lock(&s_registry_lock, K_FOREVER);

	for (int i = 0; i < CONFIG_LICHEN_COAP_HANDOFF_MAX_NODES && count < max_count; i++) {
		if (s_nodes[i].valid) {
			memcpy(addresses[count], s_nodes[i].address, LICHEN_IPV6_ADDR_LEN);
			count++;
		}
	}

	k_mutex_unlock(&s_registry_lock);
	return count;
}

size_t lichen_handoff_node_count(void)
{
	size_t count = 0;

	k_mutex_lock(&s_registry_lock, K_FOREVER);

	for (int i = 0; i < CONFIG_LICHEN_COAP_HANDOFF_MAX_NODES; i++) {
		if (s_nodes[i].valid) {
			count++;
		}
	}

	k_mutex_unlock(&s_registry_lock);
	return count;
}

/* --------------------------------------------------------------------------
 * Handoff protocol logic
 * -------------------------------------------------------------------------- */

int lichen_handoff_process_request(const struct lichen_handoff_request *request,
				   struct lichen_handoff_response *response)
{
	if (request == NULL || response == NULL) {
		return -EINVAL;
	}

	memset(response, 0, sizeof(*response));

	k_mutex_lock(&s_registry_lock, K_FOREVER);

	struct lichen_node_entry *entry = find_node(request->node_address);
	if (entry == NULL) {
		k_mutex_unlock(&s_registry_lock);
		response->status = LICHEN_HANDOFF_NODE_NOT_FOUND;
		snprintf(response->message, sizeof(response->message),
			 "node not in registry");
		LOG_DBG("Handoff request for unknown node");
		return 0;
	}

	if (entry->busy) {
		k_mutex_unlock(&s_registry_lock);
		response->status = LICHEN_HANDOFF_NODE_BUSY;
		snprintf(response->message, sizeof(response->message),
			 "node in active transaction");
		LOG_DBG("Handoff request for busy node");
		return 0;
	}

	/* Build success response with state transfer */
	response->status = LICHEN_HANDOFF_SUCCESS;
	memcpy(response->node_address, entry->address, LICHEN_IPV6_ADDR_LEN);
	response->dao_sequence = entry->dao_sequence;
	response->path_sequence = entry->path_sequence;

	/* Copy OSCORE state if present */
	if (entry->oscore.valid) {
		memcpy(&response->oscore, &entry->oscore, sizeof(response->oscore));
	}

	/* Copy freshness state if present */
	if (entry->freshness.valid) {
		memcpy(&response->freshness, &entry->freshness, sizeof(response->freshness));
	}

	/* Copy parents */
	response->parent_count = entry->parent_count;
	memcpy(response->parents, entry->parents,
	       entry->parent_count * LICHEN_IPV6_ADDR_LEN);

	/* SECURITY: Wipe sensitive data and release ownership */
	secure_zero(entry->oscore.master_secret, sizeof(entry->oscore.master_secret));
	entry->valid = false;

	k_mutex_unlock(&s_registry_lock);
	LOG_INF("Handoff completed for node");
	return 0;
}

int lichen_handoff_accept_response(const struct lichen_handoff_response *response)
{
	if (response == NULL) {
		return -EINVAL;
	}

	if (response->status != LICHEN_HANDOFF_SUCCESS) {
		LOG_WRN("Cannot accept failed handoff: status=%d", response->status);
		return -EINVAL;
	}

	k_mutex_lock(&s_registry_lock, K_FOREVER);

	/* Find free slot */
	struct lichen_node_entry *entry = find_free_slot();
	if (entry == NULL) {
		k_mutex_unlock(&s_registry_lock);
		LOG_WRN("Cannot accept handoff: registry full");
		return -ENOMEM;
	}

	/* Initialize entry with transferred state */
	memset(entry, 0, sizeof(*entry));
	memcpy(entry->address, response->node_address, LICHEN_IPV6_ADDR_LEN);

	/* SECURITY: Increment sequence numbers to prevent replay of
	 * in-flight messages from before the handoff. A gap of 1 is the
	 * minimum safe increment. */
	entry->dao_sequence = response->dao_sequence + 1;
	entry->path_sequence = response->path_sequence + 1;

	/* Copy OSCORE state if present, incrementing sender sequence */
	if (response->oscore.valid) {
		memcpy(&entry->oscore, &response->oscore, sizeof(entry->oscore));
		/* SECURITY: Increment sender sequence to prevent nonce reuse */
		entry->oscore.sender_sequence++;
	}

	/* Copy freshness state */
	if (response->freshness.valid) {
		memcpy(&entry->freshness, &response->freshness, sizeof(entry->freshness));
	}

	/* Copy parents */
	entry->parent_count = response->parent_count;
	if (entry->parent_count > LICHEN_HANDOFF_MAX_PARENTS) {
		entry->parent_count = LICHEN_HANDOFF_MAX_PARENTS;
	}
	memcpy(entry->parents, response->parents,
	       entry->parent_count * LICHEN_IPV6_ADDR_LEN);

	entry->last_seen = k_uptime_get();
	entry->valid = true;

	k_mutex_unlock(&s_registry_lock);
	LOG_INF("Accepted handoff for node");
	return 0;
}

/* --------------------------------------------------------------------------
 * CBOR encoding context (similar to coap_keys_cbor.c)
 * -------------------------------------------------------------------------- */

struct cbor_enc_ctx {
	uint8_t *buf;
	size_t off;
	size_t size;
	bool overflow;
};

static void cbor_enc_init(struct cbor_enc_ctx *ctx, uint8_t *buf, size_t size)
{
	ctx->buf = buf;
	ctx->off = 0;
	ctx->size = size;
	ctx->overflow = false;
}

static bool cbor_enc_check(struct cbor_enc_ctx *ctx, size_t n)
{
	if (ctx->overflow || ctx->off + n > ctx->size) {
		ctx->overflow = true;
		return false;
	}
	return true;
}

static void cbor_enc_uint(struct cbor_enc_ctx *ctx, uint8_t major, uint64_t val)
{
	if (val < 24) {
		if (!cbor_enc_check(ctx, 1)) return;
		ctx->buf[ctx->off++] = (major << 5) | (uint8_t)val;
	} else if (val <= UINT8_MAX) {
		if (!cbor_enc_check(ctx, 2)) return;
		ctx->buf[ctx->off++] = (major << 5) | 24;
		ctx->buf[ctx->off++] = (uint8_t)val;
	} else if (val <= UINT16_MAX) {
		if (!cbor_enc_check(ctx, 3)) return;
		ctx->buf[ctx->off++] = (major << 5) | 25;
		ctx->buf[ctx->off++] = (uint8_t)(val >> 8);
		ctx->buf[ctx->off++] = (uint8_t)val;
	} else if (val <= UINT32_MAX) {
		if (!cbor_enc_check(ctx, 5)) return;
		ctx->buf[ctx->off++] = (major << 5) | 26;
		ctx->buf[ctx->off++] = (uint8_t)(val >> 24);
		ctx->buf[ctx->off++] = (uint8_t)(val >> 16);
		ctx->buf[ctx->off++] = (uint8_t)(val >> 8);
		ctx->buf[ctx->off++] = (uint8_t)val;
	} else {
		if (!cbor_enc_check(ctx, 9)) return;
		ctx->buf[ctx->off++] = (major << 5) | 27;
		ctx->buf[ctx->off++] = (uint8_t)(val >> 56);
		ctx->buf[ctx->off++] = (uint8_t)(val >> 48);
		ctx->buf[ctx->off++] = (uint8_t)(val >> 40);
		ctx->buf[ctx->off++] = (uint8_t)(val >> 32);
		ctx->buf[ctx->off++] = (uint8_t)(val >> 24);
		ctx->buf[ctx->off++] = (uint8_t)(val >> 16);
		ctx->buf[ctx->off++] = (uint8_t)(val >> 8);
		ctx->buf[ctx->off++] = (uint8_t)val;
	}
}

static void cbor_enc_int(struct cbor_enc_ctx *ctx, int64_t val)
{
	if (val >= 0) {
		cbor_enc_uint(ctx, 0, (uint64_t)val);
	} else {
		cbor_enc_uint(ctx, 1, (uint64_t)(-1 - val));
	}
}

static void cbor_enc_bstr(struct cbor_enc_ctx *ctx, const uint8_t *data, size_t len)
{
	cbor_enc_uint(ctx, 2, len);
	if (!cbor_enc_check(ctx, len)) return;
	memcpy(&ctx->buf[ctx->off], data, len);
	ctx->off += len;
}

static void cbor_enc_tstr(struct cbor_enc_ctx *ctx, const char *str)
{
	size_t len = str ? strlen(str) : 0;
	cbor_enc_uint(ctx, 3, len);
	if (!cbor_enc_check(ctx, len)) return;
	memcpy(&ctx->buf[ctx->off], str, len);
	ctx->off += len;
}

static void cbor_enc_map_header(struct cbor_enc_ctx *ctx, size_t count)
{
	cbor_enc_uint(ctx, 5, count);
}

static void cbor_enc_array_header(struct cbor_enc_ctx *ctx, size_t count)
{
	cbor_enc_uint(ctx, 4, count);
}

static void cbor_enc_float64(struct cbor_enc_ctx *ctx, double val)
{
	if (!cbor_enc_check(ctx, 9)) return;
	ctx->buf[ctx->off++] = 0xfb;  /* float64 */
	union { double d; uint64_t u; } conv;
	conv.d = val;
	ctx->buf[ctx->off++] = (uint8_t)(conv.u >> 56);
	ctx->buf[ctx->off++] = (uint8_t)(conv.u >> 48);
	ctx->buf[ctx->off++] = (uint8_t)(conv.u >> 40);
	ctx->buf[ctx->off++] = (uint8_t)(conv.u >> 32);
	ctx->buf[ctx->off++] = (uint8_t)(conv.u >> 24);
	ctx->buf[ctx->off++] = (uint8_t)(conv.u >> 16);
	ctx->buf[ctx->off++] = (uint8_t)(conv.u >> 8);
	ctx->buf[ctx->off++] = (uint8_t)conv.u;
}

/* --------------------------------------------------------------------------
 * CBOR encoding/decoding
 * -------------------------------------------------------------------------- */

int lichen_handoff_encode_request(const struct lichen_handoff_request *request,
				  uint8_t *buf, size_t buf_len)
{
	if (request == NULL || buf == NULL) {
		return -EINVAL;
	}

	struct cbor_enc_ctx ctx;
	cbor_enc_init(&ctx, buf, buf_len);

	/* Count map entries: node_address + timestamp + optional rssi */
	int count = 2;
	if (request->rssi != INT32_MIN) {
		count++;
	}

	cbor_enc_map_header(&ctx, count);

	/* node_address (key 1) */
	cbor_enc_int(&ctx, KEY_NODE_ADDR);
	cbor_enc_bstr(&ctx, request->node_address, LICHEN_IPV6_ADDR_LEN);

	/* timestamp (key 10) */
	cbor_enc_int(&ctx, KEY_TIMESTAMP);
	cbor_enc_uint(&ctx, 0, request->timestamp);

	/* rssi (key 9, optional) */
	if (request->rssi != INT32_MIN) {
		cbor_enc_int(&ctx, KEY_RSSI);
		cbor_enc_int(&ctx, request->rssi);
	}

	if (ctx.overflow) {
		return -ENOBUFS;
	}

	return (int)ctx.off;
}

int lichen_handoff_encode_response(const struct lichen_handoff_response *response,
				   uint8_t *buf, size_t buf_len)
{
	if (response == NULL || buf == NULL) {
		return -EINVAL;
	}

	struct cbor_enc_ctx ctx;
	cbor_enc_init(&ctx, buf, buf_len);

	/* Count map entries for header */
	int count = 1;  /* status always present */
	if (response->message[0] != '\0') {
		count++;
	}
	if (response->status == LICHEN_HANDOFF_SUCCESS) {
		count += 3;  /* node_address, dao_sequence, path_sequence */
		if (response->oscore.valid) {
			count += 3;  /* oscore_params, oscore_sender_seq, oscore_replay */
		}
		if (response->freshness.valid) {
			count++;
		}
		if (response->parent_count > 0) {
			count++;
		}
	}

	cbor_enc_map_header(&ctx, count);

	/* status (key 100) */
	cbor_enc_int(&ctx, KEY_STATUS);
	cbor_enc_int(&ctx, response->status);

	/* message (key 101, optional) */
	if (response->message[0] != '\0') {
		cbor_enc_int(&ctx, KEY_MESSAGE);
		cbor_enc_tstr(&ctx, response->message);
	}

	if (response->status == LICHEN_HANDOFF_SUCCESS) {
		/* node_address (key 1) */
		cbor_enc_int(&ctx, KEY_NODE_ADDR);
		cbor_enc_bstr(&ctx, response->node_address, LICHEN_IPV6_ADDR_LEN);

		/* dao_sequence (key 2) */
		cbor_enc_int(&ctx, KEY_DAO_SEQ);
		cbor_enc_uint(&ctx, 0, response->dao_sequence);

		/* path_sequence (key 3) */
		cbor_enc_int(&ctx, KEY_PATH_SEQ);
		cbor_enc_uint(&ctx, 0, response->path_sequence);

		/* OSCORE state (keys 4, 5, 6) */
		if (response->oscore.valid) {
			/* oscore_params (key 4) - nested map */
			cbor_enc_int(&ctx, KEY_OSCORE_PARAMS);

			int oscore_count = 7;  /* required fields */
			if (response->oscore.id_context_len > 0) {
				oscore_count++;
			}
			cbor_enc_map_header(&ctx, oscore_count);

			cbor_enc_int(&ctx, KEY_OSCORE_SECRET);
			cbor_enc_bstr(&ctx, response->oscore.master_secret,
				      LICHEN_HANDOFF_SECRET_LEN);

			cbor_enc_int(&ctx, KEY_OSCORE_SALT);
			cbor_enc_bstr(&ctx, response->oscore.master_salt,
				      response->oscore.master_salt_len);

			cbor_enc_int(&ctx, KEY_OSCORE_SENDER_ID);
			cbor_enc_bstr(&ctx, response->oscore.sender_id,
				      response->oscore.sender_id_len);

			cbor_enc_int(&ctx, KEY_OSCORE_RECIPIENT_ID);
			cbor_enc_bstr(&ctx, response->oscore.recipient_id,
				      response->oscore.recipient_id_len);

			cbor_enc_int(&ctx, KEY_OSCORE_ALG);
			cbor_enc_int(&ctx, response->oscore.algorithm);

			cbor_enc_int(&ctx, KEY_OSCORE_HASHFUN);
			cbor_enc_tstr(&ctx, (const char *)response->oscore.hashfun);

			cbor_enc_int(&ctx, KEY_OSCORE_WINDOW);
			cbor_enc_uint(&ctx, 0, response->oscore.window_size);

			if (response->oscore.id_context_len > 0) {
				cbor_enc_int(&ctx, KEY_OSCORE_ID_CTX);
				cbor_enc_bstr(&ctx, response->oscore.id_context,
					      response->oscore.id_context_len);
			}

			/* oscore_sender_seq (key 5) */
			cbor_enc_int(&ctx, KEY_OSCORE_SENDER_SEQ);
			cbor_enc_uint(&ctx, 0, response->oscore.sender_sequence);

			/* oscore_replay (key 6) - [index, bitfield] */
			cbor_enc_int(&ctx, KEY_OSCORE_REPLAY);
			cbor_enc_array_header(&ctx, 2);
			cbor_enc_uint(&ctx, 0, response->oscore.replay_index);
			cbor_enc_uint(&ctx, 0, response->oscore.replay_bitfield);
		}

		/* freshness (key 7) */
		if (response->freshness.valid) {
			cbor_enc_int(&ctx, KEY_FRESHNESS);

			int fresh_count = 3;  /* seq, retain, updated */
			if (response->freshness.active_until >= 0) {
				fresh_count++;
			}
			cbor_enc_map_header(&ctx, fresh_count);

			cbor_enc_tstr(&ctx, KEY_FRESH_SEQ);
			cbor_enc_uint(&ctx, 0, response->freshness.sequence);

			cbor_enc_tstr(&ctx, KEY_FRESH_RETAIN);
			cbor_enc_float64(&ctx, (double)response->freshness.retain_until / 1000000.0);

			cbor_enc_tstr(&ctx, KEY_FRESH_UPDATED);
			cbor_enc_float64(&ctx, (double)response->freshness.updated_at / 1000000.0);

			if (response->freshness.active_until >= 0) {
				cbor_enc_tstr(&ctx, KEY_FRESH_ACTIVE);
				cbor_enc_float64(&ctx, (double)response->freshness.active_until / 1000000.0);
			}
		}

		/* parents (key 8) */
		if (response->parent_count > 0) {
			cbor_enc_int(&ctx, KEY_PARENTS);
			cbor_enc_array_header(&ctx, response->parent_count);
			for (int i = 0; i < response->parent_count; i++) {
				cbor_enc_bstr(&ctx, response->parents[i], LICHEN_IPV6_ADDR_LEN);
			}
		}
	}

	if (ctx.overflow) {
		return -ENOBUFS;
	}

	return (int)ctx.off;
}

/* --------------------------------------------------------------------------
 * CBOR decoding helpers
 * -------------------------------------------------------------------------- */

struct cbor_dec_ctx {
	const uint8_t *buf;
	size_t off;
	size_t size;
	bool error;
};

static void cbor_dec_init(struct cbor_dec_ctx *ctx, const uint8_t *buf, size_t size)
{
	ctx->buf = buf;
	ctx->off = 0;
	ctx->size = size;
	ctx->error = false;
}

static bool cbor_dec_check(struct cbor_dec_ctx *ctx, size_t n)
{
	if (ctx->error || ctx->off + n > ctx->size) {
		ctx->error = true;
		return false;
	}
	return true;
}

static uint64_t cbor_dec_uint_arg(struct cbor_dec_ctx *ctx, uint8_t info)
{
	if (info < 24) {
		return info;
	} else if (info == 24) {
		if (!cbor_dec_check(ctx, 1)) return 0;
		return ctx->buf[ctx->off++];
	} else if (info == 25) {
		if (!cbor_dec_check(ctx, 2)) return 0;
		uint64_t val = ((uint64_t)ctx->buf[ctx->off] << 8) |
			       ctx->buf[ctx->off + 1];
		ctx->off += 2;
		return val;
	} else if (info == 26) {
		if (!cbor_dec_check(ctx, 4)) return 0;
		uint64_t val = ((uint64_t)ctx->buf[ctx->off] << 24) |
			       ((uint64_t)ctx->buf[ctx->off + 1] << 16) |
			       ((uint64_t)ctx->buf[ctx->off + 2] << 8) |
			       ctx->buf[ctx->off + 3];
		ctx->off += 4;
		return val;
	} else if (info == 27) {
		if (!cbor_dec_check(ctx, 8)) return 0;
		uint64_t val = ((uint64_t)ctx->buf[ctx->off] << 56) |
			       ((uint64_t)ctx->buf[ctx->off + 1] << 48) |
			       ((uint64_t)ctx->buf[ctx->off + 2] << 40) |
			       ((uint64_t)ctx->buf[ctx->off + 3] << 32) |
			       ((uint64_t)ctx->buf[ctx->off + 4] << 24) |
			       ((uint64_t)ctx->buf[ctx->off + 5] << 16) |
			       ((uint64_t)ctx->buf[ctx->off + 6] << 8) |
			       ctx->buf[ctx->off + 7];
		ctx->off += 8;
		return val;
	}
	ctx->error = true;
	return 0;
}

static int64_t cbor_dec_int(struct cbor_dec_ctx *ctx)
{
	if (!cbor_dec_check(ctx, 1)) return 0;
	uint8_t initial = ctx->buf[ctx->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	uint64_t val = cbor_dec_uint_arg(ctx, info);

	if (major == 0) {
		return (int64_t)val;
	} else if (major == 1) {
		return -1 - (int64_t)val;
	}
	ctx->error = true;
	return 0;
}

static uint64_t cbor_dec_uint(struct cbor_dec_ctx *ctx)
{
	if (!cbor_dec_check(ctx, 1)) return 0;
	uint8_t initial = ctx->buf[ctx->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 0) {
		ctx->error = true;
		return 0;
	}
	return cbor_dec_uint_arg(ctx, info);
}

static size_t cbor_dec_bstr(struct cbor_dec_ctx *ctx, uint8_t *out, size_t max_len)
{
	if (!cbor_dec_check(ctx, 1)) return 0;
	uint8_t initial = ctx->buf[ctx->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 2) {
		ctx->error = true;
		return 0;
	}

	uint64_t len = cbor_dec_uint_arg(ctx, info);
	if (len > max_len || !cbor_dec_check(ctx, len)) {
		ctx->error = true;
		return 0;
	}

	memcpy(out, &ctx->buf[ctx->off], len);
	ctx->off += len;
	return (size_t)len;
}

static size_t cbor_dec_map_header(struct cbor_dec_ctx *ctx)
{
	if (!cbor_dec_check(ctx, 1)) return 0;
	uint8_t initial = ctx->buf[ctx->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 5) {
		ctx->error = true;
		return 0;
	}
	return (size_t)cbor_dec_uint_arg(ctx, info);
}

int lichen_handoff_decode_request(const uint8_t *buf, size_t buf_len,
				  struct lichen_handoff_request *request)
{
	if (buf == NULL || request == NULL) {
		return -EINVAL;
	}

	memset(request, 0, sizeof(*request));
	request->rssi = INT32_MIN;  /* Mark as absent */

	struct cbor_dec_ctx ctx;
	cbor_dec_init(&ctx, buf, buf_len);

	size_t map_count = cbor_dec_map_header(&ctx);
	if (ctx.error) {
		return -EBADMSG;
	}

	bool got_addr = false;
	bool got_timestamp = false;

	for (size_t i = 0; i < map_count && !ctx.error; i++) {
		int64_t key = cbor_dec_int(&ctx);
		if (ctx.error) break;

		switch (key) {
		case KEY_NODE_ADDR:
			if (cbor_dec_bstr(&ctx, request->node_address,
					  LICHEN_IPV6_ADDR_LEN) != LICHEN_IPV6_ADDR_LEN) {
				ctx.error = true;
			}
			got_addr = true;
			break;

		case KEY_TIMESTAMP:
			request->timestamp = (uint32_t)cbor_dec_uint(&ctx);
			got_timestamp = true;
			break;

		case KEY_RSSI:
			request->rssi = (int32_t)cbor_dec_int(&ctx);
			break;

		default:
			/* Skip unknown keys - would need a more robust skip function */
			ctx.error = true;
			break;
		}
	}

	if (ctx.error || !got_addr || !got_timestamp) {
		return -EBADMSG;
	}

	return 0;
}

int lichen_handoff_decode_response(const uint8_t *buf, size_t buf_len,
				   struct lichen_handoff_response *response)
{
	if (buf == NULL || response == NULL) {
		return -EINVAL;
	}

	memset(response, 0, sizeof(*response));

	struct cbor_dec_ctx ctx;
	cbor_dec_init(&ctx, buf, buf_len);

	size_t map_count = cbor_dec_map_header(&ctx);
	if (ctx.error) {
		return -EBADMSG;
	}

	bool got_status = false;

	for (size_t i = 0; i < map_count && !ctx.error; i++) {
		int64_t key = cbor_dec_int(&ctx);
		if (ctx.error) break;

		switch (key) {
		case KEY_STATUS:
			response->status = (enum lichen_handoff_reason)cbor_dec_int(&ctx);
			got_status = true;
			break;

		case KEY_NODE_ADDR:
			cbor_dec_bstr(&ctx, response->node_address, LICHEN_IPV6_ADDR_LEN);
			break;

		case KEY_DAO_SEQ:
			response->dao_sequence = (uint32_t)cbor_dec_uint(&ctx);
			break;

		case KEY_PATH_SEQ:
			response->path_sequence = (uint32_t)cbor_dec_uint(&ctx);
			break;

		/* Skip complex nested structures for minimal implementation */
		default:
			ctx.error = true;
			break;
		}
	}

	if (ctx.error || !got_status) {
		return -EBADMSG;
	}

	return 0;
}

/* --------------------------------------------------------------------------
 * CoAP resource handler
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LICHEN_COAP_HANDOFF_RESOURCE

static int handoff_post(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	int ret;

	/* SECURITY: Require OSCORE protection for handoff requests */
	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len, COAP_METHOD_POST,
						     &oscore);
	if (ret != 0) {
		return ret;
	}

	if (!oscore.is_protected) {
		LOG_WRN("Handoff request not OSCORE protected");
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_UNAUTHORIZED,
					   0, NULL, 0);
	}

	if (oscore.payload == NULL || oscore.payload_len == 0) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST,
					   0, NULL, 0);
	}

	/* Decode request */
	struct lichen_handoff_request handoff_req;
	ret = lichen_handoff_decode_request(oscore.payload, oscore.payload_len,
					    &handoff_req);
	if (ret < 0) {
		LOG_WRN("Failed to decode handoff request: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_BAD_REQUEST,
					   0, NULL, 0);
	}

	/* Process handoff */
	struct lichen_handoff_response handoff_resp;
	ret = lichen_handoff_process_request(&handoff_req, &handoff_resp);
	if (ret < 0) {
		LOG_ERR("Handoff processing failed: %d", ret);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0);
	}

	/* Encode response */
	static uint8_t resp_buf[512];
	int resp_len = lichen_handoff_encode_response(&handoff_resp, resp_buf,
						      sizeof(resp_buf));
	if (resp_len < 0) {
		LOG_ERR("Failed to encode handoff response: %d", resp_len);
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0);
	}

	uint8_t code = (handoff_resp.status == LICHEN_HANDOFF_SUCCESS)
		       ? COAP_RESPONSE_CODE_CHANGED
		       : COAP_RESPONSE_CODE_BAD_REQUEST;

	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, code, CBOR_CONTENT_FORMAT,
					    resp_buf, resp_len);
}

/* Path: /.well-known/lichen-gw/handoff */
static const char * const handoff_path[] = {
	".well-known", "lichen-gw", "handoff", NULL
};

static const char * const handoff_attrs[] = {
	"rt=\"gcp.handoff\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_handoff, lichen_coap_server, {
	.post = handoff_post,
	.path = handoff_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = handoff_attrs,
	}),
});

#endif /* CONFIG_LICHEN_COAP_HANDOFF_RESOURCE */
