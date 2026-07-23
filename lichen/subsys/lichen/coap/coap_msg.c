/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_msg.c
 * @brief CoAP messaging resources for LCI
 *
 * Implements /msg resources per LCI spec section 17.5.7.
 */

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>
#include <zcbor_decode.h>

#include <lichen/coap_msg.h>
#include <lichen/coap_status.h>
#include <lichen/coap_server.h>

LOG_MODULE_REGISTER(lichen_coap_msg, CONFIG_LICHEN_COAP_MSG_LOG_LEVEL);

/* CBOR content-format code (RFC 7252) */
#define CBOR_CONTENT_FORMAT 60

/* Maximum CBOR buffer sizes */
#define MSG_CBOR_MAX_SIZE 512
#define MSG_LOCATION_PATH_MAX 16

/* CBOR encoding helpers - local copies to avoid cross-module deps */
static void cbor_put_map_header(uint8_t *buf, size_t *off, uint8_t count)
{
	if (count < 24U) {
		buf[(*off)++] = 0xa0U | count;
	} else {
		buf[(*off)++] = 0xb8;
		buf[(*off)++] = count;
	}
}

static void cbor_put_array_header(uint8_t *buf, size_t *off, uint8_t count)
{
	if (count < 24U) {
		buf[(*off)++] = 0x80U | count;
	} else {
		buf[(*off)++] = 0x98;
		buf[(*off)++] = count;
	}
}

static void cbor_put_tstr(uint8_t *buf, size_t *off, const char *value, size_t len)
{
	if (len > 0xffffffffU) {
		len = 0xffffffffU;
	}
	if (len < 24U) {
		buf[(*off)++] = 0x60U | (uint8_t)len;
	} else if (len <= UINT8_MAX) {
		buf[(*off)++] = 0x78;
		buf[(*off)++] = (uint8_t)len;
	} else if (len <= 0xffffU) {
		buf[(*off)++] = 0x79;
		buf[(*off)++] = (uint8_t)(len >> 8);
		buf[(*off)++] = (uint8_t)(len & 0xffU);
	} else {
		buf[(*off)++] = 0x7a;
		buf[(*off)++] = (uint8_t)(len >> 24);
		buf[(*off)++] = (uint8_t)(len >> 16);
		buf[(*off)++] = (uint8_t)(len >> 8);
		buf[(*off)++] = (uint8_t)(len & 0xffU);
	}
	memcpy(&buf[*off], value, len);
	*off += len;
}

static void cbor_put_key(uint8_t *buf, size_t *off, const char *key)
{
	cbor_put_tstr(buf, off, key, strlen(key));
}

static void cbor_put_uint(uint8_t *buf, size_t *off, uint32_t value)
{
	if (value < 24U) {
		buf[(*off)++] = (uint8_t)value;
	} else if (value <= UINT8_MAX) {
		buf[(*off)++] = 0x18;
		buf[(*off)++] = (uint8_t)value;
	} else if (value <= UINT16_MAX) {
		buf[(*off)++] = 0x19;
		buf[(*off)++] = (uint8_t)(value >> 8);
		buf[(*off)++] = (uint8_t)(value & 0xffU);
	} else {
		buf[(*off)++] = 0x1a;
		buf[(*off)++] = (uint8_t)(value >> 24);
		buf[(*off)++] = (uint8_t)(value >> 16);
		buf[(*off)++] = (uint8_t)(value >> 8);
		buf[(*off)++] = (uint8_t)(value & 0xffU);
	}
}

/* Message queues - protected by mutex */
static struct lichen_msg s_inbox[LICHEN_MSG_INBOX_MAX];
static size_t s_inbox_count;
static struct lichen_msg s_sent[LICHEN_MSG_SENT_MAX];
static size_t s_sent_count;
static uint32_t s_next_msg_id = 1;
static K_MUTEX_DEFINE(s_msg_mutex);
static bool s_initialized;

/* Forward declare the inbox resource for notify */
#if IS_ENABLED(CONFIG_LICHEN_COAP_MSG)
extern struct coap_resource coap_resource_msg_inbox;
#endif

int lichen_msg_init(void)
{
	k_mutex_lock(&s_msg_mutex, K_FOREVER);

	if (s_initialized) {
		k_mutex_unlock(&s_msg_mutex);
		return 0;
	}

	memset(s_inbox, 0, sizeof(s_inbox));
	memset(s_sent, 0, sizeof(s_sent));
	s_inbox_count = 0;
	s_sent_count = 0;
	s_next_msg_id = 1;
	s_initialized = true;

	k_mutex_unlock(&s_msg_mutex);
	LOG_INF("Message subsystem initialized");
	return 0;
}

int lichen_msg_send(const uint8_t *to_addr,
		    const char *body, size_t body_len,
		    bool ack, uint32_t *msg_id)
{
	struct lichen_msg *msg;
	int ret = 0;

	if (to_addr == NULL || body == NULL) {
		return -EINVAL;
	}
	if (body_len > LICHEN_MSG_MAX_BODY_LEN) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&s_msg_mutex, K_FOREVER);

	if (!s_initialized) {
		ret = -ENODEV;
		goto out;
	}

	if (s_sent_count >= LICHEN_MSG_SENT_MAX) {
		/* Queue full - drop oldest */
		memmove(&s_sent[0], &s_sent[1],
			sizeof(s_sent[0]) * (LICHEN_MSG_SENT_MAX - 1));
		s_sent_count = LICHEN_MSG_SENT_MAX - 1;
	}

	msg = &s_sent[s_sent_count];
	memset(msg, 0, sizeof(*msg));
	msg->id = s_next_msg_id++;
	memcpy(msg->peer_addr, to_addr, 16);
	memcpy(msg->body, body, body_len);
	msg->body_len = body_len;
	msg->timestamp = (uint32_t)(k_uptime_get() / 1000);
	msg->status = LICHEN_MSG_STATUS_QUEUED;
	msg->ack_requested = ack;
	s_sent_count++;

	if (msg_id != NULL) {
		*msg_id = msg->id;
	}

	LOG_INF("Queued outbound message id=%u len=%zu ack=%d",
		msg->id, body_len, ack);

out:
	k_mutex_unlock(&s_msg_mutex);
	return ret;
}

int lichen_msg_receive(const uint8_t *from_addr,
		       const char *body, size_t body_len,
		       uint32_t timestamp)
{
	struct lichen_msg *msg;
	int ret = 0;

	if (from_addr == NULL || body == NULL) {
		return -EINVAL;
	}
	if (body_len > LICHEN_MSG_MAX_BODY_LEN) {
		return -EMSGSIZE;
	}

	k_mutex_lock(&s_msg_mutex, K_FOREVER);

	if (!s_initialized) {
		ret = -ENODEV;
		goto out;
	}

	if (s_inbox_count >= LICHEN_MSG_INBOX_MAX) {
		/* Queue full - drop oldest */
		memmove(&s_inbox[0], &s_inbox[1],
			sizeof(s_inbox[0]) * (LICHEN_MSG_INBOX_MAX - 1));
		s_inbox_count = LICHEN_MSG_INBOX_MAX - 1;
	}

	msg = &s_inbox[s_inbox_count];
	memset(msg, 0, sizeof(*msg));
	msg->id = s_next_msg_id++;
	memcpy(msg->peer_addr, from_addr, 16);
	memcpy(msg->body, body, body_len);
	msg->body_len = body_len;
	msg->timestamp = timestamp;
	msg->status = LICHEN_MSG_STATUS_DELIVERED;
	s_inbox_count++;

	LOG_INF("Received message id=%u len=%zu", msg->id, body_len);

out:
	k_mutex_unlock(&s_msg_mutex);
	return ret;
}

int lichen_msg_ack(uint32_t msg_id)
{
	int ret = -ENOENT;

	k_mutex_lock(&s_msg_mutex, K_FOREVER);

	for (size_t i = 0; i < s_inbox_count; i++) {
		if (s_inbox[i].id == msg_id) {
			s_inbox[i].acknowledged = true;
			ret = 0;
			LOG_INF("Message %u acknowledged", msg_id);
			break;
		}
	}

	k_mutex_unlock(&s_msg_mutex);
	return ret;
}

int lichen_msg_sent_get(uint32_t msg_id, struct lichen_msg *msg)
{
	int ret = -ENOENT;

	if (msg == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_msg_mutex, K_FOREVER);

	for (size_t i = 0; i < s_sent_count; i++) {
		if (s_sent[i].id == msg_id) {
			*msg = s_sent[i];
			ret = 0;
			break;
		}
	}

	k_mutex_unlock(&s_msg_mutex);
	return ret;
}

size_t lichen_msg_inbox_count(void)
{
	size_t count;

	k_mutex_lock(&s_msg_mutex, K_FOREVER);
	count = s_inbox_count;
	k_mutex_unlock(&s_msg_mutex);

	return count;
}

int lichen_msg_inbox_get(size_t index, struct lichen_msg *msg)
{
	int ret = -ENOENT;

	if (msg == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_msg_mutex, K_FOREVER);

	if (index < s_inbox_count) {
		*msg = s_inbox[index];
		ret = 0;
	}

	k_mutex_unlock(&s_msg_mutex);
	return ret;
}

void lichen_msg_inbox_notify(void)
{
#if IS_ENABLED(CONFIG_LICHEN_COAP_MSG)
	coap_resource_notify(&coap_resource_msg_inbox);
#endif
}

/* --------------------------------------------------------------------------
 * CoAP response helper
 * -------------------------------------------------------------------------- */

static int coap_respond(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len,
			uint8_t resp_code,
			const uint8_t *payload, size_t payload_len)
{
	static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet resp;
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t tkl = coap_header_get_token(request, token);
	uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
		       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int r;

	r = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1,
			     type, tkl, token, resp_code,
			     coap_header_get_id(request));
	if (r < 0) {
		return r;
	}

	if (payload != NULL && payload_len > 0) {
		r = coap_append_option_int(&resp, COAP_OPTION_CONTENT_FORMAT,
					   CBOR_CONTENT_FORMAT);
		if (r < 0) {
			return r;
		}
		r = coap_packet_append_payload_marker(&resp);
		if (r < 0) {
			return r;
		}
		r = coap_packet_append_payload(&resp, payload, payload_len);
		if (r < 0) {
			return r;
		}
	}

	return coap_resource_send(resource, &resp, addr, addr_len, NULL);
}

/* --------------------------------------------------------------------------
 * CBOR decoding helpers
 * -------------------------------------------------------------------------- */

#define KEY_TO "to"
#define KEY_TO_LEN (sizeof(KEY_TO) - 1)
#define KEY_BODY "body"
#define KEY_BODY_LEN (sizeof(KEY_BODY) - 1)
#define KEY_ACK "ack"
#define KEY_ACK_LEN (sizeof(KEY_ACK) - 1)
#define KEY_ID "id"
#define KEY_ID_LEN (sizeof(KEY_ID) - 1)

static bool key_matches(const struct zcbor_string *key,
			const char *expected, size_t expected_len)
{
	return key->len == expected_len &&
	       memcmp(key->value, expected, expected_len) == 0;
}

/* Parse IPv6 address string to binary */
static int parse_ipv6_addr(const char *str, size_t len, uint8_t *addr)
{
	char addr_buf[LICHEN_MSG_ADDR_LEN + 1];
	struct in6_addr in6;

	if (len >= sizeof(addr_buf)) {
		return -EINVAL;
	}

	memcpy(addr_buf, str, len);
	addr_buf[len] = '\0';

	if (net_addr_pton(AF_INET6, addr_buf, &in6) < 0) {
		return -EINVAL;
	}

	memcpy(addr, in6.s6_addr, 16);
	return 0;
}

/* --------------------------------------------------------------------------
 * POST /msg/sent - Queue outbound message
 * -------------------------------------------------------------------------- */

int lichen_msg_sent_post(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	uint8_t to_addr[16] = {0};
	char body[LICHEN_MSG_MAX_BODY_LEN];
	size_t body_len = 0;
	bool ack = false;
	bool found_to = false;
	bool found_body = false;
	uint32_t msg_id = 0;
	int ret;

	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_UNAUTHORIZED, NULL, 0);
	}

	if (payload == NULL || payload_len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Decode CBOR payload */
	ZCBOR_STATE_D(zsd, 2, payload, payload_len, 1, 0);

	if (!zcbor_map_start_decode(zsd)) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	while (!zcbor_array_at_end(zsd)) {
		struct zcbor_string key;

		if (!zcbor_tstr_decode(zsd, &key)) {
			goto bad_request;
		}

		if (key_matches(&key, KEY_TO, KEY_TO_LEN)) {
			struct zcbor_string to_str;

			if (!zcbor_tstr_decode(zsd, &to_str)) {
				goto bad_request;
			}
			if (parse_ipv6_addr((const char *)to_str.value,
					    to_str.len, to_addr) < 0) {
				goto bad_request;
			}
			found_to = true;
		} else if (key_matches(&key, KEY_BODY, KEY_BODY_LEN)) {
			struct zcbor_string body_str;

			if (!zcbor_tstr_decode(zsd, &body_str)) {
				goto bad_request;
			}
			if (body_str.len > sizeof(body)) {
				goto bad_request;
			}
			memcpy(body, body_str.value, body_str.len);
			body_len = body_str.len;
			found_body = true;
		} else if (key_matches(&key, KEY_ACK, KEY_ACK_LEN)) {
			if (!zcbor_bool_decode(zsd, &ack)) {
				goto bad_request;
			}
		} else {
			/* Skip unknown value (key already decoded) */
			if (!zcbor_any_skip(zsd, NULL)) {
				goto bad_request;
			}
		}
	}

	if (!zcbor_map_end_decode(zsd) || !found_to || !found_body) {
		goto bad_request;
	}

	/* Queue the message */
	ret = lichen_msg_send(to_addr, body, body_len, ack, &msg_id);
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE,
				    NULL, 0);
	}

	/* Build response with Location-Path */
	{
		static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
		struct coap_packet resp;
		uint8_t token[COAP_TOKEN_MAX_LEN];
		uint8_t tkl = coap_header_get_token(request, token);
		uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
			       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
		char id_str[12];
		int id_len;

		ret = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1,
				       type, tkl, token,
				       COAP_RESPONSE_CODE_CREATED,
				       coap_header_get_id(request));
		if (ret < 0) {
			return ret;
		}

		/* Location-Path: /msg/sent/<id> */
		ret = coap_packet_append_option(&resp, COAP_OPTION_LOCATION_PATH,
						"msg", 3);
		if (ret < 0) {
			return ret;
		}
		ret = coap_packet_append_option(&resp, COAP_OPTION_LOCATION_PATH,
						"sent", 4);
		if (ret < 0) {
			return ret;
		}

		id_len = snprintf(id_str, sizeof(id_str), "%u", msg_id);
		if (id_len < 0 || (size_t)id_len >= sizeof(id_str)) {
			return -EINVAL;
		}
		ret = coap_packet_append_option(&resp, COAP_OPTION_LOCATION_PATH,
						id_str, (uint16_t)id_len);
		if (ret < 0) {
			return ret;
		}

		return coap_resource_send(resource, &resp, addr, addr_len, NULL);
	}

bad_request:
	(void)zcbor_list_map_end_force_decode(zsd);
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
}

/* --------------------------------------------------------------------------
 * GET /msg/sent/<id> - Get sent message status
 * -------------------------------------------------------------------------- */

int lichen_msg_sent_id_get(struct coap_resource *resource,
			   struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	uint32_t msg_id = 0;
	struct lichen_msg msg;
	uint8_t cbor_buf[MSG_CBOR_MAX_SIZE];
	size_t off = 0;
	char addr_str[LICHEN_MSG_ADDR_LEN];
	const char *status_str;
	int ret;
	int opt_count;
	struct coap_option opts[4];

	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, opts, 4);
	if (opt_count < 3) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	{
		char id_buf[12];
		size_t id_len = opts[2].len;

		if (id_len >= sizeof(id_buf) || id_len == 0) {
			return coap_respond(resource, request, addr, addr_len,
					    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
		}
		memcpy(id_buf, opts[2].value, id_len);
		id_buf[id_len] = '\0';

		if (!isdigit((unsigned char)id_buf[0])) {
			return coap_respond(resource, request, addr, addr_len,
					    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
		}

		char *endptr;
		errno = 0;
		unsigned long val = strtoul(id_buf, &endptr, 10);

		if (errno == ERANGE || endptr == id_buf || *endptr != '\0' || val > UINT32_MAX) {
			return coap_respond(resource, request, addr, addr_len,
					    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
		}
		msg_id = (uint32_t)val;
	}

	ret = lichen_msg_sent_get(msg_id, &msg);
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}

	/* Encode response CBOR */
	switch (msg.status) {
	case LICHEN_MSG_STATUS_QUEUED:
		status_str = "queued";
		break;
	case LICHEN_MSG_STATUS_SENDING:
		status_str = "sending";
		break;
	case LICHEN_MSG_STATUS_DELIVERED:
		status_str = "delivered";
		break;
	case LICHEN_MSG_STATUS_FAILED:
		status_str = "failed";
		break;
	default:
		status_str = "unknown";
		break;
	}

	if (lichen_coap_format_ipv6(msg.peer_addr, addr_str, sizeof(addr_str)) < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	cbor_put_map_header(cbor_buf, &off, 5);
	cbor_put_key(cbor_buf, &off, "id");
	cbor_put_uint(cbor_buf, &off, msg.id);
	cbor_put_key(cbor_buf, &off, "to");
	cbor_put_tstr(cbor_buf, &off, addr_str, strlen(addr_str));
	cbor_put_key(cbor_buf, &off, "body");
	cbor_put_tstr(cbor_buf, &off, msg.body, msg.body_len);
	cbor_put_key(cbor_buf, &off, "timestamp");
	cbor_put_uint(cbor_buf, &off, msg.timestamp);
	cbor_put_key(cbor_buf, &off, "status");
	cbor_put_tstr(cbor_buf, &off, status_str, strlen(status_str));

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, off);
}

/* --------------------------------------------------------------------------
 * GET /msg/inbox - Retrieve inbound messages (Observable)
 * -------------------------------------------------------------------------- */

static size_t encode_inbox_cbor(uint8_t *buf, size_t buf_size)
{
	size_t off = 0;
	size_t count;
	char addr_str[LICHEN_MSG_ADDR_LEN];

	k_mutex_lock(&s_msg_mutex, K_FOREVER);
	count = s_inbox_count;

	/* {"messages": [...]} */
	cbor_put_map_header(buf, &off, 1);
	cbor_put_key(buf, &off, "messages");
	cbor_put_array_header(buf, &off, (uint8_t)count);

	for (size_t i = 0; i < count && off + 100 < buf_size; i++) {
		const struct lichen_msg *msg = &s_inbox[i];

		if (lichen_coap_format_ipv6(msg->peer_addr, addr_str,
				     sizeof(addr_str)) < 0) {
			continue;
		}

		/* Each message: {id, from, body, received} */
		cbor_put_map_header(buf, &off, 4);
		cbor_put_key(buf, &off, "id");
		cbor_put_uint(buf, &off, msg->id);
		cbor_put_key(buf, &off, "from");
		cbor_put_tstr(buf, &off, addr_str, strlen(addr_str));
		cbor_put_key(buf, &off, "body");
		cbor_put_tstr(buf, &off, msg->body, msg->body_len);
		cbor_put_key(buf, &off, "received");
		cbor_put_uint(buf, &off, msg->timestamp);
	}

	k_mutex_unlock(&s_msg_mutex);
	return off;
}

/* Renamed handler function to avoid conflict with lichen_msg_inbox_get */
int lichen_msg_inbox_get_handler(struct coap_resource *resource,
				 struct coap_packet *request,
				 struct sockaddr *addr, socklen_t addr_len)
{
	uint8_t cbor_buf[MSG_CBOR_MAX_SIZE];
	size_t len;

	len = encode_inbox_cbor(cbor_buf, sizeof(cbor_buf));
	if (len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CONTENT, cbor_buf, len);
}

void lichen_msg_inbox_notify_cb(struct coap_resource *resource,
				struct coap_observer *observer)
{
	static uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t cbor_buf[MSG_CBOR_MAX_SIZE];
	struct coap_packet notif;
	size_t cbor_len;
	int r;

	cbor_len = encode_inbox_cbor(cbor_buf, sizeof(cbor_buf));
	if (cbor_len == 0) {
		return;
	}

	r = coap_packet_init(&notif, buf, sizeof(buf), COAP_VERSION_1,
			     COAP_TYPE_NON_CON,
			     observer->tkl, observer->token,
			     COAP_RESPONSE_CODE_CONTENT, 0);
	if (r < 0) {
		return;
	}

	r = coap_append_option_int(&notif, COAP_OPTION_OBSERVE, resource->age);
	if (r < 0) {
		return;
	}

	r = coap_append_option_int(&notif, COAP_OPTION_CONTENT_FORMAT,
				   CBOR_CONTENT_FORMAT);
	if (r < 0) {
		return;
	}

	r = coap_packet_append_payload_marker(&notif);
	if (r < 0) {
		return;
	}

	r = coap_packet_append_payload(&notif, cbor_buf, cbor_len);
	if (r < 0) {
		return;
	}

	(void)coap_resource_send(resource, &notif,
				 &observer->addr, sizeof(observer->addr), NULL);
}

/* --------------------------------------------------------------------------
 * POST /msg/ack - Acknowledge message receipt
 * -------------------------------------------------------------------------- */

int lichen_msg_ack_post(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t payload_len = 0;
	const uint8_t *payload = coap_packet_get_payload(request, &payload_len);
	uint32_t msg_id = 0;
	bool found_id = false;
	int ret;

	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_UNAUTHORIZED, NULL, 0);
	}

	if (payload == NULL || payload_len == 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	/* Decode CBOR: {"id": <uint>} */
	ZCBOR_STATE_D(zsd, 2, payload, payload_len, 1, 0);

	if (!zcbor_map_start_decode(zsd)) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
	}

	while (!zcbor_array_at_end(zsd)) {
		struct zcbor_string key;

		if (!zcbor_tstr_decode(zsd, &key)) {
			goto bad_request;
		}

		if (key_matches(&key, KEY_ID, KEY_ID_LEN)) {
			if (!zcbor_uint32_decode(zsd, &msg_id)) {
				goto bad_request;
			}
			found_id = true;
		} else {
			/* Skip unknown value (key already decoded) */
			if (!zcbor_any_skip(zsd, NULL)) {
				goto bad_request;
			}
		}
	}

	if (!zcbor_map_end_decode(zsd) || !found_id) {
		goto bad_request;
	}

	ret = lichen_msg_ack(msg_id);
	if (ret == -ENOENT) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_NOT_FOUND, NULL, 0);
	}
	if (ret < 0) {
		return coap_respond(resource, request, addr, addr_len,
				    COAP_RESPONSE_CODE_INTERNAL_ERROR, NULL, 0);
	}

	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_CHANGED, NULL, 0);

bad_request:
	(void)zcbor_list_map_end_force_decode(zsd);
	return coap_respond(resource, request, addr, addr_len,
			    COAP_RESPONSE_CODE_BAD_REQUEST, NULL, 0);
}

/* --------------------------------------------------------------------------
 * CoAP resource definitions
 *
 * These are conditionally compiled and reference the lichen_coap_server
 * service defined in coap_server.c (via COAP_SERVICE_DEFINE).
 * -------------------------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LICHEN_COAP_MSG)

static const char * const msg_sent_path[] = { "msg", "sent", NULL };
COAP_RESOURCE_DEFINE(msg_sent, lichen_coap_server, {
	.post = lichen_msg_sent_post,
	.path = msg_sent_path,
});

static const char * const msg_sent_id_path[] = { "msg", "sent", "*", NULL };
COAP_RESOURCE_DEFINE(msg_sent_id, lichen_coap_server, {
	.get = lichen_msg_sent_id_get,
	.path = msg_sent_id_path,
});

static const char * const msg_inbox_path[] = { "msg", "inbox", NULL };
COAP_RESOURCE_DEFINE(msg_inbox, lichen_coap_server, {
	.get = lichen_msg_inbox_get_handler,
	.notify = lichen_msg_inbox_notify_cb,
	.path = msg_inbox_path,
});

static const char * const msg_ack_path[] = { "msg", "ack", NULL };
COAP_RESOURCE_DEFINE(msg_ack, lichen_coap_server, {
	.post = lichen_msg_ack_post,
	.path = msg_ack_path,
});

#endif /* CONFIG_LICHEN_COAP_MSG */
