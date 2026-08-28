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
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>
#include <zephyr/net/net_ip.h>

#include <lichen/coap_msg.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_status.h>
#include <lichen/coap_server.h>

LOG_MODULE_REGISTER(lichen_coap_msg, CONFIG_LICHEN_COAP_MSG_LOG_LEVEL);

/* CBOR content-format code (RFC 7252) */
#define CBOR_CONTENT_FORMAT 60

/* Maximum CBOR buffer sizes */
#define MSG_CBOR_MAX_SIZE 512
#define MSG_ID_DECIMAL_SIZE 21
#define MSG_ACK_CBOR_MAX_SIZE 96
#define MSG_SENT_POST_CBOR_MAX_SIZE 288
#define MSG_INBOX_MAX_OBSERVERS 4U
#define MSG_INBOX_OBSERVER_TTL_MS (5U * 60U * 1000U)
#define MSG_INBOX_OBSERVE_MAX_RETRIES 3U

/* Worst-case encoded sizes used to keep the unchecked local CBOR helpers
 * inside their caller-provided buffer. */
#define MSG_INBOX_ENTRY_MAX_CBOR 304
#define MSG_SENT_ENTRY_MAX_CBOR 302

/* CBOR encoding helpers - local copies to avoid cross-module deps */
static void cbor_put_map_header(uint8_t *buf, size_t *off, size_t count)
{
	if (count < 24U) {
		buf[(*off)++] = 0xa0U | (uint8_t)count;
	} else if (count <= UINT8_MAX) {
		buf[(*off)++] = 0xb8;
		buf[(*off)++] = (uint8_t)count;
	} else {
		buf[(*off)++] = 0xb9;
		buf[(*off)++] = (uint8_t)(count >> 8);
		buf[(*off)++] = (uint8_t)(count & 0xffU);
	}
}

static void cbor_put_array_header(uint8_t *buf, size_t *off, size_t count)
{
	if (count < 24U) {
		buf[(*off)++] = 0x80U | (uint8_t)count;
	} else if (count <= UINT8_MAX) {
		buf[(*off)++] = 0x98;
		buf[(*off)++] = (uint8_t)count;
	} else {
		buf[(*off)++] = 0x99;
		buf[(*off)++] = (uint8_t)(count >> 8);
		buf[(*off)++] = (uint8_t)(count & 0xffU);
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

static void cbor_put_uint(uint8_t *buf, size_t *off, uint64_t value)
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
	} else if (value <= UINT32_MAX) {
		buf[(*off)++] = 0x1a;
		buf[(*off)++] = (uint8_t)(value >> 24);
		buf[(*off)++] = (uint8_t)(value >> 16);
		buf[(*off)++] = (uint8_t)(value >> 8);
		buf[(*off)++] = (uint8_t)(value & 0xffU);
	} else {
		buf[(*off)++] = 0x1b;
		buf[(*off)++] = (uint8_t)(value >> 56);
		buf[(*off)++] = (uint8_t)(value >> 48);
		buf[(*off)++] = (uint8_t)(value >> 40);
		buf[(*off)++] = (uint8_t)(value >> 32);
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
static uint64_t s_next_msg_id = 1;
static K_MUTEX_DEFINE(s_msg_mutex);
static bool s_initialized;

struct msg_inbox_observer_slot {
	struct coap_observer observer;
	struct coap_resource *resource;
	socklen_t addr_len;
	int64_t last_refresh_ms;
	uint64_t generation;
	size_t offset;
	size_t limit;
	uint8_t retries;
	bool active;
	bool pending;
	bool remove_pending;
};

static struct msg_inbox_observer_slot
	s_inbox_observers[MSG_INBOX_MAX_OBSERVERS];
static K_MUTEX_DEFINE(s_inbox_observe_mutex);
static uint64_t s_inbox_generation;

/* Forward declare the inbox resource for notify */
#if IS_ENABLED(CONFIG_LICHEN_COAP_MSG)
extern struct coap_resource coap_resource_msg_inbox;
extern struct coap_resource coap_resource_msg_sent;
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
	s_inbox_generation = 0U;
	memset(s_inbox_observers, 0, sizeof(s_inbox_observers));
	s_initialized = true;

	k_mutex_unlock(&s_msg_mutex);
	LOG_INF("Message subsystem initialized");
	return 0;
}

static bool sent_message_matches(const struct lichen_msg *msg,
				 const uint8_t *to_addr,
				 const char *body, size_t body_len, bool ack)
{
	return memcmp(msg->peer_addr, to_addr, sizeof(msg->peer_addr)) == 0 &&
	       msg->body_len == body_len &&
	       memcmp(msg->body, body, body_len) == 0 &&
	       msg->ack_requested == ack;
}

static int msg_store_sent(const uint8_t *to_addr,
			  const char *body, size_t body_len, bool ack,
			  bool explicit_id, uint64_t requested_id,
			  uint64_t *msg_id)
{
	struct lichen_msg *msg;
	uint64_t assigned_id;
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
	if (explicit_id) {
		assigned_id = requested_id;
		for (size_t i = 0U; i < s_sent_count; i++) {
			if (s_sent[i].id != assigned_id) {
				continue;
			}
			if (!sent_message_matches(&s_sent[i], to_addr, body,
						  body_len, ack)) {
				ret = -EEXIST;
				goto out;
			}
			if (msg_id != NULL) {
				*msg_id = assigned_id;
			}
			goto out;
		}
	} else {
		if (s_next_msg_id == 0U) {
			ret = -EOVERFLOW;
			goto out;
		}
		assigned_id = s_next_msg_id;
	}

	if (s_sent_count >= LICHEN_MSG_SENT_MAX) {
		/* Queue full - drop oldest */
		memmove(&s_sent[0], &s_sent[1],
			sizeof(s_sent[0]) * (LICHEN_MSG_SENT_MAX - 1));
		s_sent_count = LICHEN_MSG_SENT_MAX - 1;
	}

	msg = &s_sent[s_sent_count];
	memset(msg, 0, sizeof(*msg));
	msg->id = assigned_id;
	memcpy(msg->peer_addr, to_addr, 16);
	memcpy(msg->body, body, body_len);
	msg->body_len = body_len;
	msg->timestamp = (uint32_t)(k_uptime_get() / 1000);
	msg->status = LICHEN_MSG_STATUS_QUEUED;
	msg->status_timestamp = 0U;
	msg->ack_requested = ack;
	s_sent_count++;
	if (!explicit_id ||
	    (s_next_msg_id != 0U && assigned_id >= s_next_msg_id)) {
		s_next_msg_id = assigned_id == UINT64_MAX ? 0U : assigned_id + 1U;
	}

	if (msg_id != NULL) {
		*msg_id = msg->id;
	}

	LOG_INF("Queued outbound message id=%" PRIu64 " len=%zu ack=%d",
		msg->id, body_len, ack);

out:
	k_mutex_unlock(&s_msg_mutex);
	return ret;
}

int lichen_msg_send(const uint8_t *to_addr,
		    const char *body, size_t body_len,
		    bool ack, uint64_t *msg_id)
{
	return msg_store_sent(to_addr, body, body_len, ack, false, 0U, msg_id);
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
	if (s_next_msg_id == 0U) {
		ret = -EOVERFLOW;
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
	msg->id = s_next_msg_id;
	s_next_msg_id = msg->id == UINT64_MAX ? 0U : msg->id + 1U;
	memcpy(msg->peer_addr, from_addr, 16);
	memcpy(msg->body, body, body_len);
	msg->body_len = body_len;
	msg->timestamp = timestamp;
	msg->status = LICHEN_MSG_STATUS_DELIVERED;
	s_inbox_count++;
	s_inbox_generation++;

	LOG_INF("Received message id=%" PRIu64 " len=%zu", msg->id, body_len);

out:
	k_mutex_unlock(&s_msg_mutex);
	if (ret == 0) {
		lichen_msg_inbox_notify();
	}
	return ret;
}

int lichen_msg_ack(uint64_t msg_id)
{
	int ret = -ENOENT;

	k_mutex_lock(&s_msg_mutex, K_FOREVER);
	if (!s_initialized) {
		ret = -ENODEV;
		goto out;
	}

	for (size_t i = 0; i < s_inbox_count; i++) {
		if (s_inbox[i].id == msg_id) {
			s_inbox[i].acknowledged = true;
			ret = 0;
			LOG_INF("Message id=%" PRIu64 " acknowledged", msg_id);
			break;
		}
	}

out:
	k_mutex_unlock(&s_msg_mutex);
	return ret;
}

int lichen_msg_receipt_apply(uint64_t msg_id,
			     enum lichen_msg_status status,
			     uint32_t timestamp,
			     const uint8_t *peer_addr,
			     bool local_admin)
{
	int ret = -ENOENT;
	bool changed = false;

	if (status != LICHEN_MSG_STATUS_DELIVERED &&
	    status != LICHEN_MSG_STATUS_READ &&
	    status != LICHEN_MSG_STATUS_FAILED) {
		return -EINVAL;
	}

	k_mutex_lock(&s_msg_mutex, K_FOREVER);
	if (!s_initialized) {
		ret = -ENODEV;
		goto out;
	}

	for (size_t i = 0; i < s_sent_count; i++) {
		struct lichen_msg *msg = &s_sent[i];

		if (msg->id != msg_id) {
			continue;
		}
		if (!msg->ack_requested ||
		    (!local_admin &&
		     (peer_addr == NULL ||
		      memcmp(&msg->peer_addr[8], &peer_addr[8], 8) != 0))) {
			ret = -EACCES;
			break;
		}
		if (msg->receipt_present) {
			if (msg->status == status &&
			    msg->receipt_timestamp == timestamp) {
				ret = 0;
				break;
			}
			if ((msg->receipt_timestamp != 0U &&
			     (timestamp == 0U || timestamp <= msg->receipt_timestamp)) ||
			    msg->status == LICHEN_MSG_STATUS_READ ||
			    msg->status == LICHEN_MSG_STATUS_FAILED ||
			    (msg->status == LICHEN_MSG_STATUS_DELIVERED &&
			     status != LICHEN_MSG_STATUS_READ)) {
				ret = -EALREADY;
				break;
			}
		}
		if (msg->status == LICHEN_MSG_STATUS_READ ||
		    msg->status == LICHEN_MSG_STATUS_FAILED ||
		    (status == LICHEN_MSG_STATUS_READ &&
		     msg->status != LICHEN_MSG_STATUS_DELIVERED)) {
			ret = -EALREADY;
			break;
		}

		msg->status = status;
		msg->acknowledged = true;
		msg->receipt_present = true;
		msg->receipt_timestamp = timestamp;
		msg->status_timestamp = timestamp;
		changed = true;
		ret = 0;
		LOG_INF("Applied receipt id=%" PRIu64 " status=%d ts=%u",
			msg_id, status, timestamp);
		break;
	}

out:
	k_mutex_unlock(&s_msg_mutex);
	if (changed) {
		lichen_msg_status_changed(msg_id, status, timestamp);
		lichen_msg_sent_notify();
	}
	return ret;
}

int lichen_msg_sent_status_update(uint64_t msg_id,
				  enum lichen_msg_status status,
				  uint32_t timestamp)
{
	int ret = -ENOENT;
	bool changed = false;

	if (status != LICHEN_MSG_STATUS_SENT &&
	    status != LICHEN_MSG_STATUS_FAILED) {
		return -EINVAL;
	}
	k_mutex_lock(&s_msg_mutex, K_FOREVER);
	if (!s_initialized) {
		ret = -ENODEV;
		goto out;
	}
	for (size_t i = 0U; i < s_sent_count; i++) {
		struct lichen_msg *msg = &s_sent[i];

		if (msg->id != msg_id) {
			continue;
		}
		if (msg->status == status && msg->status_timestamp == timestamp) {
			ret = 0;
			break;
		}
		if ((msg->status_timestamp != 0U &&
		     (timestamp == 0U || timestamp <= msg->status_timestamp)) ||
		    msg->status == LICHEN_MSG_STATUS_DELIVERED ||
		    msg->status == LICHEN_MSG_STATUS_READ ||
		    msg->status == LICHEN_MSG_STATUS_FAILED ||
		    (status == LICHEN_MSG_STATUS_SENT &&
		     msg->status != LICHEN_MSG_STATUS_QUEUED)) {
			ret = -EALREADY;
			break;
		}
		msg->status = status;
		msg->status_timestamp = timestamp;
		changed = true;
		ret = 0;
		break;
	}
out:
	k_mutex_unlock(&s_msg_mutex);
	if (changed) {
		lichen_msg_status_changed(msg_id, status, timestamp);
		lichen_msg_sent_notify();
	}
	return ret;
}

__weak void lichen_msg_status_changed(uint64_t msg_id,
				      enum lichen_msg_status status,
				      uint32_t timestamp)
{
	ARG_UNUSED(msg_id);
	ARG_UNUSED(status);
	ARG_UNUSED(timestamp);
}

void lichen_msg_sent_notify(void)
{
#if IS_ENABLED(CONFIG_LICHEN_COAP_MSG)
	(void)coap_resource_notify(&coap_resource_msg_sent);
#endif
}

int lichen_msg_sent_get(uint64_t msg_id, struct lichen_msg *msg)
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
	int64_t now_ms = k_uptime_get();

	k_mutex_lock(&s_inbox_observe_mutex, K_FOREVER);
	for (size_t i = 0U; i < ARRAY_SIZE(s_inbox_observers); i++) {
		struct msg_inbox_observer_slot *slot = &s_inbox_observers[i];

		if (!slot->active) {
			continue;
		}
		if (slot->remove_pending ||
		    (now_ms >= slot->last_refresh_ms &&
		     (uint64_t)(now_ms - slot->last_refresh_ms) >=
			     MSG_INBOX_OBSERVER_TTL_MS)) {
			(void)coap_remove_observer(slot->resource, &slot->observer);
			memset(slot, 0, sizeof(*slot));
		}
	}
	k_mutex_unlock(&s_inbox_observe_mutex);
	coap_resource_notify(&coap_resource_msg_inbox);
#endif
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
#define KEY_STATUS "status"
#define KEY_STATUS_LEN (sizeof(KEY_STATUS) - 1)
#define KEY_TS "ts"
#define KEY_TS_LEN (sizeof(KEY_TS) - 1)

struct strict_cbor_cursor {
	const uint8_t *buf;
	size_t len;
	size_t off;
};

static bool strict_cbor_read_tstr(struct strict_cbor_cursor *cursor,
				  const uint8_t **value, size_t *len)
{
	uint8_t initial;
	uint8_t additional;
	size_t string_len;

	if (cursor->off >= cursor->len) {
		return false;
	}
	initial = cursor->buf[cursor->off++];
	if ((initial & 0xe0U) != 0x60U) {
		return false;
	}
	additional = initial & 0x1fU;
	if (additional < 24U) {
		string_len = additional;
	} else if (additional == 24U && cursor->off < cursor->len &&
		   cursor->buf[cursor->off] >= 24U) {
		string_len = cursor->buf[cursor->off++];
	} else {
		return false;
	}
	if (string_len > cursor->len - cursor->off) {
		return false;
	}
	*value = &cursor->buf[cursor->off];
	*len = string_len;
	cursor->off += string_len;
	return true;
}

static bool strict_cbor_read_uint(struct strict_cbor_cursor *cursor,
				  uint64_t *value)
{
	uint8_t initial;
	uint8_t additional;
	uint64_t decoded = 0U;
	size_t width = 0U;

	if (cursor->off >= cursor->len) {
		return false;
	}
	initial = cursor->buf[cursor->off++];
	if ((initial & 0xe0U) != 0U) {
		return false;
	}
	additional = initial & 0x1fU;
	if (additional < 24U) {
		*value = additional;
		return true;
	}
	switch (additional) {
	case 24U:
		width = 1U;
		break;
	case 25U:
		width = 2U;
		break;
	case 26U:
		width = 4U;
		break;
	case 27U:
		width = 8U;
		break;
	default:
		return false;
	}
	if (width > cursor->len - cursor->off) {
		return false;
	}
	for (size_t i = 0U; i < width; i++) {
		decoded = (decoded << 8) | cursor->buf[cursor->off++];
	}
	if ((width == 1U && decoded < 24U) ||
	    (width == 2U && decoded <= UINT8_MAX) ||
	    (width == 4U && decoded <= UINT16_MAX) ||
	    (width == 8U && decoded <= UINT32_MAX)) {
		return false;
	}
	*value = decoded;
	return true;
}

static bool strict_cbor_read_bool(struct strict_cbor_cursor *cursor,
				  bool *value)
{
	if (cursor->off >= cursor->len) {
		return false;
	}
	if (cursor->buf[cursor->off] == 0xf4U) {
		*value = false;
	} else if (cursor->buf[cursor->off] == 0xf5U) {
		*value = true;
	} else {
		return false;
	}
	cursor->off++;
	return true;
}

static bool strict_cbor_read_map_count(struct strict_cbor_cursor *cursor,
				       size_t *count)
{
	uint8_t initial;

	if (cursor->off >= cursor->len) {
		return false;
	}
	initial = cursor->buf[cursor->off++];
	if ((initial & 0xe0U) != 0xa0U || (initial & 0x1fU) >= 24U) {
		return false;
	}
	*count = initial & 0x1fU;
	return true;
}

static int msg_ack_decode(const uint8_t *payload, size_t payload_len,
			  uint64_t *msg_id,
			  enum lichen_msg_status *status,
			  uint32_t *timestamp)
{
	struct strict_cbor_cursor cursor = {
		.buf = payload,
		.len = payload_len,
	};
	uint8_t fields = 0U;

	if (payload == NULL || msg_id == NULL || status == NULL ||
	    timestamp == NULL || payload_len == 0U || payload[0] != 0xa3U) {
		return -EBADMSG;
	}
	cursor.off = 1U;
	for (size_t i = 0U; i < 3U; i++) {
		const uint8_t *key;
		size_t key_len;

		if (!strict_cbor_read_tstr(&cursor, &key, &key_len)) {
			return -EBADMSG;
		}
		if (key_len == KEY_ID_LEN && memcmp(key, KEY_ID, KEY_ID_LEN) == 0) {
			if ((fields & BIT(0)) != 0U ||
			    !strict_cbor_read_uint(&cursor, msg_id)) {
				return -EBADMSG;
			}
			fields |= BIT(0);
		} else if (key_len == KEY_STATUS_LEN &&
			   memcmp(key, KEY_STATUS, KEY_STATUS_LEN) == 0) {
			const uint8_t *value;
			size_t value_len;

			if ((fields & BIT(1)) != 0U ||
			    !strict_cbor_read_tstr(&cursor, &value, &value_len)) {
				return -EBADMSG;
			}
			if (value_len == 9U && memcmp(value, "delivered", 9U) == 0) {
				*status = LICHEN_MSG_STATUS_DELIVERED;
			} else if (value_len == 4U && memcmp(value, "read", 4U) == 0) {
				*status = LICHEN_MSG_STATUS_READ;
			} else if (value_len == 6U && memcmp(value, "failed", 6U) == 0) {
				*status = LICHEN_MSG_STATUS_FAILED;
			} else {
				return -EBADMSG;
			}
			fields |= BIT(1);
		} else if (key_len == KEY_TS_LEN &&
			   memcmp(key, KEY_TS, KEY_TS_LEN) == 0) {
			uint64_t value;

			if ((fields & BIT(2)) != 0U ||
			    !strict_cbor_read_uint(&cursor, &value) || value > UINT32_MAX) {
				return -EBADMSG;
			}
			*timestamp = (uint32_t)value;
			fields |= BIT(2);
		} else {
			return -EBADMSG;
		}
	}
	return fields == (BIT(0) | BIT(1) | BIT(2)) && cursor.off == cursor.len
		       ? 0 : -EBADMSG;
}

/* Parse IPv6 address string to binary */
static int parse_ipv6_addr(const char *str, size_t len, uint8_t *addr)
{
	char addr_buf[LICHEN_MSG_ADDR_LEN + 1];
	struct in6_addr in6;

	if (len == 0U || len >= sizeof(addr_buf) || memchr(str, '\0', len) != NULL) {
		return -EINVAL;
	}

	memcpy(addr_buf, str, len);
	addr_buf[len] = '\0';

	if (net_addr_pton(AF_INET6, addr_buf, &in6) < 0) {
		return -EINVAL;
	}

	memcpy(addr, in6.s6_addr, 16);
	return net_ipv6_is_addr_unspecified(&in6) ? -EINVAL : 0;
}

static bool msg_body_is_valid_utf8(const uint8_t *body, size_t len)
{
	size_t i = 0U;

	while (i < len) {
		uint8_t first = body[i++];
		size_t continuation;

		if (first <= 0x7fU) {
			continue;
		}
		if (first >= 0xc2U && first <= 0xdfU) {
			continuation = 1U;
		} else if (first >= 0xe0U && first <= 0xefU) {
			if (i >= len ||
			    (first == 0xe0U && body[i] < 0xa0U) ||
			    (first == 0xedU && body[i] >= 0xa0U)) {
				return false;
			}
			continuation = 2U;
		} else if (first >= 0xf0U && first <= 0xf4U) {
			if (i >= len ||
			    (first == 0xf0U && body[i] < 0x90U) ||
			    (first == 0xf4U && body[i] >= 0x90U)) {
				return false;
			}
			continuation = 3U;
		} else {
			return false;
		}
		if (continuation > len - i) {
			return false;
		}
		for (size_t j = 0U; j < continuation; j++) {
			if ((body[i + j] & 0xc0U) != 0x80U) {
				return false;
			}
		}
		i += continuation;
	}
	return true;
}

struct msg_sent_request {
	uint8_t to_addr[16];
	char body[LICHEN_MSG_MAX_BODY_LEN];
	size_t body_len;
	uint64_t id;
	bool explicit_id;
	bool ack;
};

static int msg_sent_decode(const uint8_t *payload, size_t payload_len,
			   struct msg_sent_request *decoded)
{
	struct strict_cbor_cursor cursor = {
		.buf = payload,
		.len = payload_len,
	};
	size_t count;
	uint8_t fields = 0U;

	if (payload == NULL || decoded == NULL || payload_len == 0U ||
	    !strict_cbor_read_map_count(&cursor, &count) ||
	    count < 2U || count > 4U) {
		return -EBADMSG;
	}
	memset(decoded, 0, sizeof(*decoded));
	for (size_t i = 0U; i < count; i++) {
		const uint8_t *key;
		size_t key_len;

		if (!strict_cbor_read_tstr(&cursor, &key, &key_len)) {
			return -EBADMSG;
		}
		if (key_len == KEY_TO_LEN && memcmp(key, KEY_TO, KEY_TO_LEN) == 0) {
			const uint8_t *value;
			size_t value_len;

			if ((fields & BIT(0)) != 0U ||
			    !strict_cbor_read_tstr(&cursor, &value, &value_len) ||
			    parse_ipv6_addr((const char *)value, value_len,
					    decoded->to_addr) < 0) {
				return -EBADMSG;
			}
			fields |= BIT(0);
		} else if (key_len == KEY_BODY_LEN &&
			   memcmp(key, KEY_BODY, KEY_BODY_LEN) == 0) {
			const uint8_t *value;
			size_t value_len;

			if ((fields & BIT(1)) != 0U ||
			    !strict_cbor_read_tstr(&cursor, &value, &value_len) ||
			    value_len == 0U || value_len > sizeof(decoded->body) ||
			    !msg_body_is_valid_utf8(value, value_len)) {
				return -EBADMSG;
			}
			memcpy(decoded->body, value, value_len);
			decoded->body_len = value_len;
			fields |= BIT(1);
		} else if (key_len == KEY_ACK_LEN &&
			   memcmp(key, KEY_ACK, KEY_ACK_LEN) == 0) {
			if ((fields & BIT(2)) != 0U ||
			    !strict_cbor_read_bool(&cursor, &decoded->ack)) {
				return -EBADMSG;
			}
			fields |= BIT(2);
		} else if (key_len == KEY_ID_LEN &&
			   memcmp(key, KEY_ID, KEY_ID_LEN) == 0) {
			if ((fields & BIT(3)) != 0U ||
			    !strict_cbor_read_uint(&cursor, &decoded->id)) {
				return -EBADMSG;
			}
			decoded->explicit_id = true;
			fields |= BIT(3);
		} else {
			return -EBADMSG;
		}
	}
	if ((fields & (BIT(0) | BIT(1))) != (BIT(0) | BIT(1)) ||
	    cursor.off != cursor.len) {
		return -EBADMSG;
	}
	return 0;
}

/* --------------------------------------------------------------------------
 * POST /msg/sent - Queue outbound message
 * -------------------------------------------------------------------------- */

int lichen_msg_sent_post(struct coap_resource *resource,
			 struct coap_packet *request,
			 struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct msg_sent_request decoded;
	uint64_t msg_id = 0;
	int ret;

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len, COAP_METHOD_POST,
						     &oscore);
	if (ret != 0) {
		return ret;
	}
	/* Direct archive writes are an LCI administrative operation. A mesh peer
	 * may deliver to /msg/inbox, but must not fabricate local sent history. */
	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0);
	}
	/* Content-Format is optional for the local LCI transport, but when it is
	 * present it must describe the canonical CBOR payload.  Protected inner
	 * options have already been consumed by the OSCORE adapter. */
	if (!oscore.is_protected) {
		int content_format = coap_get_option_int(request,
						 COAP_OPTION_CONTENT_FORMAT);

		if (content_format != -ENOENT && content_format != CBOR_CONTENT_FORMAT) {
			return coap_oscore_respond_resource(resource, request, addr,
							    addr_len, &oscore,
							    COAP_RESPONSE_CODE_BAD_REQUEST,
							    0, NULL, 0);
		}
	}

	if (oscore.payload == NULL || oscore.payload_len == 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}
	if (oscore.payload_len > MSG_SENT_POST_CBOR_MAX_SIZE) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_REQUEST_TOO_LARGE,
						    0, NULL, 0);
	}
	if (msg_sent_decode(oscore.payload, oscore.payload_len, &decoded) < 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}

	ret = msg_store_sent(decoded.to_addr, decoded.body, decoded.body_len,
			     decoded.ack, decoded.explicit_id, decoded.id, &msg_id);
	if (ret == -EEXIST) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_CONFLICT,
						    0, NULL, 0);
	}
	if (ret < 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE,
						    0, NULL, 0);
	}

#ifdef CONFIG_LICHEN_COAP_SERVER_OSCORE
	if (oscore.is_protected && oscore.ctx != NULL && oscore.piv_len > 0) {
		uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
		struct coap_packet resp;
		char id_str[MSG_ID_DECIMAL_SIZE];
		int id_len;

		int r = coap_oscore_protect_response(oscore.ctx, oscore.piv,
						     oscore.piv_len, request,
						     COAP_RESPONSE_CODE_CREATED,
						     NULL, 0, &resp, buf, sizeof(buf));
		if (r < 0) {
			return coap_oscore_respond_resource(resource, request, addr,
							    addr_len, &oscore,
							    COAP_RESPONSE_CODE_INTERNAL_ERROR,
							    0, NULL, 0);
		}
		r = coap_packet_append_option(&resp, COAP_OPTION_LOCATION_PATH,
					      "msg", 3);
		if (r < 0) return r;
		r = coap_packet_append_option(&resp, COAP_OPTION_LOCATION_PATH,
					      "sent", 4);
		if (r < 0) return r;
		id_len = snprintf(id_str, sizeof(id_str), "%" PRIu64, msg_id);
		if (id_len < 0 || (size_t)id_len >= sizeof(id_str)) {
			return -EINVAL;
		}
		r = coap_packet_append_option(&resp, COAP_OPTION_LOCATION_PATH,
					      id_str, id_len);
		if (r < 0) return r;
		return coap_resource_send(resource, &resp, addr, addr_len, NULL);
	}
#endif

	{
		uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
		struct coap_packet resp;
		uint8_t token[COAP_TOKEN_MAX_LEN];
		uint8_t tkl = coap_header_get_token(request, token);
		uint8_t type = (coap_header_get_type(request) == COAP_TYPE_CON)
			       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
		char id_str[MSG_ID_DECIMAL_SIZE];
		int id_len;

		ret = coap_packet_init(&resp, buf, sizeof(buf), COAP_VERSION_1,
				       type, tkl, token,
				       COAP_RESPONSE_CODE_CREATED,
				       coap_header_get_id(request));
		if (ret < 0) {
			return ret;
		}

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

		id_len = snprintf(id_str, sizeof(id_str), "%" PRIu64, msg_id);
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
}

/* --------------------------------------------------------------------------
 * GET /msg/sent/<id> - Get sent message status
 * -------------------------------------------------------------------------- */

int lichen_msg_sent_id_get(struct coap_resource *resource,
			   struct coap_packet *request,
			   struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	uint64_t msg_id = 0;
	struct lichen_msg msg;
	uint8_t cbor_buf[MSG_CBOR_MAX_SIZE];
	size_t off = 0;
	char addr_str[LICHEN_MSG_ADDR_LEN];
	const char *status_str;
	int ret;
	int opt_count;
	struct coap_option opts[4];

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len, COAP_METHOD_GET,
						     &oscore);
	if (ret != 0) {
		return ret;
	}
	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0);
	}

	opt_count = coap_find_options(request, COAP_OPTION_URI_PATH, opts, 4);
	if (opt_count != 3) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_NOT_FOUND,
						    0, NULL, 0);
	}

	{
		char id_buf[MSG_ID_DECIMAL_SIZE];
		size_t id_len = opts[2].len;

		if (id_len >= sizeof(id_buf) || id_len == 0U ||
		    (id_len > 1U && opts[2].value[0] == '0')) {
			return coap_oscore_respond_resource(resource, request, addr,
							    addr_len, &oscore,
							    COAP_RESPONSE_CODE_NOT_FOUND,
							    0, NULL, 0);
		}
		memcpy(id_buf, opts[2].value, id_len);
		id_buf[id_len] = '\0';

		for (size_t i = 0U; i < id_len; i++) {
			if (!isdigit((unsigned char)id_buf[i])) {
				return coap_oscore_respond_resource(resource, request, addr,
								    addr_len, &oscore,
								    COAP_RESPONSE_CODE_NOT_FOUND,
								    0, NULL, 0);
			}
		}

		char *endptr;
		errno = 0;
		unsigned long long val = strtoull(id_buf, &endptr, 10);

		if (errno == ERANGE || endptr == id_buf || *endptr != '\0') {
			return coap_oscore_respond_resource(resource, request, addr,
							    addr_len, &oscore,
							    COAP_RESPONSE_CODE_NOT_FOUND,
							    0, NULL, 0);
		}
		msg_id = (uint64_t)val;
	}

	ret = lichen_msg_sent_get(msg_id, &msg);
	if (ret < 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_NOT_FOUND,
						    0, NULL, 0);
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
	case LICHEN_MSG_STATUS_READ:
		status_str = "read";
		break;
	default:
		status_str = "unknown";
		break;
	}

	if (lichen_coap_format_ipv6(msg.peer_addr, addr_str, sizeof(addr_str)) < 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_INTERNAL_ERROR,
						    0, NULL, 0);
	}

	cbor_put_map_header(cbor_buf, &off, 5);
	cbor_put_key(cbor_buf, &off, "id");
	cbor_put_uint(cbor_buf, &off, msg.id);
	cbor_put_key(cbor_buf, &off, "to");
	cbor_put_tstr(cbor_buf, &off, addr_str, strlen(addr_str));
	cbor_put_key(cbor_buf, &off, "body");
	cbor_put_tstr(cbor_buf, &off, msg.body, msg.body_len);
	cbor_put_key(cbor_buf, &off, "status");
	cbor_put_tstr(cbor_buf, &off, status_str, strlen(status_str));
	cbor_put_key(cbor_buf, &off, "timestamp");
	cbor_put_uint(cbor_buf, &off, msg.timestamp);

	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CONTENT,
					    CBOR_CONTENT_FORMAT, cbor_buf, off);
}

/* --------------------------------------------------------------------------
 * GET /msg/sent - Retrieve sent messages
 * -------------------------------------------------------------------------- */

static size_t encode_sent_cbor(uint8_t *buf, size_t buf_size)
{
	size_t off = 0;
	size_t count;
	size_t encoded = 0U;
	size_t array_pos;
	char addr_str[LICHEN_MSG_ADDR_LEN];
	const char *status_str;

	k_mutex_lock(&s_msg_mutex, K_FOREVER);
	count = s_sent_count;

	/* {"messages": [...]} */
	cbor_put_map_header(buf, &off, 1);
	cbor_put_key(buf, &off, "messages");
	array_pos = off;
	cbor_put_array_header(buf, &off, 0U);

	for (size_t i = 0; i < count && off + MSG_SENT_ENTRY_MAX_CBOR <= buf_size; i++) {
		const struct lichen_msg *msg = &s_sent[i];

		if (lichen_coap_format_ipv6(msg->peer_addr, addr_str,
				     sizeof(addr_str)) < 0) {
			continue;
		}

		switch (msg->status) {
		case LICHEN_MSG_STATUS_QUEUED:
			status_str = "queued";
			break;
		case LICHEN_MSG_STATUS_SENT:
			status_str = "sent";
			break;
		case LICHEN_MSG_STATUS_DELIVERED:
			status_str = "delivered";
			break;
		case LICHEN_MSG_STATUS_FAILED:
			status_str = "failed";
			break;
		case LICHEN_MSG_STATUS_READ:
			status_str = "read";
			break;
		default:
			status_str = "unknown";
			break;
		}

		/* Each message: {id, to, body, timestamp, status} */
		cbor_put_map_header(buf, &off, 5);
		cbor_put_key(buf, &off, "id");
		cbor_put_uint(buf, &off, msg->id);
		cbor_put_key(buf, &off, "to");
		cbor_put_tstr(buf, &off, addr_str, strlen(addr_str));
		cbor_put_key(buf, &off, "body");
		cbor_put_tstr(buf, &off, msg->body, msg->body_len);
		cbor_put_key(buf, &off, "timestamp");
		cbor_put_uint(buf, &off, msg->timestamp);
		cbor_put_key(buf, &off, "status");
		cbor_put_tstr(buf, &off, status_str, strlen(status_str));
		encoded++;
	}
	buf[array_pos] = 0x80U | (uint8_t)encoded;

	k_mutex_unlock(&s_msg_mutex);
	return off;
}

static int send_sent_observe_initial(struct coap_resource *resource,
				     struct coap_packet *request,
				     struct sockaddr *addr, socklen_t addr_len,
				     const uint8_t *payload, size_t payload_len)
{
	uint8_t packet_buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t token_len = coap_header_get_token(request, token);
	struct coap_packet response;
	uint8_t type = coap_header_get_type(request) == COAP_TYPE_CON
			       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int ret;

	ret = coap_packet_init(&response, packet_buf, sizeof(packet_buf),
			       COAP_VERSION_1, type, token_len, token,
			       COAP_RESPONSE_CODE_CONTENT,
			       coap_header_get_id(request));
	if (ret == 0) {
		ret = coap_append_option_int(&response, COAP_OPTION_OBSERVE,
					     (uint32_t)resource->age);
	}
	if (ret == 0) {
		ret = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT,
					     CBOR_CONTENT_FORMAT);
	}
	if (ret == 0) {
		ret = coap_packet_append_payload_marker(&response);
	}
	if (ret == 0) {
		ret = coap_packet_append_payload(&response, payload,
						 (uint16_t)payload_len);
	}
	return ret < 0 ? ret : coap_resource_send(resource, &response, addr,
						     addr_len, NULL);
}

int lichen_msg_sent_get_handler(struct coap_resource *resource,
				struct coap_packet *request,
				struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct coap_option observe_options[2];
	uint8_t cbor_buf[MSG_CBOR_MAX_SIZE];
	size_t len;
	int observe_count;
	int ret;

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len, COAP_METHOD_GET,
						     &oscore);
	if (ret != 0) {
		return ret;
	}
	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0U);
	}
	observe_count = coap_find_options(request, COAP_OPTION_OBSERVE,
					  observe_options,
					  ARRAY_SIZE(observe_options));
	if (observe_count < 0 || observe_count > 1 ||
	    (observe_count == 1 && oscore.is_protected)) {
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0U);
	}
	if (observe_count == 1) {
		ret = coap_resource_parse_observe(resource, request, addr);
		if (ret < 0) {
			return coap_oscore_respond_resource(
				resource, request, addr, addr_len, &oscore,
				ret == -ENOMEM ? COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE
					       : COAP_RESPONSE_CODE_BAD_REQUEST,
				0, NULL, 0U);
		}
	}
	len = encode_sent_cbor(cbor_buf, sizeof(cbor_buf));
	if (len == 0) {
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    &oscore,
						    COAP_RESPONSE_CODE_INTERNAL_ERROR,
						    0, NULL, 0U);
	}
	if (observe_count == 1 &&
	    coap_get_option_int(request, COAP_OPTION_OBSERVE) == 0) {
		return send_sent_observe_initial(resource, request, addr, addr_len,
						 cbor_buf, len);
	}

	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CONTENT,
					    CBOR_CONTENT_FORMAT, cbor_buf, len);
}

void lichen_msg_sent_notify_cb(struct coap_resource *resource,
			      struct coap_observer *observer)
{
	uint8_t packet_buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	uint8_t cbor_buf[MSG_CBOR_MAX_SIZE];
	struct coap_packet packet;
	size_t len = encode_sent_cbor(cbor_buf, sizeof(cbor_buf));
	int ret;

	if (len == 0U) {
		return;
	}
	ret = coap_packet_init(&packet, packet_buf, sizeof(packet_buf),
			       COAP_VERSION_1, COAP_TYPE_NON_CON,
			       observer->tkl, observer->token,
			       COAP_RESPONSE_CODE_CONTENT, coap_next_id());
	if (ret == 0) {
		ret = coap_append_option_int(&packet, COAP_OPTION_OBSERVE,
					     (uint32_t)resource->age);
	}
	if (ret == 0) {
		ret = coap_append_option_int(&packet, COAP_OPTION_CONTENT_FORMAT,
					     CBOR_CONTENT_FORMAT);
	}
	if (ret == 0) {
		ret = coap_packet_append_payload_marker(&packet);
	}
	if (ret == 0) {
		ret = coap_packet_append_payload(&packet, cbor_buf, (uint16_t)len);
	}
	if (ret == 0) {
		(void)coap_resource_send(resource, &packet, &observer->addr,
					 sizeof(observer->addr), NULL);
	}
}

/* --------------------------------------------------------------------------
 * GET /msg/inbox - Retrieve inbound messages (Observable)
 * -------------------------------------------------------------------------- */

static int encode_inbox_entry(uint8_t *buf, size_t buf_size,
			      const struct lichen_msg *msg)
{
	char addr_str[LICHEN_MSG_ADDR_LEN];
	const char *status = msg->status == LICHEN_MSG_STATUS_READ
				     ? "read" : "unread";
	size_t off = 0U;

	if (buf_size < MSG_INBOX_ENTRY_MAX_CBOR ||
	    msg->body_len > LICHEN_MSG_MAX_BODY_LEN ||
	    lichen_coap_format_ipv6(msg->peer_addr, addr_str,
				     sizeof(addr_str)) < 0) {
		return -ENOBUFS;
	}
	/* Deterministic canonical key order: encoded-key length, then bytes. */
	cbor_put_map_header(buf, &off, 5U);
	cbor_put_key(buf, &off, "id");
	cbor_put_uint(buf, &off, msg->id);
	cbor_put_key(buf, &off, "body");
	cbor_put_tstr(buf, &off, msg->body, msg->body_len);
	cbor_put_key(buf, &off, "from");
	cbor_put_tstr(buf, &off, addr_str, strlen(addr_str));
	cbor_put_key(buf, &off, "status");
	cbor_put_tstr(buf, &off, status, strlen(status));
	cbor_put_key(buf, &off, "received");
	cbor_put_uint(buf, &off, msg->timestamp);
	return (int)off;
}

static int encode_inbox_page(uint8_t *buf, size_t buf_size,
			     size_t offset, size_t limit)
{
	uint8_t entries[MSG_CBOR_MAX_SIZE];
	uint8_t entry[MSG_INBOX_ENTRY_MAX_CBOR];
	size_t count;
	size_t unread = 0U;
	size_t entries_len = 0U;
	size_t selected = 0U;
	size_t next;
	size_t off = 0U;

	if (buf == NULL || buf_size < 48U || limit == 0U) {
		return -EINVAL;
	}
	k_mutex_lock(&s_msg_mutex, K_FOREVER);
	count = s_inbox_count;
	for (size_t i = 0U; i < count; i++) {
		unread += s_inbox[i].status == LICHEN_MSG_STATUS_READ ? 0U : 1U;
	}
	if (offset > count) {
		offset = count;
	}
	for (size_t i = offset; i < count && selected < limit; i++) {
		int entry_len = encode_inbox_entry(entry, sizeof(entry), &s_inbox[i]);

		if (entry_len < 0) {
			k_mutex_unlock(&s_msg_mutex);
			return entry_len;
		}
		if (entries_len + (size_t)entry_len > buf_size - 48U) {
			break;
		}
		memcpy(&entries[entries_len], entry, (size_t)entry_len);
		entries_len += (size_t)entry_len;
		selected++;
	}
	k_mutex_unlock(&s_msg_mutex);
	if (offset < count && selected == 0U) {
		return -ENOBUFS;
	}
	next = offset + selected < count ? offset + selected : 0U;

	/* {"next": uint, "unread": uint, "messages": [...]} */
	cbor_put_map_header(buf, &off, 3U);
	cbor_put_key(buf, &off, "next");
	cbor_put_uint(buf, &off, next);
	cbor_put_key(buf, &off, "unread");
	cbor_put_uint(buf, &off, unread);
	cbor_put_key(buf, &off, "messages");
	cbor_put_array_header(buf, &off, selected);
	memcpy(&buf[off], entries, entries_len);
	off += entries_len;
	return (int)off;
}

static uint64_t inbox_generation(void)
{
	uint64_t generation;

	k_mutex_lock(&s_msg_mutex, K_FOREVER);
	generation = s_inbox_generation;
	k_mutex_unlock(&s_msg_mutex);
	return generation;
}

static int parse_inbox_pagination(const struct coap_packet *request,
				  size_t *offset, size_t *limit)
{
	struct coap_option options[3];
	unsigned int fields = 0U;
	int count;

	*offset = 0U;
	*limit = LICHEN_MSG_INBOX_MAX;
	count = coap_find_options(request, COAP_OPTION_URI_QUERY, options,
				  ARRAY_SIZE(options));
	if (count < 0 || count > 2) {
		return -EBADMSG;
	}
	for (int i = 0; i < count; i++) {
		const uint8_t *value = options[i].value;
		size_t len = options[i].len;
		size_t parsed;
		size_t prefix;

		if (len > 7U && memcmp(value, "offset=", 7U) == 0) {
			prefix = 7U;
			if ((fields & BIT(0)) != 0U) {
				return -EBADMSG;
			}
			fields |= BIT(0);
		} else if (len > 6U && memcmp(value, "limit=", 6U) == 0) {
			prefix = 6U;
			if ((fields & BIT(1)) != 0U) {
				return -EBADMSG;
			}
			fields |= BIT(1);
		} else {
			return -EBADMSG;
		}
		if (len - prefix > 1U || value[prefix] < '0' ||
		    value[prefix] > '8') {
			return -EBADMSG;
		}
		parsed = (size_t)(value[prefix] - '0');
		if (prefix == 7U) {
			*offset = parsed;
		} else if (parsed == 0U) {
			return -EBADMSG;
		} else {
			*limit = parsed;
		}
	}
	return 0;
}

static bool inbox_observer_addr_equal(const struct sockaddr *a,
				      const struct sockaddr *b)
{
	if (a == NULL || b == NULL || a->sa_family != b->sa_family) {
		return false;
	}
	if (a->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;

		return a6->sin6_port == b6->sin6_port &&
		       a6->sin6_scope_id == b6->sin6_scope_id &&
		       net_ipv6_addr_cmp(&a6->sin6_addr, &b6->sin6_addr);
	}
	return false;
}

static struct msg_inbox_observer_slot *find_inbox_observer_locked(
	const struct sockaddr *addr, const uint8_t *token, uint8_t token_len)
{
	for (size_t i = 0U; i < ARRAY_SIZE(s_inbox_observers); i++) {
		struct msg_inbox_observer_slot *slot = &s_inbox_observers[i];

		if (slot->active && slot->observer.tkl == token_len &&
		    memcmp(slot->observer.token, token, token_len) == 0 &&
		    inbox_observer_addr_equal(&slot->observer.addr, addr)) {
			return slot;
		}
	}
	return NULL;
}

__weak int lichen_msg_inbox_observe_send(
	struct coap_resource *resource, const struct sockaddr *addr,
	socklen_t addr_len, const uint8_t *token, uint8_t token_len,
	uint32_t sequence, const uint8_t *payload, size_t payload_len,
	bool initial, uint8_t request_type, uint16_t request_id)
{
	uint8_t buf[CONFIG_COAP_SERVER_MESSAGE_SIZE];
	struct coap_packet response;
	uint8_t type = initial && request_type == COAP_TYPE_CON
			       ? COAP_TYPE_ACK : COAP_TYPE_NON_CON;
	int ret;

	ret = coap_packet_init(&response, buf, sizeof(buf), COAP_VERSION_1, type,
			       token_len, token, COAP_RESPONSE_CODE_CONTENT,
			       initial ? request_id : coap_next_id());
	if (ret < 0) {
		return ret;
	}
	ret = coap_append_option_int(&response, COAP_OPTION_OBSERVE, sequence);
	if (ret < 0) {
		return ret;
	}
	ret = coap_append_option_int(&response, COAP_OPTION_CONTENT_FORMAT,
				     CBOR_CONTENT_FORMAT);
	if (ret < 0) {
		return ret;
	}
	ret = coap_packet_append_payload_marker(&response);
	if (ret < 0) {
		return ret;
	}
	ret = coap_packet_append_payload(&response, payload,
					 (uint16_t)payload_len);
	if (ret < 0) {
		return ret;
	}
	return coap_resource_send(resource, &response, addr, addr_len, NULL);
}

static int inbox_observe_request(struct coap_resource *resource,
				 struct coap_packet *request,
				 struct sockaddr *addr, socklen_t addr_len,
				 const struct coap_oscore_unprotect_result *oscore,
				 const uint8_t *payload, size_t payload_len,
				 size_t offset, size_t limit, int observe)
{
	uint8_t token[COAP_TOKEN_MAX_LEN];
	uint8_t token_len = coap_header_get_token(request, token);
	struct msg_inbox_observer_slot *slot = NULL;
	int ret;

	if (oscore->is_protected || addr == NULL || token_len == 0U ||
	    addr_len > sizeof(struct sockaddr_storage) ||
	    (observe != 0 && observe != 1)) {
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0U);
	}
	k_mutex_lock(&s_inbox_observe_mutex, K_FOREVER);
	for (size_t i = 0U; i < ARRAY_SIZE(s_inbox_observers); i++) {
		struct msg_inbox_observer_slot *expired = &s_inbox_observers[i];
		int64_t now_ms = k_uptime_get();

		if (expired->active && now_ms >= expired->last_refresh_ms &&
		    (uint64_t)(now_ms - expired->last_refresh_ms) >=
			    MSG_INBOX_OBSERVER_TTL_MS) {
			(void)coap_remove_observer(expired->resource,
						   &expired->observer);
			memset(expired, 0, sizeof(*expired));
		}
	}
	slot = find_inbox_observer_locked(addr, token, token_len);
	if (observe == 1) {
		if (slot != NULL) {
			(void)coap_remove_observer(resource, &slot->observer);
			memset(slot, 0, sizeof(*slot));
		}
		k_mutex_unlock(&s_inbox_observe_mutex);
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    oscore,
						    COAP_RESPONSE_CODE_CONTENT,
						    CBOR_CONTENT_FORMAT,
						    payload, payload_len);
	}
	if (slot == NULL) {
		for (size_t i = 0U; i < ARRAY_SIZE(s_inbox_observers); i++) {
			if (!s_inbox_observers[i].active) {
				slot = &s_inbox_observers[i];
				break;
			}
		}
		if (slot == NULL) {
			k_mutex_unlock(&s_inbox_observe_mutex);
			return coap_oscore_respond_resource(
				resource, request, addr, addr_len, oscore,
				COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE, 0, NULL, 0U);
		}
		memset(slot, 0, sizeof(*slot));
		coap_observer_init(&slot->observer, request, addr);
		slot->resource = resource;
		slot->addr_len = addr_len;
		slot->active = true;
		(void)coap_register_observer(resource, &slot->observer);
	}
	slot->last_refresh_ms = k_uptime_get();
	slot->generation = inbox_generation();
	slot->offset = offset;
	slot->limit = limit;
	slot->pending = false;
	slot->retries = 0U;
	ret = lichen_msg_inbox_observe_send(
		resource, &slot->observer.addr, slot->addr_len,
		slot->observer.token, slot->observer.tkl, (uint32_t)resource->age,
		payload, payload_len, true, coap_header_get_type(request),
		coap_header_get_id(request));
	if (ret < 0) {
		(void)coap_remove_observer(resource, &slot->observer);
		memset(slot, 0, sizeof(*slot));
	}
	k_mutex_unlock(&s_inbox_observe_mutex);
	return ret;
}

/* Renamed handler function to avoid conflict with lichen_msg_inbox_get */
int lichen_msg_inbox_get_handler(struct coap_resource *resource,
				 struct coap_packet *request,
				 struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct coap_option observe_options[2];
	uint8_t cbor_buf[MSG_CBOR_MAX_SIZE];
	size_t offset;
	size_t limit;
	int observe;
	int len;
	int ret;

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len, COAP_METHOD_GET,
						     &oscore);
	if (ret != 0) {
		return ret;
	}
	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0U);
	}
	ret = coap_find_options(request, COAP_OPTION_OBSERVE, observe_options,
				ARRAY_SIZE(observe_options));
	if (ret < 0 || ret > 1 || parse_inbox_pagination(request, &offset, &limit) < 0) {
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0U);
	}
	len = encode_inbox_page(cbor_buf, sizeof(cbor_buf), offset, limit);
	if (len < 0) {
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    &oscore,
						    COAP_RESPONSE_CODE_INTERNAL_ERROR,
						    0, NULL, 0U);
	}
	observe = coap_get_option_int(request, COAP_OPTION_OBSERVE);
	if (observe >= 0) {
		return inbox_observe_request(resource, request, addr, addr_len,
					     &oscore, cbor_buf, (size_t)len,
					     offset, limit, observe);
	}
	if (observe != -ENOENT) {
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0U);
	}
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CONTENT,
					    CBOR_CONTENT_FORMAT, cbor_buf, (size_t)len);
}

int lichen_msg_inbox_id_get(struct coap_resource *resource,
			    struct coap_packet *request,
			    struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct coap_option paths[4];
	struct lichen_msg msg;
	uint8_t cbor_buf[MSG_INBOX_ENTRY_MAX_CBOR];
	uint64_t id = 0U;
	bool changed = false;
	int count;
	int len;
	int ret;

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len, COAP_METHOD_GET,
						     &oscore);
	if (ret != 0) {
		return ret;
	}
	if (!lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0U);
	}
	count = coap_find_options(request, COAP_OPTION_URI_PATH, paths,
				  ARRAY_SIZE(paths));
	if (count != 3 || paths[2].len == 0U || paths[2].len > 20U ||
	    (paths[2].len > 1U && paths[2].value[0] == '0')) {
		goto not_found;
	}
	for (size_t i = 0U; i < paths[2].len; i++) {
		uint8_t digit = paths[2].value[i];

		if (digit < '0' || digit > '9' ||
		    id > (UINT64_MAX - (uint64_t)(digit - '0')) / 10U) {
			goto not_found;
		}
		id = id * 10U + (uint64_t)(digit - '0');
	}
	k_mutex_lock(&s_msg_mutex, K_FOREVER);
	ret = -ENOENT;
	for (size_t i = 0U; i < s_inbox_count; i++) {
		if (s_inbox[i].id == id) {
			if (s_inbox[i].status != LICHEN_MSG_STATUS_READ) {
				s_inbox[i].status = LICHEN_MSG_STATUS_READ;
				s_inbox_generation++;
				changed = true;
			}
			msg = s_inbox[i];
			ret = 0;
			break;
		}
	}
	k_mutex_unlock(&s_msg_mutex);
	if (ret < 0) {
		goto not_found;
	}
	len = encode_inbox_entry(cbor_buf, sizeof(cbor_buf), &msg);
	if (len < 0) {
		return coap_oscore_respond_resource(resource, request, addr, addr_len,
						    &oscore,
						    COAP_RESPONSE_CODE_INTERNAL_ERROR,
						    0, NULL, 0U);
	}
	ret = coap_oscore_respond_resource(resource, request, addr, addr_len,
						    &oscore,
						    COAP_RESPONSE_CODE_CONTENT,
						    CBOR_CONTENT_FORMAT,
						    cbor_buf, (size_t)len);
	if (changed) {
		lichen_msg_inbox_notify();
	}
	return ret;

not_found:
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_NOT_FOUND,
					    0, NULL, 0U);
}

void lichen_msg_inbox_notify_cb(struct coap_resource *resource,
				struct coap_observer *observer)
{
	uint8_t cbor_buf[MSG_CBOR_MAX_SIZE];
	struct msg_inbox_observer_slot *slot =
		CONTAINER_OF(observer, struct msg_inbox_observer_slot, observer);
	uint64_t generation;
	int cbor_len;
	int ret;

	k_mutex_lock(&s_inbox_observe_mutex, K_FOREVER);
	if (!slot->active || slot->remove_pending) {
		k_mutex_unlock(&s_inbox_observe_mutex);
		return;
	}
	generation = inbox_generation();
	if (!slot->pending && slot->generation == generation) {
		k_mutex_unlock(&s_inbox_observe_mutex);
		return;
	}
	cbor_len = encode_inbox_page(cbor_buf, sizeof(cbor_buf),
				     slot->offset, slot->limit);
	if (cbor_len < 0) {
		slot->remove_pending = true;
		k_mutex_unlock(&s_inbox_observe_mutex);
		return;
	}
	ret = lichen_msg_inbox_observe_send(
		resource, &slot->observer.addr, slot->addr_len,
		slot->observer.token, slot->observer.tkl, (uint32_t)resource->age,
		cbor_buf, (size_t)cbor_len, false, COAP_TYPE_NON_CON, 0U);
	if (ret == 0) {
		slot->generation = generation;
		slot->pending = false;
		slot->retries = 0U;
	} else if ((ret == -EAGAIN || ret == -ENOMEM || ret == -ENOBUFS ||
		    ret == -ENETDOWN) &&
		   ++slot->retries < MSG_INBOX_OBSERVE_MAX_RETRIES) {
		slot->pending = true;
	} else {
		slot->remove_pending = true;
	}
	k_mutex_unlock(&s_inbox_observe_mutex);
}

/* --------------------------------------------------------------------------
 * POST /msg/ack - Acknowledge message receipt
 * -------------------------------------------------------------------------- */

int lichen_msg_ack_post(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	uint64_t msg_id = 0U;
	uint32_t timestamp = 0U;
	enum lichen_msg_status status = LICHEN_MSG_STATUS_QUEUED;
	uint8_t peer_addr[16];
	const uint8_t *authenticated_peer = NULL;
	bool local_admin;
	int ret;

	ret = coap_oscore_unprotect_resource_request(resource, request, addr,
						     addr_len, COAP_METHOD_POST,
						     &oscore);
	if (ret != 0) {
		return ret;
	}
	local_admin = lichen_coap_is_local_admin(addr, addr_len);
	if (!oscore.is_protected && !local_admin) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0);
	}

	if (oscore.payload == NULL || oscore.payload_len == 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}
	if (oscore.payload_len > MSG_ACK_CBOR_MAX_SIZE) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_REQUEST_TOO_LARGE,
						    0, NULL, 0);
	}
	if (msg_ack_decode(oscore.payload, oscore.payload_len, &msg_id,
			   &status, &timestamp) < 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}

	if (!local_admin) {
		if (addr == NULL || addr_len < sizeof(struct sockaddr_in6) ||
		    addr->sa_family != AF_INET6) {
			return coap_oscore_respond_resource(resource, request, addr,
							    addr_len, &oscore,
							    COAP_RESPONSE_CODE_FORBIDDEN,
							    0, NULL, 0);
		}
		memcpy(peer_addr,
		       ((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr,
		       sizeof(peer_addr));
		authenticated_peer = peer_addr;
	}

	ret = lichen_msg_receipt_apply(msg_id, status, timestamp,
				       authenticated_peer, local_admin);
	if (ret == -ENOENT) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_NOT_FOUND,
						    0, NULL, 0);
	}
	if (ret == -EACCES) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_FORBIDDEN,
						    0, NULL, 0);
	}
	if (ret == -EALREADY) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_CONFLICT,
						    0, NULL, 0);
	}
	if (ret < 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_INTERNAL_ERROR,
						    0, NULL, 0);
	}

	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CHANGED,
					    0, NULL, 0);
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
	.get = lichen_msg_sent_get_handler,
	.post = lichen_msg_sent_post,
	.notify = lichen_msg_sent_notify_cb,
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

static const char * const msg_inbox_id_path[] = { "msg", "inbox", "*", NULL };
COAP_RESOURCE_DEFINE(msg_inbox_id, lichen_coap_server, {
	.get = lichen_msg_inbox_id_get,
	.path = msg_inbox_id_path,
});

static const char * const msg_ack_path[] = { "msg", "ack", NULL };
COAP_RESOURCE_DEFINE(msg_ack, lichen_coap_server, {
	.post = lichen_msg_ack_post,
	.path = msg_ack_path,
});

#endif /* CONFIG_LICHEN_COAP_MSG */
