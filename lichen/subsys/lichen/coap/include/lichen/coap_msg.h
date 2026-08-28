/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_msg.h
 * @brief CoAP messaging resources for LCI
 *
 * Implements /msg resources per LCI spec section 17.5.7:
 * - GET /msg/sent - retrieve sent messages
 * - POST /msg/sent - queue outbound message
 * - GET /msg/sent/<id> - get status of sent message
 * - GET /msg/inbox - retrieve inbound messages (observable)
 * - POST /msg/ack - acknowledge message receipt
 *
 * CBOR format for messages uses string keys per LCI spec.
 */

#ifndef LICHEN_COAP_MSG_H_
#define LICHEN_COAP_MSG_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <zephyr/net/coap.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum message body length */
#define LICHEN_MSG_MAX_BODY_LEN 200

/** Maximum number of messages in inbox queue */
#define LICHEN_MSG_INBOX_MAX 8

/** Maximum number of messages in sent queue */
#define LICHEN_MSG_SENT_MAX 8

/** Maximum IPv6 address string length */
#define LICHEN_MSG_ADDR_LEN 46

/**
 * @brief Message status codes
 */
enum lichen_msg_status {
	LICHEN_MSG_STATUS_QUEUED = 0,    /**< Message queued for sending */
	LICHEN_MSG_STATUS_SENT = 1,      /**< Message handed to transport */
	LICHEN_MSG_STATUS_SENDING = LICHEN_MSG_STATUS_SENT, /**< Legacy alias */
	LICHEN_MSG_STATUS_DELIVERED = 2, /**< Message delivered (ACK received) */
	LICHEN_MSG_STATUS_FAILED = 3,    /**< Delivery failed */
	LICHEN_MSG_STATUS_READ = 4,      /**< Message read by recipient */
};

/**
 * @brief Message structure for inbox/sent queues
 */
struct lichen_msg {
	uint64_t id;                      /**< Unique message ID */
	uint8_t peer_addr[16];            /**< Peer IPv6 address (from/to) */
	char body[LICHEN_MSG_MAX_BODY_LEN]; /**< Message body (UTF-8) */
	size_t body_len;                  /**< Body length */
	uint32_t timestamp;               /**< Unix timestamp */
	enum lichen_msg_status status;    /**< Message status */
	bool ack_requested;               /**< ACK requested for sent messages */
	bool acknowledged;                /**< ACK received/sent */
	bool receipt_present;             /**< A delivery receipt was applied */
	uint32_t receipt_timestamp;       /**< Receipt Unix timestamp */
	uint32_t status_timestamp;        /**< Latest local/receipt transition time */
};

/**
 * @brief Initialize the messaging subsystem
 *
 * Initializes message queues. Call once at startup.
 *
 * @return 0 on success, negative error code on failure
 */
int lichen_msg_init(void);

/**
 * @brief Queue an outbound message
 *
 * @param[in]  to_addr   Destination IPv6 address (16 bytes)
 * @param[in]  body      Message body (UTF-8)
 * @param[in]  body_len  Body length
 * @param[in]  ack       Request acknowledgment
 * @param[out] msg_id    Assigned message ID (optional, may be NULL)
 * @return 0 on success, negative error code on failure
 */
int lichen_msg_send(const uint8_t *_Nonnull to_addr,
		    const char *_Nonnull body, size_t body_len,
		    bool ack, uint64_t *_Nullable msg_id);

/**
 * @brief Add a received message to inbox
 *
 * Called by the network layer when a message is received.
 *
 * @param[in] from_addr  Source IPv6 address (16 bytes)
 * @param[in] body       Message body (UTF-8)
 * @param[in] body_len   Body length
 * @param[in] timestamp  Unix timestamp
 * @return 0 on success, negative error code on failure
 */
int lichen_msg_receive(const uint8_t *_Nonnull from_addr,
		       const char *_Nonnull body, size_t body_len,
		       uint32_t timestamp);

/**
 * @brief Acknowledge an inbox message
 *
 * @param[in] msg_id Message ID to acknowledge
 * @return 0 on success, -ENOENT if message not found
 */
int lichen_msg_ack(uint64_t msg_id);

/**
 * @brief Atomically apply a delivery receipt to a sent message
 *
 * Only messages that requested an acknowledgment accept receipts. Remote
 * receipts are bound to the destination identity by comparing the IPv6 IID;
 * a trusted local administrator may override this ownership check. Exact
 * duplicate receipts are idempotent. Stale, conflicting, or terminal-state
 * regressions return -EALREADY without mutating the message.
 *
 * @param[in] msg_id        Sent message identifier
 * @param[in] status        DELIVERED, READ, or FAILED
 * @param[in] timestamp     Receipt Unix timestamp
 * @param[in] peer_addr     Authenticated peer IPv6 address (16 bytes), or NULL
 * @param[in] local_admin   Whether the request came from the local admin path
 * @return 0 on success/idempotent duplicate, -ENOENT if unknown, -EACCES on
 *         authorization failure, -EALREADY on replay/conflict, or -ENODEV
 */
int lichen_msg_receipt_apply(uint64_t msg_id,
			     enum lichen_msg_status status,
			     uint32_t timestamp,
			     const uint8_t *_Nullable peer_addr,
			     bool local_admin);

/**
 * @brief Atomically propagate a local transport status transition
 *
 * Permits QUEUED -> SENT and QUEUED/SENT -> FAILED. Exact duplicates are
 * idempotent; stale, conflicting, or terminal regressions return -EALREADY.
 * State is intentionally RAM-resident and resets on reboot; durable delivery
 * queues must replay their authoritative state through this API after boot.
 */
int lichen_msg_sent_status_update(uint64_t msg_id,
				  enum lichen_msg_status status,
				  uint32_t timestamp);

/** Notify registered /msg/sent observers after a committed status change. */
void lichen_msg_sent_notify(void);

/** Optional platform hook invoked after a committed sent-status change. */
void lichen_msg_status_changed(uint64_t msg_id,
			       enum lichen_msg_status status,
			       uint32_t timestamp);

/**
 * @brief Get sent message by ID
 *
 * @param[in]  msg_id Message ID
 * @param[out] msg    Message structure (copied)
 * @return 0 on success, -ENOENT if not found
 */
int lichen_msg_sent_get(uint64_t msg_id, struct lichen_msg *_Nonnull msg);

/**
 * @brief Get inbox message count
 *
 * @return Number of messages in inbox
 */
size_t lichen_msg_inbox_count(void);

/**
 * @brief Get inbox message by index
 *
 * @param[in]  index Message index (0-based)
 * @param[out] msg   Message structure (copied)
 * @return 0 on success, -ENOENT if index out of range
 */
int lichen_msg_inbox_get(size_t index, struct lichen_msg *_Nonnull msg);

/**
 * @brief Notify observers of inbox changes
 *
 * Call this after adding messages to inbox to trigger Observe notifications.
 */
void lichen_msg_inbox_notify(void);

/**
 * @brief CoAP handler for POST /msg/sent
 *
 * Queue an outbound message. CBOR payload format:
 * {
 *   "id": <optional uint64 idempotency key>,
 *   "to": "<IPv6 address string>",
 *   "body": "<message text>",
 *   "ack": true/false
 * }
 *
 * Direct writes to the sent archive require local administrative authority.
 * An exact repeated explicit ID is idempotent; conflicting reuse returns
 * 4.09 Conflict.
 *
 * Response: 2.01 Created with Location-Path: /msg/sent/<id>
 */
int lichen_msg_sent_post(struct coap_resource *_Nonnull resource,
			 struct coap_packet *_Nonnull request,
			 struct sockaddr *_Nonnull addr, socklen_t addr_len);

/**
 * @brief CoAP handler for GET /msg/sent/<id>
 *
 * Get status of a sent message. Sent-record details require local
 * administrative authority and use canonical decimal uint64 path IDs.
 */
int lichen_msg_sent_id_get(struct coap_resource *_Nonnull resource,
			   struct coap_packet *_Nonnull request,
			   struct sockaddr *_Nonnull addr, socklen_t addr_len);

/**
 * @brief CoAP handler for GET /msg/sent
 *
 * Retrieve sent messages. CBOR response format:
 * {
 *   "messages": [
 *     {
 *       "id": <uint>,
 *       "to": "<IPv6 address string>",
 *       "body": "<message text>",
 *       "timestamp": <uint>,
 *       "status": "queued"|"sending"|"delivered"|"failed"
 *     },
 *     ...
 *   ]
 * }
 */
int lichen_msg_sent_get_handler(struct coap_resource *_Nonnull resource,
				struct coap_packet *_Nonnull request,
				struct sockaddr *_Nonnull addr, socklen_t addr_len);

/**
 * @brief CoAP handler for GET /msg/inbox
 *
 * Retrieve the private local inbox. Supports RFC 7641 Observe and bounded
 * pagination with canonical `offset=0..8` and `limit=1..8` URI queries.
 * CBOR response format:
 * {
 *   "next": <next offset, or 0 at end>,
 *   "unread": <count>,
 *   "messages": [
 *     {
 *       "id": <uint>,
 *       "from": "<IPv6 address string>",
 *       "body": "<message text>",
 *       "status": "unread"|"read",
 *       "received": <Unix timestamp>
 *     },
 *     ...
 *   ]
 * }
 */
int lichen_msg_inbox_get_handler(struct coap_resource *_Nonnull resource,
				 struct coap_packet *_Nonnull request,
				 struct sockaddr *_Nonnull addr, socklen_t addr_len);

/**
 * @brief CoAP handler for GET /msg/inbox/<id>
 *
 * Returns one private inbox record and atomically marks it read. Canonical
 * decimal uint64 IDs are required; unknown or non-canonical paths return 4.04.
 */
int lichen_msg_inbox_id_get(struct coap_resource *_Nonnull resource,
			    struct coap_packet *_Nonnull request,
			    struct sockaddr *_Nonnull addr, socklen_t addr_len);

/**
 * @brief CoAP Observe notify callback for /msg/inbox
 */
void lichen_msg_inbox_notify_cb(struct coap_resource *_Nonnull resource,
				struct coap_observer *_Nonnull observer);

/** CoAP Observe notify callback for /msg/sent status changes. */
void lichen_msg_sent_notify_cb(struct coap_resource *_Nonnull resource,
			      struct coap_observer *_Nonnull observer);

/**
 * @brief CoAP handler for POST /msg/ack
 *
 * Acknowledge receipt of a message. CBOR payload format:
 * {
 *   "id": <uint64 message id>,
 *   "status": "delivered" / "read" / "failed",
 *   "ts": <uint32 Unix timestamp>
 * }
 *
 * Response: 2.04 Changed
 */
int lichen_msg_ack_post(struct coap_resource *_Nonnull resource,
			struct coap_packet *_Nonnull request,
			struct sockaddr *_Nonnull addr, socklen_t addr_len);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_MSG_H_ */
