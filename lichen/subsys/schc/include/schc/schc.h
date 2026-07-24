/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc/schc.h
 * @brief Generic SCHC profile dispatch API.
 *
 * This module provides reusable SCHC compression/decompression boundaries for
 * Zephyr applications. Protocol profiles install static rule tables; profile
 * callbacks implement the rule-specific field matching and residue handling.
 *
 * The API is packet-oriented: callers pass a complete packet and receive one
 * complete SCHC datagram. RFC 8724 fragmentation is represented as a separate
 * API surface so profiles can share one fragmentation engine as it matures.
 */

#ifndef SCHC_SCHC_H_
#define SCHC_SCHC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef SCHC_WARN_UNUSED_RESULT
#if defined(__GNUC__) || defined(__clang__)
#define SCHC_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define SCHC_WARN_UNUSED_RESULT
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Error codes shared by generic and profile-specific SCHC code. */
enum schc_error {
	SCHC_OK = 0,
	SCHC_ERR_NO_MATCHING_RULE = -1,
	SCHC_ERR_BUFFER_TOO_SMALL = -2,
	SCHC_ERR_UNKNOWN_RULE_ID = -3,
	SCHC_ERR_TOO_SHORT = -4,
	SCHC_ERR_NOT_SUPPORTED = -5,
	SCHC_ERR_INVALID_ARGUMENT = -6,
	SCHC_ERR_DONE = -7,
	SCHC_ERR_MIC_MISMATCH = -8,
	SCHC_ERR_FRAGMENT_LENGTH = -9,
	SCHC_ERR_FRAGMENT_PADDING = -10,
	SCHC_ERR_FRAGMENT_FCN = -11,
	SCHC_ERR_ACK_MALFORMED = -12,
	SCHC_ERR_ACK_NONCANONICAL = -13,
	SCHC_ERR_ACK_UNASSIGNED = -14,
};

struct schc_rule;

typedef int (*schc_rule_compress_fn)(const struct schc_rule *rule,
				     const uint8_t *packet, size_t packet_len,
				     uint8_t *out, size_t out_len);

typedef int (*schc_rule_decompress_fn)(const struct schc_rule *rule,
				       const uint8_t *data, size_t data_len,
				       uint8_t *out, size_t out_len);

/**
 * @brief One static SCHC rule installed by a profile.
 *
 * Rule IDs are wire values. They are not local table indexes.
 */
struct schc_rule {
	uint8_t rule_id;
	schc_rule_compress_fn compress;
	schc_rule_decompress_fn decompress;
	const void *user_data;
};

/**
 * @brief Static SCHC profile context.
 *
 * Profiles own packet matching and residue formats. The generic dispatcher
 * owns rule iteration, rule-ID demux, and uncompressed fallback behavior.
 */
struct schc_profile {
	const struct schc_rule *rules;
	size_t rule_count;
	uint8_t uncompressed_rule_id;
	bool use_uncompressed_fallback;
};

/**
 * @brief Compress a packet using a SCHC profile rule table.
 *
 * Rules are tried in table order. When no rule matches and uncompressed
 * fallback is enabled, the output is rule_id followed by the original packet.
 */
SCHC_WARN_UNUSED_RESULT
int schc_compress(const struct schc_profile *profile,
		  const uint8_t *packet, size_t packet_len,
		  uint8_t *out, size_t out_len);

/**
 * @brief Decompress a SCHC datagram using a profile rule table.
 */
SCHC_WARN_UNUSED_RESULT
int schc_decompress(const struct schc_profile *profile,
		    const uint8_t *data, size_t data_len,
		    uint8_t *out, size_t out_len);

static inline int schc_rule_id(const uint8_t *data, size_t len)
{
	return (len > 0) ? data[0] : -1;
}

#define SCHC_FRAGMENT_RULE_A_TO_B 0x78u
#define SCHC_FRAGMENT_RULE_B_TO_A 0x79u
#define SCHC_FRAGMENT_TILE_SIZE 187u
#define SCHC_FRAGMENT_WINDOW_SIZE 63u
#define SCHC_FRAGMENT_MAX_TILES 126u
#define SCHC_ALL_1 0x3fu
#define SCHC_FRAGMENT_MAX_PACKET_SIZE 23562u
#define SCHC_FRAGMENT_DEFAULT_RECEIVER_LIMIT 1281u
#define SCHC_FRAGMENT_MAX_ATTEMPTS 4u
#define SCHC_FRAGMENT_MAX_MESSAGE_SIZE 193u

enum schc_fragment_control {
	SCHC_CONTROL_ACK_REQUEST,
	SCHC_CONTROL_SENDER_ABORT,
	SCHC_CONTROL_RECEIVER_ABORT,
};

enum schc_sender_status {
	SCHC_SENDER_READY,
	SCHC_SENDER_ACTIVE,
	SCHC_SENDER_SUCCEEDED,
	SCHC_SENDER_ABORTED,
};

#define SCHC_MAX_PACKET 1281

struct schc_fragmenter_config {
	uint8_t rule_id;
	uint8_t window;
	uint8_t fcn;
	uint8_t rcs[4];
};

struct schc_ack {
	uint64_t bitmap;
	uint8_t rule_id;
	uint8_t window;
	bool complete;
};

SCHC_WARN_UNUSED_RESULT
int schc_fragment_encode(const struct schc_fragment *fragment,
			 uint8_t *out, size_t out_len);

SCHC_WARN_UNUSED_RESULT
int schc_fragment_decode(struct schc_fragment *fragment,
			 const uint8_t *data, size_t data_len,
			 uint8_t *tile, size_t tile_len);

SCHC_WARN_UNUSED_RESULT
int schc_ack_encode(const struct schc_ack *ack, uint8_t *out, size_t out_len);

/** assigned_bitmap uses FCN bit positions; pass false to decode without context. */
SCHC_WARN_UNUSED_RESULT
int schc_ack_decode(struct schc_ack *ack, uint64_t assigned_bitmap,
		    bool check_assigned, const uint8_t *data, size_t data_len);

SCHC_WARN_UNUSED_RESULT
int schc_control_encode(enum schc_fragment_control control, uint8_t rule_id,
			uint8_t window, uint8_t *out, size_t out_len);

struct schc_fragmenter {
	const uint8_t *packet;
	size_t packet_len;
	size_t fragment_count;
	size_t next_fragment;
	uint64_t missing;
	uint8_t rule_id;
	uint8_t retransmit_window;
	uint8_t retransmit_position;
	uint8_t attempts;
	uint8_t phase;
	enum schc_sender_status status;
};

/**
 * Initialize a sender that borrows packet storage.
 *
 * The packet pointer must remain valid and its bytes immutable until status is
 * SCHC_SENDER_SUCCEEDED or SCHC_SENDER_ABORTED.
 */
SCHC_WARN_UNUSED_RESULT
int schc_fragmenter_init(struct schc_fragmenter *fragmenter, uint8_t rule_id,
			 const uint8_t *packet, size_t packet_len,
			 size_t receiver_limit);

/** Emit the next initial, retransmission, ACK REQ, or Sender-Abort message. */
SCHC_WARN_UNUSED_RESULT
int schc_fragmenter_next(struct schc_fragmenter *fragmenter,
			 uint8_t *out, size_t out_len);

/** Consume an ACK or Receiver-Abort. Ignored stale/wrong messages return 0. */
SCHC_WARN_UNUSED_RESULT
int schc_fragmenter_input(struct schc_fragmenter *fragmenter,
			  const uint8_t *message, size_t message_len);

/** Queue a final-window ACK REQ, or Sender-Abort after four attempts. */
SCHC_WARN_UNUSED_RESULT
int schc_fragmenter_timeout(struct schc_fragmenter *fragmenter);

struct schc_reassembly_result {
	size_t packet_len;
	bool complete;
	bool rcs_checked;
	bool rcs_ok;
	bool aborted;
};

struct schc_reassembler {
	uint8_t *packet;
	size_t capacity;
	size_t limit;
	size_t final_len;
	size_t final_staging;
	size_t complete_len;
	uint64_t bitmap[2];
	uint8_t decode_tile[SCHC_FRAGMENT_TILE_SIZE];
	uint8_t rcs[4];
	struct schc_ack pending_ack;
	uint8_t rule_id;
	uint8_t final_window;
	uint8_t attempts;
	uint8_t pending;
	bool active;
	bool have_all1;
	bool delivered;
};

SCHC_WARN_UNUSED_RESULT
int schc_reassembler_init(struct schc_reassembler *reassembler,
			  uint8_t *packet, size_t capacity, size_t limit);

/**
 * Process one Fragment, ACK REQ, or abort message and queue any response.
 *
 * Callers dispatch contexts by authenticated link and fragmentation Rule ID.
 * Input for the opposite Rule ID is ignored without changing this context.
 */
SCHC_WARN_UNUSED_RESULT
int schc_reassembler_input(struct schc_reassembler *reassembler,
			   const uint8_t *message, size_t message_len,
			   struct schc_reassembly_result *result);

/**
 * Write a queued ACK or Receiver-Abort. A short output leaves it queued and
 * result noncomplete. Successful C=1 output reports completion in result.
 */
SCHC_WARN_UNUSED_RESULT
int schc_reassembler_next(struct schc_reassembler *reassembler,
			  uint8_t *out, size_t out_len,
			  struct schc_reassembly_result *result);

/**
 * Return a borrowed packet view only after its C=1 ACK was written.
 *
 * The view remains valid until an accepted, valid same-Rule-ID Fragment or
 * ACK REQ starts a new T=0 context, schc_reassembler_release(), re-init, or a
 * matching abort. Malformed and opposite-Rule-ID input does not invalidate it.
 */
SCHC_WARN_UNUSED_RESULT
int schc_reassembler_packet(const struct schc_reassembler *reassembler,
			    const uint8_t **packet, size_t *packet_len);

/** Queue Receiver-Abort for an active incomplete transfer. */
SCHC_WARN_UNUSED_RESULT
int schc_reassembler_expire(struct schc_reassembler *reassembler);

void schc_reassembler_release(struct schc_reassembler *reassembler);

#ifdef __cplusplus
}
#endif

#endif /* SCHC_SCHC_H_ */
