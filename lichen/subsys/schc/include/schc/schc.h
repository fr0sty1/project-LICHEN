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

enum schc_fragment_direction {
	SCHC_FRAGMENT_UPLINK,
	SCHC_FRAGMENT_DOWNLINK,
};

enum schc_fragment_mode {
	SCHC_FRAGMENT_NO_ACK,
	SCHC_FRAGMENT_ACK_ALWAYS,
	SCHC_FRAGMENT_ACK_ON_ERROR,
};

#define SCHC_MAX_PACKET 1281

struct schc_fragmenter_config {
	uint8_t rule_id;
	uint8_t dtag;
	uint8_t dtag_bits;
	uint8_t window_bits;
	uint8_t fcn_bits;
	size_t tile_size;
	size_t mtu;
	enum schc_fragment_direction direction;
	enum schc_fragment_mode mode;
};

struct schc_fragmenter {
	struct schc_fragmenter_config config;
	const uint8_t *packet;
	size_t packet_len;
	size_t offset;
};

struct schc_ack {
	uint8_t rule_id;
	uint8_t dtag;
	uint8_t dtag_bits;
	uint8_t window;
	uint8_t window_bits;
	bool complete;
	uint8_t bitmap_bits;
	uint64_t bitmap;
};

size_t schc_fragment_header_len(const struct schc_fragmenter_config *config);

SCHC_WARN_UNUSED_RESULT
int schc_fragmenter_init(struct schc_fragmenter *fragmenter,
			 const struct schc_fragmenter_config *config,
			 const uint8_t *packet, size_t packet_len);

SCHC_WARN_UNUSED_RESULT
int schc_fragmenter_next(struct schc_fragmenter *fragmenter,
			 uint8_t *out, size_t out_len);

SCHC_WARN_UNUSED_RESULT
int schc_fragmenter_retransmit(const struct schc_fragmenter *fragmenter,
			       const struct schc_ack *ack,
			       uint8_t *out, size_t out_len);

size_t schc_ack_len(const struct schc_ack *ack);

SCHC_WARN_UNUSED_RESULT
int schc_ack_encode(const struct schc_ack *ack, uint8_t *out, size_t out_len);

SCHC_WARN_UNUSED_RESULT
int schc_ack_decode(struct schc_ack *ack, uint8_t dtag_bits,
		    uint8_t window_bits, uint8_t bitmap_bits,
		    const uint8_t *data, size_t data_len);

struct schc_reassembler_config {
	uint8_t rule_id;
	uint8_t dtag;
	uint8_t dtag_bits;
	uint8_t window_bits;
	uint8_t fcn_bits;
	size_t tile_size;
	enum schc_fragment_mode mode;
};

struct schc_reassembler {
	struct schc_reassembler_config config;
	uint8_t *packet;
	size_t packet_max_len;
	size_t packet_len;
	bool complete;
	uint64_t received_tiles;
	size_t received_tile_count;
	size_t contiguous_tile_count;
	uint8_t last_window;
};

size_t schc_reassembler_header_len(const struct schc_reassembler_config *config);

SCHC_WARN_UNUSED_RESULT
int schc_reassembler_init(struct schc_reassembler *reassembler,
			  const struct schc_reassembler_config *config,
			  uint8_t *packet, size_t packet_max_len);

SCHC_WARN_UNUSED_RESULT
int schc_reassembler_input(struct schc_reassembler *reassembler,
			   const uint8_t *fragment, size_t fragment_len,
			   bool *complete);

SCHC_WARN_UNUSED_RESULT
int schc_reassembler_ack(const struct schc_reassembler *reassembler,
			 struct schc_ack *ack);

#ifdef __cplusplus
}
#endif

#endif /* SCHC_SCHC_H_ */
