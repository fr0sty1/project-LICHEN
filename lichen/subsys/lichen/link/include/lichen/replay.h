/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/replay.h
 * @brief Replay protection window
 *
 * Per-public-key sliding window to detect and reject replayed frames.
 * Uses a 32-bit bitmap to track recently seen sequence numbers.
 *
 * Ported from rust/lichen-link/src/replay.rs
 */

#ifndef LICHEN_REPLAY_H_
#define LICHEN_REPLAY_H_

#include <stdint.h>
#include <stdbool.h>

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

/** Maximum peers to track replay state for */
#ifndef CONFIG_LICHEN_LINK_MAX_NEIGHBORS
#define CONFIG_LICHEN_LINK_MAX_NEIGHBORS 16
#endif

/* Use LICHEN_EUI64_LEN from link_ctx.h for consistency */
#include <lichen/link_ctx.h>

/**
 * @brief Replay window state for one peer
 *
 * Tracks a 32-slot sliding window within the latest finite epoch. Epochs and
 * sequence numbers never wrap: a lower epoch is stale, and a lower sequence
 * number is accepted only when it is an unseen value still in the window.
 *
 * Bit layout: bit 0 of bitmap represents last_seq, bit i represents
 * last_seq - i. A set bit means that sequence number was already accepted.
 */
struct lichen_replay_window {
	uint16_t last_seq; /**< Highest accepted sequence in current epoch */
	uint8_t epoch;     /**< Highest accepted finite epoch */
	uint32_t bitmap;   /**< 32-bit seen sequence bitmap */
	bool initialised;  /**< True once first tuple accepted */
};

/**
 * @brief Per-peer replay table entry
 */
struct lichen_replay_entry {
	uint8_t public_key[LICHEN_PK_LEN]; /**< Authenticated peer public key */
	struct lichen_replay_window window;
	bool active;                       /**< Entry is in use */
};

/**
 * @brief Table of per-peer replay windows
 */
struct lichen_replay_table {
	struct lichen_replay_entry peers[CONFIG_LICHEN_LINK_MAX_NEIGHBORS];
};

/**
 * @brief Initialize a replay window.
 *
 * @param[out] rw Replay window to initialize
 */
void lichen_replay_init(struct lichen_replay_window *_Nonnull rw);

/**
 * @brief Check and update replay window.
 *
 * Call this for every received frame. Returns true if the frame
 * should be accepted (not a replay), false if it should be rejected.
 *
 * A higher epoch starts a fresh sequence window. A lower epoch, including
 * epoch 0 after epoch 255, is always rejected. Within an epoch, sequence
 * numbers use ordinary finite ordering; 0 after 65535 is not a wrap.
 *
 * @param[in,out] rw     Replay window state
 * @param[in]     epoch  8-bit epoch from frame header
 * @param[in]     seq    16-bit sequence number from frame header
 * @return true if frame should be accepted, false if replay
 */
bool lichen_replay_check(struct lichen_replay_window *_Nonnull rw,
			 uint8_t epoch, uint16_t seq);

/**
 * @brief Initialize a replay table.
 *
 * @param[out] table Replay table to initialize
 */
void lichen_replay_table_init(struct lichen_replay_table *_Nonnull table);

/**
 * @brief Get or create replay window for a peer.
 *
 * Looks up the replay window for the authenticated public key. If no entry
 * exists and there's room in the table, creates a new entry. A full table
 * fails closed instead of evicting replay history (prevents poisoning).
 *
 * Callers MUST verify Schnorr-48 authentication (via peer_try_all_pubkeys +
 * schnorr48_verify_frame) before calling. Fixed unauthenticated LRU eviction
 * and EUI flooding attack (project-LICHEN-bbti).
 *
 * @param[in,out] table Replay table
 * @param[in]     public_key Authenticated peer public key (32 bytes)
 * @return Pointer to replay window, or NULL on invalid input or full table
 */
struct lichen_replay_window *_Nullable lichen_replay_get(
	struct lichen_replay_table *_Nonnull table,
	const uint8_t public_key[_Nonnull LICHEN_PK_LEN]);

/**
 * @brief Remove a peer from the replay table.
 *
 * @param[in,out] table Replay table
 * @param[in]     public_key Peer's public key (32 bytes)
 */
void lichen_replay_remove(struct lichen_replay_table *_Nonnull table,
			  const uint8_t public_key[_Nonnull LICHEN_PK_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_REPLAY_H_ */
