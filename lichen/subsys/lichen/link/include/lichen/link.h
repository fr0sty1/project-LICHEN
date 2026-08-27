/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/link.h
 * @brief LICHEN link layer API
 *
 * Implements the LICHEN frame format with LLSec flags, replay-window tracking,
 * and Schnorr-48 link signatures per spec section 4.
 *
 * Wire layout:
 *   +--------+--------+-------+--------+----------+---------+-------+
 *   | Length | LLSec  | Epoch | SeqNum | Dst Addr | Payload |  MIC  |
 *   +--------+--------+-------+--------+----------+---------+-------+
 *      1B       1B       1B      2B       0/2/8B     var       0/48B
 *
 * @note Portability: bool (from stdbool.h) is used for in-memory state only.
 *       Wire formats use explicit uint8_t fields and bit manipulation.
 *       Structs are never raw-serialized; all encoding is byte-level.
 */

#ifndef LICHEN_LINK_H_
#define LICHEN_LINK_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __ZEPHYR__
#include <zephyr/sys/util.h>
#else
/* BUILD_ASSERT for non-Zephyr test builds. Variadic fallback supports both
 * the Zephyr-style single-argument form and an optional message (message
 * omitted requires C23 or GCC/Clang static_assert extension). */
#define BUILD_ASSERT_1(cond) _Static_assert(cond, "BUILD_ASSERT")
#define BUILD_ASSERT_2(cond, msg) _Static_assert(cond, msg)
#define BUILD_ASSERT_SEL(_1, _2, name, ...) name
#define BUILD_ASSERT(...) \
	BUILD_ASSERT_SEL(__VA_ARGS__, BUILD_ASSERT_2, BUILD_ASSERT_1)(__VA_ARGS__)
#endif

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

/** Maximum LICHEN frame payload size (LoRa SF10 255B - overhead) */
#define LICHEN_MAX_PAYLOAD 200

/** Maximum total frame length including LENGTH byte */
#ifndef LICHEN_MAX_FRAME_LEN
#define LICHEN_MAX_FRAME_LEN 255
#endif

/** Maximum frame body length (LICHEN_MAX_FRAME_LEN minus LENGTH byte) */
#ifndef LICHEN_MAX_FRAME_BODY_LEN
#define LICHEN_MAX_FRAME_BODY_LEN 254
#endif

#ifdef CONFIG_LICHEN_TDMA
struct LICHEN_TDMA_Slot {
	uint32_t start_ms;
	uint32_t duration_ms;
	uint8_t node_id[8];
	uint8_t slot_id;
	uint8_t priority;
};
BUILD_ASSERT(sizeof(struct LICHEN_TDMA_Slot) == 20);
#endif

	/** Schnorr-48 signature length in bytes */
#define LICHEN_SIG_LEN 48

#define LICHEN_TDMA_GUARD_MS 50 /* spec/02a-coordinated-capacity.md §2a.2: guard "MUST be 50 for this revision"; ccp_tdma.json guard_ms=50 */
#define LICHEN_TDMA_SLOT_MS 250 /* spec/02a-coordinated-capacity.md §2a.2 Slot=(fnv1a32(EUI64)+u32(SFN)) mod n via lichen_hash_32; epoch MUST NOT enter the hash */
#define LICHEN_TDMA_BEACON_TIMEOUT_SUPERFRAMES 3 /* BEACON_TIMEOUT per 09-packets-timing.md FSM */
#define LICHEN_TDMA_CONTENTION_RETRIES 5 /* Max DAO retransmissions in contention slot */
#define LICHEN_TDMA_CONTENTION_BACKOFF_MIN_MS 100 /* CSMA min backoff */
#define LICHEN_TDMA_CONTENTION_BACKOFF_MAX_MS 1000 /* CSMA max backoff */
#define LICHEN_TDMA_MISSED_BEACON_THRESHOLD 3 /* >3 missed beacons triggers DRIFTING per 09-packets-timing.md FSM */

/* CSMA/CA profile constants (spec/09-packets-timing.md section 14.5). */
#define LICHEN_CSMA_CAD_TIMEOUT_SYMBOLS 3U
#define LICHEN_CSMA_BACKOFF_UNIT_MS     10U
#define LICHEN_CSMA_BACKOFF_MAX_EXPONENT 5U
#define LICHEN_CSMA_RETRY_LIMIT         3U

#ifdef CONFIG_LICHEN_TDMA
struct lichen_tdma_slot {uint8_t id;uint8_t assigned;uint32_t next;};

/**
 * @brief CCP FSM states per spec/09-packets-timing.md section 14.8
 *
 * State machine for desync/rejoin robustness. See test/vectors/tdma_ccp_fsm.json.
 */
enum lichen_ccp_state {
	LICHEN_CCP_UNJOINED = 0,   /**< Power-on/reset; CH0 listen only */
	LICHEN_CCP_ACQUIRING = 1,  /**< Listening for valid beacon */
	LICHEN_CCP_SYNCED = 2,     /**< TDMA slot assigned; normal operation */
	LICHEN_CCP_DRIFTING = 3,   /**< Lost sync; extended CH0 listen */
	LICHEN_CCP_REJOINING = 4,  /**< Re-acquiring via DAO */
};

/**
 * @brief CCP FSM events per spec/09-packets-timing.md section 14.8
 */
enum lichen_ccp_event {
	LICHEN_CCP_EVENT_INIT = 0,             /**< lichen_node_init() called */
	LICHEN_CCP_EVENT_VALID_BEACON = 1,     /**< Valid beacon received (sig verified) */
	LICHEN_CCP_EVENT_BEACON_IN_SLOT = 2,   /**< Beacon rx in assigned slot */
	LICHEN_CCP_EVENT_MISSED_BEACON = 3,    /**< Missed beacon count update */
	LICHEN_CCP_EVENT_RPL_VERSION = 4,      /**< RPL version increment */
	LICHEN_CCP_EVENT_INVALID_BEACON = 5,   /**< Invalid beacon (sig fail) */
	LICHEN_CCP_EVENT_DAO_ACK_SLOT = 6,     /**< DAO-ACK with slot assignment */
};
#endif


/** Maximum destination address length (EUI-64) */
#define LICHEN_ADDR_MAX 8

/**
 * @brief Address mode (LLSec bits 0-1)
 */
enum lichen_addr_mode {
	LICHEN_ADDR_BROADCAST = 0,  /**< No address (broadcast) */
	LICHEN_ADDR_SHORT = 1,      /**< 16-bit short address */
	LICHEN_ADDR_EUI64 = 2,      /**< 64-bit EUI-64 */
	LICHEN_ADDR_ELIDED = 3,     /**< Address elided (context-dependent) */
};

/**
 * @brief MIC length compatibility selector (LLSec bits 2-4)
 */
enum lichen_mic_len {
	LICHEN_MIC_32 = 0,  /**< Compatibility value; unsigned frames have no MIC */
	LICHEN_MIC_64 = 1,  /**< Compatibility value; unsigned frames have no MIC */
};

/**
 * @brief Coordination mechanisms per CCP-5 (da2q context)
 *
 * Priority order for negotiation: scheduled > hash_based > announce_driven > fallback
 *
 * Exact mapping to ccp9-rendezvous.json test vector "mechanism" strings:
 *   LICHEN_COORD_HASH_BASED      = 0  ↔  "hash_based"
 *   LICHEN_COORD_SCHEDULED       = 1  ↔  "scheduled"
 *   LICHEN_COORD_ANNOUNCE_DRIVEN = 2  ↔  "announce_driven"
 *   LICHEN_COORD_FALLBACK        = 3  ↔  "fallback"
 *
 * Implementations MUST serialize/deserialize using these exact strings.
 */
enum lichen_coordination_mechanism {
	LICHEN_COORD_HASH_BASED = 0,
	LICHEN_COORD_SCHEDULED = 1,
	LICHEN_COORD_ANNOUNCE_DRIVEN = 2,
	LICHEN_COORD_FALLBACK = 3,
};

/** Legacy MIC length constant; not a current wire MIC length */
#define LICHEN_MIC_32_LEN 4

/** Legacy MIC length constant; not a current wire MIC length */
#define LICHEN_MIC_64_LEN 8

/** Wire length of the frame length field */
#define LICHEN_FRAME_LEN_FIELD_LEN 1

/** Wire length of the LLSec field */
#define LICHEN_FRAME_LLSEC_LEN 1

/** Wire length of the epoch field */
#define LICHEN_FRAME_EPOCH_LEN 1

/** Wire length of the sequence number field */
#define LICHEN_FRAME_SEQNUM_LEN 2

/** Fixed wire header length before the destination address */
#define LICHEN_FRAME_FIXED_HEADER_LEN \
	(LICHEN_FRAME_LEN_FIELD_LEN + LICHEN_FRAME_LLSEC_LEN + \
	 LICHEN_FRAME_EPOCH_LEN + LICHEN_FRAME_SEQNUM_LEN)

/** Payload offset for a parsed frame with the given destination address length */
#define LICHEN_FRAME_PAYLOAD_OFFSET(addr_len) \
	(LICHEN_FRAME_FIXED_HEADER_LEN + (size_t)(addr_len))

/**
 * Maximum inner payload of any valid frame. The serialized total is at most
 * LICHEN_MAX_FRAME_LEN including the LENGTH byte, so the largest unsigned
 * broadcast/elided payload is 250 bytes.
 */
#define LICHEN_FRAME_PAYLOAD_MAX \
	(LICHEN_MAX_FRAME_LEN - LICHEN_FRAME_FIXED_HEADER_LEN)

/**
 * @brief LICHEN frame structure for parsing/building frames
 */
struct lichen_frame {
	uint8_t epoch;           /**< Epoch counter (key rotation) */
	uint16_t seqnum;         /**< Sequence number (replay protection) */
	uint8_t dst_addr[8];     /**< Destination address (0-8 bytes) */
	uint8_t dst_addr_len;    /**< Destination address length */
	uint8_t signer_iid[8];   /**< Signer EUI-64 from the wire SIID field */
	uint8_t signer_iid_len;  /**< 8 when the SI bit is set, else 0 */
	bool signer_iid_present; /**< LLSec bit 7; MUST equal signature_present */
	const uint8_t *_Nullable payload;  /**< Inner payload */
	size_t payload_len;      /**< Inner payload length */
	size_t inner_payload_len; /**< Same as payload_len; signature is in MIC */
	uint8_t mic[LICHEN_SIG_LEN]; /**< MIC or Schnorr-48 signature */
	uint8_t mic_len;         /**< MIC length (0 or 48) */

	/* LLSec flags */
	enum lichen_addr_mode addr_mode;
	enum lichen_mic_len mic_length;
	bool signature_present;  /**< Schnorr-48 occupies the MIC field */
	bool encrypted;          /**< Encrypted frame flag; currently unsupported */
};

#ifdef CONFIG_LICHEN_TDMA
struct lichen_tdma_ctx {
	uint32_t superframe;
	uint8_t slot;
	uint8_t n_slots;
	uint16_t slot_duration;
	bool synced;
	enum lichen_ccp_state ccp_state;     /**< CCP FSM state */
	uint8_t missed_beacons;              /**< Consecutive missed beacon count */
};

/**
 * @brief Process a CCP FSM event and transition state.
 *
 * Implements the state machine from spec/09-packets-timing.md section 14.8.
 * Test vectors: test/vectors/tdma_ccp_fsm.json.
 *
 * @param[in,out] tdma   TDMA context
 * @param[in]     event  FSM event
 * @param[in]     missed Missed beacon count (only for MISSED_BEACON event)
 * @return 0 on success, -EINVAL on NULL tdma
 */
int lichen_ccp_fsm_event(struct lichen_tdma_ctx *_Nonnull tdma,
			 enum lichen_ccp_event event,
			 uint8_t missed);
#endif

	/**
 * @brief Parse a LICHEN frame from wire bytes.
 *
 * @param[out] frame  Parsed frame structure
 * @param[in]  data   Wire bytes
 * @param[in]  len    Length of wire data
 * @return 0 on success, negative error code on failure
 */
int lichen_frame_parse(struct lichen_frame *_Nullable frame,
		       const uint8_t *_Nullable data, size_t len);


/**
 * @brief Serialize a LICHEN frame to wire bytes.
 *
 * @param[in]  frame  Frame to serialize
 * @param[out] buf    Output buffer
 * @param[in]  buflen Buffer size
 * @return Number of bytes written, or negative error code
 */
int lichen_frame_write(const struct lichen_frame *_Nullable frame,
		       uint8_t *_Nullable buf, size_t buflen);

/* ─── replay table ────────────────────────────────────────────────────────── */

#include <lichen/replay.h>

/* Replay structs and functions are defined in replay.h */

/* ─── link context ────────────────────────────────────────────────────────── */

/* Forward declaration - full definition in link_ctx.h */
struct lichen_link_ctx;

/* ─── TX path ─────────────────────────────────────────────────────────────── */

/**
 * @brief Build and transmit a LICHEN frame from an IPv6 packet.
 *
 * Takes an IPv6 packet, compresses it with SCHC, builds a LICHEN frame
 * with optional Schnorr-48 signature, and outputs the wire-ready frame.
 *
 * Steps:
 * 1. Compress IPv6 with SCHC
 * 2. Build frame header: length, LLSec flags, epoch, seqnum, dst addr
 * 3. Append compressed payload
 * 4. If signing enabled, compute Schnorr-48 signature for the MIC field
 * 5. Leave the MIC absent for unsigned frames; signed frames carry Schnorr-48
 *
 * @param[in]     ctx        Link context with keypair and sequence state
 * @param[in]     ipv6_pkt   IPv6 packet to transmit
 * @param[in]     ipv6_len   Length of IPv6 packet
 * @param[in]     dst_eui64  Destination EUI-64 (NULL for broadcast)
 * @param[out]    out_frame  Output buffer for LICHEN frame
 * @param[in,out] out_len    In: buffer size, Out: frame length
 * @return 0 on success, negative error code on failure
 *         -EINVAL: NULL parameter
 *         -ENOMEM: Output buffer too small
 *         -EMSGSIZE: Frame would exceed 255 bytes
 *         -EPROTONOSUPPORT: Link-layer encryption requested
 */
int lichen_link_tx(struct lichen_link_ctx *_Nonnull ctx,
		   const uint8_t *_Nonnull ipv6_pkt, size_t ipv6_len,
		   const uint8_t *_Nullable dst_eui64,
		   uint8_t *_Nonnull out_frame, size_t *_Nonnull out_len);

/**
 * @brief Re-sign a raw payload for relay with local link signature.
 *
 * Used for SOS relay and other cases where authenticated frames must be
 * re-broadcast with the relaying node's link signature. The inner payload
 * (which may contain origin signatures) is preserved; only the link-layer
 * signature is replaced with the relayer's.
 *
 * This function does NOT compress the payload (caller provides raw bytes).
 * For relaying, the payload is typically already-compressed content from
 * a received frame.
 *
 * @param[in]     ctx        Link context with keypair and sequence state
 * @param[in]     payload    Raw payload bytes to relay
 * @param[in]     payload_len Length of payload
 * @param[in]     dst_eui64  Destination EUI-64 (NULL for broadcast)
 * @param[out]    out_frame  Output buffer for LICHEN frame
 * @param[in,out] out_len    In: buffer size, Out: frame length
 * @return 0 on success, negative error code on failure
 *         -EINVAL: NULL parameter
 *         -ENOMEM: Output buffer too small
 *         -EMSGSIZE: Frame would exceed 255 bytes
 *         -ENOKEY: No signing key loaded
 */
int lichen_link_relay_raw(struct lichen_link_ctx *_Nonnull ctx,
			  const uint8_t *_Nonnull payload, size_t payload_len,
			  const uint8_t *_Nullable dst_eui64,
			  uint8_t *_Nonnull out_frame, size_t *_Nonnull out_len);

/* ─── RX path ─────────────────────────────────────────────────────────────── */

/**
 * @brief RX context for frame reception
 *
 * Provides peer context for signature verification and timing
 * for replay aging. Set peer_pubkey before calling lichen_link_rx()
 * for signed frames.
 */
struct lichen_link_rx_ctx {
	const uint8_t *_Nullable peer_pubkey;  /**< 32-byte peer public key (NULL if unknown) */
	const uint8_t *_Nonnull peer_eui64;    /**< 8-byte peer EUI-64 for MIC nonce */
	const uint8_t *_Nullable link_key;     /**< Retained legacy key (NULL to skip) */
	uint32_t current_time;                 /**< Current timestamp for replay aging */
};

/**
 * @brief Authenticated raw link payload metadata.
 *
 * Filled by lichen_link_rx_payload() after frame parse, signature/MIC
 * verification, source identification, and replay commit. The payload bytes
 * returned by that API are the authenticated inner payload. A Schnorr-48
 * signature is carried in the MIC field.
 */
struct lichen_link_rx_payload_info {
	uint8_t src_eui64[LICHEN_EUI64_LEN]; /**< Immediate sender EUI-64 */
	uint8_t dst_addr[LICHEN_ADDR_MAX];   /**< Destination address from frame */
	uint8_t dst_addr_len;                /**< Destination address length */
	uint8_t epoch;                       /**< Link epoch */
	uint16_t seqnum;                     /**< Link sequence number */
	enum lichen_addr_mode addr_mode;     /**< Destination address mode */
	bool signature_present;              /**< Schnorr-48 signature verified */
	bool encrypted;                      /**< Encrypted frame flag; unsupported */
};

/**
 * @brief Parse a LICHEN frame and extract authenticated inner payload bytes.
 *
 * Takes a raw LICHEN frame, verifies signature/MIC/source context, commits
 * replay protection, and returns the authenticated inner payload before any
 * SCHC decompression. This is the production boundary for dispatching raw
 * routing/control payloads such as 0x15||announce.
 *
 * @param[in]     ctx          RX context (must have peer_pubkey set for signed frames)
 * @param[in,out] replay       Replay table (NULL to skip replay check)
 * @param[in]     frame        Raw LICHEN frame bytes
 * @param[in]     frame_len    Length of frame
 * @param[out]    out_payload  Output buffer for authenticated inner payload
 *                             (use LICHEN_MAX_PAYLOAD for any valid payload)
 * @param[in,out] out_len      In: buffer size, Out: inner payload length
 * @param[out]    info         Authenticated frame metadata
 * @return 0 on success, negative error code on failure
 *         -EINVAL: malformed frame
 *         -EPROTONOSUPPORT: encrypted frame received
 *         -LICHEN_EAUTH: signature/MIC verification failed
 *         -EALREADY: replay detected
 *         -ENOMEM: output buffer too small
 */
struct lichen_replay_table;

int lichen_link_rx_payload(struct lichen_link_rx_ctx *_Nonnull ctx,
			   struct lichen_replay_table *_Nullable replay,
			   const uint8_t *_Nonnull frame, size_t frame_len,
			   uint8_t *_Nonnull out_payload, size_t *_Nonnull out_len,
			   struct lichen_link_rx_payload_info *_Nonnull info);

/**
 * @brief Parse a LICHEN frame and extract the IPv6 packet.
 *
 * Takes a raw LICHEN frame, verifies signature/MIC/source context,
 * decompresses accepted SCHC payloads to a full IPv6 packet, then commits
 * replay protection.
 *
 * Steps:
 * 1. Parse frame header: length, LLSec, epoch, seqnum, dst addr
 * 2. Reject unsupported encrypted frames; verify the 48-byte MIC if signed
 * 3. If signature present, verify Schnorr-48 using sender's public key
 * 4. Identify immediate sender
 * 5. Decompress accepted SCHC payload with SCHC
 * 6. Commit replay protection for authenticated frames
 * 7. Return decompressed IPv6 packet
 *
 * @param[in]     ctx        RX context (must have peer_pubkey set for signed frames)
 * @param[in,out] replay     Replay table (NULL to skip replay check)
 * @param[in]     frame      Raw LICHEN frame bytes
 * @param[in]     frame_len  Length of frame
 * @param[out]    out_ipv6   Output buffer for IPv6 packet
 * @param[in,out] out_len    In: buffer size, Out: IPv6 packet length
 * @param[out]    src_eui64  Filled with sender's EUI-64 (8 bytes)
 * @return 0 on success, negative error code on failure
 *         -EINVAL: malformed frame
 *         -LICHEN_EAUTH: signature/MIC verification failed
 *         -EALREADY: replay detected
 *         -ENOMEM: output buffer too small
 */
int lichen_link_rx(struct lichen_link_rx_ctx *_Nonnull ctx,
		   struct lichen_replay_table *_Nullable replay,
		   const uint8_t *_Nonnull frame, size_t frame_len,
		   uint8_t *_Nonnull out_ipv6, size_t *_Nonnull out_len,
		   uint8_t *_Nonnull src_eui64);

#ifdef CONFIG_LICHEN_TDMA
int lichen_tdma_init(struct lichen_tdma_ctx *_Nonnull tdma, struct lichen_link_ctx *_Nonnull ctx);
int lichen_link_set_slot(struct lichen_link_ctx *_Nullable ctx,
			 struct lichen_tdma_ctx *_Nullable tdma, uint8_t slot_id,
			 uint8_t n_slots, uint32_t sfn);
bool tdma_tx_allowed(const struct lichen_tdma_ctx *_Nullable tdma,
			 uint32_t now_ms);
uint8_t lichen_tdma_compute_slot(
	const uint8_t eui64[_Nonnull 8], uint32_t sfn, uint8_t num_slots);

/**
 * @brief Validate the CCP-7 guard budget.
 *
 * All arguments use the same caller-selected time unit.  The guard is
 * sufficient exactly when G >= B_i + B_j + J_i + J_j + P + M.  Arithmetic
 * overflow fails closed and returns false.
 */
bool lichen_tdma_guard_budget_sufficient(uint64_t guard,
					 uint64_t local_bound,
					 uint64_t peer_bound,
					 uint64_t local_jitter,
					 uint64_t peer_jitter,
					 uint64_t propagation,
					 uint64_t margin);
#endif

uint32_t lichen_hash_32(const uint8_t *_Nonnull data, size_t len);

/**
 * @brief Select a LoRa channel per CCP-12 synchronized hopping.
 *
 * Implements the SelectChannel pseudocode from spec/02a-coordinated-capacity.md:190.
 * Uses FNV-1a32 hash over (EUI-64 || epoch), where epoch is the key-rotation
 * counter from the link context (see lichen_link_next_tx and
 * lichen_link_set_epoch) — it is not a PHY time-sync value. Spec/02a:193
 * defines SelectChannel's Data = CONCAT(EUI64 as BE bytes, Epoch as LE u32),
 * so the epoch MAY enter the CHANNEL hash; the prohibition on epoch
 * substitution applies to the SLOT hash instead (§2a.2: Slot =
 * (fnv1a32(EUI64) + u32(SFN)) mod n). Both sender and receiver compute
 * identical channels for the same (eui64, epoch) pair, enabling deterministic
 * synchronized frequency hopping without explicit channel negotiation.
 *
 * @param[in]  eui64       8-byte EUI-64 address (big-endian)
 * @param[in]  epoch       Current epoch (key-rotation counter from link context)
 * @param[in]  density     Neighbor density count (0-8 normal; >8 forces channel 0)
 * @param[in]  num_channels Number of available channels (clamped to min 3)
 * @param[out] channel     Selected channel (0 = control channel, or 1..num_channels)
 *
 * @return 0 on success, -EINVAL if eui64 or channel is NULL
 */
int lichen_link_channel_select(const uint8_t eui64[_Nonnull LICHEN_EUI64_LEN],
			       uint32_t epoch,
			       uint8_t density,
			       uint8_t num_channels,
			       uint8_t *_Nonnull channel);

/* ---- Time Synchronization (spec 09 section 14.6) ---- */

/**
 * @brief Time source class (provenance of wall-clock sample)
 *
 * Wire strings match Python lichen.timing.time_sync.SourceClass.
 */
enum lichen_time_source_class {
	LICHEN_TIME_SOURCE_GNSS = 0,        /**< GNSS receiver (GPS/Galileo) */
	LICHEN_TIME_SOURCE_NETWORK = 1,     /**< NTS/Roughtime/SNTP/mesh DIO */
	LICHEN_TIME_SOURCE_LOCAL_CLIENT = 2,/**< Phone/app via LCI, gpsd */
	LICHEN_TIME_SOURCE_MANUAL = 3,      /**< Operator-provisioned static */
	LICHEN_TIME_SOURCE_INTERNAL_RTC = 4,/**< On-board RTC */
	LICHEN_TIME_SOURCE_MONOTONIC = 5,   /**< Uptime only; no wall clock */
};

#define LICHEN_TIME_SOURCE_CLASS_COUNT 6U

/**
 * @brief Configurable time-source ranking, best source first
 *
 * A valid policy contains every time source class exactly once.  The default
 * order is the canonical spec order: GNSS, Network, Local-client, Manual,
 * Internal RTC, then Monotonic.
 */
struct lichen_time_source_precedence {
	enum lichen_time_source_class order[LICHEN_TIME_SOURCE_CLASS_COUNT];
};

/**
 * @brief Prevalidated candidate for precedence/fallback selection
 *
 * These booleans are evidence supplied by the owning time provider after its
 * source-specific authentication, validity, freshness, and correction checks.
 * They MUST NOT be populated directly from unauthenticated packet fields.
 */
struct lichen_time_source_candidate {
	enum lichen_time_source_class source;
	bool source_valid;
	bool fresh;
	bool policy_accepted;
	bool rollback_safe;
};

/**
 * @brief Non-decreasing uptime observations for one power cycle
 *
 * The tracker deliberately has no wraparound semantics: a smaller observation,
 * including a counter wrapping to zero, is rejected and leaves the last
 * accepted value unchanged. Callers must synchronize access to a shared
 * tracker.
 */
struct lichen_monotonic_uptime {
	uint64_t last_ticks;
	bool initialized;
};

#define LICHEN_WALL_CLOCK_DEFAULT_FRESH_S 300U
#define LICHEN_WALL_CLOCK_DEFAULT_HOLDOVER_S 0U

enum lichen_wall_clock_state {
	LICHEN_WALL_CLOCK_INVALID = 0,
	LICHEN_WALL_CLOCK_FRESH = 1,
	LICHEN_WALL_CLOCK_HOLDOVER = 2,
};

struct lichen_wall_clock_snapshot {
	bool wall_clock_valid;
	enum lichen_wall_clock_state state;
	uint32_t unix_time;
	enum lichen_time_source_class source;
	uint8_t stratum;
	uint32_t age_s;
};

/**
 * @brief Provenance of the immutable firmware build epoch
 *
 * Release and SOURCE_DATE_EPOCH values are production metadata.  Fixed test
 * and developer values remain distinguishable so a generated host timestamp
 * can never be mistaken for reproducible release metadata.
 */
enum lichen_build_epoch_source {
	LICHEN_BUILD_EPOCH_SOURCE_INVALID = 0,
	LICHEN_BUILD_EPOCH_SOURCE_DATE_EPOCH = 1,
	LICHEN_BUILD_EPOCH_SOURCE_RELEASE = 2,
	LICHEN_BUILD_EPOCH_SOURCE_DEVELOPER_FIXED = 3,
	LICHEN_BUILD_EPOCH_SOURCE_DEVELOPER_GENERATED = 4,
	LICHEN_BUILD_EPOCH_SOURCE_FIXED_TEST = 5,
};

struct lichen_build_epoch_metadata {
	uint64_t unix_time;
	enum lichen_build_epoch_source source;
};

struct lichen_build_epoch_snapshot {
	bool initialized;
	uint32_t unix_time;
	enum lichen_build_epoch_source source;
	bool deterministic;
	bool production;
};

/**
 * @brief Time stratum values for DIO Time Option
 */
#define LICHEN_TIME_STRATUM_NO_SYNC        0  /**< No valid wall-clock source */
#define LICHEN_TIME_STRATUM_CONSERVATIVE   1  /**< Conservative synchronized */
#define LICHEN_TIME_STRATUM_ROUGHTIME      2  /**< Roughtime (BR) */
#define LICHEN_TIME_STRATUM_NTS            3  /**< NTS (BR) */
#define LICHEN_TIME_STRATUM_GNSS_GPSD      4  /**< GNSS or verified gpsd */

/**
 * @brief Board provision epoch evaluation status
 */
enum lichen_provision_status {
	LICHEN_PROVISION_MISSING = 0,       /**< No provision metadata */
	LICHEN_PROVISION_ACCEPTED = 1,      /**< Authenticated, floor raised */
	LICHEN_PROVISION_UNAUTHENTICATED = 2,/**< Raw integer ignored */
	LICHEN_PROVISION_BEFORE_BUILD = 3,  /**< Earlier than firmware epoch */
	LICHEN_PROVISION_BEYOND_LEAD = 4,   /**< Exceeds configured lead bound */
};

/**
 * @brief DIO Time Option (provisional Type 0x15)
 *
 * Wire layout: Type(1) + Len(1) + Stratum(1) + Reserved(1) + Timestamp(4)
 */
#define LICHEN_DIO_TIME_OPTION_TYPE     0x15
#define LICHEN_DIO_TIME_OPTION_DATA_LEN 6   /**< Length field value */
#define LICHEN_DIO_TIME_OPTION_LEN      8   /**< Total encoded size */

struct lichen_dio_time_option {
	uint8_t stratum;    /**< Time stratum 0-4 */
	uint32_t timestamp; /**< Unix epoch seconds (BE on wire) */
};

#ifdef CONFIG_LICHEN_CCP_TIME_SYNC
/* Time source class helpers */
const char *lichen_time_source_class_str(enum lichen_time_source_class source);
bool lichen_time_source_can_establish_wall_clock(enum lichen_time_source_class source);

/* Monotonic uptime tracking (single power cycle) */
int lichen_monotonic_uptime_init(
	struct lichen_monotonic_uptime *_Nonnull uptime);
int lichen_monotonic_uptime_observe(
	struct lichen_monotonic_uptime *_Nonnull uptime, uint64_t ticks);
int lichen_monotonic_uptime_now(
	const struct lichen_monotonic_uptime *_Nonnull uptime,
	uint64_t *_Nonnull ticks);
int lichen_monotonic_uptime_sample(
	struct lichen_monotonic_uptime *_Nonnull uptime,
	uint64_t *_Nonnull ticks);

/* Time source precedence and fallback */
int lichen_time_source_precedence_default(
	struct lichen_time_source_precedence *_Nonnull policy);
int lichen_time_source_precedence_init(
	struct lichen_time_source_precedence *_Nonnull policy,
	const enum lichen_time_source_class *_Nonnull order,
	size_t count);
int lichen_time_source_precedence_rank(
	const struct lichen_time_source_precedence *_Nonnull policy,
	enum lichen_time_source_class source,
	uint8_t *_Nonnull rank);
int lichen_time_source_precedence_preferred(
	const struct lichen_time_source_precedence *_Nonnull policy,
	enum lichen_time_source_class left,
	enum lichen_time_source_class right,
	enum lichen_time_source_class *_Nonnull preferred);
int lichen_time_source_precedence_select(
	const struct lichen_time_source_precedence *_Nonnull policy,
	const struct lichen_time_source_candidate *_Nullable candidates,
	size_t count,
	enum lichen_time_source_class *_Nonnull selected);

/* Time stratum validation */
bool lichen_time_stratum_valid(uint8_t stratum);

/* Epoch floor (firmware build + optional board provision) */
int lichen_epoch_floor_init(uint32_t firmware_build_epoch);
int lichen_epoch_floor_init_metadata(
	const struct lichen_build_epoch_metadata *_Nonnull metadata);
int lichen_build_epoch_snapshot_get(
	struct lichen_build_epoch_snapshot *_Nonnull snapshot);
int lichen_epoch_floor_set_provision(uint32_t provision_epoch,
				     bool authenticated,
				     uint32_t max_lead_s,
				     enum lichen_provision_status *_Nonnull status);
uint32_t lichen_epoch_floor_get(void);
bool lichen_epoch_floor_accepts(uint32_t unix_time);
const char *lichen_provision_status_str(enum lichen_provision_status status);

/* DIO Time Option encode/decode */
int lichen_dio_time_option_encode(const struct lichen_dio_time_option *_Nonnull opt,
				  uint8_t *_Nonnull buf, size_t buflen);
int lichen_dio_time_option_decode(const uint8_t *_Nonnull buf, size_t buflen,
				  struct lichen_dio_time_option *_Nonnull opt);

/* Wall clock management */
int lichen_wall_clock_establish(
	uint32_t unix_time,
	enum lichen_time_source_class source,
	uint8_t stratum,
	uint64_t observed_monotonic_ms,
	uint64_t now_monotonic_ms,
	uint32_t fresh_for_s,
	uint32_t holdover_s);
int lichen_wall_clock_snapshot_get(
	uint64_t now_monotonic_ms,
	struct lichen_wall_clock_snapshot *_Nonnull snapshot);
int lichen_wall_clock_set(uint32_t unix_time,
			  enum lichen_time_source_class source,
			  uint8_t stratum);
bool lichen_wall_clock_valid(void);
uint32_t lichen_wall_clock_get(void);
enum lichen_time_source_class lichen_wall_clock_source(void);
void lichen_wall_clock_invalidate(void);

/* SFN and sync state */
int lichen_time_sync_init(void);
uint32_t lichen_time_sync_get_sfn(void);
int lichen_time_sync_set_sfn(uint32_t sfn);
bool lichen_time_sync_is_synced(void);
void lichen_time_sync_advance_sfn(void);
void lichen_time_sync_desync(void);
uint8_t lichen_time_sync_get_stratum(void);
int lichen_time_sync_set_stratum(uint8_t stratum);
int lichen_time_sync_update_from_parent(uint32_t sfn, uint8_t parent_stratum);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LINK_H_ */
