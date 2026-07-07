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
 *      1B       1B       1B      2B       0/2/8B     var      4/8B
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

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum LICHEN frame payload size (LoRa SF10 255B - overhead) */
#define LICHEN_MAX_PAYLOAD 200

/** Schnorr-48 signature length in bytes */
#define LICHEN_SIG_LEN 48

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
 * @brief MIC length (LLSec bits 2-4)
 */
enum lichen_mic_len {
	LICHEN_MIC_32 = 0,  /**< 32-bit MIC (4 bytes) */
	LICHEN_MIC_64 = 1,  /**< 64-bit MIC (8 bytes) */
};

/** 32-bit MIC length in bytes */
#define LICHEN_MIC_32_LEN 4

/** 64-bit MIC length in bytes */
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
 * @brief LICHEN frame structure for parsing/building frames
 */
struct lichen_frame {
	uint8_t epoch;           /**< Epoch counter (key rotation) */
	uint16_t seqnum;         /**< Sequence number (replay protection) */
	uint8_t dst_addr[8];     /**< Destination address (0-8 bytes) */
	uint8_t dst_addr_len;    /**< Destination address length */
	const uint8_t *payload;  /**< Payload (may include signature) */
	size_t payload_len;      /**< Total payload length (includes signature if present) */
	size_t inner_payload_len; /**< Payload length excluding signature (equals payload_len when no signature) */
	uint8_t mic[8];          /**< Message integrity code */
	uint8_t mic_len;         /**< MIC length (4 or 8) */

	/* LLSec flags */
	enum lichen_addr_mode addr_mode;
	enum lichen_mic_len mic_length;
	bool signature_present;  /**< Schnorr-48 appended to payload */
	bool encrypted;          /**< AES-CCM encrypted */
};

/**
 * @brief Parse a LICHEN frame from wire bytes.
 *
 * @param[out] frame  Parsed frame structure
 * @param[in]  data   Wire bytes
 * @param[in]  len    Length of wire data
 * @return 0 on success, negative error code on failure
 */
int lichen_frame_parse(struct lichen_frame *frame,
		       const uint8_t *data, size_t len);

/**
 * @brief Serialize a LICHEN frame to wire bytes.
 *
 * @param[in]  frame  Frame to serialize
 * @param[out] buf    Output buffer
 * @param[in]  buflen Buffer size
 * @return Number of bytes written, or negative error code
 */
int lichen_frame_write(const struct lichen_frame *frame,
		       uint8_t *buf, size_t buflen);

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
 * 4. If signing enabled, compute Schnorr-48 signature and append
 * 5. Compute MIC (CRC32 placeholder for AES-CCM)
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
 */
int lichen_link_tx(struct lichen_link_ctx *ctx,
		   const uint8_t *ipv6_pkt, size_t ipv6_len,
		   const uint8_t *dst_eui64,
		   uint8_t *out_frame, size_t *out_len);

/* ─── RX path ─────────────────────────────────────────────────────────────── */

/**
 * @brief RX context for frame reception
 *
 * Provides peer context for signature verification and timing
 * for replay aging. Set peer_pubkey before calling lichen_link_rx()
 * for signed frames.
 */
struct lichen_link_rx_ctx {
	const uint8_t *peer_pubkey;  /**< 32-byte peer public key (NULL if unknown) */
	const uint8_t *peer_eui64;   /**< 8-byte peer EUI-64 for MIC nonce */
	const uint8_t *link_key;     /**< 16-byte AES-128 key for MIC (NULL to skip) */
	uint32_t current_time;       /**< Current timestamp for replay aging */
};

/**
 * @brief Authenticated raw link payload metadata.
 *
 * Filled by lichen_link_rx_payload() after frame parse, signature/MIC
 * verification, source identification, and replay commit. The payload bytes
 * returned by that API are the authenticated inner payload, excluding any
 * appended Schnorr-48 signature.
 */
struct lichen_link_rx_payload_info {
	uint8_t src_eui64[LICHEN_EUI64_LEN]; /**< Immediate sender EUI-64 */
	uint8_t dst_addr[LICHEN_ADDR_MAX];   /**< Destination address from frame */
	uint8_t dst_addr_len;                /**< Destination address length */
	uint8_t epoch;                       /**< Link epoch */
	uint16_t seqnum;                     /**< Link sequence number */
	enum lichen_addr_mode addr_mode;     /**< Destination address mode */
	bool signature_present;              /**< Schnorr-48 signature verified */
	bool encrypted;                      /**< Payload was AES-CCM encrypted */
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
 *         -LICHEN_EAUTH: signature/MIC verification failed
 *         -EALREADY: replay detected
 *         -ENOMEM: output buffer too small
 */
int lichen_link_rx_payload(struct lichen_link_rx_ctx *ctx,
			   struct lichen_replay_table *replay,
			   const uint8_t *frame, size_t frame_len,
			   uint8_t *out_payload, size_t *out_len,
			   struct lichen_link_rx_payload_info *info);

/**
 * @brief Parse a LICHEN frame and extract the IPv6 packet.
 *
 * Takes a raw LICHEN frame, verifies signature/MIC/source context,
 * decompresses accepted SCHC payloads to a full IPv6 packet, then commits
 * replay protection.
 *
 * Steps:
 * 1. Parse frame header: length, LLSec, epoch, seqnum, dst addr
 * 2. Decrypt if needed and verify MIC
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
int lichen_link_rx(struct lichen_link_rx_ctx *ctx,
		   struct lichen_replay_table *replay,
		   const uint8_t *frame, size_t frame_len,
		   uint8_t *out_ipv6, size_t *out_len,
		   uint8_t *src_eui64);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LINK_H_ */
