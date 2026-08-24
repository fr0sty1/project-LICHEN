/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file frame.c
 * @brief LICHEN frame parsing and serialization
 */

#include <lichen/link.h>
#include <lichen/errno.h>
#include <string.h>

/* LLSec byte bit positions */
#define LLSEC_ADDR_MODE_MASK  0x03
#define LLSEC_MIC_LEN_SHIFT   2
#define LLSEC_MIC_LEN_MASK    0x1c
#define LLSEC_SIG_PRESENT     0x20
#define LLSEC_ENCRYPTED       0x40
#define LLSEC_RESERVED        0x80

/* Address lengths by mode (index = enum lichen_addr_mode value) */
static const uint8_t addr_lens[] = { 0, 2, 8, 0 };
#define ADDR_LENS_COUNT (sizeof(addr_lens) / sizeof(addr_lens[0]))

/* Compile-time assertions: ensure struct field sizes match max values */
_Static_assert(sizeof(((struct lichen_frame *)0)->dst_addr) >= 8,
	       "dst_addr must hold at least 8 bytes (EUI-64)");
_Static_assert(sizeof(((struct lichen_frame *)0)->mic) >= LICHEN_SIG_LEN,
	       "mic must hold a Schnorr-48 signature");

int lichen_frame_parse(struct lichen_frame *frame,
		       const uint8_t *data, size_t len)
{
	if (frame == NULL || data == NULL) {
		return -EINVAL;
	}
	if (len > LICHEN_MAX_FRAME_LEN ||
	    (len > 0U && data[0] > LICHEN_MAX_FRAME_BODY_LEN)) {
		return -EMSGSIZE;
	}

	/*
	 * Minimum frame size: 5 bytes
	 *   length(1) + llsec(1) + epoch(1) + seqnum(2). Unsigned
	 * frames have no MIC; signed frames are checked after LLSec parsing.
	 */
	if (len < LICHEN_FRAME_FIXED_HEADER_LEN) {
		return -EINVAL;
	}

	size_t off = 0;
	uint8_t frame_len = data[off++];

	if (frame_len != len - 1) {
		return -EINVAL;
	}

	uint8_t llsec = data[off++];

	frame->addr_mode = llsec & LLSEC_ADDR_MODE_MASK;

	/* SECURITY: Reject encrypted frames before any other LLSec policy so
	 * E=1 is always reported as unsupported encryption (spec 4.2). */
	frame->encrypted = (llsec & LLSEC_ENCRYPTED) != 0;
	if (frame->encrypted) {
		return -EPROTONOSUPPORT;
	}

	/* Only selectors 0b000 and 0b001 are defined; both mean no MIC on an
	 * unsigned frame. Selectors 0b010-0b111 are reserved. */
	uint8_t mic_length = (llsec & LLSEC_MIC_LEN_MASK) >> LLSEC_MIC_LEN_SHIFT;
	if (mic_length > LICHEN_MIC_64) {
		return -EINVAL;
	}

	/* LLSec bit 7 is reserved and MUST be zero (spec/02-physical-link.md
	 * section 4.2); frames with bit 7 set MUST be discarded. */
	if ((llsec & LLSEC_RESERVED) != 0U) {
		return -EINVAL;
	}

	frame->mic_length = (enum lichen_mic_len)mic_length;
	frame->signature_present = (llsec & LLSEC_SIG_PRESENT) != 0;
	frame->signer_iid_present = false;
	frame->signer_iid_len = 0U;

	/* Signed frames carry the full 48-byte Schnorr signature in the MIC
	 * field; unsigned frames have no MIC bytes regardless of selector. */
	frame->mic_len = frame->signature_present ? LICHEN_SIG_LEN : 0U;
	uint8_t addr_len = addr_lens[frame->addr_mode];

	/* Check total required length: fixed header + address + MIC */
	if (len < LICHEN_FRAME_FIXED_HEADER_LEN + (size_t)addr_len +
		   frame->mic_len) {
		return -EINVAL;
	}

	frame->epoch = data[off++];
	frame->seqnum = (uint16_t)(((uint16_t)data[off] << 8) | data[off + 1]);
	off += 2;

	/* Destination address */
	frame->dst_addr_len = addr_len;
	memcpy(frame->dst_addr, &data[off], frame->dst_addr_len);
	off += frame->dst_addr_len;

	/* MIC at the end */
	memcpy(frame->mic, &data[len - frame->mic_len], frame->mic_len);

	/* Payload is everything between address/signer IID and MIC */
	frame->payload = &data[off];
	frame->payload_len = len - off - frame->mic_len;

	frame->inner_payload_len = frame->payload_len;

	return 0;
}

int lichen_frame_write(const struct lichen_frame *frame,
		       uint8_t *buf, size_t buflen)
{
	if (frame == NULL || buf == NULL) {
		return -EINVAL;
	}

	if ((unsigned int)frame->addr_mode >= ADDR_LENS_COUNT) {
		return -EINVAL;
	}

	if (frame->dst_addr_len != addr_lens[frame->addr_mode]) {
		return -EINVAL;
	}

	/* The MIC-length selector must be a defined value (0 or 1). */
	if ((unsigned int)frame->mic_length > LICHEN_MIC_64) {
		return -EINVAL;
	}

	/* LLSec bit 7 is reserved; the current wire profile carries no
	 * Signer IID field. */
	if (frame->signer_iid_present || frame->signer_iid_len != 0U) {
		return -EINVAL;
	}

	if (frame->encrypted) {
		return -EPROTONOSUPPORT;
	}

	/*
	 * Caller must initialize frame->mic and frame->mic_len before calling.
	 * The MIC is not computed here - it must be computed externally over
	 * the frame data and stored in frame->mic before serialization.
	 */
	uint8_t addr_len = addr_lens[frame->addr_mode];
	uint8_t mic_len = frame->signature_present ? LICHEN_SIG_LEN : 0U;

	if (frame->mic_len != mic_len) {
		return -EINVAL;
	}

	/* Subtraction-first sizing: non_payload_len counts every byte of the
	 * serialized frame except the payload (including LENGTH), and the
	 * payload must fit in what remains of the 255-byte total. */
	size_t non_payload_len = LICHEN_FRAME_FIXED_HEADER_LEN + (size_t)addr_len +
				 mic_len;

	if (LICHEN_MAX_FRAME_LEN < non_payload_len ||
	    frame->payload_len > LICHEN_MAX_FRAME_LEN - non_payload_len) {
		return -EMSGSIZE;
	}

	size_t frame_len = non_payload_len + frame->payload_len;

	if (frame_len > buflen) {
		return -ENOMEM;
	}

	size_t off = 0;

	/* Length byte (excludes itself) */
	buf[off++] = (uint8_t)(frame_len - 1);

	/* LLSec byte — selector encoded from mic_length; bit 7 stays clear. */
	uint8_t llsec = frame->addr_mode & LLSEC_ADDR_MODE_MASK;
	llsec |= ((uint8_t)frame->mic_length << LLSEC_MIC_LEN_SHIFT) &
		 LLSEC_MIC_LEN_MASK;
	if (frame->signature_present) {
		llsec |= LLSEC_SIG_PRESENT;
	}
	buf[off++] = llsec;

	/* Epoch */
	buf[off++] = frame->epoch;

	/* Sequence number (big-endian) */
	buf[off++] = (uint8_t)(frame->seqnum >> 8);
	buf[off++] = (uint8_t)(frame->seqnum & 0xFF);

	/* Destination address */
	if (addr_len > 0) {
		memcpy(&buf[off], frame->dst_addr, addr_len);
	}
	off += addr_len;

	/* Payload */
	if (frame->payload_len > 0) {
		if (frame->payload == NULL) {
			return -EINVAL;
		}
		memcpy(&buf[off], frame->payload, frame->payload_len);
	}
	off += frame->payload_len;

	/* MIC */
	memcpy(&buf[off], frame->mic, mic_len);
	off += mic_len;

	return (int)off;
}
