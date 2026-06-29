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
#define LLSEC_MIC_LEN_MASK    0x04
#define LLSEC_SIG_PRESENT     0x20
#define LLSEC_ENCRYPTED       0x40
#define LLSEC_RESERVED        0x80

/* Address lengths by mode (index = enum lichen_addr_mode value) */
static const uint8_t addr_lens[] = { 0, 2, 8, 0 };

/* Compile-time assertions: ensure struct field sizes match max values */
_Static_assert(sizeof(((struct lichen_frame *)0)->dst_addr) >= 8,
	       "dst_addr must hold at least 8 bytes (EUI-64)");
_Static_assert(sizeof(((struct lichen_frame *)0)->mic) >= 8,
	       "mic must hold at least 8 bytes (64-bit MIC)");

int lichen_frame_parse(struct lichen_frame *frame,
		       const uint8_t *data, size_t len)
{
	if (frame == NULL || data == NULL) {
		return -EINVAL;
	}

	/*
	 * Minimum frame size: 9 bytes
	 *   length(1) + llsec(1) + epoch(1) + seqnum(2) + mic(4) = 9
	 * With 64-bit MIC it's 13 bytes, but we can't know MIC length
	 * until we parse LLSec, so check for minimum 32-bit MIC first.
	 */
	if (len < 9) {
		return -EINVAL;
	}

	size_t off = 0;
	uint8_t frame_len = data[off++];

	if (frame_len != len - 1) {
		return -EINVAL;
	}

	uint8_t llsec = data[off++];

	if (llsec & LLSEC_RESERVED) {
		return -EINVAL;
	}

	frame->addr_mode = llsec & LLSEC_ADDR_MODE_MASK;

	/* Reject ELIDED (addr_mode=3) - context-dependent addressing not yet supported */
	if (frame->addr_mode == LICHEN_ADDR_ELIDED) {
		return -EINVAL;
	}

	frame->mic_length = (llsec & LLSEC_MIC_LEN_MASK) ? LICHEN_MIC_64 : LICHEN_MIC_32;
	frame->signature_present = (llsec & LLSEC_SIG_PRESENT) != 0;
	frame->encrypted = (llsec & LLSEC_ENCRYPTED) != 0;

	/* Now that we know MIC length, verify frame is long enough */
	frame->mic_len = (frame->mic_length == LICHEN_MIC_64) ? LICHEN_MIC_64_LEN : LICHEN_MIC_32_LEN;
	uint8_t addr_len = addr_lens[frame->addr_mode];

	/* Check total required length: header(5) + addr + mic */
	if (len < 5 + addr_len + frame->mic_len) {
		return -EINVAL;
	}

	frame->epoch = data[off++];
	frame->seqnum = ((uint16_t)data[off] << 8) | data[off + 1];
	off += 2;

	/* Destination address */
	frame->dst_addr_len = addr_len;
	memcpy(frame->dst_addr, &data[off], frame->dst_addr_len);
	off += frame->dst_addr_len;

	/* MIC at the end */
	memcpy(frame->mic, &data[len - frame->mic_len], frame->mic_len);

	/* Payload is everything between address and MIC */
	frame->payload = &data[off];
	frame->payload_len = len - off - frame->mic_len;

	/* Compute inner payload length (excluding signature if present) */
	if (frame->signature_present) {
		if (frame->payload_len < LICHEN_SIG_LEN) {
			return -EINVAL;  /* Payload too short for signature */
		}
		frame->inner_payload_len = frame->payload_len - LICHEN_SIG_LEN;
	} else {
		frame->inner_payload_len = frame->payload_len;
	}

	return 0;
}

int lichen_frame_write(const struct lichen_frame *frame,
		       uint8_t *buf, size_t buflen)
{
	if (frame == NULL || buf == NULL) {
		return -EINVAL;
	}

	/* Reject ELIDED mode - not yet supported (matches parse behavior) */
	if (frame->addr_mode == LICHEN_ADDR_ELIDED) {
		return -EINVAL;
	}

	/*
	 * Caller must initialize frame->mic and frame->mic_len before calling.
	 * The MIC is not computed here - it must be computed externally over
	 * the frame data and stored in frame->mic before serialization.
	 */
	if (frame->mic_len != LICHEN_MIC_32_LEN && frame->mic_len != LICHEN_MIC_64_LEN) {
		return -EINVAL;
	}

	uint8_t addr_len = addr_lens[frame->addr_mode];
	uint8_t mic_len = (frame->mic_length == LICHEN_MIC_64) ? LICHEN_MIC_64_LEN : LICHEN_MIC_32_LEN;

	/* Calculate total frame size */
	size_t frame_len = 1 + 1 + 1 + 2 + addr_len + frame->payload_len + mic_len;

	if (frame_len > buflen) {
		return -ENOMEM; /* Buffer too small */
	}
	if (frame_len > 256) {
		return -EMSGSIZE; /* Frame too large */
	}

	size_t off = 0;

	/* Length byte (excludes itself) */
	buf[off++] = (uint8_t)(frame_len - 1);

	/* LLSec byte */
	uint8_t llsec = frame->addr_mode & LLSEC_ADDR_MODE_MASK;
	if (frame->mic_length == LICHEN_MIC_64) {
		llsec |= LLSEC_MIC_LEN_MASK;
	}
	if (frame->signature_present) {
		llsec |= LLSEC_SIG_PRESENT;
	}
	if (frame->encrypted) {
		llsec |= LLSEC_ENCRYPTED;
	}
	buf[off++] = llsec;

	/* Epoch */
	buf[off++] = frame->epoch;

	/* Sequence number (big-endian) */
	buf[off++] = (uint8_t)(frame->seqnum >> 8);
	buf[off++] = (uint8_t)(frame->seqnum & 0xFF);

	/* Destination address */
	memcpy(&buf[off], frame->dst_addr, addr_len);
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
