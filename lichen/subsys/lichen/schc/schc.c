/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc.c
 * @brief SCHC compress/decompress (RFC 8724) - rules 0-4 + uncompressed fallback
 *
 * Ported from rust/lichen-schc/src/codec.rs.
 * Bit order: MSB-first (network bit order). The residue is zero-padded to
 * a byte boundary.
 *
 * SECURITY CONSIDERATIONS
 * =======================
 * SCHC compression can leak information about packet contents through
 * compressed size variations (compression oracle attack). In contexts where
 * encrypted payloads are compressed, an attacker observing compressed sizes
 * may infer plaintext content by correlating size changes with known inputs.
 *
 * Mitigations applied in LICHEN:
 * - OSCORE encryption happens BEFORE SCHC compression, so encrypted CoAP
 *   payloads appear as opaque bytes that don't compress differentially.
 * - Link-layer encryption (if any) wraps the already-compressed frame.
 *
 * Residual risks:
 * - Header field values (ports, addresses, hop limit) are compressed but
 *   not encrypted; their presence in specific rules may leak metadata.
 * - Tail length variations remain observable.
 *
 * For high-security deployments, consider padding payloads to fixed sizes
 * before OSCORE encryption.
 */

#include <lichen/schc.h>
#include <string.h>
#include <stdbool.h>

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(schc, CONFIG_LICHEN_SCHC_LOG_LEVEL);
#else
#include <stdio.h>
#define LOG_WRN(...) fprintf(stderr, "WRN: " __VA_ARGS__)
#endif

/* IPv6 protocol constants */
#define IPV6_NH_UDP     17   /* UDP next header (RFC 768) */
#define IPV6_NH_ICMPV6  58   /* ICMPv6 next header (RFC 4443) */
#define IPV6_HDR_LEN    40   /* IPv6 base header length */
#define UDP_HDR_LEN     8    /* UDP header length */
#define ICMPV6_ECHO_HDR_LEN 8  /* ICMPv6 Echo Request/Reply header size */
#define ICMPV6_TYPE_RPL 155  /* RPL ICMPv6 type (RFC 6550) */

/* ─── bit-packing ─────────────────────────────────────────────────────────── */

struct bit_writer {
	uint8_t *buf;
	size_t buf_len;
	size_t nbits;
};

static void bit_writer_init(struct bit_writer *w, uint8_t *buf, size_t len)
{
	memset(buf, 0, len);
	w->buf = buf;
	w->buf_len = len;
	w->nbits = 0;
}

/**
 * Write the low @p nbits of @p value, MSB first.
 * Returns 0 on success, -1 if buffer too small.
 *
 * Optimized to write full bytes when bit-aligned, falling back to
 * bit-by-bit for partial bytes.
 */
static int bit_writer_write(struct bit_writer *w, uint64_t value, int nbits)
{
	/* Reject invalid bit counts */
	if (nbits < 0 || nbits > 64) {
		return -1;
	}

	/* Check for overflow before computing bytes_needed */
	if ((size_t)nbits > SIZE_MAX - w->nbits - 7) {
		return -1;
	}
	size_t bytes_needed = (w->nbits + (size_t)nbits + 7) / 8;
	if (bytes_needed > w->buf_len) {
		return -1;
	}

	int remaining = nbits;

	/* If not byte-aligned, write bits until we are (or until done) */
	int bit_offset = w->nbits % 8;
	if (bit_offset != 0) {
		int bits_to_align = 8 - bit_offset;
		if (bits_to_align > remaining) {
			bits_to_align = remaining;
		}
		/* Extract the top 'bits_to_align' bits from the remaining value */
		int shift = remaining - bits_to_align;
		uint8_t partial = (value >> shift) & ((1 << bits_to_align) - 1);
		w->buf[w->nbits / 8] |= partial << (8 - bit_offset - bits_to_align);
		w->nbits += bits_to_align;
		remaining -= bits_to_align;
	}

	/* Write full bytes */
	while (remaining >= 8) {
		remaining -= 8;
		w->buf[w->nbits / 8] = (value >> remaining) & 0xFF;
		w->nbits += 8;
	}

	/* Write any remaining bits */
	if (remaining > 0) {
		uint8_t partial = value & ((1 << remaining) - 1);
		w->buf[w->nbits / 8] = partial << (8 - remaining);
		w->nbits += remaining;
	}

	return 0;
}

/**
 * Write up to 128 bits from a byte array (for IPv6 addresses).
 *
 * Optimized to use memcpy for full bytes when byte-aligned, falling back
 * to bit-by-bit for unaligned cases or partial bytes.
 */
static int bit_writer_write128(struct bit_writer *w,
			       const uint8_t value[16], int nbits)
{
	/* Reject invalid bit counts */
	if (nbits < 0 || nbits > 128) {
		return -1;
	}

	/* Check for overflow before computing bytes_needed */
	if ((size_t)nbits > SIZE_MAX - w->nbits - 7) {
		return -1;
	}
	size_t bytes_needed = (w->nbits + (size_t)nbits + 7) / 8;
	if (bytes_needed > w->buf_len) {
		return -1;
	}

	int remaining = nbits;
	int src_bit = 0;  /* bit position in value[] */

	/* If not byte-aligned, write bits until we are (or until done) */
	int bit_offset = w->nbits % 8;
	if (bit_offset != 0) {
		int bits_to_align = 8 - bit_offset;
		if (bits_to_align > remaining) {
			bits_to_align = remaining;
		}
		for (int i = 0; i < bits_to_align; i++) {
			int byte_idx = src_bit / 8;
			int bit_idx = 7 - (src_bit % 8);
			uint8_t bit = (value[byte_idx] >> bit_idx) & 1;
			w->buf[w->nbits / 8] |= bit << (7 - (w->nbits % 8));
			w->nbits++;
			src_bit++;
		}
		remaining -= bits_to_align;
	}

	/* Copy full bytes directly when both src and dst are byte-aligned */
	if (remaining >= 8 && (src_bit % 8) == 0) {
		int full_bytes = remaining / 8;
		memcpy(&w->buf[w->nbits / 8], &value[src_bit / 8], full_bytes);
		w->nbits += full_bytes * 8;
		src_bit += full_bytes * 8;
		remaining -= full_bytes * 8;
	}

	/* Write any remaining bits */
	for (int i = 0; i < remaining; i++) {
		int byte_idx = src_bit / 8;
		int bit_idx = 7 - (src_bit % 8);
		uint8_t bit = (value[byte_idx] >> bit_idx) & 1;
		w->buf[w->nbits / 8] |= bit << (7 - (w->nbits % 8));
		w->nbits++;
		src_bit++;
	}

	return 0;
}

static size_t bit_writer_byte_len(const struct bit_writer *w)
{
	return (w->nbits + 7) / 8;
}

struct bit_reader {
	const uint8_t *buf;
	size_t buf_len;
	size_t pos;
};

static void bit_reader_init(struct bit_reader *r, const uint8_t *buf, size_t len)
{
	r->buf = buf;
	r->buf_len = len;
	r->pos = 0;
}

/**
 * Read @p nbits from the bit stream (max 64 bits).
 * Returns 0 on success, -1 if not enough data.
 *
 * Optimized to extract full bytes directly when byte-aligned, falling back
 * to bit-by-bit for unaligned or partial reads.
 */
static int bit_reader_read(struct bit_reader *r, int nbits, uint64_t *out)
{
	if (nbits < 0 || nbits > 64 || r->pos + (size_t)nbits > r->buf_len * 8) {
		return -1;
	}

	uint64_t value = 0;
	int remaining = nbits;

	/* If not byte-aligned, read bits until we are (or until done) */
	int bit_offset = r->pos % 8;
	if (bit_offset != 0) {
		int bits_to_align = 8 - bit_offset;
		if (bits_to_align > remaining) {
			bits_to_align = remaining;
		}
		for (int i = 0; i < bits_to_align; i++) {
			uint8_t byte = r->buf[r->pos / 8];
			uint8_t bit = (byte >> (7 - (r->pos % 8))) & 1;
			value = (value << 1) | bit;
			r->pos++;
		}
		remaining -= bits_to_align;
	}

	/* Read full bytes directly */
	while (remaining >= 8) {
		value = (value << 8) | r->buf[r->pos / 8];
		r->pos += 8;
		remaining -= 8;
	}

	/* Read any remaining bits */
	for (int i = 0; i < remaining; i++) {
		uint8_t byte = r->buf[r->pos / 8];
		uint8_t bit = (byte >> (7 - (r->pos % 8))) & 1;
		value = (value << 1) | bit;
		r->pos++;
	}

	*out = value;
	return 0;
}

/**
 * Read up to 128 bits into a byte array.
 * @p out_size specifies the size of the output buffer (must be >= nbits/8).
 *
 * Optimized to use memcpy when byte-aligned and nbits is a multiple of 8,
 * falling back to bit-by-bit otherwise.
 */
static int bit_reader_read_bytes(struct bit_reader *r, int nbits,
				 uint8_t *out, size_t out_size)
{
	if (nbits < 0) {
		return -1;
	}
	size_t bytes_needed = ((size_t)nbits + 7) / 8;
	if (bytes_needed > out_size || r->pos + (size_t)nbits > r->buf_len * 8) {
		return -1;
	}

	/* Fast path: byte-aligned reader and nbits is multiple of 8 */
	if ((r->pos % 8) == 0 && (nbits % 8) == 0) {
		int full_bytes = nbits / 8;
		memcpy(out, &r->buf[r->pos / 8], full_bytes);
		r->pos += nbits;
		return 0;
	}

	/* Slow path: bit-by-bit for unaligned or partial byte reads */
	memset(out, 0, bytes_needed);
	for (int i = 0; i < nbits; i++) {
		uint8_t byte = r->buf[r->pos / 8];
		uint8_t bit = (byte >> (7 - (r->pos % 8))) & 1;
		int byte_idx = i / 8;
		int bit_idx = 7 - (i % 8);
		out[byte_idx] |= bit << bit_idx;
		r->pos++;
	}
	return 0;
}

/** Return byte offset of last partially-read byte (rounds up). */
static size_t bit_reader_residue_byte_end(const struct bit_reader *r)
{
	return (r->pos + 7) / 8;
}

/* ─── address helpers ─────────────────────────────────────────────────────── */

/** Return true if addr is an IPv6 link-local address (fe80::/10). */
static bool is_link_local(const uint8_t addr[16])
{
	return addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80;
}

/** Return true if addr is an IPv6 global unicast address (2000::/3). */
static bool is_global(const uint8_t addr[16])
{
	return (addr[0] >> 5) == 0x01; /* 001x xxxx = 2000::/3 */
}

/* ─── checksum helpers ────────────────────────────────────────────────────── */

/** Add two values with one's-complement carry folding. */
static uint32_t oc_add(uint32_t a, uint32_t b)
{
	uint32_t s = a + b;
	if (s >> 16) {
		s = (s & 0xFFFF) + (s >> 16);
	}
	return s;
}

/** Sum bytes as 16-bit big-endian words for checksum calculation. */
static uint32_t checksum_bytes(const uint8_t *data, size_t len)
{
	uint32_t sum = 0;
	size_t i;

	for (i = 0; i + 1 < len; i += 2) {
		sum = oc_add(sum, ((uint16_t)data[i] << 8) | data[i + 1]);
	}
	if (i < len) {
		sum = oc_add(sum, (uint32_t)data[i] << 8);
	}
	return sum;
}

/** Compute IPv6 pseudo-header checksum contribution. */
static uint32_t pseudo_sum(const uint8_t src[16], const uint8_t dst[16],
			   uint8_t next_header, uint16_t length)
{
	uint32_t sum = 0;

	for (int i = 0; i < 16; i += 2) {
		sum = oc_add(sum, ((uint16_t)src[i] << 8) | src[i + 1]);
	}
	for (int i = 0; i < 16; i += 2) {
		sum = oc_add(sum, ((uint16_t)dst[i] << 8) | dst[i + 1]);
	}
	sum = oc_add(sum, length);
	sum = oc_add(sum, next_header);
	return sum;
}

/** Fold and complement accumulated sum to produce final checksum. */
static uint16_t finalize_checksum(uint32_t sum)
{
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return ~((uint16_t)sum);
}

/**
 * @brief Compute UDP checksum.
 *
 * @param src         Source IPv6 address
 * @param dst         Destination IPv6 address
 * @param src_port    Source port
 * @param dst_port    Destination port
 * @param payload     UDP payload (CoAP data)
 * @param payload_len Payload length
 * @param cksum_out   Output: computed checksum (only valid if return is 0)
 * @return 0 on success, -1 if payload_len would overflow UDP length field
 */
static int udp_checksum(const uint8_t src[16], const uint8_t dst[16],
			uint16_t src_port, uint16_t dst_port,
			const uint8_t *payload, size_t payload_len,
			uint16_t *cksum_out)
{
	/* UDP length field is 16 bits; header is 8 bytes, max payload is 65527 */
	if (payload_len > UINT16_MAX - 8) {
		return -1;
	}
	uint16_t udp_len = (uint16_t)(8 + payload_len);
	uint32_t sum = pseudo_sum(src, dst, 17, udp_len);

	sum = oc_add(sum, src_port);
	sum = oc_add(sum, dst_port);
	sum = oc_add(sum, udp_len);
	/* checksum field (0 during computation) */
	sum = oc_add(sum, checksum_bytes(payload, payload_len));
	*cksum_out = finalize_checksum(sum);
	return 0;
}

static uint16_t icmpv6_checksum(const uint8_t src[16], const uint8_t dst[16],
				const uint8_t *icmpv6_payload, size_t len)
{
	uint32_t sum = pseudo_sum(src, dst, 58, len);

	sum = oc_add(sum, checksum_bytes(icmpv6_payload, len));
	return finalize_checksum(sum);
}

/* ─── per-rule compress ───────────────────────────────────────────────────── */

/*
 * Compression functions follow a common pattern:
 *
 *   1. Validate minimum input length for the rule
 *   2. Write rule ID to out[0]
 *   3. Initialize bit_writer at out[1]
 *   4. For link-local rules: call compress_link_local_header() helper
 *      For global rules: write full addresses inline
 *   5. Write protocol-specific fields
 *   6. Call compress_finish() to copy tail and return total length
 *
 * This pattern ensures consistent bounds checking and avoids code duplication
 * for the common prologue (link-local header) and epilogue (tail copy).
 */

/**
 * Common epilogue for compress_* functions: compute output size, bounds-check,
 * copy the uncompressed tail, and return the total compressed length.
 *
 * @param w         Pointer to bit_writer (already populated with residue)
 * @param out       Output buffer (rule ID already at out[0])
 * @param out_len   Size of output buffer
 * @param tail      Pointer to uncompressed tail data
 * @param tail_len  Length of tail data
 * @return          Total compressed length on success, SCHC_ERR_BUFFER_TOO_SMALL on failure
 */
static int compress_finish(const struct bit_writer *w, uint8_t *out,
			   size_t out_len, const uint8_t *tail, size_t tail_len)
{
	size_t residue_len = bit_writer_byte_len(w);
	size_t tail_start = 1 + residue_len;
	size_t needed = tail_start + tail_len;

	if (needed > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	memcpy(&out[tail_start], tail, tail_len);
	return (int)needed;
}

/**
 * Common prologue for link-local compress_* functions: write hop_limit and
 * src/dst IIDs (64 bits each).
 *
 * @param w          Pointer to initialized bit_writer
 * @param hop_limit  IPv6 hop limit
 * @param src        Source IPv6 address (16 bytes)
 * @param dst        Destination IPv6 address (16 bytes)
 * @return           0 on success, -1 on buffer overflow
 */
static int compress_link_local_header(struct bit_writer *w, uint8_t hop_limit,
				      const uint8_t *src, const uint8_t *dst)
{
	if (bit_writer_write(w, hop_limit, 8) < 0 ||
	    bit_writer_write128(w, &src[8], 64) < 0 ||
	    bit_writer_write128(w, &dst[8], 64) < 0) {
		return -1;
	}
	return 0;
}

/**
 * Rule 0 (link-local) and Rule 1 (global): IPv6 + UDP + CoAP.
 */
static int compress_coap(const uint8_t *packet, size_t pkt_len,
			 uint8_t *out, size_t out_len, uint8_t rule_id)
{
	if (pkt_len < 40 + 8 + 4) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = packet[7];
	const uint8_t *src = &packet[8];
	const uint8_t *dst = &packet[24];
	const uint8_t *udp = &packet[40];
	uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];
	uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];
	const uint8_t *coap = &udp[8];
	uint8_t coap_type = (coap[0] >> 4) & 0x3;
	uint8_t coap_tkl = coap[0] & 0x0F;
	uint8_t coap_code = coap[1];
	uint16_t coap_mid = ((uint16_t)coap[2] << 8) | coap[3];
	const uint8_t *tail = &coap[4];
	size_t tail_len = pkt_len - 40 - 8 - 4;

	if (out_len == 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = rule_id;

	struct bit_writer w;
	bit_writer_init(&w, &out[1], out_len - 1);

	if (bit_writer_write(&w, hop_limit, 8) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	if (rule_id == SCHC_RULE_LINK_LOCAL_COAP) {
		/* Send only IID (64 bits) */
		if (bit_writer_write128(&w, &src[8], 64) < 0 ||
		    bit_writer_write128(&w, &dst[8], 64) < 0) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
	} else {
		/* Send full 128-bit addresses */
		if (bit_writer_write128(&w, src, 128) < 0 ||
		    bit_writer_write128(&w, dst, 128) < 0) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
	}

	if (bit_writer_write(&w, src_port, 16) < 0 ||
	    bit_writer_write(&w, dst_port, 16) < 0 ||
	    bit_writer_write(&w, coap_type, 2) < 0 ||
	    bit_writer_write(&w, coap_tkl, 4) < 0 ||
	    bit_writer_write(&w, coap_code, 8) < 0 ||
	    bit_writer_write(&w, coap_mid, 16) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/**
 * Rule 2: link-local IPv6 + ICMPv6 Echo.
 */
static int compress_icmpv6_echo(const uint8_t *packet, size_t pkt_len,
				uint8_t *out, size_t out_len)
{
	if (pkt_len < 40 + 8) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = packet[7];
	const uint8_t *src = &packet[8];
	const uint8_t *dst = &packet[24];
	const uint8_t *icmp = &packet[40];
	uint8_t icmp_type = icmp[0];
	uint16_t icmp_id = ((uint16_t)icmp[4] << 8) | icmp[5];
	uint16_t icmp_seq = ((uint16_t)icmp[6] << 8) | icmp[7];
	const uint8_t *tail = &icmp[8];
	size_t tail_len = pkt_len - 40 - 8;

	if (out_len < 1) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_ICMPV6_ECHO;

	struct bit_writer w;
	bit_writer_init(&w, &out[1], out_len - 1);

	if (compress_link_local_header(&w, hop_limit, src, dst) < 0 ||
	    bit_writer_write(&w, icmp_type, 8) < 0 ||
	    bit_writer_write(&w, icmp_id, 16) < 0 ||
	    bit_writer_write(&w, icmp_seq, 16) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/**
 * Rule 3: link-local IPv6 + ICMPv6 RPL DIO.
 */
static int compress_rpl_dio(const uint8_t *packet, size_t pkt_len,
			    uint8_t *out, size_t out_len)
{
	if (pkt_len < 40 + 4 + 24) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = packet[7];
	const uint8_t *src = &packet[8];
	const uint8_t *dst = &packet[24];
	const uint8_t *rpl = &packet[44]; /* skip ICMPv6 type/code/checksum (4B) */
	uint8_t instance = rpl[0];
	uint8_t version = rpl[1];
	uint16_t rank = ((uint16_t)rpl[2] << 8) | rpl[3];
	uint8_t gmop = rpl[4];
	uint8_t dtsn = rpl[5];
	/* flags (rpl[6]) and reserved (rpl[7]) are NOT_SENT */
	const uint8_t *dodagid = &rpl[8];
	const uint8_t *tail = &rpl[24];
	size_t tail_len = pkt_len - 40 - 4 - 24;

	if (out_len < 1) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_RPL_DIO;

	struct bit_writer w;
	bit_writer_init(&w, &out[1], out_len - 1);

	if (compress_link_local_header(&w, hop_limit, src, dst) < 0 ||
	    bit_writer_write(&w, instance, 8) < 0 ||
	    bit_writer_write(&w, version, 8) < 0 ||
	    bit_writer_write(&w, rank, 16) < 0 ||
	    bit_writer_write(&w, gmop, 8) < 0 ||
	    bit_writer_write(&w, dtsn, 8) < 0 ||
	    bit_writer_write128(&w, dodagid, 128) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/**
 * Rule 4: link-local IPv6 + ICMPv6 RPL DAO with DODAGID.
 */
static int compress_rpl_dao(const uint8_t *packet, size_t pkt_len,
			    uint8_t *out, size_t out_len)
{
	if (pkt_len < 40 + 4 + 20) {
		return SCHC_ERR_NO_MATCHING_RULE;
	}

	uint8_t hop_limit = packet[7];
	const uint8_t *src = &packet[8];
	const uint8_t *dst = &packet[24];
	const uint8_t *rpl = &packet[44];
	uint8_t instance = rpl[0];
	uint8_t kd_flags = rpl[1];
	/* reserved (rpl[2]) is NOT_SENT */
	uint8_t seq = rpl[3];
	const uint8_t *dodagid = &rpl[4];
	const uint8_t *tail = &rpl[20];
	size_t tail_len = pkt_len - 40 - 4 - 20;

	if (out_len < 1) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_RPL_DAO;

	struct bit_writer w;
	bit_writer_init(&w, &out[1], out_len - 1);

	if (compress_link_local_header(&w, hop_limit, src, dst) < 0 ||
	    bit_writer_write(&w, instance, 8) < 0 ||
	    bit_writer_write(&w, kd_flags, 8) < 0 ||
	    bit_writer_write(&w, seq, 8) < 0 ||
	    bit_writer_write128(&w, dodagid, 128) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	return compress_finish(&w, out, out_len, tail, tail_len);
}

/* ─── per-rule decompress ─────────────────────────────────────────────────── */

static int decompress_coap(const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len, uint8_t rule_id)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * - Rule 0 (link-local): 8 + 64 + 64 + 16 + 16 + 2 + 4 + 8 + 16 = 198 bits = 25 bytes
	 * - Rule 1 (global):     8 + 128 + 128 + 16 + 16 + 2 + 4 + 8 + 16 = 326 bits = 41 bytes
	 */
	size_t min_residue = (rule_id == SCHC_RULE_LINK_LOCAL_COAP) ? 25 : 41;
	if (data_len < 1 + min_residue) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct bit_reader r;
	bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	if (bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint8_t src[16], dst[16];

	if (rule_id == SCHC_RULE_LINK_LOCAL_COAP) {
		/* Reconstruct link-local prefix + IID */
		memset(src, 0, 16);
		memset(dst, 0, 16);
		src[0] = 0xFE;
		src[1] = 0x80;
		dst[0] = 0xFE;
		dst[1] = 0x80;
		if (bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
		    bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
			return SCHC_ERR_TOO_SHORT;
		}
	} else {
		if (bit_reader_read_bytes(&r, 128, src, 16) < 0 ||
		    bit_reader_read_bytes(&r, 128, dst, 16) < 0) {
			return SCHC_ERR_TOO_SHORT;
		}
	}

	uint64_t src_port, dst_port, coap_type, coap_tkl, coap_code, coap_mid;
	if (bit_reader_read(&r, 16, &src_port) < 0 ||
	    bit_reader_read(&r, 16, &dst_port) < 0 ||
	    bit_reader_read(&r, 2, &coap_type) < 0 ||
	    bit_reader_read(&r, 4, &coap_tkl) < 0 ||
	    bit_reader_read(&r, 8, &coap_code) < 0 ||
	    bit_reader_read(&r, 16, &coap_mid) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	/* Build CoAP header: ver(2)=1 | type(2) | tkl(4), code, mid[2] */
	uint8_t coap_b0 = (1 << 6) | ((coap_type & 0x3) << 4) | (coap_tkl & 0x0F);
	size_t coap_len = 4 + tail_len;
	uint16_t udp_len = 8 + coap_len;

	/* Build CoAP for checksum computation.
	 * ponytail: 512-byte stack buffer limits CoAP payload to ~508 bytes.
	 * This is adequate for LoRa MTUs (~250 bytes). For larger payloads,
	 * implement incremental checksum computation. */
	uint8_t coap_buf[512];

	/* Ensure tail fits in working buffer */
	if (tail_len > sizeof(coap_buf) - 4) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	coap_buf[0] = coap_b0;
	coap_buf[1] = (uint8_t)coap_code;
	coap_buf[2] = (uint8_t)(coap_mid >> 8);
	coap_buf[3] = (uint8_t)coap_mid;
	if (tail_len > 0) {
		memcpy(&coap_buf[4], tail, tail_len);
	}

	uint16_t udp_cksum;
	if (udp_checksum(src, dst, (uint16_t)src_port, (uint16_t)dst_port,
			 coap_buf, coap_len, &udp_cksum) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;  /* Payload too large for UDP */
	}

	uint16_t ipv6_payload_len = udp_len;
	size_t total = 40 + 8 + coap_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	/* IPv6 header */
	out[0] = 0x60;
	out[1] = 0;
	out[2] = 0;
	out[3] = 0;
	out[4] = (uint8_t)(ipv6_payload_len >> 8);
	out[5] = (uint8_t)ipv6_payload_len;
	out[6] = 17; /* UDP */
	out[7] = (uint8_t)hop_limit;
	memcpy(&out[8], src, 16);
	memcpy(&out[24], dst, 16);

	/* UDP header */
	out[40] = (uint8_t)(src_port >> 8);
	out[41] = (uint8_t)src_port;
	out[42] = (uint8_t)(dst_port >> 8);
	out[43] = (uint8_t)dst_port;
	out[44] = (uint8_t)(udp_len >> 8);
	out[45] = (uint8_t)udp_len;
	out[46] = (uint8_t)(udp_cksum >> 8);
	out[47] = (uint8_t)udp_cksum;

	/* CoAP */
	memcpy(&out[48], coap_buf, coap_len);

	return (int)total;
}

static int decompress_icmpv6_echo(const uint8_t *data, size_t data_len,
				  uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 16 + 16 = 176 bits = 22 bytes
	 */
	if (data_len < 1 + 22) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct bit_reader r;
	bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t icmp_type, icmp_id, icmp_seq;
	if (bit_reader_read(&r, 8, &icmp_type) < 0 ||
	    bit_reader_read(&r, 16, &icmp_id) < 0 ||
	    bit_reader_read(&r, 16, &icmp_seq) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t icmp_len = 8 + tail_len;
	size_t total = 40 + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	/* Build ICMPv6 with zero checksum for computation.
	 * ponytail: 512-byte stack buffer limits ICMPv6 payload to ~504 bytes.
	 * This is adequate for LoRa MTUs (~250 bytes). For larger payloads,
	 * implement incremental checksum computation. */
	uint8_t icmp_buf[512];

	/* Ensure tail fits in working buffer */
	if (tail_len > sizeof(icmp_buf) - 8) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	icmp_buf[0] = (uint8_t)icmp_type;
	icmp_buf[1] = 0; /* code NOT_SENT = 0 */
	icmp_buf[2] = 0; /* checksum placeholder */
	icmp_buf[3] = 0;
	icmp_buf[4] = (uint8_t)(icmp_id >> 8);
	icmp_buf[5] = (uint8_t)icmp_id;
	icmp_buf[6] = (uint8_t)(icmp_seq >> 8);
	icmp_buf[7] = (uint8_t)icmp_seq;
	if (tail_len > 0) {
		memcpy(&icmp_buf[8], tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp_buf, icmp_len);

	/* IPv6 header */
	out[0] = 0x60;
	out[1] = 0;
	out[2] = 0;
	out[3] = 0;
	out[4] = (uint8_t)(icmp_len >> 8);
	out[5] = (uint8_t)icmp_len;
	out[6] = 58; /* ICMPv6 */
	out[7] = (uint8_t)hop_limit;
	memcpy(&out[8], src, 16);
	memcpy(&out[24], dst, 16);

	/* ICMPv6 */
	out[40] = (uint8_t)icmp_type;
	out[41] = 0;
	out[42] = (uint8_t)(cksum >> 8);
	out[43] = (uint8_t)cksum;
	out[44] = (uint8_t)(icmp_id >> 8);
	out[45] = (uint8_t)icmp_id;
	out[46] = (uint8_t)(icmp_seq >> 8);
	out[47] = (uint8_t)icmp_seq;
	if (tail_len > 0) {
		memcpy(&out[48], tail, tail_len);
	}

	return (int)total;
}

static int decompress_rpl_dio(const uint8_t *data, size_t data_len,
			      uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 8 + 16 + 8 + 8 + 128 = 312 bits = 39 bytes
	 */
	if (data_len < 1 + 39) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct bit_reader r;
	bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t instance, version, rank, gmop, dtsn;
	uint8_t dodagid[16];

	if (bit_reader_read(&r, 8, &instance) < 0 ||
	    bit_reader_read(&r, 8, &version) < 0 ||
	    bit_reader_read(&r, 16, &rank) < 0 ||
	    bit_reader_read(&r, 8, &gmop) < 0 ||
	    bit_reader_read(&r, 8, &dtsn) < 0 ||
	    bit_reader_read_bytes(&r, 128, dodagid, 16) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	/* RPL DIO base (24 bytes) + tail */
	size_t rpl_body_len = 24 + tail_len;
	size_t icmp_len = 4 + rpl_body_len; /* type+code+cksum + body */
	size_t total = 40 + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	/* ponytail: 512-byte stack buffer limits DIO options to ~484 bytes.
	 * This is adequate for LoRa MTUs (~250 bytes). For larger payloads,
	 * implement incremental checksum computation. */
	uint8_t icmp_buf[512];

	/* Ensure tail fits in working buffer (28 = DIO header) */
	if (tail_len > sizeof(icmp_buf) - 28) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	icmp_buf[0] = 155; /* RPL */
	icmp_buf[1] = 1;   /* DIO code */
	icmp_buf[2] = 0;   /* checksum placeholder */
	icmp_buf[3] = 0;
	icmp_buf[4] = (uint8_t)instance;
	icmp_buf[5] = (uint8_t)version;
	icmp_buf[6] = (uint8_t)(rank >> 8);
	icmp_buf[7] = (uint8_t)rank;
	icmp_buf[8] = (uint8_t)gmop;
	icmp_buf[9] = (uint8_t)dtsn;
	icmp_buf[10] = 0; /* flags (NOT_SENT = 0) */
	icmp_buf[11] = 0; /* reserved (NOT_SENT = 0) */
	memcpy(&icmp_buf[12], dodagid, 16);
	if (tail_len > 0) {
		memcpy(&icmp_buf[28], tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp_buf, icmp_len);

	/* IPv6 header */
	out[0] = 0x60;
	out[1] = 0;
	out[2] = 0;
	out[3] = 0;
	out[4] = (uint8_t)(icmp_len >> 8);
	out[5] = (uint8_t)icmp_len;
	out[6] = 58; /* ICMPv6 */
	out[7] = (uint8_t)hop_limit;
	memcpy(&out[8], src, 16);
	memcpy(&out[24], dst, 16);

	/* ICMPv6 / RPL DIO */
	memcpy(&out[40], icmp_buf, icmp_len);
	out[42] = (uint8_t)(cksum >> 8);
	out[43] = (uint8_t)cksum;

	return (int)total;
}

static int decompress_rpl_dao(const uint8_t *data, size_t data_len,
			      uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 8 + 8 + 128 = 288 bits = 36 bytes
	 */
	if (data_len < 1 + 36) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct bit_reader r;
	bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t instance, kd_flags, seq;
	uint8_t dodagid[16];

	if (bit_reader_read(&r, 8, &instance) < 0 ||
	    bit_reader_read(&r, 8, &kd_flags) < 0 ||
	    bit_reader_read(&r, 8, &seq) < 0 ||
	    bit_reader_read_bytes(&r, 128, dodagid, 16) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t rpl_body_len = 20 + tail_len;
	size_t icmp_len = 4 + rpl_body_len;
	size_t total = 40 + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	/* ponytail: 512-byte stack buffer limits DAO options to ~488 bytes.
	 * This is adequate for LoRa MTUs (~250 bytes). For larger payloads,
	 * implement incremental checksum computation. */
	uint8_t icmp_buf[512];

	/* Ensure tail fits in working buffer (24 = DAO header) */
	if (tail_len > sizeof(icmp_buf) - 24) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	icmp_buf[0] = 155; /* RPL */
	icmp_buf[1] = 2;   /* DAO code */
	icmp_buf[2] = 0;   /* checksum placeholder */
	icmp_buf[3] = 0;
	icmp_buf[4] = (uint8_t)instance;
	icmp_buf[5] = (uint8_t)kd_flags;
	icmp_buf[6] = 0; /* reserved (NOT_SENT = 0) */
	icmp_buf[7] = (uint8_t)seq;
	memcpy(&icmp_buf[8], dodagid, 16);
	if (tail_len > 0) {
		memcpy(&icmp_buf[24], tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp_buf, icmp_len);

	/* IPv6 header */
	out[0] = 0x60;
	out[1] = 0;
	out[2] = 0;
	out[3] = 0;
	out[4] = (uint8_t)(icmp_len >> 8);
	out[5] = (uint8_t)icmp_len;
	out[6] = 58;
	out[7] = (uint8_t)hop_limit;
	memcpy(&out[8], src, 16);
	memcpy(&out[24], dst, 16);

	/* ICMPv6 / RPL DAO */
	memcpy(&out[40], icmp_buf, icmp_len);
	out[42] = (uint8_t)(cksum >> 8);
	out[43] = (uint8_t)cksum;

	return (int)total;
}

/* ─── public API ──────────────────────────────────────────────────────────── */

int lichen_schc_compress(const uint8_t *packet, size_t pkt_len,
			 uint8_t *out, size_t out_len)
{
	int ret;

	if (packet == NULL || out == NULL) {
		return SCHC_ERR_TOO_SHORT;
	}

	if (pkt_len < IPV6_HDR_LEN || (packet[0] >> 4) != 6) {
		/* Not IPv6 - uncompressed fallback */
		size_t needed = 1 + pkt_len;
		if (out_len < needed) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
		out[0] = SCHC_RULE_UNCOMPRESSED;
		memcpy(&out[1], packet, pkt_len);
		return (int)needed;
	}

	/* Validate NOT_SENT fields match rule assumptions.
	 * All SCHC rules assume traffic_class=0 and flow_label=0.
	 * Non-zero values will be lost in compression. */
	uint8_t tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
	uint32_t fl = ((uint32_t)(packet[1] & 0x0F) << 16) |
		      ((uint32_t)packet[2] << 8) | packet[3];
	if (tc != 0 || fl != 0) {
		LOG_WRN("SCHC: non-zero TC/FL will be lost (tc=%u fl=%u)\n",
			tc, (unsigned)fl);
	}

	uint8_t nh = packet[6];
	const uint8_t *src = &packet[8];
	const uint8_t *dst = &packet[24];

	if (nh == IPV6_NH_UDP) {
		/* UDP - rules 0 or 1 */
		if (is_link_local(src) && is_link_local(dst)) {
			ret = compress_coap(packet, pkt_len, out, out_len,
					    SCHC_RULE_LINK_LOCAL_COAP);
			if (ret > 0) {
				return ret;
			}
		} else if (is_global(src) && is_global(dst)) {
			ret = compress_coap(packet, pkt_len, out, out_len,
					    SCHC_RULE_GLOBAL_COAP);
			if (ret > 0) {
				return ret;
			}
		}
	} else if (nh == IPV6_NH_ICMPV6 && pkt_len >= IPV6_HDR_LEN + 4) {
		/* ICMPv6 */
		uint8_t icmp_type = packet[IPV6_HDR_LEN];
		uint8_t icmp_code = packet[IPV6_HDR_LEN + 1];

		if ((icmp_type == 128 || icmp_type == 129) &&
		    icmp_code == 0 &&
		    is_link_local(src) && is_link_local(dst) &&
		    pkt_len >= IPV6_HDR_LEN + ICMPV6_ECHO_HDR_LEN) {
			ret = compress_icmpv6_echo(packet, pkt_len, out, out_len);
			if (ret > 0) {
				return ret;
			}
		} else if (icmp_type == ICMPV6_TYPE_RPL &&
			   is_link_local(src) && is_link_local(dst)) {
			if (icmp_code == 1 && pkt_len >= IPV6_HDR_LEN + 4 + 24) {
				/* DIO */
				ret = compress_rpl_dio(packet, pkt_len, out, out_len);
				if (ret > 0) {
					return ret;
				}
			} else if (icmp_code == 2 && pkt_len >= 40 + 4 + 20) {
				/* DAO - only rule 4 if D flag set */
				uint8_t kd_flags = packet[45];
				if (kd_flags & 0x40) {
					ret = compress_rpl_dao(packet, pkt_len,
							       out, out_len);
					if (ret > 0) {
						return ret;
					}
				}
			}
		}
	}

	/* Uncompressed fallback */
	size_t needed = 1 + pkt_len;
	if (out_len < needed) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	out[0] = SCHC_RULE_UNCOMPRESSED;
	memcpy(&out[1], packet, pkt_len);
	return (int)needed;
}

int lichen_schc_decompress(const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len)
{
	if (data == NULL || out == NULL) {
		return SCHC_ERR_TOO_SHORT;
	}

	if (data_len == 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	switch (data[0]) {
	case SCHC_RULE_LINK_LOCAL_COAP:
		return decompress_coap(data, data_len, out, out_len,
				       SCHC_RULE_LINK_LOCAL_COAP);
	case SCHC_RULE_GLOBAL_COAP:
		return decompress_coap(data, data_len, out, out_len,
				       SCHC_RULE_GLOBAL_COAP);
	case SCHC_RULE_ICMPV6_ECHO:
		return decompress_icmpv6_echo(data, data_len, out, out_len);
	case SCHC_RULE_RPL_DIO:
		return decompress_rpl_dio(data, data_len, out, out_len);
	case SCHC_RULE_RPL_DAO:
		return decompress_rpl_dao(data, data_len, out, out_len);
	case SCHC_RULE_UNCOMPRESSED: {
		const uint8_t *payload = &data[1];
		size_t payload_len = data_len - 1;
		if (out_len < payload_len) {
			return SCHC_ERR_BUFFER_TOO_SMALL;
		}
		memcpy(out, payload, payload_len);
		return (int)payload_len;
	}
	default:
		return SCHC_ERR_UNKNOWN_RULE_ID;
	}
}
