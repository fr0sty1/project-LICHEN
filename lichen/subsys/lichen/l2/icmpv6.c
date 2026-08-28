/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file icmpv6.c
 * @brief LICHEN ICMPv6 implementation (RFC 4443, spec section 6.4)
 */

#include "icmpv6.h"

#include <string.h>
#include <limits.h>

#include <lichen/lichen_log.h>

LICHEN_LOG_MODULE(lichen_icmpv6, LOG_LEVEL_INF);

/*
 * IPv6 header field offsets.
 */
#define IPV6_VERSION_TC_FLOW_OFFSET     0
#define IPV6_PAYLOAD_LEN_OFFSET         4
#define IPV6_NEXT_HEADER_OFFSET         6
#define IPV6_HOP_LIMIT_OFFSET           7
#define IPV6_SRC_OFFSET                 8
#define IPV6_DST_OFFSET                 24
#define IPV6_FIXED_HEADER_LEN           40

/* IPv6 extension/upper-layer Next Header values. */
#define IPV6_NEXT_HEADER_HOP_BY_HOP   0
#define IPV6_NEXT_HEADER_ROUTING      43
#define IPV6_NEXT_HEADER_FRAGMENT     44
#define IPV6_NEXT_HEADER_ESP          50
#define IPV6_NEXT_HEADER_AH           51
#define IPV6_NEXT_HEADER_NONE         59
#define IPV6_NEXT_HEADER_DEST_OPTIONS 60

#define ICMPV6_REDIRECT 137

#define INVOKING_FLAGS_MASK    UINT8_C(0x0f)
#define ECHO_REQUEST_FLAGS_MASK UINT8_C(0x03)

/*
 * ICMPv6 header field offsets (relative to ICMPv6 start).
 */
#define ICMPV6_TYPE_OFFSET              0
#define ICMPV6_CODE_OFFSET              1
#define ICMPV6_CHECKSUM_OFFSET          2
#define ICMPV6_BODY_OFFSET              4

/*
 * Echo-specific offsets (relative to ICMPv6 start).
 */
#define ICMPV6_ECHO_ID_OFFSET           4
#define ICMPV6_ECHO_SEQ_OFFSET          6
#define ICMPV6_ECHO_DATA_OFFSET         8

/*
 * Error message rest-of-header offset (4 bytes after checksum).
 */
#define ICMPV6_ERROR_REST_OFFSET        4
#define ICMPV6_ERROR_INVOKING_OFFSET    8

/*
 * Default hop limit for ICMPv6 messages.
 */
#define DEFAULT_HOP_LIMIT               64

static bool ipv6_addr_is_unspecified(const uint8_t *addr)
{
	static const uint8_t unspecified[16];

	return memcmp(addr, unspecified, sizeof(unspecified)) == 0;
}

static bool ipv6_addr_is_multicast(const uint8_t *addr)
{
	return addr[0] == 0xff;
}

/*
 * Locate the invoking packet's upper-layer header.  Return 1 when it cannot
 * be inspected safely (ESP or a non-initial fragment), 0 on success, and a
 * negative errno for a malformed/truncated header chain.
 */
static int invoking_upper_layer(const uint8_t *packet, size_t packet_len, uint8_t *next_header,
				size_t *offset)
{
	uint8_t next;
	size_t cursor;

	if (packet_len < IPV6_FIXED_HEADER_LEN || ((uint32_t)packet[0] >> 4U) != 6U) {
		return -EINVAL;
	}

	next = packet[IPV6_NEXT_HEADER_OFFSET];
	cursor = IPV6_FIXED_HEADER_LEN;

	while (next == IPV6_NEXT_HEADER_HOP_BY_HOP || next == IPV6_NEXT_HEADER_ROUTING ||
	       next == IPV6_NEXT_HEADER_FRAGMENT || next == IPV6_NEXT_HEADER_AH ||
	       next == IPV6_NEXT_HEADER_DEST_OPTIONS) {
		size_t header_len;

		if (next == IPV6_NEXT_HEADER_FRAGMENT) {
			uint16_t fragment_offset;

			if (packet_len - cursor < 8U) {
				return -EINVAL;
			}
			fragment_offset = (uint16_t)(((uint32_t)packet[cursor + 2U] << 8U) |
						     (uint32_t)packet[cursor + 3U]);
			/* A non-initial fragment does not expose the upper-layer type. */
			if ((fragment_offset & UINT16_C(0xfff8)) != 0U) {
				return 1;
			}
			header_len = 8U;
		} else {
			if (packet_len - cursor < 2U) {
				return -EINVAL;
			}
			if (next == IPV6_NEXT_HEADER_AH) {
				header_len = ((size_t)packet[cursor + 1U] + 2U) * 4U;
			} else {
				header_len = ((size_t)packet[cursor + 1U] + 1U) * 8U;
			}
			if (header_len < 8U || header_len > packet_len - cursor) {
				return -EINVAL;
			}
		}

		next = packet[cursor];
		cursor += header_len;
	}

	if (next == IPV6_NEXT_HEADER_ESP) {
		return 1;
	}

	*next_header = next;
	*offset = cursor;
	return 0;
}

/* Return 1 when RFC 4443 requires suppression, 0 when allowed, or errno. */
static int error_suppression(const struct in6_addr *src, const struct in6_addr *dst,
			     const uint8_t *invoking_packet, size_t invoking_len,
			     uint8_t invoking_flags, bool allow_multicast)
{
	const uint8_t *invoking_src;
	const uint8_t *invoking_dst;
	uint8_t next_header;
	size_t upper_offset;
	int ret;

	if ((invoking_flags & (uint8_t)~INVOKING_FLAGS_MASK) != 0U) {
		return -EINVAL;
	}
	if (src == NULL || dst == NULL || invoking_packet == NULL) {
		return -EINVAL;
	}
	if (ipv6_addr_is_unspecified(src->s6_addr) || ipv6_addr_is_multicast(src->s6_addr)) {
		return -EINVAL;
	}

	ret = invoking_upper_layer(invoking_packet, invoking_len, &next_header, &upper_offset);
	if (ret != 0) {
		return ret;
	}

	invoking_src = invoking_packet + IPV6_SRC_OFFSET;
	invoking_dst = invoking_packet + IPV6_DST_OFFSET;
	if ((invoking_flags &
	     (LICHEN_ICMPV6_INVOKING_SOURCE_ANYCAST | LICHEN_ICMPV6_INVOKING_CONGESTION)) != 0U ||
	    ipv6_addr_is_unspecified(invoking_src) || ipv6_addr_is_multicast(invoking_src)) {
		return 1;
	}
	if (memcmp(dst->s6_addr, invoking_src, 16U) != 0) {
		return -EINVAL;
	}
	if (!allow_multicast && ((invoking_flags & (LICHEN_ICMPV6_INVOKING_LINK_MULTICAST |
						    LICHEN_ICMPV6_INVOKING_LINK_BROADCAST)) != 0U ||
				 ipv6_addr_is_multicast(invoking_dst))) {
		return 1;
	}

	if (next_header == LICHEN_ICMPV6_NEXT_HEADER) {
		uint8_t type;

		if (upper_offset >= invoking_len) {
			return -EINVAL;
		}
		type = invoking_packet[upper_offset];
		if (type < 128U || type == ICMPV6_REDIRECT) {
			return 1;
		}
	} else if (next_header == IPV6_NEXT_HEADER_NONE && upper_offset != invoking_len) {
		return -EINVAL;
	}

	return 0;
}

uint16_t lichen_internet_checksum(const uint8_t *data, size_t len)
{
    if (data == NULL && len > 0) {
        return 0;
    }

    uint32_t sum = 0;

    /* Sum 16-bit words */
    while (len >= 2) {
        sum += ((uint32_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }

    /* Handle odd byte */
    if (len == 1) {
        sum += (uint32_t)data[0] << 8;
    }

    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum & 0xFFFF);
}

uint16_t lichen_icmpv6_checksum(const struct in6_addr *src,
                                const struct in6_addr *dst,
                                const uint8_t *icmpv6_data,
                                size_t icmpv6_len)
{
    /*
     * IPv6 pseudo-header (RFC 2460 section 8.1):
     * - Source address (16 bytes)
     * - Destination address (16 bytes)
     * - Upper-layer packet length (4 bytes, big-endian)
     * - Zero padding (3 bytes)
     * - Next Header (1 byte = 58 for ICMPv6)
     *
     * Total pseudo-header: 40 bytes
     */
    uint8_t pseudo_header[40];
    uint32_t sum = 0;
    size_t i;

    /* Build pseudo-header */
    memcpy(pseudo_header, src->s6_addr, 16);
    memcpy(pseudo_header + 16, dst->s6_addr, 16);
    pseudo_header[32] = (icmpv6_len >> 24) & 0xFF;
    pseudo_header[33] = (icmpv6_len >> 16) & 0xFF;
    pseudo_header[34] = (icmpv6_len >> 8) & 0xFF;
    pseudo_header[35] = icmpv6_len & 0xFF;
    pseudo_header[36] = 0;
    pseudo_header[37] = 0;
    pseudo_header[38] = 0;
    pseudo_header[39] = LICHEN_ICMPV6_NEXT_HEADER;

    /* Sum pseudo-header */
    for (i = 0; i < 40; i += 2) {
        sum += ((uint32_t)pseudo_header[i] << 8) | pseudo_header[i + 1];
    }

    /* Sum ICMPv6 data */
    for (i = 0; i + 1 < icmpv6_len; i += 2) {
        sum += ((uint32_t)icmpv6_data[i] << 8) | icmpv6_data[i + 1];
    }

    /* Handle odd byte */
    if (icmpv6_len & 1) {
        sum += (uint32_t)icmpv6_data[icmpv6_len - 1] << 8;
    }

    /* Fold and complement */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum & 0xFFFF);
}

bool lichen_icmpv6_verify_checksum(const struct in6_addr *src,
                                   const struct in6_addr *dst,
                                   const uint8_t *icmpv6_data,
                                   size_t icmpv6_len)
{
    if (src == NULL || dst == NULL || icmpv6_data == NULL) {
        return false;
    }

    if (icmpv6_len < LICHEN_ICMPV6_HEADER_LEN) {
        return false;
    }

    /*
     * SECURITY: RFC 4443 mandates checksum verification.
     *
     * When computing the checksum over a received packet that already
     * contains a checksum, if the packet is valid the result will be zero.
     * This is because ones-complement math is self-inverting.
     */
    uint16_t computed = lichen_icmpv6_checksum(src, dst, icmpv6_data, icmpv6_len);
    return computed == 0;
}

int lichen_icmpv6_parse(const uint8_t *data, size_t len,
                        struct lichen_icmpv6_msg *msg)
{
    if (data == NULL || msg == NULL) {
        LOG_ERR("icmpv6: parse failed (NULL input)");
        return -EINVAL;
    }

    if (len < LICHEN_ICMPV6_HEADER_LEN) {
        LOG_ERR("icmpv6: parse failed (message too short: %zu bytes)", len);
        return -EINVAL;
    }

    msg->type = data[ICMPV6_TYPE_OFFSET];
    msg->code = data[ICMPV6_CODE_OFFSET];
    msg->body = data + ICMPV6_BODY_OFFSET;
    msg->body_len = len - ICMPV6_BODY_OFFSET;

    return 0;
}

int lichen_icmpv6_parse_echo(const struct lichen_icmpv6_msg *msg,
                             struct lichen_icmpv6_echo *echo)
{
    if (msg == NULL || echo == NULL) {
        LOG_ERR("icmpv6: parse_echo failed (NULL input)");
        return -EINVAL;
    }

    if (msg->type != LICHEN_ICMPV6_ECHO_REQUEST &&
        msg->type != LICHEN_ICMPV6_ECHO_REPLY) {
        LOG_ERR("icmpv6: parse_echo failed (wrong type: %u)", msg->type);
        return -EINVAL;
    }

    if (msg->code != 0U) {
        LOG_ERR("icmpv6: parse_echo failed (nonzero code: %u)", msg->code);
        return -EINVAL;
    }

    /* Body must have at least identifier (2) + sequence (2) */
    if (msg->body == NULL || msg->body_len < 4) {
        LOG_ERR("icmpv6: parse_echo failed (body too short: %zu)", msg->body_len);
        return -EINVAL;
    }

    echo->identifier = (uint16_t)(((uint16_t)msg->body[0] << 8) | msg->body[1]);
    echo->sequence = (uint16_t)(((uint16_t)msg->body[2] << 8) | msg->body[3]);
    echo->data = msg->body_len > 4 ? msg->body + 4 : NULL;
    echo->data_len = msg->body_len > 4 ? msg->body_len - 4 : 0;

    return 0;
}

/**
 * Build IPv6 header into buffer.
 */
static void build_ipv6_header(uint8_t *out,
                              const struct in6_addr *src,
                              const struct in6_addr *dst,
                              uint16_t payload_len,
                              uint8_t next_header,
                              uint8_t hop_limit)
{
    /* Version (4) + Traffic Class (8) + Flow Label (20) = 0x60000000 */
    out[0] = 0x60;
    out[1] = 0x00;
    out[2] = 0x00;
    out[3] = 0x00;

    /* Payload length */
    out[4] = (payload_len >> 8) & 0xFF;
    out[5] = payload_len & 0xFF;

    /* Next header */
    out[6] = next_header;

    /* Hop limit */
    out[7] = hop_limit;

    /* Source address */
    memcpy(out + IPV6_SRC_OFFSET, src->s6_addr, 16);

    /* Destination address */
    memcpy(out + IPV6_DST_OFFSET, dst->s6_addr, 16);
}

/**
 * Build ICMPv6 echo message (request or reply) with checksum.
 */
static int build_echo(uint8_t type,
                      const struct in6_addr *src,
                      const struct in6_addr *dst,
                      uint16_t identifier,
                      uint16_t sequence,
                      const uint8_t *data,
                      size_t data_len,
                      uint8_t *out,
                      size_t out_len)
{
    size_t icmpv6_len;
    size_t total_len;
    uint16_t checksum;

    if (src == NULL || dst == NULL || out == NULL) {
        LOG_ERR("icmpv6: build_echo failed (NULL input)");
        return -EINVAL;
    }

    if (data_len > 0 && data == NULL) {
        LOG_ERR("icmpv6: build_echo failed (data_len > 0 but data is NULL)");
        return -EINVAL;
    }

    if (type != LICHEN_ICMPV6_ECHO_REQUEST && type != LICHEN_ICMPV6_ECHO_REPLY) {
        return -EINVAL;
    }
    if (ipv6_addr_is_unspecified(src->s6_addr) || ipv6_addr_is_multicast(src->s6_addr) ||
        ipv6_addr_is_unspecified(dst->s6_addr) ||
        (type == LICHEN_ICMPV6_ECHO_REPLY && ipv6_addr_is_multicast(dst->s6_addr))) {
        return -EINVAL;
    }
    if (data_len > UINT16_MAX - LICHEN_ICMPV6_ECHO_HEADER_LEN) {
        return -EMSGSIZE;
    }

    icmpv6_len = LICHEN_ICMPV6_ECHO_HEADER_LEN + data_len;
    total_len = LICHEN_IPV6_HEADER_LEN + icmpv6_len;

    if (out_len < total_len) {
        return 0; /* Buffer too small */
    }

    /* Build IPv6 header */
    build_ipv6_header(out, src, dst, (uint16_t)icmpv6_len,
                      LICHEN_ICMPV6_NEXT_HEADER, DEFAULT_HOP_LIMIT);

    /* ICMPv6 header */
    uint8_t *icmpv6 = out + LICHEN_IPV6_HEADER_LEN;
    icmpv6[ICMPV6_TYPE_OFFSET] = type;
    icmpv6[ICMPV6_CODE_OFFSET] = 0;
    icmpv6[ICMPV6_CHECKSUM_OFFSET] = 0; /* Placeholder */
    icmpv6[ICMPV6_CHECKSUM_OFFSET + 1] = 0;

    /* Echo fields */
    icmpv6[ICMPV6_ECHO_ID_OFFSET] = (identifier >> 8) & 0xFF;
    icmpv6[ICMPV6_ECHO_ID_OFFSET + 1] = identifier & 0xFF;
    icmpv6[ICMPV6_ECHO_SEQ_OFFSET] = (sequence >> 8) & 0xFF;
    icmpv6[ICMPV6_ECHO_SEQ_OFFSET + 1] = sequence & 0xFF;

    /* Echo data */
    if (data_len > 0) {
        memcpy(icmpv6 + ICMPV6_ECHO_DATA_OFFSET, data, data_len);
    }

    /* Compute and fill checksum */
    checksum = lichen_icmpv6_checksum(src, dst, icmpv6, icmpv6_len);
    icmpv6[ICMPV6_CHECKSUM_OFFSET] = (checksum >> 8) & 0xFF;
    icmpv6[ICMPV6_CHECKSUM_OFFSET + 1] = checksum & 0xFF;

    if (total_len > (size_t)INT_MAX) {
        return -EOVERFLOW;
    }
    return (int)total_len;
}

int lichen_icmpv6_build_echo_request(const struct in6_addr *src,
                                     const struct in6_addr *dst,
                                     uint16_t identifier,
                                     uint16_t sequence,
                                     const uint8_t *data,
                                     size_t data_len,
                                     uint8_t *out,
                                     size_t out_len)
{
    return build_echo(LICHEN_ICMPV6_ECHO_REQUEST, src, dst,
                      identifier, sequence, data, data_len, out, out_len);
}

int lichen_icmpv6_build_echo_reply(const struct in6_addr *src,
                                   const struct in6_addr *dst,
                                   uint16_t identifier,
                                   uint16_t sequence,
                                   const uint8_t *data,
                                   size_t data_len,
                                   uint8_t *out,
                                   size_t out_len)
{
    return build_echo(LICHEN_ICMPV6_ECHO_REPLY, src, dst,
                      identifier, sequence, data, data_len, out, out_len);
}

/**
 * Build ICMPv6 error message with invoking packet.
 */
static int build_error(uint8_t type,
                       uint8_t code,
                       uint32_t rest_of_header,
                       const struct in6_addr *src,
                       const struct in6_addr *dst,
                       const uint8_t *invoking_packet,
                       size_t invoking_len,
                       uint8_t *out,
                       size_t out_len)
{
    size_t quoted_len;
    size_t icmpv6_len;
    size_t total_len;
    uint16_t checksum;

    if (src == NULL || dst == NULL || out == NULL) {
        LOG_ERR("icmpv6: build_error failed (NULL input)");
        return -EINVAL;
    }

    /* SECURITY: Prevent information disclosure from uninitialized memory */
    if (invoking_len > 0 && invoking_packet == NULL) {
        LOG_ERR("icmpv6: build_error failed (invoking_len > 0 but invoking_packet is NULL)");
        return -EINVAL;
    }

    /* Limit quoted packet to prevent bloat */
    quoted_len = invoking_len;
    if (quoted_len > LICHEN_ICMPV6_MAX_INVOKING_PACKET) {
        quoted_len = LICHEN_ICMPV6_MAX_INVOKING_PACKET;
    }

    /* ICMPv6 error: type(1) + code(1) + checksum(2) + rest(4) + invoking */
    icmpv6_len = 8 + quoted_len;
    total_len = LICHEN_IPV6_HEADER_LEN + icmpv6_len;

    if (out_len < total_len) {
        return 0; /* Buffer too small */
    }

    /* Build IPv6 header */
    build_ipv6_header(out, src, dst, (uint16_t)icmpv6_len,
                      LICHEN_ICMPV6_NEXT_HEADER, DEFAULT_HOP_LIMIT);

    /* ICMPv6 header */
    uint8_t *icmpv6 = out + LICHEN_IPV6_HEADER_LEN;
    icmpv6[ICMPV6_TYPE_OFFSET] = type;
    icmpv6[ICMPV6_CODE_OFFSET] = code;
    icmpv6[ICMPV6_CHECKSUM_OFFSET] = 0;
    icmpv6[ICMPV6_CHECKSUM_OFFSET + 1] = 0;

    /* Rest of header (32-bit value) */
    icmpv6[ICMPV6_ERROR_REST_OFFSET] = (rest_of_header >> 24) & 0xFF;
    icmpv6[ICMPV6_ERROR_REST_OFFSET + 1] = (rest_of_header >> 16) & 0xFF;
    icmpv6[ICMPV6_ERROR_REST_OFFSET + 2] = (rest_of_header >> 8) & 0xFF;
    icmpv6[ICMPV6_ERROR_REST_OFFSET + 3] = rest_of_header & 0xFF;

    /* Invoking packet */
    if (quoted_len > 0 && invoking_packet != NULL) {
        memcpy(icmpv6 + ICMPV6_ERROR_INVOKING_OFFSET, invoking_packet, quoted_len);
    }

    /* Compute and fill checksum */
    checksum = lichen_icmpv6_checksum(src, dst, icmpv6, icmpv6_len);
    icmpv6[ICMPV6_CHECKSUM_OFFSET] = (checksum >> 8) & 0xFF;
    icmpv6[ICMPV6_CHECKSUM_OFFSET + 1] = checksum & 0xFF;

    if (total_len > (size_t)INT_MAX) {
        return -EOVERFLOW;
    }
    return (int)total_len;
}

int lichen_icmpv6_build_dest_unreachable(const struct in6_addr *src, const struct in6_addr *dst,
					 enum lichen_icmpv6_dest_unreach_code code,
					 const uint8_t *invoking_packet, size_t invoking_len,
					 uint8_t invoking_flags, uint8_t *out, size_t out_len)
{
	int suppression;

	if ((unsigned int)code > LICHEN_ICMPV6_REJECT_ROUTE) {
		return -EINVAL;
	}

	suppression =
	    error_suppression(src, dst, invoking_packet, invoking_len, invoking_flags, false);
	if (suppression != 0) {
		return suppression > 0 ? 0 : suppression;
	}

	/* Destination Unreachable: rest-of-header is unused (zeros) */
	return build_error(LICHEN_ICMPV6_DEST_UNREACHABLE, (uint8_t)code, 0, src, dst,
			   invoking_packet, invoking_len, out, out_len);
}

int lichen_icmpv6_build_packet_too_big(const struct in6_addr *src, const struct in6_addr *dst,
				       uint32_t mtu, const uint8_t *invoking_packet,
				       size_t invoking_len, uint8_t invoking_flags, uint8_t *out,
				       size_t out_len)
{
	int suppression;

	/* RFC 4443 section 3.2 permits PTB for multicast/broadcast packets. */
	suppression =
	    error_suppression(src, dst, invoking_packet, invoking_len, invoking_flags, true);
	if (suppression != 0) {
		return suppression > 0 ? 0 : suppression;
	}

	/* Packet Too Big: rest-of-header is the full 32-bit next-hop MTU. */
	return build_error(LICHEN_ICMPV6_PACKET_TOO_BIG, 0, mtu, src, dst, invoking_packet,
			   invoking_len, out, out_len);
}

int lichen_icmpv6_build_time_exceeded(const struct in6_addr *src,
                                      const struct in6_addr *dst,
                                      enum lichen_icmpv6_time_exceeded_code code,
                                      const uint8_t *invoking_packet,
                                      size_t invoking_len,
			      uint8_t invoking_flags,
                                      uint8_t *out,
                                      size_t out_len)
{
	int suppression;

	if ((unsigned int)code > LICHEN_ICMPV6_FRAGMENT_REASSEMBLY) {
		return -EINVAL;
	}

	suppression = error_suppression(src, dst, invoking_packet, invoking_len, invoking_flags, false);
	if (suppression != 0) {
		return suppression > 0 ? 0 : suppression;
	}

    /* Time Exceeded: rest-of-header is unused (zeros) */
    return build_error(LICHEN_ICMPV6_TIME_EXCEEDED, (uint8_t)code, 0,
                       src, dst, invoking_packet, invoking_len, out, out_len);
}

int lichen_icmpv6_build_param_problem(const struct in6_addr *src,
                                      const struct in6_addr *dst,
                                      enum lichen_icmpv6_param_problem_code code,
                                      uint32_t pointer,
                                      const uint8_t *invoking_packet,
                                      size_t invoking_len,
                                      uint8_t *out,
                                      size_t out_len)
{
    /* Parameter Problem: rest-of-header is the pointer */
    return build_error(LICHEN_ICMPV6_PARAM_PROBLEM, (uint8_t)code, pointer,
                       src, dst, invoking_packet, invoking_len, out, out_len);
}

int lichen_icmpv6_handle(const struct in6_addr *src,
                         const struct in6_addr *dst,
                         const uint8_t *icmpv6_data,
                         size_t icmpv6_len,
                         uint8_t request_flags,
                         uint8_t *reply_out,
                         size_t reply_out_len)
{
    struct lichen_icmpv6_msg msg;
    struct lichen_icmpv6_echo echo;
    int ret;

    if (src == NULL || dst == NULL || icmpv6_data == NULL || reply_out == NULL) {
        LOG_ERR("icmpv6: handle failed (NULL input)");
        return -EINVAL;
    }
    if ((request_flags & (uint8_t)~ECHO_REQUEST_FLAGS_MASK) != 0U) {
        return -EINVAL;
    }

    /* SECURITY: RFC 4443 section 2.3 requires checksum verification before
     * processing. Silently discard packets with invalid checksums. */
    if (!lichen_icmpv6_verify_checksum(src, dst, icmpv6_data, icmpv6_len)) {
        LOG_DBG("icmpv6: discarding packet with invalid checksum");
        return 0; /* Silent discard */
    }

    ret = lichen_icmpv6_parse(icmpv6_data, icmpv6_len, &msg);
    if (ret < 0) {
        return ret;
    }

    /* Only Echo Request generates a reply */
    if (msg.type != LICHEN_ICMPV6_ECHO_REQUEST) {
        LOG_DBG("icmpv6: received %s, no reply needed",
                lichen_icmpv6_type_str(msg.type));
        return 0;
    }

    /* Echo code is fixed at zero.  Invalid requests are discarded silently. */
    if (msg.code != 0U) {
        return 0;
    }

    /*
     * This API has no interface-address selector.  Suppress multicast and
     * known-anycast addresses rather than illegally sourcing from or replying
     * to them.  Callers may originate a reply explicitly once they have selected
     * a unicast interface address as required by RFC 4443 section 4.2.
     */
    if (ipv6_addr_is_unspecified(src->s6_addr) || ipv6_addr_is_multicast(src->s6_addr) ||
        ipv6_addr_is_unspecified(dst->s6_addr) || ipv6_addr_is_multicast(dst->s6_addr) ||
        (request_flags & (LICHEN_ICMPV6_ECHO_DESTINATION_ANYCAST |
                          LICHEN_ICMPV6_ECHO_SOURCE_ANYCAST)) != 0U) {
        return 0;
    }

    ret = lichen_icmpv6_parse_echo(&msg, &echo);
    if (ret < 0) {
        return ret;
    }

    LOG_INF("icmpv6: echo request id=0x%04x seq=%u, sending reply",
            echo.identifier, echo.sequence);

    /* Build reply: swap src/dst addresses */
    return lichen_icmpv6_build_echo_reply(dst, src,
                                          echo.identifier, echo.sequence,
                                          echo.data, echo.data_len,
                                          reply_out, reply_out_len);
}

const char *lichen_icmpv6_type_str(uint8_t type)
{
    switch (type) {
    case LICHEN_ICMPV6_DEST_UNREACHABLE:
        return "Destination Unreachable";
    case LICHEN_ICMPV6_PACKET_TOO_BIG:
        return "Packet Too Big";
    case LICHEN_ICMPV6_TIME_EXCEEDED:
        return "Time Exceeded";
    case LICHEN_ICMPV6_PARAM_PROBLEM:
        return "Parameter Problem";
    case LICHEN_ICMPV6_ECHO_REQUEST:
        return "Echo Request";
    case LICHEN_ICMPV6_ECHO_REPLY:
        return "Echo Reply";
    default:
        return "Unknown";
    }
}
