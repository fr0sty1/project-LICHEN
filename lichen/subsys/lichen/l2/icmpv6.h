/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file icmpv6.h
 * @brief LICHEN ICMPv6 implementation (RFC 4443, spec section 6.4)
 *
 * Implements ICMPv6 message types for diagnostics and error reporting:
 * - Echo Request/Reply (ping)
 * - Destination Unreachable
 * - Packet Too Big
 * - Time Exceeded
 * - Parameter Problem
 *
 * The checksum covers the IPv6 pseudo-header (source, destination,
 * upper-layer length, Next Header = 58) followed by the ICMPv6 message.
 *
 * This module provides standalone ICMPv6 utilities that can work with
 * or without Zephyr's full networking stack.
 */

#ifndef LICHEN_ICMPV6_H_
#define LICHEN_ICMPV6_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include "ipv6_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

/** ICMPv6 Next Header value (RFC 4443). */
#define LICHEN_ICMPV6_NEXT_HEADER 58

/** Minimum ICMPv6 header length (type, code, checksum). */
#define LICHEN_ICMPV6_HEADER_LEN 4

/** ICMPv6 Echo header length (type, code, checksum, identifier, sequence). */
#define LICHEN_ICMPV6_ECHO_HEADER_LEN 8

/** IPv6 header length (fixed 40 bytes). */
#define LICHEN_IPV6_HEADER_LEN 40

/**
 * Maximum size of invoking packet quoted in error messages.
 * RFC 4443 allows up to IPv6 minimum MTU (1280), but LICHEN frames
 * are much smaller, so a modest bound suffices and prevents bloat.
 */
#define LICHEN_ICMPV6_MAX_INVOKING_PACKET 256

/**
 * @brief ICMPv6 message types (RFC 4443).
 */
enum lichen_icmpv6_type {
    /** Type 1: Destination Unreachable */
    LICHEN_ICMPV6_DEST_UNREACHABLE = 1,
    /** Type 2: Packet Too Big */
    LICHEN_ICMPV6_PACKET_TOO_BIG = 2,
    /** Type 3: Time Exceeded */
    LICHEN_ICMPV6_TIME_EXCEEDED = 3,
    /** Type 4: Parameter Problem */
    LICHEN_ICMPV6_PARAM_PROBLEM = 4,
    /** Type 128: Echo Request */
    LICHEN_ICMPV6_ECHO_REQUEST = 128,
    /** Type 129: Echo Reply */
    LICHEN_ICMPV6_ECHO_REPLY = 129,
};

/**
 * @brief Destination Unreachable codes (RFC 4443 section 3.1).
 */
enum lichen_icmpv6_dest_unreach_code {
    /** Code 0: No route to destination */
    LICHEN_ICMPV6_NO_ROUTE = 0,
    /** Code 1: Communication administratively prohibited */
    LICHEN_ICMPV6_ADMIN_PROHIBITED = 1,
    /** Code 2: Beyond scope of source address */
    LICHEN_ICMPV6_BEYOND_SCOPE = 2,
    /** Code 3: Address unreachable */
    LICHEN_ICMPV6_ADDR_UNREACHABLE = 3,
    /** Code 4: Port unreachable */
    LICHEN_ICMPV6_PORT_UNREACHABLE = 4,
    /** Code 5: Source address failed ingress/egress policy */
    LICHEN_ICMPV6_SRC_ADDR_FAILED = 5,
    /** Code 6: Reject route to destination */
    LICHEN_ICMPV6_REJECT_ROUTE = 6,
};

/**
 * @brief Time Exceeded codes (RFC 4443 section 3.3).
 */
enum lichen_icmpv6_time_exceeded_code {
    /** Code 0: Hop limit exceeded in transit */
    LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED = 0,
    /** Code 1: Fragment reassembly time exceeded */
    LICHEN_ICMPV6_FRAGMENT_REASSEMBLY = 1,
};

/**
 * @brief Parameter Problem codes (RFC 4443 section 3.4).
 */
enum lichen_icmpv6_param_problem_code {
    /** Code 0: Erroneous header field encountered */
    LICHEN_ICMPV6_ERRONEOUS_HEADER = 0,
    /** Code 1: Unrecognized Next Header type */
    LICHEN_ICMPV6_UNRECOGNIZED_NEXT_HEADER = 1,
    /** Code 2: Unrecognized IPv6 option */
    LICHEN_ICMPV6_UNRECOGNIZED_OPTION = 2,
};

/**
 * @brief Generic ICMPv6 message structure.
 *
 * Represents a parsed ICMPv6 message without the checksum.
 * The body contains everything after the type/code/checksum header.
 */
struct lichen_icmpv6_msg {
    uint8_t type;
    uint8_t code;
    const uint8_t *body;
    size_t body_len;
};

/**
 * @brief Echo Request/Reply data.
 */
struct lichen_icmpv6_echo {
    uint16_t identifier;
    uint16_t sequence;
    const uint8_t *data;
    size_t data_len;
};

/**
 * @brief Compute 16-bit ones-complement Internet checksum (RFC 1071).
 *
 * @param data Data to checksum.
 * @param len Length of data in bytes.
 * @return 16-bit checksum.
 */
uint16_t lichen_internet_checksum(const uint8_t *data, size_t len);

/**
 * @brief Compute ICMPv6 checksum over pseudo-header and message.
 *
 * The ICMPv6 checksum covers:
 * - IPv6 pseudo-header: source (16), dest (16), length (4), zeros (3), NH (1)
 * - ICMPv6 message (with checksum field set to zero)
 *
 * @param src Source IPv6 address.
 * @param dst Destination IPv6 address.
 * @param icmpv6_data ICMPv6 message with checksum field set to zero.
 * @param icmpv6_len Length of ICMPv6 message.
 * @return 16-bit ICMPv6 checksum.
 */
uint16_t lichen_icmpv6_checksum(const struct in6_addr *src,
                                const struct in6_addr *dst,
                                const uint8_t *icmpv6_data,
                                size_t icmpv6_len);

/**
 * @brief Verify ICMPv6 checksum on a received message.
 *
 * SECURITY: RFC 4443 section 2.3 requires checksum verification before
 * processing. Silently discard packets with invalid checksums.
 *
 * @param src Source IPv6 address.
 * @param dst Destination IPv6 address.
 * @param icmpv6_data Raw ICMPv6 message (including checksum field).
 * @param icmpv6_len Length of ICMPv6 message.
 * @return true if checksum is valid, false otherwise.
 */
bool lichen_icmpv6_verify_checksum(const struct in6_addr *src,
                                   const struct in6_addr *dst,
                                   const uint8_t *icmpv6_data,
                                   size_t icmpv6_len);

/**
 * @brief Parse an ICMPv6 message from raw bytes.
 *
 * Does NOT verify the checksum - call lichen_icmpv6_verify_checksum() first.
 *
 * @param data Raw ICMPv6 message.
 * @param len Length of data.
 * @param msg Output parsed message (body points into original data).
 * @return 0 on success, -EINVAL if data is NULL or too short.
 */
int lichen_icmpv6_parse(const uint8_t *data, size_t len,
                        struct lichen_icmpv6_msg *msg);

/**
 * @brief Parse Echo Request/Reply body from an ICMPv6 message.
 *
 * @param msg Parsed ICMPv6 message (type must be 128 or 129).
 * @param echo Output echo data (data points into original message body).
 * @return 0 on success, -EINVAL if wrong type or body too short.
 */
int lichen_icmpv6_parse_echo(const struct lichen_icmpv6_msg *msg,
                             struct lichen_icmpv6_echo *echo);

/**
 * @brief Build an ICMPv6 Echo Request packet into a buffer.
 *
 * Constructs a complete IPv6 + ICMPv6 Echo Request packet with computed
 * checksum. Buffer must be at least (40 + 8 + data_len) bytes.
 *
 * @param src Source IPv6 address.
 * @param dst Destination IPv6 address.
 * @param identifier Echo identifier.
 * @param sequence Echo sequence number.
 * @param data Echo payload data (may be NULL if data_len is 0).
 * @param data_len Length of echo payload.
 * @param out Output buffer.
 * @param out_len Length of output buffer.
 * @return Bytes written on success (>= 48), 0 if buffer too small,
 *         negative errno on error.
 */
int lichen_icmpv6_build_echo_request(const struct in6_addr *src,
                                     const struct in6_addr *dst,
                                     uint16_t identifier,
                                     uint16_t sequence,
                                     const uint8_t *data,
                                     size_t data_len,
                                     uint8_t *out,
                                     size_t out_len);

/**
 * @brief Build an ICMPv6 Echo Reply packet into a buffer.
 *
 * Constructs a complete IPv6 + ICMPv6 Echo Reply packet with computed
 * checksum. Buffer must be at least (40 + 8 + data_len) bytes.
 *
 * @param src Source IPv6 address.
 * @param dst Destination IPv6 address.
 * @param identifier Echo identifier.
 * @param sequence Echo sequence number.
 * @param data Echo payload data (may be NULL if data_len is 0).
 * @param data_len Length of echo payload.
 * @param out Output buffer.
 * @param out_len Length of output buffer.
 * @return Bytes written on success (>= 48), 0 if buffer too small,
 *         negative errno on error.
 */
int lichen_icmpv6_build_echo_reply(const struct in6_addr *src,
                                   const struct in6_addr *dst,
                                   uint16_t identifier,
                                   uint16_t sequence,
                                   const uint8_t *data,
                                   size_t data_len,
                                   uint8_t *out,
                                   size_t out_len);

/**
 * @brief Build an ICMPv6 Destination Unreachable error message.
 *
 * Constructs a complete IPv6 + ICMPv6 Destination Unreachable packet.
 * Buffer must be at least (40 + 8 + min(invoking_len, MAX_INVOKING)) bytes.
 *
 * @param src Source IPv6 address (address generating the error).
 * @param dst Destination IPv6 address (original packet's source).
 * @param code Destination Unreachable code.
 * @param invoking_packet First bytes of the invoking packet.
 * @param invoking_len Length of invoking packet data.
 * @param out Output buffer.
 * @param out_len Length of output buffer.
 * @return Bytes written on success, 0 if buffer too small,
 *         negative errno on error.
 */
int lichen_icmpv6_build_dest_unreachable(const struct in6_addr *src,
                                         const struct in6_addr *dst,
                                         enum lichen_icmpv6_dest_unreach_code code,
                                         const uint8_t *invoking_packet,
                                         size_t invoking_len,
                                         uint8_t *out,
                                         size_t out_len);

/**
 * @brief Build an ICMPv6 Packet Too Big error message.
 *
 * Constructs a complete IPv6 + ICMPv6 Packet Too Big packet with the MTU
 * that should be used.
 *
 * @param src Source IPv6 address.
 * @param dst Destination IPv6 address.
 * @param mtu MTU value to advertise.
 * @param invoking_packet First bytes of the invoking packet.
 * @param invoking_len Length of invoking packet data.
 * @param out Output buffer.
 * @param out_len Length of output buffer.
 * @return Bytes written on success, 0 if buffer too small,
 *         negative errno on error.
 */
int lichen_icmpv6_build_packet_too_big(const struct in6_addr *src,
                                       const struct in6_addr *dst,
                                       uint32_t mtu,
                                       const uint8_t *invoking_packet,
                                       size_t invoking_len,
                                       uint8_t *out,
                                       size_t out_len);

/**
 * @brief Build an ICMPv6 Time Exceeded error message.
 *
 * @param src Source IPv6 address.
 * @param dst Destination IPv6 address.
 * @param code Time Exceeded code.
 * @param invoking_packet First bytes of the invoking packet.
 * @param invoking_len Length of invoking packet data.
 * @param out Output buffer.
 * @param out_len Length of output buffer.
 * @return Bytes written on success, 0 if buffer too small,
 *         negative errno on error.
 */
int lichen_icmpv6_build_time_exceeded(const struct in6_addr *src,
                                      const struct in6_addr *dst,
                                      enum lichen_icmpv6_time_exceeded_code code,
                                      const uint8_t *invoking_packet,
                                      size_t invoking_len,
                                      uint8_t *out,
                                      size_t out_len);

/**
 * @brief Build an ICMPv6 Parameter Problem error message.
 *
 * @param src Source IPv6 address.
 * @param dst Destination IPv6 address.
 * @param code Parameter Problem code.
 * @param pointer Byte offset in the invoking packet where the error was found.
 * @param invoking_packet First bytes of the invoking packet.
 * @param invoking_len Length of invoking packet data.
 * @param out Output buffer.
 * @param out_len Length of output buffer.
 * @return Bytes written on success, 0 if buffer too small,
 *         negative errno on error.
 */
int lichen_icmpv6_build_param_problem(const struct in6_addr *src,
                                      const struct in6_addr *dst,
                                      enum lichen_icmpv6_param_problem_code code,
                                      uint32_t pointer,
                                      const uint8_t *invoking_packet,
                                      size_t invoking_len,
                                      uint8_t *out,
                                      size_t out_len);

/**
 * @brief Handle an inbound ICMPv6 packet, generating a reply if needed.
 *
 * Verifies the checksum and processes the message. Only Echo Requests
 * produce a reply (Echo Reply with addresses swapped). Replies and error
 * messages are consumed without response.
 *
 * SECURITY: Per RFC 4443 section 2.3, messages with invalid checksums
 * are silently discarded.
 *
 * @param src Source IPv6 address of received packet.
 * @param dst Destination IPv6 address of received packet.
 * @param icmpv6_data Raw ICMPv6 message.
 * @param icmpv6_len Length of ICMPv6 message.
 * @param reply_out Buffer for reply packet (full IPv6 + ICMPv6).
 * @param reply_out_len Length of reply buffer.
 * @return Bytes written to reply_out if a reply is generated,
 *         0 if no reply needed (not an echo request or checksum failed),
 *         negative errno on error.
 */
int lichen_icmpv6_handle(const struct in6_addr *src,
                         const struct in6_addr *dst,
                         const uint8_t *icmpv6_data,
                         size_t icmpv6_len,
                         uint8_t *reply_out,
                         size_t reply_out_len);

/**
 * @brief Get human-readable name for ICMPv6 type.
 *
 * @param type ICMPv6 type value.
 * @return Type name string (never NULL).
 */
const char *lichen_icmpv6_type_str(uint8_t type);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_ICMPV6_H_ */
