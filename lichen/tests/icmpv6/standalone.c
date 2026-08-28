/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "icmpv6.h"

static const struct in6_addr error_src = {
	.s6_addr = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};

static const struct in6_addr original_src = {
	.s6_addr = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}};

static void make_udp_packet(uint8_t *packet, size_t packet_len)
{
	size_t payload_len = packet_len - LICHEN_IPV6_HEADER_LEN;

	memset(packet, 0, packet_len);
	packet[0] = 0x60;
	packet[4] = (uint8_t)(payload_len >> 8);
	packet[5] = (uint8_t)payload_len;
	packet[6] = 17;
	packet[7] = 64;
	memcpy(&packet[8], original_src.s6_addr, 16);
	memcpy(&packet[24], error_src.s6_addr, 16);
}

int main(void)
{
	uint8_t invoking[48];
	uint8_t echo_request[64];
	uint8_t output[sizeof(invoking) + 48U];
	int ret;
	int echo_len;

	echo_len = lichen_icmpv6_build_echo_request(&error_src, &original_src, 0x1234, 7,
						   (const uint8_t *)"ping", 4U, echo_request,
						   sizeof(echo_request));
	assert(echo_len == 52);
	ret = lichen_icmpv6_handle(&error_src, &original_src, &echo_request[40],
				   (size_t)echo_len - 40U, LICHEN_ICMPV6_ECHO_DESTINATION_UNICAST,
				   output, sizeof(output));
	assert(ret == echo_len);
	assert(output[40] == LICHEN_ICMPV6_ECHO_REPLY);
	assert(output[41] == 0);
	assert(memcmp(&output[8], original_src.s6_addr, 16U) == 0);
	assert(memcmp(&output[24], error_src.s6_addr, 16U) == 0);
	assert(memcmp(&output[44], "\x12\x34\0\7ping", 8U) == 0);
	assert(lichen_icmpv6_verify_checksum(&original_src, &error_src, &output[40],
					     (size_t)ret - 40U));

	make_udp_packet(invoking, sizeof(invoking));
	ret = lichen_icmpv6_build_dest_unreachable(
	    &error_src, &original_src, LICHEN_ICMPV6_PORT_UNREACHABLE, invoking, sizeof(invoking),
	    LICHEN_ICMPV6_INVOKING_UNICAST, output, sizeof(output));
	assert(ret == (int)sizeof(output));
	assert(output[40] == LICHEN_ICMPV6_DEST_UNREACHABLE);
	assert(output[41] == LICHEN_ICMPV6_PORT_UNREACHABLE);
	assert(lichen_icmpv6_verify_checksum(&error_src, &original_src, &output[40],
					     sizeof(output) - 40U));

	ret = lichen_icmpv6_build_packet_too_big(
	    &error_src, &original_src, LICHEN_IPV6_MIN_MTU, invoking, sizeof(invoking),
	    LICHEN_ICMPV6_INVOKING_UNICAST, output, sizeof(output));
	assert(ret == (int)sizeof(output));
	assert(output[40] == LICHEN_ICMPV6_PACKET_TOO_BIG);
	assert(output[41] == 0);
	assert(memcmp(&output[44], "\0\0\5\0", 4U) == 0);
	assert(lichen_icmpv6_verify_checksum(&error_src, &original_src, &output[40],
					     sizeof(output) - 40U));

	ret = lichen_icmpv6_build_time_exceeded(
		&error_src, &original_src, LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED, invoking,
		sizeof(invoking), LICHEN_ICMPV6_INVOKING_UNICAST, output, sizeof(output));
	assert(ret == (int)sizeof(output));
	assert(output[40] == LICHEN_ICMPV6_TIME_EXCEEDED);
	assert(output[41] == LICHEN_ICMPV6_HOP_LIMIT_EXCEEDED);
	assert(memcmp(&output[44], "\0\0\0\0", 4U) == 0);
	assert(lichen_icmpv6_verify_checksum(&error_src, &original_src, &output[40],
					     sizeof(output) - 40U));

	memset(output, 0xa5, sizeof(output));
	invoking[24] = 0xff;
	ret = lichen_icmpv6_build_dest_unreachable(
	    &error_src, &original_src, LICHEN_ICMPV6_NO_ROUTE, invoking, sizeof(invoking),
	    LICHEN_ICMPV6_INVOKING_UNICAST, output, sizeof(output));
	assert(ret == 0);
	for (size_t i = 0; i < sizeof(output); ++i) {
		assert(output[i] == 0xa5);
	}

	make_udp_packet(invoking, sizeof(invoking));
	ret = lichen_icmpv6_build_packet_too_big(
	    &error_src, &original_src, LICHEN_IPV6_MIN_MTU, invoking, sizeof(invoking),
	    LICHEN_ICMPV6_INVOKING_LINK_BROADCAST, output, sizeof(output));
	assert(ret == (int)sizeof(output));

	return 0;
}
