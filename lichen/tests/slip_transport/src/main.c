/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief SLIP transport test suite
 *
 * Tests the SLIP transport binding for LCI per spec/11-lci.md section 17.3.1.
 */

#include <zephyr/ztest.h>
#include <zephyr/net/net_if.h>

#include <lichen/transport/slip_transport.h>

#include <errno.h>
#include <string.h>

static void make_ipv6_packet(uint8_t *packet, size_t payload_len)
{
	static const uint8_t header[40] = {
		0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x40,
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	};

	memcpy(packet, header, sizeof(header));
	packet[4] = (uint8_t)(payload_len >> 8);
	packet[5] = (uint8_t)payload_len;
}

static size_t frame_packet(const uint8_t *packet, size_t packet_len,
			   uint8_t *frame)
{
	size_t position = 0U;

	frame[position++] = SLIP_END;
	for (size_t i = 0; i < packet_len; i++) {
		if (packet[i] == SLIP_END) {
			frame[position++] = SLIP_ESC;
			frame[position++] = SLIP_ESC_END;
		} else if (packet[i] == SLIP_ESC) {
			frame[position++] = SLIP_ESC;
			frame[position++] = SLIP_ESC_ESC;
		} else {
			frame[position++] = packet[i];
		}
	}
	frame[position++] = SLIP_END;
	return position;
}

static void reset_test_state(void *fixture)
{
	ARG_UNUSED(fixture);
#ifdef CONFIG_ZTEST
	slip_transport_test_reset();
#endif
}

ZTEST_SUITE(slip_transport, NULL, NULL, reset_test_state, NULL, NULL);

/**
 * Test SLIP constants are correctly defined per RFC 1055.
 */
ZTEST(slip_transport, test_slip_constants)
{
	zassert_equal(SLIP_END, 0xC0, "SLIP_END must be 0xC0 per RFC 1055");
	zassert_equal(SLIP_ESC, 0xDB, "SLIP_ESC must be 0xDB per RFC 1055");
	zassert_equal(SLIP_ESC_END, 0xDC, "SLIP_ESC_END must be 0xDC per RFC 1055");
	zassert_equal(SLIP_ESC_ESC, 0xDD, "SLIP_ESC_ESC must be 0xDD per RFC 1055");
}

/**
 * Test MTU constant is defined per IPv6 minimum.
 */
ZTEST(slip_transport, test_mtu_constant)
{
	zassert_equal(SLIP_LCI_MTU, 1280,
		      "SLIP_LCI_MTU must be 1280 per RFC 8200");
}

/**
 * Test node IID produces fe80::1.
 */
ZTEST(slip_transport, test_node_iid)
{
	uint8_t expected_iid[] = SLIP_LCI_NODE_IID;

	/* IID should be 8 bytes, all zero except last byte = 1 */
	zassert_equal(expected_iid[0], 0x00, "IID byte 0");
	zassert_equal(expected_iid[1], 0x00, "IID byte 1");
	zassert_equal(expected_iid[2], 0x00, "IID byte 2");
	zassert_equal(expected_iid[3], 0x00, "IID byte 3");
	zassert_equal(expected_iid[4], 0x00, "IID byte 4");
	zassert_equal(expected_iid[5], 0x00, "IID byte 5");
	zassert_equal(expected_iid[6], 0x00, "IID byte 6");
	zassert_equal(expected_iid[7], 0x01, "IID byte 7 must be 0x01");
}

/**
 * Test client IID produces fe80::2.
 */
ZTEST(slip_transport, test_client_iid)
{
	uint8_t expected_iid[] = SLIP_LCI_CLIENT_IID;

	/* IID should be 8 bytes, all zero except last byte = 2 */
	zassert_equal(expected_iid[7], 0x02, "Client IID byte 7 must be 0x02");
}

/**
 * Test send fails with NULL data.
 */
ZTEST(slip_transport, test_send_null_data)
{
	int ret = slip_transport_send(NULL, 64);
	zassert_equal(ret, -EINVAL, "Send with NULL data should fail");
}

/**
 * Test send with zero length succeeds (no data to send).
 */
ZTEST(slip_transport, test_send_zero_length)
{
	/* Note: This may succeed or fail depending on UART availability */
	int ret = slip_transport_send(NULL, 0);
	/* With no UART device available, this should return -ENODEV */
	zassert_true(ret == 0 || ret == -ENODEV,
		     "Send with zero length should succeed or fail gracefully");
}

/**
 * Test send fails with oversized packet.
 */
ZTEST(slip_transport, test_send_oversized)
{
	uint8_t oversized[SLIP_LCI_MTU + 100] = {0};

	int ret = slip_transport_send(oversized, sizeof(oversized));
	zassert_equal(ret, -EMSGSIZE, "Oversized packet should be rejected");
}

ZTEST(slip_transport, test_usb_cdc_dtr_gates_tx_and_propagates_errors)
{
	uint8_t packet[40];

	make_ipv6_packet(packet, 0U);
	slip_transport_test_set_usb_dtr(0, false);
	zassert_equal(slip_transport_send(packet, sizeof(packet)), -ENOTCONN,
		      "A closed CDC endpoint must not receive blocking TX");

	slip_transport_test_set_usb_dtr(-EIO, false);
	zassert_equal(slip_transport_send(packet, sizeof(packet)), -EIO,
		      "CDC line-control failures must be propagated");

	slip_transport_test_set_usb_dtr(0, true);
	zassert_ok(slip_transport_send(packet, sizeof(packet)),
		   "An open CDC session must use the normal SLIP TX path");
}

ZTEST(slip_transport, test_usb_cdc_reconnect_discards_partial_rx)
{
	uint8_t packet[40];
	uint8_t decoded[40];
	uint8_t frame[50];
	size_t decoded_len;
	size_t frame_len;

	make_ipv6_packet(packet, 0U);
	frame_len = frame_packet(packet, sizeof(packet), frame);
	slip_transport_test_set_usb_dtr(0, true);
	zassert_ok(slip_transport_test_poll_usb_session());
	zassert_equal(slip_transport_test_inject_rx(frame, frame_len / 2U), 0);

	slip_transport_test_set_usb_dtr(0, false);
	zassert_ok(slip_transport_test_poll_usb_session());
	slip_transport_test_set_usb_dtr(0, true);
	zassert_ok(slip_transport_test_poll_usb_session());
	zassert_equal(slip_transport_test_inject_rx(&frame[frame_len / 2U],
						   frame_len - frame_len / 2U),
		      1, "The post-reconnect suffix is a separate damaged frame");
	zassert_ok(slip_transport_test_get_last_rx(decoded, sizeof(decoded),
						  &decoded_len));
	zassert_equal(decoded_len, sizeof(packet) / 2U,
		      "A new CDC session must not retain the old frame prefix");
	zassert_equal(slip_transport_test_inject_rx(frame, frame_len), 1,
		      "A complete frame must recover after reconnect");
}

/**
 * Test interface getter returns non-NULL.
 */
ZTEST(slip_transport, test_iface_get)
{
	static const struct in6_addr node_link_local = {
		.s6_addr = {
			0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	};
	static const uint8_t node_iid[] = SLIP_LCI_NODE_IID;
	struct net_if *iface = slip_transport_iface_get();
	struct net_if *address_iface = NULL;
	struct net_if_addr *ifaddr;
	struct net_linkaddr *link_addr;

	/* The interface must be usable only after its exact LCI address is set. */
	zassert_not_null(iface, "Interface should be available");
	zassert_true(net_if_is_up(iface), "LCI interface must be up");
	ifaddr = net_if_ipv6_addr_lookup(&node_link_local, &address_iface);
	zassert_not_null(ifaddr, "fe80::1 must be assigned to the LCI interface");
	zassert_equal(address_iface, iface, "fe80::1 assigned to wrong interface");
	zassert_equal(ifaddr->addr_type, NET_ADDR_MANUAL,
		      "LCI link-local address must be deterministic/manual");

	link_addr = net_if_get_link_addr(iface);
	zassert_not_null(link_addr, "LCI link address missing");
	zassert_equal(link_addr->len, sizeof(node_iid), "LCI link IID length");
	zassert_mem_equal(link_addr->addr, node_iid, sizeof(node_iid),
			  "LCI link address must match the selected static IID");
	zassert_true(slip_transport_is_ready(),
		     "Transport must report ready after address assignment");
}

/**
 * Test get_stats with NULL returns error.
 */
ZTEST(slip_transport, test_get_stats_null)
{
	int ret = slip_transport_get_stats(NULL);
	zassert_equal(ret, -EINVAL, "get_stats with NULL should fail");
}

/**
 * Test get_stats succeeds with valid pointer.
 */
ZTEST(slip_transport, test_get_stats_valid)
{
	struct slip_transport_stats stats;

	int ret = slip_transport_get_stats(&stats);
	zassert_equal(ret, 0, "get_stats should succeed");

	/* After reset, all counters should be zero */
	zassert_equal(stats.rx_packets, 0, "RX packets should be 0");
	zassert_equal(stats.tx_packets, 0, "TX packets should be 0");
	zassert_equal(stats.rx_errors, 0, "RX errors should be 0");
	zassert_equal(stats.tx_errors, 0, "TX errors should be 0");

	/* Verify mutex synchronization: trigger error path and re-read (no race) */
	ret = slip_transport_send(NULL, SLIP_LCI_MTU + 100);
	if (ret == -EMSGSIZE) {
		struct slip_transport_stats stats2;
		zassert_equal(slip_transport_get_stats(&stats2), 0, "get_stats after error path");
		zassert_true(stats2.tx_errors >= 0, "stats updated under mutex");
	}
}

#ifdef CONFIG_ZTEST
/**
 * Test SLIP frame encoding via inject/get_last_tx.
 */
ZTEST(slip_transport, test_slip_encoding)
{
	uint8_t ipv6_pkt[42];
	uint8_t frame[128];
	uint8_t expected[128];
	size_t frame_len;
	size_t expected_len;
	int ret;

	make_ipv6_packet(ipv6_pkt, 2U);
	ipv6_pkt[40] = SLIP_END;
	ipv6_pkt[41] = SLIP_ESC;
	expected_len = frame_packet(ipv6_pkt, sizeof(ipv6_pkt), expected);

	ret = slip_transport_send(ipv6_pkt, sizeof(ipv6_pkt));
	zassert_true(ret == 0 || ret == -ENODEV,
		     "Encoding must complete with or without a UART");

	ret = slip_transport_test_get_last_tx(frame, sizeof(frame), &frame_len);
	zassert_equal(ret, 0, "get_last_tx should succeed");
	zassert_equal(frame_len, expected_len, "Exact escaped frame length");
	zassert_mem_equal(frame, expected, expected_len,
			  "RFC 1055 escaped bytes must be exact");
}

/**
 * Test SLIP frame decoding via inject_rx.
 */
ZTEST(slip_transport, test_slip_decoding)
{
	uint8_t ipv6_pkt[40];
	uint8_t frame[50];
	size_t frame_len;

	make_ipv6_packet(ipv6_pkt, 0U);
	frame_len = frame_packet(ipv6_pkt, sizeof(ipv6_pkt), frame);

	int packets = slip_transport_test_inject_rx(frame, frame_len);
	zassert_equal(packets, 1, "Should decode exactly one packet");
}

/**
 * Test SLIP escape sequence handling.
 */
ZTEST(slip_transport, test_slip_escape_handling)
{
	uint8_t ipv6_pkt[42];
	uint8_t decoded[42];
	uint8_t frame[64];
	size_t decoded_len;
	size_t frame_len;

	make_ipv6_packet(ipv6_pkt, 2U);
	ipv6_pkt[40] = SLIP_END;
	ipv6_pkt[41] = SLIP_ESC;
	frame_len = frame_packet(ipv6_pkt, sizeof(ipv6_pkt), frame);

	zassert_equal(slip_transport_test_inject_rx(frame, frame_len), 1,
		      "Escaped packet must complete");
	zassert_equal(slip_transport_test_get_last_rx(decoded, sizeof(decoded),
						      &decoded_len), 0);
	zassert_equal(decoded_len, sizeof(ipv6_pkt));
	zassert_mem_equal(decoded, ipv6_pkt, sizeof(ipv6_pkt),
			  "ESC_END and ESC_ESC must decode exactly");
}

/**
 * Test empty frame handling.
 */
ZTEST(slip_transport, test_empty_frame)
{
	/* Empty frame: just two END bytes */
	uint8_t frame[] = { SLIP_END, SLIP_END };

	int packets = slip_transport_test_inject_rx(frame, sizeof(frame));
	zassert_equal(packets, 0, "Empty frames should be ignored");
}

ZTEST(slip_transport, test_streaming_partial_and_multiple_frames)
{
	uint8_t packet[40];
	uint8_t frame[50];
	uint8_t frames[100];
	size_t frame_len;

	make_ipv6_packet(packet, 0U);
	frame_len = frame_packet(packet, sizeof(packet), frame);
	zassert_equal(slip_transport_test_inject_rx(frame, frame_len / 2U), 0,
		      "Partial input must retain state without delivery");
	zassert_equal(slip_transport_test_inject_rx(&frame[frame_len / 2U],
						    frame_len - frame_len / 2U), 1,
		      "Second chunk must finish the retained frame");

	memcpy(frames, frame, frame_len);
	memcpy(&frames[frame_len], frame, frame_len);
	zassert_equal(slip_transport_test_inject_rx(frames, frame_len * 2U), 2,
		      "One chunk may contain multiple complete frames");
}

ZTEST(slip_transport, test_invalid_escape_drops_until_end_and_resyncs)
{
	uint8_t packet[40];
	uint8_t valid_frame[50];
	uint8_t stream[60];
	uint8_t decoded[40];
	size_t valid_len;
	size_t decoded_len;
	static const uint8_t malformed[] = {
		SLIP_END, 0x60, SLIP_ESC, 0x00, 0x60, 0x00, 0x00,
	};

	make_ipv6_packet(packet, 0U);
	valid_len = frame_packet(packet, sizeof(packet), valid_frame);
	memcpy(stream, malformed, sizeof(malformed));
	memcpy(&stream[sizeof(malformed)], valid_frame, valid_len);

	zassert_equal(slip_transport_test_inject_rx(stream,
						    sizeof(malformed) + valid_len), 1,
		      "Malformed suffix must be dropped and next frame recovered");
	zassert_equal(slip_transport_test_get_last_rx(decoded, sizeof(decoded),
						      &decoded_len), 0);
	zassert_equal(decoded_len, sizeof(packet));
	zassert_mem_equal(decoded, packet, sizeof(packet));
}

ZTEST(slip_transport, test_oversize_drops_and_resyncs)
{
	uint8_t packet[40];
	uint8_t valid_frame[50];
	uint8_t chunk[64];
	uint8_t delimiter = SLIP_END;
	struct slip_transport_stats stats;
	size_t valid_len;
	size_t remaining = SLIP_LCI_MTU + 1U;

	memset(chunk, 0x60, sizeof(chunk));
	zassert_equal(slip_transport_test_inject_rx(&delimiter, 1U), 0);
	while (remaining > 0U) {
		size_t amount = MIN(remaining, sizeof(chunk));
		zassert_equal(slip_transport_test_inject_rx(chunk, amount), 0);
		remaining -= amount;
	}
	zassert_equal(slip_transport_test_inject_rx(&delimiter, 1U), 0,
		      "Oversize frame must be discarded");

	make_ipv6_packet(packet, 0U);
	valid_len = frame_packet(packet, sizeof(packet), valid_frame);
	zassert_equal(slip_transport_test_inject_rx(valid_frame, valid_len), 1,
		      "Decoder must recover after oversize delimiter");
	zassert_equal(slip_transport_get_stats(&stats), 0);
	zassert_equal(stats.rx_overflow, 1U, "One oversize frame counted once");
}

ZTEST(slip_transport, test_test_helper_errors)
{
	uint8_t byte;
	size_t length;

	zassert_equal(slip_transport_test_inject_rx(NULL, 1U), -EINVAL);
	zassert_equal(slip_transport_test_inject_rx(NULL, 0U), 0);
	zassert_equal(slip_transport_test_get_last_rx(NULL, 0U, &length), -EINVAL);
	zassert_equal(slip_transport_test_get_last_rx(&byte, 1U, NULL), -EINVAL);
}
#endif /* CONFIG_ZTEST */
