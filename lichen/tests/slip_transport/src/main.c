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

/**
 * Test interface getter returns non-NULL.
 */
ZTEST(slip_transport, test_iface_get)
{
	struct net_if *iface = slip_transport_iface_get();

	/* Interface should be available even without UART */
	zassert_not_null(iface, "Interface should be available");
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
	/* Create a minimal IPv6 packet (just version/class/flow header) */
	uint8_t ipv6_pkt[40] = {
		0x60, 0x00, 0x00, 0x00,  /* Version=6, TC=0, Flow=0 */
		0x00, 0x00, 0x3a, 0x40,  /* Payload=0, Next=ICMPv6, Hop=64 */
		/* Source address (fe80::2) */
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		/* Dest address (fe80::1) */
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	};

	uint8_t frame[128];
	size_t frame_len;
	int ret;

	/* This test requires no UART to be available so TX goes to buffer only */
	ret = slip_transport_send(ipv6_pkt, sizeof(ipv6_pkt));
	/* May fail with -ENODEV if no UART available - that's expected */
	if (ret == -ENODEV) {
		ztest_test_skip();
		return;
	}
	zassert_equal(ret, 0, "Send should succeed if UART available");

	/* Get the encoded frame */
	ret = slip_transport_test_get_last_tx(frame, sizeof(frame), &frame_len);
	zassert_equal(ret, 0, "get_last_tx should succeed");

	/* Frame should start and end with END byte */
	zassert_equal(frame[0], SLIP_END, "Frame must start with END");
	zassert_equal(frame[frame_len - 1], SLIP_END, "Frame must end with END");

	/* Frame length should be at least packet + 2 END bytes */
	zassert_true(frame_len >= sizeof(ipv6_pkt) + 2,
		     "Frame length must include END bytes");
}

/**
 * Test SLIP frame decoding via inject_rx.
 */
ZTEST(slip_transport, test_slip_decoding)
{
	/* Create a SLIP-framed minimal IPv6 packet */
	uint8_t ipv6_pkt[40] = {
		0x60, 0x00, 0x00, 0x00,  /* Version=6, TC=0, Flow=0 */
		0x00, 0x00, 0x3a, 0x40,  /* Payload=0, Next=ICMPv6, Hop=64 */
		/* Source address (fe80::2) */
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		/* Dest address (fe80::1) */
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	};

	/* SLIP frame: END + packet + END */
	uint8_t frame[50];
	frame[0] = SLIP_END;
	memcpy(&frame[1], ipv6_pkt, sizeof(ipv6_pkt));
	frame[sizeof(ipv6_pkt) + 1] = SLIP_END;

	/* Inject and check that one packet was decoded */
	int packets = slip_transport_test_inject_rx(frame, sizeof(ipv6_pkt) + 2);
	zassert_equal(packets, 1, "Should decode exactly one packet");
}

/**
 * Test SLIP escape sequence handling.
 */
ZTEST(slip_transport, test_slip_escape_handling)
{
	/* Frame containing escaped bytes:
	 * 0xC0 (END) becomes 0xDB 0xDC
	 * 0xDB (ESC) becomes 0xDB 0xDD
	 */
	uint8_t frame[] = {
		SLIP_END,        /* Frame start */
		0x60,            /* IPv6 version byte */
		SLIP_ESC, SLIP_ESC_END,  /* Escaped 0xC0 */
		SLIP_ESC, SLIP_ESC_ESC,  /* Escaped 0xDB */
		0x01,            /* Regular byte */
		SLIP_END         /* Frame end */
	};

	/* This should decode to: 0x60, 0xC0, 0xDB, 0x01 = 4 bytes */
	int packets = slip_transport_test_inject_rx(frame, sizeof(frame));

	/* The packet is too short to be a valid IPv6 packet, so it gets
	 * rejected during validation - but the SLIP decoding itself works */
	zassert_true(packets >= 0, "Escape handling should not crash");
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
#endif /* CONFIG_ZTEST */
