/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lichen/udp_port_dispatch.h>

static int tests_run;
static int tests_passed;

#define ASSERT_TRUE(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		return 0; \
	} \
} while (0)
#define ASSERT_EQ(actual, expected, msg) ASSERT_TRUE((actual) == (expected), msg)

static int test_shared_port_vectors(void)
{
	static const struct {
		uint16_t port;
		enum lichen_udp_app_protocol app;
		enum lichen_udp_transport transport;
		int status;
	} cases[] = {
		{ 5681, LICHEN_UDP_APP_COMPACT_COT, LICHEN_UDP_TRANSPORT_RAW, 0 },
		{ 5682, LICHEN_UDP_APP_SENML, LICHEN_UDP_TRANSPORT_RAW, 0 },
		{ 5683, LICHEN_UDP_APP_COAP, LICHEN_UDP_TRANSPORT_COAP, 0 },
		{ 5684, LICHEN_UDP_APP_RESERVED_DTLS, LICHEN_UDP_TRANSPORT_UNUSED,
		  LICHEN_UDP_DISPATCH_ERR_RESERVED },
		{ 5685, LICHEN_UDP_APP_CAYENNE_LPP, LICHEN_UDP_TRANSPORT_RAW, 0 },
		{ 5686, LICHEN_UDP_APP_APRS_IS, LICHEN_UDP_TRANSPORT_RAW, 0 },
		{ 5687, LICHEN_UDP_APP_NMEA, LICHEN_UDP_TRANSPORT_RAW, 0 },
		{ 10883, LICHEN_UDP_APP_MQTT_SN, LICHEN_UDP_TRANSPORT_MQTT_SN, 0 },
		{ 9999, LICHEN_UDP_APP_UNKNOWN, LICHEN_UDP_TRANSPORT_UNKNOWN,
		  LICHEN_UDP_DISPATCH_ERR_UNKNOWN },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct lichen_udp_port_info info;
		int ret = lichen_udp_port_classify(cases[i].port, &info);

		ASSERT_EQ(ret, cases[i].status, "port status");
		ASSERT_EQ(info.app, cases[i].app, "port application");
		ASSERT_EQ(info.transport, cases[i].transport, "port transport");
	}
	return 1;
}

static int test_schc_568x_boundaries(void)
{
	ASSERT_TRUE(!lichen_udp_port_is_schc_568x(5679), "below prefix");
	ASSERT_TRUE(lichen_udp_port_is_schc_568x(5680), "prefix lower bound");
	ASSERT_TRUE(lichen_udp_port_is_schc_568x(5681), "assigned prefix port");
	ASSERT_TRUE(lichen_udp_port_is_schc_568x(5684), "reserved still compressible");
	ASSERT_TRUE(lichen_udp_port_is_schc_568x(5695), "prefix upper bound");
	ASSERT_TRUE(!lichen_udp_port_is_schc_568x(5696), "above prefix");
	ASSERT_TRUE(!lichen_udp_port_is_schc_568x(10883), "MQTT uses Rule 7");
	return 1;
}

static int test_mqtt_direction_rules(void)
{
	enum lichen_udp_mqtt_direction direction;
	uint16_t other;

	ASSERT_EQ(lichen_udp_mqtt_sn_rule_ports(10883, 49152, &direction, &other), 0,
		  "MQTT source match");
	ASSERT_EQ(direction, LICHEN_UDP_MQTT_SOURCE, "source direction zero");
	ASSERT_EQ(other, 49152, "destination is other port");
	ASSERT_EQ(lichen_udp_mqtt_sn_rule_ports(49152, 10883, &direction, &other), 0,
		  "MQTT destination match");
	ASSERT_EQ(direction, LICHEN_UDP_MQTT_DESTINATION, "destination direction one");
	ASSERT_EQ(other, 49152, "source is other port");
	ASSERT_EQ(lichen_udp_mqtt_sn_rule_ports(10883, 10883, &direction, &other), 0,
		  "both endpoints match");
	ASSERT_EQ(direction, LICHEN_UDP_MQTT_SOURCE, "both canonicalize source");
	ASSERT_EQ(other, 10883, "canonical both other port");
	ASSERT_EQ(lichen_udp_mqtt_sn_rule_ports(5683, 49152, &direction, &other),
		  LICHEN_UDP_DISPATCH_ERR_UNKNOWN, "no Rule 7 endpoint");
	return 1;
}

struct callback_capture {
	int calls;
	enum lichen_udp_app_protocol app;
	uint16_t source_port;
	uint16_t destination_port;
	uint8_t payload[16];
	size_t payload_len;
	int result;
};

static int capture_callback(enum lichen_udp_app_protocol app,
			    uint16_t source_port, uint16_t destination_port,
			    const uint8_t *payload, size_t payload_len,
			    void *user_data)
{
	struct callback_capture *capture = user_data;

	capture->calls++;
	capture->app = app;
	capture->source_port = source_port;
	capture->destination_port = destination_port;
	capture->payload_len = payload_len;
	if (payload_len <= sizeof(capture->payload)) {
		memcpy(capture->payload, payload, payload_len);
	}
	return capture->result;
}

static int test_network_byte_order_and_callback(void)
{
	/* src=49152 (c000), dst=10883 (2a83), len=11, checksum=1234. */
	const uint8_t datagram[] = {
		0xc0, 0x00, 0x2a, 0x83, 0x00, 0x0b, 0x12, 0x34,
		'm', 'q', 't'
	};
	struct callback_capture capture = { .result = 37 };

	ASSERT_EQ(lichen_udp_port_dispatch(datagram, sizeof(datagram), capture_callback,
					   &capture), 37,
		  "callback result propagated");
	ASSERT_EQ(capture.calls, 1, "callback once");
	ASSERT_EQ(capture.app, LICHEN_UDP_APP_MQTT_SN, "MQTT callback");
	ASSERT_EQ(capture.source_port, 49152, "source network order");
	ASSERT_EQ(capture.destination_port, 10883, "destination network order");
	ASSERT_EQ(capture.payload_len, 3, "payload length");
	ASSERT_EQ(memcmp(capture.payload, "mqt", 3), 0, "payload bytes");
	return 1;
}

static int test_destination_only_dispatch(void)
{
	/* Known source port must not claim a datagram sent to an unknown service. */
	const uint8_t source_mqtt[] = {
		0x2a, 0x83, 0x27, 0x0f, 0x00, 0x08, 0x12, 0x34
	};
	struct callback_capture capture = { 0 };

	ASSERT_EQ(lichen_udp_port_dispatch(source_mqtt, sizeof(source_mqtt),
					   capture_callback, &capture),
		  LICHEN_UDP_DISPATCH_ERR_UNKNOWN, "destination controls dispatch");
	ASSERT_EQ(capture.calls, 0, "unknown destination no callback");
	return 1;
}

static int test_reserved_unknown_and_malformed(void)
{
	uint8_t datagram[] = {
		0xc0, 0x00, 0x16, 0x34, 0x00, 0x08, 0x12, 0x34
	};
	struct callback_capture capture = { 0 };

	ASSERT_EQ(lichen_udp_port_dispatch(datagram, 7, capture_callback, &capture),
		  LICHEN_UDP_DISPATCH_ERR_TOO_SHORT, "truncated UDP header");
	datagram[5] = 9;
	ASSERT_EQ(lichen_udp_port_dispatch(datagram, sizeof(datagram), capture_callback,
					   &capture), LICHEN_UDP_DISPATCH_ERR_BAD_LENGTH,
		  "declared length mismatch");
	datagram[5] = 8;
	datagram[6] = 0;
	datagram[7] = 0;
	ASSERT_EQ(lichen_udp_port_dispatch(datagram, sizeof(datagram), capture_callback,
					   &capture), LICHEN_UDP_DISPATCH_ERR_BAD_CHECKSUM,
		  "zero IPv6 UDP checksum");
	datagram[6] = 0x12;
	datagram[7] = 0x34;
	ASSERT_EQ(lichen_udp_port_dispatch(datagram, sizeof(datagram), capture_callback,
					   &capture), LICHEN_UDP_DISPATCH_ERR_RESERVED,
		  "reserved 5684 rejected");
	datagram[2] = 0x16;
	datagram[3] = 0x30; /* 5680: compressible but unassigned */
	ASSERT_EQ(lichen_udp_port_dispatch(datagram, sizeof(datagram), capture_callback,
					   &capture), LICHEN_UDP_DISPATCH_ERR_UNKNOWN,
		  "unassigned 568x rejected");
	ASSERT_EQ(capture.calls, 0, "failures do not call callback");
	return 1;
}

static int test_null_contracts(void)
{
	uint8_t datagram[8] = { 0 };
	struct lichen_udp_port_info info;
	enum lichen_udp_mqtt_direction direction;
	uint16_t other;

	ASSERT_EQ(lichen_udp_port_classify(5683, NULL),
		  LICHEN_UDP_DISPATCH_ERR_INVALID, "NULL info");
	ASSERT_EQ(lichen_udp_mqtt_sn_rule_ports(10883, 1, NULL, &other),
		  LICHEN_UDP_DISPATCH_ERR_INVALID, "NULL direction");
	ASSERT_EQ(lichen_udp_mqtt_sn_rule_ports(10883, 1, &direction, NULL),
		  LICHEN_UDP_DISPATCH_ERR_INVALID, "NULL other port");
	ASSERT_EQ(lichen_udp_port_dispatch(NULL, 8, capture_callback, &info),
		  LICHEN_UDP_DISPATCH_ERR_INVALID, "NULL datagram");
	ASSERT_EQ(lichen_udp_port_dispatch(datagram, 8, NULL, &info),
		  LICHEN_UDP_DISPATCH_ERR_INVALID, "NULL callback");
	return 1;
}

int main(void)
{
	struct {
		const char *name;
		int (*fn)(void);
	} tests[] = {
		{ "shared port vectors", test_shared_port_vectors },
		{ "SCHC 568x boundaries", test_schc_568x_boundaries },
		{ "MQTT direction rules", test_mqtt_direction_rules },
		{ "network byte order and callback", test_network_byte_order_and_callback },
		{ "destination-only dispatch", test_destination_only_dispatch },
		{ "reserved/unknown/malformed", test_reserved_unknown_and_malformed },
		{ "NULL contracts", test_null_contracts },
	};

	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		tests_run++;
		printf("  %s: ", tests[i].name);
		if (tests[i].fn()) {
			tests_passed++;
			printf("PASS\n");
		}
	}
	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
