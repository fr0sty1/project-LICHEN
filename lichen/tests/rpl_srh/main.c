/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * RFC 6554 SRH codec tests.  The three-address wire image is copied from
 * test/vectors/source_route_hop_limit.json and is also consumed by Rust and
 * Python, so it is an independent cross-implementation oracle.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lichen/rpl_routing.h>

static int tests_run;
static int tests_passed;

#define ASSERT_TRUE(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		return 0; \
	} \
} while (0)

#define ASSERT_EQ(actual, expected, msg) \
	ASSERT_TRUE((actual) == (expected), msg)

static const uint8_t canonical_three_hop[] = {
	0x03, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x10,
	0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x11,
	0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x12,
};

static int test_canonical_vector_round_trip(void)
{
	struct lichen_rpl_srh srh;
	uint8_t encoded[sizeof(canonical_three_hop)];

	ASSERT_EQ(lichen_rpl_srh_parse(&srh, canonical_three_hop,
				       sizeof(canonical_three_hop)), LICHEN_RPL_OK,
		  "canonical parse");
	ASSERT_EQ(srh.segments_left, 3, "segments left");
	ASSERT_EQ(srh.num_addresses, 3, "address count");
	ASSERT_EQ(memcmp(srh.addresses[0], &canonical_three_hop[6], 48), 0,
		  "address order");
	ASSERT_EQ(lichen_rpl_srh_write(&srh, encoded, sizeof(encoded)),
		  (int)sizeof(encoded), "canonical write length");
	ASSERT_EQ(memcmp(encoded, canonical_three_hop, sizeof(encoded)), 0,
		  "canonical bytes");
	ASSERT_EQ(lichen_rpl_srh_hdr_ext_len(3), 6, "Hdr Ext Len");
	return 1;
}

static int test_reserved_bits_ignored_and_padding_rejected(void)
{
	struct lichen_rpl_srh srh;
	uint8_t wire[22] = { 3, 1, 0, 0x0f, 0xa5, 0x5a };
	uint8_t encoded[22];

	wire[6] = 0x02;
	ASSERT_EQ(lichen_rpl_srh_parse(&srh, wire, sizeof(wire)), LICHEN_RPL_OK,
		  "reserved fields ignored");
	ASSERT_EQ(lichen_rpl_srh_write(&srh, encoded, sizeof(encoded)), 22,
		  "reserved case re-encodes");
	ASSERT_EQ(encoded[3], 0, "reserved nibble canonicalized");
	ASSERT_EQ(encoded[4], 0, "reserved octet 1 canonicalized");
	ASSERT_EQ(encoded[5], 0, "reserved octet 2 canonicalized");

	wire[3] = 0x1f;
	ASSERT_EQ(lichen_rpl_srh_parse(&srh, wire, sizeof(wire)),
		  LICHEN_RPL_ERR_BAD_RT, "nonzero Pad rejected");
	return 1;
}

static int test_compression_and_type_rejected_atomically(void)
{
	struct lichen_rpl_srh srh;
	struct lichen_rpl_srh before;
	uint8_t wire[22] = { 3, 1, 0, 0, 0, 0 };
	static const uint8_t invalid_cmpr[] = { 0x01, 0x10, 0x0f, 0xf0, 0xff };

	memset(&srh, 0xa5, sizeof(srh));
	before = srh;
	for (size_t i = 0; i < sizeof(invalid_cmpr); i++) {
		wire[2] = invalid_cmpr[i];
		ASSERT_EQ(lichen_rpl_srh_parse(&srh, wire, sizeof(wire)),
			  LICHEN_RPL_ERR_BAD_RT, "compressed address rejected");
		ASSERT_EQ(memcmp(&srh, &before, sizeof(srh)), 0,
			  "failed parse leaves output unchanged");
	}
	wire[2] = 0;
	wire[0] = 4;
	ASSERT_EQ(lichen_rpl_srh_parse(&srh, wire, sizeof(wire)),
		  LICHEN_RPL_ERR_BAD_RT, "wrong routing type rejected");
	ASSERT_EQ(memcmp(&srh, &before, sizeof(srh)), 0,
		  "wrong type is atomic");
	return 1;
}

static int test_lengths_counts_and_limits(void)
{
	struct lichen_rpl_srh srh;
	uint8_t wire[6 + 16 * (LICHEN_RPL_MAX_HOPS + 1)] = { 3, 0, 0, 0, 0, 0 };
	uint8_t encoded[6 + 16 * LICHEN_RPL_MAX_HOPS];

	for (size_t len = 0; len < 6; len++) {
		ASSERT_EQ(lichen_rpl_srh_parse(&srh, wire, len),
			  LICHEN_RPL_ERR_TOO_SHORT, "truncated fixed header");
	}
	ASSERT_EQ(lichen_rpl_srh_parse(&srh, wire, 7), LICHEN_RPL_ERR_TOO_SHORT,
		  "misaligned address residue");
	ASSERT_EQ(lichen_rpl_srh_parse(&srh, wire, sizeof(wire)),
		  LICHEN_RPL_ERR_OVERRUN, "nine-address parse rejected");
	wire[1] = LICHEN_RPL_MAX_HOPS;
	ASSERT_EQ(lichen_rpl_srh_parse(&srh, wire, sizeof(encoded)), LICHEN_RPL_OK,
		  "eight-address parse accepted");
	ASSERT_EQ(srh.num_addresses, LICHEN_RPL_MAX_HOPS, "maximum address count");
	ASSERT_EQ(lichen_rpl_srh_write(&srh, encoded, sizeof(encoded)),
		  (int)sizeof(encoded), "eight-address write accepted");

	wire[1] = 0;
	ASSERT_EQ(lichen_rpl_srh_parse(&srh, wire, 6), LICHEN_RPL_OK,
		  "empty completed SRH accepted");
	ASSERT_EQ(srh.num_addresses, 0, "empty address count");
	wire[1] = 1;
	ASSERT_EQ(lichen_rpl_srh_parse(&srh, wire, 6), LICHEN_RPL_ERR_BAD_RT,
		  "segments exceed address count");
	return 1;
}

static int test_write_failures_are_atomic(void)
{
	struct lichen_rpl_srh srh = { .segments_left = 1, .num_addresses = 1 };
	uint8_t output[22];
	uint8_t before[22];

	srh.addresses[0][0] = 0x02;
	memset(output, 0xa5, sizeof(output));
	memcpy(before, output, sizeof(before));
	ASSERT_EQ(lichen_rpl_srh_write(&srh, output, sizeof(output) - 1),
		  LICHEN_RPL_ERR_BUF_SMALL, "short output rejected");
	ASSERT_EQ(memcmp(output, before, sizeof(output)), 0,
		  "short write leaves buffer unchanged");

	srh.segments_left = 2;
	ASSERT_EQ(lichen_rpl_srh_write(&srh, output, sizeof(output)),
		  LICHEN_RPL_ERR_INVALID, "invalid segment count rejected");
	ASSERT_EQ(memcmp(output, before, sizeof(output)), 0,
		  "invalid write leaves buffer unchanged");
	srh.segments_left = 0;
	srh.num_addresses = LICHEN_RPL_MAX_HOPS + 1;
	ASSERT_EQ(lichen_rpl_srh_write(&srh, output, sizeof(output)),
		  LICHEN_RPL_ERR_INVALID, "overlong route write rejected");
	return 1;
}

static int test_null_contracts(void)
{
	struct lichen_rpl_srh srh = { 0 };
	uint8_t wire[6] = { 3, 0, 0, 0, 0, 0 };

	ASSERT_EQ(lichen_rpl_srh_parse(NULL, wire, sizeof(wire)),
		  LICHEN_RPL_ERR_INVALID, "NULL parse output");
	ASSERT_EQ(lichen_rpl_srh_parse(&srh, NULL, sizeof(wire)),
		  LICHEN_RPL_ERR_INVALID, "NULL parse input");
	ASSERT_EQ(lichen_rpl_srh_write(NULL, wire, sizeof(wire)),
		  LICHEN_RPL_ERR_INVALID, "NULL write input");
	ASSERT_EQ(lichen_rpl_srh_write(&srh, NULL, sizeof(wire)),
		  LICHEN_RPL_ERR_INVALID, "NULL write output");
	ASSERT_EQ(lichen_rpl_srh_check_nonstoring(NULL, wire),
		  LICHEN_RPL_ERR_INVALID, "NULL profile SRH");
	ASSERT_EQ(lichen_rpl_srh_check_nonstoring(&srh, NULL),
		  LICHEN_RPL_ERR_INVALID, "NULL local address");
	return 1;
}

static int test_nonstoring_profile_check(void)
{
	struct lichen_rpl_srh srh = { .segments_left = 1, .num_addresses = 1 };
	uint8_t local[16] = { 0xfe, 0x80 };

	memcpy(srh.addresses[0], local, sizeof(local));
	ASSERT_EQ(lichen_rpl_srh_check_nonstoring(&srh, local),
		  LICHEN_RPL_ERR_BAD_RT, "self-target rejected");
	srh.addresses[0][15] = 1;
	ASSERT_EQ(lichen_rpl_srh_check_nonstoring(&srh, local), LICHEN_RPL_OK,
		  "distinct next hop accepted");
	srh.num_addresses = 0;
	ASSERT_EQ(lichen_rpl_srh_check_nonstoring(&srh, local),
		  LICHEN_RPL_ERR_BAD_RT, "empty forwarding route rejected");
	return 1;
}

static void make_addr(uint8_t addr[16], uint8_t last)
{
	memset(addr, 0, 16);
	addr[0] = 0x02;
	addr[15] = last;
}

static int test_intermediate_two_hop_destination_swap(void)
{
	struct lichen_rpl_srh srh = { .segments_left = 2, .num_addresses = 2 };
	uint8_t source[16];
	uint8_t relay1[16];
	uint8_t relay2[16];
	uint8_t final[16];
	uint8_t destination[16];
	uint8_t next_hop[16] = { 0 };
	uint8_t hop_limit = 3;

	make_addr(source, 1);
	make_addr(relay1, 2);
	make_addr(relay2, 3);
	make_addr(final, 4);
	memcpy(destination, relay1, 16);
	memcpy(srh.addresses[0], relay2, 16);
	memcpy(srh.addresses[1], final, 16);

	ASSERT_EQ(lichen_rpl_srh_advance(&srh, source, destination, &hop_limit,
					 next_hop), LICHEN_RPL_SRH_FORWARD,
		  "relay 1 forwards");
	ASSERT_EQ(memcmp(next_hop, relay2, 16), 0, "relay 2 next hop");
	ASSERT_EQ(memcmp(destination, relay2, 16), 0, "destination becomes relay 2");
	ASSERT_EQ(memcmp(srh.addresses[0], relay1, 16), 0, "relay 1 swapped into SRH");
	ASSERT_EQ(srh.segments_left, 1, "one segment remains");
	ASSERT_EQ(hop_limit, 2, "hop limit decremented once");

	ASSERT_EQ(lichen_rpl_srh_advance(&srh, source, destination, &hop_limit,
					 next_hop), LICHEN_RPL_SRH_FORWARD,
		  "relay 2 forwards");
	ASSERT_EQ(memcmp(next_hop, final, 16), 0, "final next hop");
	ASSERT_EQ(memcmp(destination, final, 16), 0, "destination becomes final");
	ASSERT_EQ(memcmp(srh.addresses[1], relay2, 16), 0, "relay 2 swapped into SRH");
	ASSERT_EQ(srh.segments_left, 0, "route consumed");
	ASSERT_EQ(hop_limit, 1, "second hop decrement");

	memset(next_hop, 0xa5, sizeof(next_hop));
	ASSERT_EQ(lichen_rpl_srh_advance(&srh, source, destination, &hop_limit,
					 next_hop), LICHEN_RPL_SRH_COMPLETE,
		  "final destination completes");
	ASSERT_EQ(hop_limit, 1, "completed route does not decrement");
	ASSERT_EQ(next_hop[0], 0xa5, "completed route has no next hop");
	return 1;
}

static int assert_advance_error_atomic(struct lichen_rpl_srh *srh,
				       const uint8_t source[16],
				       uint8_t destination[16], uint8_t *hop_limit,
				       const char *msg)
{
	struct lichen_rpl_srh before_srh = *srh;
	uint8_t before_destination[16];
	uint8_t before_hop_limit = *hop_limit;
	uint8_t next_hop[16];
	uint8_t before_next_hop[16];

	memcpy(before_destination, destination, 16);
	memset(next_hop, 0xa5, sizeof(next_hop));
	memcpy(before_next_hop, next_hop, sizeof(next_hop));
	ASSERT_TRUE(lichen_rpl_srh_advance(srh, source, destination, hop_limit,
					   next_hop) < 0, msg);
	ASSERT_EQ(memcmp(srh, &before_srh, sizeof(*srh)), 0, "SRH error atomic");
	ASSERT_EQ(memcmp(destination, before_destination, 16), 0,
		  "destination error atomic");
	ASSERT_EQ(*hop_limit, before_hop_limit, "hop-limit error atomic");
	ASSERT_EQ(memcmp(next_hop, before_next_hop, 16), 0,
		  "next-hop error atomic");
	return 1;
}

static int test_hop_limit_vector_boundaries(void)
{
	struct lichen_rpl_srh srh = { .segments_left = 3, .num_addresses = 3 };
	uint8_t source[16];
	uint8_t destination[16];
	uint8_t next_hop[16];
	uint8_t hop_limit;

	make_addr(source, 1);
	make_addr(destination, 2);
	make_addr(srh.addresses[0], 3);
	make_addr(srh.addresses[1], 4);
	make_addr(srh.addresses[2], 5);

	hop_limit = 4;
	ASSERT_EQ(lichen_rpl_srh_advance(&srh, source, destination, &hop_limit,
					 next_hop), LICHEN_RPL_SRH_FORWARD,
		  "segments 3 < hop limit 4");

	srh.segments_left = 3;
	make_addr(destination, 2);
	make_addr(srh.addresses[0], 3);
	hop_limit = 3;
	if (!assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					 "segments equal hop limit rejected")) {
		return 0;
	}
	hop_limit = 2;
	if (!assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					 "segments exceed hop limit rejected")) {
		return 0;
	}
	hop_limit = 0;
	srh.segments_left = 0;
	return assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					   "zero hop limit rejected");
}

static int test_route_security_rejections(void)
{
	struct lichen_rpl_srh srh = { .segments_left = 2, .num_addresses = 2 };
	uint8_t source[16];
	uint8_t destination[16];
	uint8_t hop_limit = 3;

	make_addr(source, 1);
	make_addr(destination, 2);
	make_addr(srh.addresses[0], 3);
	make_addr(srh.addresses[1], 4);

	memcpy(srh.addresses[1], srh.addresses[0], 16);
	if (!assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					 "duplicate route hop rejected")) {
		return 0;
	}
	make_addr(srh.addresses[1], 4);
	memcpy(srh.addresses[1], source, 16);
	if (!assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					 "packet source in route rejected")) {
		return 0;
	}
	make_addr(srh.addresses[1], 4);
	memcpy(srh.addresses[1], destination, 16);
	if (!assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					 "current destination in route rejected")) {
		return 0;
	}
	make_addr(srh.addresses[1], 4);
	srh.addresses[1][0] = 0xff;
	if (!assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					 "multicast route hop rejected")) {
		return 0;
	}
	make_addr(srh.addresses[1], 4);
	source[0] = 0xff;
	if (!assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					 "multicast source rejected")) {
		return 0;
	}
	make_addr(source, 1);
	destination[0] = 0xff;
	if (!assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					 "multicast destination rejected")) {
		return 0;
	}
	make_addr(destination, 2);
	memcpy(source, destination, 16);
	if (!assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					 "source equals destination rejected")) {
		return 0;
	}
	make_addr(source, 1);
	srh.segments_left = 3;
	if (!assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					 "segments exceed vector rejected")) {
		return 0;
	}
	srh.segments_left = 2;
	srh.num_addresses = LICHEN_RPL_MAX_HOPS + 1;
	return assert_advance_error_atomic(&srh, source, destination, &hop_limit,
					   "overlong vector rejected");
}

static int test_advance_null_contracts(void)
{
	struct lichen_rpl_srh srh = { 0 };
	uint8_t source[16] = { 0x02 };
	uint8_t destination[16] = { 0x02 };
	uint8_t next_hop[16];
	uint8_t hop_limit = 1;

	ASSERT_EQ(lichen_rpl_srh_advance(NULL, source, destination, &hop_limit,
					 next_hop), LICHEN_RPL_ERR_INVALID,
		  "NULL SRH");
	ASSERT_EQ(lichen_rpl_srh_advance(&srh, NULL, destination, &hop_limit,
					 next_hop), LICHEN_RPL_ERR_INVALID,
		  "NULL source");
	ASSERT_EQ(lichen_rpl_srh_advance(&srh, source, NULL, &hop_limit,
					 next_hop), LICHEN_RPL_ERR_INVALID,
		  "NULL destination");
	ASSERT_EQ(lichen_rpl_srh_advance(&srh, source, destination, NULL,
					 next_hop), LICHEN_RPL_ERR_INVALID,
		  "NULL hop limit");
	ASSERT_EQ(lichen_rpl_srh_advance(&srh, source, destination, &hop_limit,
					 NULL), LICHEN_RPL_ERR_INVALID,
		  "NULL next hop");
	return 1;
}

int main(void)
{
	struct {
		const char *name;
		int (*fn)(void);
	} tests[] = {
		{ "canonical vector round trip", test_canonical_vector_round_trip },
		{ "reserved and padding fields", test_reserved_bits_ignored_and_padding_rejected },
		{ "compression/type atomic rejection", test_compression_and_type_rejected_atomically },
		{ "lengths, counts, and limits", test_lengths_counts_and_limits },
		{ "atomic write failures", test_write_failures_are_atomic },
		{ "NULL contracts", test_null_contracts },
		{ "non-storing profile check", test_nonstoring_profile_check },
		{ "intermediate two-hop destination swap", test_intermediate_two_hop_destination_swap },
		{ "hop-limit vector boundaries", test_hop_limit_vector_boundaries },
		{ "route security rejection", test_route_security_rejections },
		{ "advance NULL contracts", test_advance_null_contracts },
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
