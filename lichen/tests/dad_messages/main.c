/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "dad.h"

static const uint8_t probe_1234[LICHEN_DAD_PACKET_LEN] = {
	0x60, 0, 0, 0, 0, 0x18, 0x3a, 0xff,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, 0, 0x12, 0x34,
	0x87, 0, 0x58, 0xbf, 0, 0, 0, 0,
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0x12, 0x34,
};

static const uint8_t conflict_1234[LICHEN_DAD_PACKET_LEN] = {
	0x60, 0, 0, 0, 0, 0x18, 0x3a, 0xff,
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0x12, 0x34,
	0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	0x88, 0, 0x39, 0x3f, 0x20, 0, 0, 0,
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0x12, 0x34,
};

static void test_canonical_vectors(void)
{
	uint8_t packet[LICHEN_DAD_PACKET_LEN];
	size_t len = 0;
	uint16_t short_addr = 0;

	assert(lichen_dad_build_probe(0x1234, packet, sizeof(packet), &len) == 0);
	assert(len == sizeof(probe_1234));
	assert(memcmp(packet, probe_1234, len) == 0);
	assert(lichen_dad_parse_probe(packet, len, &short_addr) == 0);
	assert(short_addr == 0x1234);

	assert(lichen_dad_build_conflict(0x1234, packet, sizeof(packet), &len) == 0);
	assert(memcmp(packet, conflict_1234, len) == 0);
	assert(lichen_dad_parse_conflict(packet, len, 0x1234) == 1);
	assert(lichen_dad_parse_conflict(packet, len, 0x1235) == 0);
}

static void test_bounds_reserved_and_malformed(void)
{
	uint8_t packet[LICHEN_DAD_PACKET_LEN];
	uint8_t before[LICHEN_DAD_PACKET_LEN];
	size_t len = 77;
	uint16_t short_addr;

	memset(packet, 0xa5, sizeof(packet));
	memcpy(before, packet, sizeof(packet));
	assert(lichen_dad_build_probe(0, packet, sizeof(packet), &len) == -EINVAL);
	assert(len == 77 && memcmp(packet, before, sizeof(packet)) == 0);
	assert(lichen_dad_build_probe(0xfffe, packet, sizeof(packet), &len) == -EINVAL);
	assert(lichen_dad_build_probe(0xffff, packet, sizeof(packet), &len) == -EINVAL);
	assert(lichen_dad_build_probe(0x1234, packet, sizeof(packet) - 1, &len) == -ENOBUFS);
	assert(lichen_dad_build_probe(0x1234, packet, sizeof(packet), &len) == 0);

	packet[7] = 64;
	assert(lichen_dad_parse_probe(packet, len, &short_addr) == -EBADMSG);
	memcpy(packet, probe_1234, sizeof(packet));
	packet[42] ^= 1;
	assert(lichen_dad_parse_probe(packet, len, &short_addr) == -EBADMSG);
	memcpy(packet, probe_1234, sizeof(packet));
	packet[8] = 1;
	assert(lichen_dad_parse_probe(packet, len, &short_addr) == -EBADMSG);
	assert(lichen_dad_parse_probe(probe_1234, len - 1, &short_addr) == -EBADMSG);

	memcpy(packet, conflict_1234, sizeof(packet));
	packet[44] |= 0x40;
	assert(lichen_dad_parse_conflict(packet, len, 0x1234) == -EBADMSG);
	memcpy(packet, conflict_1234, sizeof(packet));
	packet[44] |= 1;
	assert(lichen_dad_parse_conflict(packet, len, 0x1234) == -EBADMSG);
}

static void test_identity_and_exchange_state(void)
{
	const uint8_t challenger[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	const uint8_t owner[8] = { 8, 9, 10, 11, 12, 13, 14, 15 };
	struct lichen_dad_exchange exchange;
	uint8_t packet[LICHEN_DAD_PACKET_LEN];
	size_t len;

	assert(lichen_dad_conflict_for_probe(probe_1234, sizeof(probe_1234), 0x1234,
					     owner, owner, packet, sizeof(packet), &len) == -EACCES);
	assert(lichen_dad_conflict_for_probe(probe_1234, sizeof(probe_1234), 0x1235,
					     owner, challenger, packet, sizeof(packet), &len) == 0);
	assert(lichen_dad_conflict_for_probe(probe_1234, sizeof(probe_1234), 0x1234,
					     owner, challenger, packet, sizeof(packet), &len) == 1);
	assert(memcmp(packet, conflict_1234, len) == 0);

	assert(lichen_dad_exchange_init(&exchange, challenger, 0x1234) == 0);
	assert(lichen_dad_exchange_finish(&exchange) == -EAGAIN);
	for (unsigned int i = 0; i < LICHEN_DAD_PROBE_COUNT; ++i) {
		assert(lichen_dad_exchange_next_probe(&exchange, packet, sizeof(packet), &len) == 0);
	}
	assert(lichen_dad_exchange_next_probe(&exchange, packet, sizeof(packet), &len) == -EALREADY);
	assert(lichen_dad_exchange_finish(&exchange) == 0);

	assert(lichen_dad_exchange_init(&exchange, challenger, 0x1234) == 0);
	assert(lichen_dad_exchange_next_probe(&exchange, packet, sizeof(packet), &len) == 0);
	assert(lichen_dad_exchange_record_conflict(&exchange, conflict_1234,
						   sizeof(conflict_1234), challenger) == -EACCES);
	assert(lichen_dad_exchange_record_conflict(&exchange, conflict_1234,
						   sizeof(conflict_1234), owner) == 1);
	assert(exchange.conflict_detected && exchange.completed);
	assert(lichen_dad_exchange_next_probe(&exchange, packet, sizeof(packet), &len) == -EADDRINUSE);

	assert(lichen_dad_exchange_init(&exchange, challenger, 0x1234) == 0);
	assert(lichen_dad_exchange_cancel(&exchange) == 1);
	assert(lichen_dad_exchange_next_probe(&exchange, packet, sizeof(packet), &len) == -ECANCELED);
}

int main(void)
{
	test_canonical_vectors();
	test_bounds_reserved_and_malformed();
	test_identity_and_exchange_state();
	return 0;
}
