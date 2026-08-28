/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <lichen/meshtastic/adapter.h>

#ifdef CONFIG_ZTEST
#include <zephyr/ztest.h>
#define CHECK(condition, ...) zassert_true(condition, __VA_ARGS__)
#else
#define CHECK(condition, ...)                                                   \
	do {                                                                      \
		if (!(condition)) {                                                 \
			fprintf(stderr, __VA_ARGS__);                                 \
			fprintf(stderr, "\n");                                      \
			return false;                                                  \
		}                                                                 \
	} while (0)
#endif

_Static_assert(
	sizeof(((struct lichen_meshtastic_adapter_packet_info *)0)->payload_buf) ==
		LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX + 1U,
	"owned payload storage must include one terminator byte");
_Static_assert(
	offsetof(struct lichen_meshtastic_adapter_packet_info, payload_len) <
		offsetof(struct lichen_meshtastic_adapter_packet_info, payload_buf),
	"payload_len must precede the owned buffer in the established ABI");
_Static_assert(
	offsetof(struct lichen_meshtastic_adapter_packet_info, has_from) >=
		offsetof(struct lichen_meshtastic_adapter_packet_info, payload_buf) +
			sizeof(((struct lichen_meshtastic_adapter_packet_info *)0)
				       ->payload_buf),
	"owned payload storage overlaps the following member");

static bool test_layout_and_maximum_terminator(void)
{
	struct lichen_meshtastic_adapter_packet_info packet = { 0 };

	packet.payload_len = LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX;
	packet.payload = packet.payload_buf;
	for (size_t index = 0U; index < packet.payload_len; ++index) {
		packet.payload_buf[index] = (uint8_t)'x';
	}
	packet.payload_buf[packet.payload_len] = 0U;

	CHECK(packet.payload == packet.payload_buf, "payload does not reference storage");
	CHECK(packet.payload[packet.payload_len] == 0U,
	      "maximum payload has no terminator slot");
	CHECK(sizeof(packet.payload_buf) == LICHEN_MESHTASTIC_TEXT_PAYLOAD_MAX + 1U,
	      "runtime buffer size mismatch");
	return true;
}

#ifdef CONFIG_ZTEST
ZTEST(meshtastic_adapter_layout, layout_and_maximum_terminator)
{
	zassert_true(test_layout_and_maximum_terminator(), "layout test failed");
}

ZTEST_SUITE(meshtastic_adapter_layout, NULL, NULL, NULL, NULL, NULL);
#else
int main(void)
{
	if (!test_layout_and_maximum_terminator()) {
		return 1;
	}
	puts("Meshtastic adapter layout test passed");
	return 0;
}
#endif
