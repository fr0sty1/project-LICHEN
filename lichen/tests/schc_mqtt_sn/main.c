/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/schc.h>

#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define CHECK(c) do { if (!(c)) { \
	printf("FAIL line %d: %s\n", __LINE__, #c); return 1; \
} } while (0)

struct vector {
	const char *packet;
	const char *compressed;
};

static int nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return c - 'A' + 10;
}

static size_t decode(const char *hex, uint8_t *out, size_t capacity)
{
	size_t n = strlen(hex) / 2;

	if (n > capacity || strlen(hex) % 2 != 0) return 0;
	for (size_t i = 0; i < n; i++) {
		out[i] = (uint8_t)((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
	}
	return n;
}

static const struct vector vectors[] = {
	{
		"60000000000c1140fe800000000000000000000000000001fe8000000000000000000000000000022a831388000cdcec74657374",
		"07400000000000000000800000000000000104e20074657374",
	},
	{
		"6000000000081140fe800000000000000000000000000001fe8000000000000000000000000000022a8313880008c4ce",
		"07400000000000000000800000000000000104e200",
	},
	{
		"60000000000f1140fe800000000000000000000000000001fe80000000000000000000000000000213882a83000f197f636f6e6e656374",
		"07400000000000000000800000000000000144e200636f6e6e656374",
	},
	{
		"6000000000091140fe800000000000000000000000000001fe8000000000000000000000000000022a832a83000935d178",
		"0740000000000000000080000000000000010aa0c078",
	},
	{
		"60000000000b114020010db800000000000000000000000120010db80000000000000000000000022a8322b8000b84b2707562",
		"0740900086dc000000000000000000000000900086dc00000000000000000000000108ae00707562",
	},
	{
		"6000000000091140fe80000000000000000000000000000120010db80000000000000000000000022a831388000928946d",
		"0740ff400000000000000000000000000000900086dc00000000000000000000000104e2006d",
	},
};

static int test_vectors(void)
{
	uint8_t packet[256], compressed[256], actual[256], restored[256];

	for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
		size_t packet_len = decode(vectors[i].packet, packet, sizeof(packet));
		size_t compressed_len = decode(vectors[i].compressed, compressed,
					       sizeof(compressed));
		int n = lichen_schc_compress(packet, packet_len, actual, sizeof(actual));
		CHECK(n == (int)compressed_len);
		CHECK(memcmp(actual, compressed, compressed_len) == 0);
		int m = lichen_schc_decompress(compressed, compressed_len, restored,
					       sizeof(restored));
		CHECK(m == (int)packet_len);
		CHECK(memcmp(restored, packet, packet_len) == 0);
	}
	return 0;
}

static int expect_malformed(const char *hex)
{
	uint8_t compressed[256], out[256];
	size_t len = decode(hex, compressed, sizeof(compressed));

	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_decompress(compressed, len, out, sizeof(out)) < 0);
	CHECK(out[0] == 0xA5);
	return 0;
}

static int test_rejections(void)
{
	CHECK(expect_malformed("07400000000000000000800000000000000104e2") == 0);
	CHECK(expect_malformed("07400000000000000000800000000000000104e20174657374") == 0);
	CHECK(expect_malformed("0740000000000000000080000000000000014aa0c078") == 0);
	CHECK(expect_malformed("0740ff400000000000000000000000000000ff40000000000000000000000000000104e20078") == 0);
	CHECK(expect_malformed("0740ff810000000000000000000000000000900086dc00000000000000000000000104e20078") == 0);
	CHECK(expect_malformed("0740900086dc0000000000000000000000008000000000000000000000000000000004e20078") == 0);

	uint8_t packet[256], out[256];
	size_t len = decode(vectors[0].packet, packet, sizeof(packet));
	packet[46] ^= 1; /* Invalid nonzero UDP checksum must be dropped, not fallback. */
	memset(out, 0xA5, sizeof(out));
	CHECK(lichen_schc_compress(packet, len, out, sizeof(out)) < 0);
	CHECK(out[0] == 0xA5);

	len = decode(vectors[0].packet, packet, sizeof(packet));
	CHECK(lichen_schc_compress(packet, len, out, 20) < 0);

	/* A valid non-MQTT UDP packet is not captured by Rule 7. */
	len = decode(
		"6000000000131140fe800000000000000000000000000001fe80000000000000000000000000000216331633001328dd40011234ff737461747573",
		packet, sizeof(packet));
	int n = lichen_schc_compress(packet, len, out, sizeof(out));
	CHECK(n > 0 && out[0] != SCHC_RULE_MQTT_SN);
	return 0;
}

static int test_profile_size_boundary(void)
{
	static uint8_t compressed[SCHC_FRAGMENT_MAX_PACKET_SIZE + 1];
	static uint8_t packet[22581];
	static const char prefix_hex[] =
		"07400000000000000000800000000000000104e200";
	size_t prefix_len = decode(prefix_hex, compressed, sizeof(compressed));

	CHECK(prefix_len == 21);
	memset(&compressed[prefix_len], 0,
	       SCHC_FRAGMENT_MAX_PACKET_SIZE - prefix_len);
	CHECK(lichen_schc_decompress(compressed, SCHC_FRAGMENT_MAX_PACKET_SIZE,
				    packet, sizeof(packet)) == (int)sizeof(packet));
	compressed[SCHC_FRAGMENT_MAX_PACKET_SIZE] = 0;
	CHECK(lichen_schc_decompress(compressed,
				    SCHC_FRAGMENT_MAX_PACKET_SIZE + 1,
				    packet, sizeof(packet)) < 0);
	return 0;
}

int main(void)
{
	CHECK(test_vectors() == 0);
	CHECK(test_rejections() == 0);
	CHECK(test_profile_size_boundary() == 0);
	puts("SCHC MQTT-SN Rule 7: PASS");
	return 0;
}
