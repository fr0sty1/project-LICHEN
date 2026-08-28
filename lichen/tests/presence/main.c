/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Presence CBOR encoder/decoder tests with reference vectors
 *
 * Test vectors from test/vectors/presence_cbor.json.
 */

#include <lichen/presence.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/* --- test framework --- */

static int tests_run;
static int tests_passed;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
	if (memcmp((a), (b), (len)) != 0) { \
		printf("  FAIL: %s (memory mismatch)\n", msg); \
		printf("    got:      "); \
		for (size_t i = 0; i < (len); i++) { \
			printf("%02x", ((uint8_t*)(a))[i]); \
		} \
		printf("\n    expected: "); \
		for (size_t i = 0; i < (len); i++) { \
			printf("%02x", ((uint8_t*)(b))[i]); \
		} \
		printf("\n"); \
		return 0; \
	} \
} while (0)

static size_t hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
	size_t len = strlen(hex) / 2U;

	if (len > out_len || (strlen(hex) & 1U) != 0U) {
		return 0U;
	}
	for (size_t i = 0; i < len; i++) {
		unsigned int value;

		if (sscanf(&hex[i * 2U], "%2x", &value) != 1) {
			return 0U;
		}
		out[i] = (uint8_t)value;
	}
	return len;
}

/* --- test vectors from presence_cbor.json --- */

/*
 * minimal_available: status=available, ts=1716742800
 */
static const char VEC_MINIMAL_AVAILABLE[] =
	"a26673746174757369617661696c61626c656274731a66536a90";

/*
 * all_fields: status=available, activity=moving, msg="On patrol", battery=87, ts=1716742800
 */
static const char VEC_ALL_FIELDS[] =
	"a56673746174757369617661696c61626c6568616374697669"
	"7479666d6f76696e67636d7367694f6e20706174726f6c6762"
	"617474657279185762"
	"74731a66536a90";

/*
 * busy_working: status=busy, activity=working, ts=1716742800
 */
static const char VEC_BUSY_WORKING[] =
	"a366737461747573646275737968616374697669747967776f"
	"726b696e676274731a66536a90";

/*
 * away_with_battery: status=away, battery=45, ts=1716742800
 */
static const char VEC_AWAY_BATTERY[] =
	"a36673746174757364617761796762617474657279182d6274"
	"731a66536a90";

/*
 * emergency_status: status=emergency, ts=1716742800
 */
static const char VEC_EMERGENCY[] =
	"a26673746174757369656d657267656e63796274731a66536a90";

/*
 * offline_status: status=offline, ts=1716742800
 */
static const char VEC_OFFLINE[] =
	"a266737461747573676f66666c696e656274731a66536a90";

/*
 * battery_zero: status=available, battery=0, low_battery=true, ts=1716742800
 */
static const char VEC_BATTERY_ZERO[] =
	"a46673746174757369617661696c61626c6567626174746572"
	"79006b6c6f775f62617474657279f56274731a66536a90";

/*
 * cache_empty: nodes=[]
 */
static const char VEC_CACHE_EMPTY[] = "a1656e6f64657380";

/*
 * cache_single_node: nodes=[{addr:"0200::1111", status:available, battery:87, age_s:30}]
 */
static const char VEC_CACHE_SINGLE[] =
	"a1656e6f64657381a464616464726a303230303a3a31313131"
	"6673746174757369617661696c61626c656762617474657279"
	"1857656167655f73181e";

/* --- tests --- */

static int test_encode_minimal_available(void)
{
	struct presence p;
	uint8_t buf[256];
	uint8_t expected[256];
	size_t encoded_len;
	size_t expected_len;
	int ret;

	presence_init(&p, PRESENCE_STATUS_AVAILABLE, 1716742800ULL);

	ret = presence_to_cbor(&p, buf, sizeof(buf), &encoded_len);
	ASSERT_EQ(ret, 0, "encode minimal_available");

	expected_len = hex_decode(VEC_MINIMAL_AVAILABLE, expected, sizeof(expected));
	ASSERT_EQ(expected_len > 0, 1, "decode expected hex");
	ASSERT_EQ(encoded_len, expected_len, "encoded length");
	ASSERT_MEM_EQ(buf, expected, expected_len, "CBOR output");

	return 1;
}

static int test_encode_all_fields(void)
{
	struct presence p;
	uint8_t buf[256];
	uint8_t expected[256];
	size_t encoded_len;
	size_t expected_len;
	int ret;

	presence_init(&p, PRESENCE_STATUS_AVAILABLE, 1716742800ULL);
	presence_set_activity(&p, PRESENCE_ACTIVITY_MOVING);
	presence_set_message(&p, "On patrol");
	presence_set_battery(&p, 87);

	ret = presence_to_cbor(&p, buf, sizeof(buf), &encoded_len);
	ASSERT_EQ(ret, 0, "encode all_fields");

	expected_len = hex_decode(VEC_ALL_FIELDS, expected, sizeof(expected));
	ASSERT_EQ(expected_len > 0, 1, "decode expected hex");
	ASSERT_EQ(encoded_len, expected_len, "encoded length");
	ASSERT_MEM_EQ(buf, expected, expected_len, "CBOR output");

	return 1;
}

static int test_encode_busy_working(void)
{
	struct presence p;
	uint8_t buf[256];
	uint8_t expected[256];
	size_t encoded_len;
	size_t expected_len;
	int ret;

	presence_init(&p, PRESENCE_STATUS_BUSY, 1716742800ULL);
	presence_set_activity(&p, PRESENCE_ACTIVITY_WORKING);

	ret = presence_to_cbor(&p, buf, sizeof(buf), &encoded_len);
	ASSERT_EQ(ret, 0, "encode busy_working");

	expected_len = hex_decode(VEC_BUSY_WORKING, expected, sizeof(expected));
	ASSERT_EQ(expected_len > 0, 1, "decode expected hex");
	ASSERT_EQ(encoded_len, expected_len, "encoded length");
	ASSERT_MEM_EQ(buf, expected, expected_len, "CBOR output");

	return 1;
}

static int test_encode_away_battery(void)
{
	struct presence p;
	uint8_t buf[256];
	uint8_t expected[256];
	size_t encoded_len;
	size_t expected_len;
	int ret;

	presence_init(&p, PRESENCE_STATUS_AWAY, 1716742800ULL);
	presence_set_battery(&p, 45);

	ret = presence_to_cbor(&p, buf, sizeof(buf), &encoded_len);
	ASSERT_EQ(ret, 0, "encode away_battery");

	expected_len = hex_decode(VEC_AWAY_BATTERY, expected, sizeof(expected));
	ASSERT_EQ(expected_len > 0, 1, "decode expected hex");
	ASSERT_EQ(encoded_len, expected_len, "encoded length");
	ASSERT_MEM_EQ(buf, expected, expected_len, "CBOR output");

	return 1;
}

static int test_encode_emergency(void)
{
	struct presence p;
	uint8_t buf[256];
	uint8_t expected[256];
	size_t encoded_len;
	size_t expected_len;
	int ret;

	presence_init(&p, PRESENCE_STATUS_EMERGENCY, 1716742800ULL);

	ret = presence_to_cbor(&p, buf, sizeof(buf), &encoded_len);
	ASSERT_EQ(ret, 0, "encode emergency");

	expected_len = hex_decode(VEC_EMERGENCY, expected, sizeof(expected));
	ASSERT_EQ(expected_len > 0, 1, "decode expected hex");
	ASSERT_EQ(encoded_len, expected_len, "encoded length");
	ASSERT_MEM_EQ(buf, expected, expected_len, "CBOR output");

	return 1;
}

static int test_encode_offline(void)
{
	struct presence p;
	uint8_t buf[256];
	uint8_t expected[256];
	size_t encoded_len;
	size_t expected_len;
	int ret;

	presence_init(&p, PRESENCE_STATUS_OFFLINE, 1716742800ULL);

	ret = presence_to_cbor(&p, buf, sizeof(buf), &encoded_len);
	ASSERT_EQ(ret, 0, "encode offline");

	expected_len = hex_decode(VEC_OFFLINE, expected, sizeof(expected));
	ASSERT_EQ(expected_len > 0, 1, "decode expected hex");
	ASSERT_EQ(encoded_len, expected_len, "encoded length");
	ASSERT_MEM_EQ(buf, expected, expected_len, "CBOR output");

	return 1;
}

static int test_encode_battery_zero(void)
{
	struct presence p;
	uint8_t buf[256];
	uint8_t expected[256];
	size_t encoded_len;
	size_t expected_len;
	int ret;

	presence_init(&p, PRESENCE_STATUS_AVAILABLE, 1716742800ULL);
	presence_set_battery(&p, 0);

	ret = presence_to_cbor(&p, buf, sizeof(buf), &encoded_len);
	ASSERT_EQ(ret, 0, "encode battery_zero");

	/* Should have low_battery=true since battery < 10 */
	ASSERT_EQ(p.has_low_battery, true, "low_battery set");
	ASSERT_EQ(p.low_battery, true, "low_battery true");

	expected_len = hex_decode(VEC_BATTERY_ZERO, expected, sizeof(expected));
	ASSERT_EQ(expected_len > 0, 1, "decode expected hex");
	ASSERT_EQ(encoded_len, expected_len, "encoded length");
	ASSERT_MEM_EQ(buf, expected, expected_len, "CBOR output");

	return 1;
}

static int test_decode_minimal_available(void)
{
	struct presence p;
	uint8_t buf[256];
	size_t len;
	int ret;

	len = hex_decode(VEC_MINIMAL_AVAILABLE, buf, sizeof(buf));
	ASSERT_EQ(len > 0, 1, "decode hex");

	ret = presence_from_cbor(buf, len, &p);
	ASSERT_EQ(ret, 0, "decode minimal_available");
	ASSERT_EQ(p.status, PRESENCE_STATUS_AVAILABLE, "status");
	ASSERT_EQ(p.ts, 1716742800ULL, "ts");
	ASSERT_EQ(p.has_activity, false, "no activity");
	ASSERT_EQ(p.has_msg, false, "no msg");
	ASSERT_EQ(p.has_battery, false, "no battery");

	return 1;
}

static int test_decode_all_fields(void)
{
	struct presence p;
	uint8_t buf[256];
	size_t len;
	int ret;

	len = hex_decode(VEC_ALL_FIELDS, buf, sizeof(buf));
	ASSERT_EQ(len > 0, 1, "decode hex");

	ret = presence_from_cbor(buf, len, &p);
	ASSERT_EQ(ret, 0, "decode all_fields");
	ASSERT_EQ(p.status, PRESENCE_STATUS_AVAILABLE, "status");
	ASSERT_EQ(p.ts, 1716742800ULL, "ts");
	ASSERT_EQ(p.has_activity, true, "has activity");
	ASSERT_EQ(p.activity, PRESENCE_ACTIVITY_MOVING, "activity");
	ASSERT_EQ(p.has_msg, true, "has msg");
	ASSERT_EQ(strcmp(p.msg, "On patrol"), 0, "msg content");
	ASSERT_EQ(p.has_battery, true, "has battery");
	ASSERT_EQ(p.battery, 87, "battery");

	return 1;
}

static int test_encode_cache_empty(void)
{
	struct presence_cache cache;
	uint8_t buf[256];
	uint8_t expected[256];
	size_t encoded_len;
	size_t expected_len;
	int ret;

	presence_cache_init(&cache);

	ret = presence_cache_to_cbor(&cache, buf, sizeof(buf), &encoded_len);
	ASSERT_EQ(ret, 0, "encode cache_empty");

	expected_len = hex_decode(VEC_CACHE_EMPTY, expected, sizeof(expected));
	ASSERT_EQ(expected_len > 0, 1, "decode expected hex");
	ASSERT_EQ(encoded_len, expected_len, "encoded length");
	ASSERT_MEM_EQ(buf, expected, expected_len, "CBOR output");

	return 1;
}

static int test_encode_cache_single(void)
{
	struct presence_cache cache;
	uint8_t buf[256];
	uint8_t expected[256];
	size_t encoded_len;
	size_t expected_len;
	int ret;

	presence_cache_init(&cache);
	cache.count = 1;
	strcpy(cache.entries[0].addr, "0200::1111");
	cache.entries[0].status = PRESENCE_STATUS_AVAILABLE;
	cache.entries[0].has_battery = true;
	cache.entries[0].battery = 87;
	cache.entries[0].age_s = 30;

	ret = presence_cache_to_cbor(&cache, buf, sizeof(buf), &encoded_len);
	ASSERT_EQ(ret, 0, "encode cache_single");

	expected_len = hex_decode(VEC_CACHE_SINGLE, expected, sizeof(expected));
	ASSERT_EQ(expected_len > 0, 1, "decode expected hex");
	ASSERT_EQ(encoded_len, expected_len, "encoded length");
	ASSERT_MEM_EQ(buf, expected, expected_len, "CBOR output");

	return 1;
}

static int test_decode_cache_single(void)
{
	struct presence_cache cache;
	uint8_t buf[256];
	size_t len;
	int ret;

	len = hex_decode(VEC_CACHE_SINGLE, buf, sizeof(buf));
	ASSERT_EQ(len > 0, 1, "decode hex");

	ret = presence_cache_from_cbor(buf, len, &cache);
	ASSERT_EQ(ret, 0, "decode cache_single");
	ASSERT_EQ(cache.count, 1, "count");
	ASSERT_EQ(strcmp(cache.entries[0].addr, "0200::1111"), 0, "addr");
	ASSERT_EQ(cache.entries[0].status, PRESENCE_STATUS_AVAILABLE, "status");
	ASSERT_EQ(cache.entries[0].has_battery, true, "has battery");
	ASSERT_EQ(cache.entries[0].battery, 87, "battery");
	ASSERT_EQ(cache.entries[0].age_s, 30, "age_s");

	return 1;
}

static int test_roundtrip_presence(void)
{
	struct presence p1;
	struct presence p2;
	uint8_t buf[256];
	size_t encoded_len;
	int ret;

	presence_init(&p1, PRESENCE_STATUS_BUSY, 1234567890ULL);
	presence_set_activity(&p1, PRESENCE_ACTIVITY_RESTING);
	presence_set_message(&p1, "Taking a break");
	presence_set_battery(&p1, 55);

	ret = presence_to_cbor(&p1, buf, sizeof(buf), &encoded_len);
	ASSERT_EQ(ret, 0, "encode");

	ret = presence_from_cbor(buf, encoded_len, &p2);
	ASSERT_EQ(ret, 0, "decode");

	ASSERT_EQ(p2.status, p1.status, "status roundtrip");
	ASSERT_EQ(p2.ts, p1.ts, "ts roundtrip");
	ASSERT_EQ(p2.has_activity, p1.has_activity, "has_activity roundtrip");
	ASSERT_EQ(p2.activity, p1.activity, "activity roundtrip");
	ASSERT_EQ(p2.has_msg, p1.has_msg, "has_msg roundtrip");
	ASSERT_EQ(strcmp(p2.msg, p1.msg), 0, "msg roundtrip");
	ASSERT_EQ(p2.has_battery, p1.has_battery, "has_battery roundtrip");
	ASSERT_EQ(p2.battery, p1.battery, "battery roundtrip");

	return 1;
}

static int test_battery_rejects_over_100(void)
{
	struct presence p;
	int ret;

	presence_init(&p, PRESENCE_STATUS_AVAILABLE, 0);
	ret = presence_set_battery(&p, 101);
	ASSERT_EQ(ret, -1, "battery > 100 rejected");
	ASSERT_EQ(p.has_battery, false, "battery not set");

	return 1;
}

static int test_status_string_conversion(void)
{
	enum presence_status status;

	ASSERT_EQ(strcmp(presence_status_str(PRESENCE_STATUS_AVAILABLE), "available"), 0, "available str");
	ASSERT_EQ(strcmp(presence_status_str(PRESENCE_STATUS_BUSY), "busy"), 0, "busy str");
	ASSERT_EQ(strcmp(presence_status_str(PRESENCE_STATUS_AWAY), "away"), 0, "away str");
	ASSERT_EQ(strcmp(presence_status_str(PRESENCE_STATUS_OFFLINE), "offline"), 0, "offline str");
	ASSERT_EQ(strcmp(presence_status_str(PRESENCE_STATUS_EMERGENCY), "emergency"), 0, "emergency str");

	ASSERT_EQ(presence_status_parse("available", &status), 0, "parse available");
	ASSERT_EQ(status, PRESENCE_STATUS_AVAILABLE, "available parsed");

	ASSERT_EQ(presence_status_parse("busy", &status), 0, "parse busy");
	ASSERT_EQ(status, PRESENCE_STATUS_BUSY, "busy parsed");

	ASSERT_EQ(presence_status_parse("unknown", &status), -1, "unknown rejected");

	return 1;
}

static int test_activity_string_conversion(void)
{
	enum presence_activity activity;

	ASSERT_EQ(presence_activity_str(PRESENCE_ACTIVITY_NONE) == NULL, true, "none str");
	ASSERT_EQ(strcmp(presence_activity_str(PRESENCE_ACTIVITY_STATIONARY), "stationary"), 0, "stationary str");
	ASSERT_EQ(strcmp(presence_activity_str(PRESENCE_ACTIVITY_MOVING), "moving"), 0, "moving str");
	ASSERT_EQ(strcmp(presence_activity_str(PRESENCE_ACTIVITY_RESTING), "resting"), 0, "resting str");
	ASSERT_EQ(strcmp(presence_activity_str(PRESENCE_ACTIVITY_WORKING), "working"), 0, "working str");

	ASSERT_EQ(presence_activity_parse("moving", &activity), 0, "parse moving");
	ASSERT_EQ(activity, PRESENCE_ACTIVITY_MOVING, "moving parsed");

	ASSERT_EQ(presence_activity_parse("invalid", &activity), -1, "invalid rejected");

	return 1;
}

/* --- test runner --- */

#define RUN_TEST(fn) do { \
	printf("  %s...", #fn); \
	tests_run++; \
	if (fn()) { \
		printf(" OK\n"); \
		tests_passed++; \
	} \
} while (0)

int main(void)
{
	printf("Presence CBOR Tests\n");
	printf("===================\n\n");

	RUN_TEST(test_encode_minimal_available);
	RUN_TEST(test_encode_all_fields);
	RUN_TEST(test_encode_busy_working);
	RUN_TEST(test_encode_away_battery);
	RUN_TEST(test_encode_emergency);
	RUN_TEST(test_encode_offline);
	RUN_TEST(test_encode_battery_zero);
	RUN_TEST(test_decode_minimal_available);
	RUN_TEST(test_decode_all_fields);
	RUN_TEST(test_encode_cache_empty);
	RUN_TEST(test_encode_cache_single);
	RUN_TEST(test_decode_cache_single);
	RUN_TEST(test_roundtrip_presence);
	RUN_TEST(test_battery_rejects_over_100);
	RUN_TEST(test_status_string_conversion);
	RUN_TEST(test_activity_string_conversion);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
