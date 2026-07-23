/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief SenML CBOR encoder tests with reference vectors
 *
 * Test vectors are generated using Python cbor2 and verified against
 * RFC 8428 CBOR label definitions. Each test compares encoder output
 * against known-good CBOR bytes.
 */

#include <lichen/senml.h>
#include <lichen/errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* ─── test framework ──────────────────────────────────────────────────────── */

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_MEM_EQ(a, b, len, msg) do { \
	if (memcmp((a), (b), (len)) != 0) { \
		printf("  FAIL: %s (memory mismatch)\n", msg); \
		for (size_t i = 0; i < (len); i++) { \
			printf("    [%zu] got=0x%02x expected=0x%02x\n", \
			       i, ((uint8_t*)(a))[i], ((uint8_t*)(b))[i]); \
		} \
		return 0; \
	} \
} while (0)

/* ─── test vectors ────────────────────────────────────────────────────────── */

/*
 * Test vector: temperature 25.0 Celsius with base time 0
 * Python: cbor2.dumps([{-3: 0, 0: 'temp', 1: 'Cel', 2: 25.0}]) (float32)
 * CBOR structure:
 *   81        array(1)
 *   a4        map(4)
 *   22        label -3 (bt)
 *   00        uint 0
 *   00        label 0 (n)
 *   64 74656d70 tstr "temp"
 *   01        label 1 (u)
 *   63 43656c tstr "Cel"
 *   02        label 2 (v)
 *   fa 41c80000 float32(25.0)
 */
static const uint8_t VEC_TEMP_SIMPLE[] = {
	0x81, 0xa4,
	0x22, 0x00,
	0x00, 0x64, 0x74, 0x65, 0x6d, 0x70,
	0x01, 0x63, 0x43, 0x65, 0x6c,
	0x02, 0xfa, 0x41, 0xc8, 0x00, 0x00
};

/*
 * Test vector: boolean value (charging: true) with base time 0
 * Python: cbor2.dumps([{-3: 0, 0: 'charging', 4: True}])
 * CBOR structure:
 *   81        array(1)
 *   a3        map(3)
 *   22        label -3 (bt)
 *   00        0
 *   00        label 0 (n)
 *   68 6368617267696e67 tstr "charging"
 *   04        label 4 (vb)
 *   f5        true
 */
static const uint8_t VEC_BOOL_TRUE[] = {
	0x81, 0xa3,
	0x22, 0x00,
	0x00, 0x68, 0x63, 0x68, 0x61, 0x72, 0x67, 0x69, 0x6e, 0x67,
	0x04, 0xf5
};

/*
 * Test vector: base time 2^63, boolean value (ok: true)
 * Python: cbor2.dumps([{-3: 0x8000000000000000, 0: 'ok', 4: True}])
 * CBOR structure:
 *   81        array(1)
 *   a3        map(3)
 *   22        label -3 (bt = base time)
 *   1b 8000000000000000  uint64(2^63)
 *   00        label 0 (n)
 *   62 6f6b   tstr(2) "ok"
 *   04        label 4 (vb = boolean value)
 *   f5        true
 */
static const uint8_t VEC_BASE_TIME_UINT64_HIGH[] = {
	0x81, 0xa3,
	0x22, 0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x62, 0x6f, 0x6b,
	0x04, 0xf5
};

static void fill_string(char *str, size_t len, char ch)
{
	memset(str, ch, len);
	str[len] = '\0';
}

/* ─── tests ───────────────────────────────────────────────────────────────── */

static int test_encode_temperature(void)
{
	struct senml_pack pack;
	uint8_t buf[64];
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");
	ret = senml_add_float(&pack, "temp", "Cel", 25.0f);
	ASSERT_EQ(ret, 0, "senml_add_float");

	ret = senml_encode_cbor(&pack, buf, sizeof(buf));
	ASSERT_EQ(ret, (int)sizeof(VEC_TEMP_SIMPLE), "encoded length");
	ASSERT_MEM_EQ(buf, VEC_TEMP_SIMPLE, sizeof(VEC_TEMP_SIMPLE), "CBOR output");

	return 1;
}

static int test_encode_boolean(void)
{
	struct senml_pack pack;
	uint8_t buf[64];
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");
	ret = senml_add_bool(&pack, "charging", true);
	ASSERT_EQ(ret, 0, "senml_add_bool");

	ret = senml_encode_cbor(&pack, buf, sizeof(buf));
	ASSERT_EQ(ret, (int)sizeof(VEC_BOOL_TRUE), "encoded length");
	ASSERT_MEM_EQ(buf, VEC_BOOL_TRUE, sizeof(VEC_BOOL_TRUE), "CBOR output");

	return 1;
}

static int test_base_time_uint64_high(void)
{
	struct senml_pack pack;
	uint8_t buf[64];
	int ret;

	ret = senml_pack_init(&pack, NULL, 0x8000000000000000ULL);
	ASSERT_EQ(ret, 0, "senml_pack_init");
	ret = senml_add_bool(&pack, "ok", true);
	ASSERT_EQ(ret, 0, "senml_add_bool");

	ret = senml_encode_cbor(&pack, buf, sizeof(buf));
	ASSERT_EQ(ret, (int)sizeof(VEC_BASE_TIME_UINT64_HIGH), "encoded length");
	ASSERT_MEM_EQ(buf, VEC_BASE_TIME_UINT64_HIGH,
		      sizeof(VEC_BASE_TIME_UINT64_HIGH), "CBOR output");

	return 1;
}

static int test_empty_pack_rejected(void)
{
	struct senml_pack pack;
	uint8_t buf[64];
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");
	ret = senml_encode_cbor(&pack, buf, sizeof(buf));
	ASSERT_EQ(ret, -EINVAL, "empty pack returns -EINVAL");

	return 1;
}

static int test_buffer_too_small(void)
{
	struct senml_pack pack;
	uint8_t buf[4]; /* Too small */
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");
	ret = senml_add_float(&pack, "temp", "Cel", 25.0f);
	ASSERT_EQ(ret, 0, "senml_add_float");

	ret = senml_encode_cbor(&pack, buf, sizeof(buf));
	ASSERT_EQ(ret, -ENOMEM, "small buffer returns -ENOMEM");

	return 1;
}

static int test_pack_full(void)
{
	struct senml_pack pack;
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");

	/* Fill the pack to capacity */
	for (int i = 0; i < SENML_MAX_RECORDS; i++) {
		ret = senml_add_float(&pack, "x", NULL, (float)i);
		ASSERT_EQ(ret, 0, "add record");
	}

	/* Next add should fail */
	ret = senml_add_float(&pack, "overflow", NULL, 999.0f);
	ASSERT_EQ(ret, -ENOMEM, "pack full returns -ENOMEM");

	return 1;
}

static int test_string_length_limits(void)
{
	struct senml_pack pack;
	char max_name[SENML_MAX_NAME_LEN + 1];
	char long_name[SENML_MAX_NAME_LEN + 2];
	char max_unit[SENML_MAX_UNIT_LEN + 1];
	char long_unit[SENML_MAX_UNIT_LEN + 2];
	uint8_t buf[128];
	int ret;

	fill_string(max_name, SENML_MAX_NAME_LEN, 'n');
	fill_string(long_name, SENML_MAX_NAME_LEN + 1, 'n');
	fill_string(max_unit, SENML_MAX_UNIT_LEN, 'u');
	fill_string(long_unit, SENML_MAX_UNIT_LEN + 1, 'u');

	ret = senml_pack_init(&pack, max_name, 0);
	ASSERT_EQ(ret, 0, "max-length base name accepted");

	ret = senml_pack_init(&pack, long_name, 0);
	ASSERT_EQ(ret, -EMSGSIZE, "overlong base name rejected");
	ASSERT_EQ(pack.record_count, 0, "failed init leaves empty pack");
	ASSERT_EQ(pack.base_name == NULL, true, "failed init clears base name");

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");

	ret = senml_add_float(&pack, max_name, max_unit, 1.0f);
	ASSERT_EQ(ret, 0, "max-length name/unit accepted");
	ASSERT_EQ(pack.record_count, 1, "accepted record counted");

	ret = senml_add_float(&pack, long_name, max_unit, 1.0f);
	ASSERT_EQ(ret, -EMSGSIZE, "overlong float name rejected");
	ASSERT_EQ(pack.record_count, 1, "rejected name not counted");

	ret = senml_add_float_t(&pack, max_name, long_unit, 1.0f, 1);
	ASSERT_EQ(ret, -EMSGSIZE, "overlong timed float unit rejected");
	ASSERT_EQ(pack.record_count, 1, "rejected unit not counted");

	ret = senml_add_bool(&pack, long_name, true);
	ASSERT_EQ(ret, -EMSGSIZE, "overlong bool name rejected");
	ASSERT_EQ(pack.record_count, 1, "rejected bool not counted");

	pack.records[0].name = long_name;
	ret = senml_encode_cbor(&pack, buf, sizeof(buf));
	ASSERT_EQ(ret, -EMSGSIZE, "manually overlong record rejected at encode");

	return 1;
}

static int test_location_rejects_nan_lat(void)
{
	uint8_t buf[128];
	int ret;

	ret = senml_encode_location(NULL, 0, NAN, -122.0f, 100.0f, buf, sizeof(buf));
	ASSERT_EQ(ret, -EINVAL, "NaN latitude rejected with -EINVAL");

	return 1;
}

static int test_location_rejects_nan_lon(void)
{
	uint8_t buf[128];
	int ret;

	ret = senml_encode_location(NULL, 0, 37.0f, NAN, 100.0f, buf, sizeof(buf));
	ASSERT_EQ(ret, -EINVAL, "NaN longitude rejected with -EINVAL");

	return 1;
}

static int test_location_rejects_inf_lat(void)
{
	uint8_t buf[128];
	int ret;

	ret = senml_encode_location(NULL, 0, INFINITY, -122.0f, 100.0f, buf, sizeof(buf));
	ASSERT_EQ(ret, -EINVAL, "Inf latitude rejected with -EINVAL");

	ret = senml_encode_location(NULL, 0, -INFINITY, -122.0f, 100.0f, buf, sizeof(buf));
	ASSERT_EQ(ret, -EINVAL, "-Inf latitude rejected with -EINVAL");

	return 1;
}

static int test_location_rejects_inf_lon(void)
{
	uint8_t buf[128];
	int ret;

	ret = senml_encode_location(NULL, 0, 37.0f, INFINITY, 100.0f, buf, sizeof(buf));
	ASSERT_EQ(ret, -EINVAL, "Inf longitude rejected with -EINVAL");

	ret = senml_encode_location(NULL, 0, 37.0f, -INFINITY, 100.0f, buf, sizeof(buf));
	ASSERT_EQ(ret, -EINVAL, "-Inf longitude rejected with -EINVAL");

	return 1;
}

static int test_location_rejects_out_of_range_lat(void)
{
	uint8_t buf[128];
	int ret;

	/* Latitude must be between -90 and +90 */
	ret = senml_encode_location(NULL, 0, 91.0f, -122.0f, 100.0f, buf, sizeof(buf));
	ASSERT_EQ(ret, -ERANGE, "latitude > 90 rejected with -ERANGE");

	ret = senml_encode_location(NULL, 0, -91.0f, -122.0f, 100.0f, buf, sizeof(buf));
	ASSERT_EQ(ret, -ERANGE, "latitude < -90 rejected with -ERANGE");

	return 1;
}

static int test_location_rejects_out_of_range_lon(void)
{
	uint8_t buf[128];
	int ret;

	/* Longitude must be between -180 and +180 */
	ret = senml_encode_location(NULL, 0, 37.0f, 181.0f, 100.0f, buf, sizeof(buf));
	ASSERT_EQ(ret, -ERANGE, "longitude > 180 rejected with -ERANGE");

	ret = senml_encode_location(NULL, 0, 37.0f, -181.0f, 100.0f, buf, sizeof(buf));
	ASSERT_EQ(ret, -ERANGE, "longitude < -180 rejected with -ERANGE");

	return 1;
}

static int test_location_valid_coordinates(void)
{
	uint8_t buf[128];
	int ret;

	/* Valid coordinates should encode successfully */
	ret = senml_encode_location(NULL, 0, 37.7749f, -122.4194f, 10.0f, buf, sizeof(buf));
	ASSERT_EQ(ret > 0, 1, "valid coordinates encode successfully");

	/* Boundary values should also work */
	ret = senml_encode_location(NULL, 0, 90.0f, 180.0f, NAN, buf, sizeof(buf));
	ASSERT_EQ(ret > 0, 1, "boundary values (90, 180) encode successfully");

	ret = senml_encode_location(NULL, 0, -90.0f, -180.0f, NAN, buf, sizeof(buf));
	ASSERT_EQ(ret > 0, 1, "boundary values (-90, -180) encode successfully");

	return 1;
}

static int test_null_name_rejected(void)
{
	struct senml_pack pack;
	int ret;
	/*
	 * Use a volatile pointer to prevent the compiler from detecting
	 * that we're intentionally passing NULL to a _Nonnull parameter.
	 * This tests the runtime check.
	 */
	volatile const char *null_name = NULL;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");

	/* NULL name must be rejected by senml_add_float */
	ret = senml_add_float(&pack, (const char *)null_name, "Cel", 25.0f);
	ASSERT_EQ(ret, -EINVAL, "NULL name rejected by senml_add_float");
	ASSERT_EQ(pack.record_count, 0, "rejected NULL name not counted");

	/* NULL name must be rejected by senml_add_float_t */
	ret = senml_add_float_t(&pack, (const char *)null_name, "Cel", 25.0f, 0);
	ASSERT_EQ(ret, -EINVAL, "NULL name rejected by senml_add_float_t");
	ASSERT_EQ(pack.record_count, 0, "rejected NULL name not counted");

	/* NULL name must be rejected by senml_add_bool */
	ret = senml_add_bool(&pack, (const char *)null_name, true);
	ASSERT_EQ(ret, -EINVAL, "NULL name rejected by senml_add_bool");
	ASSERT_EQ(pack.record_count, 0, "rejected NULL name not counted");

	return 1;
}

/* ─── test runner ─────────────────────────────────────────────────────────── */

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
	printf("SenML Encoder Tests\n");
	printf("===================\n\n");

	RUN_TEST(test_encode_temperature);
	RUN_TEST(test_encode_boolean);
	RUN_TEST(test_base_time_uint64_high);
	RUN_TEST(test_empty_pack_rejected);
	RUN_TEST(test_buffer_too_small);
	RUN_TEST(test_pack_full);
	RUN_TEST(test_string_length_limits);
	RUN_TEST(test_location_rejects_nan_lat);
	RUN_TEST(test_location_rejects_nan_lon);
	RUN_TEST(test_location_rejects_inf_lat);
	RUN_TEST(test_location_rejects_inf_lon);
	RUN_TEST(test_location_rejects_out_of_range_lat);
	RUN_TEST(test_location_rejects_out_of_range_lon);
	RUN_TEST(test_location_valid_coordinates);
	RUN_TEST(test_null_name_rejected);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
