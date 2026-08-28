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
 * Test vector: temperature 25.0 Celsius, no base name/time
 * Python: cbor2.dumps([{0: 'temp', 1: 'Cel', 2: 25.0}])  (with float32)
 * Base time 0 is omitted (defaults to 0 per RFC 8428 §6.1).
 * CBOR structure:
 *   81        array(1)
 *   a3        map(3)
 *   00        label 0 (n = name)
 *   64 74656d70   tstr(4) "temp"
 *   01        label 1 (u = unit)
 *   63 43656c     tstr(3) "Cel"
 *   02        label 2 (v = value)
 *   fa 41c80000   float32(25.0)
 */
static const uint8_t VEC_TEMP_SIMPLE[] = {
	0x81, 0xa3,
	0x00, 0x64, 0x74, 0x65, 0x6d, 0x70,
	0x01, 0x63, 0x43, 0x65, 0x6c,
	0x02, 0xfa, 0x41, 0xc8, 0x00, 0x00
};

/*
 * Test vector: boolean value (charging: true), no base name/time
 * Python: cbor2.dumps([{0: 'charging', 4: True}])
 * Base time 0 is omitted (defaults to 0 per RFC 8428 §6.1).
 * CBOR structure:
 *   81        array(1)
 *   a2        map(2)
 *   00        label 0 (n)
 *   68 6368617267696e67   tstr(8) "charging"
 *   04        label 4 (vb = boolean value)
 *   f5        true
 */
static const uint8_t VEC_BOOL_TRUE[] = {
	0x81, 0xa2,
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

/* ─── tests ───────────────────────────────────────────────────────────────── */

static int test_content_format(void)
{
	ASSERT_EQ(SENML_CBOR_CONTENT_FORMAT, 112,
		  "application/senml+cbor Content-Format");
	return 1;
}

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

/*
 * Test vector: string value (message="hello") with base time 0
 * Python: cbor2.dumps([{0: 'msg', 3: 'hello'}])
 * CBOR structure:
 *   81        array(1)
 *   a2        map(2)
 *   00        label 0 (n)
 *   63 6d7367 tstr(3) "msg"
 *   03        label 3 (vs)
 *   65 68656c6c6f tstr(5) "hello"
 */
static const uint8_t VEC_STRING_SIMPLE[] = {
	0x81, 0xa2,
	0x00, 0x63, 0x6d, 0x73, 0x67,
	0x03, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f
};

/*
 * Test vector: string value with base_name and base_time
 * Python: cbor2.dumps([{-2: 'urn:dev:mac:', 0: 'msg', 3: 'hello'}])
 */
static const uint8_t VEC_STRING_WITH_BASE[] = {
	0x81, 0xa3,
	0x21, 0x6c, 0x75, 0x72, 0x6e, 0x3a, 0x64, 0x65,
	0x76, 0x3a, 0x6d, 0x61, 0x63, 0x3a,
	0x00, 0x63, 0x6d, 0x73, 0x67,
	0x03, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f
};

/*
 * Test vector: string value NULL (empty string)
 * Python: cbor2.dumps([{0: 'ack', 3: ''}])
 * CBOR structure:
 *   81        array(1)
 *   a2        map(2)
 *   00        label 0 (n)
 *   63 61636b tstr(3) "ack"
 *   03        label 3 (vs)
 *   60        tstr(0) ""
 */
static const uint8_t VEC_STRING_EMPTY[] = {
	0x81, 0xa2,
	0x00, 0x63, 0x61, 0x63, 0x6b,
	0x03, 0x60
};

static int test_encode_string(void)
{
	struct senml_pack pack;
	uint8_t buf[128];
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");
	ret = senml_add_string(&pack, "msg", "hello");
	ASSERT_EQ(ret, 0, "senml_add_string");

	ret = senml_encode_cbor(&pack, buf, sizeof(buf));
	ASSERT_EQ(ret, (int)sizeof(VEC_STRING_SIMPLE), "encoded length");
	ASSERT_MEM_EQ(buf, VEC_STRING_SIMPLE, sizeof(VEC_STRING_SIMPLE),
		      "CBOR output");

	return 1;
}

static int test_encode_string_with_base(void)
{
	struct senml_pack pack;
	uint8_t buf[128];
	int ret;

	ret = senml_pack_init(&pack, "urn:dev:mac:", 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");
	ret = senml_add_string(&pack, "msg", "hello");
	ASSERT_EQ(ret, 0, "senml_add_string");

	ret = senml_encode_cbor(&pack, buf, sizeof(buf));
	ASSERT_EQ(ret, (int)sizeof(VEC_STRING_WITH_BASE), "encoded length");
	ASSERT_MEM_EQ(buf, VEC_STRING_WITH_BASE,
		      sizeof(VEC_STRING_WITH_BASE), "CBOR output");

	return 1;
}

static int test_encode_string_null_value(void)
{
	struct senml_pack pack;
	uint8_t buf[64];
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");
	ret = senml_add_string(&pack, "ack", NULL);
	ASSERT_EQ(ret, 0, "senml_add_string with NULL value");

	ret = senml_encode_cbor(&pack, buf, sizeof(buf));
	ASSERT_EQ(ret, (int)sizeof(VEC_STRING_EMPTY), "encoded length");
	ASSERT_MEM_EQ(buf, VEC_STRING_EMPTY, sizeof(VEC_STRING_EMPTY),
		      "CBOR output");

	return 1;
}

static int test_string_length_limits_extended(void)
{
	struct senml_pack pack;
	char max_str[SENML_MAX_STRING_LEN + 1];
	char long_str[SENML_MAX_STRING_LEN + 2];
	uint8_t buf[256];
	int ret;

	fill_string(max_str, SENML_MAX_STRING_LEN, 's');
	fill_string(long_str, SENML_MAX_STRING_LEN + 1, 'x');

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");

	ret = senml_add_string(&pack, "msg", max_str);
	ASSERT_EQ(ret, 0, "max-length string accepted");
	ASSERT_EQ(pack.record_count, 1, "accepted record counted");

	ret = senml_add_string(&pack, "msg", long_str);
	ASSERT_EQ(ret, -EMSGSIZE, "overlong string rejected");
	ASSERT_EQ(pack.record_count, 1, "rejected string not counted");

	pack.records[0].value.s = long_str;
	ret = senml_encode_cbor(&pack, buf, sizeof(buf));
	ASSERT_EQ(ret, -EMSGSIZE, "manually overlong string rejected at encode");

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

static int test_add_float_rejects_nan(void)
{
	struct senml_pack pack;
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");

	ret = senml_add_float(&pack, "test", NULL, NAN);
	ASSERT_EQ(ret, -EINVAL, "NaN value rejected by senml_add_float");
	ASSERT_EQ(pack.record_count, 0, "rejected NaN not counted");

	return 1;
}

static int test_add_float_rejects_inf(void)
{
	struct senml_pack pack;
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");

	ret = senml_add_float(&pack, "test", NULL, INFINITY);
	ASSERT_EQ(ret, -EINVAL, "+Inf value rejected by senml_add_float");
	ASSERT_EQ(pack.record_count, 0, "rejected +Inf not counted");

	ret = senml_add_float(&pack, "test", NULL, -INFINITY);
	ASSERT_EQ(ret, -EINVAL, "-Inf value rejected by senml_add_float");
	ASSERT_EQ(pack.record_count, 0, "rejected -Inf not counted");

	return 1;
}

static int test_add_float_t_rejects_nan(void)
{
	struct senml_pack pack;
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");

	ret = senml_add_float_t(&pack, "test", NULL, NAN, 1);
	ASSERT_EQ(ret, -EINVAL, "NaN value rejected by senml_add_float_t");
	ASSERT_EQ(pack.record_count, 0, "rejected NaN not counted");

	return 1;
}

static int test_add_float_t_rejects_inf(void)
{
	struct senml_pack pack;
	int ret;

	ret = senml_pack_init(&pack, NULL, 0);
	ASSERT_EQ(ret, 0, "senml_pack_init");

	ret = senml_add_float_t(&pack, "test", NULL, INFINITY, 1);
	ASSERT_EQ(ret, -EINVAL, "+Inf value rejected by senml_add_float_t");
	ASSERT_EQ(pack.record_count, 0, "rejected +Inf not counted");

	ret = senml_add_float_t(&pack, "test", NULL, -INFINITY, 1);
	ASSERT_EQ(ret, -EINVAL, "-Inf value rejected by senml_add_float_t");
	ASSERT_EQ(pack.record_count, 0, "rejected -Inf not counted");

	return 1;
}

static int test_binary_data_round_trip(void)
{
	static const uint8_t data[] = { 0x00, 0xff, 0x10 };
	static const uint8_t expected[] = {
		0x81, 0xa2, 0x00, 0x63, 0x72, 0x61, 0x77,
		0x08, 0x43, 0x00, 0xff, 0x10
	};
	struct senml_pack encoded;
	struct senml_decoded_pack decoded;
	uint8_t buf[32];
	int ret;

	ASSERT_EQ(senml_pack_init(&encoded, NULL, 0U), 0, "data pack init");
	ASSERT_EQ(senml_add_data(&encoded, "raw", data, sizeof(data)), 0,
		  "add binary data");
	ret = senml_encode_cbor(&encoded, buf, sizeof(buf));
	ASSERT_EQ(ret, (int)sizeof(expected), "binary data encoded length");
	ASSERT_MEM_EQ(buf, expected, sizeof(expected), "binary data canonical bytes");
	ASSERT_EQ(senml_decode_cbor(buf, (size_t)ret, &decoded), 0,
		  "decode encoded binary data");
	ASSERT_EQ(decoded.record_count, 1, "one decoded data record");
	ASSERT_EQ(decoded.records[0].value_type, SENML_VALUE_DATA,
		  "decoded data value type");
	ASSERT_EQ(decoded.records[0].data_value.len, sizeof(data),
		  "decoded data length");
	ASSERT_MEM_EQ(decoded.records[0].data_value.data, data, sizeof(data),
		      "decoded data bytes");
	ASSERT_EQ(senml_add_data(&encoded, "bad", NULL, 1U), -EINVAL,
		  "non-empty NULL data rejected");
	ASSERT_EQ(senml_add_data(&encoded, "large", data,
				 SENML_MAX_DATA_LEN + 1U), -EMSGSIZE,
		  "oversized data rejected before access");

	return 1;
}

static int test_decode_full_rfc8428_vector(void)
{
	static const char full_fields_hex[] =
		"85a621781d75726e3a6465763a6d61633a303031313232333334343535363637373a"
		"221a6553f100236343656c24fb3ff800000000000025fb4004000000000000200a"
		"a6006474656d70016343656c02fb403580000000000005fb4059100000000000"
		"062107181ea2006673746174757303626f6ba2006661637469766504f5"
		"a20063726177084300ff10";
	uint8_t buf[256];
	struct senml_decoded_pack pack;
	size_t len = hex_decode(full_fields_hex, buf, sizeof(buf));

	ASSERT_EQ(len > 0U, true, "decode full-fields hex fixture");
	ASSERT_EQ(senml_decode_cbor(buf, len, &pack), 0,
		  "decode senml_full_fields.json");
	ASSERT_EQ(pack.record_count, 5, "full vector record count");
	ASSERT_EQ(pack.records[0].has_base_name, true, "base name present");
	ASSERT_EQ(pack.records[0].base_name.len, 29, "base name length");
	ASSERT_EQ(pack.records[0].has_base_time, true, "base time present");
	ASSERT_EQ(pack.records[0].base_time == 1700000000.0, true,
		  "base time value");
	ASSERT_EQ(pack.records[0].has_base_unit, true, "base unit present");
	ASSERT_EQ(pack.records[0].has_base_value, true, "base value present");
	ASSERT_EQ(pack.records[0].base_value == 1.5, true, "base value");
	ASSERT_EQ(pack.records[0].has_base_sum, true, "base sum present");
	ASSERT_EQ(pack.records[0].base_sum == 2.5, true, "base sum");
	ASSERT_EQ(pack.records[0].base_version, 10, "base version");
	ASSERT_EQ(pack.records[1].value_type, SENML_VALUE_FLOAT,
		  "numeric value type");
	ASSERT_EQ(pack.records[1].value == 21.5, true, "numeric value");
	ASSERT_EQ(pack.records[1].sum == 100.25, true, "sum value");
	ASSERT_EQ(pack.records[1].time == -2.0, true, "negative time");
	ASSERT_EQ(pack.records[1].update_time == 30.0, true, "update time");
	ASSERT_EQ(pack.records[2].value_type, SENML_VALUE_STRING,
		  "string value type");
	ASSERT_EQ(pack.records[3].value_type, SENML_VALUE_BOOL,
		  "boolean value type");
	ASSERT_EQ(pack.records[3].bool_value, true, "boolean value");
	ASSERT_EQ(pack.records[4].value_type, SENML_VALUE_DATA,
		  "data value type");
	ASSERT_EQ(pack.records[4].data_value.len, 3, "data value length");

	return 1;
}

static int test_decode_rejects_malformed_inputs(void)
{
	static const uint8_t not_array[] = { 0xa0 };
	static const uint8_t empty_array[] = { 0x80 };
	static const uint8_t record_not_map[] = { 0x81, 0x00 };
	static const uint8_t duplicate_name[] = {
		0x81, 0xa2, 0x00, 0x61, 0x61, 0x00, 0x61, 0x62
	};
	static const uint8_t multiple_values[] = {
		0x81, 0xa2, 0x02, 0xfa, 0x3f, 0x80, 0x00, 0x00,
		0x03, 0x61, 0x31
	};
	static const uint8_t nan_value[] = {
		0x81, 0xa1, 0x02, 0xfa, 0x7f, 0xc0, 0x00, 0x00
	};
	static const uint8_t invalid_utf8[] = {
		0x81, 0xa1, 0x00, 0x61, 0xff
	};
	static const uint8_t mandatory_extension[] = {
		0x81, 0xa1, 0x62, 0x78, 0x5f, 0x00
	};
	static const uint8_t trailing[] = { 0x81, 0xa0, 0x00 };
	static const uint8_t too_many_records[] = { 0x91 };
	static const uint8_t huge_text_length[] = {
		0x81, 0xa1, 0x00, 0x7b,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	static const uint8_t wrong_unit_type[] = {
		0x81, 0xa3, 0x00, 0x63, 0x6c, 0x61, 0x74, 0x01, 0x18, 0x7b,
		0x02, 0xfb, 0x40, 0x42, 0xe3, 0x30, 0xdf, 0x9b, 0xdc, 0x6a
	};
	static const uint8_t wrong_value_type[] = {
		0x81, 0xa3, 0x00, 0x63, 0x6c, 0x61, 0x74,
		0x01, 0x63, 0x6c, 0x61, 0x74,
		0x02, 0x65, 0x33, 0x37, 0x2e, 0x37, 0x37
	};
	struct {
		const uint8_t *data;
		size_t len;
		int error;
	} cases[] = {
		{ not_array, sizeof(not_array), -EINVAL },
		{ empty_array, sizeof(empty_array), -EINVAL },
		{ record_not_map, sizeof(record_not_map), -EINVAL },
		{ duplicate_name, sizeof(duplicate_name), -EINVAL },
		{ multiple_values, sizeof(multiple_values), -EINVAL },
		{ nan_value, sizeof(nan_value), -EINVAL },
		{ invalid_utf8, sizeof(invalid_utf8), -EINVAL },
		{ mandatory_extension, sizeof(mandatory_extension), -EINVAL },
		{ trailing, sizeof(trailing), -EINVAL },
		{ too_many_records, sizeof(too_many_records), -ENOMEM },
		{ huge_text_length, sizeof(huge_text_length), -EINVAL },
		{ wrong_unit_type, sizeof(wrong_unit_type), -EINVAL },
		{ wrong_value_type, sizeof(wrong_value_type), -EINVAL },
	};
	struct senml_decoded_pack pack;

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		memset(&pack, 0xa5, sizeof(pack));
		ASSERT_EQ(senml_decode_cbor(cases[i].data, cases[i].len, &pack),
			  cases[i].error, "malformed CBOR rejected");
		ASSERT_EQ(pack.record_count, 0, "failed decode clears record count");
	}
	ASSERT_EQ(senml_decode_cbor(NULL, 1U, &pack), -EINVAL,
		  "NULL input rejected");
	ASSERT_EQ(senml_decode_cbor(not_array, sizeof(not_array), NULL), -EINVAL,
		  "NULL output rejected");

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

	RUN_TEST(test_content_format);
	RUN_TEST(test_encode_temperature);
	RUN_TEST(test_encode_boolean);
	RUN_TEST(test_base_time_uint64_high);
	RUN_TEST(test_empty_pack_rejected);
	RUN_TEST(test_buffer_too_small);
	RUN_TEST(test_pack_full);
	RUN_TEST(test_string_length_limits);
	RUN_TEST(test_encode_string);
	RUN_TEST(test_encode_string_with_base);
	RUN_TEST(test_encode_string_null_value);
	RUN_TEST(test_string_length_limits_extended);
	RUN_TEST(test_location_rejects_nan_lat);
	RUN_TEST(test_location_rejects_nan_lon);
	RUN_TEST(test_location_rejects_inf_lat);
	RUN_TEST(test_location_rejects_inf_lon);
	RUN_TEST(test_location_rejects_out_of_range_lat);
	RUN_TEST(test_location_rejects_out_of_range_lon);
	RUN_TEST(test_location_valid_coordinates);
	RUN_TEST(test_null_name_rejected);
	RUN_TEST(test_add_float_rejects_nan);
	RUN_TEST(test_add_float_rejects_inf);
	RUN_TEST(test_add_float_t_rejects_nan);
	RUN_TEST(test_add_float_t_rejects_inf);
	RUN_TEST(test_binary_data_round_trip);
	RUN_TEST(test_decode_full_rfc8428_vector);
	RUN_TEST(test_decode_rejects_malformed_inputs);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
