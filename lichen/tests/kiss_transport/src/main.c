/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief KISS transport test suite
 *
 * Tests the KISS TNC protocol transport per spec/kiss-framing.md.
 */

#include <zephyr/ztest.h>

#include <lichen/transport/kiss_transport.h>

/* Test state */
static int ax25_rx_count;
static int raw_rx_count;
static int lci_ipv6_rx_count;
static int lci_ctrl_rx_count;
static uint8_t last_ax25_data[256];
static size_t last_ax25_len;
static uint8_t last_raw_data[256];
static size_t last_raw_len;
static uint8_t last_lci_ipv6_data[256];
static size_t last_lci_ipv6_len;
static uint8_t last_lci_ctrl_data[256];
static size_t last_lci_ctrl_len;
static uint8_t written_data[KISS_MAX_PAYLOAD * 2u + 4u];
static size_t written_len;
static size_t writer_chunk;
static int writer_error;
static bool writer_stall;
static struct k_thread send_threads[2];
K_THREAD_STACK_ARRAY_DEFINE(send_stacks, 2, 1024);

static void ax25_rx_cb(const uint8_t *data, size_t len, void *user_ctx)
{
	ARG_UNUSED(user_ctx);
	ax25_rx_count++;
	if (len <= sizeof(last_ax25_data)) {
		memcpy(last_ax25_data, data, len);
		last_ax25_len = len;
	}
}

static void raw_rx_cb(const uint8_t *data, size_t len, void *user_ctx)
{
	ARG_UNUSED(user_ctx);
	raw_rx_count++;
	if (len <= sizeof(last_raw_data)) {
		memcpy(last_raw_data, data, len);
		last_raw_len = len;
	}
}

static void lci_ipv6_rx_cb(const uint8_t *data, size_t len, void *user_ctx)
{
	ARG_UNUSED(user_ctx);
	lci_ipv6_rx_count++;
	if (len <= sizeof(last_lci_ipv6_data)) {
		memcpy(last_lci_ipv6_data, data, len);
		last_lci_ipv6_len = len;
	}
}

static void lci_ctrl_rx_cb(const uint8_t *data, size_t len, void *user_ctx)
{
	ARG_UNUSED(user_ctx);
	lci_ctrl_rx_count++;
	if (len <= sizeof(last_lci_ctrl_data)) {
		memcpy(last_lci_ctrl_data, data, len);
		last_lci_ctrl_len = len;
	}
}

static int test_write_cb(const uint8_t *data, size_t len, void *user_ctx)
{
	size_t count;

	ARG_UNUSED(user_ctx);
	if (writer_error != 0) {
		return writer_error;
	}
	if (writer_stall) {
		return 0;
	}
	count = writer_chunk == 0u ? len : MIN(len, writer_chunk);
	if (count > sizeof(written_data) - written_len) {
		return -ENOSPC;
	}
	memcpy(&written_data[written_len], data, count);
	written_len += count;
	return (int)count;
}

static void concurrent_send(void *p1, void *p2, void *p3)
{
	const uint8_t *payload = p1;
	int *result = p2;

	ARG_UNUSED(p3);
	*result = kiss_transport_send_ax25(payload, 4u);
}

static struct kiss_transport_config get_test_config(void) {
	struct kiss_transport_config c = {
		.ax25_rx_cb = ax25_rx_cb,
		.raw_rx_cb = raw_rx_cb,
		.lci_ipv6_cb = lci_ipv6_rx_cb,
		.lci_ctrl_cb = lci_ctrl_rx_cb,
		.write_cb = test_write_cb,
		.user_ctx = NULL,
	};
	return c;
}

static void reset_test_state(void *fixture)
{
	ARG_UNUSED(fixture);
	kiss_transport_deinit();
	ax25_rx_count = 0;
	raw_rx_count = 0;
	lci_ipv6_rx_count = 0;
	lci_ctrl_rx_count = 0;
	last_ax25_len = 0;
	last_raw_len = 0;
	last_lci_ipv6_len = 0;
	last_lci_ctrl_len = 0;
	written_len = 0;
	writer_chunk = 0;
	writer_error = 0;
	writer_stall = false;
}

ZTEST_SUITE(kiss_transport, NULL, NULL, reset_test_state, NULL, NULL);

/**
 * Test KISS constants are correctly defined per KA9Q spec.
 */
ZTEST(kiss_transport, test_kiss_constants)
{
	zassert_equal(KISS_FEND, 0xC0, "KISS_FEND must be 0xC0");
	zassert_equal(KISS_FESC, 0xDB, "KISS_FESC must be 0xDB");
	zassert_equal(KISS_TFEND, 0xDC, "KISS_TFEND must be 0xDC");
	zassert_equal(KISS_TFESC, 0xDD, "KISS_TFESC must be 0xDD");
}

/**
 * Test KISS command constants.
 */
ZTEST(kiss_transport, test_kiss_commands)
{
	zassert_equal(KISS_CMD_DATA, 0x00, "KISS_CMD_DATA must be 0x00");
	zassert_equal(KISS_CMD_TXDELAY, 0x01, "KISS_CMD_TXDELAY must be 0x01");
	zassert_equal(KISS_CMD_PERSISTENCE, 0x02, "KISS_CMD_PERSISTENCE must be 0x02");
	zassert_equal(KISS_CMD_SLOTTIME, 0x03, "KISS_CMD_SLOTTIME must be 0x03");
	zassert_equal(KISS_CMD_TXTAIL, 0x04, "KISS_CMD_TXTAIL must be 0x04");
	zassert_equal(KISS_CMD_FULLDUPLEX, 0x05, "KISS_CMD_FULLDUPLEX must be 0x05");
	zassert_equal(KISS_CMD_SETHARDWARE, 0x06, "KISS_CMD_SETHARDWARE must be 0x06");
	zassert_equal(KISS_CMD_RETURN, 0x0F, "KISS_CMD_RETURN must be 0x0F");
}

/**
 * Test KISS port assignments.
 */
ZTEST(kiss_transport, test_kiss_ports)
{
	zassert_equal(KISS_PORT_AX25, 0, "Port 0 must be AX.25");
	zassert_equal(KISS_PORT_LICHEN_RAW, 1, "Port 1 must be raw LICHEN");
	zassert_equal(KISS_PORT_MAX, 15, "Max port must be 15");
}

/**
 * Test CMD byte extraction macros.
 */
ZTEST(kiss_transport, test_cmd_macros)
{
	/* Port 0, Data command */
	zassert_equal(KISS_CMD_PORT(0x00), 0, "Port extraction for 0x00");
	zassert_equal(KISS_CMD_TYPE(0x00), 0, "Type extraction for 0x00");
	zassert_equal(KISS_CMD_MAKE(0, 0), 0x00, "Make cmd 0x00");

	/* Port 1, Data command */
	zassert_equal(KISS_CMD_PORT(0x10), 1, "Port extraction for 0x10");
	zassert_equal(KISS_CMD_TYPE(0x10), 0, "Type extraction for 0x10");
	zassert_equal(KISS_CMD_MAKE(1, 0), 0x10, "Make cmd 0x10");

	/* Port 0, TxDelay command */
	zassert_equal(KISS_CMD_PORT(0x01), 0, "Port extraction for 0x01");
	zassert_equal(KISS_CMD_TYPE(0x01), 1, "Type extraction for 0x01");
	zassert_equal(KISS_CMD_MAKE(0, 1), 0x01, "Make cmd 0x01");

	/* Port 15, Return command */
	zassert_equal(KISS_CMD_PORT(0xFF), 15, "Port extraction for 0xFF");
	zassert_equal(KISS_CMD_TYPE(0xFF), 15, "Type extraction for 0xFF");
	zassert_equal(KISS_CMD_MAKE(15, 15), 0xFF, "Make cmd 0xFF");
}

/**
 * Test KISS decode context initialization.
 */
ZTEST(kiss_transport, test_decode_init)
{
	struct kiss_decode_ctx ctx;

	kiss_decode_init(&ctx);

	zassert_equal(ctx.len, 0, "Length should be 0");
	zassert_false(ctx.in_frame, "Should not be in frame");
	zassert_false(ctx.escape_next, "Should not be escaping");
	zassert_false(ctx.has_cmd, "Should not have command");
}

/**
 * Test KISS frame encoding.
 */
ZTEST(kiss_transport, test_encode_simple)
{
	uint8_t data[] = { 0x01, 0x02, 0x03 };
	uint8_t frame[32];
	size_t frame_len;
	int ret;

	ret = kiss_encode(0, KISS_CMD_DATA, data, sizeof(data),
			  frame, sizeof(frame), &frame_len);
	zassert_equal(ret, 0, "Encode should succeed");

	/* Expected: FEND + CMD + data + FEND */
	zassert_equal(frame_len, 6, "Frame length should be 6");
	zassert_equal(frame[0], KISS_FEND, "First byte should be FEND");
	zassert_equal(frame[1], 0x00, "CMD byte should be 0x00 (port 0, data)");
	zassert_equal(frame[2], 0x01, "Data byte 1");
	zassert_equal(frame[3], 0x02, "Data byte 2");
	zassert_equal(frame[4], 0x03, "Data byte 3");
	zassert_equal(frame[5], KISS_FEND, "Last byte should be FEND");
}

/**
 * Test KISS frame encoding with port 1.
 */
ZTEST(kiss_transport, test_encode_port1)
{
	uint8_t data[] = { 0xAA, 0xBB };
	uint8_t frame[32];
	size_t frame_len;
	int ret;

	ret = kiss_encode(1, KISS_CMD_DATA, data, sizeof(data),
			  frame, sizeof(frame), &frame_len);
	zassert_equal(ret, 0, "Encode should succeed");

	zassert_equal(frame[1], 0x10, "CMD byte should be 0x10 (port 1, data)");
}

/**
 * Test KISS frame encoding with escape sequences.
 */
ZTEST(kiss_transport, test_encode_escape)
{
	/* Data containing special bytes that need escaping */
	uint8_t data[] = { 0xC0, 0xDB, 0x42 };  /* FEND, FESC, regular */
	uint8_t frame[32];
	size_t frame_len;
	int ret;

	ret = kiss_encode(0, KISS_CMD_DATA, data, sizeof(data),
			  frame, sizeof(frame), &frame_len);
	zassert_equal(ret, 0, "Encode should succeed");

	/* Expected: FEND + CMD + (FESC TFEND) + (FESC TFESC) + 0x42 + FEND = 8 bytes */
	zassert_equal(frame_len, 8, "Frame length should be 8");
	zassert_equal(frame[0], KISS_FEND, "First byte");
	zassert_equal(frame[1], 0x00, "CMD byte");
	zassert_equal(frame[2], KISS_FESC, "Escape prefix for 0xC0");
	zassert_equal(frame[3], KISS_TFEND, "Escaped FEND");
	zassert_equal(frame[4], KISS_FESC, "Escape prefix for 0xDB");
	zassert_equal(frame[5], KISS_TFESC, "Escaped FESC");
	zassert_equal(frame[6], 0x42, "Regular byte");
	zassert_equal(frame[7], KISS_FEND, "Last byte");
}

/**
 * Test that a command byte colliding with FEND is escaped on the wire.
 *
 * (port=12, cmd=0) makes the command byte 0xC0 == FEND; an unescaped
 * encoding produces a frame the decoder rejects as empty.
 */
ZTEST(kiss_transport, test_encode_cmd_byte_escaped)
{
	uint8_t data[] = { 0x01 };
	uint8_t frame[32];
	size_t frame_len;
	struct kiss_decode_ctx ctx;
	int ret;

	ret = kiss_encode(12, KISS_CMD_DATA, data, sizeof(data),
			  frame, sizeof(frame), &frame_len);
	zassert_equal(ret, 0, "Encode should succeed");

	/* Expected: FEND + FESC + TFEND + data + FEND */
	zassert_equal(frame_len, 5, "Frame length should be 5");
	zassert_equal(frame[0], KISS_FEND, "First byte should be FEND");
	zassert_equal(frame[1], KISS_FESC, "Escaped cmd: FESC");
	zassert_equal(frame[2], KISS_TFEND, "Escaped cmd: TFEND");
	zassert_equal(frame[3], 0x01, "Data byte");
	zassert_equal(frame[4], KISS_FEND, "Last byte should be FEND");

	/* Round-trip through the stream decoder */
	kiss_decode_init(&ctx);
	for (size_t i = 0; i < frame_len - 1; i++) {
		ret = kiss_decode_byte(&ctx, frame[i]);
		zassert_equal(ret, 0, "Intermediate bytes should return 0");
	}
	ret = kiss_decode_byte(&ctx, frame[frame_len - 1]);
	zassert_equal(ret, 1, "Final FEND should complete frame");
	zassert_equal(ctx.cmd, 0xC0, "CMD should be 0xC0 (port 12, data)");
	zassert_equal(ctx.len, 1, "Data length should be 1");
	zassert_equal(ctx.buf[0], 0x01, "Data byte");
}

/**
 * Test KISS frame decoding.
 */
ZTEST(kiss_transport, test_decode_simple)
{
	struct kiss_decode_ctx ctx;
	const uint8_t frame[] = { KISS_FEND, 0x00, 0x01, 0x02, 0x03, KISS_FEND };
	int ret;

	kiss_decode_init(&ctx);

	for (size_t i = 0; i < sizeof(frame) - 1; i++) {
		ret = kiss_decode_byte(&ctx, frame[i]);
		zassert_equal(ret, 0, "Intermediate bytes should return 0");
	}

	/* Last byte should complete the frame */
	ret = kiss_decode_byte(&ctx, frame[sizeof(frame) - 1]);
	zassert_equal(ret, 1, "Final FEND should complete frame");

	zassert_equal(ctx.cmd, 0x00, "CMD should be 0x00");
	zassert_equal(ctx.len, 3, "Data length should be 3");
	zassert_equal(ctx.buf[0], 0x01, "Data byte 1");
	zassert_equal(ctx.buf[1], 0x02, "Data byte 2");
	zassert_equal(ctx.buf[2], 0x03, "Data byte 3");
}

/**
 * Test KISS frame decoding with escape sequences.
 */
ZTEST(kiss_transport, test_decode_escape)
{
	struct kiss_decode_ctx ctx;
	const uint8_t frame[] = { KISS_FEND, 0x00, KISS_FESC, KISS_TFEND,
			    KISS_FESC, KISS_TFESC, KISS_FEND };
	int ret;

	kiss_decode_init(&ctx);

	for (size_t i = 0; i < sizeof(frame) - 1; i++) {
		ret = kiss_decode_byte(&ctx, frame[i]);
		zassert_true(ret <= 0, "Intermediate bytes should not complete");
	}

	ret = kiss_decode_byte(&ctx, frame[sizeof(frame) - 1]);
	zassert_equal(ret, 1, "Final FEND should complete frame");

	zassert_equal(ctx.len, 2, "Data length should be 2");
	zassert_equal(ctx.buf[0], 0xC0, "First byte should be unescaped FEND");
	zassert_equal(ctx.buf[1], 0xDB, "Second byte should be unescaped FESC");
}

/**
 * Test invalid escape sequence handling.
 */
ZTEST(kiss_transport, test_decode_invalid_escape)
{
	struct kiss_decode_ctx ctx;
	const uint8_t frame[] = { KISS_FEND, 0x00, KISS_FESC, 0x42, KISS_FEND };
	int ret;

	kiss_decode_init(&ctx);

	ret = kiss_decode_byte(&ctx, frame[0]);
	zassert_equal(ret, 0, "FEND ok");
	ret = kiss_decode_byte(&ctx, frame[1]);
	zassert_equal(ret, 0, "CMD ok");
	ret = kiss_decode_byte(&ctx, frame[2]);
	zassert_equal(ret, 0, "FESC ok");

	/* Invalid escape sequence should return error */
	ret = kiss_decode_byte(&ctx, frame[3]);
	zassert_equal(ret, -EILSEQ, "Invalid escape should fail");
}

/**
 * Test empty frame handling.
 */
ZTEST(kiss_transport, test_decode_empty)
{
	struct kiss_decode_ctx ctx;
	const uint8_t frame[] = { KISS_FEND, KISS_FEND };
	int ret;

	kiss_decode_init(&ctx);

	ret = kiss_decode_byte(&ctx, frame[0]);
	zassert_equal(ret, 0, "First FEND ok");

	ret = kiss_decode_byte(&ctx, frame[1]);
	zassert_equal(ret, 0, "Empty frame should not complete");
}

/**
 * Test frame with command only (no data).
 */
ZTEST(kiss_transport, test_decode_cmd_only)
{
	struct kiss_decode_ctx ctx;
	const uint8_t frame[] = { KISS_FEND, 0x01, KISS_FEND };  /* TxDelay cmd */
	int ret;

	kiss_decode_init(&ctx);

	for (size_t i = 0; i < sizeof(frame) - 1; i++) {
		ret = kiss_decode_byte(&ctx, frame[i]);
		zassert_equal(ret, 0, "Intermediate bytes ok");
	}

	/* DATA is 0-N bytes and Return is command-only, so the decoder must
	 * publish a frame once a command byte has been received. */
	ret = kiss_decode_byte(&ctx, frame[sizeof(frame) - 1]);
	zassert_equal(ret, 1, "Frame with no data should complete");
	zassert_equal(ctx.len, 0, "Command-only frame has empty data");
}

ZTEST(kiss_transport, test_decode_requires_delimiter_and_resynchronizes)
{
	struct kiss_decode_ctx ctx;
	const uint8_t noise[] = { 0x00, 0x11, KISS_FESC, KISS_TFEND };
	const uint8_t malformed[] = {
		KISS_FEND, 0x00, KISS_FESC, 0x42, 0x99,
		KISS_FEND, 0x10, 0x55, KISS_FEND,
	};
	int ret = 0;

	kiss_decode_init(&ctx);
	for (size_t i = 0; i < sizeof(noise); i++) {
		zassert_equal(kiss_decode_byte(&ctx, noise[i]), 0,
			      "Pre-delimiter noise must be ignored");
	}
	zassert_false(ctx.has_cmd, "Noise must not create a frame");

	for (size_t i = 0; i < sizeof(malformed); i++) {
		ret = kiss_decode_byte(&ctx, malformed[i]);
		if (i == 3u) {
			zassert_equal(ret, -EILSEQ, "Malformed escape rejected");
		}
	}
	zassert_equal(ret, 1, "Decoder must recover at the next delimiter");
	zassert_equal(ctx.cmd, 0x10, "Recovered frame command");
	zassert_equal(ctx.len, 1, "Recovered frame length");
	zassert_equal(ctx.buf[0], 0x55, "Recovered frame payload");
}

ZTEST(kiss_transport, test_decode_fragmented_multiple_and_overflow)
{
	struct kiss_decode_ctx ctx;
	int ret;

	kiss_decode_init(&ctx);
	zassert_equal(kiss_decode_byte(&ctx, KISS_FEND), 0, "Start");
	zassert_equal(kiss_decode_byte(&ctx, 0x00), 0, "Command");
	for (size_t i = 0; i < KISS_MAX_PAYLOAD; i++) {
		zassert_equal(kiss_decode_byte(&ctx, 0x5a), 0, "Max payload accepted");
	}
	ret = kiss_decode_byte(&ctx, 0x5a);
	zassert_equal(ret, -EOVERFLOW, "One byte beyond maximum rejected");
	zassert_equal(kiss_decode_byte(&ctx, 0x77), 0, "Discard until delimiter");
	zassert_equal(kiss_decode_byte(&ctx, KISS_FEND), 0, "Resynchronize");
	zassert_equal(kiss_decode_byte(&ctx, 0x00), 0, "Next command");
	zassert_equal(kiss_decode_byte(&ctx, 0x01), 0, "Fragment one");
	zassert_equal(kiss_decode_byte(&ctx, 0x02), 0, "Fragment two");
	zassert_equal(kiss_decode_byte(&ctx, KISS_FEND), 1, "Frame complete");
	zassert_equal(ctx.len, 2, "Fragmented payload retained");

	kiss_decode_consume(&ctx);
	zassert_equal(kiss_decode_byte(&ctx, 0x10), 0,
		      "Shared delimiter starts next frame");
	zassert_equal(kiss_decode_byte(&ctx, KISS_FEND), 1,
		      "Back-to-back command-only frame complete");
	zassert_equal(ctx.cmd, 0x10, "Second frame command");
}

ZTEST(kiss_transport, test_encode_validates_and_is_atomic)
{
	const uint8_t data[] = { KISS_FEND, KISS_FESC };
	uint8_t frame[8];
	uint8_t before[sizeof(frame)];
	size_t frame_len = 0x1234u;
	int ret;

	memset(frame, 0xa5, sizeof(frame));
	memcpy(before, frame, sizeof(frame));
	ret = kiss_encode(0, KISS_CMD_DATA, data, sizeof(data), frame, 6u, &frame_len);
	zassert_equal(ret, -ENOMEM, "Short output rejected");
	zassert_mem_equal(frame, before, sizeof(frame), "Failed encode is atomic");
	zassert_equal(frame_len, 0x1234u, "Failed encode preserves length output");
	zassert_equal(kiss_encode(0, 16u, NULL, 0u, frame, sizeof(frame), &frame_len),
		      -EINVAL, "Command nibble validated");
	zassert_equal(kiss_encode(16u, 0u, NULL, 0u, frame, sizeof(frame), &frame_len),
		      -EINVAL, "Port nibble validated");
	zassert_equal(kiss_encode(0u, 0u, before, KISS_MAX_PAYLOAD + 1u,
				  frame, sizeof(frame), &frame_len),
		      -EMSGSIZE, "Payload bound validated before reading input");
}

ZTEST(kiss_transport, test_encode_maximum_escaped_payload)
{
	static uint8_t payload[KISS_MAX_PAYLOAD];
	static uint8_t frame[KISS_MAX_PAYLOAD * 2u + 4u];
	size_t frame_len = 0;

	memset(payload, KISS_FEND, sizeof(payload));
	zassert_ok(kiss_encode(0, KISS_CMD_DATA, payload, sizeof(payload),
			       frame, sizeof(frame), &frame_len),
		   "Maximum payload encodes");
	zassert_equal(frame_len, KISS_MAX_PAYLOAD * 2u + 3u,
		      "Exact worst-case encoded size");
	zassert_equal(frame[0], KISS_FEND, "Opening delimiter");
	zassert_equal(frame[frame_len - 1u], KISS_FEND, "Closing delimiter");
}

/**
 * Test get_stats with NULL returns error.
 */
ZTEST(kiss_transport, test_get_stats_null)
{
	int ret = kiss_transport_get_stats(NULL);
	zassert_equal(ret, -EINVAL, "get_stats with NULL should fail");
}

/**
 * Test get_params with NULL returns error.
 */
ZTEST(kiss_transport, test_get_params_null)
{
	int ret = kiss_transport_get_params(NULL);
	zassert_equal(ret, -EINVAL, "get_params with NULL should fail");
}

/**
 * Test set_params with NULL returns error.
 */
ZTEST(kiss_transport, test_set_params_null)
{
	int ret = kiss_transport_set_params(NULL);
	zassert_equal(ret, -EINVAL, "set_params with NULL should fail");
}

#ifdef CONFIG_ZTEST
/**
 * Test AX.25 frame reception (port 0) via inject.
 */
ZTEST(kiss_transport, test_rx_ax25)
{
	/* Initialize transport first */
	struct kiss_transport_config config = get_test_config();
	int ret = kiss_transport_init(&config);
	zassert_true(ret == 0 || ret == -EALREADY, "Init should succeed or already be done");

	/* KISS frame: port 0, data command, payload "TEST" */
	uint8_t frame[] = { KISS_FEND, 0x00, 'T', 'E', 'S', 'T', KISS_FEND };

	int frames = kiss_transport_test_inject_rx(frame, sizeof(frame));
	zassert_equal(frames, 1, "Should decode one frame");
	zassert_equal(ax25_rx_count, 1, "AX.25 callback should be called once");
	zassert_equal(raw_rx_count, 0, "Raw callback should not be called");
	zassert_equal(last_ax25_len, 4, "AX.25 data length should be 4");
	zassert_mem_equal(last_ax25_data, "TEST", 4, "AX.25 data should match");
}

/**
 * Test raw LICHEN frame reception (port 1) via inject.
 */
ZTEST(kiss_transport, test_rx_raw)
{
	/* Initialize transport first */
	struct kiss_transport_config config = get_test_config();
	int ret = kiss_transport_init(&config);
	zassert_ok(ret);

	/* KISS frame: port 1 (0x10), data command, payload */
	uint8_t frame[] = { KISS_FEND, 0x10, 0xAA, 0xBB, 0xCC, KISS_FEND };

	int frames = kiss_transport_test_inject_rx(frame, sizeof(frame));
	zassert_equal(frames, 1, "Should decode one frame");
	zassert_equal(raw_rx_count, 1, "Raw callback should be called once");
	zassert_equal(last_raw_len, 3, "Raw data length should be 3");
	zassert_equal(last_raw_data[0], 0xAA, "Raw data byte 0");
	zassert_equal(last_raw_data[1], 0xBB, "Raw data byte 1");
	zassert_equal(last_raw_data[2], 0xCC, "Raw data byte 2");
}

/**
 * Test TxDelay command handling via inject.
 */
ZTEST(kiss_transport, test_cmd_txdelay)
{
	struct kiss_transport_config config = get_test_config();
	int ret = kiss_transport_init(&config);
	zassert_ok(ret);

	const uint8_t frame[] = { KISS_FEND, KISS_CMD_TXDELAY, 100, KISS_FEND };

	int frames = kiss_transport_test_inject_rx(frame, sizeof(frame));
	zassert_equal(frames, 1, "Should process one command frame");

	struct kiss_params params;
	ret = kiss_transport_get_params(&params);
	zassert_equal(ret, 0, "get_params ok");
	zassert_equal(params.txdelay, 100, "TxDelay should be 100");
}

/**
 * Test Persistence command handling via inject.
 */
ZTEST(kiss_transport, test_cmd_persistence)
{
	struct kiss_transport_config config = get_test_config();
	int ret = kiss_transport_init(&config);
	zassert_true(ret == 0 || ret == -EALREADY,
		     "Init should succeed or already be done");

	const uint8_t frame[] = { KISS_FEND, KISS_CMD_PERSISTENCE, 128, KISS_FEND };

	int frames = kiss_transport_test_inject_rx(frame, sizeof(frame));
	zassert_equal(frames, 1, "Should process one command frame");

	struct kiss_params params;
	ret = kiss_transport_get_params(&params);
	zassert_equal(ret, 0, "get_params ok");
	zassert_equal(params.persistence, 128, "Persistence should be 128");

	struct kiss_transport_stats stats;
	ret = kiss_transport_get_stats(&stats);
	zassert_equal(ret, 0, "get_stats ok");
	zassert_equal(stats.rx_commands, 1u, "One timing command should be counted");
}

/**
 * Test SlotTime command handling via inject.
 */
ZTEST(kiss_transport, test_cmd_slottime)
{
	struct kiss_transport_config config = get_test_config();
	int ret = kiss_transport_init(&config);
	zassert_true(ret == 0 || ret == -EALREADY,
		     "Init should succeed or already be done");

	/* SlotTime command (10ms units): set to 20 (=200ms) */
	uint8_t frame[] = { KISS_FEND, KISS_CMD_SLOTTIME, 20, KISS_FEND };

	int frames = kiss_transport_test_inject_rx(frame, sizeof(frame));
	zassert_equal(frames, 1, "Should process one command frame");

	struct kiss_params params;
	ret = kiss_transport_get_params(&params);
	zassert_equal(ret, 0, "get_params ok");
	zassert_equal(params.slottime, 20, "SlotTime should be 20");

	struct kiss_transport_stats stats;
	ret = kiss_transport_get_stats(&stats);
	zassert_equal(ret, 0, "get_stats ok");
	zassert_equal(stats.rx_commands, 1u, "One timing command should be counted");
}

/**
 * Test send functions when not ready.
 */
ZTEST(kiss_transport, test_send_not_ready)
{
	uint8_t data[] = { 0x01, 0x02 };

	int ret = kiss_transport_send_ax25(data, sizeof(data));
	zassert_equal(ret, -ENODEV, "Uninitialized AX.25 send rejected");

	ret = kiss_transport_send_raw(data, sizeof(data));
	zassert_equal(ret, -ENODEV, "Uninitialized raw send rejected");
}

/**
 * Test send with oversized data.
 */
ZTEST(kiss_transport, test_send_oversized)
{
	struct kiss_transport_config config = get_test_config();
	uint8_t oversized[KISS_MAX_PAYLOAD + 100] = {0};
	zassert_ok(kiss_transport_init(&config), "Init");

	int ret = kiss_transport_send_ax25(oversized, sizeof(oversized));
	zassert_equal(ret, -EMSGSIZE, "Oversized data should be rejected");

	ret = kiss_transport_send_raw(oversized, KISS_RAW_MAX_PAYLOAD + 1U);
	zassert_equal(ret, -EMSGSIZE, "Oversized raw frame should be rejected");
}

/**
 * Test send with invalid port.
 */
ZTEST(kiss_transport, test_send_invalid_port)
{
	struct kiss_transport_config config = get_test_config();
	uint8_t data[] = { 0x01 };
	zassert_ok(kiss_transport_init(&config), "Init");

	int ret = kiss_transport_send(16, data, sizeof(data));
	zassert_equal(ret, -EINVAL, "Port > 15 should be rejected");
}

ZTEST(kiss_transport, test_partial_write_and_backpressure)
{
	struct kiss_transport_config config = get_test_config();
	const uint8_t data[] = { 0x01, KISS_FEND, KISS_FESC, 0x02 };
	struct kiss_transport_stats stats;
	int ret;

	writer_chunk = 2u;
	zassert_ok(kiss_transport_init(&config), "Init with injectable writer");
	zassert_true(kiss_transport_is_ready(), "Writer-backed transport ready");
	ret = kiss_transport_send_ax25(data, sizeof(data));
	zassert_ok(ret, "Partial writes must be retried to completion");
	zassert_equal(written_len, 9u, "Escaped frame length");
	zassert_equal(written_data[0], KISS_FEND, "Opening delimiter");
	zassert_equal(written_data[written_len - 1u], KISS_FEND, "Closing delimiter");
	zassert_ok(kiss_transport_get_stats(&stats), "Stats");
	zassert_equal(stats.tx_frames, 1u, "Only complete sends counted");

	writer_error = -EAGAIN;
	ret = kiss_transport_send_ax25(data, sizeof(data));
	zassert_equal(ret, -EAGAIN, "Writer backpressure propagated");
	zassert_ok(kiss_transport_get_stats(&stats), "Stats after error");
	zassert_equal(stats.tx_frames, 1u, "Failed sends not counted");

	writer_error = 0;
	writer_stall = true;
	ret = kiss_transport_send_ax25(data, sizeof(data));
	zassert_equal(ret, -EIO, "Zero-progress writer fails instead of looping");
}

ZTEST(kiss_transport, test_stream_multiple_empty_and_invalid_command)
{
	struct kiss_transport_config config = get_test_config();
	const uint8_t stream[] = {
		0x55, 0xaa, KISS_FEND,
		0x00, KISS_FEND,       /* Empty AX.25 data frame. */
		0x10, 0x42, KISS_FEND, /* Shared delimiter, raw frame. */
		0x20, 0x60, KISS_FEND, /* LCI IPv6 port. */
		0x30, 0xa1, KISS_FEND, /* LCI control port. */
		0x07, 0x99, KISS_FEND, /* Undefined command. */
	};
	struct kiss_transport_stats stats;

	zassert_ok(kiss_transport_init(&config), "Init");
	zassert_equal(kiss_transport_test_inject_rx(stream, sizeof(stream)), 5,
		      "Five syntactically complete frames consumed");
	zassert_equal(ax25_rx_count, 1, "Empty data frame delivered");
	zassert_equal(last_ax25_len, 0u, "Empty payload preserved");
	zassert_equal(raw_rx_count, 1, "Second shared-delimiter frame delivered");
	zassert_equal(last_raw_data[0], 0x42, "Second payload");
	zassert_equal(lci_ipv6_rx_count, 1, "LCI IPv6 port delivered");
	zassert_equal(last_lci_ipv6_data[0], 0x60, "IPv6 version nibble retained");
	zassert_equal(lci_ctrl_rx_count, 1, "LCI control port delivered");
	zassert_equal(last_lci_ctrl_data[0], 0xa1, "Control payload retained");
	zassert_ok(kiss_transport_get_stats(&stats), "Stats");
	zassert_equal(stats.rx_frames, 4u, "Undefined command is not accepted");
	zassert_equal(stats.frame_errors, 1u, "Undefined command counted as error");
}

ZTEST(kiss_transport, test_concurrent_sends_are_not_interleaved)
{
	struct kiss_transport_config config = get_test_config();
	static const uint8_t payloads[2][4] = {
		{ 0x11, 0x12, 0x13, 0x14 },
		{ 0x21, 0x22, 0x23, 0x24 },
	};
	int results[2] = { -1, -1 };

	writer_chunk = 1u;
	zassert_ok(kiss_transport_init(&config), "Init");
	for (size_t i = 0; i < ARRAY_SIZE(send_threads); i++) {
		k_thread_create(&send_threads[i], send_stacks[i],
				K_THREAD_STACK_SIZEOF(send_stacks[i]), concurrent_send,
				(void *)payloads[i], &results[i], NULL,
				K_PRIO_PREEMPT(1), 0, K_NO_WAIT);
	}
	for (size_t i = 0; i < ARRAY_SIZE(send_threads); i++) {
		zassert_ok(k_thread_join(&send_threads[i], K_SECONDS(1)), "Join sender");
		zassert_ok(results[i], "Concurrent send result");
	}
	zassert_equal(written_len, 14u, "Two complete frames written");
	zassert_equal(written_data[0], KISS_FEND, "First frame start");
	zassert_equal(written_data[6], KISS_FEND, "First frame end");
	zassert_equal(written_data[7], KISS_FEND, "Second frame start");
	zassert_equal(written_data[13], KISS_FEND, "Second frame end");
}
#endif /* CONFIG_ZTEST */
