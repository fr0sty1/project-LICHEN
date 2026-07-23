/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <lichen/native.h>
#include <zcbor_common.h>
#include <zcbor_decode.h>

int lichen_native_parse_msg_type_for_test(const uint8_t *buf, size_t len);
int lichen_native_parse_log_subscribe_for_test(const uint8_t *buf, size_t len,
					       bool *enable);
int lichen_native_encode_hello_for_test(uint8_t *buf, size_t len);
void lichen_native_test_tx_clear(void);
size_t lichen_native_test_tx_snapshot(uint8_t *buf, size_t cap, bool *overflow);

#define NATIVE_FRAME_SYNC 0xC1u
#define NATIVE_FRAME_SYNC_OFFSET 0U
#define NATIVE_FRAME_LEN_HI_OFFSET 1U
#define NATIVE_FRAME_LEN_LO_OFFSET 2U
#define NATIVE_FRAME_HEADER_LEN 3U

#define TX_WORKER_COUNT 4U
#define TX_SENDS_PER_WORKER 12U
#define TX_CAPTURE_SIZE 8192U

struct tx_worker_ctx {
	struct k_sem *start;
	struct k_sem *done;
	uint8_t worker_id;
};

static K_THREAD_STACK_ARRAY_DEFINE(tx_worker_stacks, TX_WORKER_COUNT, 2048);
static struct k_thread tx_worker_threads[TX_WORKER_COUNT];
static struct tx_worker_ctx tx_worker_ctxs[TX_WORKER_COUNT];
static struct k_sem tx_start_sem;
static struct k_sem tx_done_sem;
static uint8_t tx_capture[TX_CAPTURE_SIZE];

static uint16_t native_frame_payload_len(const uint8_t *frame)
{
	return ((uint16_t)frame[NATIVE_FRAME_LEN_HI_OFFSET] << 8) |
	       frame[NATIVE_FRAME_LEN_LO_OFFSET];
}

static int native_next_frame(const uint8_t *stream, size_t stream_len, size_t *offset,
			     const uint8_t **payload, size_t *payload_len)
{
	size_t pos;
	uint16_t len;

	if (stream == NULL || offset == NULL || payload == NULL || payload_len == NULL) {
		return -EINVAL;
	}

	pos = *offset;
	if (pos == stream_len) {
		return -ENOENT;
	}
	if (stream_len - pos < NATIVE_FRAME_HEADER_LEN ||
	    stream[pos + NATIVE_FRAME_SYNC_OFFSET] != NATIVE_FRAME_SYNC) {
		return -EBADMSG;
	}

	len = native_frame_payload_len(&stream[pos]);
	if (len == 0 || stream_len - pos - NATIVE_FRAME_HEADER_LEN < len) {
		return -EBADMSG;
	}

	*payload = &stream[pos + NATIVE_FRAME_HEADER_LEN];
	*payload_len = len;
	*offset = pos + NATIVE_FRAME_HEADER_LEN + len;
	return 0;
}

static int cbor_map_is_complete(const uint8_t *buf, size_t len)
{
	if (buf == NULL || len == 0) {
		return -EINVAL;
	}

	ZCBOR_STATE_D(zsd, 2, buf, len, 1, 0);

	if (!zcbor_map_start_decode(zsd)) {
		return -EINVAL;
	}

	while (!zcbor_array_at_end(zsd)) {
		if (!zcbor_any_skip(zsd, NULL) || !zcbor_any_skip(zsd, NULL)) {
			goto cleanup;
		}
	}

	if (!zcbor_map_end_decode(zsd) || !zcbor_payload_at_end(zsd)) {
		goto cleanup;
	}

	return 0;

cleanup:
	(void)zcbor_list_map_end_force_decode(zsd);
	return -EINVAL;
}

static void native_enable_log_stream_for_test(void)
{
	const uint8_t payload[] = {
		0xa2,                         /* map(2) */
		0x00, 0x18, LN_TYPE_LOG_SUBSCRIBE,
		0x01, 0xf5,                   /* 1: true */
	};

	lichen_native_handle_rx(LN_TYPE_LOG_SUBSCRIBE, payload, sizeof(payload));
	zassert_true(lichen_native_log_is_subscribed());
}

static void tx_worker(void *p1, void *p2, void *p3)
{
	struct tx_worker_ctx *ctx = p1;
	static const uint8_t iid[8] = {
		0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01,
	};
	const struct ln_radio_stats radio = {
		.tx_pkts = 17,
		.rx_pkts = 23,
	};
	const struct ln_gps_info gps = {
		.lat_udeg = 47500000,
		.lon_udeg = -122300000,
		.alt_cm = 1234,
		.satellites = 8,
		.valid = true,
	};
	uint8_t payload[48];

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	memset(payload, (int)(0x30u + ctx->worker_id), sizeof(payload));
	k_sem_take(ctx->start, K_FOREVER);

	for (uint32_t i = 0; i < TX_SENDS_PER_WORKER; i++) {
		switch (ctx->worker_id) {
		case 0:
			zassert_ok(lichen_native_send_hello());
			break;
		case 1:
			zassert_ok(lichen_native_send_node_info("native-tx-node",
							       "fw-test",
							       "qemu-test",
							       i, iid, &gps, &radio));
			break;
		case 2:
			payload[0] = (uint8_t)i;
			zassert_ok(lichen_native_send_message_received(iid, payload,
								      sizeof(payload),
								      -71, 9));
			break;
		case 3:
			zassert_ok(lichen_native_send_log_entry(3, "native_tx",
							       "concurrency-regression"));
			break;
		default:
			zassert_unreachable("unexpected worker id");
		}
		k_yield();
	}

	k_sem_give(ctx->done);
}

static int hello_supported_contains(const uint8_t *buf, size_t len, uint8_t needle,
				    bool *found)
{
	uint32_t key = 0;

	if (buf == NULL || found == NULL) {
		return -EINVAL;
	}

	*found = false;

	ZCBOR_STATE_D(zsd, 2, buf, len, 1, 0);

	if (!zcbor_map_start_decode(zsd)) {
		return -EINVAL;
	}

	while (!zcbor_array_at_end(zsd)) {
		zcbor_state_t key_state = *zsd;

		if (zcbor_uint32_decode(zsd, &key) && key == 2u) {
			if (!zcbor_list_start_decode(zsd)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			while (!zcbor_array_at_end(zsd)) {
				uint32_t type = 0;

				if (!zcbor_uint32_decode(zsd, &type) || type > UINT8_MAX) {
					(void)zcbor_list_map_end_force_decode(zsd);
					return -EINVAL;
				}
				if ((uint8_t)type == needle) {
					*found = true;
				}
			}
			if (!zcbor_list_end_decode(zsd)) {
				(void)zcbor_list_map_end_force_decode(zsd);
				return -EINVAL;
			}
			continue;
		}

		(void)zcbor_pop_error(zsd);
		*zsd = key_state;

		if (!zcbor_any_skip(zsd, NULL) || !zcbor_any_skip(zsd, NULL)) {
			(void)zcbor_list_map_end_force_decode(zsd);
			return -EINVAL;
		}
	}

	if (!zcbor_map_end_decode(zsd)) {
		(void)zcbor_list_map_end_force_decode(zsd);
		return -EINVAL;
	}

	return 0;
}

ZTEST(native_parse, test_message_type_first)
{
	const uint8_t payload[] = {
		0xa2,       /* map(2) */
		0x00, 0x01, /* 0: hello */
		0x01, 0x01, /* 1: version */
	};

	zassert_equal(lichen_native_parse_msg_type_for_test(payload, sizeof(payload)),
		      LN_TYPE_HELLO);
}

ZTEST(native_parse, test_message_type_after_other_fields)
{
	const uint8_t payload[] = {
		0xa4,                   /* map(4) */
		0x03, 0x66, 'n', 'a', 't', 'i', 'v', 'e',
		0x07, 0xa1, 0x04, 0xf5, /* nested features map */
		0x00, 0x18, LN_TYPE_LOG_SUBSCRIBE,
		0x02, 0x82, 0x01, 0x02,
	};

	zassert_equal(lichen_native_parse_msg_type_for_test(payload, sizeof(payload)),
		      LN_TYPE_LOG_SUBSCRIBE);
}

ZTEST(native_parse, test_missing_message_type_rejected)
{
	const uint8_t payload[] = {
		0xa2,       /* map(2) */
		0x01, 0x01,
		0x02, 0x80,
	};

	zassert_equal(lichen_native_parse_msg_type_for_test(payload, sizeof(payload)), -1);
}

ZTEST(native_parse, test_non_map_rejected)
{
	const uint8_t payload[] = {
		0x82, 0x00, LN_TYPE_HELLO,
	};

	zassert_equal(lichen_native_parse_msg_type_for_test(payload, sizeof(payload)), -1);
}

ZTEST(native_parse, test_non_uint_message_type_rejected)
{
	const uint8_t payload[] = {
		0xa1, 0x00, 0xf5,
	};

	zassert_equal(lichen_native_parse_msg_type_for_test(payload, sizeof(payload)), -1);
}

ZTEST(native_parse, test_truncated_map_rejected)
{
	const uint8_t payload[] = {
		0xa1, 0x00, 0x18,
	};

	zassert_equal(lichen_native_parse_msg_type_for_test(payload, sizeof(payload)), -1);
}

ZTEST(native_parse, test_truncated_extension_after_message_type_rejected)
{
	const uint8_t payload[] = {
		0xa2, 0x00, LN_TYPE_HELLO, 0x01,
	};

	zassert_equal(lichen_native_parse_msg_type_for_test(payload, sizeof(payload)), -1);
}

ZTEST(native_parse, test_log_subscribe_enable_after_module_filter)
{
	const uint8_t payload[] = {
		0xa4,                         /* map(4) */
		0x00, 0x18, LN_TYPE_LOG_SUBSCRIBE,
		0x03, 0x82,                   /* 3: ["radio", "lora"] */
		      0x65, 'r', 'a', 'd', 'i', 'o',
		      0x64, 'l', 'o', 'r', 'a',
		0x01, 0xf5,                   /* 1: true */
		0x02, 0x04,                   /* 2: debug */
	};
	bool enable = false;

	zassert_ok(lichen_native_parse_log_subscribe_for_test(payload, sizeof(payload),
							     &enable));
	zassert_true(enable);
}

ZTEST(native_parse, test_log_subscribe_enable_after_extension_field)
{
	const uint8_t payload[] = {
		0xa4,                         /* map(4) */
		0x00, 0x18, LN_TYPE_LOG_SUBSCRIBE,
		0x09, 0xa1, 0x01, 0x82, 0x02, 0x03,
		0x02, 0x01,
		0x01, 0xf5,
	};
	bool enable = false;

	zassert_ok(lichen_native_parse_log_subscribe_for_test(payload, sizeof(payload),
							     &enable));
	zassert_true(enable);
}

ZTEST(native_parse, test_log_subscribe_disable)
{
	const uint8_t payload[] = {
		0xa2,
		0x00, 0x18, LN_TYPE_LOG_SUBSCRIBE,
		0x01, 0xf4,
	};
	bool enable = true;

	zassert_ok(lichen_native_parse_log_subscribe_for_test(payload, sizeof(payload),
							     &enable));
	zassert_false(enable);
}

ZTEST(native_parse, test_log_subscribe_missing_enable_rejected)
{
	const uint8_t payload[] = {
		0xa2,
		0x00, 0x18, LN_TYPE_LOG_SUBSCRIBE,
		0x02, 0x03,
	};
	bool enable = true;

	zassert_equal(lichen_native_parse_log_subscribe_for_test(payload, sizeof(payload),
								&enable),
		      -EINVAL);
	zassert_true(enable);
}

ZTEST(native_parse, test_log_subscribe_non_bool_enable_rejected)
{
	const uint8_t payload[] = {
		0xa2,
		0x00, 0x18, LN_TYPE_LOG_SUBSCRIBE,
		0x01, 0x01,
	};
	bool enable = false;

	zassert_equal(lichen_native_parse_log_subscribe_for_test(payload, sizeof(payload),
								&enable),
		      -EINVAL);
	zassert_false(enable);
}

ZTEST(native_parse, test_log_subscribe_truncated_extension_rejected)
{
	const uint8_t payload[] = {
		0xa3,
		0x00, 0x18, LN_TYPE_LOG_SUBSCRIBE,
		0x01, 0xf5,
		0x03, 0x82, 0x61, 'x',
	};
	bool enable = false;

	zassert_equal(lichen_native_parse_log_subscribe_for_test(payload, sizeof(payload),
								&enable),
		      -EINVAL);
	zassert_false(enable);
}

ZTEST(native_parse, test_default_hello_omits_unhandled_host_commands)
{
	uint8_t hello[96];
	int len = lichen_native_encode_hello_for_test(hello, sizeof(hello));
	bool found = true;

	zassert_true(len > 0);

	zassert_ok(hello_supported_contains(hello, (size_t)len,
					    LN_TYPE_SEND_MESSAGE, &found));
	zassert_false(found);

	zassert_ok(hello_supported_contains(hello, (size_t)len,
					    LN_TYPE_CONFIG_GET, &found));
	zassert_false(found);

	zassert_ok(hello_supported_contains(hello, (size_t)len,
					    LN_TYPE_CONFIG_RESULT, &found));
	zassert_false(found);

	zassert_ok(hello_supported_contains(hello, (size_t)len,
					    LN_TYPE_LOG_SUBSCRIBE, &found));
	zassert_true(found);

	zassert_ok(hello_supported_contains(hello, (size_t)len,
					    LN_TYPE_HELLO, &found));
	zassert_true(found);

	zassert_ok(hello_supported_contains(hello, (size_t)len,
					    LN_TYPE_MESSAGE_RECEIVED, &found));
	zassert_true(found);

	zassert_ok(hello_supported_contains(hello, (size_t)len,
					    LN_TYPE_NODE_INFO, &found));
	zassert_true(found);

	zassert_ok(hello_supported_contains(hello, (size_t)len,
					    LN_TYPE_LOG_ENTRY, &found));
	zassert_true(found);
}

ZTEST(native_parse, test_concurrent_public_tx_frames_remain_complete_cbor)
{
	size_t capture_len;
	size_t offset = 0;
	uint32_t hello_count = 0;
	uint32_t node_info_count = 0;
	uint32_t message_received_count = 0;
	uint32_t log_entry_count = 0;
	uint32_t total_count = 0;
	bool overflow = true;

	native_enable_log_stream_for_test();
	lichen_native_test_tx_clear();

	k_sem_init(&tx_start_sem, 0, TX_WORKER_COUNT);
	k_sem_init(&tx_done_sem, 0, TX_WORKER_COUNT);

	for (uint8_t i = 0; i < TX_WORKER_COUNT; i++) {
		tx_worker_ctxs[i].start = &tx_start_sem;
		tx_worker_ctxs[i].done = &tx_done_sem;
		tx_worker_ctxs[i].worker_id = i;

		k_thread_create(&tx_worker_threads[i], tx_worker_stacks[i],
				K_THREAD_STACK_SIZEOF(tx_worker_stacks[i]),
				tx_worker, &tx_worker_ctxs[i], NULL, NULL,
				K_PRIO_PREEMPT(0), 0, K_NO_WAIT);
	}

	for (uint8_t i = 0; i < TX_WORKER_COUNT; i++) {
		k_sem_give(&tx_start_sem);
	}
	for (uint8_t i = 0; i < TX_WORKER_COUNT; i++) {
		zassert_ok(k_sem_take(&tx_done_sem, K_SECONDS(10)));
	}

	capture_len = lichen_native_test_tx_snapshot(tx_capture, sizeof(tx_capture),
						    &overflow);
	zassert_false(overflow);

	while (offset < capture_len) {
		const uint8_t *payload = NULL;
		size_t payload_len = 0;
		int type;

		zassert_ok(native_next_frame(tx_capture, capture_len, &offset,
					     &payload, &payload_len));
		zassert_ok(cbor_map_is_complete(payload, payload_len));

		type = lichen_native_parse_msg_type_for_test(payload, payload_len);
		switch (type) {
		case LN_TYPE_HELLO:
			hello_count++;
			break;
		case LN_TYPE_NODE_INFO:
			node_info_count++;
			break;
		case LN_TYPE_MESSAGE_RECEIVED:
			message_received_count++;
			break;
		case LN_TYPE_LOG_ENTRY:
			log_entry_count++;
			break;
		default:
			zassert_unreachable("unexpected native TX type");
		}
		total_count++;
	}

	zassert_equal(total_count, TX_WORKER_COUNT * TX_SENDS_PER_WORKER);
	zassert_equal(hello_count, TX_SENDS_PER_WORKER);
	zassert_equal(node_info_count, TX_SENDS_PER_WORKER);
	zassert_equal(message_received_count, TX_SENDS_PER_WORKER);
	zassert_equal(log_entry_count, TX_SENDS_PER_WORKER);
}

ZTEST_SUITE(native_parse, NULL, NULL, NULL, NULL, NULL);
