/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include <lichen/app_identity/app_identity.h>
#include <lichen/app_interface/app_interface.h>
#include <lichen/meshcore/codec.h>

#include "ble_meshcore.h"
#include "fake_ble_meshcore.h"
#include "gateway_identity.h"
#include "message_contract.h"
#include "meshcore_adapter.h"

#define WORKER_STACK_SIZE 1024

void fake_l2_identity_set_publish_ret(int ret);

struct emit_worker_ctx {
	struct k_sem *start;
	const uint8_t *payload;
	size_t payload_len;
	int ret;
};

struct submit_ctx {
	uint8_t payload[LICHEN_MESHCORE_FRAME_MAX];
	struct k_sem *entered;
	uint32_t from;
	uint32_t to;
	size_t payload_len;
	uint32_t count;
	int ret;
	bool emit_during_submit;
	bool pause_during_submit;
};

static K_THREAD_STACK_DEFINE(worker_stack, WORKER_STACK_SIZE);
static struct k_thread worker_thread;

static void emit_worker(void *a, void *b, void *c)
{
	struct emit_worker_ctx *ctx = a;
	const struct lichen_app_text_event event = {
		.payload = ctx->payload,
		.payload_len = ctx->payload_len,
	};

	ARG_UNUSED(b);
	ARG_UNUSED(c);

	k_sem_take(ctx->start, K_FOREVER);
	ctx->ret = lichen_app_interface_emit_text(&event);
}

static int submit_text_sink(const struct lichen_app_text_event *event,
			    void *user_data)
{
	struct submit_ctx *ctx = user_data;

	if (event == NULL || ctx == NULL) {
		return -EINVAL;
	}
	if (ctx->ret < 0) {
		return ctx->ret;
	}
	if (event->payload_len > sizeof(ctx->payload)) {
		return -EMSGSIZE;
	}

	ctx->from = event->from;
	ctx->to = event->to;
	ctx->payload_len = event->payload_len;
	if (event->payload_len > 0U) {
		memcpy(ctx->payload, event->payload, event->payload_len);
	}
	ctx->count++;
	if (ctx->emit_during_submit) {
		return lichen_app_interface_emit_text(event);
	}
	if (ctx->pause_during_submit) {
		k_sem_give(ctx->entered);
		k_sleep(K_MSEC(50));
	}
	return 0;
}

static void expect_tx(size_t index, uint8_t type, size_t expected_len)
{
	const uint8_t *frame;
	size_t len;

	frame = fake_ble_meshcore_tx(index, &len);
	zassert_not_null(frame);
	zassert_equal(len, expected_len);
	zassert_equal(frame[0], type);
}

static void expect_error(size_t index, uint8_t err)
{
	const uint8_t *frame;
	size_t len;

	frame = fake_ble_meshcore_tx(index, &len);
	zassert_not_null(frame);
	zassert_equal(len, 2U);
	zassert_equal(frame[0], LICHEN_MESHCORE_RESP_ERR);
	zassert_equal(frame[1], err);
}

static void reset_gateway(uint32_t tx_cap)
{
	fake_l2_identity_set_publish_ret(0);
	lichen_app_identity_test_reset();
	gateway_message_contract_test_reset();
	lichen_app_interface_test_reset();
	fake_ble_meshcore_reset(tx_cap);
	gateway_meshcore_adapter_test_reset();
}

static void expect_self_info_key(size_t index, const uint8_t *expected_key,
				 size_t expected_key_len)
{
	const uint8_t *frame;
	size_t len;

	frame = fake_ble_meshcore_tx(index, &len);
	zassert_not_null(frame);
	zassert_equal(len, 64U);
	zassert_equal(frame[0], LICHEN_MESHCORE_RESP_SELF_INFO);
	zassert_mem_equal(&frame[4], expected_key, expected_key_len);
}

ZTEST(meshcore_gateway_adapter, test_process_once_dispatches_current_session)
{
	const uint8_t query[] = { LICHEN_MESHCORE_CMD_DEVICE_QUERY, 0x03 };

	reset_gateway(2U);
	zassert_ok(fake_ble_meshcore_push_rx(query, sizeof(query), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	zassert_equal(fake_ble_meshcore_tx_count(), 1U);
	expect_tx(0U, LICHEN_MESHCORE_RESP_DEVICE_INFO, 82U);
}

ZTEST(meshcore_gateway_adapter,
      test_gateway_identity_publish_self_info_nonzero_key)
{
	const uint8_t app_start[] = { LICHEN_MESHCORE_CMD_APP_START,
				      0, 0, 0, 0, 0, 0, 0, 't' };
	uint8_t expected_key[32];
	const uint8_t *frame;
	size_t len;

	for (uint8_t i = 0U; i < sizeof(expected_key); i++) {
		expected_key[i] = (uint8_t)(0xd0U + i);
	}

	reset_gateway(2U);
	zassert_ok(gateway_identity_publish_self());
	zassert_ok(fake_ble_meshcore_push_rx(app_start, sizeof(app_start), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	expect_self_info_key(0U, expected_key, sizeof(expected_key));
	frame = fake_ble_meshcore_tx(0U, &len);
	zassert_mem_equal(&frame[58], "LICHEN", 6U);
}

ZTEST(meshcore_gateway_adapter,
      test_gateway_identity_retry_replaces_degraded_self_info)
{
	const uint8_t app_start[] = { LICHEN_MESHCORE_CMD_APP_START,
				      0, 0, 0, 0, 0, 0, 0, 't' };
	uint8_t expected_key[32];
	uint8_t zero_key[32] = { 0 };

	for (uint8_t i = 0U; i < sizeof(expected_key); i++) {
		expected_key[i] = (uint8_t)(0xd0U + i);
	}

	reset_gateway(4U);
	fake_l2_identity_set_publish_ret(-ENOKEY);
	zassert_ok(fake_ble_meshcore_push_rx(app_start, sizeof(app_start), 1U));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	expect_self_info_key(0U, zero_key, sizeof(zero_key));

	fake_l2_identity_set_publish_ret(0);
	zassert_ok(fake_ble_meshcore_push_rx(app_start, sizeof(app_start), 1U));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	expect_self_info_key(1U, expected_key, sizeof(expected_key));
}

ZTEST(meshcore_gateway_adapter, test_process_once_rejects_stale_session)
{
	const uint8_t query[] = { LICHEN_MESHCORE_CMD_DEVICE_QUERY, 0x03 };

	reset_gateway(2U);
	zassert_ok(fake_ble_meshcore_push_rx(query, sizeof(query), 1U));
	fake_ble_meshcore_set_epoch(2U);

	zassert_equal(gateway_meshcore_adapter_test_process_once(), -ESTALE);
	zassert_equal(fake_ble_meshcore_tx_count(), 0U);
}

ZTEST(meshcore_gateway_adapter, test_contacts_preflight_avoids_partial_tx)
{
	const uint8_t contacts[] = { LICHEN_MESHCORE_CMD_GET_CONTACTS };

	reset_gateway(1U);
	zassert_ok(fake_ble_meshcore_push_rx(contacts, sizeof(contacts), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), -ENOMEM);
	zassert_equal(fake_ble_meshcore_tx_count(), 0U);
}

ZTEST(meshcore_gateway_adapter, test_send_channel_text_submits_to_app_interface)
{
	struct submit_ctx submit = { 0 };
	const struct lichen_app_interface_sink sink = {
		.submit_text = submit_text_sink,
		.user_data = &submit,
	};
	const uint8_t send[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG, 0x00, 0x00, 'h', 'i',
	};

	reset_gateway(4U);
	zassert_ok(lichen_app_interface_register_sink(&sink, NULL));
	zassert_ok(fake_ble_meshcore_push_rx(send, sizeof(send), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	zassert_equal(submit.count, 1U);
	zassert_equal(submit.from, 0U);
	zassert_equal(submit.to, UINT32_MAX);
	zassert_equal(submit.payload_len, 2U);
	zassert_mem_equal(submit.payload, "hi", 2U);
	zassert_equal(fake_ble_meshcore_tx_count(), 1U);
	expect_tx(0U, LICHEN_MESHCORE_RESP_OK, 1U);
}

ZTEST(meshcore_gateway_adapter,
      test_send_channel_text_enqueues_message_contract)
{
	const uint8_t send[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG,
		0x00,
		0x00,
		'p',
		'i',
		'n',
		'g',
	};
	struct gateway_message_contract_text submitted;

	reset_gateway(4U);
	zassert_ok(gateway_message_contract_init());
	zassert_ok(fake_ble_meshcore_push_rx(send, sizeof(send), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	zassert_equal(fake_ble_meshcore_tx_count(), 1U);
	expect_tx(0U, LICHEN_MESHCORE_RESP_OK, 1U);
	zassert_ok(gateway_message_contract_pop_text(&submitted));
	zassert_equal(submitted.from, 0U);
	zassert_equal(submitted.to, UINT32_MAX);
	zassert_false(submitted.has_id);
	zassert_false(submitted.has_to_iid);
	zassert_equal(submitted.payload_len, 4U);
	zassert_mem_equal(submitted.payload, "ping", 4U);
	zassert_equal(gateway_message_contract_pop_text(&submitted), -ENOENT);
}

ZTEST(meshcore_gateway_adapter,
      test_send_channel_text_rejects_reentrant_emit)
{
	struct submit_ctx submit = {
		.emit_during_submit = true,
	};
	const struct lichen_app_interface_sink sink = {
		.submit_text = submit_text_sink,
		.user_data = &submit,
	};
	const uint8_t send[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG, 0x00, 0x00, 'h',
	};

	reset_gateway(2U);
	zassert_ok(lichen_app_interface_register_sink(&sink, NULL));
	zassert_ok(fake_ble_meshcore_push_rx(send, sizeof(send), 1U));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	zassert_equal(submit.count, 1U);
	zassert_equal(fake_ble_meshcore_tx_count(), 1U);
	expect_error(0U, LICHEN_MESHCORE_ERR_BAD_STATE);
}

ZTEST(meshcore_gateway_adapter,
      test_send_channel_text_allows_external_emit_after_ack)
{
	struct k_sem entered;
	const uint8_t worker_payload[] = { 'w' };
	struct emit_worker_ctx worker = {
		.payload = worker_payload,
		.payload_len = sizeof(worker_payload),
		.ret = -EAGAIN,
	};
	struct submit_ctx submit = {
		.pause_during_submit = true,
	};
	const struct lichen_app_interface_sink sink = {
		.submit_text = submit_text_sink,
		.user_data = &submit,
	};
	const uint8_t send[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG, 0x00, 0x00, 'h',
	};

	k_sem_init(&entered, 0, 1);
	submit.entered = &entered;
	worker.start = &entered;

	reset_gateway(4U);
	k_thread_create(&worker_thread, worker_stack,
			K_THREAD_STACK_SIZEOF(worker_stack), emit_worker,
			&worker, NULL, NULL, K_PRIO_PREEMPT(0), 0, K_NO_WAIT);
	zassert_ok(lichen_app_interface_register_sink(&sink, NULL));
	zassert_ok(fake_ble_meshcore_push_rx(send, sizeof(send), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	zassert_ok(k_thread_join(&worker_thread, K_SECONDS(1)));
	zassert_ok(worker.ret);
	zassert_equal(submit.count, 1U);
	zassert_equal(fake_ble_meshcore_tx_count(), 2U);
	expect_tx(0U, LICHEN_MESHCORE_RESP_OK, 1U);
	expect_tx(1U, LICHEN_MESHCORE_PUSH_MSG_WAITING, 1U);
}

ZTEST(meshcore_gateway_adapter, test_send_channel_text_requires_submit_sink)
{
	const uint8_t send[] = {
		LICHEN_MESHCORE_CMD_SEND_CHANNEL_TXT_MSG, 0x00, 0x00, 'h',
	};

	reset_gateway(4U);
	zassert_ok(fake_ble_meshcore_push_rx(send, sizeof(send), 1U));

	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	zassert_equal(fake_ble_meshcore_tx_count(), 1U);
	expect_error(0U, LICHEN_MESHCORE_ERR_UNSUPPORTED_CMD);
}

ZTEST(meshcore_gateway_adapter, test_app_interface_text_waiting_and_sync)
{
	const uint8_t payload[] = { 'h', 'i' };
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const struct lichen_app_text_event event = {
		.id = 0x01020304U,
		.payload = payload,
		.payload_len = sizeof(payload),
		.has_id = true,
	};
	const uint8_t *frame;
	size_t len;

	reset_gateway(4U);
	zassert_ok(lichen_app_interface_emit_text(&event));
	expect_tx(0U, LICHEN_MESHCORE_PUSH_MSG_WAITING, 1U);

	zassert_ok(fake_ble_meshcore_push_rx(sync_next, sizeof(sync_next), 1U));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	frame = fake_ble_meshcore_tx(1U, &len);
	zassert_not_null(frame);
	zassert_equal(frame[0], LICHEN_MESHCORE_RESP_CHANNEL_MSG_RECV_V3);
	zassert_equal(len, 13U);
	zassert_mem_equal(&frame[11], payload, sizeof(payload));
}

ZTEST(meshcore_gateway_adapter, test_app_interface_status_waiting_and_sync)
{
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const struct lichen_app_status_event event = {
		.request_id = 0x12345678U,
		.error_reason = 2U,
		.has_error_reason = true,
	};
	const uint8_t *frame;
	size_t len;

	reset_gateway(4U);
	zassert_ok(lichen_app_interface_emit_status(&event));
	expect_tx(0U, LICHEN_MESHCORE_PUSH_MSG_WAITING, 1U);

	zassert_ok(fake_ble_meshcore_push_rx(sync_next, sizeof(sync_next), 1U));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	frame = fake_ble_meshcore_tx(1U, &len);
	zassert_not_null(frame);
	zassert_equal(frame[0], LICHEN_MESHCORE_PUSH_SEND_CONFIRMED);
	zassert_equal(sys_get_le32(&frame[1]), event.request_id);
	zassert_equal(len, 7U);
}

ZTEST(meshcore_gateway_adapter, test_app_interface_rejects_disconnected_session)
{
	const uint8_t payload[] = { 'h' };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	reset_gateway(4U);
	fake_ble_meshcore_set_connected(false);
	zassert_equal(lichen_app_interface_emit_text(&event), -ENOTCONN);
	zassert_equal(fake_ble_meshcore_tx_count(), 0U);
}

ZTEST(meshcore_gateway_adapter, test_app_interface_disconnect_race_drops_pending)
{
	const uint8_t payload[] = { 'h' };
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	reset_gateway(4U);
	fake_ble_meshcore_disconnect_on_next_enqueue();
	zassert_equal(lichen_app_interface_emit_text(&event), -ENOTCONN);

	fake_ble_meshcore_set_connected(true);
	zassert_ok(fake_ble_meshcore_push_rx(sync_next, sizeof(sync_next),
					     ble_meshcore_session_epoch()));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	expect_tx(0U, LICHEN_MESHCORE_RESP_NO_MORE_MESSAGES, 1U);
}

ZTEST(meshcore_gateway_adapter,
      test_app_interface_reconnect_before_sync_drops_pending)
{
	const uint8_t payload[] = { 'h' };
	const uint8_t sync_next[] = { LICHEN_MESHCORE_CMD_SYNC_NEXT_MESSAGE };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	reset_gateway(4U);
	zassert_ok(lichen_app_interface_emit_text(&event));
	expect_tx(0U, LICHEN_MESHCORE_PUSH_MSG_WAITING, 1U);

	fake_ble_meshcore_set_connected(false);
	fake_ble_meshcore_set_connected(true);
	zassert_ok(fake_ble_meshcore_push_rx(sync_next, sizeof(sync_next),
					     ble_meshcore_session_epoch()));
	zassert_equal(gateway_meshcore_adapter_test_process_once(), 0);
	expect_tx(0U, LICHEN_MESHCORE_RESP_NO_MORE_MESSAGES, 1U);
}

ZTEST(meshcore_gateway_adapter, test_app_interface_pending_queue_full)
{
	const uint8_t payload[] = { 'h' };
	const struct lichen_app_text_event event = {
		.payload = payload,
		.payload_len = sizeof(payload),
	};

	reset_gateway(16U);
	for (uint32_t i = 0U; i < CONFIG_LICHEN_MESHCORE_PENDING_EVENTS; i++) {
		zassert_ok(lichen_app_interface_emit_text(&event));
	}
	zassert_equal(lichen_app_interface_emit_text(&event), -ENOMEM);
}

ZTEST_SUITE(meshcore_gateway_adapter, NULL, NULL, NULL, NULL, NULL);
