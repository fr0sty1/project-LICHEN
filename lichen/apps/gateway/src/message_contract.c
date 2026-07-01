/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "message_contract.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>

#include <lichen/app_interface/app_interface.h>

#ifndef CONFIG_LORA_LICHEN_GATEWAY_MESSAGE_QUEUE_DEPTH
#define CONFIG_LORA_LICHEN_GATEWAY_MESSAGE_QUEUE_DEPTH 4
#endif
#define MESSAGE_QUEUE_DEPTH CONFIG_LORA_LICHEN_GATEWAY_MESSAGE_QUEUE_DEPTH

static struct gateway_message_contract_text s_text_queue[MESSAGE_QUEUE_DEPTH];
static K_MUTEX_DEFINE(s_mutex);
static size_t s_head;
static size_t s_count;
static bool s_sink_registered;
static uint8_t s_sink_id;

static int submit_text(const struct lichen_app_text_event *event,
		       void *user_data)
{
	struct gateway_message_contract_text *slot;
	size_t index;

	ARG_UNUSED(user_data);

	if (event == NULL ||
	    (event->payload == NULL && event->payload_len > 0U) ||
	    event->payload_len > sizeof(slot->payload)) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	if (s_count >= ARRAY_SIZE(s_text_queue)) {
		k_mutex_unlock(&s_mutex);
		return -ENOMEM;
	}

	index = (s_head + s_count) % ARRAY_SIZE(s_text_queue);
	slot = &s_text_queue[index];
	memset(slot, 0, sizeof(*slot));
	slot->from = event->from;
	slot->to = event->to;
	slot->id = event->id;
	slot->payload_len = event->payload_len;
	slot->has_id = event->has_id;
	slot->has_to_iid = event->has_to_iid;
	if (event->has_to_iid) {
		memcpy(slot->to_iid, event->to_iid, sizeof(slot->to_iid));
	}
	if (event->payload_len > 0U) {
		memcpy(slot->payload, event->payload, event->payload_len);
	}
	s_count++;
	k_mutex_unlock(&s_mutex);

	return 0;
}

int gateway_message_contract_init(void)
{
	const struct lichen_app_interface_sink sink = {
		.submit_text = submit_text,
	};
	int ret = 0;

	k_mutex_lock(&s_mutex, K_FOREVER);
	if (!s_sink_registered) {
		ret = lichen_app_interface_register_sink(&sink, &s_sink_id);
		if (ret == 0) {
			s_sink_registered = true;
		}
	}
	k_mutex_unlock(&s_mutex);

	return ret;
}

int gateway_message_contract_pop_text(
	struct gateway_message_contract_text *event)
{
	if (event == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_mutex, K_FOREVER);
	if (s_count == 0U) {
		k_mutex_unlock(&s_mutex);
		return -ENOENT;
	}
	*event = s_text_queue[s_head];
	memset(&s_text_queue[s_head], 0, sizeof(s_text_queue[s_head]));
	s_head = (s_head + 1U) % ARRAY_SIZE(s_text_queue);
	s_count--;
	k_mutex_unlock(&s_mutex);

	return 0;
}

#ifdef CONFIG_ZTEST
void gateway_message_contract_test_reset(void)
{
	k_mutex_lock(&s_mutex, K_FOREVER);
	if (s_sink_registered) {
		(void)lichen_app_interface_unregister_sink(s_sink_id);
		s_sink_registered = false;
	}
	memset(s_text_queue, 0, sizeof(s_text_queue));
	s_head = 0U;
	s_count = 0U;
	k_mutex_unlock(&s_mutex);
}
#endif
