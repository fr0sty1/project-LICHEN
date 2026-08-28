/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>

#include <lichen/app_interface/ipc.h>

#define IPC_DEPTH CONFIG_LICHEN_APP_INTERFACE_IPC_QUEUE_DEPTH
#define IPC_PACKET_MAX CONFIG_LICHEN_APP_INTERFACE_IPC_MAX_PACKET

struct ipc_queue_state {
	uint8_t packets[IPC_DEPTH][IPC_PACKET_MAX];
	uint16_t lengths[IPC_DEPTH];
	size_t head;
	size_t tail;
	bool shutdown;
};

struct ipc_queue_ref {
	struct ipc_queue_state *state;
	struct k_mutex *mutex;
	struct k_sem *items;
	struct k_sem *spaces;
};

static struct ipc_queue_state s_to_network;
static struct ipc_queue_state s_to_app;
static K_MUTEX_DEFINE(s_to_network_mutex);
static K_MUTEX_DEFINE(s_to_app_mutex);
static K_SEM_DEFINE(s_to_network_items, 0, IPC_DEPTH);
static K_SEM_DEFINE(s_to_network_spaces, IPC_DEPTH, IPC_DEPTH);
static K_SEM_DEFINE(s_to_app_items, 0, IPC_DEPTH);
static K_SEM_DEFINE(s_to_app_spaces, IPC_DEPTH, IPC_DEPTH);

static struct ipc_queue_ref to_network_queue(void)
{
	return (struct ipc_queue_ref){
		.state = &s_to_network,
		.mutex = &s_to_network_mutex,
		.items = &s_to_network_items,
		.spaces = &s_to_network_spaces,
	};
}

static struct ipc_queue_ref to_app_queue(void)
{
	return (struct ipc_queue_ref){
		.state = &s_to_app,
		.mutex = &s_to_app_mutex,
		.items = &s_to_app_items,
		.spaces = &s_to_app_spaces,
	};
}

static k_timeout_t ipc_timeout(uint32_t timeout_ms)
{
	return timeout_ms == LICHEN_APP_INTERFACE_IPC_WAIT_FOREVER ?
		K_FOREVER : K_MSEC(timeout_ms);
}

static bool queue_is_shutdown(struct ipc_queue_ref queue)
{
	bool shutdown;

	k_mutex_lock(queue.mutex, K_FOREVER);
	shutdown = queue.state->shutdown;
	k_mutex_unlock(queue.mutex);
	return shutdown;
}

static int wait_result(struct ipc_queue_ref queue, int ret)
{
	if (ret == 0) {
		return 0;
	}
	return queue_is_shutdown(queue) ? -ESHUTDOWN : -EAGAIN;
}

static int queue_send(struct ipc_queue_ref queue, const uint8_t *packet,
		      size_t len, uint32_t timeout_ms)
{
	int ret;

	if (packet == NULL || len == 0U) {
		return -EINVAL;
	}
	if (len > IPC_PACKET_MAX) {
		return -EMSGSIZE;
	}
	if (queue_is_shutdown(queue)) {
		return -ESHUTDOWN;
	}

	ret = wait_result(queue, k_sem_take(queue.spaces, ipc_timeout(timeout_ms)));
	if (ret < 0) {
		return ret;
	}

	k_mutex_lock(queue.mutex, K_FOREVER);
	if (queue.state->shutdown) {
		k_mutex_unlock(queue.mutex);
		return -ESHUTDOWN;
	}
	memcpy(queue.state->packets[queue.state->tail], packet, len);
	queue.state->lengths[queue.state->tail] = (uint16_t)len;
	queue.state->tail = (queue.state->tail + 1U) % IPC_DEPTH;
	k_mutex_unlock(queue.mutex);
	k_sem_give(queue.items);
	return 0;
}

static int queue_recv(struct ipc_queue_ref queue, uint8_t *buf, size_t max_len,
		      size_t *required_len, uint32_t timeout_ms)
{
	size_t len;
	int ret;

	if (buf == NULL || required_len == NULL) {
		return -EINVAL;
	}
	*required_len = 0U;
	if (queue_is_shutdown(queue)) {
		return -ESHUTDOWN;
	}

	ret = wait_result(queue, k_sem_take(queue.items, ipc_timeout(timeout_ms)));
	if (ret < 0) {
		return ret;
	}

	k_mutex_lock(queue.mutex, K_FOREVER);
	if (queue.state->shutdown) {
		k_mutex_unlock(queue.mutex);
		return -ESHUTDOWN;
	}
	len = queue.state->lengths[queue.state->head];
	*required_len = len;
	if (max_len < len) {
		k_mutex_unlock(queue.mutex);
		k_sem_give(queue.items);
		return -EMSGSIZE;
	}
	memcpy(buf, queue.state->packets[queue.state->head], len);
	queue.state->lengths[queue.state->head] = 0U;
	queue.state->head = (queue.state->head + 1U) % IPC_DEPTH;
	k_mutex_unlock(queue.mutex);
	k_sem_give(queue.spaces);
	return 0;
}

static void queue_shutdown(struct ipc_queue_ref queue)
{
	k_mutex_lock(queue.mutex, K_FOREVER);
	queue.state->shutdown = true;
	queue.state->head = 0U;
	queue.state->tail = 0U;
	memset(queue.state->lengths, 0, sizeof(queue.state->lengths));
	k_mutex_unlock(queue.mutex);
	k_sem_reset(queue.items);
	k_sem_reset(queue.spaces);
}

#ifdef CONFIG_LICHEN_APP_INTERFACE_TEST_HOOKS
static void queue_test_reset(struct ipc_queue_ref queue)
{
	k_mutex_lock(queue.mutex, K_FOREVER);
	memset(queue.state, 0, sizeof(*queue.state));
	k_mutex_unlock(queue.mutex);
	k_sem_reset(queue.items);
	k_sem_reset(queue.spaces);
	for (size_t i = 0U; i < IPC_DEPTH; i++) {
		k_sem_give(queue.spaces);
	}
}
#endif

size_t lichen_app_interface_ipc_max_packet_size(void)
{
	return IPC_PACKET_MAX;
}

size_t lichen_app_interface_ipc_queue_capacity(void)
{
	return IPC_DEPTH;
}

int lichen_app_interface_ipc_send_to_network(const uint8_t *packet, size_t len,
					     uint32_t timeout_ms)
{
	return queue_send(to_network_queue(), packet, len, timeout_ms);
}

int lichen_app_interface_ipc_recv_for_network(uint8_t *buf, size_t max_len,
					      size_t *required_len,
					      uint32_t timeout_ms)
{
	return queue_recv(to_network_queue(), buf, max_len, required_len, timeout_ms);
}

int lichen_app_interface_ipc_send_to_app(const uint8_t *packet, size_t len,
					 uint32_t timeout_ms)
{
	return queue_send(to_app_queue(), packet, len, timeout_ms);
}

int lichen_app_interface_ipc_recv_for_app(uint8_t *buf, size_t max_len,
					  size_t *required_len,
					  uint32_t timeout_ms)
{
	return queue_recv(to_app_queue(), buf, max_len, required_len, timeout_ms);
}

void lichen_app_interface_ipc_shutdown(void)
{
	queue_shutdown(to_network_queue());
	queue_shutdown(to_app_queue());
}

bool lichen_app_interface_ipc_is_shutdown(void)
{
	return queue_is_shutdown(to_network_queue()) || queue_is_shutdown(to_app_queue());
}

#ifdef CONFIG_LICHEN_APP_INTERFACE_TEST_HOOKS
void lichen_app_interface_ipc_test_reset(void)
{
	queue_test_reset(to_network_queue());
	queue_test_reset(to_app_queue());
}
#endif
