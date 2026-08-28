/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_APP_INTERFACE_IPC_H_
#define LICHEN_APP_INTERFACE_IPC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Use an unbounded wait. All other values are finite millisecond timeouts. */
#define LICHEN_APP_INTERFACE_IPC_WAIT_FOREVER UINT32_MAX

size_t lichen_app_interface_ipc_max_packet_size(void);
size_t lichen_app_interface_ipc_queue_capacity(void);

/** Copy one complete IPv6 packet from the local app into the network queue. */
int lichen_app_interface_ipc_send_to_network(const uint8_t *packet, size_t len,
					     uint32_t timeout_ms);

/**
 * Receive the oldest app packet. On -EMSGSIZE, required_len is populated and
 * the packet remains queued. A successful call transfers a copy to buf.
 */
int lichen_app_interface_ipc_recv_for_network(uint8_t *buf, size_t max_len,
					      size_t *required_len,
					      uint32_t timeout_ms);

/** Copy one complete IPv6 packet from the network stack into the app queue. */
int lichen_app_interface_ipc_send_to_app(const uint8_t *packet, size_t len,
					 uint32_t timeout_ms);

/** Receive the oldest network packet using the same semantics as above. */
int lichen_app_interface_ipc_recv_for_app(uint8_t *buf, size_t max_len,
					  size_t *required_len,
					  uint32_t timeout_ms);

/** Stop both directions, discard queued packets, and wake blocked callers. */
void lichen_app_interface_ipc_shutdown(void);
bool lichen_app_interface_ipc_is_shutdown(void);

#ifdef CONFIG_LICHEN_APP_INTERFACE_TEST_HOOKS
/** Restore empty running queues. Call only after test worker threads join. */
void lichen_app_interface_ipc_test_reset(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_APP_INTERFACE_IPC_H_ */
