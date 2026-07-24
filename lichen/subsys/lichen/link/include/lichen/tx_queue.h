/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/tx_queue.h
 * @brief LICHEN TX queue with priority and deadline support
 *
 * Small, bounded TX queue for holding packets awaiting radio access.
 * Implements bufferbloat avoidance per spec/appendix-bufferbloat.md:
 *   - Fixed size (4 packets max)
 *   - Time-based expiry (packets dropped after deadline)
 *   - Priority preemption (high-priority packets bypass/preempt low)
 *   - Explicit backpressure (ENOBUFS when full, not silent drop)
 */

#ifndef LICHEN_TX_QUEUE_H_
#define LICHEN_TX_QUEUE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __ZEPHYR__
#include <zephyr/kernel.h>
#else
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum TX queue depth */
#define TX_QUEUE_SIZE 4

/** Maximum packet size in TX queue */
#define TX_QUEUE_MAX_PACKET_SIZE 256

/**
 * @brief TX packet priority levels
 *
 * Lower values = higher priority. Routing control gets priority
 * to maintain mesh connectivity under load.
 */
enum tx_queue_priority {
	TX_PRIORITY_ROUTING = 0,  /**< Routing control (DIO/DAO) */
	TX_PRIORITY_ACK = 1,      /**< Link-layer ACKs */
	TX_PRIORITY_URGENT = 2,   /**< Urgent app messages */
	TX_PRIORITY_BULK = 3,     /**< Bulk data (default) */
	TX_PRIORITY_COUNT
};

/** Default deadline for routing control packets (ms) */
#define TX_DEADLINE_ROUTING_MS   5000

/** Default deadline for ACK packets (ms) */
#define TX_DEADLINE_ACK_MS       10000

/** Default deadline for application data packets (ms) */
#define TX_DEADLINE_APP_MS       60000

/**
 * @brief TX queue entry
 *
 * Holds a single packet waiting for transmission.
 */
struct tx_queue_entry {
	uint8_t data[TX_QUEUE_MAX_PACKET_SIZE]; /**< Packet data */
	uint16_t len;                           /**< Packet length */
	uint32_t deadline_ms;                   /**< Absolute deadline (uptime ms) */
	uint8_t priority;                       /**< Priority (0 = highest) */
	bool valid;                             /**< Entry contains valid packet */
};

/**
 * @brief TX queue statistics
 */
struct tx_queue_stats {
	uint32_t packets_queued;         /**< Total packets accepted */
	uint32_t packets_sent;           /**< Total packets popped for TX */
	uint32_t packets_dropped_deadline; /**< Dropped due to deadline expiry */
	uint32_t packets_dropped_full;   /**< Dropped due to queue full (preemption failure) */
	uint32_t packets_preempted;      /**< Lower-priority packets preempted */
	uint32_t max_latency_ms;         /**< Worst-case queue time observed */
};

/**
 * @brief TX queue
 *
 * Thread-safe queue for packets awaiting transmission.
 */
struct tx_queue {
	struct tx_queue_entry entries[TX_QUEUE_SIZE]; /**< Queue entries */
	struct tx_queue_stats stats;                   /**< Queue statistics */
#ifdef __ZEPHYR__
	struct k_mutex lock;  /**< Protects queue state */
#else
	pthread_mutex_t lock; /**< Protects queue state */
#endif
};

/**
 * @brief Initialize a TX queue.
 *
 * @param[out] queue Queue to initialize (must not be NULL)
 * @return 0 on success, -EINVAL if queue is NULL
 */
int tx_queue_init(struct tx_queue *_Nonnull queue);

/**
 * @brief Push a packet onto the TX queue.
 *
 * Behavior:
 * 1. Expire any packets past their deadline
 * 2. If space available, add packet
 * 3. If full and new packet is higher priority, preempt lowest-priority packet
 * 4. If full and same/lower priority, return -ENOBUFS
 *
 * @param[in,out] queue    TX queue
 * @param[in]     data     Packet data
 * @param[in]     len      Packet length (must be <= TX_QUEUE_MAX_PACKET_SIZE)
 * @param[in]     priority Packet priority (0 = highest)
 * @param[in]     deadline_ms Absolute deadline in uptime milliseconds; must be
 *                            less than 2^31 ms ahead of the current uptime
 * @return 0 on success, -EINVAL on bad args, -ENOBUFS if full and cannot preempt,
 *         -EIO if the monotonic clock cannot be read
 */
int tx_queue_push(struct tx_queue *_Nonnull queue,
		  const uint8_t *_Nonnull data, uint16_t len,
		  uint8_t priority, uint32_t deadline_ms);

/**
 * @brief Push a packet with default deadline based on priority.
 *
 * Convenience wrapper that sets deadline based on priority:
 *   - TX_PRIORITY_ROUTING: 5 seconds
 *   - TX_PRIORITY_ACK: 10 seconds
 *   - TX_PRIORITY_BULK/others: 60 seconds
 *
 * @param[in,out] queue    TX queue
 * @param[in]     data     Packet data
 * @param[in]     len      Packet length
 * @param[in]     priority Packet priority
 * @return 0 on success, -EINVAL on bad args, -ENOBUFS if full,
 *         -EIO if the monotonic clock cannot be read
 */
int tx_queue_push_default_deadline(struct tx_queue *_Nonnull queue,
				   const uint8_t *_Nonnull data, uint16_t len,
				   uint8_t priority);

/**
 * @brief Pop the highest-priority packet from the queue.
 *
 * Returns the highest-priority (lowest priority value) non-expired packet.
 * Expired packets are silently dropped and counted in stats.
 *
 * @param[in,out] queue   TX queue
 * @param[out]    data    Buffer to receive packet data
 * @param[in,out] len     In: buffer size, Out: packet length
 * @param[out]    latency_ms Optional: time packet spent in queue (NULL to skip)
 * @return 0 on success, -EAGAIN if queue is empty, -EINVAL on bad args,
 *         -ENOMEM if buffer too small, -EIO if the monotonic clock cannot be read
 */
int tx_queue_pop(struct tx_queue *_Nonnull queue,
		 uint8_t *_Nonnull data, uint16_t *_Nonnull len,
		 uint32_t *_Nullable latency_ms);

/**
 * @brief Get the number of valid (non-expired) packets in the queue.
 *
 * Acquires queue lock for thread-safe consistent snapshot. Does not
 * expire packets (lazily done by push/pop/clear).
 *
 * @param[in,out] queue TX queue (non-const due to internal locking)
 * @return Number of packets (>=0), or -EINVAL if queue is NULL
 */
int tx_queue_count(const struct tx_queue *_Nonnull queue);

/**
 * @brief Check if the queue is empty.
 *
 * Thread-safe via lock; returns snapshot of current valid entries.
 *
 * @param[in,out] queue TX queue (non-const due to internal locking)
 * @return true if empty, false otherwise (NULL returns true)
 */
bool tx_queue_empty(const struct tx_queue *_Nonnull queue);

/**
 * @brief Get a copy of queue statistics.
 *
 * Thread-safe atomic copy under lock (no longer non-atomic).
 *
 * @param[in,out] queue TX queue (non-const due to internal locking)
 * @param[out] stats Statistics output
 * @return 0 on success, -EINVAL if args are NULL
 */
int tx_queue_stats_get(const struct tx_queue *_Nonnull queue,
		       struct tx_queue_stats *_Nonnull stats);

/**
 * @brief Clear the queue and reset statistics.
 *
 * @param[in,out] queue TX queue
 */
void tx_queue_clear(struct tx_queue *_Nonnull queue);

/**
 * @brief Destroy a TX queue (releases pthread mutex on POSIX).
 *
 * Propagates pthread_mutex_destroy failures. Zephyr path is no-op.
 *
 * @param[in,out] queue TX queue
 * @return 0 on success, negative errno on mutex destroy failure
 */
int tx_queue_destroy(struct tx_queue *_Nonnull queue);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_TX_QUEUE_H_ */
