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

#include <lichen/frame_pool.h>

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
#define TX_QUEUE_SIZE LICHEN_FRAME_POOL_CAPACITY

/** Maximum packet size in TX queue */
#define TX_QUEUE_MAX_PACKET_SIZE LICHEN_FRAME_BUFFER_SIZE

/**
 * @brief TX packet priority levels
 *
 * Lower values = higher priority. Routing control gets priority
 * to maintain mesh connectivity under load.
 */
enum tx_queue_priority {
	TX_PRIORITY_SOS = 0,      /**< Emergency/SOS traffic */
	TX_PRIORITY_ROUTING = 1,  /**< Routing control (DIO/DAO) */
	TX_PRIORITY_ACK = TX_PRIORITY_ROUTING, /**< ACKs share routing priority */
	TX_PRIORITY_URGENT = 2,   /**< Urgent application messages */
	TX_PRIORITY_NORMAL = 3,   /**< Normal application data */
	TX_PRIORITY_BULK = 4,     /**< Bulk transfers */
	TX_PRIORITY_COUNT = 5
};

/** Canonical default deadlines from appendix-bufferbloat.md B.2.2. */
#define TX_DEADLINE_SOS_MS       UINT32_C(2000)
#define TX_DEADLINE_ROUTING_MS   UINT32_C(5000)
#define TX_DEADLINE_ACK_MS       UINT32_C(10000)
#define TX_DEADLINE_URGENT_MS    UINT32_C(30000)
#define TX_DEADLINE_NORMAL_MS    UINT32_C(60000)
#define TX_DEADLINE_BULK_MS      UINT32_C(120000)

/* Slot-count forms retained for coordinated-capacity callers (250 ms/slot). */
#define TX_DEADLINE_SOS_SLOTS       8
#define TX_DEADLINE_ROUTING_SLOTS   20
#define TX_DEADLINE_ACK_SLOTS       40
#define TX_DEADLINE_URGENT_SLOTS    120
#define TX_DEADLINE_NORMAL_SLOTS    240
#define TX_DEADLINE_BULK_SLOTS      480

/** Backward-compatible name for the normal application deadline. */
#define TX_DEADLINE_APP_SLOTS TX_DEADLINE_NORMAL_SLOTS

/**
 * @brief TX queue entry
 *
 * Holds a single packet waiting for transmission.
 */
struct tx_queue_entry {
	struct lichen_frame_handle buffer;      /**< Owned pool buffer */
	uint16_t len;                           /**< Packet length */
	uint32_t deadline_ms;                   /**< Absolute deadline (uptime ms) */
	uint64_t deadline_ms64;                 /**< Deadline in extended monotonic ms (internal) */
	uint32_t enqueue_ms;                    /**< Enqueue timestamp (uptime ms) */
	uint64_t enqueue_order;                 /**< FIFO order within a priority */
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
	uint32_t avg_latency_ms;         /**< Smoothed average queue time (EWMA alpha 1/8) */
};

/**
 * @brief TX queue
 *
 * Thread-safe queue for packets awaiting transmission.
 */
struct tx_queue {
	struct tx_queue_entry entries[TX_QUEUE_SIZE]; /**< Queue entries */
	struct lichen_frame_pool pool;                 /**< Fixed frame storage */
	struct tx_queue_stats stats;                   /**< Queue statistics */
	uint32_t avg_latency_scaled;                   /**< EWMA latency, scaled by 8 (internal) */
	uint64_t next_enqueue_order;                   /**< Next FIFO sequence number */
	uint64_t now_ms64;                             /**< Extended monotonic time base, ms (internal) */
	bool terminal;                                 /**< Unrecoverable destroy failure */
#ifdef __ZEPHYR__
	struct k_mutex lock;  /**< Protects queue state */
#else
	pthread_mutex_t lock; /**< Protects queue state */
#endif
};

/**
 * @brief Initialize a TX queue.
 *
 * Storage must be fresh or have completed tx_queue_destroy() successfully;
 * a terminal or partially destroyed queue MUST NOT be reinitialized in place.
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
 * @return 0 on success, -EINVAL on bad args or invalid priority,
 *         -ENOBUFS if full and cannot preempt,
 *         -EIO if the monotonic clock cannot be read
 */
int tx_queue_push(struct tx_queue *_Nonnull queue,
		  const uint8_t *_Nonnull data, uint16_t len,
		  uint8_t priority, uint32_t deadline_ms);

/**
 * @brief Push a packet with default deadline based on priority.
 *
 * Convenience wrapper that sets deadline based on priority:
 *   - TX_PRIORITY_SOS: 2 seconds
 *   - TX_PRIORITY_ROUTING/TX_PRIORITY_ACK: 5 seconds
 *   - TX_PRIORITY_URGENT: 30 seconds
 *   - TX_PRIORITY_NORMAL: 60 seconds
 *   - TX_PRIORITY_BULK: 120 seconds
 *
 * ACK is an alias of routing priority, so this convenience API uses the
 * routing default. Callers that require the distinct 10-second ACK deadline
 * pass an absolute deadline based on TX_DEADLINE_ACK_MS to tx_queue_push().
 *
 * @param[in,out] queue    TX queue
 * @param[in]     data     Packet data
 * @param[in]     len      Packet length
 * @param[in]     priority Packet priority
 * @return 0 on success, -EINVAL on bad args or invalid priority,
 *         -ENOBUFS if full,
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
 * Updates the latency statistics: max_latency_ms tracks the worst-case
 * queue time and avg_latency_ms an EWMA (alpha 1/8) of observed queue
 * time, computed from each entry's enqueue timestamp.
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
 * @return Number of packets (>=0), -EINVAL if queue is NULL, or -EIO if the
 *         queue is terminal.
 */
int tx_queue_count(struct tx_queue *_Nullable queue);

/**
 * @brief Check if the queue is empty.
 *
 * Thread-safe via lock; returns snapshot of current valid entries.
 *
 * @param[in,out] queue TX queue (NULL accepted, returns true)
 * @return true if empty/unusable, false otherwise (NULL and terminal queues
 *         return true)
 */
bool tx_queue_empty(struct tx_queue *_Nullable queue);

/**
 * @brief Get a copy of queue statistics.
 *
 * Thread-safe atomic copy under lock (no longer non-atomic).
 *
 * @param[in,out] queue TX queue (non-const due to internal locking)
 * @param[out] stats Statistics output
 * @return 0 on success, -EINVAL if args are NULL, or -EIO if terminal
 */
int tx_queue_stats_get(struct tx_queue *_Nonnull queue,
		       struct tx_queue_stats *_Nonnull stats);

/**
 * @brief Clear the queue and reset statistics.
 *
 * @param[in,out] queue TX queue
 * @return 0 on success, -EINVAL if queue is NULL, -EIO if terminal, or a
 *         frame-pool error.
 *         On failure, the entry whose buffer could not be released remains
 *         valid so the operation can be retried.
 */
int tx_queue_clear(struct tx_queue *_Nonnull queue);

/**
 * @brief Destroy a TX queue (releases pthread mutex on POSIX).
 *
 * The caller MUST have exclusive ownership: all threads and callbacks that
 * can access the queue must be stopped and joined before this call. Concurrent
 * queue operations during destruction are unsupported.
 *
 * Propagates frame-pool and pthread mutex failures. A failed operation is
 * retryable unless the queue enters its terminal state; terminal queues reject
 * all later operations with -EIO and must not be reinitialized in place.
 *
 * @param[in,out] queue TX queue
 * @return 0 on success, negative errno on mutex destroy failure
 */
int tx_queue_destroy(struct tx_queue *_Nonnull queue);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_TX_QUEUE_H_ */
