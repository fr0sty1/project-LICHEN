/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file tx_queue.c
 * @brief LICHEN TX queue with priority and deadline support
 *
 * Implements bufferbloat avoidance for the link-layer TX path:
 *   - Small, bounded queue (4 packets)
 *   - Time-based expiry via deadlines
 *   - Priority preemption
 *   - Explicit backpressure (ENOBUFS, not silent drop)
 */

#include <lichen/tx_queue.h>
#include <lichen/errno.h>
#include <string.h>

#ifdef CONFIG_TX_QUEUE_TEST_TIME
static bool fail_test_time;
#endif

#ifdef __ZEPHYR__
#include <zephyr/kernel.h>

static int tx_queue_platform_now_ms(uint32_t *now_ms)
{
#ifdef CONFIG_TX_QUEUE_TEST_TIME
	if (fail_test_time) {
		return -EIO;
	}
#endif
	*now_ms = (uint32_t)k_uptime_get();
	return 0;
}
#else
#include <time.h>

#ifdef CONFIG_TX_QUEUE_TEST_TIME
static int tx_queue_clock_gettime(clockid_t clock_id, struct timespec *ts)
{
	return fail_test_time ? -1 : clock_gettime(clock_id, ts);
}
#else
#define tx_queue_clock_gettime(clock_id, ts) clock_gettime(clock_id, ts)
#endif

static int tx_queue_platform_now_ms(uint32_t *now_ms)
{
	struct timespec ts;
	if (tx_queue_clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return -EIO;
	}
	*now_ms = (uint32_t)ts.tv_sec * 1000U +
		  (uint32_t)(ts.tv_nsec / 1000000L);
	return 0;
}
#endif

/* For testing: allow overriding the time source */
#ifdef CONFIG_TX_QUEUE_TEST_TIME
static uint32_t test_time_ms;
static bool use_test_time;

void tx_queue_test_set_time(uint32_t time_ms)
{
	test_time_ms = time_ms;
	use_test_time = true;
	fail_test_time = false;
}

void tx_queue_test_use_real_time(void)
{
	use_test_time = false;
}

void tx_queue_test_fail_time(bool fail)
{
	fail_test_time = fail;
}

static int get_now_ms(uint32_t *now_ms)
{
	if (fail_test_time) {
		return tx_queue_platform_now_ms(now_ms);
	}
	if (use_test_time) {
		*now_ms = test_time_ms;
		return 0;
	}
	return tx_queue_platform_now_ms(now_ms);
}
#else
#define get_now_ms(now_ms) tx_queue_platform_now_ms(now_ms)
#endif

static void lock_queue(struct tx_queue *queue)
{
#ifdef __ZEPHYR__
	k_mutex_lock(&queue->lock, K_FOREVER);
#else
	pthread_mutex_lock(&queue->lock);
#endif
}

static void unlock_queue(struct tx_queue *queue)
{
#ifdef __ZEPHYR__
	k_mutex_unlock(&queue->lock);
#else
	pthread_mutex_unlock(&queue->lock);
#endif
}

/*
 * Expiry compares the entry's 64-bit extended monotonic deadline. A plain
 * 32-bit signed difference resurrects an entry once it is serviced at
 * least 2^31 ms past its deadline (the difference wraps back negative);
 * the extended base keeps queued packets expired across that window.
 */
static bool deadline_expired(uint64_t deadline_ms64, uint64_t now_ms64)
{
	return now_ms64 >= deadline_ms64;
}

/*
 * Extend a 32-bit monotonic sample onto the queue's 64-bit time base.
 * The platform clock is monotonic, so the forward difference of the low
 * 32 bits is the true elapsed time as long as the gap between consecutive
 * samples stays under 2^32 ms.
 */
static uint64_t extend_now64(uint64_t prev_ms64, uint32_t now_ms)
{
	return prev_ms64 + (uint32_t)(now_ms - (uint32_t)prev_ms64);
}

/* Absolute deadlines must be unambiguously in the next half of uptime. */
static bool deadline_valid_future(uint32_t deadline_ms, uint32_t now_ms)
{
	uint32_t delta = deadline_ms - now_ms;

	return delta != 0U && delta <= INT32_MAX;
}

/**
 * @brief Expire packets past their deadline (caller holds lock).
 */
static int expire_packets_locked(struct tx_queue *queue, uint64_t now_ms64)
{
	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (queue->entries[i].valid &&
		    deadline_expired(queue->entries[i].deadline_ms64, now_ms64)) {
			int ret = lichen_frame_pool_release(&queue->pool,
						    queue->entries[i].buffer);
			if (ret < 0) {
				return -EIO;
			}
			queue->entries[i].valid = false;
			queue->stats.packets_dropped_deadline++;
		}
	}
	return 0;
}

/**
 * @brief Find an empty slot (caller holds lock).
 * @return Slot index, or -1 if none available
 */
static int find_empty_slot_locked(struct tx_queue *queue)
{
	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (!queue->entries[i].valid) {
			return i;
		}
	}
	return -1;
}

/* A 64-bit monotonic order avoids ambiguity across 32-bit enqueue gaps. */
static bool enqueue_order_before(uint64_t left, uint64_t right)
{
	return left < right;
}

/* Compress the at-most-four live sequence values before uint64_t wraps. */
static void renormalize_enqueue_orders_locked(struct tx_queue *queue)
{
	uint64_t original[TX_QUEUE_SIZE];
	bool assigned[TX_QUEUE_SIZE] = {false};
	uint64_t rank = 0U;

	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		original[i] = queue->entries[i].enqueue_order;
	}
	for (;;) {
		int oldest = -1;

		for (int i = 0; i < TX_QUEUE_SIZE; i++) {
			if (!queue->entries[i].valid || assigned[i]) {
				continue;
			}
			if (oldest < 0 || original[i] < original[oldest]) {
				oldest = i;
			}
		}
		if (oldest < 0) {
			break;
		}
		queue->entries[oldest].enqueue_order = rank++;
		assigned[oldest] = true;
	}
	queue->next_enqueue_order = rank;
}

/**
 * @brief Find the lowest-priority entry (caller holds lock).
 * @return Slot index of lowest priority entry, or -1 if queue empty
 */
static int find_lowest_priority_locked(struct tx_queue *queue)
{
	int lowest_idx = -1;
	uint8_t lowest_priority = 0;

	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (queue->entries[i].valid) {
			/* Higher priority value = lower priority */
			if (lowest_idx < 0 ||
			    queue->entries[i].priority > lowest_priority ||
			    (queue->entries[i].priority == lowest_priority &&
			     enqueue_order_before(queue->entries[i].enqueue_order,
					  queue->entries[lowest_idx].enqueue_order))) {
				lowest_idx = i;
				lowest_priority = queue->entries[i].priority;
			}
		}
	}
	return lowest_idx;
}

/**
 * @brief Find the highest-priority non-expired entry (caller holds lock).
 * @return Slot index of highest priority entry, or -1 if queue empty
 */
static int find_highest_priority_locked(struct tx_queue *queue,
					uint64_t now_ms64)
{
	int highest_idx = -1;
	uint8_t highest_priority = 255;

	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (queue->entries[i].valid &&
		    !deadline_expired(queue->entries[i].deadline_ms64,
				      now_ms64)) {
			/* Lower priority value = higher priority */
			if (highest_idx < 0 ||
			    queue->entries[i].priority < highest_priority ||
			    (queue->entries[i].priority == highest_priority &&
			     enqueue_order_before(queue->entries[i].enqueue_order,
					  queue->entries[highest_idx].enqueue_order))) {
				highest_idx = i;
				highest_priority = queue->entries[i].priority;
			}
		}
	}
	return highest_idx;
}

int tx_queue_init(struct tx_queue *queue)
{
	if (queue == NULL) {
		return -EINVAL;
	}

	memset(queue, 0, sizeof(*queue));
	int ret = lichen_frame_pool_init(&queue->pool);
	if (ret < 0) {
		return ret;
	}

#ifdef __ZEPHYR__
	k_mutex_init(&queue->lock);
#else
	int err = pthread_mutex_init(&queue->lock, NULL);
	if (err != 0) {
		(void)lichen_frame_pool_destroy(&queue->pool);
		return -err;
	}
#endif

	return 0;
}

static int tx_queue_push_at(struct tx_queue *queue, const uint8_t *data,
			    uint16_t len, uint8_t priority,
			    uint32_t deadline_value, bool relative_deadline)
{
	int ret = 0;
	uint32_t now_ms;
	uint32_t deadline_ms;
	uint8_t *storage = NULL;
	size_t capacity = 0U;
	bool acquired = false;

	lock_queue(queue);
	ret = get_now_ms(&now_ms);
	if (ret < 0) {
		goto out;
	}
	queue->now_ms64 = extend_now64(queue->now_ms64, now_ms);
	deadline_ms = relative_deadline ? now_ms + deadline_value : deadline_value;

	/* Step 1: Expire old packets */
	ret = expire_packets_locked(queue, queue->now_ms64);
	if (ret < 0) {
		goto out;
	}
	if (!deadline_valid_future(deadline_ms, now_ms)) {
		ret = -EINVAL;
		goto out;
	}
	uint64_t deadline_ms64 = queue->now_ms64 +
				 (uint64_t)(deadline_ms - now_ms);

	/* Step 2: Try to find an empty slot */
	int slot = find_empty_slot_locked(queue);

	if (slot < 0) {
		/* Queue full - try preemption */
		int lowest_idx = find_lowest_priority_locked(queue);

		if (lowest_idx >= 0 &&
		    queue->entries[lowest_idx].priority > priority) {
			slot = lowest_idx;
		} else {
			/* Cannot preempt: return backpressure */
			queue->stats.packets_dropped_full++;
			ret = -ENOBUFS;
			goto out;
		}
	}

	if (queue->entries[slot].valid) {
		ret = lichen_frame_pool_get(&queue->pool,
					    queue->entries[slot].buffer,
					    &storage, &capacity);
		if (ret < 0) {
			ret = -EIO;
			goto out;
		}
		queue->stats.packets_preempted++;
	} else {
		ret = lichen_frame_pool_acquire(&queue->pool,
						&queue->entries[slot].buffer,
						&storage, &capacity);
		if (ret < 0) {
			goto out;
		}
		acquired = true;
	}
	if (capacity < len) {
		if (acquired) {
			(void)lichen_frame_pool_release(&queue->pool,
							queue->entries[slot].buffer);
		}
		ret = -EIO;
		goto out;
	}

	/* Insert packet */
	memset(storage, 0, capacity);
	memcpy(storage, data, len);
	if (queue->next_enqueue_order == UINT64_MAX) {
		renormalize_enqueue_orders_locked(queue);
	}
	queue->entries[slot].len = len;
	queue->entries[slot].deadline_ms = deadline_ms;
	queue->entries[slot].deadline_ms64 = deadline_ms64;
	queue->entries[slot].enqueue_ms = now_ms;
	queue->entries[slot].enqueue_order = queue->next_enqueue_order++;
	queue->entries[slot].priority = priority;
	queue->entries[slot].valid = true;
	queue->stats.packets_queued++;

out:
	unlock_queue(queue);
	return ret;
}

int tx_queue_push(struct tx_queue *queue, const uint8_t *data, uint16_t len,
		  uint8_t priority, uint32_t deadline_ms)
{
	if (queue == NULL || data == NULL || len == 0 ||
	    len > TX_QUEUE_MAX_PACKET_SIZE || priority >= TX_PRIORITY_COUNT) {
		return -EINVAL;
	}
	if (queue->terminal) {
		return -EIO;
	}
	return tx_queue_push_at(queue, data, len, priority, deadline_ms, false);
}

int tx_queue_push_default_deadline(struct tx_queue *queue,
				   const uint8_t *data, uint16_t len,
				   uint8_t priority)
{
	uint32_t timeout_ms;

	if (queue == NULL || data == NULL || len == 0 ||
	    len > TX_QUEUE_MAX_PACKET_SIZE || priority >= TX_PRIORITY_COUNT) {
		return -EINVAL;
	}
	if (queue->terminal) {
		return -EIO;
	}

	switch (priority) {
	case TX_PRIORITY_SOS:
		timeout_ms = TX_DEADLINE_SOS_MS;
		break;
	case TX_PRIORITY_ROUTING:
		timeout_ms = TX_DEADLINE_ROUTING_MS;
		break;
	case TX_PRIORITY_URGENT:
		timeout_ms = TX_DEADLINE_URGENT_MS;
		break;
	case TX_PRIORITY_NORMAL:
		timeout_ms = TX_DEADLINE_NORMAL_MS;
		break;
	case TX_PRIORITY_BULK:
		timeout_ms = TX_DEADLINE_BULK_MS;
		break;
	default:
		return -EINVAL;
	}

	return tx_queue_push_at(queue, data, len, priority, timeout_ms, true);
}

int tx_queue_pop(struct tx_queue *queue, uint8_t *data, uint16_t *len,
		 uint32_t *latency_ms)
{
	if (queue == NULL || data == NULL || len == NULL) {
		return -EINVAL;
	}
	if (queue->terminal) {
		return -EIO;
	}

	uint32_t now_ms;
	int ret = 0;

	lock_queue(queue);
	ret = get_now_ms(&now_ms);
	if (ret < 0) {
		goto out;
	}
	queue->now_ms64 = extend_now64(queue->now_ms64, now_ms);

	/* Expire old packets first */
	ret = expire_packets_locked(queue, queue->now_ms64);
	if (ret < 0) {
		goto out;
	}

	/* Find highest priority valid packet */
	int idx = find_highest_priority_locked(queue, queue->now_ms64);

	if (idx < 0) {
		ret = -EAGAIN; /* Queue empty */
		goto out;
	}

	struct tx_queue_entry *entry = &queue->entries[idx];
	uint8_t *storage;
	size_t capacity;

	if (entry->len > *len) {
		ret = -ENOMEM; /* Buffer too small */
		goto out;
	}
	ret = lichen_frame_pool_get(&queue->pool, entry->buffer,
				    &storage, &capacity);
	if (ret < 0 || capacity < entry->len) {
		ret = -EIO;
		goto out;
	}

	/* Copy data out */
	memcpy(data, storage, entry->len);
	*len = entry->len;

	/*
	 * Latency = time spent in queue, from the enqueue timestamp taken at
	 * push time. Signed difference handles 32-bit uptime wraparound;
	 * a negative result (clock stepped backwards) clamps to zero.
	 * EWMA alpha = 1/8, stored scaled by 8 to avoid a divide per update:
	 *   scaled = scaled - scaled/8 + latency
	 *   avg_latency_ms = scaled / 8
	 */
	uint32_t latency_ms_now = 0;
	int32_t signed_diff = (int32_t)(now_ms - entry->enqueue_ms);
	if (signed_diff > 0) {
		latency_ms_now = (uint32_t)signed_diff;
	}
	if (latency_ms_now > queue->stats.max_latency_ms) {
		queue->stats.max_latency_ms = latency_ms_now;
	}
	uint32_t decayed = queue->avg_latency_scaled -
			   queue->avg_latency_scaled / 8U;
	if (decayed > UINT32_MAX - latency_ms_now) {
		queue->avg_latency_scaled = UINT32_MAX;
	} else {
		queue->avg_latency_scaled = decayed + latency_ms_now;
	}
	queue->stats.avg_latency_ms = queue->avg_latency_scaled / 8U;

	if (latency_ms != NULL) {
		*latency_ms = latency_ms_now;
	}

	ret = lichen_frame_pool_release(&queue->pool, entry->buffer);
	if (ret < 0) {
		ret = -EIO;
		goto out;
	}

	/* Mark entry as consumed only after pool ownership is released. */
	entry->valid = false;
	queue->stats.packets_sent++;
	ret = 0;

out:
	unlock_queue(queue);
	return ret;
}

int tx_queue_count(struct tx_queue *queue)
{
	if (queue == NULL) {
		return -EINVAL;
	}
	if (queue->terminal) {
		return -EIO;
	}

	lock_queue(queue);

	int count = 0;
	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (queue->entries[i].valid) {
			count++;
		}
	}

	unlock_queue(queue);
	return count;
}

bool tx_queue_empty(struct tx_queue *queue)
{
	if (queue == NULL) {
		return true;
	}
	if (queue->terminal) {
		return true;
	}

	lock_queue(queue);

	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (queue->entries[i].valid) {
			unlock_queue(queue);
			return false;
		}
	}

	unlock_queue(queue);
	return true;
}

int tx_queue_stats_get(struct tx_queue *queue, struct tx_queue_stats *stats)
{
	if (queue == NULL || stats == NULL) {
		return -EINVAL;
	}
	if (queue->terminal) {
		return -EIO;
	}

	lock_queue(queue);
	*stats = queue->stats;
	unlock_queue(queue);
	return 0;
}

int tx_queue_clear(struct tx_queue *queue)
{
	if (queue == NULL) {
		return -EINVAL;
	}
	if (queue->terminal) {
		return -EIO;
	}

	lock_queue(queue);

	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (queue->entries[i].valid) {
			int ret = lichen_frame_pool_release(&queue->pool,
							    queue->entries[i].buffer);
			if (ret < 0) {
				unlock_queue(queue);
				return ret;
			}
			queue->entries[i].valid = false;
		}
	}

	memset(&queue->stats, 0, sizeof(queue->stats));
	queue->avg_latency_scaled = 0;
	queue->next_enqueue_order = 0;

	unlock_queue(queue);
	return 0;
}

int tx_queue_destroy(struct tx_queue *queue)
{
	if (queue == NULL) {
		return -EINVAL;
	}
	if (queue->terminal) {
		return -EIO;
	}
	int ret = tx_queue_clear(queue);
	if (ret < 0) {
		return ret;
	}
	ret = lichen_frame_pool_destroy(&queue->pool);
	if (ret < 0) {
		return ret;
	}

#ifdef __ZEPHYR__
	/* Zephyr k_mutex has no destroy operation */
	return 0;
#else
	int mutex_ret = pthread_mutex_destroy(&queue->lock);
	if (mutex_ret != 0) {
		/* Restore the already-destroyed empty pool so retry remains safe. */
		queue->terminal = true;
		ret = lichen_frame_pool_init(&queue->pool);
		if (ret == 0) {
			queue->terminal = false;
			return -mutex_ret;
		}
		return ret;
	}
	return 0;
#endif
}
