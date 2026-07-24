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

/**
 * @brief Check if a deadline has passed (handles wraparound).
 *
 * Uses signed comparison to handle 32-bit wraparound correctly.
 * A deadline is expired if (now - deadline) is positive when interpreted
 * as a signed value. This works for wraparound within ~24 days.
 */
static bool deadline_expired(uint32_t deadline_ms, uint32_t now_ms)
{
	return now_ms - deadline_ms < UINT32_C(0x80000000);
}

/**
 * @brief Expire packets past their deadline (caller holds lock).
 */
static void expire_packets_locked(struct tx_queue *queue, uint32_t now_ms)
{
	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (queue->entries[i].valid &&
		    deadline_expired(queue->entries[i].deadline_ms, now_ms)) {
			queue->entries[i].valid = false;
			queue->stats.packets_dropped_deadline++;
		}
	}
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
			    queue->entries[i].priority > lowest_priority) {
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
static int find_highest_priority_locked(struct tx_queue *queue, uint32_t now_ms)
{
	int highest_idx = -1;
	uint8_t highest_priority = 255;

	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (queue->entries[i].valid &&
		    !deadline_expired(queue->entries[i].deadline_ms, now_ms)) {
			/* Lower priority value = higher priority */
			if (highest_idx < 0 ||
			    queue->entries[i].priority < highest_priority) {
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

#ifdef __ZEPHYR__
	k_mutex_init(&queue->lock);
#else
	pthread_mutex_init(&queue->lock, NULL);
#endif

	return 0;
}

static int tx_queue_push_at(struct tx_queue *queue, const uint8_t *data,
			    uint16_t len, uint8_t priority,
			    uint32_t deadline_ms, uint32_t now_ms)
{
	int ret = 0;

	lock_queue(queue);

	/* Step 1: Expire old packets */
	expire_packets_locked(queue, now_ms);

	/* Step 2: Try to find an empty slot */
	int slot = find_empty_slot_locked(queue);

	if (slot < 0) {
		/* Queue full - try preemption */
		int lowest_idx = find_lowest_priority_locked(queue);

		if (lowest_idx >= 0 &&
		    queue->entries[lowest_idx].priority > priority) {
			/* Preempt: new packet has higher priority (lower value) */
			queue->entries[lowest_idx].valid = false;
			queue->stats.packets_preempted++;
			slot = lowest_idx;
		} else {
			/* Cannot preempt: return backpressure */
			queue->stats.packets_dropped_full++;
			ret = -ENOBUFS;
			goto out;
		}
	}

	/* Insert packet */
	memcpy(queue->entries[slot].data, data, len);
	queue->entries[slot].len = len;
	queue->entries[slot].deadline_ms = deadline_ms;
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
	uint32_t now_ms;
	int ret;

	if (queue == NULL || data == NULL || len == 0 ||
	    len > TX_QUEUE_MAX_PACKET_SIZE) {
		return -EINVAL;
	}
	ret = get_now_ms(&now_ms);
	if (ret < 0) {
		return ret;
	}
	return tx_queue_push_at(queue, data, len, priority, deadline_ms, now_ms);
}

int tx_queue_push_default_deadline(struct tx_queue *queue,
				   const uint8_t *data, uint16_t len,
				   uint8_t priority)
{
	uint32_t now_ms;
	int ret;
	uint32_t deadline_ms;

	if (queue == NULL || data == NULL || len == 0 ||
	    len > TX_QUEUE_MAX_PACKET_SIZE) {
		return -EINVAL;
	}
	ret = get_now_ms(&now_ms);
	if (ret < 0) {
		return ret;
	}

	switch (priority) {
	case TX_PRIORITY_ROUTING:
		deadline_ms = now_ms + TX_DEADLINE_ROUTING_MS;
		break;
	case TX_PRIORITY_ACK:
		deadline_ms = now_ms + TX_DEADLINE_ACK_MS;
		break;
	default:
		deadline_ms = now_ms + TX_DEADLINE_APP_MS;
		break;
	}

	return tx_queue_push_at(queue, data, len, priority, deadline_ms, now_ms);
}

int tx_queue_pop(struct tx_queue *queue, uint8_t *data, uint16_t *len,
		 uint32_t *latency_ms)
{
	if (queue == NULL || data == NULL || len == NULL) {
		return -EINVAL;
	}

	uint32_t now_ms;
	int ret = get_now_ms(&now_ms);

	if (ret < 0) {
		return ret;
	}
	ret = 0;

	lock_queue(queue);

	/* Expire old packets first */
	expire_packets_locked(queue, now_ms);

	/* Find highest priority valid packet */
	int idx = find_highest_priority_locked(queue, now_ms);

	if (idx < 0) {
		ret = -EAGAIN; /* Queue empty */
		goto out;
	}

	struct tx_queue_entry *entry = &queue->entries[idx];

	if (entry->len > *len) {
		ret = -ENOMEM; /* Buffer too small */
		goto out;
	}

	/* Copy data out */
	memcpy(data, entry->data, entry->len);
	*len = entry->len;

	/* Calculate latency if requested */
	if (latency_ms != NULL) {
		/*
		 * Latency = time from when deadline was set minus TTL.
		 * Since we store absolute deadline, we calculate based on
		 * the difference between now and when it would have been
		 * queued. This is approximate since we don't store enqueue time.
		 *
		 * For accurate latency, we'd need to store enqueue timestamp.
		 * For now, report 0 as a placeholder.
		 */
		*latency_ms = 0;
	}

	/* Mark entry as consumed */
	entry->valid = false;
	queue->stats.packets_sent++;

out:
	unlock_queue(queue);
	return ret;
}

int tx_queue_count(const struct tx_queue *queue)
{
	if (queue == NULL) {
		return -EINVAL;
	}

	struct tx_queue *q = (struct tx_queue *)queue;
	lock_queue(q);

	int count = 0;
	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (q->entries[i].valid) {
			count++;
		}
	}

	unlock_queue(q);
	return count;
}

bool tx_queue_empty(const struct tx_queue *queue)
{
	if (queue == NULL) {
		return true;
	}

	struct tx_queue *q = (struct tx_queue *)queue;
	lock_queue(q);

	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		if (q->entries[i].valid) {
			unlock_queue(q);
			return false;
		}
	}

	unlock_queue(q);
	return true;
}

int tx_queue_stats_get(const struct tx_queue *queue,
		       struct tx_queue_stats *stats)
{
	if (queue == NULL || stats == NULL) {
		return -EINVAL;
	}

	/*
	 * Note: This read is not atomic with respect to concurrent writes.
	 * For diagnostic purposes this is acceptable; for precise accounting
	 * the caller should serialize access externally.
	 */
	*stats = queue->stats;
	return 0;
}

void tx_queue_clear(struct tx_queue *queue)
{
	if (queue == NULL) {
		return;
	}

	lock_queue(queue);

	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		queue->entries[i].valid = false;
	}

	memset(&queue->stats, 0, sizeof(queue->stats));

	unlock_queue(queue);
}

int tx_queue_destroy(struct tx_queue *queue)
{
	if (queue == NULL) {
		return -EINVAL;
	}

#ifdef __ZEPHYR__
	(void)queue;
	return 0;
#else
	return -pthread_mutex_destroy(&queue->lock);
#endif
}
