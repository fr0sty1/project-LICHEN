/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief LICHEN TX queue tests
 *
 * Tests for bufferbloat avoidance: bounded queue, deadlines, priority,
 * and explicit backpressure.
 */

#include <lichen/tx_queue.h>
#include <lichen/errno.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <lichen_generated_tx_queue_vectors.h>

/* Disable nonnull warnings for tests that intentionally pass NULL */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wnonnull"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wnonnull"
#endif

/* Test time control (defined in tx_queue.c when CONFIG_TX_QUEUE_TEST_TIME) */
extern void tx_queue_test_set_time(uint32_t time_ms);
extern void tx_queue_test_use_real_time(void);
extern void tx_queue_test_fail_time(bool fail);

static int tests_run;
static int tests_passed;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

#define ASSERT_TRUE(cond, msg) do { \
	if (!(cond)) { \
		printf("  FAIL: %s\n", msg); \
		return 0; \
	} \
} while (0)

static int test_init_rejects_null(void)
{
	ASSERT_EQ(tx_queue_init(NULL), -EINVAL, "init rejects NULL queue");
	return 1;
}

static int test_empty_null_returns_true(void)
{
	/* Documented contract: tx_queue_empty(NULL) returns true */
	ASSERT_TRUE(tx_queue_empty(NULL), "empty(NULL) returns true");
	return 1;
}

static int test_init_success(void)
{
	struct tx_queue queue;

	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_TRUE(tx_queue_empty(&queue), "queue is empty after init");
	ASSERT_EQ(tx_queue_count(&queue), 0, "count is 0 after init");

	return 1;
}

static int test_push_rejects_null_queue(void)
{
	uint8_t data[10] = {1, 2, 3};

	ASSERT_EQ(tx_queue_push(NULL, data, sizeof(data), TX_PRIORITY_BULK, 1000),
		  -EINVAL, "push rejects NULL queue");
	return 1;
}

static int test_push_rejects_null_data(void)
{
	struct tx_queue queue;

	tx_queue_init(&queue);
	ASSERT_EQ(tx_queue_push(&queue, NULL, 10, TX_PRIORITY_BULK, 1000),
		  -EINVAL, "push rejects NULL data");
	return 1;
}

static int test_push_rejects_zero_len(void)
{
	struct tx_queue queue;
	uint8_t data[10] = {0};

	tx_queue_init(&queue);
	ASSERT_EQ(tx_queue_push(&queue, data, 0, TX_PRIORITY_BULK, 1000),
		  -EINVAL, "push rejects zero length");
	return 1;
}

static int test_push_rejects_oversized(void)
{
	struct tx_queue queue;
	uint8_t data[10] = {0};

	tx_queue_init(&queue);
	ASSERT_EQ(tx_queue_push(&queue, data, TX_QUEUE_MAX_PACKET_SIZE + 1,
				TX_PRIORITY_BULK, 1000),
		  -EINVAL, "push rejects oversized packet");
	return 1;
}

static int test_push_rejects_invalid_priority_without_mutation(void)
{
	struct tx_queue queue;
	uint8_t data[4] = {0};
	struct tx_queue_stats stats;

	tx_queue_test_set_time(1000);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, data, sizeof(data), TX_PRIORITY_COUNT, 60000),
		  -EINVAL, "explicit push rejects invalid priority");
	ASSERT_EQ(tx_queue_push_default_deadline(&queue, data, sizeof(data), UINT8_MAX),
		  -EINVAL, "default push rejects invalid priority");
	ASSERT_EQ(tx_queue_count(&queue), 0, "invalid priority does not enqueue");
	ASSERT_EQ(tx_queue_stats_get(&queue, &stats), 0, "stats read succeeds");
	ASSERT_EQ(stats.packets_queued, 0, "invalid priority does not mutate stats");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");
	return 1;
}

static int test_shared_vector_constants(void)
{
	ASSERT_EQ(TX_QUEUE_SIZE, VECTOR_TX_QUEUE_CAPACITY,
		  "queue capacity matches shared vectors");
	ASSERT_EQ(TX_PRIORITY_SOS, VECTOR_PRIORITY_SOS, "SOS priority matches vectors");
	ASSERT_EQ(TX_PRIORITY_ROUTING, VECTOR_PRIORITY_ROUTING,
		  "routing priority matches vectors");
	ASSERT_EQ(TX_PRIORITY_ACK, VECTOR_PRIORITY_ACK, "ACK priority matches vectors");
	ASSERT_EQ(TX_PRIORITY_URGENT, VECTOR_PRIORITY_URGENT,
		  "urgent priority matches vectors");
	ASSERT_EQ(TX_PRIORITY_NORMAL, VECTOR_PRIORITY_NORMAL,
		  "normal priority matches vectors");
	ASSERT_EQ(TX_PRIORITY_BULK, VECTOR_PRIORITY_BULK,
		  "bulk priority matches vectors");
	ASSERT_EQ(TX_PRIORITY_COUNT, VECTOR_PRIORITY_BULK + 1,
		  "priority count covers canonical values");
	ASSERT_EQ(TX_DEADLINE_SOS_MS, VECTOR_DEADLINE_SOS_MS,
		  "SOS deadline matches vectors");
	ASSERT_EQ(TX_DEADLINE_ROUTING_MS, VECTOR_DEADLINE_ROUTING_MS,
		  "routing deadline matches vectors");
	ASSERT_EQ(TX_DEADLINE_ACK_MS, VECTOR_DEADLINE_ACK_MS,
		  "ACK deadline matches vectors");
	ASSERT_EQ(TX_DEADLINE_URGENT_MS, VECTOR_DEADLINE_URGENT_MS,
		  "urgent deadline matches vectors");
	ASSERT_EQ(TX_DEADLINE_NORMAL_MS, VECTOR_DEADLINE_NORMAL_MS,
		  "normal deadline matches vectors");
	ASSERT_EQ(TX_DEADLINE_BULK_MS, VECTOR_DEADLINE_BULK_MS,
		  "bulk deadline matches vectors");
	ASSERT_EQ(-ENOBUFS, VECTOR_ENOBUFS, "backpressure errno matches vectors");
	return 1;
}

static int test_push_validates_absolute_deadline_range(void)
{
	struct tx_queue queue;
	uint8_t data = 0xa5;
	struct tx_queue_stats stats;
	const uint32_t now = 1000U;

	tx_queue_test_set_time(now);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL, now),
		  -EINVAL, "deadline at now is rejected");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL, now - 1U),
		  -EINVAL, "past deadline is rejected");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL,
				now + UINT32_C(0x80000000)),
		  -EINVAL, "ambiguous half-range deadline is rejected");
	ASSERT_EQ(tx_queue_count(&queue), 0, "invalid deadlines do not enqueue");
	ASSERT_EQ(tx_queue_stats_get(&queue, &stats), 0, "stats read succeeds");
	ASSERT_EQ(stats.packets_queued, 0, "invalid deadlines do not mutate stats");

	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL,
				now + (uint32_t)INT32_MAX),
		  0, "largest unambiguous future deadline is accepted");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");

	/* A small future delta remains valid when the absolute timestamp wraps. */
	tx_queue_test_set_time(UINT32_MAX - 100U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "wrap queue init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL, 99U),
		  0, "future deadline across uptime wrap is accepted");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "wrap queue destroy succeeds");
	return 1;
}

static int test_invalid_incoming_deadline_expires_stale_first(void)
{
	struct tx_queue queue;
	uint8_t stale = 1U;
	uint8_t incoming = 2U;
	struct tx_queue_stats stats;

	tx_queue_test_set_time(100U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &stale, 1U, TX_PRIORITY_BULK, 200U),
		  0, "stale candidate is queued");
	tx_queue_test_set_time(300U);
	ASSERT_EQ(tx_queue_push(&queue, &incoming, 1U, TX_PRIORITY_SOS, 300U),
		  -EINVAL, "invalid incoming deadline is rejected");
	ASSERT_EQ(tx_queue_count(&queue), 0, "stale entry expired before rejection");
	ASSERT_EQ(tx_queue_stats_get(&queue, &stats), 0, "stats read succeeds");
	ASSERT_EQ(stats.packets_dropped_deadline, 1,
		  "deadline-drop statistic records stale expiry");
	ASSERT_EQ(stats.packets_dropped_full, 0,
		  "invalid incoming packet does not count as backpressure");
	ASSERT_EQ(stats.packets_preempted, 0,
		  "invalid incoming packet does not preempt");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");
	return 1;
}

static int test_push_and_pop_single(void)
{
	struct tx_queue queue;
	uint8_t in_data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len = sizeof(out_data);

	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	/* Push one packet */
	ASSERT_EQ(tx_queue_push(&queue, in_data, sizeof(in_data),
				TX_PRIORITY_BULK, 60000),
		  0, "push succeeds");
	ASSERT_EQ(tx_queue_count(&queue), 1, "count is 1 after push");
	ASSERT_TRUE(!tx_queue_empty(&queue), "queue not empty");

	/* Pop it back */
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL),
		  0, "pop succeeds");
	ASSERT_EQ(out_len, sizeof(in_data), "popped length matches");
	ASSERT_TRUE(memcmp(in_data, out_data, sizeof(in_data)) == 0,
		    "popped data matches");
	ASSERT_TRUE(tx_queue_empty(&queue), "queue empty after pop");

	return 1;
}

static int test_pop_empty_returns_eagain(void)
{
	struct tx_queue queue;
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len = sizeof(out_data);

	tx_queue_init(&queue);

	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL),
		  -EAGAIN, "pop on empty queue returns EAGAIN");
	return 1;
}

static int test_queue_full_returns_enobufs(void)
{
	struct tx_queue queue;
	uint8_t data[4] = {1, 2, 3, 4};

	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	/* Fill the queue */
	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		ASSERT_EQ(tx_queue_push(&queue, data, sizeof(data),
					TX_PRIORITY_BULK, 60000),
			  0, "push succeeds while filling");
	}

	ASSERT_EQ(tx_queue_count(&queue), TX_QUEUE_SIZE, "queue is full");

	/* Try to add one more at same priority - should fail */
	ASSERT_EQ(tx_queue_push(&queue, data, sizeof(data),
				TX_PRIORITY_BULK, 60000),
		  -ENOBUFS, "push returns ENOBUFS when full");

	return 1;
}

static int test_priority_preemption(void)
{
	struct tx_queue queue;
	uint8_t bulk_data[4] = {0x01, 0x01, 0x01, 0x01};
	uint8_t routing_data[4] = {0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len;
	struct tx_queue_stats stats;

	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	/* Fill queue with bulk (low priority) packets */
	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		ASSERT_EQ(tx_queue_push(&queue, bulk_data, sizeof(bulk_data),
					TX_PRIORITY_BULK, 60000),
			  0, "bulk push succeeds");
	}

	/* Now push a high-priority routing packet - should preempt */
	ASSERT_EQ(tx_queue_push(&queue, routing_data, sizeof(routing_data),
				TX_PRIORITY_ROUTING, 6000),
		  0, "high-priority push succeeds via preemption");

	/* Verify preemption stats */
	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.packets_preempted, 1, "one packet preempted");

	/* Pop should return the routing packet first */
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop succeeds");
	ASSERT_TRUE(memcmp(out_data, routing_data, sizeof(routing_data)) == 0,
		    "highest priority packet popped first");

	return 1;
}

static int test_priority_order(void)
{
	struct tx_queue queue;
	const uint8_t push_data[] = {
		VECTOR_ALIAS_PUSH_0_DATA, VECTOR_ALIAS_PUSH_1_DATA,
		VECTOR_ALIAS_PUSH_2_DATA, VECTOR_ALIAS_PUSH_3_DATA,
	};
	const uint8_t push_priorities[] = {
		VECTOR_ALIAS_PUSH_0_PRIORITY, VECTOR_ALIAS_PUSH_1_PRIORITY,
		VECTOR_ALIAS_PUSH_2_PRIORITY, VECTOR_ALIAS_PUSH_3_PRIORITY,
	};
	const uint8_t expected_pop[] = {
		VECTOR_ALIAS_POP_0_DATA, VECTOR_ALIAS_POP_1_DATA,
		VECTOR_ALIAS_POP_2_DATA, VECTOR_ALIAS_POP_3_DATA,
	};
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len;

	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	for (size_t i = 0U; i < sizeof(push_data) / sizeof(push_data[0]); i++) {
		ASSERT_EQ(tx_queue_push(&queue, &push_data[i], 1U,
					push_priorities[i], 60000U),
			  0, "vector-driven priority push succeeds");
	}
	for (size_t i = 0U; i < sizeof(expected_pop) / sizeof(expected_pop[0]); i++) {
		out_len = sizeof(out_data);
		ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0,
			  "vector-driven priority pop succeeds");
		ASSERT_EQ(out_data[0], expected_pop[i],
			  "pop order matches priority vector");
	}

	return 1;
}

static int test_same_priority_fifo_survives_slot_reuse(void)
{
	struct tx_queue queue;
	uint8_t first = 1;
	uint8_t second = 2;
	uint8_t third = 3;
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len;

	tx_queue_test_set_time(1000);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &first, 1, TX_PRIORITY_BULK, 60000), 0,
		  "push first");
	ASSERT_EQ(tx_queue_push(&queue, &second, 1, TX_PRIORITY_BULK, 60000), 0,
		  "push second");

	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop first");
	ASSERT_EQ(out_data[0], first, "oldest packet pops first");
	ASSERT_EQ(tx_queue_push(&queue, &third, 1, TX_PRIORITY_BULK, 60000), 0,
		  "push third into reused slot");

	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop second");
	ASSERT_EQ(out_data[0], second, "slot reuse preserves FIFO");
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop third");
	ASSERT_EQ(out_data[0], third, "newest packet pops last");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");
	return 1;
}

static int test_same_priority_fifo_survives_sequence_wrap(void)
{
	struct tx_queue queue;
	uint8_t before_wrap = 1;
	uint8_t at_wrap = 2;
	uint8_t after_wrap = 3;
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len;

	tx_queue_test_set_time(1000);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	queue.next_enqueue_order = UINT64_MAX - 1U;
	ASSERT_EQ(tx_queue_push(&queue, &before_wrap, 1, TX_PRIORITY_BULK, 60000), 0,
		  "push before wrap");
	ASSERT_EQ(tx_queue_push(&queue, &at_wrap, 1, TX_PRIORITY_BULK, 60000), 0,
		  "push at wrap");
	ASSERT_EQ(tx_queue_push(&queue, &after_wrap, 1, TX_PRIORITY_BULK, 60000), 0,
		  "push after wrap");

	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop before wrap");
	ASSERT_EQ(out_data[0], before_wrap, "first pre-wrap packet remains oldest");
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop at wrap");
	ASSERT_EQ(out_data[0], at_wrap, "second pre-wrap packet remains ordered");
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop after wrap");
	ASSERT_EQ(out_data[0], after_wrap, "post-wrap packet remains newest");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");
	return 1;
}

static int test_preemption_order_survives_uint32_half_range_gap(void)
{
	struct tx_queue queue;
	uint8_t oldest_bulk = 1U;
	uint8_t newer_bulk = 2U;
	uint8_t normal = 3U;
	uint8_t sos = 4U;
	uint8_t out[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len;

	tx_queue_test_set_time(1000U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &oldest_bulk, 1U, TX_PRIORITY_BULK, 60000U),
		  0, "push oldest bulk");
	queue.next_enqueue_order = (uint64_t)UINT32_MAX + 1U;
	ASSERT_EQ(tx_queue_push(&queue, &newer_bulk, 1U, TX_PRIORITY_BULK, 60000U),
		  0, "push bulk after uint32 half-range");
	ASSERT_EQ(tx_queue_push(&queue, &normal, 1U, TX_PRIORITY_NORMAL, 60000U),
		  0, "push normal");
	ASSERT_EQ(tx_queue_push(&queue, &normal, 1U, TX_PRIORITY_NORMAL, 60000U),
		  0, "fill queue");
	ASSERT_EQ(tx_queue_push(&queue, &sos, 1U, TX_PRIORITY_SOS, 60000U),
		  0, "SOS preempts oldest lowest-priority entry");

	out_len = sizeof(out);
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), 0, "pop SOS");
	ASSERT_EQ(out[0], sos, "SOS is first");
	out_len = sizeof(out);
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), 0, "pop first normal");
	out_len = sizeof(out);
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), 0, "pop second normal");
	out_len = sizeof(out);
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), 0, "pop remaining bulk");
	ASSERT_EQ(out[0], newer_bulk, "oldest bulk was preempted across half-range gap");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");
	return 1;
}

static int test_preemption_evicts_oldest_same_lowest_priority(void)
{
	struct tx_queue queue;
	uint8_t urgent = 10;
	uint8_t bulk_oldest = 20;
	uint8_t bulk_middle = 21;
	uint8_t bulk_newer = 22;
	uint8_t bulk_newest = 23;
	uint8_t routing = 30;
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len;

	tx_queue_test_set_time(1000);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &urgent, 1, TX_PRIORITY_URGENT, 60000), 0,
		  "push urgent");
	ASSERT_EQ(tx_queue_push(&queue, &bulk_oldest, 1, TX_PRIORITY_BULK, 60000), 0,
		  "push oldest bulk");
	ASSERT_EQ(tx_queue_push(&queue, &bulk_middle, 1, TX_PRIORITY_BULK, 60000), 0,
		  "push middle bulk");
	ASSERT_EQ(tx_queue_push(&queue, &bulk_newer, 1, TX_PRIORITY_BULK, 60000), 0,
		  "push newer bulk");

	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop urgent");
	ASSERT_EQ(out_data[0], urgent, "urgent pops first");
	ASSERT_EQ(tx_queue_push(&queue, &bulk_newest, 1, TX_PRIORITY_BULK, 60000), 0,
		  "reuse lower slot for newest bulk");
	ASSERT_EQ(tx_queue_push(&queue, &routing, 1, TX_PRIORITY_ROUTING, 60000), 0,
		  "routing preempts bulk");

	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop routing");
	ASSERT_EQ(out_data[0], routing, "routing is never starved by bulk");
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop middle bulk");
	ASSERT_EQ(out_data[0], bulk_middle, "oldest bulk was the preemption victim");
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop newer bulk");
	ASSERT_EQ(out_data[0], bulk_newer, "remaining bulk preserves FIFO");
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop newest bulk");
	ASSERT_EQ(out_data[0], bulk_newest, "reused-slot bulk remains newest");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");
	return 1;
}

static int test_deadline_expiry_on_push(void)
{
	struct tx_queue queue;
	uint8_t old_data[4] = {0x00, 0x00, 0x00, 0x00};
	uint8_t new_data[4] = {0xFF, 0xFF, 0xFF, 0xFF};
	struct tx_queue_stats stats;

	/* Start at t=1000 */
	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	/* Push packets with deadline at t=2000 */
	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		ASSERT_EQ(tx_queue_push(&queue, old_data, sizeof(old_data),
					TX_PRIORITY_BULK, 2000),
			  0, "initial push succeeds");
	}

	/* Advance time past deadline */
	tx_queue_test_set_time(3000);

	/* Push new packet - should expire old ones first and succeed */
	ASSERT_EQ(tx_queue_push(&queue, new_data, sizeof(new_data),
				TX_PRIORITY_BULK, 60000),
		  0, "push after expiry succeeds");

	/* Verify expiry stats */
	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.packets_dropped_deadline, TX_QUEUE_SIZE,
		  "all old packets expired");

	/* Only the new packet should be in queue */
	ASSERT_EQ(tx_queue_count(&queue), 1, "one packet in queue");

	return 1;
}

static int test_deadline_expiry_on_pop(void)
{
	struct tx_queue queue;
	uint8_t data[4] = {0xAB, 0xCD, 0xEF, 0x01};
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len = sizeof(out_data);

	/* Start at t=1000 */
	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	/* Push packet with deadline at t=2000 */
	ASSERT_EQ(tx_queue_push(&queue, data, sizeof(data),
				TX_PRIORITY_BULK, 2000),
		  0, "push succeeds");
	ASSERT_EQ(tx_queue_count(&queue), 1, "packet in queue");

	/* Advance time past deadline */
	tx_queue_test_set_time(3000);

	/* Pop should expire the packet and return EAGAIN */
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL),
		  -EAGAIN, "pop returns EAGAIN after deadline expiry");

	return 1;
}

static int test_stale_deadline_not_resurrected_after_half_range(void)
{
	struct tx_queue queue;
	uint8_t data = 0x5a;
	uint8_t out[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len = sizeof(out);
	struct tx_queue_stats stats;

	tx_queue_test_set_time(1000U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL, 2000U),
		  0, "packet with near deadline is queued");

	/* Serviced exactly half a 32-bit range past the deadline: the
	 * 32-bit signed difference wraps to "unexpired" here. */
	tx_queue_test_set_time(2000U + UINT32_C(0x80000000));
	out_len = sizeof(out);
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), -EAGAIN,
		  "deadline plus half range does not resurrect packet");
	ASSERT_EQ(tx_queue_stats_get(&queue, &stats), 0, "stats read succeeds");
	ASSERT_EQ(stats.packets_dropped_deadline, 1,
		  "half-range service records deadline drop");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");

	tx_queue_test_set_time(1000U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "wrap queue init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL, 2000U),
		  0, "wrap queue packet is queued");
	tx_queue_test_set_time(2000U + UINT32_C(0x80000000) + 12345U);
	out_len = sizeof(out);
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), -EAGAIN,
		  "past deadline plus half range and wrap stays expired");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "wrap queue destroy succeeds");

	/* A deadline that is still legitimately far in the future survives
	 * the same long jump without false expiry. */
	tx_queue_test_set_time(1000U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "far deadline queue init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL,
				1000U + (uint32_t)INT32_MAX),
		  0, "far future deadline is queued");
	tx_queue_test_set_time(1000U + (UINT32_C(1) << 30));
	out_len = sizeof(out);
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), 0,
		  "packet before its far deadline survives long inactivity");
	ASSERT_EQ(out[0], data, "surviving packet data is intact");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "far deadline queue destroy succeeds");
	return 1;
}

static int test_default_deadlines(void)
{
	uint8_t data[4] = {1, 2, 3, 4};
	const uint8_t priorities[] = {
		TX_PRIORITY_SOS, TX_PRIORITY_ROUTING, TX_PRIORITY_URGENT,
		TX_PRIORITY_NORMAL, TX_PRIORITY_BULK,
	};
	const uint32_t deadlines[] = {
		VECTOR_DEADLINE_SOS_MS, VECTOR_DEADLINE_ROUTING_MS,
		VECTOR_DEADLINE_URGENT_MS, VECTOR_DEADLINE_NORMAL_MS,
		VECTOR_DEADLINE_BULK_MS,
	};

	for (size_t i = 0U; i < sizeof(priorities) / sizeof(priorities[0]); i++) {
		struct tx_queue queue;
		uint8_t out[TX_QUEUE_MAX_PACKET_SIZE];
		uint16_t out_len = sizeof(out);

		tx_queue_test_set_time(1000U);
		ASSERT_EQ(tx_queue_init(&queue), 0, "queue init succeeds");
		ASSERT_EQ(tx_queue_push_default_deadline(&queue, data, sizeof(data),
							  priorities[i]),
			  0, "default-deadline push succeeds");
		tx_queue_test_set_time(1000U + deadlines[i] - 1U);
		ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), 0,
			  "packet remains valid before vector deadline");
		ASSERT_EQ(tx_queue_destroy(&queue), 0, "queue destroy succeeds");

		tx_queue_test_set_time(1000U);
		ASSERT_EQ(tx_queue_init(&queue), 0, "queue re-init succeeds");
		ASSERT_EQ(tx_queue_push_default_deadline(&queue, data, sizeof(data),
							  priorities[i]),
			  0, "second default-deadline push succeeds");
		tx_queue_test_set_time(1000U + deadlines[i]);
		out_len = sizeof(out);
		ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), -EAGAIN,
			  "packet expires exactly at vector deadline");
		ASSERT_EQ(tx_queue_destroy(&queue), 0, "queue destroy after expiry succeeds");
	}

	/* ACK aliases routing for ordering; its 10-second deadline is explicit. */
	struct tx_queue queue;
	uint8_t out[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len = sizeof(out);
	tx_queue_test_set_time(1000U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "ACK queue init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, data, sizeof(data), TX_PRIORITY_ACK,
				1000U + TX_DEADLINE_ACK_MS),
		  0, "explicit ACK deadline push succeeds");
	tx_queue_test_set_time(1000U + VECTOR_DEADLINE_ACK_MS);
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), -EAGAIN,
		  "ACK expires exactly at explicit vector deadline");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "ACK queue destroy succeeds");

	return 1;
}

static int test_shared_vector_expiry_boundary(void)
{
	struct tx_queue queue;
	uint8_t data = 1U;
	uint8_t out[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len = sizeof(out);

	tx_queue_test_set_time(VECTOR_EXPIRY_ENQUEUE_MS);
	ASSERT_EQ(tx_queue_init(&queue), 0, "boundary queue init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL,
				VECTOR_EXPIRY_DEADLINE_MS),
		  0, "boundary packet push succeeds");
	tx_queue_test_set_time(VECTOR_EXPIRY_BEFORE_MS);
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), 0,
		  "packet is live at vector time before deadline");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "boundary queue destroy succeeds");

	tx_queue_test_set_time(VECTOR_EXPIRY_ENQUEUE_MS);
	ASSERT_EQ(tx_queue_init(&queue), 0, "exact queue init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL,
				VECTOR_EXPIRY_DEADLINE_MS),
		  0, "exact packet push succeeds");
	tx_queue_test_set_time(VECTOR_EXPIRY_EXACT_MS);
	out_len = sizeof(out);
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), -EAGAIN,
		  "packet expires exactly at vector deadline");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "exact queue destroy succeeds");
	return 1;
}

static int test_stats_tracking(void)
{
	struct tx_queue queue;
	uint8_t data[4] = {1, 2, 3, 4};
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len;
	struct tx_queue_stats stats;

	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	/* Initial stats should be zero */
	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.packets_queued, 0, "initial queued = 0");
	ASSERT_EQ(stats.packets_sent, 0, "initial sent = 0");

	/* Push and pop */
	tx_queue_push(&queue, data, sizeof(data), TX_PRIORITY_BULK, 60000);
	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.packets_queued, 1, "queued increments on push");

	out_len = sizeof(out_data);
	tx_queue_pop(&queue, out_data, &out_len, NULL);
	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.packets_sent, 1, "sent increments on pop");

	return 1;
}

static int test_latency_tracking(void)
{
	struct tx_queue queue;
	uint8_t data[4] = {1, 2, 3, 4};
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len;
	uint32_t latency = UINT32_MAX;
	struct tx_queue_stats stats;

	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	tx_queue_push(&queue, data, sizeof(data), TX_PRIORITY_BULK, 160000);

	tx_queue_test_set_time(1100);
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, &latency), 0,
		  "pop succeeds");
	ASSERT_EQ(latency, 100, "latency measured from enqueue time");

	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.max_latency_ms, 100, "max latency tracked");
	ASSERT_EQ(stats.avg_latency_ms, 12, "avg latency is EWMA of 100");

	return 1;
}

static int test_latency_max_and_reset(void)
{
	struct tx_queue queue;
	uint8_t data[4] = {1, 2, 3, 4};
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len;
	struct tx_queue_stats stats;

	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	tx_queue_push(&queue, data, sizeof(data), TX_PRIORITY_BULK, 160000);
	tx_queue_test_set_time(1050);
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop 1");

	tx_queue_test_set_time(1200);
	tx_queue_push(&queue, data, sizeof(data), TX_PRIORITY_BULK, 160000);
	tx_queue_test_set_time(1400);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop 2");

	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.max_latency_ms, 200, "max latency keeps worst case");

	ASSERT_EQ(tx_queue_clear(&queue), 0, "clear succeeds");
	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.max_latency_ms, 0, "clear resets max latency");
	ASSERT_EQ(stats.avg_latency_ms, 0, "clear resets avg latency");

	return 1;
}

static int test_clear_release_failure_is_retryable(void)
{
	struct tx_queue queue;
	uint8_t data = 0xa5;
	struct lichen_frame_handle original;
	int clear_ret;

	tx_queue_test_set_time(1000U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL, 60000U),
		  0, "push succeeds");
	original = queue.entries[0].buffer;
	queue.entries[0].buffer.generation++;
	clear_ret = tx_queue_clear(&queue);
	ASSERT_TRUE(clear_ret < 0, "clear propagates stale handle error");
	ASSERT_TRUE(queue.entries[0].valid, "failed clear retains live entry");
	ASSERT_EQ(lichen_frame_pool_in_use(&queue.pool), 1,
		  "failed clear retains pool ownership");
	ASSERT_EQ(tx_queue_destroy(&queue), clear_ret,
		  "destroy propagates clear failure without destroying synchronization");

	queue.entries[0].buffer = original;
	ASSERT_EQ(tx_queue_clear(&queue), 0, "clear retry succeeds");
	ASSERT_TRUE(!queue.entries[0].valid, "retry invalidates released entry");
	ASSERT_EQ(lichen_frame_pool_in_use(&queue.pool), 0,
		  "retry releases pool ownership");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy retry succeeds");
	return 1;
}

static int test_clear(void)
{
	struct tx_queue queue;
	uint8_t data[4] = {1, 2, 3, 4};
	struct tx_queue_stats stats;

	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	/* Add some packets */
	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		tx_queue_push(&queue, data, sizeof(data), TX_PRIORITY_BULK, 60000);
	}

	ASSERT_EQ(tx_queue_count(&queue), TX_QUEUE_SIZE, "queue is full");

	/* Clear */
	ASSERT_EQ(tx_queue_clear(&queue), 0, "clear succeeds");

	ASSERT_TRUE(tx_queue_empty(&queue), "queue empty after clear");
	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.packets_queued, 0, "stats reset after clear");

	return 1;
}

static int test_frame_pool_ownership_lifecycle(void)
{
	struct tx_queue queue;
	uint8_t in_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len = sizeof(out_data);

	memset(in_data, 0xa5, sizeof(in_data));
	tx_queue_test_set_time(1000);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	for (int i = 0; i < TX_QUEUE_SIZE; i++) {
		ASSERT_EQ(tx_queue_push(&queue, in_data, sizeof(in_data),
					TX_PRIORITY_BULK, 60000),
			  0, "each queue entry acquires one buffer");
	}
	ASSERT_EQ(lichen_frame_pool_in_use(&queue.pool), TX_QUEUE_SIZE,
		  "full queue owns exactly four buffers");
	ASSERT_EQ(tx_queue_push(&queue, in_data, sizeof(in_data),
				TX_PRIORITY_BULK, 60000),
		  -ENOBUFS, "rejected packet acquires no buffer");
	ASSERT_EQ(lichen_frame_pool_in_use(&queue.pool), TX_QUEUE_SIZE,
		  "backpressure preserves pool ownership");

	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0,
		  "pop succeeds");
	ASSERT_EQ(lichen_frame_pool_in_use(&queue.pool), TX_QUEUE_SIZE - 1,
		  "pop releases its owned buffer");

	ASSERT_EQ(tx_queue_clear(&queue), 0, "clear succeeds");
	ASSERT_EQ(lichen_frame_pool_in_use(&queue.pool), 0,
		  "clear releases every owned buffer");
	for (int slot = 0; slot < TX_QUEUE_SIZE; slot++) {
		for (size_t byte = 0U; byte < LICHEN_FRAME_BUFFER_SIZE; byte++) {
			ASSERT_EQ(queue.pool.buffers[slot].data[byte], 0U,
				  "clear zeroizes released storage");
		}
	}

	ASSERT_EQ(tx_queue_push(&queue, in_data, 1U, TX_PRIORITY_BULK, 1500U),
		  0, "expiring packet acquires a buffer");
	ASSERT_EQ(lichen_frame_pool_in_use(&queue.pool), 1,
		  "one queued packet owns one buffer");
	tx_queue_test_set_time(1500U);
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), -EAGAIN,
		  "expired packet is not returned");
	ASSERT_EQ(lichen_frame_pool_in_use(&queue.pool), 0,
		  "expiry releases its owned buffer");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds after release");
	return 1;
}

static int test_pop_buffer_too_small(void)
{
	struct tx_queue queue;
	uint8_t in_data[100];
	uint8_t out_data[10];
	uint16_t out_len = sizeof(out_data);

	memset(in_data, 0xAA, sizeof(in_data));
	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	tx_queue_push(&queue, in_data, sizeof(in_data), TX_PRIORITY_BULK, 60000);

	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL),
		  -ENOMEM, "pop returns ENOMEM if buffer too small");

	/* Packet should still be in queue */
	ASSERT_EQ(tx_queue_count(&queue), 1, "packet still in queue after failed pop");

	return 1;
}

static void *tx_queue_reader(void *arg)
{
	struct tx_queue *q = arg;
	for (int i = 0; i < 5000; i++) {
		(void)tx_queue_count(q);
		(void)tx_queue_empty(q);
		struct tx_queue_stats st;
		(void)tx_queue_stats_get(q, &st);
	}
	return NULL;
}

static int test_clock_failure_preserves_queue(void)
{
	struct tx_queue queue;
	uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len = sizeof(out_data);

	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	/* Push a packet */
	ASSERT_EQ(tx_queue_push(&queue, data, sizeof(data),
				TX_PRIORITY_BULK, 60000),
		  0, "push succeeds");
	ASSERT_EQ(tx_queue_count(&queue), 1, "queue has one packet");

	/* Simulate clock failure: push/pop should return -EIO */
	tx_queue_test_fail_time(true);
	ASSERT_EQ(tx_queue_push(&queue, data, sizeof(data),
				TX_PRIORITY_BULK, 60000),
		  -EIO, "push returns EIO on clock failure");
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL),
		  -EIO, "pop returns EIO on clock failure");
	tx_queue_test_fail_time(false);

	/* Original packet should still be intact */
	ASSERT_EQ(tx_queue_count(&queue), 1, "original packet preserved");

	return 1;
}

struct delayed_push_args {
	struct tx_queue *queue;
	int result;
};

struct delayed_pop_args {
	struct tx_queue *queue;
	int result;
	uint8_t data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t len;
};

static void *delayed_expired_push(void *arg)
{
	struct delayed_push_args *args = arg;
	uint8_t data = 0x5a;

	args->result = tx_queue_push(args->queue, &data, 1U, TX_PRIORITY_SOS, 200U);
	return NULL;
}

static void *delayed_expired_pop(void *arg)
{
	struct delayed_pop_args *args = arg;

	args->result = tx_queue_pop(args->queue, args->data, &args->len, NULL);
	return NULL;
}

static int test_push_samples_time_after_lock_acquisition(void)
{
	struct tx_queue queue;
	struct delayed_push_args args = {.queue = &queue, .result = 0};
	pthread_t thread;

	tx_queue_test_set_time(100U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_EQ(pthread_mutex_lock(&queue.lock), 0, "test holds queue lock");
	ASSERT_EQ(pthread_create(&thread, NULL, delayed_expired_push, &args), 0,
		  "delayed push thread starts");
	tx_queue_test_set_time(300U);
	ASSERT_EQ(pthread_mutex_unlock(&queue.lock), 0, "test releases queue lock");
	ASSERT_EQ(pthread_join(thread, NULL), 0, "delayed push thread joins");
	ASSERT_EQ(args.result, -EINVAL,
		  "deadline that passed while blocked is rejected");
	ASSERT_EQ(tx_queue_count(&queue), 0, "stale incoming packet was not admitted");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");
	return 1;
}

static int test_pop_samples_time_after_lock_acquisition(void)
{
	struct tx_queue queue;
	uint8_t data = 0x5a;
	struct delayed_pop_args args = {
		.queue = &queue,
		.result = 0,
		.len = TX_QUEUE_MAX_PACKET_SIZE,
	};
	struct tx_queue_stats stats;
	pthread_t thread;

	tx_queue_test_set_time(100U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL, 200U),
		  0, "packet is queued before deadline");
	ASSERT_EQ(pthread_mutex_lock(&queue.lock), 0, "test holds queue lock");
	ASSERT_EQ(pthread_create(&thread, NULL, delayed_expired_pop, &args), 0,
		  "delayed pop thread starts");
	tx_queue_test_set_time(300U);
	ASSERT_EQ(pthread_mutex_unlock(&queue.lock), 0, "test releases queue lock");
	ASSERT_EQ(pthread_join(thread, NULL), 0, "delayed pop thread joins");
	ASSERT_EQ(args.result, -EAGAIN,
		  "packet that expired while blocked is not transmitted");
	ASSERT_EQ(tx_queue_stats_get(&queue, &stats), 0, "stats read succeeds");
	ASSERT_EQ(stats.packets_dropped_deadline, 1,
		  "blocked pop records deadline expiry");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");
	return 1;
}

static int test_terminal_queue_rejects_operations(void)
{
	struct tx_queue queue;
	uint8_t data = 1U;
	uint8_t out[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len = sizeof(out);
	struct tx_queue_stats stats;

	tx_queue_test_set_time(100U);
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");
	queue.terminal = true;
	ASSERT_EQ(tx_queue_push(&queue, &data, 1U, TX_PRIORITY_NORMAL, 200U),
		  -EIO, "terminal queue rejects explicit push");
	ASSERT_EQ(tx_queue_push_default_deadline(&queue, &data, 1U,
						  TX_PRIORITY_NORMAL),
		  -EIO, "terminal queue rejects default push");
	ASSERT_EQ(tx_queue_pop(&queue, out, &out_len, NULL), -EIO,
		  "terminal queue rejects pop");
	ASSERT_EQ(tx_queue_count(&queue), -EIO, "terminal queue rejects count");
	ASSERT_TRUE(tx_queue_empty(&queue), "terminal queue reports no usable entries");
	ASSERT_EQ(tx_queue_stats_get(&queue, &stats), -EIO,
		  "terminal queue rejects stats");
	ASSERT_EQ(tx_queue_clear(&queue), -EIO, "terminal queue rejects clear");
	ASSERT_EQ(tx_queue_destroy(&queue), -EIO, "terminal queue rejects destroy retry");
	queue.terminal = false;
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "test cleanup succeeds");
	return 1;
}

static int test_concurrent_thread_safety(void)
{
	struct tx_queue queue;
	ASSERT_EQ(tx_queue_init(&queue), 0, "init succeeds");

	uint8_t d[16] = {0};
	for (int i = 0; i < 4; i++) {
		tx_queue_push_default_deadline(&queue, d, sizeof(d), TX_PRIORITY_BULK);
	}

	pthread_t t;
	int r = pthread_create(&t, NULL, tx_queue_reader, &queue);
	ASSERT_EQ(r, 0, "pthread_create");

	for (int i = 0; i < 1000; i++) {
		uint16_t len = sizeof(d);
		if (tx_queue_pop(&queue, d, &len, NULL) == 0) {
			tx_queue_push_default_deadline(&queue, d, len, TX_PRIORITY_BULK);
		}
	}

	void *res;
	pthread_join(t, &res);

	ASSERT_EQ(tx_queue_count(&queue), 4, "final count consistent");
	ASSERT_EQ(tx_queue_destroy(&queue), 0, "destroy succeeds");

	return 1;
}

#define RUN_TEST(fn) do { \
	printf("  %s...", #fn); \
	tests_run++; \
	if (fn()) { \
		printf(" OK\n"); \
		tests_passed++; \
	} \
} while (0)

int main(void)
{
	printf("LICHEN TX Queue Tests\n");
	printf("=====================\n\n");

	printf("Initialization tests:\n");
	RUN_TEST(test_init_rejects_null);
	RUN_TEST(test_empty_null_returns_true);
	RUN_TEST(test_init_success);

	printf("\nPush validation tests:\n");
	RUN_TEST(test_push_rejects_null_queue);
	RUN_TEST(test_push_rejects_null_data);
	RUN_TEST(test_push_rejects_zero_len);
	RUN_TEST(test_push_rejects_oversized);
	RUN_TEST(test_push_rejects_invalid_priority_without_mutation);
	RUN_TEST(test_shared_vector_constants);
	RUN_TEST(test_push_validates_absolute_deadline_range);
	RUN_TEST(test_invalid_incoming_deadline_expires_stale_first);

	printf("\nBasic push/pop tests:\n");
	RUN_TEST(test_push_and_pop_single);
	RUN_TEST(test_pop_empty_returns_eagain);
	RUN_TEST(test_pop_buffer_too_small);
	RUN_TEST(test_clock_failure_preserves_queue);
	RUN_TEST(test_push_samples_time_after_lock_acquisition);
	RUN_TEST(test_pop_samples_time_after_lock_acquisition);
	RUN_TEST(test_terminal_queue_rejects_operations);

	printf("\nBackpressure tests:\n");
	RUN_TEST(test_queue_full_returns_enobufs);

	printf("\nPriority tests:\n");
	RUN_TEST(test_priority_preemption);
	RUN_TEST(test_priority_order);
	RUN_TEST(test_same_priority_fifo_survives_slot_reuse);
	RUN_TEST(test_same_priority_fifo_survives_sequence_wrap);
	RUN_TEST(test_preemption_order_survives_uint32_half_range_gap);
	RUN_TEST(test_preemption_evicts_oldest_same_lowest_priority);

	printf("\nDeadline tests:\n");
	RUN_TEST(test_deadline_expiry_on_push);
	RUN_TEST(test_deadline_expiry_on_pop);
	RUN_TEST(test_stale_deadline_not_resurrected_after_half_range);
	RUN_TEST(test_default_deadlines);
	RUN_TEST(test_shared_vector_expiry_boundary);

	printf("\nStatistics and misc tests:\n");
	RUN_TEST(test_stats_tracking);
	RUN_TEST(test_latency_tracking);
	RUN_TEST(test_latency_max_and_reset);
	RUN_TEST(test_clear);
	RUN_TEST(test_clear_release_failure_is_retryable);
	RUN_TEST(test_frame_pool_ownership_lifecycle);

	printf("\nConcurrency/TSAN tests:\n");
	RUN_TEST(test_concurrent_thread_safety);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	tx_queue_test_use_real_time();
	tx_queue_test_fail_time(false);

	return (tests_passed == tests_run) ? 0 : 1;
}
