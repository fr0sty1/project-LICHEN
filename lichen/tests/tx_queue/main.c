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
	uint8_t data0[1] = {0};
	uint8_t data1[1] = {1};
	uint8_t data2[1] = {2};
	uint8_t data3[1] = {3};
	uint8_t out_data[TX_QUEUE_MAX_PACKET_SIZE];
	uint16_t out_len;

	tx_queue_test_set_time(1000);
	tx_queue_init(&queue);

	/* Push in reverse priority order */
	ASSERT_EQ(tx_queue_push(&queue, data3, 1, TX_PRIORITY_BULK, 60000), 0, "push bulk");
	ASSERT_EQ(tx_queue_push(&queue, data2, 1, TX_PRIORITY_URGENT, 60000), 0, "push urgent");
	ASSERT_EQ(tx_queue_push(&queue, data1, 1, TX_PRIORITY_ACK, 60000), 0, "push ack");
	ASSERT_EQ(tx_queue_push(&queue, data0, 1, TX_PRIORITY_ROUTING, 60000), 0, "push routing");

	/* Pop should return in priority order: routing, ack, urgent, bulk */
	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop 1");
	ASSERT_EQ(out_data[0], 0, "first pop is routing (priority 0)");

	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop 2");
	ASSERT_EQ(out_data[0], 1, "second pop is ack (priority 1)");

	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop 3");
	ASSERT_EQ(out_data[0], 2, "third pop is urgent (priority 2)");

	out_len = sizeof(out_data);
	ASSERT_EQ(tx_queue_pop(&queue, out_data, &out_len, NULL), 0, "pop 4");
	ASSERT_EQ(out_data[0], 3, "fourth pop is bulk (priority 3)");

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

static int test_default_deadlines(void)
{
	struct tx_queue queue;
	uint8_t data[4] = {1, 2, 3, 4};

	tx_queue_test_set_time(0);
	tx_queue_init(&queue);

	/* Push with default deadline - routing (5s) */
	ASSERT_EQ(tx_queue_push_default_deadline(&queue, data, sizeof(data),
						  TX_PRIORITY_ROUTING),
		  0, "routing push succeeds");

	/* Verify it expires after 5s but not before */
	tx_queue_test_set_time(4999);
	ASSERT_EQ(tx_queue_count(&queue), 1, "routing packet valid before 5s");

	tx_queue_test_set_time(5001);
	/* Push another packet to trigger expiry */
	ASSERT_EQ(tx_queue_push_default_deadline(&queue, data, sizeof(data),
						  TX_PRIORITY_BULK),
		  0, "bulk push succeeds");

	/* Should now have 1 packet (bulk) - routing expired */
	struct tx_queue_stats stats;
	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.packets_dropped_deadline, 1, "routing packet expired");

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
	tx_queue_clear(&queue);

	ASSERT_TRUE(tx_queue_empty(&queue), "queue empty after clear");
	tx_queue_stats_get(&queue, &stats);
	ASSERT_EQ(stats.packets_queued, 0, "stats reset after clear");

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
	RUN_TEST(test_init_success);

	printf("\nPush validation tests:\n");
	RUN_TEST(test_push_rejects_null_queue);
	RUN_TEST(test_push_rejects_null_data);
	RUN_TEST(test_push_rejects_zero_len);
	RUN_TEST(test_push_rejects_oversized);

	printf("\nBasic push/pop tests:\n");
	RUN_TEST(test_push_and_pop_single);
	RUN_TEST(test_pop_empty_returns_eagain);
	RUN_TEST(test_pop_buffer_too_small);
	RUN_TEST(test_clock_failure_preserves_queue);

	printf("\nBackpressure tests:\n");
	RUN_TEST(test_queue_full_returns_enobufs);

	printf("\nPriority tests:\n");
	RUN_TEST(test_priority_preemption);
	RUN_TEST(test_priority_order);

	printf("\nDeadline tests:\n");
	RUN_TEST(test_deadline_expiry_on_push);
	RUN_TEST(test_deadline_expiry_on_pop);
	RUN_TEST(test_default_deadlines);

	printf("\nStatistics and misc tests:\n");
	RUN_TEST(test_stats_tracking);
	RUN_TEST(test_clear);

	printf("\nConcurrency/TSAN tests:\n");
	RUN_TEST(test_concurrent_thread_safety);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);

	tx_queue_test_use_real_time();
	tx_queue_test_fail_time(false);

	return (tests_passed == tests_run) ? 0 : 1;
}
