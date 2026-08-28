/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/frame_pool.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_passed;

#define ASSERT_EQ(actual, expected, message) do { \
	long long got_ = (long long)(actual); \
	long long expected_ = (long long)(expected); \
	if (got_ != expected_) { \
		printf("  FAIL: %s (got %lld, expected %lld)\n", \
		       message, got_, expected_); \
		return 0; \
	} \
} while (0)

#define ASSERT_TRUE(condition, message) do { \
	if (!(condition)) { \
		printf("  FAIL: %s\n", message); \
		return 0; \
	} \
} while (0)

static int test_argument_validation(void)
{
	struct lichen_frame_pool pool;
	struct lichen_frame_handle handle = {0};
	uint8_t *data = NULL;
	size_t capacity = 0U;

	ASSERT_EQ(lichen_frame_pool_init(NULL), -EINVAL, "init rejects NULL");
	ASSERT_EQ(lichen_frame_pool_init(&pool), 0, "init succeeds");
	ASSERT_EQ(lichen_frame_pool_acquire(NULL, &handle, &data, &capacity),
		  -EINVAL, "acquire rejects NULL pool");
	ASSERT_EQ(lichen_frame_pool_acquire(&pool, NULL, &data, &capacity),
		  -EINVAL, "acquire rejects NULL handle");
	ASSERT_EQ(lichen_frame_pool_acquire(&pool, &handle, NULL, &capacity),
		  -EINVAL, "acquire rejects NULL data");
	ASSERT_EQ(lichen_frame_pool_get(&pool, handle, &data, &capacity),
		  -EINVAL, "get rejects malformed handle");
	ASSERT_EQ(lichen_frame_pool_release(&pool, handle), -EINVAL,
		  "release rejects malformed handle");
	ASSERT_EQ(lichen_frame_pool_in_use(NULL), -EINVAL,
		  "in_use rejects NULL");
	ASSERT_EQ(lichen_frame_pool_destroy(NULL), -EINVAL,
		  "destroy rejects NULL");
	ASSERT_EQ(lichen_frame_pool_destroy(&pool), 0, "destroy succeeds");
	return 1;
}

static int test_bounded_capacity_and_busy_destroy(void)
{
	struct lichen_frame_pool pool;
	struct lichen_frame_handle handles[LICHEN_FRAME_POOL_CAPACITY];
	uint8_t *buffers[LICHEN_FRAME_POOL_CAPACITY];
	size_t capacity;

	ASSERT_EQ(lichen_frame_pool_init(&pool), 0, "init succeeds");
	for (size_t i = 0U; i < LICHEN_FRAME_POOL_CAPACITY; i++) {
		capacity = 0U;
		ASSERT_EQ(lichen_frame_pool_acquire(&pool, &handles[i],
						    &buffers[i], &capacity),
			  0, "acquire succeeds within capacity");
		ASSERT_EQ(handles[i].slot, i, "slots are uniquely allocated");
		ASSERT_TRUE(buffers[i] != NULL, "buffer pointer returned");
		ASSERT_EQ(capacity, LICHEN_FRAME_BUFFER_SIZE,
			  "buffer has fixed capacity");
	}
	ASSERT_EQ(lichen_frame_pool_in_use(&pool),
		  LICHEN_FRAME_POOL_CAPACITY, "pool reports full ownership");

	struct lichen_frame_handle unchanged = {
		.generation = UINT32_C(0x12345678),
		.slot = 42U,
	};
	uint8_t sentinel = 0U;
	uint8_t *unchanged_data = &sentinel;
	size_t unchanged_capacity = 17U;
	ASSERT_EQ(lichen_frame_pool_acquire(&pool, &unchanged, &unchanged_data,
					    &unchanged_capacity),
		  -ENOBUFS, "fifth acquire returns explicit backpressure");
	ASSERT_EQ(unchanged.generation, UINT32_C(0x12345678),
		  "failed acquire preserves handle");
	ASSERT_EQ(unchanged.slot, 42U, "failed acquire preserves slot");
	ASSERT_TRUE(unchanged_data == &sentinel,
		    "failed acquire preserves data output");
	ASSERT_EQ(unchanged_capacity, 17U,
		  "failed acquire preserves capacity output");
	ASSERT_EQ(lichen_frame_pool_destroy(&pool), -EBUSY,
		  "destroy refuses outstanding ownership");

	for (size_t i = 0U; i < LICHEN_FRAME_POOL_CAPACITY; i++) {
		ASSERT_EQ(lichen_frame_pool_release(&pool, handles[i]), 0,
			  "release succeeds");
	}
	ASSERT_EQ(lichen_frame_pool_in_use(&pool), 0, "all buffers released");
	ASSERT_EQ(lichen_frame_pool_destroy(&pool), 0, "destroy succeeds");
	return 1;
}

static int test_generation_and_zeroization(void)
{
	struct lichen_frame_pool pool;
	struct lichen_frame_handle first;
	struct lichen_frame_handle second;
	uint8_t *data;
	size_t capacity;

	ASSERT_EQ(lichen_frame_pool_init(&pool), 0, "init succeeds");
	ASSERT_EQ(lichen_frame_pool_acquire(&pool, &first, &data, &capacity), 0,
		  "first acquire succeeds");
	memset(data, 0xa5, capacity);
	ASSERT_EQ(lichen_frame_pool_release(&pool, first), 0,
		  "first release succeeds");
	for (size_t i = 0U; i < LICHEN_FRAME_BUFFER_SIZE; i++) {
		ASSERT_EQ(pool.buffers[first.slot].data[i], 0U,
			  "released storage is zeroized");
	}
	ASSERT_EQ(lichen_frame_pool_release(&pool, first), -EALREADY,
		  "double release fails closed");

	ASSERT_EQ(lichen_frame_pool_acquire(&pool, &second, &data, &capacity), 0,
		  "reacquire succeeds");
	ASSERT_EQ(second.slot, first.slot, "released slot is reused");
	ASSERT_TRUE(second.generation != first.generation,
		    "reused slot receives new generation");
	uint8_t sentinel = 0U;
	uint8_t *unchanged_data = &sentinel;
	size_t unchanged_capacity = 23U;
	ASSERT_EQ(lichen_frame_pool_get(&pool, first, &unchanged_data,
					&unchanged_capacity),
		  -ESTALE, "stale handle cannot access reused storage");
	ASSERT_TRUE(unchanged_data == &sentinel,
		    "failed get preserves data output");
	ASSERT_EQ(unchanged_capacity, 23U,
		  "failed get preserves capacity output");
	ASSERT_EQ(lichen_frame_pool_release(&pool, second), 0,
		  "current owner releases storage");
	ASSERT_EQ(lichen_frame_pool_destroy(&pool), 0, "destroy succeeds");
	return 1;
}

static int test_generation_wrap_skips_invalid_zero(void)
{
	struct lichen_frame_pool pool;
	struct lichen_frame_handle before_wrap;
	struct lichen_frame_handle after_wrap;
	uint8_t *data;
	size_t capacity;

	ASSERT_EQ(lichen_frame_pool_init(&pool), 0, "init succeeds");
	pool.next_generation = UINT32_MAX - 1U;
	ASSERT_EQ(lichen_frame_pool_acquire(&pool, &before_wrap, &data, &capacity),
		  0, "acquire at generation boundary succeeds");
	ASSERT_EQ(before_wrap.generation, UINT32_MAX,
		  "last nonzero generation is usable");
	ASSERT_EQ(lichen_frame_pool_release(&pool, before_wrap), 0,
		  "release before wrap succeeds");
	ASSERT_EQ(lichen_frame_pool_acquire(&pool, &after_wrap, &data, &capacity),
		  0, "acquire after generation wrap succeeds");
	ASSERT_EQ(after_wrap.generation, 1U, "generation zero is skipped");
	ASSERT_EQ(lichen_frame_pool_release(&pool, after_wrap), 0,
		  "release after wrap succeeds");
	ASSERT_EQ(lichen_frame_pool_destroy(&pool), 0, "destroy succeeds");
	return 1;
}

struct worker_context {
	struct lichen_frame_pool *pool;
	atomic_bool *failed;
};

static void *pool_worker(void *arg)
{
	struct worker_context *context = arg;

	for (size_t iteration = 0U; iteration < 1000U; iteration++) {
		struct lichen_frame_handle handle;
		uint8_t *data;
		size_t capacity;
		int ret;

		do {
			ret = lichen_frame_pool_acquire(context->pool, &handle,
							&data, &capacity);
			if (ret == -ENOBUFS) {
				sched_yield();
			}
		} while (ret == -ENOBUFS);
		if (ret != 0 || capacity != LICHEN_FRAME_BUFFER_SIZE) {
			atomic_store(context->failed, true);
			return NULL;
		}
		memset(data, (int)(iteration & 0xffU), capacity);
		if (lichen_frame_pool_release(context->pool, handle) != 0) {
			atomic_store(context->failed, true);
			return NULL;
		}
	}
	return NULL;
}

static int test_concurrent_acquire_release(void)
{
	struct lichen_frame_pool pool;
	pthread_t threads[8];
	atomic_bool failed = false;
	struct worker_context context = {
		.pool = &pool,
		.failed = &failed,
	};

	ASSERT_EQ(lichen_frame_pool_init(&pool), 0, "init succeeds");
	for (size_t i = 0U; i < 8U; i++) {
		ASSERT_EQ(pthread_create(&threads[i], NULL, pool_worker, &context),
			  0, "worker starts");
	}
	for (size_t i = 0U; i < 8U; i++) {
		ASSERT_EQ(pthread_join(threads[i], NULL), 0, "worker joins");
	}
	ASSERT_TRUE(!atomic_load(&failed), "concurrent ownership remains valid");
	ASSERT_EQ(lichen_frame_pool_in_use(&pool), 0,
		  "concurrent workers release every buffer");
	ASSERT_EQ(lichen_frame_pool_destroy(&pool), 0, "destroy succeeds");
	return 1;
}

#define RUN_TEST(function) do { \
	printf("  %s...", #function); \
	tests_run++; \
	if (function()) { \
		printf(" OK\n"); \
		tests_passed++; \
	} \
} while (0)

int main(void)
{
	printf("LICHEN Frame Pool Tests\n");
	printf("=======================\n\n");

	RUN_TEST(test_argument_validation);
	RUN_TEST(test_bounded_capacity_and_busy_destroy);
	RUN_TEST(test_generation_and_zeroization);
	RUN_TEST(test_generation_wrap_skips_invalid_zero);
	RUN_TEST(test_concurrent_acquire_release);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
