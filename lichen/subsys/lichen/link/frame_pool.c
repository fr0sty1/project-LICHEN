/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/frame_pool.h>

#include <errno.h>
#include <string.h>

static void pool_lock(struct lichen_frame_pool *pool)
{
#ifdef __ZEPHYR__
	k_mutex_lock(&pool->lock, K_FOREVER);
#else
	(void)pthread_mutex_lock(&pool->lock);
#endif
}

static void pool_unlock(struct lichen_frame_pool *pool)
{
#ifdef __ZEPHYR__
	k_mutex_unlock(&pool->lock);
#else
	(void)pthread_mutex_unlock(&pool->lock);
#endif
}

static void zero_buffer(uint8_t *data, size_t len)
{
	volatile uint8_t *p = data;

	while (len-- > 0U) {
		*p++ = 0U;
	}
}

static int validate_handle_locked(struct lichen_frame_pool *pool,
				  struct lichen_frame_handle handle,
				  struct lichen_frame_buffer **buffer)
{
	if (handle.slot >= LICHEN_FRAME_POOL_CAPACITY || handle.generation == 0U) {
		return -EINVAL;
	}
	struct lichen_frame_buffer *candidate = &pool->buffers[handle.slot];

	if (!candidate->in_use) {
		return -EALREADY;
	}
	if (candidate->generation != handle.generation) {
		return -ESTALE;
	}
	*buffer = candidate;
	return 0;
}

int lichen_frame_pool_init(struct lichen_frame_pool *pool)
{
	if (pool == NULL) {
		return -EINVAL;
	}
	memset(pool, 0, sizeof(*pool));
#ifdef __ZEPHYR__
	k_mutex_init(&pool->lock);
#else
	int ret = pthread_mutex_init(&pool->lock, NULL);
	if (ret != 0) {
		return -ret;
	}
#endif
	return 0;
}

int lichen_frame_pool_acquire(struct lichen_frame_pool *pool,
			      struct lichen_frame_handle *handle,
			      uint8_t **data, size_t *capacity)
{
	if (pool == NULL || handle == NULL || data == NULL || capacity == NULL) {
		return -EINVAL;
	}
	pool_lock(pool);
	for (uint8_t slot = 0U; slot < LICHEN_FRAME_POOL_CAPACITY; slot++) {
		struct lichen_frame_buffer *buffer = &pool->buffers[slot];

		if (buffer->in_use) {
			continue;
		}
		pool->next_generation++;
		if (pool->next_generation == 0U) {
			pool->next_generation++;
		}
		buffer->generation = pool->next_generation;
		buffer->in_use = true;
		*handle = (struct lichen_frame_handle) {
			.generation = buffer->generation,
			.slot = slot,
		};
		*data = buffer->data;
		*capacity = sizeof(buffer->data);
		pool_unlock(pool);
		return 0;
	}
	pool_unlock(pool);
	return -ENOBUFS;
}

int lichen_frame_pool_get(struct lichen_frame_pool *pool,
			  struct lichen_frame_handle handle,
			  uint8_t **data, size_t *capacity)
{
	struct lichen_frame_buffer *buffer;

	if (pool == NULL || data == NULL || capacity == NULL) {
		return -EINVAL;
	}
	pool_lock(pool);
	int ret = validate_handle_locked(pool, handle, &buffer);
	if (ret == 0) {
		*data = buffer->data;
		*capacity = sizeof(buffer->data);
	}
	pool_unlock(pool);
	return ret;
}

int lichen_frame_pool_release(struct lichen_frame_pool *pool,
			      struct lichen_frame_handle handle)
{
	struct lichen_frame_buffer *buffer;

	if (pool == NULL) {
		return -EINVAL;
	}
	pool_lock(pool);
	int ret = validate_handle_locked(pool, handle, &buffer);
	if (ret == 0) {
		zero_buffer(buffer->data, sizeof(buffer->data));
		buffer->in_use = false;
	}
	pool_unlock(pool);
	return ret;
}

int lichen_frame_pool_in_use(struct lichen_frame_pool *pool)
{
	if (pool == NULL) {
		return -EINVAL;
	}
	pool_lock(pool);
	int count = 0;
	for (size_t i = 0U; i < LICHEN_FRAME_POOL_CAPACITY; i++) {
		if (pool->buffers[i].in_use) {
			count++;
		}
	}
	pool_unlock(pool);
	return count;
}

int lichen_frame_pool_destroy(struct lichen_frame_pool *pool)
{
	if (pool == NULL) {
		return -EINVAL;
	}
	if (lichen_frame_pool_in_use(pool) != 0) {
		return -EBUSY;
	}
#ifdef __ZEPHYR__
	return 0;
#else
	int ret = pthread_mutex_destroy(&pool->lock);
	return ret == 0 ? 0 : -ret;
#endif
}
