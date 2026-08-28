/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_FRAME_POOL_H_
#define LICHEN_FRAME_POOL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __ZEPHYR__
#include <zephyr/kernel.h>
#else
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_FRAME_POOL_CAPACITY 4
#define LICHEN_FRAME_BUFFER_SIZE 256U
#define LICHEN_FRAME_POOL_INVALID_SLOT UINT8_MAX

struct lichen_frame_handle {
	uint32_t generation;
	uint8_t slot;
};

struct lichen_frame_buffer {
	uint8_t data[LICHEN_FRAME_BUFFER_SIZE];
	uint32_t generation;
	bool in_use;
};

struct lichen_frame_pool {
	struct lichen_frame_buffer buffers[LICHEN_FRAME_POOL_CAPACITY];
	uint32_t next_generation;
#ifdef __ZEPHYR__
	struct k_mutex lock;
#else
	pthread_mutex_t lock;
#endif
};

/** Initialize an empty fixed-capacity pool. */
int lichen_frame_pool_init(struct lichen_frame_pool *pool);

/**
 * Acquire one exclusively-owned frame buffer.
 *
 * Outputs are changed only on success. Returns -ENOBUFS when all slots are
 * owned. The returned pointer remains valid until the matching handle is
 * released; callers must not retain it afterward.
 */
int lichen_frame_pool_acquire(struct lichen_frame_pool *pool,
			      struct lichen_frame_handle *handle,
			      uint8_t **data, size_t *capacity);

/** Resolve a live handle to its exclusively-owned buffer. */
int lichen_frame_pool_get(struct lichen_frame_pool *pool,
			  struct lichen_frame_handle handle,
			  uint8_t **data, size_t *capacity);

/** Zero and release a live buffer; stale and duplicate releases fail. */
int lichen_frame_pool_release(struct lichen_frame_pool *pool,
			      struct lichen_frame_handle handle);

/** Return a thread-safe snapshot of the number of owned buffers. */
int lichen_frame_pool_in_use(struct lichen_frame_pool *pool);

/** Destroy host synchronization state; fails if a buffer remains owned. */
int lichen_frame_pool_destroy(struct lichen_frame_pool *pool);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_FRAME_POOL_H_ */
