/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_util.h
 * @brief LICHEN shared utility functions
 */

#ifndef LICHEN_UTIL_H
#define LICHEN_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <zephyr/toolchain.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/printk.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>

BUILD_ASSERT((sizeof(unsigned long) & (sizeof(unsigned long) - 1)) == 0,
	     "secure_zero alignment mask requires power-of-two unsigned long size");

/*
 * LICHEN-specific error codes (only when link layer is available).
 * Uses defined() rather than IS_ENABLED() to work in host-side tests
 * where Zephyr's util.h may not be available.
 *
 * Build configuration:
 *   - CONFIG_LICHEN_LINK: Enables <lichen/errno.h> which defines LICHEN_EAUTH.
 *     Without this, only standard POSIX error codes are available.
 *   - LICHEN_EAUTH (200): Authentication/signature verification failed.
 *     Only meaningful for builds with link-layer security (Schnorr-48).
 *
 * When LICHEN_LINK is disabled (e.g., LoRa L2 driver without full link
 * security), authentication errors cannot occur, so the code is excluded.
 */
#if defined(CONFIG_LICHEN_LINK)
#include <lichen/errno.h>
#define HAVE_LICHEN_ERRNO 1
#endif

/*
 * SECURITY: Secure memset that won't be optimized away.
 * Standard memset() on dead buffers can be removed by the compiler.
 * The volatile pointer forces each store to actually execute.
 * The memory barrier prevents LTO removal and ensures ordering.
 *
 * Performance: Uses word-aligned writes for larger buffers (>= 32 bytes)
 * to reduce latency when clearing structures like lichen_link_ctx (~100 bytes)
 * while holding mutexes. (project-LICHEN-gy7h.18)
 *
 * Implementation: Uses memcpy to write zero words, avoiding strict aliasing
 * violations. memcpy is allowed to alias any type, and the volatile read-back
 * prevents the compiler from optimizing away the stores.
 */
static inline void secure_zero(void *ptr, size_t len)
{
    /* SECURITY: Explicit NULL check with warning - never silently ignore NULL.
     * This catches caller bugs even in release builds where __ASSERT is disabled. */
    __ASSERT(ptr != NULL, "secure_zero called with NULL pointer");
    if (ptr == NULL) {
        printk("WARN: secure_zero called with NULL pointer\n");
        return;
    }
    if (len == 0) return;
    volatile uint8_t *p = ptr;

    /* For larger buffers, use word-aligned writes.
     *
     * SECURITY: Word-sized writes go through a volatile unsigned long pointer,
     * ensuring the compiler cannot optimize away any stores. The volatile
     * qualifier applies to the full word write - no separate readback needed.
     *
     * The cast through uintptr_t (line 84) is safe because:
     *   1. p is already word-aligned at this point (alignment loop above)
     *   2. Writing zeros through any pointer type is well-defined
     *   3. The volatile qualifier is preserved on the target pointer
     *
     * No explicit read-back verification (project-LICHEN-tvfm.94):
     * The volatile qualifier on both word and byte writes is the security
     * mechanism - it forces the stores to execute. Read-back would be belt-
     * and-suspenders paranoia but adds code complexity and provides no
     * additional protection beyond what volatile already guarantees. The
     * compiler_barrier() at function end prevents LTO from removing any
     * stores and ensures ordering relative to subsequent code.
     */
    if (len >= 32) {
        /* Align to word boundary first using byte writes */
        while (len > 0 && ((uintptr_t)p & (sizeof(unsigned long) - 1)) != 0) {
            *p++ = 0;
            len--;
        }
        /* Word-sized writes for the bulk (p is now word-aligned).
         * Cast through uintptr_t to get word-aligned volatile pointer. */
        volatile unsigned long *wp = (volatile unsigned long *)(uintptr_t)p;
        while (len >= sizeof(unsigned long)) {
            *wp++ = 0;
            len -= sizeof(unsigned long);
        }
        /* Update byte pointer for remainder */
        p = (volatile uint8_t *)wp;
    }

    /* Byte cleanup for remainder (or small buffers) */
    while (len--) {
        *p++ = 0;
    }
    compiler_barrier();
}

/**
 * @brief Compute SHA-256 hash with secure cleanup
 *
 * SECURITY: The output buffer MUST be at least TC_SHA256_DIGEST_SIZE (32) bytes.
 * The array parameter syntax provides no compile-time bounds checking - it decays
 * to a pointer. Passing a smaller buffer causes undefined behavior (buffer overflow).
 * Callers should declare: uint8_t hash[TC_SHA256_DIGEST_SIZE];
 *
 * @param input Input data (may be NULL if inlen is 0)
 * @param inlen Input length in bytes
 * @param output Output buffer, must be >= 32 bytes (not bounds-checked at runtime)
 * @return 0 on success, -EINVAL if output is NULL or input is NULL with inlen > 0
 */
int lichen_sha256(const uint8_t *input, size_t inlen,
                  uint8_t output[TC_SHA256_DIGEST_SIZE]);
uint32_t lichen_hash_32(const uint8_t *data, size_t len);

/**
 * @brief Convert LICHEN link error code to human-readable string.
 *
 * Returns a brief description for debugging. Used by L2 layer to produce
 * meaningful log messages instead of raw error numbers.
 *
 * Covered error codes:
 *   POSIX: EINVAL, ENOMEM, EMSGSIZE, EOVERFLOW, EALREADY, EIO, ENODEV,
 *          ENETDOWN, EBUSY, EAGAIN, ECANCELED, ENODATA, ESRCH, ENOBUFS
 *   LICHEN: LICHEN_EAUTH
 *
 * @param err Negative error code from lichen_link_tx/rx
 * @return Human-readable string (never NULL)
 */
static inline const char *lichen_link_strerror(int err)
{
    if (err >= 0) {
        return "success";
    }

    switch (err) {
    case -EINVAL:
        return "invalid argument";
    case -ENOMEM:
        return "buffer too small";
    case -EMSGSIZE:
        return "frame too large";
#ifdef EOVERFLOW
    case -EOVERFLOW:
        return "nonce exhausted";
#endif
#ifdef EALREADY
    case -EALREADY:
        return "replay detected";
#endif
#ifdef EIO
    case -EIO:
        return "I/O error";
#endif
#ifdef ENODEV
    case -ENODEV:
        return "no device";
#endif
#ifdef ENETDOWN
    case -ENETDOWN:
        return "network down";
#endif
#ifdef EBUSY
    case -EBUSY:
        return "device busy";
#endif
#ifdef EAGAIN
    case -EAGAIN:
        return "try again";
#endif
#ifdef ECANCELED
    case -ECANCELED:
        return "operation canceled";
#endif
#ifdef ENODATA
    case -ENODATA:
        return "no data available";
#endif
#ifdef ESRCH
    case -ESRCH:
        return "no such process";
#endif
#ifdef ENOBUFS
    case -ENOBUFS:
        return "no buffer space";
#endif
/* LICHEN_EAUTH only exists when CONFIG_LICHEN_LINK is enabled (see top of file) */
#if HAVE_LICHEN_ERRNO
    case -LICHEN_EAUTH:
        return "authentication failed";
#endif
    default:
        return "unknown error";
    }
}

int lichen_iid_to_human_address(const uint8_t *iid, char *buf, size_t buflen);

#endif /* LICHEN_UTIL_H */
