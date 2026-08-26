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
 * The volatile pointer forces each store to execute. The compiler_barrier()
 * prevents LTO removal and ensures ordering relative to subsequent code.
 */
static inline void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = ptr;
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
 * @return 0 on success, -EINVAL if output is NULL or input is NULL with inlen > 0,
 *         -EIO if SHA-256 init fails, -EMSGSIZE if SHA-256 update fails,
 *         -EBADMSG if SHA-256 final fails
 */
int lichen_sha256(const uint8_t *input, size_t inlen,
                  uint8_t output[TC_SHA256_DIGEST_SIZE]);

/**
 * @brief Convert LICHEN link error code to human-readable string.
 *
 * Returns a brief description for debugging. Used by L2 layer to produce
 * meaningful log messages instead of raw error numbers.
 *
 * Covered error codes:
 *   POSIX: EACCES, EINVAL, ENOMEM, EMSGSIZE, EOVERFLOW, EALREADY, EIO, ENODEV,
 *          ENETDOWN, EBUSY, EAGAIN, ECANCELED, ENODATA, ENOENT, ENOSPC,
 *          ENOTSUP, ESRCH, ENOBUFS
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
#ifdef EACCES
    case -EACCES:
        return "permission denied";
#endif
#ifdef ENOSPC
    case -ENOSPC:
        return "buffer full or peer table inconsistent";
#endif
#ifdef ENOTSUP
    case -ENOTSUP:
        return "operation not supported";
#endif
#ifdef ENOENT
    case -ENOENT:
        return "peer not found";
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

#endif /* LICHEN_UTIL_H */
