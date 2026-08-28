/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_RPL_DAO_TIMING_H_
#define LICHEN_RPL_DAO_TIMING_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Inclusive LICHEN profile bounds for the first DAO after joining. */
#define LICHEN_RPL_DAO_INITIAL_DELAY_MIN_MS 0U
#define LICHEN_RPL_DAO_INITIAL_DELAY_MAX_MS 2000U

/**
 * Maximum random draws made by one scheduling attempt.
 *
 * Rejection sampling avoids modulo bias.  Only 886 of the 2^32 possible
 * words are rejected, so exhausting this bound indicates a broken RNG while
 * keeping the caller-driven state machine bounded.
 */
#define LICHEN_RPL_DAO_INITIAL_RNG_MAX_DRAWS 8U

/** Retry profile after an unacknowledged DAO. */
#define LICHEN_RPL_DAO_RETRY_LIMIT 3U
#define LICHEN_RPL_DAO_RETRY_FIRST_MS 4000U
#define LICHEN_RPL_DAO_RETRY_SECOND_MS 8000U
#define LICHEN_RPL_DAO_RETRY_THIRD_MS 16000U

/**
 * Route soft-state and refresh cadence from the current Section 14.2 profile.
 *
 * A route lives for 30 minutes and is refreshed at half-life, every 15
 * minutes.  The older draft text saying "refresh every 30 minutes" is stale.
 */
#define LICHEN_RPL_DAO_SOFT_STATE_LIFETIME_S 1800U
#define LICHEN_RPL_DAO_REFRESH_INTERVAL_S                                      \
  (LICHEN_RPL_DAO_SOFT_STATE_LIFETIME_S / 2U)
#define LICHEN_RPL_DAO_REFRESH_INTERVAL_MS                                     \
  (LICHEN_RPL_DAO_REFRESH_INTERVAL_S * 1000U)

/** Fill @p value with one uniformly distributed 32-bit word. */
typedef int (*lichen_rpl_dao_rng_fn)(void *user, uint32_t *value);

/** Caller-owned, one-shot timer for the first DAO after joining. */
struct lichen_rpl_dao_initial_timer {
  uint32_t deadline_ms;
  bool armed;
};

/** Initialize or reset an inactive timer. */
void lichen_rpl_dao_initial_timer_init(
    struct lichen_rpl_dao_initial_timer *timer);

/**
 * Map one uniformly random word to the inclusive 0..2000 ms profile range.
 *
 * Returns -EAGAIN for the incomplete tail of the uint32_t domain.  The caller
 * must draw a fresh independent word; rejecting that tail avoids modulo bias.
 * The output is unchanged on error.
 */
int lichen_rpl_dao_initial_delay_from_random(uint32_t random_word,
                                             uint16_t *delay_ms);

/**
 * Arm the first-DAO timer relative to caller-supplied monotonic milliseconds.
 *
 * The RNG is injectable for deterministic tests and platform adapters.  Up to
 * LICHEN_RPL_DAO_INITIAL_RNG_MAX_DRAWS words are sampled.  RNG errors and a
 * persistently rejected source fail closed without changing timer or output.
 * An already armed timer returns -EALREADY so a duplicate join notification
 * cannot silently postpone the scheduled DAO.
 */
int lichen_rpl_dao_initial_timer_start(
    struct lichen_rpl_dao_initial_timer *timer, uint32_t now_ms,
    lichen_rpl_dao_rng_fn rng, void *rng_user, uint16_t *delay_ms);

/** Return whether the one-shot timer is armed and due at @p now_ms. */
bool lichen_rpl_dao_initial_timer_is_due(
    const struct lichen_rpl_dao_initial_timer *timer, uint32_t now_ms);

/**
 * Consume a due timer exactly once.
 *
 * Returns true only for the first call at or after the deadline.  This is the
 * transmission gate: callers build/send the initial DAO only when it returns
 * true.
 */
bool lichen_rpl_dao_initial_timer_take_if_due(
    struct lichen_rpl_dao_initial_timer *timer, uint32_t now_ms);

/** Caller-owned state for one logical DAO's bounded retry sequence. */
struct lichen_rpl_dao_retry_timer {
  uint32_t deadline_ms;
  uint8_t attempts;
  bool armed;
};

/** Initialize a fresh retry sequence whose next delay is four seconds. */
void lichen_rpl_dao_retry_timer_init(struct lichen_rpl_dao_retry_timer *timer);

/**
 * Return the delay for a zero-based retry attempt.
 *
 * Attempts 0, 1, and 2 return 4000, 8000, and 16000 milliseconds.  Later
 * attempts return -ENOENT and leave the output unchanged.
 */
int lichen_rpl_dao_retry_delay_ms(uint8_t attempt, uint32_t *delay_ms);

/** Return whether all three retry slots have been consumed. */
bool lichen_rpl_dao_retry_timer_is_exhausted(
    const struct lichen_rpl_dao_retry_timer *timer);

/**
 * Arm the next retry relative to caller-supplied monotonic milliseconds.
 *
 * A successful call consumes one retry slot.  -EALREADY means a retry is
 * already pending and -ENOENT means the three-slot sequence is exhausted.
 * All error paths leave the timer and output unchanged.
 */
int lichen_rpl_dao_retry_timer_schedule_next(
    struct lichen_rpl_dao_retry_timer *timer, uint32_t now_ms,
    uint32_t *delay_ms);

/** Return whether the pending retry is due at @p now_ms. */
bool lichen_rpl_dao_retry_timer_is_due(
    const struct lichen_rpl_dao_retry_timer *timer, uint32_t now_ms);

/** Consume a due retry exactly once without changing the retry count. */
bool lichen_rpl_dao_retry_timer_take_if_due(
    struct lichen_rpl_dao_retry_timer *timer, uint32_t now_ms);

/** Cancel any pending retry and restore a fresh three-slot sequence. */
void lichen_rpl_dao_retry_timer_reset(struct lichen_rpl_dao_retry_timer *timer);

/** Caller-owned timer for refreshing one valid DAO route. */
struct lichen_rpl_dao_refresh_timer {
  uint32_t deadline_ms;
  bool armed;
};

/** Initialize an inactive refresh timer. */
void lichen_rpl_dao_refresh_timer_init(
    struct lichen_rpl_dao_refresh_timer *timer);

/**
 * Start refresh scheduling after a successful logical DAO transmission.
 *
 * The deadline is exactly 15 minutes after @p now_ms.  An already scheduled
 * timer returns -EALREADY and is not postponed.
 */
int lichen_rpl_dao_refresh_timer_start(
    struct lichen_rpl_dao_refresh_timer *timer, uint32_t now_ms);

/**
 * Schedule the next periodic refresh from a successful transmission time.
 *
 * Unlike start, this deliberately replaces an existing schedule so a
 * successful early refresh or route update begins a fresh 15-minute period.
 */
int lichen_rpl_dao_refresh_timer_reschedule(
    struct lichen_rpl_dao_refresh_timer *timer, uint32_t now_ms);

/** Return whether the refresh timer is due at @p now_ms. */
bool lichen_rpl_dao_refresh_timer_is_due(
    const struct lichen_rpl_dao_refresh_timer *timer, uint32_t now_ms);

/** Consume a due refresh exactly once. */
bool lichen_rpl_dao_refresh_timer_take_if_due(
    struct lichen_rpl_dao_refresh_timer *timer, uint32_t now_ms);

/** Cancel refresh scheduling when the route is no longer valid. */
void lichen_rpl_dao_refresh_timer_reset(
    struct lichen_rpl_dao_refresh_timer *timer);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_DAO_TIMING_H_ */
