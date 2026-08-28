/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rpl_dao_timing.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>

#define DAO_INITIAL_DELAY_OUTCOMES                                             \
  (LICHEN_RPL_DAO_INITIAL_DELAY_MAX_MS - LICHEN_RPL_DAO_INITIAL_DELAY_MIN_MS + \
   1U)

/* 2^32 - (2^32 modulo 2001), calculated in uint64_t without overflowing. */
#define DAO_U32_OUTCOMES (UINT64_C(0xffffffff) + UINT64_C(1))
#define DAO_RANDOM_ACCEPTANCE_LIMIT                                            \
  (DAO_U32_OUTCOMES - (DAO_U32_OUTCOMES % DAO_INITIAL_DELAY_OUTCOMES))

_Static_assert(LICHEN_RPL_DAO_INITIAL_DELAY_MAX_MS <= UINT16_MAX,
               "DAO delay must fit the public uint16_t output");
_Static_assert(LICHEN_RPL_DAO_INITIAL_DELAY_MAX_MS <= INT32_MAX,
               "DAO deadline comparison requires a sub-half-range delay");
_Static_assert(DAO_RANDOM_ACCEPTANCE_LIMIT == UINT64_C(4294966410),
               "DAO rejection boundary must match the cross-language oracle");
_Static_assert(LICHEN_RPL_DAO_RETRY_THIRD_MS <= INT32_MAX,
               "DAO retry deadline requires a sub-half-range delay");
_Static_assert(LICHEN_RPL_DAO_SOFT_STATE_LIFETIME_S == 30U * 60U,
               "DAO route soft-state lifetime must remain 30 minutes");
_Static_assert(LICHEN_RPL_DAO_REFRESH_INTERVAL_S == 15U * 60U,
               "DAO refresh must occur at the 15-minute half-life");
_Static_assert(LICHEN_RPL_DAO_REFRESH_INTERVAL_MS <= INT32_MAX,
               "DAO refresh deadline requires a sub-half-range interval");

static bool dao_deadline_is_due(uint32_t deadline_ms, uint32_t now_ms) {
  /* A due time is at most INT32_MAX ticks in the past.  Express the
   * half-range comparison without implementation-defined unsigned-to-signed
   * conversion so this remains portable across the supported C toolchains. */
  return (now_ms - deadline_ms) <= (uint32_t)INT32_MAX;
}

void lichen_rpl_dao_initial_timer_init(
    struct lichen_rpl_dao_initial_timer *timer) {
  if (timer == NULL) {
    return;
  }
  timer->deadline_ms = 0U;
  timer->armed = false;
}

int lichen_rpl_dao_initial_delay_from_random(uint32_t random_word,
                                             uint16_t *delay_ms) {
  if (delay_ms == NULL) {
    return -EINVAL;
  }
  if ((uint64_t)random_word >= DAO_RANDOM_ACCEPTANCE_LIMIT) {
    return -EAGAIN;
  }

  uint16_t selected =
      (uint16_t)(LICHEN_RPL_DAO_INITIAL_DELAY_MIN_MS +
                 ((uint64_t)random_word % DAO_INITIAL_DELAY_OUTCOMES));
  *delay_ms = selected;
  return 0;
}

int lichen_rpl_dao_initial_timer_start(
    struct lichen_rpl_dao_initial_timer *timer, uint32_t now_ms,
    lichen_rpl_dao_rng_fn rng, void *rng_user, uint16_t *delay_ms) {
  if (timer == NULL || rng == NULL || delay_ms == NULL) {
    return -EINVAL;
  }
  if (timer->armed) {
    return -EALREADY;
  }

  for (uint8_t draw = 0U; draw < LICHEN_RPL_DAO_INITIAL_RNG_MAX_DRAWS; ++draw) {
    uint32_t random_word;
    uint16_t selected;
    int ret = rng(rng_user, &random_word);

    if (ret < 0) {
      return ret;
    }
    if (ret > 0) {
      return -EIO;
    }
    ret = lichen_rpl_dao_initial_delay_from_random(random_word, &selected);
    if (ret == -EAGAIN) {
      continue;
    }
    if (ret < 0) {
      return ret;
    }

    /* Unsigned addition intentionally follows the monotonic uint32_t
     * clock across wrap.  The maximum delay is far below half range. */
    timer->deadline_ms = now_ms + selected;
    timer->armed = true;
    *delay_ms = selected;
    return 0;
  }

  return -EAGAIN;
}

bool lichen_rpl_dao_initial_timer_is_due(
    const struct lichen_rpl_dao_initial_timer *timer, uint32_t now_ms) {
  if (timer == NULL || !timer->armed) {
    return false;
  }

  return dao_deadline_is_due(timer->deadline_ms, now_ms);
}

bool lichen_rpl_dao_initial_timer_take_if_due(
    struct lichen_rpl_dao_initial_timer *timer, uint32_t now_ms) {
  if (!lichen_rpl_dao_initial_timer_is_due(timer, now_ms)) {
    return false;
  }
  timer->armed = false;
  return true;
}

void lichen_rpl_dao_retry_timer_init(struct lichen_rpl_dao_retry_timer *timer) {
  if (timer == NULL) {
    return;
  }
  timer->deadline_ms = 0U;
  timer->attempts = 0U;
  timer->armed = false;
}

int lichen_rpl_dao_retry_delay_ms(uint8_t attempt, uint32_t *delay_ms) {
  uint32_t selected;

  if (delay_ms == NULL) {
    return -EINVAL;
  }

  switch (attempt) {
  case 0U:
    selected = LICHEN_RPL_DAO_RETRY_FIRST_MS;
    break;
  case 1U:
    selected = LICHEN_RPL_DAO_RETRY_SECOND_MS;
    break;
  case 2U:
    selected = LICHEN_RPL_DAO_RETRY_THIRD_MS;
    break;
  default:
    return -ENOENT;
  }

  *delay_ms = selected;
  return 0;
}

bool lichen_rpl_dao_retry_timer_is_exhausted(
    const struct lichen_rpl_dao_retry_timer *timer) {
  return timer != NULL && timer->attempts >= LICHEN_RPL_DAO_RETRY_LIMIT;
}

int lichen_rpl_dao_retry_timer_schedule_next(
    struct lichen_rpl_dao_retry_timer *timer, uint32_t now_ms,
    uint32_t *delay_ms) {
  uint32_t selected;
  int ret;

  if (timer == NULL || delay_ms == NULL) {
    return -EINVAL;
  }
  if (timer->armed) {
    return -EALREADY;
  }
  ret = lichen_rpl_dao_retry_delay_ms(timer->attempts, &selected);
  if (ret < 0) {
    return ret;
  }

  /* Unsigned addition deliberately carries the monotonic clock across wrap.
   * Each profile delay is well below the half-range comparison limit. */
  timer->deadline_ms = now_ms + selected;
  timer->attempts++;
  timer->armed = true;
  *delay_ms = selected;
  return 0;
}

bool lichen_rpl_dao_retry_timer_is_due(
    const struct lichen_rpl_dao_retry_timer *timer, uint32_t now_ms) {
  return timer != NULL && timer->armed &&
         dao_deadline_is_due(timer->deadline_ms, now_ms);
}

bool lichen_rpl_dao_retry_timer_take_if_due(
    struct lichen_rpl_dao_retry_timer *timer, uint32_t now_ms) {
  if (!lichen_rpl_dao_retry_timer_is_due(timer, now_ms)) {
    return false;
  }
  timer->armed = false;
  return true;
}

void lichen_rpl_dao_retry_timer_reset(
    struct lichen_rpl_dao_retry_timer *timer) {
  lichen_rpl_dao_retry_timer_init(timer);
}

void lichen_rpl_dao_refresh_timer_init(
    struct lichen_rpl_dao_refresh_timer *timer) {
  if (timer == NULL) {
    return;
  }
  timer->deadline_ms = 0U;
  timer->armed = false;
}

int lichen_rpl_dao_refresh_timer_start(
    struct lichen_rpl_dao_refresh_timer *timer, uint32_t now_ms) {
  if (timer == NULL) {
    return -EINVAL;
  }
  if (timer->armed) {
    return -EALREADY;
  }

  timer->deadline_ms = now_ms + LICHEN_RPL_DAO_REFRESH_INTERVAL_MS;
  timer->armed = true;
  return 0;
}

int lichen_rpl_dao_refresh_timer_reschedule(
    struct lichen_rpl_dao_refresh_timer *timer, uint32_t now_ms) {
  if (timer == NULL) {
    return -EINVAL;
  }

  /* Anchor periodic refresh to the successful transmission, not the previous
   * deadline.  This prevents an early route update from causing a near-term
   * duplicate refresh while still keeping every route within its half-life. */
  timer->deadline_ms = now_ms + LICHEN_RPL_DAO_REFRESH_INTERVAL_MS;
  timer->armed = true;
  return 0;
}

bool lichen_rpl_dao_refresh_timer_is_due(
    const struct lichen_rpl_dao_refresh_timer *timer, uint32_t now_ms) {
  return timer != NULL && timer->armed &&
         dao_deadline_is_due(timer->deadline_ms, now_ms);
}

bool lichen_rpl_dao_refresh_timer_take_if_due(
    struct lichen_rpl_dao_refresh_timer *timer, uint32_t now_ms) {
  if (!lichen_rpl_dao_refresh_timer_is_due(timer, now_ms)) {
    return false;
  }
  timer->armed = false;
  return true;
}

void lichen_rpl_dao_refresh_timer_reset(
    struct lichen_rpl_dao_refresh_timer *timer) {
  lichen_rpl_dao_refresh_timer_init(timer);
}

#undef DAO_RANDOM_ACCEPTANCE_LIMIT
#undef DAO_U32_OUTCOMES
#undef DAO_INITIAL_DELAY_OUTCOMES
