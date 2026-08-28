/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <lichen/rpl_dao_timing.h>

#ifdef CONFIG_ZTEST
#include <zephyr/ztest.h>
#define CHECK(condition, ...) zassert_true(condition, __VA_ARGS__)
#else
#define CHECK(condition, ...)                                                  \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, __VA_ARGS__);                                            \
      fprintf(stderr, "\n");                                                   \
      return false;                                                            \
    }                                                                          \
  } while (0)
#endif

#define ACCEPTANCE_LIMIT UINT32_C(4294966410)

struct scripted_rng {
  const uint32_t *words;
  size_t count;
  size_t next;
  int result;
};

static int scripted_random(void *user, uint32_t *value) {
  struct scripted_rng *rng = user;

  if (rng->result != 0) {
    return rng->result;
  }
  if (rng->next >= rng->count) {
    return -ENODATA;
  }
  *value = rng->words[rng->next++];
  return 0;
}

static bool test_exact_mapping_and_rejection_boundary(void) {
  uint16_t delay = UINT16_MAX;

  for (uint32_t expected = LICHEN_RPL_DAO_INITIAL_DELAY_MIN_MS;
       expected <= LICHEN_RPL_DAO_INITIAL_DELAY_MAX_MS; ++expected) {
    CHECK(lichen_rpl_dao_initial_delay_from_random(expected, &delay) == 0,
          "accepted word %u rejected", expected);
    CHECK(delay == expected, "word %u mapped to %u", expected, delay);
  }
  CHECK(lichen_rpl_dao_initial_delay_from_random(2001U, &delay) == 0 &&
            delay == 0U,
        "range did not repeat at 2001");
  CHECK(lichen_rpl_dao_initial_delay_from_random(ACCEPTANCE_LIMIT - 1U,
                                                 &delay) == 0 &&
            delay == LICHEN_RPL_DAO_INITIAL_DELAY_MAX_MS,
        "last accepted word did not map to upper bound");

  delay = UINT16_C(0x5a5a);
  for (uint64_t rejected = ACCEPTANCE_LIMIT; rejected <= UINT32_MAX;
       ++rejected) {
    CHECK(lichen_rpl_dao_initial_delay_from_random((uint32_t)rejected,
                                                   &delay) == -EAGAIN,
          "tail word %llu accepted", (unsigned long long)rejected);
    CHECK(delay == UINT16_C(0x5a5a), "rejection changed output");
  }
  CHECK(lichen_rpl_dao_initial_delay_from_random(0U, NULL) == -EINVAL,
        "NULL output accepted");
  return true;
}

static bool test_injected_rng_and_fail_closed_bounds(void) {
  const uint32_t words[] = {UINT32_MAX, 2000U};
  struct scripted_rng rng = {.words = words, .count = 2U};
  struct lichen_rpl_dao_initial_timer timer;
  uint16_t delay = UINT16_MAX;

  lichen_rpl_dao_initial_timer_init(&timer);
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 100U, scripted_random, &rng,
                                           &delay) == 0,
        "rejection retry failed");
  CHECK(rng.next == 2U && delay == 2000U && timer.armed &&
            timer.deadline_ms == 2100U,
        "deterministic injected result mismatch");

  const uint32_t rejected[LICHEN_RPL_DAO_INITIAL_RNG_MAX_DRAWS] = {
      UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX,
      UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX,
  };
  rng = (struct scripted_rng){.words = rejected,
                              .count = LICHEN_RPL_DAO_INITIAL_RNG_MAX_DRAWS};
  timer = (struct lichen_rpl_dao_initial_timer){.deadline_ms = 1234U,
                                                .armed = false};
  delay = UINT16_C(0xbeef);
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 55U, scripted_random, &rng,
                                           &delay) == -EAGAIN,
        "bounded rejection exhaustion not reported");
  CHECK(rng.next == LICHEN_RPL_DAO_INITIAL_RNG_MAX_DRAWS && !timer.armed &&
            timer.deadline_ms == 1234U && delay == UINT16_C(0xbeef),
        "rejection exhaustion mutated state");

  rng = (struct scripted_rng){.result = -EIO};
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 0U, scripted_random, &rng,
                                           &delay) == -EIO,
        "negative RNG error not propagated");
  rng.result = 1;
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 0U, scripted_random, &rng,
                                           &delay) == -EIO,
        "positive RNG error not normalized");
  CHECK(lichen_rpl_dao_initial_timer_start(NULL, 0U, scripted_random, &rng,
                                           &delay) == -EINVAL &&
            lichen_rpl_dao_initial_timer_start(&timer, 0U, NULL, NULL,
                                               &delay) == -EINVAL &&
            lichen_rpl_dao_initial_timer_start(&timer, 0U, scripted_random,
                                               &rng, NULL) == -EINVAL,
        "NULL input accepted");
  return true;
}

static bool test_one_shot_deadlines_and_wrap(void) {
  const uint32_t zero[] = {0U};
  struct scripted_rng rng = {.words = zero, .count = 1U};
  struct lichen_rpl_dao_initial_timer timer;
  uint16_t delay;

  lichen_rpl_dao_initial_timer_init(NULL);
  lichen_rpl_dao_initial_timer_init(&timer);
  CHECK(!lichen_rpl_dao_initial_timer_is_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_initial_timer_take_if_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_initial_timer_is_due(NULL, 0U) &&
            !lichen_rpl_dao_initial_timer_take_if_due(NULL, 0U),
        "inactive/NULL timer became due");
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 77U, scripted_random, &rng,
                                           &delay) == 0 &&
            delay == 0U,
        "zero-delay start failed");
  CHECK(lichen_rpl_dao_initial_timer_is_due(&timer, 77U),
        "zero delay not due immediately");
  CHECK(lichen_rpl_dao_initial_timer_take_if_due(&timer, 77U),
        "due timer was not consumed");
  CHECK(!lichen_rpl_dao_initial_timer_take_if_due(&timer, 77U),
        "timer was not one-shot");

  const uint32_t upper[] = {2000U};
  rng = (struct scripted_rng){.words = upper, .count = 1U};
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, UINT32_MAX - 999U,
                                           scripted_random, &rng, &delay) == 0,
        "wrap-crossing start failed");
  CHECK(timer.deadline_ms == 1000U &&
            !lichen_rpl_dao_initial_timer_is_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_initial_timer_is_due(&timer, 999U) &&
            lichen_rpl_dao_initial_timer_is_due(&timer, 1000U),
        "wrap-safe deadline boundary mismatch");
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 0U, scripted_random, &rng,
                                           &delay) == -EALREADY,
        "duplicate arm postponed timer");
  CHECK(lichen_rpl_dao_initial_timer_take_if_due(&timer, 1000U),
        "due wrapped timer not consumed");
  return true;
}

static bool test_retry_profile_and_exhaustion(void) {
  const uint32_t expected[] = {
      LICHEN_RPL_DAO_RETRY_FIRST_MS,
      LICHEN_RPL_DAO_RETRY_SECOND_MS,
      LICHEN_RPL_DAO_RETRY_THIRD_MS,
  };
  struct lichen_rpl_dao_retry_timer timer;
  uint32_t delay = UINT32_C(0x5a5a5a5a);

  CHECK(LICHEN_RPL_DAO_RETRY_LIMIT == 3U, "retry limit drifted");
  for (uint8_t attempt = 0U; attempt < LICHEN_RPL_DAO_RETRY_LIMIT; ++attempt) {
    CHECK(lichen_rpl_dao_retry_delay_ms(attempt, &delay) == 0,
          "retry attempt %u rejected", attempt);
    CHECK(delay == expected[attempt], "retry attempt %u delay mismatch",
          attempt);
  }
  delay = UINT32_C(0x5a5a5a5a);
  CHECK(lichen_rpl_dao_retry_delay_ms(LICHEN_RPL_DAO_RETRY_LIMIT, &delay) ==
                -ENOENT &&
            delay == UINT32_C(0x5a5a5a5a),
        "first exhausted attempt did not fail atomically");
  CHECK(lichen_rpl_dao_retry_delay_ms(UINT8_MAX, &delay) == -ENOENT &&
            delay == UINT32_C(0x5a5a5a5a),
        "large exhausted attempt did not saturate");
  CHECK(lichen_rpl_dao_retry_delay_ms(0U, NULL) == -EINVAL,
        "NULL retry output accepted");

  lichen_rpl_dao_retry_timer_init(NULL);
  lichen_rpl_dao_retry_timer_init(&timer);
  CHECK(!timer.armed && timer.attempts == 0U &&
            !lichen_rpl_dao_retry_timer_is_exhausted(&timer) &&
            !lichen_rpl_dao_retry_timer_is_exhausted(NULL),
        "fresh retry timer state mismatch");

  for (uint8_t attempt = 0U; attempt < LICHEN_RPL_DAO_RETRY_LIMIT; ++attempt) {
    const uint32_t now_ms = 100U + attempt;
    CHECK(lichen_rpl_dao_retry_timer_schedule_next(&timer, now_ms, &delay) == 0,
          "retry attempt %u was not scheduled", attempt);
    CHECK(delay == expected[attempt] && timer.attempts == attempt + 1U &&
              timer.deadline_ms == now_ms + expected[attempt] && timer.armed,
          "retry attempt %u state mismatch", attempt);
    CHECK(lichen_rpl_dao_retry_timer_schedule_next(&timer, UINT32_MAX,
                                                   &delay) == -EALREADY,
          "pending retry was silently postponed");
    CHECK(!lichen_rpl_dao_retry_timer_is_due(&timer, timer.deadline_ms - 1U) &&
              lichen_rpl_dao_retry_timer_is_due(&timer, timer.deadline_ms),
          "retry attempt %u deadline boundary mismatch", attempt);
    CHECK(lichen_rpl_dao_retry_timer_take_if_due(&timer, timer.deadline_ms),
          "retry attempt %u was not consumed", attempt);
    CHECK(!lichen_rpl_dao_retry_timer_take_if_due(&timer, timer.deadline_ms),
          "retry attempt %u was consumed twice", attempt);
  }

  CHECK(lichen_rpl_dao_retry_timer_is_exhausted(&timer),
        "three scheduled retries did not exhaust budget");
  delay = UINT32_C(0xa5a5a5a5);
  CHECK(lichen_rpl_dao_retry_timer_schedule_next(&timer, 0U, &delay) ==
                -ENOENT &&
            timer.attempts == LICHEN_RPL_DAO_RETRY_LIMIT && !timer.armed &&
            delay == UINT32_C(0xa5a5a5a5),
        "exhaustion did not remain saturated and atomic");
  CHECK(lichen_rpl_dao_retry_timer_schedule_next(&timer, 0U, &delay) ==
                -ENOENT &&
            timer.attempts == LICHEN_RPL_DAO_RETRY_LIMIT,
        "repeated exhaustion wrapped retry count");
  CHECK(lichen_rpl_dao_retry_timer_schedule_next(NULL, 0U, &delay) == -EINVAL &&
            lichen_rpl_dao_retry_timer_schedule_next(&timer, 0U, NULL) ==
                -EINVAL,
        "NULL retry scheduling input accepted");
  return true;
}

static bool test_retry_wrap_and_reset_rearm(void) {
  struct lichen_rpl_dao_retry_timer timer;
  uint32_t delay;

  lichen_rpl_dao_retry_timer_init(&timer);
  CHECK(lichen_rpl_dao_retry_timer_schedule_next(
            &timer, UINT32_MAX - (LICHEN_RPL_DAO_RETRY_FIRST_MS - 2U),
            &delay) == 0,
        "wrap-crossing retry was not scheduled");
  CHECK(delay == LICHEN_RPL_DAO_RETRY_FIRST_MS && timer.deadline_ms == 1U,
        "wrap-crossing retry deadline mismatch");
  CHECK(!lichen_rpl_dao_retry_timer_is_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_retry_timer_is_due(&timer, 0U) &&
            lichen_rpl_dao_retry_timer_is_due(&timer, 1U),
        "retry wrap boundary mismatch");

  lichen_rpl_dao_retry_timer_reset(&timer);
  CHECK(!timer.armed && timer.attempts == 0U && timer.deadline_ms == 0U,
        "reset did not clear pending retry and budget");
  CHECK(lichen_rpl_dao_retry_timer_schedule_next(&timer, 10U, &delay) == 0 &&
            delay == LICHEN_RPL_DAO_RETRY_FIRST_MS && timer.attempts == 1U,
        "reset did not rearm from the four-second slot");
  lichen_rpl_dao_retry_timer_reset(NULL);
  return true;
}

static bool test_refresh_profile_and_periodic_rearm(void) {
  struct lichen_rpl_dao_refresh_timer timer;

  CHECK(LICHEN_RPL_DAO_SOFT_STATE_LIFETIME_S == 30U * 60U,
        "soft-state lifetime drifted");
  CHECK(LICHEN_RPL_DAO_REFRESH_INTERVAL_S == 15U * 60U &&
            LICHEN_RPL_DAO_REFRESH_INTERVAL_MS == 900000U &&
            LICHEN_RPL_DAO_REFRESH_INTERVAL_S ==
                LICHEN_RPL_DAO_SOFT_STATE_LIFETIME_S / 2U,
        "refresh is not the exact route half-life");

  lichen_rpl_dao_refresh_timer_init(NULL);
  lichen_rpl_dao_refresh_timer_init(&timer);
  CHECK(!timer.armed && timer.deadline_ms == 0U &&
            !lichen_rpl_dao_refresh_timer_is_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_refresh_timer_is_due(NULL, 0U) &&
            !lichen_rpl_dao_refresh_timer_take_if_due(NULL, 0U),
        "inactive/NULL refresh timer became due");

  CHECK(lichen_rpl_dao_refresh_timer_start(&timer, 12345U) == 0 &&
            timer.armed && timer.deadline_ms == 912345U,
        "exact refresh deadline mismatch");
  CHECK(!lichen_rpl_dao_refresh_timer_is_due(&timer, 912344U) &&
            lichen_rpl_dao_refresh_timer_is_due(&timer, 912345U) &&
            lichen_rpl_dao_refresh_timer_is_due(&timer, 912346U),
        "refresh due boundary mismatch");

  const uint32_t first_deadline = timer.deadline_ms;
  CHECK(lichen_rpl_dao_refresh_timer_start(&timer, 999U) == -EALREADY &&
            timer.armed && timer.deadline_ms == first_deadline,
        "duplicate refresh start postponed deadline");

  /* A successful early route update deliberately begins a fresh period. */
  CHECK(lichen_rpl_dao_refresh_timer_reschedule(&timer, 20000U) == 0 &&
            timer.armed && timer.deadline_ms == 920000U,
        "periodic refresh did not rearm from successful transmission");
  CHECK(!lichen_rpl_dao_refresh_timer_take_if_due(&timer, 919999U),
        "refresh consumed before rearmed deadline");
  CHECK(lichen_rpl_dao_refresh_timer_take_if_due(&timer, 920000U),
        "due refresh was not consumed");
  CHECK(!lichen_rpl_dao_refresh_timer_take_if_due(&timer, 920000U),
        "refresh timer was not one-shot");

  CHECK(lichen_rpl_dao_refresh_timer_reschedule(&timer, 30000U) == 0 &&
            timer.deadline_ms == 930000U,
        "inactive periodic timer did not rearm");
  lichen_rpl_dao_refresh_timer_reset(&timer);
  CHECK(!timer.armed && timer.deadline_ms == 0U,
        "route invalidation did not cancel refresh");
  CHECK(lichen_rpl_dao_refresh_timer_start(NULL, 0U) == -EINVAL &&
            lichen_rpl_dao_refresh_timer_reschedule(NULL, 0U) == -EINVAL,
        "NULL refresh timer accepted");
  lichen_rpl_dao_refresh_timer_reset(NULL);
  return true;
}

static bool test_refresh_wrap_boundary(void) {
  struct lichen_rpl_dao_refresh_timer timer;

  lichen_rpl_dao_refresh_timer_init(&timer);
  CHECK(lichen_rpl_dao_refresh_timer_start(
            &timer, UINT32_MAX - (LICHEN_RPL_DAO_REFRESH_INTERVAL_MS - 2U)) ==
            0,
        "wrap-crossing refresh was not scheduled");
  CHECK(timer.deadline_ms == 1U, "wrap-crossing refresh deadline mismatch");
  CHECK(!lichen_rpl_dao_refresh_timer_is_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_refresh_timer_is_due(&timer, 0U) &&
            lichen_rpl_dao_refresh_timer_is_due(&timer, 1U),
        "refresh wrap boundary mismatch");
  return true;
}

static bool run_all_tests(void) {
  return test_exact_mapping_and_rejection_boundary() &&
         test_injected_rng_and_fail_closed_bounds() &&
         test_one_shot_deadlines_and_wrap() &&
         test_retry_profile_and_exhaustion() &&
         test_retry_wrap_and_reset_rearm() &&
         test_refresh_profile_and_periodic_rearm() &&
         test_refresh_wrap_boundary();
}

#ifdef CONFIG_ZTEST
ZTEST(rpl_dao_timing, test_profile) {
  zassert_true(run_all_tests(), "DAO timing profile failed");
}

ZTEST_SUITE(rpl_dao_timing, NULL, NULL, NULL, NULL, NULL);
#else
int main(void) {
  if (!run_all_tests()) {
    return 1;
  }
  puts("rpl_dao_timing: all tests passed");
  return 0;
}
#endif

#undef ACCEPTANCE_LIMIT
