/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lichen/sync_hop.h>

#include "asn_sfn_vectors.h"

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

/* sync_hop.c also contains the channel helper; provide its normal FNV oracle.
 */
uint32_t lichen_hash_32(const uint8_t *data, size_t len) {
  uint32_t hash = UINT32_C(0x811c9dc5);
  for (size_t index = 0; index < len; ++index) {
    hash ^= data[index];
    hash *= UINT32_C(0x01000193);
  }
  return hash;
}

static bool result_equal(const struct lichen_asn_sfn_result *left,
                         const struct lichen_asn_sfn_result *right) {
  return left->asn == right->asn && left->sfn == right->sfn &&
         left->clamped == right->clamped;
}

static bool test_canonical_vectors(void) {
  for (size_t index = 0; index < ASN_SFN_VECTOR_COUNT; ++index) {
    const struct asn_sfn_vector *vector = &asn_sfn_vectors[index];
    struct lichen_asn_sfn_result actual = {
        .asn = UINT64_C(0xaaaaaaaaaaaaaaaa),
        .sfn = UINT32_C(0xbbbbbbbb),
        .clamped = !vector->expected_clamped,
    };

    CHECK(lichen_asn_sfn_derive(vector->unix_time_us, vector->epoch_base_us,
                                vector->interval_duration_us, &actual) == 0,
          "%s: derivation failed", vector->name);
    CHECK(actual.asn == vector->expected_asn &&
              actual.sfn == vector->expected_sfn &&
              actual.clamped == vector->expected_clamped,
          "%s: canonical result mismatch", vector->name);
  }
  return true;
}

static bool expect_sample_error(struct lichen_asn_time_sample sample,
                                uint64_t epoch_base_us, uint64_t duration_us,
                                int expected_error, const char *name) {
  const struct lichen_asn_sfn_result sentinel = {
      .asn = UINT64_C(0x1111111111111111),
      .sfn = UINT32_C(0x22222222),
      .clamped = true,
  };
  struct lichen_asn_sfn_result actual = sentinel;

  CHECK(lichen_asn_sfn_derive_sample(&sample, epoch_base_us, duration_us,
                                     &actual) == expected_error,
        "%s: wrong error", name);
  CHECK(result_equal(&actual, &sentinel), "%s: output mutated", name);
  return true;
}

static bool test_validated_source_and_boundaries(void) {
  const uint64_t epoch_us = UINT64_C(1704067200000000);
  struct lichen_asn_time_sample sample = {
      .unix_seconds = INT64_C(1704067202),
      .subsecond_us = 0,
      .effective_epoch_floor_us = epoch_us,
      .stratum = 4,
      .scale = LICHEN_ASN_TIME_SCALE_UNIX_UTC,
      .wall_clock_valid = true,
      .source_valid = true,
  };
  struct lichen_asn_sfn_result result;

  CHECK(lichen_asn_sfn_derive_sample(&sample, epoch_us, UINT64_C(2000000),
                                     &result) == 0,
        "valid authoritative sample rejected");
  CHECK(result.asn == 1 && result.sfn == 1 && !result.clamped,
        "exact interval boundary rounded incorrectly");

  sample.unix_seconds = INT64_C(1483228799);
  sample.effective_epoch_floor_us = UINT64_C(1483228798000000);
  CHECK(lichen_asn_sfn_derive_sample(&sample, UINT64_C(1483228798000000),
                                     UINT64_C(1000000), &result) == 0 &&
            result.asn == 1,
        "last representable pre-leap instant mismatch");
  sample.unix_seconds = INT64_C(1483228800);
  CHECK(lichen_asn_sfn_derive_sample(&sample, UINT64_C(1483228798000000),
                                     UINT64_C(1000000), &result) == 0 &&
            result.asn == 2,
        "first representable post-leap instant mismatch");

  sample.unix_seconds = INT64_C(18446744073709);
  sample.subsecond_us = 551615U;
  sample.effective_epoch_floor_us = 0;
  CHECK(lichen_asn_sfn_derive_sample(&sample, 0, 1, &result) == 0 &&
            result.asn == UINT64_MAX && result.sfn == UINT32_MAX,
        "full uint64 microsecond range was not preserved");
  return true;
}

static bool test_fail_closed_inputs(void) {
  struct lichen_asn_time_sample sample = {
      .unix_seconds = 20,
      .subsecond_us = 0,
      .effective_epoch_floor_us = UINT64_C(10000000),
      .stratum = 4,
      .scale = LICHEN_ASN_TIME_SCALE_UNIX_UTC,
      .wall_clock_valid = true,
      .source_valid = true,
  };

  sample.wall_clock_valid = false;
  CHECK(expect_sample_error(sample, 0, 1, -EACCES, "invalid wall clock"),
        "wall-clock error assertion failed");
  sample.wall_clock_valid = true;
  sample.source_valid = false;
  CHECK(expect_sample_error(sample, 0, 1, -EACCES, "invalid source"),
        "source error assertion failed");
  sample.source_valid = true;
  sample.stratum = 0;
  CHECK(expect_sample_error(sample, 0, 1, -EACCES, "no-sync stratum"),
        "stratum error assertion failed");
  sample.stratum = 5;
  CHECK(expect_sample_error(sample, 0, 1, -EACCES, "unknown stratum"),
        "stratum range assertion failed");
  sample.stratum = 4;
  sample.scale = LICHEN_ASN_TIME_SCALE_INVALID;
  CHECK(expect_sample_error(sample, 0, 1, -EACCES, "raw GPS timescale"),
        "timescale error assertion failed");
  sample.scale = LICHEN_ASN_TIME_SCALE_UNIX_UTC;
  sample.unix_seconds = -1;
  CHECK(expect_sample_error(sample, 0, 1, -ERANGE, "negative timestamp"),
        "negative error assertion failed");
  sample.unix_seconds = 20;
  sample.subsecond_us = 1000000U;
  CHECK(expect_sample_error(sample, 0, 1, -ERANGE, "invalid subsecond"),
        "subsecond error assertion failed");
  sample.unix_seconds = INT64_MAX;
  sample.subsecond_us = 0;
  CHECK(expect_sample_error(sample, 0, 1, -EOVERFLOW, "conversion overflow"),
        "overflow error assertion failed");
  sample.unix_seconds = 20;
  sample.effective_epoch_floor_us = UINT64_C(21000000);
  CHECK(expect_sample_error(sample, 0, 1, -ESTALE, "below epoch floor"),
        "floor error assertion failed");
  sample.effective_epoch_floor_us = 0;
  CHECK(expect_sample_error(sample, UINT64_C(21000000), 1, -ERANGE,
                            "before configured epoch"),
        "pre-epoch error assertion failed");
  CHECK(expect_sample_error(sample, 0, 0, -EINVAL, "zero duration"),
        "duration error assertion failed");
  return true;
}

static bool test_null_and_legacy_atomicity(void) {
  struct lichen_asn_sfn_result result = {
      .asn = 7,
      .sfn = 8,
      .clamped = false,
  };

  CHECK(lichen_asn_sfn_derive(0, 0, 1, NULL) == -EINVAL,
        "legacy NULL output accepted");
  CHECK(lichen_asn_sfn_derive_sample(NULL, 0, 1, &result) == -EINVAL &&
            result.asn == 7 && result.sfn == 8 && !result.clamped,
        "NULL sample mutated output");
  CHECK(lichen_asn_sfn_derive_sample(&(struct lichen_asn_time_sample){0}, 0, 1,
                                     NULL) == -EINVAL,
        "NULL checked output accepted");
  return true;
}

static bool test_synchronized_hop_channel_bounds(void) {
  static const uint8_t channel_counts[] = {0U, 1U, 2U, 3U, 64U, UINT8_MAX};
  static const uint32_t sfns[] = {0U, 1U, 26U, UINT32_C(0x7fffffff), UINT32_MAX};

  for (size_t count_index = 0;
       count_index < sizeof(channel_counts) / sizeof(channel_counts[0]);
       ++count_index) {
    const uint8_t n_channels = channel_counts[count_index];
    for (size_t sfn_index = 0; sfn_index < sizeof(sfns) / sizeof(sfns[0]);
         ++sfn_index) {
      uint8_t data[8] = {0};
      const uint32_t sfn = sfns[sfn_index];
      uint8_t expected;

      data[4] = (uint8_t)sfn;
      data[5] = (uint8_t)(sfn >> 8);
      data[6] = (uint8_t)(sfn >> 16);
      data[7] = (uint8_t)(sfn >> 24);
      expected = n_channels <= 1U
                     ? 0U
                     : (uint8_t)(1U + lichen_hash_32(data, sizeof(data)) %
                                          (uint32_t)(n_channels - 1U));
      CHECK(lichen_sync_hop_channel(sfn, 0U, n_channels) == expected,
            "channel mismatch for count=%u sfn=%u", n_channels, sfn);
      CHECK(n_channels <= 1U ? expected == 0U
                             : expected >= 1U && expected < n_channels,
            "out-of-plan channel %u for count=%u", expected, n_channels);
    }
  }

  CHECK(lichen_hash_32((const uint8_t[8]){0U, 0U, 0U, 0U, 26U, 0U, 0U, 0U},
                       8U) % 64U == 63U,
        "historic upper-modulus boundary precondition drifted");
  CHECK(lichen_sync_hop_channel(26U, 0U, 64U) == 15U,
        "historic upper-modulus boundary not corrected");
  return true;
}

#ifdef CONFIG_ZTEST
ZTEST(asn_sfn, canonical_vectors) {
  zassert_true(test_canonical_vectors(), "canonical vectors failed");
}

ZTEST(asn_sfn, validated_source_and_boundaries) {
  zassert_true(test_validated_source_and_boundaries(),
               "validated derivation failed");
}

ZTEST(asn_sfn, fail_closed_inputs) {
  zassert_true(test_fail_closed_inputs(), "fail-closed inputs failed");
}

ZTEST(asn_sfn, null_and_legacy_atomicity) {
  zassert_true(test_null_and_legacy_atomicity(), "atomicity failed");
}

ZTEST(asn_sfn, synchronized_hop_channel_bounds) {
  zassert_true(test_synchronized_hop_channel_bounds(), "hop bounds failed");
}

ZTEST_SUITE(asn_sfn, NULL, NULL, NULL, NULL, NULL);
#else
int main(void) {
  if (!test_canonical_vectors() || !test_validated_source_and_boundaries() ||
      !test_fail_closed_inputs() || !test_null_and_legacy_atomicity() ||
      !test_synchronized_hop_channel_bounds()) {
    return 1;
  }
  puts("ASN/SFN tests passed");
  return 0;
}
#endif
