/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_location.h
 * @brief Position beacon scheduling for the LICHEN location profile.
 */

#ifndef LICHEN_COAP_LOCATION_H_
#define LICHEN_COAP_LOCATION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/compiler.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_POSITION_BEACON_MOVING_INTERVAL_MS 60000U
#define LICHEN_POSITION_BEACON_STATIONARY_INTERVAL_MS 300000U
#define LICHEN_POSITION_BEACON_RETRY_INTERVAL_MS 5000U
#define LICHEN_POSITION_BEACON_PAYLOAD_MAX 192U
#define LICHEN_POSITION_CACHE_MAX_ENTRIES 4U
#define LICHEN_POSITION_CACHE_PAYLOAD_MAX 512U
#define LICHEN_POSITION_CACHE_EXPIRY_MS 1800000U
#define LICHEN_POSITION_OBSERVER_MAX 3U
#define LICHEN_POSITION_OBSERVE_DISTANCE_CM 5000U
#define LICHEN_POSITION_OBSERVE_INTERVAL_MS 300000U
#define LICHEN_POSITION_OBSERVE_RETRY_MS 5000U

enum lichen_position_privacy_mode {
  LICHEN_POSITION_PRIVACY_PUBLIC = 0,
  LICHEN_POSITION_PRIVACY_GROUP,
  LICHEN_POSITION_PRIVACY_PRIVATE,
  LICHEN_POSITION_PRIVACY_OFF,
};

enum lichen_position_beacon_result {
  LICHEN_POSITION_BEACON_IDLE = 0,
  LICHEN_POSITION_BEACON_SENT = 1,
  LICHEN_POSITION_BEACON_SUPPRESSED = 2,
  LICHEN_POSITION_BEACON_NO_FIX = 3,
};

typedef int (*lichen_position_beacon_tx_fn)(const uint8_t *_Nonnull payload,
                                            size_t payload_len,
                                            void *_Nullable user_data);

struct lichen_position_beacon_config {
  /** 0 selects the profile default (60 seconds). */
  uint32_t moving_interval_ms;
  /** 0 selects the profile default (300 seconds). */
  uint32_t stationary_interval_ms;
  /** 0 selects the bounded retry default (5 seconds). */
  uint32_t retry_interval_ms;
  /** Movement threshold in centimetres; 0 selects 1000 cm. */
  uint32_t moving_threshold_cm;
  /** Stationary threshold in centimetres; 0 selects 300 cm. */
  uint32_t stationary_threshold_cm;
  /** Consecutive low-motion samples before leaving moving state; 0 selects 2.
   */
  uint8_t stationary_hysteresis_samples;
  /** Retry count after transient backpressure; 0 selects 3. */
  uint8_t max_retries;
  /** IPv6 interface index for ff02::1. 0 lets the network stack choose. */
  uint32_t interface_index;
  /** Optional transport override. NULL sends NON PUT /pos to ff02::1. */
  lichen_position_beacon_tx_fn _Nullable tx_fn;
  void *_Nullable tx_user_data;
};

struct lichen_position_beacon_stats {
  uint32_t sent;
  uint32_t no_fix;
  uint32_t privacy_suppressed;
  uint32_t backpressure;
  uint32_t failures;
  int last_error;
  bool moving;
  uint8_t retry_count;
  int64_t next_due_ms;
};

enum lichen_position_observe_result {
  LICHEN_POSITION_OBSERVE_IDLE = 0,
  LICHEN_POSITION_OBSERVE_NOTIFIED = 1,
  LICHEN_POSITION_OBSERVE_SUPPRESSED = 2,
  LICHEN_POSITION_OBSERVE_NO_FIX = 3,
};

struct lichen_position_observe_stats {
  uint32_t notifications;
  uint32_t backpressure;
  uint32_t failures;
  uint8_t observers;
  uint32_t sequence;
  int last_error;
};

/** Reset observation state and cancel every registered location observer. */
void lichen_position_observe_reset(void);

/**
 * Poll the current location and notify observers on movement, source change,
 * or the profile maximum interval. Retries transient send failures boundedly.
 */
int lichen_position_observe_poll(int64_t now_ms);

/** Copy current bounded observer and delivery statistics. */
int lichen_position_observe_get_stats(
    struct lichen_position_observe_stats *_Nonnull stats);

enum lichen_position_provenance {
	LICHEN_POSITION_PROVENANCE_LINK_SIGNED = 0,
	LICHEN_POSITION_PROVENANCE_GROUP_OSCORE,
	LICHEN_POSITION_PROVENANCE_PAIRWISE_OSCORE,
};

struct lichen_position_cache_update {
	uint8_t node[16];
	uint8_t authenticated_node[16];
	int32_t latitude_e7;
	int32_t longitude_e7;
	int32_t altitude_cm;
	uint64_t timestamp_unix;
	int64_t observed_monotonic_ms;
	enum lichen_position_privacy_mode privacy;
	enum lichen_position_provenance provenance;
	bool altitude_valid;
	bool authenticated;
};

/** Clear all peer positions. */
void lichen_position_cache_reset(void);

/**
 * Insert or replace one authenticated peer position.
 *
 * Claimed and authenticated node addresses must match. Public updates require
 * link authentication; group updates require Group OSCORE. Private/off
 * positions are never cacheable broadcasts.
 */
int lichen_position_cache_update(
	const struct lichen_position_cache_update *_Nonnull update);

/** Purge expired entries and return the number removed. */
size_t lichen_position_cache_purge(int64_t now_ms, uint32_t max_age_ms);

/** Atomically encode the current cache as the /pos/cache CBOR response. */
int lichen_position_cache_encode(int64_t now_ms,
				 uint8_t *_Nonnull out, size_t out_len);

/** Set read privacy for /pos/cache; non-public modes fail closed. */
int lichen_position_cache_set_privacy(enum lichen_position_privacy_mode mode);

/** Configure deterministic beacon state without starting Zephyr work. */
int lichen_position_beacon_configure(
    const struct lichen_position_beacon_config *_Nullable config,
    int64_t now_ms);

/**
 * Process one monotonic scheduler sample.
 *
 * This entry point is suitable for deterministic event loops and tests. It
 * performs at most one transmission and never sleeps.
 */
int lichen_position_beacon_poll(int64_t now_ms);

/** Configure and start the Zephyr delayed-work scheduler. */
int lichen_position_beacon_start(
    const struct lichen_position_beacon_config *_Nullable config);

/** Stop the delayed-work scheduler. Safe when already stopped. */
void lichen_position_beacon_stop(void);

/** Change privacy policy immediately. Only public mode emits public beacons. */
int lichen_position_beacon_set_privacy(enum lichen_position_privacy_mode mode);

/** Copy current counters and scheduler state. */
int lichen_position_beacon_get_stats(
    struct lichen_position_beacon_stats *_Nonnull stats);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_LOCATION_H_ */
