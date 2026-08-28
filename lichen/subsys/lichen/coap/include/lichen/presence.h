/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/presence.h
 * @brief Presence CBOR encoding (spec section 18.5)
 *
 * Domain types and CBOR codec for presence payloads. The wire format is:
 *
 * ```cbor
 * {
 *   "status": "available",   ; presence status (tstr)
 *   "activity": "moving",    ; activity hint (tstr, optional)
 *   "msg": "On patrol",      ; status message (tstr, optional)
 *   "battery": 87,           ; battery percentage (uint 0-100, optional)
 *   "low_battery": true,     ; low battery flag (bool, optional)
 *   "ts": 1716742800         ; timestamp (uint)
 * }
 * ```
 *
 * Status values per spec 18.5.1:
 * - available: Node is reachable and active
 * - busy: Node is reachable but occupied
 * - away: Node is reachable but inactive
 * - offline: Node is not reachable
 * - emergency: Node has active SOS
 *
 * Activity values per spec 18.5.1:
 * - stationary: Not moving
 * - moving: Currently moving
 * - resting: Resting/sleeping
 * - working: Engaged in work
 */

#ifndef LICHEN_PRESENCE_H_
#define LICHEN_PRESENCE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum message length per spec */
#define PRESENCE_MSG_MAX_LEN 256

/** Maximum encoded CBOR length (conservative upper bound) */
#define PRESENCE_CBOR_MAX_LEN 384

/** Maximum address string length for cache entries */
#define PRESENCE_ADDR_MAX_LEN 48

/** Maximum entries in presence cache */
#define PRESENCE_CACHE_MAX_ENTRIES 16

/** Threshold for low_battery flag (spec 18.5.3) */
#define PRESENCE_LOW_BATTERY_PCT 10

/**
 * @brief Presence status per spec 18.5.1.
 */
enum presence_status {
	PRESENCE_STATUS_AVAILABLE = 0, /**< Reachable and active */
	PRESENCE_STATUS_BUSY = 1,      /**< Reachable but occupied */
	PRESENCE_STATUS_AWAY = 2,      /**< Reachable but inactive */
	PRESENCE_STATUS_OFFLINE = 3,   /**< Not reachable */
	PRESENCE_STATUS_EMERGENCY = 4, /**< Active SOS */
};

/**
 * @brief Activity hint per spec 18.5.1.
 */
enum presence_activity {
	PRESENCE_ACTIVITY_NONE = 0,       /**< No activity specified */
	PRESENCE_ACTIVITY_STATIONARY = 1, /**< Not moving */
	PRESENCE_ACTIVITY_MOVING = 2,     /**< Currently moving */
	PRESENCE_ACTIVITY_RESTING = 3,    /**< Resting/sleeping */
	PRESENCE_ACTIVITY_WORKING = 4,    /**< Engaged in work */
};

/**
 * @brief Presence payload structure.
 *
 * Represents the CBOR-encoded presence per spec 18.5.1.
 * Required fields: status, ts.
 * Optional fields: activity, msg, battery, low_battery.
 */
struct presence {
	enum presence_status status;          /**< Presence status */
	uint64_t ts;                          /**< Unix timestamp (seconds) */
	bool has_activity;                    /**< True if activity is present */
	enum presence_activity activity;      /**< Activity hint */
	bool has_msg;                         /**< True if msg is present */
	char msg[PRESENCE_MSG_MAX_LEN];       /**< Status message */
	bool has_battery;                     /**< True if battery is present */
	uint8_t battery;                      /**< Battery percentage (0-100) */
	bool has_low_battery;                 /**< True if low_battery is present */
	bool low_battery;                     /**< Low battery flag */
};

/**
 * @brief Presence cache entry (spec 18.5.2).
 */
struct presence_cache_entry {
	char addr[PRESENCE_ADDR_MAX_LEN];     /**< Node address (IPv6 string) */
	enum presence_status status;          /**< Node's presence status */
	bool has_battery;                     /**< True if battery is present */
	uint8_t battery;                      /**< Battery percentage (0-100) */
	uint32_t age_s;                       /**< Seconds since last update */
};

/**
 * @brief Presence cache (spec 18.5.2).
 */
struct presence_cache {
	struct presence_cache_entry entries[PRESENCE_CACHE_MAX_ENTRIES];
	size_t count;                         /**< Number of valid entries */
};

/**
 * @brief CBOR decode error codes.
 */
enum presence_error {
	PRESENCE_OK = 0,
	PRESENCE_ERR_TRUNCATED,        /**< Input ended before complete map */
	PRESENCE_ERR_NOT_A_MAP,        /**< Top-level item is not a CBOR map */
	PRESENCE_ERR_TRAILING_DATA,    /**< Extra bytes after the map */
	PRESENCE_ERR_DUPLICATE_KEY,    /**< Duplicate map key */
	PRESENCE_ERR_UNKNOWN_KEY,      /**< Unknown map key */
	PRESENCE_ERR_MISSING_FIELD,    /**< Required field missing */
	PRESENCE_ERR_UNEXPECTED_TYPE,  /**< Field had wrong CBOR type */
	PRESENCE_ERR_INVALID_VALUE,    /**< Invalid text or value */
	PRESENCE_ERR_OUT_OF_RANGE,     /**< Integer/string too large */
	PRESENCE_ERR_BUFFER_TOO_SMALL, /**< Output buffer too small */
};

/**
 * @brief Initialize a presence with required fields.
 *
 * Sets status, ts and clears optional fields.
 *
 * @param[out] p       Presence to initialize
 * @param[in]  status  Presence status
 * @param[in]  ts      Unix timestamp (seconds since epoch)
 */
void presence_init(struct presence *_Nonnull p,
		   enum presence_status status,
		   uint64_t ts);

/**
 * @brief Set activity on a presence.
 *
 * @param[in,out] p        Presence to modify
 * @param[in]     activity Activity hint
 */
void presence_set_activity(struct presence *_Nonnull p,
			   enum presence_activity activity);

/**
 * @brief Set message on a presence.
 *
 * @param[in,out] p    Presence to modify
 * @param[in]     msg  Message text (will be truncated if too long)
 */
void presence_set_message(struct presence *_Nonnull p,
			  const char *_Nonnull msg);

/**
 * @brief Set battery on a presence.
 *
 * @param[in,out] p        Presence to modify
 * @param[in]     battery  Battery percentage (0-100)
 * @return 0 on success, -1 if battery > 100
 */
int presence_set_battery(struct presence *_Nonnull p, uint8_t battery);

/**
 * @brief Get the string representation of a status.
 *
 * @param[in] status Presence status
 * @return Wire string (e.g., "available", "busy") or NULL if invalid
 */
const char *_Nullable presence_status_str(enum presence_status status);

/**
 * @brief Parse status from wire string.
 *
 * @param[in]  str    Wire string (e.g., "available", "busy")
 * @param[out] status Parsed status
 * @return 0 on success, -1 if string is unknown
 */
int presence_status_parse(const char *_Nonnull str,
			  enum presence_status *_Nonnull status);

/**
 * @brief Get the string representation of an activity.
 *
 * @param[in] activity Activity hint
 * @return Wire string (e.g., "moving", "stationary") or NULL if invalid
 */
const char *_Nullable presence_activity_str(enum presence_activity activity);

/**
 * @brief Parse activity from wire string.
 *
 * @param[in]  str      Wire string (e.g., "moving", "stationary")
 * @param[out] activity Parsed activity
 * @return 0 on success, -1 if string is unknown
 */
int presence_activity_parse(const char *_Nonnull str,
			    enum presence_activity *_Nonnull activity);

/**
 * @brief Encode presence to CBOR (wire format).
 *
 * Encodes in spec key order: status, activity, msg, battery, low_battery, ts.
 * Omits absent optional fields.
 *
 * @param[in]  p        Presence to encode
 * @param[out] buf      Output buffer
 * @param[in]  buf_len  Buffer capacity
 * @param[out] out_len  Encoded length on success
 * @return 0 on success, negative error code on failure
 */
int presence_to_cbor(const struct presence *_Nonnull p,
		     uint8_t *_Nonnull buf,
		     size_t buf_len,
		     size_t *_Nonnull out_len);

/**
 * @brief Decode presence from CBOR.
 *
 * @param[in]  buf      CBOR data
 * @param[in]  buf_len  Data length
 * @param[out] p        Parsed presence
 * @return 0 on success, enum presence_error on failure
 */
int presence_from_cbor(const uint8_t *_Nonnull buf,
		       size_t buf_len,
		       struct presence *_Nonnull p);

/**
 * @brief Initialize a presence cache.
 *
 * @param[out] cache Cache to initialize
 */
void presence_cache_init(struct presence_cache *_Nonnull cache);

/**
 * @brief Encode presence cache to CBOR.
 *
 * @param[in]  cache    Cache to encode
 * @param[out] buf      Output buffer
 * @param[in]  buf_len  Buffer capacity
 * @param[out] out_len  Encoded length on success
 * @return 0 on success, negative error code on failure
 */
int presence_cache_to_cbor(const struct presence_cache *_Nonnull cache,
			   uint8_t *_Nonnull buf,
			   size_t buf_len,
			   size_t *_Nonnull out_len);

/**
 * @brief Decode presence cache from CBOR.
 *
 * @param[in]  buf      CBOR data
 * @param[in]  buf_len  Data length
 * @param[out] cache    Parsed cache
 * @return 0 on success, enum presence_error on failure
 */
int presence_cache_from_cbor(const uint8_t *_Nonnull buf,
			     size_t buf_len,
			     struct presence_cache *_Nonnull cache);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_PRESENCE_H_ */
