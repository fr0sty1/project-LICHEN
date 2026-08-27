/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/sos_alert.h
 * @brief SOS alert CBOR encoding (spec section 18.4.2)
 *
 * Domain types and CBOR codec for SOS alert payloads. The wire format is:
 *
 * ```cbor
 * {
 *   "type": "sos",               ; alert type (tstr)
 *   "node": "0200:...:1111",     ; originating node IID (tstr)
 *   "ts": 1716742800,            ; timestamp (uint)
 *   "lat": 37.774929,            ; latitude (float, optional)
 *   "lon": -122.419416,          ; longitude (float, optional)
 *   "msg": "Injured, need evac", ; details (tstr, optional)
 *   "seq": 1                     ; sequence for updates (uint)
 * }
 * ```
 *
 * Alert types per spec 18.4.2:
 * - sos: General emergency
 * - medical: Medical emergency
 * - security: Security threat
 * - fire: Fire emergency
 * - cancel: Cancel previous alert
 */

#ifndef LICHEN_SOS_ALERT_H_
#define LICHEN_SOS_ALERT_H_

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

/** Maximum node ID string length ("0200:0000:0000:0000:0000:0000:0000:0000\0") */
#define SOS_ALERT_NODE_MAX_LEN 40

/** Maximum message length per spec */
#define SOS_ALERT_MSG_MAX_LEN 256

/** Maximum encoded CBOR length (conservative upper bound) */
#define SOS_ALERT_CBOR_MAX_LEN 384

/**
 * @brief SOS alert type per spec 18.4.2.
 */
enum sos_alert_type {
	SOS_ALERT_TYPE_SOS = 0,      /**< General emergency */
	SOS_ALERT_TYPE_MEDICAL = 1,  /**< Medical emergency */
	SOS_ALERT_TYPE_SECURITY = 2, /**< Security threat */
	SOS_ALERT_TYPE_FIRE = 3,     /**< Fire emergency */
	SOS_ALERT_TYPE_CANCEL = 4,   /**< Cancel previous alert */
};

/**
 * @brief SOS alert payload structure.
 *
 * Represents the CBOR-encoded SOS alert per spec 18.4.2.
 * Required fields: type, node, ts, seq.
 * Optional fields: lat, lon, msg.
 */
struct sos_alert {
	enum sos_alert_type type;              /**< Alert type */
	char node[SOS_ALERT_NODE_MAX_LEN];     /**< Originating node IID (IPv6 hex) */
	uint64_t ts;                           /**< Unix timestamp (seconds) */
	uint32_t seq;                          /**< Sequence number for updates */
	bool has_location;                     /**< True if lat/lon are present */
	double lat;                            /**< Latitude (-90 to 90) */
	double lon;                            /**< Longitude (-180 to 180) */
	bool has_msg;                          /**< True if msg is present */
	char msg[SOS_ALERT_MSG_MAX_LEN];       /**< Message details */
};

/**
 * @brief CBOR decode error codes.
 */
enum sos_alert_error {
	SOS_ALERT_OK = 0,
	SOS_ALERT_ERR_TRUNCATED,       /**< Input ended before complete map */
	SOS_ALERT_ERR_NOT_A_MAP,       /**< Top-level item is not a CBOR map */
	SOS_ALERT_ERR_TRAILING_DATA,   /**< Extra bytes after the map */
	SOS_ALERT_ERR_DUPLICATE_KEY,   /**< Duplicate map key */
	SOS_ALERT_ERR_UNKNOWN_KEY,     /**< Unknown map key */
	SOS_ALERT_ERR_MISSING_FIELD,   /**< Required field missing */
	SOS_ALERT_ERR_UNEXPECTED_TYPE, /**< Field had wrong CBOR type */
	SOS_ALERT_ERR_INVALID_VALUE,   /**< Invalid text or type token */
	SOS_ALERT_ERR_OUT_OF_RANGE,    /**< Integer/string too large */
	SOS_ALERT_ERR_BUFFER_TOO_SMALL,/**< Output buffer too small */
};

/**
 * @brief Initialize an SOS alert with required fields.
 *
 * Sets type, node, ts, seq and clears optional fields.
 *
 * @param[out] alert  Alert to initialize
 * @param[in]  type   Alert type
 * @param[in]  node   Originating node IID (must be null-terminated)
 * @param[in]  ts     Unix timestamp (seconds since epoch)
 * @param[in]  seq    Sequence number
 */
void sos_alert_init(struct sos_alert *_Nonnull alert,
		    enum sos_alert_type type,
		    const char *_Nonnull node,
		    uint64_t ts,
		    uint32_t seq);

/**
 * @brief Set location on an SOS alert.
 *
 * Coordinates are validated against the same contract the decoder enforces:
 * latitude [-90, 90] and longitude [-180, 180] inclusive, non-finite values
 * rejected. On failure the alert's previous location state is unchanged, so
 * it never encodes coordinates its own decoder would reject.
 *
 * @param[in,out] alert Alert to modify
 * @param[in]     lat   Latitude (-90 to 90)
 * @param[in]     lon   Longitude (-180 to 180)
 * @return SOS_ALERT_OK on success,
 *         SOS_ALERT_ERR_INVALID_VALUE if lat/lon out of range or non-finite
 */
int sos_alert_set_location(struct sos_alert *_Nonnull alert,
			   double lat,
			   double lon);

/**
 * @brief Set message on an SOS alert.
 *
 * @param[in,out] alert Alert to modify
 * @param[in]     msg   Message text (will be truncated if too long)
 */
void sos_alert_set_message(struct sos_alert *_Nonnull alert,
			   const char *_Nonnull msg);

/**
 * @brief Get the string representation of an alert type.
 *
 * @param[in] type Alert type
 * @return Wire string (e.g., "sos", "medical") or NULL if invalid
 */
const char *_Nullable sos_alert_type_str(enum sos_alert_type type);

/**
 * @brief Parse alert type from wire string.
 *
 * @param[in]  str  Wire string (e.g., "sos", "medical")
 * @param[out] type Parsed alert type
 * @return 0 on success, -1 if string is unknown
 */
int sos_alert_type_parse(const char *_Nonnull str, enum sos_alert_type *_Nonnull type);

/**
 * @brief Encode SOS alert to CBOR (wire format).
 *
 * Encodes in spec key order: type, node, ts, lat, lon, msg, seq.
 * Omits absent optional fields.
 *
 * @param[in]  alert    Alert to encode
 * @param[out] buf      Output buffer
 * @param[in]  buf_len  Buffer capacity
 * @param[out] out_len  Encoded length on success
 * @return 0 on success, negative error code on failure
 */
int sos_alert_to_cbor(const struct sos_alert *_Nonnull alert,
		      uint8_t *_Nonnull buf,
		      size_t buf_len,
		      size_t *_Nonnull out_len);

/**
 * @brief Decode SOS alert from CBOR.
 *
 * Non-finite or out-of-range coordinates are rejected with
 * SOS_ALERT_ERR_INVALID_VALUE (lat [-90,90], lon [-180,180]).
 *
 * @param[in]  buf      CBOR data
 * @param[in]  buf_len  Data length
 * @param[out] alert    Parsed alert
 * @return 0 on success, enum sos_alert_error on failure
 */
int sos_alert_from_cbor(const uint8_t *_Nonnull buf,
			size_t buf_len,
			struct sos_alert *_Nonnull alert);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SOS_ALERT_H_ */
