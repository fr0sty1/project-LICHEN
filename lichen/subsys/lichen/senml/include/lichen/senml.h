/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/senml.h
 * @brief Allocation-free SenML CBOR codec for sensor data (RFC 8428)
 *
 * Provides helpers for encoding and decoding sensor readings as SenML over CBOR.
 * Content-Format: application/senml+cbor (112)
 *
 * @warning SenML payloads may contain sensitive data (location, health
 * metrics, device identifiers). Always encrypt SenML payloads using OSCORE
 * before transmission. The base_name field often contains device identifiers
 * (e.g., MAC addresses) which leak device identity even if values are
 * encrypted separately.
 *
 * @warning Caller must ensure all string pointers (base_name, name, unit,
 * value strings) remain valid until senml_encode_cbor() returns. The API
 * stores raw pointers; strings are not copied internally.
 */

#ifndef LICHEN_SENML_H_
#define LICHEN_SENML_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SENML_KEY_CONFESSIONS "confessions"

#ifndef LICHEN_WARN_UNUSED_RESULT
#if defined(__GNUC__) || defined(__clang__)
#define LICHEN_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define LICHEN_WARN_UNUSED_RESULT
#endif
#endif

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

#define SENML_CBOR_CONTENT_FORMAT 112
#define SENML_LOCATION_LAT "lat"
#define SENML_LOCATION_LON "lon"
#define SENML_LOCATION_ALT "alt"
#define SENML_LOCATION_SPEED "speed"
#define SENML_LOCATION_HEADING "heading"
#define SENML_LOCATION_HACC "hacc"
#define SENML_LOCATION_VACC "vacc"
#define SENML_LOCATION_UNIT_DEG "deg"
#define SENML_LOCATION_UNIT_M "m"
#define SENML_LOCATION_UNIT_MS "m/s"
#define SENML_BATTERY_PCT "pct"
#define SENML_BATTERY_MV "mv"
#define SENML_BATTERY_CHARGING "charging"
#define SENML_BATTERY_UNIT_PCT "%"
#define SENML_BATTERY_UNIT_MV "mV"
#define SENML_TELEMETRY_TEMP "temp"
#define SENML_TELEMETRY_UNIT_CEL "Cel"
#define SENML_DEADDROP_PENDING "pending"
#define SENML_MAX_RECORDS 16

/** Maximum name string length */
#define SENML_MAX_NAME_LEN 32

/** Maximum string value length (for vs field, e.g. DTN messages) */
#define SENML_MAX_STRING_LEN 256

/** Maximum binary data value accepted by the bounded codec. */
#define SENML_MAX_DATA_LEN 1536

/** Maximum unit string length */
#define SENML_MAX_UNIT_LEN 8

/**
 * @brief SenML value type
 */
enum senml_value_type {
	SENML_VALUE_FLOAT,   /**< Floating point value (v) */
	SENML_VALUE_BOOL,    /**< Boolean value (vb) */
	SENML_VALUE_STRING,  /**< String value (vs) */
	SENML_VALUE_DATA,    /**< Binary data (vd) */
};

/** Borrowed byte span used for decoded text and binary values. */
struct senml_span {
	const uint8_t *_Nullable data;
	size_t len;
};

/**
 * @brief SenML record
 */
struct senml_record {
	const char *_Nullable name;  /**< Record name (n) - may be NULL per SenML spec */
	const char *_Nullable unit; /**< Unit (u) - may be NULL */
	enum senml_value_type type;
	union {
		float f;           /**< Float value */
		bool b;            /**< Boolean value */
		const char *_Nullable s; /**< String value (vs) */
		struct senml_span data;  /**< Binary value (vd) */
	} value;
	int32_t time_offset;
	bool has_time;
};


/**
 * @brief SenML pack (array of records with common base)
 */
struct senml_pack {
	const char *_Nullable base_name; /**< Base name (bn) - may be NULL */
	uint64_t base_time;        /**< Base time (bt) */
	bool has_base_time;        /**< Include base time */
	struct senml_record records[SENML_MAX_RECORDS];
	size_t record_count;
};

/**
 * @brief Initialize a SenML pack.
 *
 * @param[out] pack       Pack to initialize
 * @param[in]  base_name  Base name (e.g., "urn:dev:mac:0011223344556677:")
 * @param[in]  base_time  Base Unix timestamp (0 omits bt; callers that need
 *                        the Unix epoch can set has_base_time after init)
 * @return 0 on success, -EINVAL if pack is NULL, -EMSGSIZE if base_name is
 *         longer than SENML_MAX_NAME_LEN
 */
int senml_pack_init(struct senml_pack *_Nullable pack,
		    const char *_Nullable base_name,
		    uint64_t base_time);

/**
 * @brief Add a float record to the pack.
 *
 * @param[in,out] pack  SenML pack
 * @param[in]     name  Record name (e.g., "temp")
 * @param[in]     unit  Unit string (e.g., "Cel") or NULL
 * @param[in]     value Finite float value (NaN/Inf rejected)
 * @return 0 on success, -EINVAL if non-finite, -ENOMEM if pack is full,
 *         -EMSGSIZE if name or unit is too long
 */
int senml_add_float(struct senml_pack *_Nullable pack,
		    const char *_Nullable name,
		    const char *_Nullable unit,
		    float value);

/**
 * @brief Add a float record with time offset.
 *
 * @param[in,out] pack        SenML pack
 * @param[in]     name        Record name
 * @param[in]     unit        Unit string or NULL
 * @param[in]     value       Finite float value (NaN/Inf rejected)
 * @param[in]     time_offset Seconds from base_time
 * @return 0 on success, -EINVAL if non-finite, -ENOMEM if pack is full,
 *         -EMSGSIZE if name or unit is too long
 */
int senml_add_float_t(struct senml_pack *_Nullable pack,
		      const char *_Nullable name,
		      const char *_Nullable unit,
		      float value,
		      int32_t time_offset);

/**
 * @brief Add a boolean record to the pack.
 *
 * @param[in,out] pack  SenML pack
 * @param[in]     name  Record name (e.g., "charging")
 * @param[in]     value Boolean value
 * @return 0 on success, -EINVAL if pack or name is NULL, -ENOMEM if pack is
 *         full, -EMSGSIZE if name is too long
 */
int senml_add_bool(struct senml_pack *_Nullable pack,
		   const char *_Nullable name,
		   bool value);

/**
 * @brief Add a string record to the pack.
 *
 * @param[in,out] pack  SenML pack
 * @param[in]     name  Record name (e.g., "content" or "type")
 * @param[in]     value String value (vs field)
 * @return 0 on success, -ENOMEM if pack is full, -EMSGSIZE if name or value is
 *         too long
 */
int senml_add_string(struct senml_pack *_Nonnull pack,
		    const char *_Nonnull name,
		    const char *_Nullable value);

/**
 * @brief Add a binary data record to the pack.
 *
 * The data is borrowed until senml_encode_cbor() returns. A NULL pointer is
 * valid only when data_len is zero.
 */
int senml_add_data(struct senml_pack *_Nullable pack,
		   const char *_Nullable name,
		   const uint8_t *_Nullable data, size_t data_len);

/**
 * @brief Encode SenML pack to CBOR.
 *
 * @param[in]  pack    SenML pack to encode
 * @param[out] buf     Output buffer
 * @param[in]  buflen  Buffer size
 * @return Bytes written, or negative error code:
 *         -EINVAL if pack has no records
 *         -ENOMEM if buffer too small
 *         -EMSGSIZE if string too long to encode
 */
LICHEN_WARN_UNUSED_RESULT
int senml_encode_cbor(const struct senml_pack *_Nonnull pack,
		      uint8_t *_Nonnull buf, size_t buflen);

/** Complete RFC 8428 record returned by senml_decode_cbor(). */
struct senml_decoded_record {
	struct senml_span base_name;
	struct senml_span base_unit;
	struct senml_span name;
	struct senml_span unit;
	struct senml_span string_value;
	struct senml_span data_value;
	double base_time;
	double base_value;
	double base_sum;
	double value;
	double sum;
	double time;
	double update_time;
	uint8_t base_version;
	bool bool_value;
	bool has_base_name;
	bool has_base_time;
	bool has_base_unit;
	bool has_base_value;
	bool has_base_sum;
	bool has_base_version;
	bool has_name;
	bool has_unit;
	bool has_value;
	bool has_sum;
	bool has_time;
	bool has_update_time;
	enum senml_value_type value_type;
};

/** Fixed-capacity, allocation-free decoded SenML pack. */
struct senml_decoded_pack {
	struct senml_decoded_record records[SENML_MAX_RECORDS];
	size_t record_count;
};

/**
 * @brief Decode a definite-length SenML-CBOR pack.
 *
 * Text and binary spans borrow from @p buf, which must remain valid while the
 * decoded pack is used. The decoder rejects duplicate standard labels,
 * multiple value fields, invalid UTF-8/types, non-finite numbers, oversized
 * strings/data, excessive record counts, nesting, trailing bytes, and integer
 * or length overflow. On error, pack->record_count is zero.
 *
 * @return 0 on success, -EINVAL for malformed input, -EMSGSIZE for a bounded
 *         field violation, or -ENOMEM when the record capacity is exceeded.
 */
int senml_decode_cbor(const uint8_t *_Nullable buf, size_t buflen,
		      struct senml_decoded_pack *_Nullable pack);

 /* --------------------------------------------------------------------------
 * Convenience functions for common sensor types
 * -------------------------------------------------------------------------- */


/**
 * @brief Encode location as SenML.
 *
 * @param[in]  base_name  Base name or NULL
 * @param[in]  base_time  Unix timestamp (0 valid for epoch)
 * @param[in]  lat        Latitude (WGS84 degrees)
 * @param[in]  lon        Longitude (WGS84 degrees)
 * @param[in]  alt        Altitude (meters) or NAN to omit
 * @param[out] buf        Output buffer
 * @param[in]  buflen     Buffer size
 * @return Bytes written, or negative error code
 */
LICHEN_WARN_UNUSED_RESULT
int senml_encode_location(const char *_Nullable base_name, uint64_t base_time,
			  float lat, float lon, float alt,
			  uint8_t *_Nonnull buf, size_t buflen);


/**
 * @brief Encode full location as SenML, including optional fields.
 *
 * Optional fields (alt, speed, heading, hacc, vacc) are included only when
 * not NaN. Pass NAN to omit a field.
 *
 * @param[in]  base_name  Base name or NULL
 * @param[in]  base_time  Unix timestamp (0 valid for epoch)
 * @param[in]  lat        Latitude (WGS84 degrees)
 * @param[in]  lon        Longitude (WGS84 degrees)
 * @param[in]  alt        Altitude (meters) or NAN to omit
 * @param[in]  speed      Ground speed (m/s) or NAN to omit
 * @param[in]  heading    Heading (degrees, 0=N) or NAN to omit
 * @param[in]  hacc       Horizontal accuracy (meters) or NAN to omit
 * @param[in]  vacc       Vertical accuracy (meters) or NAN to omit
 * @param[out] buf        Output buffer
 * @param[in]  buflen     Buffer size
 * @return Bytes written, or negative error code
 */
LICHEN_WARN_UNUSED_RESULT
int senml_encode_location_full(const char *_Nullable base_name, uint64_t base_time,
			       float lat, float lon, float alt,
			       float speed, float heading,
			       float hacc, float vacc,
			       uint8_t *_Nonnull buf, size_t buflen);

/**
 * @brief Encode battery status as SenML.
 *
 * @param[in]  base_name  Base name or NULL
 * @param[in]  base_time  Unix timestamp (0 valid for epoch)
 * @param[in]  percent    State of charge (0-100)
 * @param[in]  mv         Battery voltage in millivolts
 * @param[in]  charging   True if charging
 * @param[out] buf        Output buffer
 * @param[in]  buflen     Buffer size
 * @return Bytes written, or negative error code
 */
LICHEN_WARN_UNUSED_RESULT
int senml_encode_battery(const char *_Nullable base_name, uint64_t base_time,
			 uint8_t percent, uint16_t mv, bool charging,
			 uint8_t *_Nonnull buf, size_t buflen);

/**
 * @brief Encode temperature as SenML.
 *
 * @param[in]  base_name  Base name or NULL
 * @param[in]  base_time  Unix timestamp (0 valid for epoch)
 * @param[in]  temp_c     Temperature in Celsius
 * @param[out] buf        Output buffer
 * @param[in]  buflen     Buffer size
 * @return Bytes written, or negative error code
 */
LICHEN_WARN_UNUSED_RESULT
int senml_encode_temperature(const char *_Nullable base_name, uint64_t base_time,
			     float temp_c,
			     uint8_t *_Nonnull buf, size_t buflen);
LICHEN_WARN_UNUSED_RESULT
int senml_encode_deaddrop(const char *_Nullable base_name, uint64_t base_time,
			  uint16_t pending,
			  uint8_t *_Nonnull buf, size_t buflen);
#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SENML_H_ */
