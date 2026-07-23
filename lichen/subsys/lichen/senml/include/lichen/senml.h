/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/senml.h
 * @brief SenML CBOR encoder for sensor data (RFC 8428)
 *
 * Provides helpers for encoding sensor readings as SenML over CBOR.
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

/** Maximum unit string length */
#define SENML_MAX_UNIT_LEN 8

/**
 * @brief SenML value type
 */
enum senml_value_type {
	SENML_VALUE_FLOAT,   /**< Floating point value (v) */
	SENML_VALUE_BOOL,    /**< Boolean value (vb) */
	SENML_VALUE_STRING,  /**< String value (vs) */
	SENML_VALUE_DATA,    /**< Binary data (vd) - not yet supported */
};

/**
 * @brief SenML record
 */
	struct senml_record {
	const char *name;          /**< Record name (n) */
	const char *unit;          /**< Unit (u) - may be NULL */
	enum senml_value_type type;
	union {
		float f;           /**< Float value */
		bool b;            /**< Boolean value */
		const char *s;     /**< String value (vs) */
	} value;
	int32_t time_offset;
	bool has_time;
};


/**
 * @brief SenML pack (array of records with common base)
 */
struct senml_pack {
	const char *base_name;     /**< Base name (bn) - may be NULL */
	uint64_t base_time;        /**< Base time (bt) - always included now */
	bool has_base_time;        /**< Include base time */
	struct senml_record records[SENML_MAX_RECORDS];
	size_t record_count;
};

/**
 * @brief Initialize a SenML pack.
 *
 * @param[out] pack       Pack to initialize
 * @param[in]  base_name  Base name (e.g., "urn:dev:mac:0011223344556677:")
 * @param[in]  base_time  Base Unix timestamp (0 is valid epoch)
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
 * @brief Encode SenML pack to CBOR.
 *
 * @param[in]  pack    SenML pack to encode
 * @param[out] buf     Output buffer
 * @param[in]  buflen  Buffer size
 * @return Bytes written, or negative error code:
 *         -EINVAL if pack has no records
 *         -ENOTSUP if record uses unsupported value type (DATA)
 *         -ENOMEM if buffer too small
 *         -EMSGSIZE if string too long to encode
 */
LICHEN_WARN_UNUSED_RESULT
int senml_encode_cbor(const struct senml_pack *_Nonnull pack,
		      uint8_t *_Nonnull buf, size_t buflen);

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
