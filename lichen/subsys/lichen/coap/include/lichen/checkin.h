/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/checkin.h
 * @brief Check-In / Roll Call codec and service (spec section 18.6)
 *
 * Pure C11 codec and deterministic service logic for the Check-In /
 * Roll Call application per spec/12-apps.md section 18.6. The wire format
 * is canonical CBOR (string keys) matching test/vectors/checkin_rollcall.json.
 *
 * Resources:
 * - POST /checkin          (18.6.1)  -> 2.04 Changed
 * - POST /rollcall         (18.6.2)  -> 2.01 Created
 * - GET  /rollcall/<id>    (18.6.3)  -> 2.05 Content
 * - PUT  /config/checkin   (18.6.4)  scheduled check-in configuration
 *
 * Check-in wire format (18.6.1), canonical key order:
 *
 * ```cbor
 * {
 *   "node": "0200:...:1111",  ; full-notation IPv6 address (tstr, required)
 *   "ts": 1716742800,         ; Unix timestamp (uint, required)
 *   "lat": 37.77,             ; WGS84 latitude (optional, [-90,90] incl.)
 *   "lon": -122.42,           ; WGS84 longitude (optional, [-180,180] incl.)
 *   "status": "ok",           ; "ok"|"help"|"delayed" (required)
 *   "msg": "At checkpoint 2"  ; optional note (tstr)
 * }
 * ```
 *
 * lat/lon are all-or-none; non-finite values are rejected.
 *
 * Roll call request (18.6.2):
 *
 * ```cbor
 * {
 *   "id": "roll-001",         ; tstr or uint (coerced to decimal string)
 *   "from": "0200:...",       ; originator address (optional)
 *   "ts": 1716742800,         ; start time (optional, defaults to now;
 *                             ;  negative or far-future rejected)
 *   "timeout_s": 60           ; 1..604800 (optional, defaults to 60)
 * }
 * ```
 *
 * Roll call status (18.6.3):
 *
 * ```cbor
 * {
 *   "id": "roll-001",
 *   "started": 1716742800,
 *   "timeout_s": 60,
 *   "responded": [ {"node": "...", "ts": ..., "status": "ok"}, ... ],
 *   "missing":   [ {"node": "...", "last_seen": ...}, ... ]
 * }
 * ```
 *
 * Scheduled check-in configuration (18.6.4):
 *
 * ```cbor
 * {
 *   "enabled": true,
 *   "target": "0200:...",      ; full-notation IPv6 address (tstr)
 *   "interval_s": 900,         ; uint seconds between check-ins
 *   "include_location": true   ; optional, default false
 * }
 * ```
 *
 * Service capacity is caller-provisioned: the host conformance suite runs at
 * the oracle capacity (256 entries per store, see LICHEN_CHECKIN_MAX and
 * LICHEN_ROLLCALL_MAX); constrained deployments provision smaller stores via
 * CONFIG_LICHEN_CHECKIN_* Kconfig defaults in checkin_resource.c. Policies
 * (prune-oldest-by-ts for check-ins, 5.03 for roll-call table full) are
 * capacity independent.
 *
 * Embedded bounds (documented strictness divergences from the Python
 * oracle, which is unbounded): text strings longer than the buffer limits
 * are rejected, not truncated. Roll-call request timeout_s and timestamps
 * must be CBOR unsigned integers (the oracle also accepts integral
 * floats). Unknown or duplicate map keys are rejected (presence.c style).
 *
 * This module is thread-unsafe by design: all state is per-context with no
 * globals. Callers must synchronize access to a shared context.
 */

#ifndef LICHEN_CHECKIN_H_
#define LICHEN_CHECKIN_H_

#include <stddef.h>
#include <stdint.h>
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

/** Full-notation IPv6 address length (39 chars + NUL) */
#define LICHEN_CHECKIN_ADDR_LEN 40

/** Maximum check-in note length (bounded; longer input rejected) */
#define LICHEN_CHECKIN_MSG_MAX 200

/** Maximum roll-call id length (32 chars + NUL) */
#define LICHEN_ROLLCALL_ID_MAX 33

/** Conservative CBOR size bound for a check-in payload */
#define LICHEN_CHECKIN_CBOR_MAX 512

/** Conservative CBOR size bound for a roll-call request */
#define LICHEN_ROLLCALL_REQ_CBOR_MAX 160

/** Conservative CBOR size bound for a roll-call status document (18.6.3) */
#define LICHEN_ROLLCALL_STATUS_CBOR_MAX 5120

/** Conservative CBOR size bound for a scheduled check-in config */
#define LICHEN_CHECKIN_CONFIG_CBOR_MAX 128

/** Oracle capacity for the check-in store (vector checkin_constants) */
#define LICHEN_CHECKIN_MAX 256

/** Oracle capacity for the roll-call table (vector rollcall_constants) */
#define LICHEN_ROLLCALL_MAX 256

/** Tracked responders/missing per roll call (embedded bound) */
#define LICHEN_ROLLCALL_TRACK_MAX 32

/** Maximum roll-call timeout in seconds (vector rollcall_constants) */
#define LICHEN_ROLLCALL_TIMEOUT_MAX_S 604800U

/** Default roll-call timeout in seconds (vector rollcall_constants) */
#define LICHEN_ROLLCALL_TIMEOUT_DEFAULT_S 60U

/**
 * Far-future allowance for roll-call start timestamps (seconds).
 * Timestamps beyond now + this slack are rejected so a roll call can
 * never be created that would not expire (Python oracle: now + 60).
 */
#define LICHEN_ROLLCALL_FUTURE_SLACK_S 60U

/** Inclusive latitude bound (vector checkin_coord_range) */
#define LICHEN_CHECKIN_LAT_MAX 90.0

/** Inclusive longitude bound (vector checkin_coord_range) */
#define LICHEN_CHECKIN_LON_MAX 180.0

/**
 * @brief Check-in status values (spec 18.6.1).
 */
enum lichen_checkin_status {
	LICHEN_CHECKIN_STATUS_OK = 0,      /**< "ok" */
	LICHEN_CHECKIN_STATUS_HELP = 1,    /**< "help" */
	LICHEN_CHECKIN_STATUS_DELAYED = 2, /**< "delayed" */
};

/**
 * @brief CoAP response codes used by the check-in / roll-call resources.
 *
 * Values are CoAP code bytes: class << 5 | detail.
 */
enum lichen_checkin_code {
	LICHEN_CHECKIN_CODE_CREATED = 0x41,     /**< 2.01 Created */
	LICHEN_CHECKIN_CODE_CHANGED = 0x44,     /**< 2.04 Changed */
	LICHEN_CHECKIN_CODE_CONTENT = 0x45,     /**< 2.05 Content */
	LICHEN_CHECKIN_CODE_BAD_REQUEST = 0x80, /**< 4.00 Bad Request */
	LICHEN_CHECKIN_CODE_NOT_FOUND = 0x81,   /**< 4.04 Not Found */
	LICHEN_CHECKIN_CODE_UNAVAILABLE = 0xA3, /**< 5.03 Service Unavailable */
};

/**
 * @brief Codec and validation error codes.
 *
 * These mirror the error strings in test/vectors/checkin_rollcall.json.
 */
enum lichen_checkin_error {
	LICHEN_CHECKIN_OK = 0,
	LICHEN_CHECKIN_ERR_TRUNCATED,        /**< input ended mid-item */
	LICHEN_CHECKIN_ERR_NOT_A_MAP,        /**< top-level item is not a map */
	LICHEN_CHECKIN_ERR_TRAILING_DATA,    /**< bytes after the map */
	LICHEN_CHECKIN_ERR_DUPLICATE_KEY,    /**< duplicate map key */
	LICHEN_CHECKIN_ERR_UNKNOWN_KEY,      /**< unrecognized map key */
	LICHEN_CHECKIN_ERR_UNEXPECTED_TYPE,  /**< field had wrong CBOR type */
	LICHEN_CHECKIN_ERR_OUT_OF_RANGE,     /**< string/value outside limits */
	LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL, /**< output buffer too small */
	LICHEN_CHECKIN_ERR_MISSING_FIELD,    /**< required field absent (generic) */
	LICHEN_CHECKIN_ERR_MISSING_NODE,     /**< missing_required_field_node */
	LICHEN_CHECKIN_ERR_MISSING_TS,       /**< missing_required_field_ts */
	LICHEN_CHECKIN_ERR_MISSING_STATUS,   /**< missing_required_field_status */
	LICHEN_CHECKIN_ERR_INVALID_STATUS,   /**< invalid_status_value */
	LICHEN_CHECKIN_ERR_COORD_PAIR,       /**< incomplete_coordinate_pair */
	LICHEN_CHECKIN_ERR_COORD_RANGE,      /**< coordinate_out_of_range/non-finite */
	LICHEN_CHECKIN_ERR_NODE_FORMAT,      /**< node is not full-notation IPv6 */
	LICHEN_CHECKIN_ERR_INVALID_TS,       /**< negative timestamp */
	LICHEN_CHECKIN_ERR_TS_FUTURE,        /**< timestamp too far in the future */
	LICHEN_CHECKIN_ERR_MISSING_ID,       /**< missing_required_field_id */
	LICHEN_CHECKIN_ERR_INVALID_ID,       /**< id is not tstr/uint */
	LICHEN_CHECKIN_ERR_INVALID_TIMEOUT,  /**< invalid_timeout_value (<= 0) */
	LICHEN_CHECKIN_ERR_TIMEOUT_MAX,      /**< timeout_exceeds_maximum */
};

/**
 * @brief Decoded check-in payload (spec 18.6.1).
 */
struct lichen_checkin {
	char node[LICHEN_CHECKIN_ADDR_LEN];       /**< Node IPv6 address string */
	uint64_t ts;                              /**< Unix timestamp */
	enum lichen_checkin_status status;        /**< Check-in status */
	bool has_location;                        /**< True if lat/lon present */
	double lat;                               /**< Latitude, [-90, 90] */
	double lon;                               /**< Longitude, [-180, 180] */
	bool has_msg;                             /**< True if msg present */
	char msg[LICHEN_CHECKIN_MSG_MAX];         /**< Optional note */
};

/**
 * @brief Decoded roll-call request (spec 18.6.2).
 */
struct lichen_rollcall_req {
	char id[LICHEN_ROLLCALL_ID_MAX];          /**< Roll-call id (int coerced) */
	bool has_from;                            /**< True if from present */
	char from[LICHEN_CHECKIN_ADDR_LEN];       /**< Originator address string */
	bool has_ts;                              /**< True if ts present */
	uint64_t ts;                              /**< Start timestamp */
	bool has_timeout;                         /**< True if timeout_s present */
	uint32_t timeout_s;                       /**< Timeout seconds */
};

/**
 * @brief One responded/missing entry of a roll-call status (18.6.3).
 */
struct lichen_rollcall_track {
	char node[LICHEN_CHECKIN_ADDR_LEN];       /**< Node IPv6 address string */
	uint64_t ts;                              /**< Response time / last seen */
	enum lichen_checkin_status status;        /**< Status (responded only) */
};

/**
 * @brief Decoded roll-call status document (spec 18.6.3).
 */
struct lichen_rollcall_status {
	char id[LICHEN_ROLLCALL_ID_MAX];          /**< Roll-call id */
	uint64_t started;                         /**< Start timestamp */
	uint32_t timeout_s;                       /**< Timeout seconds */
	struct lichen_rollcall_track
		responded[LICHEN_ROLLCALL_TRACK_MAX]; /**< Responded entries */
	size_t responded_count;                   /**< Valid entries in responded */
	struct lichen_rollcall_track
		missing[LICHEN_ROLLCALL_TRACK_MAX];   /**< Missing entries */
	size_t missing_count;                     /**< Valid entries in missing */
};

/**
 * @brief Scheduled check-in configuration (spec 18.6.4).
 */
struct lichen_checkin_config {
	bool enabled;                             /**< Scheduling enabled */
	bool has_target;                          /**< True if target present */
	char target[LICHEN_CHECKIN_ADDR_LEN];     /**< Leader address string */
	uint32_t interval_s;                      /**< Seconds between check-ins */
	bool include_location;                    /**< Attach lat/lon when known */
};

/**
 * @brief A stored check-in: the payload plus its arrival order.
 */
struct lichen_checkin_entry {
	struct lichen_checkin checkin;            /**< Decoded payload */
	uint64_t received_at;                     /**< Service time of last update */
};

/**
 * @brief A stored roll call.
 */
struct lichen_rollcall {
	char id[LICHEN_ROLLCALL_ID_MAX];          /**< Roll-call id */
	uint64_t started;                         /**< Start timestamp */
	uint32_t timeout_s;                       /**< Timeout seconds */
	struct lichen_rollcall_track
		responded[LICHEN_ROLLCALL_TRACK_MAX]; /**< Responded entries */
	size_t responded_count;
	struct lichen_rollcall_track
		missing[LICHEN_ROLLCALL_TRACK_MAX];   /**< Missing entries */
	size_t missing_count;
};

/**
 * @brief Check-in / roll-call service state (spec 18.6).
 *
 * Storage is caller-provisioned and passed to lichen_checkin_service_init().
 * The module keeps no global state; synchronize externally if shared.
 */
struct lichen_checkin_service {
	uint64_t now;                             /**< Current service time (s) */
	struct lichen_checkin_entry *_Nullable checkins;   /**< Check-in store */
	size_t checkin_cap;                       /**< Store capacity */
	size_t checkin_count;                     /**< Used entries */
	struct lichen_rollcall *_Nullable rollcalls; /**< Roll-call table */
	size_t rollcall_cap;                      /**< Table capacity */
	size_t rollcall_count;                    /**< Used entries */
	struct lichen_checkin_config config;      /**< Scheduled check-in config */
	uint64_t last_checkin_at;                 /**< Last scheduled send time */
};

/* ── Status helpers ────────────────────────────────────────────────────── */

/**
 * @brief Get the wire string for a status ("ok"|"help"|"delayed").
 * @return Wire string or NULL if out of range.
 */
const char *_Nullable lichen_checkin_status_str(enum lichen_checkin_status status);

/**
 * @brief Parse a status wire string.
 * @return 0 on success, -LICHEN_CHECKIN_ERR_INVALID_STATUS if unknown.
 */
int lichen_checkin_status_parse(const char *_Nonnull str,
				enum lichen_checkin_status *_Nonnull status);

/**
 * @brief Validate a full-notation IPv6 address string.
 *
 * Requires exactly 8 colon-separated groups of 4 hex digits (39 chars),
 * per the checkin_node_format vector. Case-insensitive on hex digits.
 *
 * @return 0 if valid, -LICHEN_CHECKIN_ERR_NODE_FORMAT otherwise.
 */
int lichen_checkin_addr_valid(const char *_Nonnull addr);

/**
 * @brief Validate a coordinate pair against the inclusive bounds and
 *        finiteness rules of the checkin_coord_range vector.
 * @return 0 if valid, -LICHEN_CHECKIN_ERR_COORD_RANGE otherwise.
 */
int lichen_checkin_coord_valid(double lat, double lon);

/* ── Check-in codec (18.6.1) ───────────────────────────────────────────── */

/**
 * @brief Encode a check-in payload.
 *
 * Canonical key order: node, ts, lat, lon, status, msg; optional fields
 * omitted when absent. Reproduces the oracle cbor_hex byte-for-byte.
 *
 * @return 0 on success, -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL.
 */
int lichen_checkin_to_cbor(const struct lichen_checkin *_Nonnull c,
			   uint8_t *_Nonnull buf, size_t cap, size_t *_Nonnull out_len);

/**
 * @brief Decode and fully validate a check-in payload.
 *
 * Enforces required fields, status values, coordinate pairing, inclusive
 * coordinate bounds, finiteness, node address format, and ts type.
 *
 * @return 0 on success, else enum lichen_checkin_error.
 */
int lichen_checkin_from_cbor(const uint8_t *_Nonnull buf, size_t len,
			     struct lichen_checkin *_Nonnull c);

/* ── Roll-call request codec (18.6.2) ──────────────────────────────────── */

/**
 * @brief Encode a roll-call request.
 * Canonical key order: id, from, ts, timeout_s.
 * @return 0 on success, -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL.
 */
int lichen_rollcall_req_to_cbor(const struct lichen_rollcall_req *_Nonnull r,
				uint8_t *_Nonnull buf, size_t cap, size_t *_Nonnull out_len);

/**
 * @brief Decode and validate a roll-call request (context-free rules).
 *
 * Integer ids are coerced to decimal strings. timeout_s must be a uint in
 * 1..LICHEN_ROLLCALL_TIMEOUT_MAX_S (0/negative: INVALID_TIMEOUT, above max:
 * TIMEOUT_MAX). A present ts must be a non-negative uint; the far-future
 * check needs the service clock and happens in lichen_rollcall_post().
 *
 * @return 0 on success, else enum lichen_checkin_error.
 */
int lichen_rollcall_req_from_cbor(const uint8_t *_Nonnull buf, size_t len,
				  struct lichen_rollcall_req *_Nonnull r);

/* ── Roll-call status codec (18.6.3) ───────────────────────────────────── */

/**
 * @brief Encode a roll-call status document.
 * Canonical key order: id, started, timeout_s, responded, missing.
 * @return 0 on success, -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL.
 */
int lichen_rollcall_status_to_cbor(const struct lichen_rollcall_status *_Nonnull s,
				   uint8_t *_Nonnull buf, size_t cap, size_t *_Nonnull out_len);

/**
 * @brief Decode a roll-call status document.
 *
 * Requires id, started, timeout_s; responded/missing arrays are optional
 * and default to empty. Track entries beyond LICHEN_ROLLCALL_TRACK_MAX are
 * rejected.
 *
 * @return 0 on success, else enum lichen_checkin_error.
 */
int lichen_rollcall_status_from_cbor(const uint8_t *_Nonnull buf, size_t len,
				     struct lichen_rollcall_status *_Nonnull s);

/* ── Scheduled check-in config codec (18.6.4) ──────────────────────────── */

/**
 * @brief Encode a scheduled check-in configuration.
 * Canonical key order: enabled, target, interval_s, include_location.
 * @return 0 on success, -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL.
 */
int lichen_checkin_config_to_cbor(const struct lichen_checkin_config *_Nonnull cfg,
				  uint8_t *_Nonnull buf, size_t cap, size_t *_Nonnull out_len);

/**
 * @brief Decode a scheduled check-in configuration.
 *
 * Structural decode with type validation; policy (e.g. requiring a target
 * before scheduling is honored) is enforced by the service.
 *
 * @return 0 on success, else enum lichen_checkin_error.
 */
int lichen_checkin_config_from_cbor(const uint8_t *_Nonnull buf, size_t len,
				    struct lichen_checkin_config *_Nonnull cfg);

/* ── Service (18.6.1–18.6.4) ───────────────────────────────────────────── */

/**
 * @brief Initialize a service over caller-provided storage.
 *
 * @param[out] svc          Service state
 * @param[in]  checkins     Check-in store array (may be NULL if cap is 0)
 * @param[in]  checkin_cap  Capacity of the check-in store
 * @param[in]  rollcalls    Roll-call table array (may be NULL if cap is 0)
 * @param[in]  rollcall_cap Capacity of the roll-call table
 */
void lichen_checkin_service_init(struct lichen_checkin_service *_Nonnull svc,
				 struct lichen_checkin_entry *_Nullable checkins,
				 size_t checkin_cap,
				 struct lichen_rollcall *_Nullable rollcalls,
				 size_t rollcall_cap);

/**
 * @brief Set the service clock (seconds). Injected for determinism.
 */
void lichen_checkin_service_set_time(struct lichen_checkin_service *_Nonnull svc,
				     uint64_t now);

/**
 * @brief Handle POST /checkin: decode, validate, and store (18.6.1).
 *
 * Stores at most checkin_cap entries; when a NEW node arrives at capacity,
 * the entry with the smallest ts is evicted first (vector prune_policy
 * "remove_oldest_by_ts"). Re-posting an existing node updates in place
 * without eviction.
 *
 * @param[out] detail Codec/validation error, may be NULL
 * @return CoAP code byte: 2.04 Changed or 4.00 Bad Request
 */
uint8_t lichen_checkin_post(struct lichen_checkin_service *_Nonnull svc,
			    const uint8_t *_Nonnull buf, size_t len,
			    enum lichen_checkin_error *_Nullable detail);

/**
 * @brief Handle POST /rollcall: validate and open a roll call (18.6.2).
 *
 * Applies the far-future rule (ts <= now + slack), expiry pruning, the
 * timeout rules, and the capacity rule (a NEW id at full table returns
 * 5.03; an existing id updates in place and returns 2.01). Missing ts
 * defaults to the service clock; missing timeout_s to 60.
 *
 * @param[out] detail Codec/validation error, may be NULL
 * @return 2.01 Created, 4.00 Bad Request, or 5.03 Service Unavailable
 */
uint8_t lichen_rollcall_post(struct lichen_checkin_service *_Nonnull svc,
			     const uint8_t *_Nonnull buf, size_t len,
			     enum lichen_checkin_error *_Nullable detail);

/**
 * @brief Find a live roll call by id (expiry prunes first).
 * @return The entry or NULL if unknown/expired.
 */
struct lichen_rollcall *_Nullable
lichen_rollcall_find(struct lichen_checkin_service *_Nonnull svc,
		     const char *_Nonnull id);

/**
 * @brief Record a node's response to a roll call.
 *
 * Adds or updates the node in the responded list (removed from missing).
 *
 * @return 0 on success, -ENOENT if the roll call is unknown,
 *         -ENOSPC if the track list is full.
 */
int lichen_rollcall_record_responded(struct lichen_rollcall *_Nonnull rc,
				     const struct lichen_rollcall_track *_Nonnull track);

/**
 * @brief Mark a node as missing from a roll call.
 *
 * Adds or updates the node in the missing list (removed from responded).
 *
 * @return 0 on success, -ENOENT if the roll call is unknown,
 *         -ENOSPC if the track list is full.
 */
int lichen_rollcall_record_missing(struct lichen_rollcall *_Nonnull rc,
				   const struct lichen_rollcall_track *_Nonnull track);

/**
 * @brief Encode the 18.6.3 status document of a stored roll call.
 * @return 0 on success, -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL.
 */
int lichen_rollcall_render(const struct lichen_rollcall *_Nonnull rc,
			   uint8_t *_Nonnull buf, size_t cap, size_t *_Nonnull out_len);

/**
 * @brief Encode {"checkins":[...]} for GET /checkin (oracle shape).
 * @return 0 on success, -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL.
 */
int lichen_checkin_list_encode(const struct lichen_checkin_service *_Nonnull svc,
			       uint8_t *_Nonnull buf, size_t cap, size_t *_Nonnull out_len);

/**
 * @brief Encode {"rollcalls":[...]} for GET /rollcall (oracle shape).
 * @return 0 on success, -LICHEN_CHECKIN_ERR_BUFFER_TOO_SMALL.
 */
int lichen_rollcall_list_encode(const struct lichen_checkin_service *_Nonnull svc,
				uint8_t *_Nonnull buf, size_t cap, size_t *_Nonnull out_len);

/**
 * @brief Apply a scheduled check-in configuration (18.6.4).
 */
void lichen_checkin_config_apply(struct lichen_checkin_service *_Nonnull svc,
				 const struct lichen_checkin_config *_Nonnull cfg);

/**
 * @brief Whether a scheduled check-in is due (18.6.4).
 *
 * True when enabled, a target is set, interval_s > 0, and
 * now - last_checkin_at >= interval_s.
 */
bool lichen_checkin_due(const struct lichen_checkin_service *_Nonnull svc);

/**
 * @brief Mark a scheduled check-in as sent at the current service time.
 */
void lichen_checkin_mark_sent(struct lichen_checkin_service *_Nonnull svc);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_CHECKIN_H_ */
