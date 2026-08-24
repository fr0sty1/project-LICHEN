/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_slot_coord.h
 * @brief Slot Coordination protocol for multi-gateway coordination (GCP-6)
 *
 * Per spec section 08-gateway-coordination.md GCP-6, this implements:
 *
 * - 6.1 Superframe Synchronization: GPS epoch or time master election
 * - 6.2 Slot Allocation: Interleaved or contiguous block modes
 * - 6.3 Conflict Resolution: Lowest IID wins, signature validation
 * - 6.4 CoAP Resources: /info, /slots, /channels
 *
 * SECURITY: All slot-claim messages MUST be signed with Schnorr48.
 * Claims with invalid or missing signatures MUST be silently discarded.
 */

#ifndef LICHEN_COAP_SLOT_COORD_H_
#define LICHEN_COAP_SLOT_COORD_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <lichen/compiler.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum gateways in a federation */
#ifndef CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS
#define CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS 8
#endif

/** Maximum slots per superframe */
#ifndef CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS
#define CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS 60
#endif

/** Default superframe duration in seconds */
#define LICHEN_SUPERFRAME_DURATION_S 60

/** Default slots per superframe */
#define LICHEN_SLOTS_PER_SUPERFRAME 60

/** Default slot duration in milliseconds */
#define LICHEN_SLOT_DURATION_MS 1000

/** IID length (8 bytes) */
#define LICHEN_IID_LEN 8

/** Schnorr48 signature length */
#define LICHEN_SCHNORR48_LEN 48

/**
 * @brief Time source type for superframe synchronization
 */
enum lichen_time_source {
	/** No time source available */
	LICHEN_TIME_SOURCE_NONE = 0,
	/** GPS epoch (absolute time) */
	LICHEN_TIME_SOURCE_GPS = 1,
	/** Backbone-elected time master */
	LICHEN_TIME_SOURCE_BACKBONE = 2,
	/** Local RTC fallback */
	LICHEN_TIME_SOURCE_LOCAL = 3,
};

/**
 * @brief Slot allocation mode (GCP-6.2)
 */
enum lichen_slot_alloc_mode {
	/** Interleaved: Gateway N owns slots N, N+G, N+2G... where G=gateway_count */
	LICHEN_SLOT_ALLOC_INTERLEAVED = 0,
	/** Contiguous: Each gateway owns sequential block of slots */
	LICHEN_SLOT_ALLOC_CONTIGUOUS = 1,
};

/**
 * @brief Slot claim validation result
 */
enum lichen_claim_result {
	/** Claim accepted */
	LICHEN_CLAIM_ACCEPTED = 0,
	/** Claim rejected: missing signature */
	LICHEN_CLAIM_REJECT_NO_SIG = 1,
	/** Claim rejected: invalid signature */
	LICHEN_CLAIM_REJECT_INVALID_SIG = 2,
	/** Claim rejected: conflict with higher priority gateway */
	LICHEN_CLAIM_REJECT_CONFLICT = 3,
	/** Claim rejected: invalid slot range */
	LICHEN_CLAIM_REJECT_INVALID_SLOTS = 4,
};

/**
 * @brief Gateway slot allocation entry
 */
struct lichen_gateway_alloc {
	uint8_t iid[LICHEN_IID_LEN];     /**< Gateway IID (8 bytes big-endian) */
	uint8_t ordinal;                  /**< Gateway ordinal (0-indexed) */
	uint8_t slots[CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS]; /**< Assigned slots */
	uint8_t slot_count;               /**< Number of assigned slots */
	uint32_t superframe_id;           /**< Superframe ID when allocated */
	uint64_t valid_until;             /**< Unix timestamp of allocation expiry */
	bool valid;                       /**< Entry is in use */
};

/**
 * @brief Slot claim message (POST /slots)
 */
struct lichen_slot_claim {
	uint8_t gateway_iid[LICHEN_IID_LEN];
	uint8_t slots[CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS];
	uint8_t slot_count;
	uint32_t superframe_id;
	uint8_t gateway_count;
	uint8_t ordinal;
	uint8_t slot_start;               /**< For contiguous mode */
	uint8_t signature[LICHEN_SCHNORR48_LEN];
	bool has_signature;
};

/**
 * @brief Slot grant response (2.01 Created)
 */
struct lichen_slot_grant {
	uint8_t granted_slots[CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS];
	uint8_t granted_count;
	uint32_t superframe_id;
	uint64_t valid_until;
};

/**
 * @brief Superframe timing context
 */
struct lichen_superframe_ctx {
	enum lichen_time_source time_source;
	uint64_t epoch_unix;              /**< Superframe epoch (Unix seconds) */
	uint32_t duration_s;              /**< Superframe duration in seconds */
	uint32_t slots_per_superframe;
	uint32_t slot_duration_ms;
	uint32_t current_superframe_id;
	uint8_t time_master_iid[LICHEN_IID_LEN];
	bool synced;
};

/**
 * @brief Slot coordination context
 */
struct lichen_slot_coord_ctx {
	uint8_t local_iid[LICHEN_IID_LEN];
	struct lichen_superframe_ctx superframe;
	enum lichen_slot_alloc_mode alloc_mode;
	struct lichen_gateway_alloc gateways[CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS];
	uint8_t gateway_count;
	uint8_t local_ordinal;
	uint8_t local_slots[CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS];
	uint8_t local_slot_count;
	bool initialized;
};

/**
 * @brief Initialize slot coordination subsystem.
 *
 * @param[out] ctx       Slot coordination context
 * @param[in]  local_iid Local gateway's IID (8 bytes)
 * @return 0 on success, negative error code on failure
 */
int lichen_slot_coord_init(struct lichen_slot_coord_ctx *_Nonnull ctx,
			   const uint8_t local_iid[_Nonnull LICHEN_IID_LEN]);

/**
 * @brief Compute superframe ID from Unix timestamp.
 *
 * Formula: superframe_id = unix_timestamp / superframe_duration_s
 *
 * @param[in] ctx       Slot coordination context
 * @param[in] unix_time Unix timestamp in seconds
 * @return Superframe ID
 */
uint32_t lichen_slot_coord_superframe_id(const struct lichen_slot_coord_ctx *_Nonnull ctx,
					 uint64_t unix_time);

/**
 * @brief Compute current slot within superframe.
 *
 * Formula: current_slot = (timestamp - superframe_start) % slots_per_superframe
 *
 * @param[in] ctx       Slot coordination context
 * @param[in] unix_time Unix timestamp in seconds
 * @return Current slot index (0 to slots_per_superframe-1)
 */
uint8_t lichen_slot_coord_current_slot(const struct lichen_slot_coord_ctx *_Nonnull ctx,
				       uint64_t unix_time);

/**
 * @brief Compare two IIDs as unsigned big-endian 64-bit integers.
 *
 * Per GCP-6.3: lowest IID wins in conflict resolution.
 *
 * @param[in] iid_a First IID (8 bytes)
 * @param[in] iid_b Second IID (8 bytes)
 * @return -1 if a < b, 0 if equal, +1 if a > b
 */
int lichen_iid_compare(const uint8_t iid_a[_Nonnull LICHEN_IID_LEN],
		       const uint8_t iid_b[_Nonnull LICHEN_IID_LEN]);

/**
 * @brief Elect time master from gateway candidates.
 *
 * Per GCP-6.1: lowest IID wins for non-GPS gateways.
 * GPS-equipped gateways are preferred.
 *
 * @param[in]  ctx        Slot coordination context
 * @param[out] master_iid Output IID of elected master
 * @return 0 on success, -ENOENT if no candidates
 */
int lichen_slot_coord_elect_time_master(struct lichen_slot_coord_ctx *_Nonnull ctx,
					uint8_t master_iid[_Nonnull LICHEN_IID_LEN]);

/**
 * @brief Compute interleaved slot allocation.
 *
 * Per GCP-6.2: Gateway with ordinal N owns slots N, N+G, N+2G...
 * where G = gateway_count.
 *
 * @param[in]  ordinal       Gateway ordinal (0-indexed)
 * @param[in]  gateway_count Total number of gateways
 * @param[in]  num_slots     Slots per superframe
 * @param[out] slots         Output slot array
 * @param[in]  max_slots     Maximum slots in output array
 * @return Number of slots assigned, or negative error
 */
int lichen_slot_coord_interleaved(uint8_t ordinal, uint8_t gateway_count,
				  uint8_t num_slots, uint8_t *_Nonnull slots,
				  size_t max_slots);

/**
 * @brief Compute contiguous block slot allocation.
 *
 * Per GCP-6.2: Each gateway owns sequential block of slots.
 *
 * @param[in]  ordinal       Gateway ordinal (0-indexed)
 * @param[in]  gateway_count Total number of gateways
 * @param[in]  num_slots     Slots per superframe
 * @param[out] slot_start    Output start slot
 * @param[out] slot_count    Output slot count
 * @return 0 on success, negative error
 */
int lichen_slot_coord_contiguous(uint8_t ordinal, uint8_t gateway_count,
				 uint8_t num_slots, uint8_t *_Nonnull slot_start,
				 uint8_t *_Nonnull slot_count);

/**
 * @brief Validate interleaved slot pattern.
 *
 * Checks: slots[i] == ordinal + i * gateway_count
 *
 * @param[in] slots         Slot array to validate
 * @param[in] slot_count    Number of slots
 * @param[in] ordinal       Expected ordinal
 * @param[in] gateway_count Expected gateway count
 * @return true if pattern is valid
 */
bool lichen_slot_coord_validate_interleaved(const uint8_t *_Nonnull slots,
					    uint8_t slot_count,
					    uint8_t ordinal,
					    uint8_t gateway_count);

/**
 * @brief Check if transmission is allowed in current slot.
 *
 * @param[in] ctx          Slot coordination context
 * @param[in] current_slot Current slot index
 * @return true if transmission allowed
 */
bool lichen_slot_coord_tx_allowed(const struct lichen_slot_coord_ctx *_Nonnull ctx,
				  uint8_t current_slot);

/**
 * @brief Process incoming slot claim.
 *
 * Per GCP-6.3:
 * - Claims with missing/invalid signatures MUST be silently discarded
 * - Overlapping claims: lowest IID wins
 * - Loser must select next available slot and re-claim
 *
 * SECURITY: Signature verification is mandatory.
 *
 * @param[in]  ctx    Slot coordination context
 * @param[in]  claim  Incoming slot claim
 * @param[out] grant  Output grant response (if accepted)
 * @return Claim result code
 */
enum lichen_claim_result lichen_slot_coord_process_claim(
	struct lichen_slot_coord_ctx *_Nonnull ctx,
	const struct lichen_slot_claim *_Nonnull claim,
	struct lichen_slot_grant *_Nonnull grant);

/**
 * @brief Resolve slot conflict between two claims.
 *
 * Per GCP-6.3: If both signatures verify, lowest IID wins.
 * If one signature fails, valid claim wins regardless of IID.
 *
 * @param[in] claim_a First claim
 * @param[in] sig_a_valid True if claim_a signature verified
 * @param[in] claim_b Second claim
 * @param[in] sig_b_valid True if claim_b signature verified
 * @return Pointer to winning claim, or NULL if both invalid
 */
const struct lichen_slot_claim *_Nullable lichen_slot_coord_resolve_conflict(
	const struct lichen_slot_claim *_Nonnull claim_a, bool sig_a_valid,
	const struct lichen_slot_claim *_Nonnull claim_b, bool sig_b_valid);

/**
 * @brief Find next available slots after conflict.
 *
 * Per GCP-6.3: Loser MUST select next available slot.
 *
 * @param[in]  ctx             Slot coordination context
 * @param[in]  slot_count      Number of slots needed
 * @param[out] available_slots Output available slot array
 * @param[in]  max_slots       Maximum slots in output array
 * @return Number of available slots found, or negative error
 */
int lichen_slot_coord_find_available(const struct lichen_slot_coord_ctx *_Nonnull ctx,
				     uint8_t slot_count, uint8_t *_Nonnull available_slots,
				     size_t max_slots);

/**
 * @brief Register a gateway in the slot allocation table.
 *
 * @param[in] ctx         Slot coordination context
 * @param[in] iid         Gateway IID
 * @param[in] ordinal     Gateway ordinal
 * @param[in] slots       Assigned slots
 * @param[in] slot_count  Number of slots
 * @param[in] superframe_id Superframe when allocated
 * @return 0 on success, -ENOMEM if table full
 */
int lichen_slot_coord_register_gateway(struct lichen_slot_coord_ctx *_Nonnull ctx,
				       const uint8_t iid[_Nonnull LICHEN_IID_LEN],
				       uint8_t ordinal, const uint8_t *_Nonnull slots,
				       uint8_t slot_count, uint32_t superframe_id);

/**
 * @brief Encode slot claim to CBOR.
 *
 * @param[in]  claim   Slot claim to encode
 * @param[out] buf     Output buffer
 * @param[in]  buf_len Buffer size
 * @return Bytes written, or negative error code
 */
int lichen_slot_coord_encode_claim(const struct lichen_slot_claim *_Nonnull claim,
				   uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Decode slot claim from CBOR.
 *
 * @param[in]  buf     CBOR payload
 * @param[in]  buf_len Payload length
 * @param[out] claim   Output claim
 * @return 0 on success, negative error code on failure
 */
int lichen_slot_coord_decode_claim(const uint8_t *_Nonnull buf, size_t buf_len,
				   struct lichen_slot_claim *_Nonnull claim);

/**
 * @brief Encode slot grant to CBOR.
 *
 * @param[in]  grant   Slot grant to encode
 * @param[out] buf     Output buffer
 * @param[in]  buf_len Buffer size
 * @return Bytes written, or negative error code
 */
int lichen_slot_coord_encode_grant(const struct lichen_slot_grant *_Nonnull grant,
				   uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Decode slot grant from CBOR.
 *
 * @param[in]  buf     CBOR payload
 * @param[in]  buf_len Payload length
 * @param[out] grant   Output grant
 * @return 0 on success, negative error code on failure
 */
int lichen_slot_coord_decode_grant(const uint8_t *_Nonnull buf, size_t buf_len,
				   struct lichen_slot_grant *_Nonnull grant);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_SLOT_COORD_H_ */
