/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_handoff.h
 * @brief Node handoff protocol for multi-gateway coordination (GCP-7)
 *
 * Per spec section 08-gateway-coordination.md GCP-7, when a node moves
 * between gateways (detected via better parent/RSSI):
 *
 * 1. Node sends DAO to new Gateway B
 * 2. B sends POST /handoff to A (via backbone) with node details
 * 3. A releases node from its registry, sends confirmation
 * 4. B confirms handoff to node via CoAP
 * 5. Routes updated in RPL DODAG
 *
 * State transferred includes:
 * - Node IPv6 address (derived from Ed25519 IID)
 * - Recent sequence numbers (DAO, OSCORE sender/recipient)
 * - Security contexts (OSCORE parameters, replay windows)
 * - Path sequence and freshness state
 *
 * SECURITY: Handoff messages MUST be authenticated via OSCORE. Unauthenticated
 * handoff requests enable node hijacking attacks.
 *
 * SECURITY: Sequence numbers MUST be transferred accurately. Gaps cause replay
 * acceptance; duplicates cause legitimate messages to be rejected. The receiving
 * gateway MUST use a sequence number strictly greater than the transferred value.
 */

#ifndef LICHEN_COAP_HANDOFF_H_
#define LICHEN_COAP_HANDOFF_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <lichen/compiler.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum node registry entries */
#ifndef CONFIG_LICHEN_COAP_HANDOFF_MAX_NODES
#define CONFIG_LICHEN_COAP_HANDOFF_MAX_NODES 32
#endif

/** IPv6 address length */
#define LICHEN_IPV6_ADDR_LEN 16

/** Maximum OSCORE master secret length */
#define LICHEN_HANDOFF_SECRET_LEN 16

/** Maximum OSCORE master salt length */
#define LICHEN_HANDOFF_SALT_LEN 8

/** Maximum OSCORE ID length */
#define LICHEN_HANDOFF_ID_LEN 8

/** Maximum number of parents in handoff state */
#define LICHEN_HANDOFF_MAX_PARENTS 4

/**
 * @brief Handoff reject reason codes (GCP-7)
 *
 * Matches Python HandoffRejectReason enum for wire compatibility.
 */
enum lichen_handoff_reason {
	/** Success (not an error) */
	LICHEN_HANDOFF_SUCCESS = 0,
	/** Node not found in source gateway's registry */
	LICHEN_HANDOFF_NODE_NOT_FOUND = 1,
	/** Node is currently in active communication (retry later) */
	LICHEN_HANDOFF_NODE_BUSY = 2,
	/** Authentication failed (OSCORE verification) */
	LICHEN_HANDOFF_AUTH_FAILED = 3,
	/** Malformed request payload */
	LICHEN_HANDOFF_MALFORMED = 4,
	/** Source gateway internal error */
	LICHEN_HANDOFF_INTERNAL_ERROR = 5,
	/** Rate limited (too many handoff requests) */
	LICHEN_HANDOFF_RATE_LIMITED = 6,
};

/**
 * @brief OSCORE security context state for handoff transfer
 *
 * Contains parameters needed to reconstruct an equivalent security
 * context on the receiving gateway.
 *
 * SECURITY: master_secret is sensitive. This structure should only exist
 * transiently during handoff and MUST be protected by OSCORE transport.
 */
struct lichen_handoff_oscore_state {
	uint8_t master_secret[LICHEN_HANDOFF_SECRET_LEN];
	uint8_t master_salt[LICHEN_HANDOFF_SALT_LEN];
	uint8_t master_salt_len;
	uint8_t sender_id[LICHEN_HANDOFF_ID_LEN];
	uint8_t sender_id_len;
	uint8_t recipient_id[LICHEN_HANDOFF_ID_LEN];
	uint8_t recipient_id_len;
	int32_t algorithm;  /**< COSE algorithm ID */
	uint8_t hashfun[16];  /**< Hash function name (e.g., "SHA-256") */
	uint32_t window_size;
	uint8_t id_context[LICHEN_HANDOFF_ID_LEN];
	uint8_t id_context_len;  /**< 0 if no ID context */
	uint64_t sender_sequence;
	uint32_t replay_index;
	uint32_t replay_bitfield;
	bool valid;  /**< True if OSCORE state is present */
};

/**
 * @brief DAO freshness tracking state for handoff transfer
 */
struct lichen_handoff_freshness {
	uint32_t sequence;
	int64_t active_until;  /**< Microseconds since epoch, -1 if inactive */
	int64_t retain_until;  /**< Microseconds since epoch */
	int64_t updated_at;    /**< Microseconds since epoch */
	bool valid;  /**< True if freshness state is present */
};

/**
 * @brief Handoff request payload (POST /handoff from new gateway to old)
 *
 * Sent by Gateway B (new) to Gateway A (old) to request node state transfer.
 */
struct lichen_handoff_request {
	uint8_t node_address[LICHEN_IPV6_ADDR_LEN];
	uint32_t timestamp;  /**< Unix seconds */
	int32_t rssi;        /**< Last RSSI from node (dBm), or INT32_MIN if absent */
};

/**
 * @brief Handoff response payload (from old gateway to new)
 *
 * On success, contains all state needed for the new gateway to take
 * over responsibility for the node. On failure, contains rejection reason.
 */
struct lichen_handoff_response {
	enum lichen_handoff_reason status;
	char message[64];  /**< Human-readable message (optional) */

	/* State fields (only valid on success) */
	uint8_t node_address[LICHEN_IPV6_ADDR_LEN];
	uint32_t dao_sequence;
	uint32_t path_sequence;
	struct lichen_handoff_oscore_state oscore;
	struct lichen_handoff_freshness freshness;
	uint8_t parents[LICHEN_HANDOFF_MAX_PARENTS][LICHEN_IPV6_ADDR_LEN];
	uint8_t parent_count;
};

/**
 * @brief Node registry entry for handoff protocol
 *
 * Internal state tracked per node in a gateway's registry.
 */
struct lichen_node_entry {
	uint8_t address[LICHEN_IPV6_ADDR_LEN];
	uint32_t dao_sequence;
	uint32_t path_sequence;
	struct lichen_handoff_oscore_state oscore;
	struct lichen_handoff_freshness freshness;
	uint8_t parents[LICHEN_HANDOFF_MAX_PARENTS][LICHEN_IPV6_ADDR_LEN];
	uint8_t parent_count;
	int64_t last_seen;  /**< Microseconds since epoch */
	bool busy;          /**< True if node is in active transaction */
	bool valid;         /**< True if entry is in use */
};

/**
 * @brief Initialize the handoff subsystem.
 *
 * Must be called once at startup. Initializes the node registry.
 *
 * @return 0 on success, negative error code on failure
 */
int lichen_handoff_init(void);

/**
 * @brief Register a node in the gateway's registry.
 *
 * Called when a node joins via this gateway (e.g., after DAO processing).
 *
 * @param[in] address   Node IPv6 address (16 bytes)
 * @param[in] dao_seq   Initial DAO sequence number
 * @param[in] path_seq  Initial path sequence number
 * @return 0 on success, -ENOMEM if registry full, -EINVAL if address NULL
 */
int lichen_handoff_register_node(const uint8_t *_Nonnull address,
				 uint32_t dao_seq, uint32_t path_seq);

/**
 * @brief Unregister a node from the registry.
 *
 * Called when releasing ownership of a node (e.g., during handoff).
 *
 * @param[in] address  Node IPv6 address (16 bytes)
 * @return 0 on success, -ENOENT if not found
 */
int lichen_handoff_unregister_node(const uint8_t *_Nonnull address);

/**
 * @brief Get a node entry from the registry.
 *
 * @param[in]  address  Node IPv6 address (16 bytes)
 * @param[out] entry    Output entry (copied)
 * @return 0 on success, -ENOENT if not found
 */
int lichen_handoff_get_node(const uint8_t *_Nonnull address,
			    struct lichen_node_entry *_Nonnull entry);

/**
 * @brief Update a node's OSCORE state.
 *
 * @param[in] address Node IPv6 address
 * @param[in] oscore  OSCORE state to set
 * @return 0 on success, -ENOENT if not found
 */
int lichen_handoff_set_oscore(const uint8_t *_Nonnull address,
			      const struct lichen_handoff_oscore_state *_Nonnull oscore);

/**
 * @brief Update a node's freshness state.
 *
 * @param[in] address   Node IPv6 address
 * @param[in] freshness Freshness state to set
 * @return 0 on success, -ENOENT if not found
 */
int lichen_handoff_set_freshness(const uint8_t *_Nonnull address,
				 const struct lichen_handoff_freshness *_Nonnull freshness);

/**
 * @brief Mark a node as busy (in active transaction).
 *
 * Prevents handoff while node is communicating.
 *
 * @param[in] address Node IPv6 address
 * @param[in] busy    True to mark busy, false to clear
 * @return 0 on success, -ENOENT if not found
 */
int lichen_handoff_set_busy(const uint8_t *_Nonnull address, bool busy);

/**
 * @brief Process a handoff request from another gateway.
 *
 * Core handoff logic on the source gateway side:
 * 1. Check if node exists in registry
 * 2. Check if node is busy
 * 3. Extract state
 * 4. Remove from registry
 * 5. Return success response with state
 *
 * SECURITY: Caller MUST verify OSCORE authentication before calling.
 * This function assumes the request is from a trusted peer gateway.
 *
 * @param[in]  request  Decoded handoff request
 * @param[out] response Output response (filled on return)
 * @return 0 on success (response.status == SUCCESS), negative on error
 */
int lichen_handoff_process_request(const struct lichen_handoff_request *_Nonnull request,
				   struct lichen_handoff_response *_Nonnull response);

/**
 * @brief Accept a successful handoff response from another gateway.
 *
 * Called on the new gateway after receiving a success response.
 * Registers the node with transferred state, incrementing sequence
 * numbers to prevent replay attacks.
 *
 * SECURITY: The receiving gateway MUST increment sequence numbers
 * before using them to prevent replay attacks from in-flight messages.
 *
 * @param[in] response Successful handoff response from old gateway
 * @return 0 on success, -EINVAL if response not successful or invalid
 */
int lichen_handoff_accept_response(const struct lichen_handoff_response *_Nonnull response);

/**
 * @brief Encode a handoff request to CBOR.
 *
 * @param[in]  request Handoff request to encode
 * @param[out] buf     Output buffer
 * @param[in]  buf_len Buffer size
 * @return Bytes written, or negative error code
 */
int lichen_handoff_encode_request(const struct lichen_handoff_request *_Nonnull request,
				  uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Decode a handoff request from CBOR.
 *
 * @param[in]  buf     CBOR payload
 * @param[in]  buf_len Payload length
 * @param[out] request Output request
 * @return 0 on success, negative error code on failure
 */
int lichen_handoff_decode_request(const uint8_t *_Nonnull buf, size_t buf_len,
				  struct lichen_handoff_request *_Nonnull request);

/**
 * @brief Encode a handoff response to CBOR.
 *
 * @param[in]  response Handoff response to encode
 * @param[out] buf      Output buffer
 * @param[in]  buf_len  Buffer size
 * @return Bytes written, or negative error code
 */
int lichen_handoff_encode_response(const struct lichen_handoff_response *_Nonnull response,
				   uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Decode a handoff response from CBOR.
 *
 * @param[in]  buf      CBOR payload
 * @param[in]  buf_len  Payload length
 * @param[out] response Output response
 * @return 0 on success, negative error code on failure
 */
int lichen_handoff_decode_response(const uint8_t *_Nonnull buf, size_t buf_len,
				   struct lichen_handoff_response *_Nonnull response);

/**
 * @brief List all registered nodes.
 *
 * @param[out] addresses Array to fill with node addresses
 * @param[in]  max_count Maximum entries to return
 * @return Number of nodes in registry
 */
size_t lichen_handoff_list_nodes(uint8_t (*_Nonnull addresses)[LICHEN_IPV6_ADDR_LEN],
				 size_t max_count);

/**
 * @brief Get current node count in registry.
 *
 * @return Number of registered nodes
 */
size_t lichen_handoff_node_count(void);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_HANDOFF_H_ */
