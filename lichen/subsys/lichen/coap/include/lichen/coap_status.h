/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_status.h
 * @brief LCI /status resource handlers (RFC 7641 Observable)
 *
 * Implements the status resources defined in LCI spec section 17.5.3:
 * - GET /status - Node status with uptime, battery, memory, time, DODAG, radio stats
 * - GET /status/neighbors - Neighbor table with RSSI, SNR, ETX
 * - GET /status/routes - Routing table
 *
 * All resources support RFC 7641 Observe for push notifications.
 * CCP-17: capacity validation for CBOR encoders (BUILD_ASSERT + runtime checks).
 */

#ifndef LICHEN_COAP_STATUS_H_
#define LICHEN_COAP_STATUS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum CBOR payload sizes */
#define LICHEN_COAP_STATUS_CBOR_MAX_SIZE    512U
#define LICHEN_COAP_NEIGHBORS_CBOR_MAX_SIZE 512U
#define LICHEN_COAP_ROUTES_CBOR_MAX_SIZE    512U

/* Maximum neighbors/routes in response */
#ifndef CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS
#define CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS 8
#endif

#ifndef CONFIG_LICHEN_COAP_STATUS_MAX_ROUTES
#define CONFIG_LICHEN_COAP_STATUS_MAX_ROUTES 8
#endif

#ifndef CONFIG_LICHEN_COAP_STATUS_MAX_TXQ
#define CONFIG_LICHEN_COAP_STATUS_MAX_TXQ 4
#endif

#ifndef CONFIG_LICHEN_COAP_STATUS_MAX_FWD
#define CONFIG_LICHEN_COAP_STATUS_MAX_FWD 8
#endif

/**
 * @brief Radio statistics for /status endpoint
 */
struct lichen_coap_radio_stats {
	uint32_t rx_packets;
	uint32_t tx_packets;
	uint32_t rx_errors;
	uint16_t duty_cycle_pct_x10; /**< Duty cycle * 10 (e.g., 23 = 2.3%) */
};

/**
 * @brief DODAG state for /status endpoint
 */
struct lichen_coap_dodag_state {
	bool joined;
	uint16_t rank;
	uint8_t parent[16];       /**< Preferred parent IPv6 address (valid if joined) */
	bool has_parent;
	uint8_t root[16];         /**< DODAG root IPv6 address (valid if joined) */
	bool has_root;
};

/**
 * @brief Time state for /status endpoint (per LCI spec)
 */
struct lichen_coap_time_state {
	bool wall_clock_valid;
	uint32_t unix_time;       /**< Unix timestamp (valid if wall_clock_valid) */
	const char *source_class; /**< "gnss", "network", "local-client", etc. */
	const char *source_name;  /**< Human-readable source name */
	uint32_t age_s;           /**< Seconds since last time sample */
};

/**
 * @brief Node status for /status endpoint
 */
struct lichen_coap_node_status {
	uint32_t uptime_s;
	uint8_t battery_pct;         /**< Battery percentage (0-100) */
	bool battery_pct_valid;
	uint16_t battery_mv;         /**< Battery voltage in mV */
	bool battery_mv_valid;
	uint32_t mem_free_kb;
	struct lichen_coap_time_state time;
	struct lichen_coap_dodag_state dodag;
	struct lichen_coap_radio_stats radio;
	uint8_t txq_used;
	uint8_t txq_cap;
	uint8_t fwd_used;
	uint8_t fwd_cap;
};

/**
 * @brief Trust level for neighbors
 */
enum lichen_coap_trust_level {
	LICHEN_COAP_TRUST_UNKNOWN,
	LICHEN_COAP_TRUST_TOFU,       /**< Trust-on-first-use */
	LICHEN_COAP_TRUST_DANE,       /**< DNS-based authentication */
	LICHEN_COAP_TRUST_VERIFIED,   /**< Out-of-band verified */
};

/**
 * @brief Neighbor entry for /status/neighbors endpoint
 */
struct lichen_coap_neighbor {
	uint8_t addr[16];         /**< IPv6 link-local address */
	int16_t rssi_dbm;
	int16_t snr_db_x10;       /**< SNR * 10 (e.g., 75 = 7.5 dB) */
	uint16_t etx_x10;         /**< ETX * 10 (e.g., 12 = 1.2) */
	uint32_t last_seen_s;     /**< Seconds since last heard */
	enum lichen_coap_trust_level trust;
};

/**
 * @brief Route entry for /status/routes endpoint
 */
struct lichen_coap_route {
	uint8_t prefix[16];       /**< IPv6 prefix */
	uint8_t prefix_len;       /**< Prefix length (e.g., 64) */
	uint8_t via[16];          /**< Next-hop IPv6 address */
	uint16_t metric;          /**< Route metric (RPL rank) */
	uint32_t lifetime_s;      /**< Route lifetime in seconds */
};

/**
 * @brief Callback to get current node status
 *
 * Application must implement this to provide current status.
 * Called on each GET /status request.
 *
 * @param[out] status Pointer to status structure to fill
 * @return 0 on success, negative errno on error
 */
typedef int (*lichen_coap_status_get_cb)(struct lichen_coap_node_status *status);

/**
 * @brief Callback to get neighbor table
 *
 * Application must implement this to provide neighbor information.
 *
 * @param[out] neighbors Array to fill with neighbor entries
 * @param[in]  max_neighbors Maximum number of entries to return
 * @return Number of neighbors written, or negative errno on error
 */
typedef int (*lichen_coap_neighbors_get_cb)(struct lichen_coap_neighbor *neighbors,
					    size_t max_neighbors);

/**
 * @brief Callback to get routing table
 *
 * Application must implement this to provide routing information.
 *
 * @param[out] routes Array to fill with route entries
 * @param[in]  max_routes Maximum number of entries to return
 * @param[out] default_route Default route next-hop IPv6 (filled only if *has_default_route)
 * @param[out] has_default_route Set to true if default_route was populated (non-fragile, no byte scan)
 * @return Number of routes written, or negative errno on error
 */
typedef int (*lichen_coap_routes_get_cb)(struct lichen_coap_route *routes,
					 size_t max_routes,
					 uint8_t default_route[16],
					 bool *has_default_route);

/**
 * @brief Status resource configuration
 */
struct lichen_coap_status_config {
	lichen_coap_status_get_cb status_get;
	lichen_coap_neighbors_get_cb neighbors_get;
	lichen_coap_routes_get_cb routes_get;
};

/**
 * @brief Initialize status resource handlers with callbacks
 *
 * Must be called before the CoAP service starts.
 *
 * @param config Configuration with callbacks
 * @return 0 on success, -EINVAL if config or required callbacks are NULL
 */
int lichen_coap_status_init(const struct lichen_coap_status_config *config);

/**
 * @brief Trigger status update notification to observers
 *
 * Call this when status changes significantly (battery level change,
 * DODAG state change, etc.) to push updates to Observe clients.
 */
void lichen_coap_status_notify(void);

/**
 * @brief Trigger neighbor table notification to observers
 */
void lichen_coap_status_neighbors_notify(void);

/**
 * @brief Trigger route table notification to observers
 */
void lichen_coap_status_routes_notify(void);

/**
 * @brief Encode node status to CBOR
 *
 * @param[out] buf Output buffer
 * @param[in]  buf_size Buffer size
 * @param[in]  status Status to encode
 * @return Encoded byte count, or 0 on error
 */
size_t lichen_coap_encode_status_cbor(uint8_t *buf, size_t buf_size,
				      const struct lichen_coap_node_status *status);

/**
 * @brief Encode neighbor table to CBOR
 *
 * @param[out] buf Output buffer
 * @param[in]  buf_size Buffer size
 * @param[in]  neighbors Array of neighbors
 * @param[in]  count Number of neighbors
 * @return Encoded byte count, or 0 on error
 */
size_t lichen_coap_encode_neighbors_cbor(uint8_t *buf, size_t buf_size,
					 const struct lichen_coap_neighbor *neighbors,
					 size_t count);

/**
 * @brief Encode routing table to CBOR
 *
 * @param[out] buf Output buffer
 * @param[in]  buf_size Buffer size
 * @param[in]  routes Array of routes
 * @param[in]  count Number of routes
 * @param[in]  default_route Default route next-hop (16 bytes, or NULL)
 * @return Encoded byte count, or 0 on error
 */
size_t lichen_coap_encode_routes_cbor(uint8_t *buf, size_t buf_size,
				      const struct lichen_coap_route *routes,
				      size_t count,
				      const uint8_t *default_route);

/**
 * @brief Shared helper to format IPv6 address to string
 *
 * Used by both coap_status.c and coap_msg.c. Uses net_addr_ntop for
 * standard compressed IPv6 format (no snprintf truncation issues).
 *
 * @param addr 16-byte IPv6 address
 * @param buf Output buffer (recommend >=46 bytes)
 * @param buf_size Size of buf
 * @return 0 on success, -ENOBUFS on buffer error
 */
int lichen_coap_format_ipv6(const uint8_t *addr, char *buf, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_STATUS_H_ */
