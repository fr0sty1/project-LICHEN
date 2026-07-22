/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_COAP_STATUS_H_
#define LICHEN_COAP_STATUS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_COAP_STATUS_CBOR_MAX_SIZE    256U
#define LICHEN_COAP_NEIGHBORS_CBOR_MAX_SIZE 512U
#define LICHEN_COAP_ROUTES_CBOR_MAX_SIZE    512U

#ifndef CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS
#define CONFIG_LICHEN_COAP_STATUS_MAX_NEIGHBORS 8
#endif

#ifndef CONFIG_LICHEN_COAP_STATUS_MAX_ROUTES
#define CONFIG_LICHEN_COAP_STATUS_MAX_ROUTES 8
#endif

struct lichen_coap_radio_stats {
	uint32_t rx_packets;
	uint32_t tx_packets;
	uint32_t rx_errors;
	uint16_t duty_cycle_pct_x10;
};

struct lichen_coap_dodag_state {
	bool joined;
	uint16_t rank;
	uint8_t parent[16];
	bool has_parent;
	uint8_t root[16];
	bool has_root;
};

struct lichen_coap_time_state {
	bool wall_clock_valid;
	uint32_t unix_time;
	const char *source_class;
	const char *source_name;
	uint32_t age_s;
};

struct lichen_coap_node_status {
	uint32_t uptime_s;
	uint8_t battery_pct;
	bool battery_pct_valid;
	uint16_t battery_mv;
	bool battery_mv_valid;
	uint32_t mem_free_kb;
	struct lichen_coap_time_state time;
	struct lichen_coap_dodag_state dodag;
	struct lichen_coap_radio_stats radio;
	uint16_t txq_cap;
	uint16_t txq_used;
	uint16_t fwd_cap;
	uint16_t fwd_used;
};

enum lichen_coap_trust_level {
	LICHEN_COAP_TRUST_UNKNOWN,
	LICHEN_COAP_TRUST_TOFU,
	LICHEN_COAP_TRUST_DANE,
	LICHEN_COAP_TRUST_VERIFIED,
};

struct lichen_coap_neighbor {
	uint8_t addr[16];
	int16_t rssi_dbm;
	int16_t snr_db_x10;
	uint16_t etx_x10;
	uint32_t last_seen_s;
	enum lichen_coap_trust_level trust;
};

struct lichen_coap_route {
	uint8_t prefix[16];
	uint8_t prefix_len;
	uint8_t via[16];
	uint16_t metric;
	uint32_t lifetime_s;
};

typedef int (*lichen_coap_status_get_cb)(struct lichen_coap_node_status *status);

typedef int (*lichen_coap_neighbors_get_cb)(struct lichen_coap_neighbor *neighbors,
					    size_t max_neighbors);

typedef int (*lichen_coap_routes_get_cb)(struct lichen_coap_route *routes,
					 size_t max_routes,
					 uint8_t default_route[16]);

struct lichen_coap_status_config {
	lichen_coap_status_get_cb status_get;
	lichen_coap_neighbors_get_cb neighbors_get;
	lichen_coap_routes_get_cb routes_get;
};

int lichen_coap_status_init(const struct lichen_coap_status_config *config);
void lichen_coap_status_notify(void);
void lichen_coap_status_neighbors_notify(void);

size_t lichen_coap_encode_status_cbor(uint8_t *buf, size_t buf_size,
				      const struct lichen_coap_node_status *status);

size_t lichen_coap_encode_neighbors_cbor(uint8_t *buf, size_t buf_size,
					 const struct lichen_coap_neighbor *neighbors,
					 size_t count);

size_t lichen_coap_encode_routes_cbor(uint8_t *buf, size_t buf_size,
				      const struct lichen_coap_route *routes,
				      size_t count,
				      const uint8_t *default_route);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_STATUS_H_ */
