/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_UDP_PORT_DISPATCH_H_
#define LICHEN_UDP_PORT_DISPATCH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_UDP_PORT_COMPACT_COT 5681u
#define LICHEN_UDP_PORT_SENML 5682u
#define LICHEN_UDP_PORT_COAP 5683u
#define LICHEN_UDP_PORT_COAPS_RESERVED 5684u
#define LICHEN_UDP_PORT_CAYENNE_LPP 5685u
#define LICHEN_UDP_PORT_APRS_IS 5686u
#define LICHEN_UDP_PORT_NMEA 5687u
#define LICHEN_UDP_PORT_MQTT_SN 10883u

#define LICHEN_UDP_DISPATCH_OK 0
#define LICHEN_UDP_DISPATCH_ERR_INVALID -1
#define LICHEN_UDP_DISPATCH_ERR_TOO_SHORT -2
#define LICHEN_UDP_DISPATCH_ERR_BAD_LENGTH -3
#define LICHEN_UDP_DISPATCH_ERR_BAD_CHECKSUM -4
#define LICHEN_UDP_DISPATCH_ERR_RESERVED -5
#define LICHEN_UDP_DISPATCH_ERR_UNKNOWN -6

enum lichen_udp_app_protocol {
	LICHEN_UDP_APP_UNKNOWN = 0,
	LICHEN_UDP_APP_COMPACT_COT,
	LICHEN_UDP_APP_SENML,
	LICHEN_UDP_APP_COAP,
	LICHEN_UDP_APP_RESERVED_DTLS,
	LICHEN_UDP_APP_CAYENNE_LPP,
	LICHEN_UDP_APP_APRS_IS,
	LICHEN_UDP_APP_NMEA,
	LICHEN_UDP_APP_MQTT_SN,
};

enum lichen_udp_transport {
	LICHEN_UDP_TRANSPORT_UNKNOWN = 0,
	LICHEN_UDP_TRANSPORT_RAW,
	LICHEN_UDP_TRANSPORT_COAP,
	LICHEN_UDP_TRANSPORT_UNUSED,
	LICHEN_UDP_TRANSPORT_MQTT_SN,
};

enum lichen_udp_mqtt_direction {
	/* Canonical Rule 7 PortDirection values from spec/03-adaptation.md. */
	LICHEN_UDP_MQTT_SOURCE = 0,
	LICHEN_UDP_MQTT_DESTINATION = 1,
};

struct lichen_udp_port_info {
	enum lichen_udp_app_protocol app;
	enum lichen_udp_transport transport;
};

typedef int (*lichen_udp_dispatch_cb)(enum lichen_udp_app_protocol app,
				      uint16_t source_port,
				      uint16_t destination_port,
				      const uint8_t *payload,
				      size_t payload_len,
				      void *user_data);

/** Classify one destination port from the normative LICHEN allocation. */
int lichen_udp_port_classify(uint16_t destination_port,
			     struct lichen_udp_port_info *info);

/** True for the full SCHC MSB(12) match range, including unassigned ports. */
bool lichen_udp_port_is_schc_568x(uint16_t port);

/**
 * Derive canonical SCHC Rule 7 port residue fields.
 *
 * Either endpoint may be 10883.  When both are 10883, source direction is
 * canonical.  Returns ERR_UNKNOWN when neither endpoint is MQTT-SN.
 */
int lichen_udp_mqtt_sn_rule_ports(uint16_t source_port,
				  uint16_t destination_port,
				  enum lichen_udp_mqtt_direction *direction,
				  uint16_t *other_port);

/**
 * Parse and dispatch one complete UDP datagram (header plus payload).
 *
 * UDP integers are decoded in network byte order.  Application selection is
 * strictly by destination port; a known source port never claims a datagram
 * addressed to an unknown destination.  IPv6 pseudo-header checksum
 * verification remains the caller's responsibility, but the mandatory UDP
 * checksum field must be nonzero.  The callback's return value is propagated.
 */
int lichen_udp_port_dispatch(const uint8_t *datagram, size_t datagram_len,
			     lichen_udp_dispatch_cb callback, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_UDP_PORT_DISPATCH_H_ */
