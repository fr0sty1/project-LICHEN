/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/udp_port_dispatch.h>

#include <stddef.h>
#include <stdint.h>

#define UDP_HEADER_LEN 8u

static uint16_t read_be16(const uint8_t *data)
{
	return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

int lichen_udp_port_classify(uint16_t destination_port,
			     struct lichen_udp_port_info *info)
{
	struct lichen_udp_port_info result;

	if (info == NULL) {
		return LICHEN_UDP_DISPATCH_ERR_INVALID;
	}
	switch (destination_port) {
	case LICHEN_UDP_PORT_COMPACT_COT:
		result = (struct lichen_udp_port_info){ LICHEN_UDP_APP_COMPACT_COT,
							 LICHEN_UDP_TRANSPORT_RAW };
		break;
	case LICHEN_UDP_PORT_SENML:
		result = (struct lichen_udp_port_info){ LICHEN_UDP_APP_SENML,
							 LICHEN_UDP_TRANSPORT_RAW };
		break;
	case LICHEN_UDP_PORT_COAP:
		result = (struct lichen_udp_port_info){ LICHEN_UDP_APP_COAP,
							 LICHEN_UDP_TRANSPORT_COAP };
		break;
	case LICHEN_UDP_PORT_COAPS_RESERVED:
		result = (struct lichen_udp_port_info){ LICHEN_UDP_APP_RESERVED_DTLS,
							 LICHEN_UDP_TRANSPORT_UNUSED };
		*info = result;
		return LICHEN_UDP_DISPATCH_ERR_RESERVED;
	case LICHEN_UDP_PORT_CAYENNE_LPP:
		result = (struct lichen_udp_port_info){ LICHEN_UDP_APP_CAYENNE_LPP,
							 LICHEN_UDP_TRANSPORT_RAW };
		break;
	case LICHEN_UDP_PORT_APRS_IS:
		result = (struct lichen_udp_port_info){ LICHEN_UDP_APP_APRS_IS,
							 LICHEN_UDP_TRANSPORT_RAW };
		break;
	case LICHEN_UDP_PORT_NMEA:
		result = (struct lichen_udp_port_info){ LICHEN_UDP_APP_NMEA,
							 LICHEN_UDP_TRANSPORT_RAW };
		break;
	case LICHEN_UDP_PORT_MQTT_SN:
		result = (struct lichen_udp_port_info){ LICHEN_UDP_APP_MQTT_SN,
							 LICHEN_UDP_TRANSPORT_MQTT_SN };
		break;
	default:
		*info = (struct lichen_udp_port_info){ LICHEN_UDP_APP_UNKNOWN,
						       LICHEN_UDP_TRANSPORT_UNKNOWN };
		return LICHEN_UDP_DISPATCH_ERR_UNKNOWN;
	}
	*info = result;
	return LICHEN_UDP_DISPATCH_OK;
}

bool lichen_udp_port_is_schc_568x(uint16_t port)
{
	return port >= 5680u && port <= 5695u;
}

int lichen_udp_mqtt_sn_rule_ports(uint16_t source_port,
				  uint16_t destination_port,
				  enum lichen_udp_mqtt_direction *direction,
				  uint16_t *other_port)
{
	if (direction == NULL || other_port == NULL) {
		return LICHEN_UDP_DISPATCH_ERR_INVALID;
	}
	if (source_port == LICHEN_UDP_PORT_MQTT_SN) {
		*direction = LICHEN_UDP_MQTT_SOURCE;
		*other_port = destination_port;
		return LICHEN_UDP_DISPATCH_OK;
	}
	if (destination_port == LICHEN_UDP_PORT_MQTT_SN) {
		*direction = LICHEN_UDP_MQTT_DESTINATION;
		*other_port = source_port;
		return LICHEN_UDP_DISPATCH_OK;
	}
	return LICHEN_UDP_DISPATCH_ERR_UNKNOWN;
}

int lichen_udp_port_dispatch(const uint8_t *datagram, size_t datagram_len,
			     lichen_udp_dispatch_cb callback, void *user_data)
{
	struct lichen_udp_port_info info;
	uint16_t source_port;
	uint16_t destination_port;
	uint16_t udp_len;
	int ret;

	if (datagram == NULL || callback == NULL) {
		return LICHEN_UDP_DISPATCH_ERR_INVALID;
	}
	if (datagram_len < UDP_HEADER_LEN) {
		return LICHEN_UDP_DISPATCH_ERR_TOO_SHORT;
	}
	source_port = read_be16(&datagram[0]);
	destination_port = read_be16(&datagram[2]);
	udp_len = read_be16(&datagram[4]);
	if (udp_len < UDP_HEADER_LEN || (size_t)udp_len != datagram_len) {
		return LICHEN_UDP_DISPATCH_ERR_BAD_LENGTH;
	}
	if (read_be16(&datagram[6]) == 0) {
		return LICHEN_UDP_DISPATCH_ERR_BAD_CHECKSUM;
	}
	ret = lichen_udp_port_classify(destination_port, &info);
	if (ret != LICHEN_UDP_DISPATCH_OK) {
		return ret;
	}
	return callback(info.app, source_port, destination_port,
			&datagram[UDP_HEADER_LEN], datagram_len - UDP_HEADER_LEN,
			user_data);
}
