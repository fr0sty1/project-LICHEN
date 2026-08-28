/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_internal.h
 * @brief Internal declarations shared between SCHC split source files.
 *
 * This header is NOT part of the public API. It provides shared constants,
 * layout enums, and helper function declarations for the split SCHC
 * implementation files.
 */

#ifndef SCHC_INTERNAL_H_
#define SCHC_INTERNAL_H_

#include <lichen/schc.h>
#include <schc/bitstream.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IPv6 protocol constants */
#define IPV6_NH_UDP             17   /* UDP next header (RFC 768) */
#define IPV6_NH_ICMPV6          58   /* ICMPv6 next header (RFC 4443) */
#define IPV6_HDR_LEN            40   /* IPv6 base header length */
#define UDP_HDR_LEN             8    /* UDP header length */
#define MQTT_SN_PORT            10883 /* MQTT-SN assigned UDP port */
#define ICMPV6_TYPE_ECHO_REQUEST 128 /* Echo Request (RFC 4443) */
#define ICMPV6_TYPE_ECHO_REPLY  129  /* Echo Reply (RFC 4443) */
#define ICMPV6_TYPE_RPL         155  /* RPL ICMPv6 type (RFC 6550) */
#define ICMPV6_CODE_RPL_DIO     1    /* RPL DIO code (RFC 6550) */
#define ICMPV6_CODE_RPL_DAO     2    /* RPL DAO code (RFC 6550) */

/* OSCORE option number (RFC 8613) */
#define COAP_OPTION_OSCORE 9

/*
 * Packet-layout constants.
 *
 * These compile-time constants document the offsets implied by the profile
 * code below. Rule code should use accessors built on these names instead of
 * repeating numbers such as 40, 44, or 45.
 */
enum schc_ipv6_layout {
	SCHC_IPV6_VERSION_OFFSET = 0,
	SCHC_IPV6_TC_FLOW_OFFSET = 1,
	SCHC_IPV6_TC_FLOW_LEN = 3,
	SCHC_IPV6_PAYLOAD_LEN_OFFSET = 4,
	SCHC_IPV6_NEXT_HEADER_OFFSET = 6,
	SCHC_IPV6_HOP_LIMIT_OFFSET = 7,
	SCHC_IPV6_SRC_OFFSET = 8,
	SCHC_IPV6_DST_OFFSET = 24,
	SCHC_IPV6_ADDR_LEN = 16,
};

enum schc_udp_layout {
	SCHC_UDP_SRC_PORT_OFFSET = 0,
	SCHC_UDP_DST_PORT_OFFSET = 2,
	SCHC_UDP_LEN_OFFSET = 4,
	SCHC_UDP_CHECKSUM_OFFSET = 6,
	SCHC_UDP_PAYLOAD_OFFSET = UDP_HDR_LEN,
};

enum schc_coap_layout {
	SCHC_COAP_VER_TYPE_TKL_OFFSET = 0,
	SCHC_COAP_CODE_OFFSET = 1,
	SCHC_COAP_MID_OFFSET = 2,
	SCHC_COAP_FIXED_LEN = 4,
};

enum schc_icmpv6_layout {
	SCHC_ICMPV6_TYPE_OFFSET = 0,
	SCHC_ICMPV6_CODE_OFFSET = 1,
	SCHC_ICMPV6_CHECKSUM_OFFSET = 2,
	SCHC_ICMPV6_BODY_OFFSET = 4,
	SCHC_ICMPV6_ECHO_ID_OFFSET = 4,
	SCHC_ICMPV6_ECHO_SEQ_OFFSET = 6,
	SCHC_ICMPV6_ECHO_TAIL_OFFSET = 8,
};

enum schc_rpl_layout {
	SCHC_RPL_AFTER_IPV6_OFFSET = IPV6_HDR_LEN + SCHC_ICMPV6_BODY_OFFSET,
	SCHC_RPL_INSTANCE_OFFSET = 0,
	SCHC_RPL_DIO_VERSION_OFFSET = 1,
	SCHC_RPL_DIO_RANK_OFFSET = 2,
	SCHC_RPL_DIO_GMOP_OFFSET = 4,
	SCHC_RPL_DIO_DTSN_OFFSET = 5,
	SCHC_RPL_DIO_FLAGS_OFFSET = 6,
	SCHC_RPL_DIO_RESERVED_OFFSET = 7,
	SCHC_RPL_DIO_DODAGID_OFFSET = 8,
	SCHC_RPL_DIO_BASE_LEN = 24,
	SCHC_RPL_DAO_KD_FLAGS_OFFSET = 1,
	SCHC_RPL_DAO_RESERVED_OFFSET = 2,
	SCHC_RPL_DAO_SEQUENCE_OFFSET = 3,
	SCHC_RPL_DAO_DODAGID_OFFSET = 4,
	SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN = 20,
	SCHC_RPL_DODAGID_LEN = 16,
};

/* ─── address helpers (schc_helpers.c) ───────────────────────────────────── */

bool is_link_local(const uint8_t addr[16]);
bool is_canonical_link_local(const uint8_t addr[16]);
bool is_global(const uint8_t addr[16]);
bool is_ula(const uint8_t addr[16]);
int validate_rule7_addresses(const uint8_t src[16], const uint8_t dst[16]);

uint16_t read_be16(const uint8_t *p);
void write_be16(uint8_t *p, uint16_t value);

/* ─── IPv6 accessors (schc_helpers.c) ────────────────────────────────────── */

uint8_t ipv6_version(const uint8_t *packet);
uint16_t ipv6_payload_len(const uint8_t *packet);
uint8_t ipv6_next_header(const uint8_t *packet);
uint8_t ipv6_hop_limit(const uint8_t *packet);
const uint8_t *ipv6_src(const uint8_t *packet);
const uint8_t *ipv6_dst(const uint8_t *packet);
const uint8_t *ipv6_payload(const uint8_t *packet);
uint8_t *ipv6_payload_mut(uint8_t *packet);
void ipv6_write_base(uint8_t *packet, uint16_t payload_len,
		     uint8_t next_header, uint8_t hop_limit,
		     const uint8_t src[16], const uint8_t dst[16]);

/* ─── UDP accessors (schc_helpers.c) ─────────────────────────────────────── */

uint16_t udp_src_port(const uint8_t *udp);
uint16_t udp_dst_port(const uint8_t *udp);
uint16_t udp_len(const uint8_t *udp);
const uint8_t *udp_payload(const uint8_t *udp);
uint8_t *udp_payload_mut(uint8_t *udp);
void udp_write_header(uint8_t *udp, uint16_t src_port,
		      uint16_t dst_port, uint16_t len,
		      uint16_t checksum);
void udp_write_checksum(uint8_t *udp, uint16_t checksum);

/* ─── CoAP accessors (schc_helpers.c) ────────────────────────────────────── */

uint8_t coap_type(const uint8_t *coap);
uint8_t coap_tkl(const uint8_t *coap);
uint8_t coap_version(const uint8_t *coap);
uint8_t coap_code(const uint8_t *coap);
uint16_t coap_mid(const uint8_t *coap);
const uint8_t *coap_tail(const uint8_t *coap);
uint8_t *coap_tail_mut(uint8_t *coap);
void coap_write_fixed(uint8_t *coap, uint8_t type, uint8_t tkl,
		      uint8_t code, uint16_t mid);

/* ─── ICMPv6 accessors (schc_helpers.c) ──────────────────────────────────── */

uint8_t icmpv6_type(const uint8_t *icmpv6);
uint8_t icmpv6_code(const uint8_t *icmpv6);
const uint8_t *icmpv6_body(const uint8_t *icmpv6);
uint8_t *icmpv6_body_mut(uint8_t *icmpv6);
void icmpv6_write_header(uint8_t *icmpv6, uint8_t type, uint8_t code,
			 uint16_t checksum);
void icmpv6_write_checksum(uint8_t *icmpv6, uint16_t checksum);
uint16_t icmpv6_echo_id(const uint8_t *icmpv6);
uint16_t icmpv6_echo_seq(const uint8_t *icmpv6);
const uint8_t *icmpv6_echo_tail(const uint8_t *icmpv6);
uint8_t *icmpv6_echo_tail_mut(uint8_t *icmpv6);
void icmpv6_echo_write_body(uint8_t *icmpv6, uint16_t id, uint16_t seq);

/* ─── RPL accessors (schc_helpers.c) ─────────────────────────────────────── */

uint8_t rpl_instance(const uint8_t *rpl);
uint8_t rpl_dio_version(const uint8_t *rpl);
uint16_t rpl_dio_rank(const uint8_t *rpl);
uint8_t rpl_dio_gmop(const uint8_t *rpl);
uint8_t rpl_dio_dtsn(const uint8_t *rpl);
const uint8_t *rpl_dio_dodagid(const uint8_t *rpl);
const uint8_t *rpl_dio_tail(const uint8_t *rpl);
uint8_t *rpl_dio_tail_mut(uint8_t *rpl);
void rpl_dio_write_base(uint8_t *rpl, uint8_t instance,
			uint8_t version, uint16_t rank,
			uint8_t gmop, uint8_t dtsn,
			const uint8_t dodagid[16]);
uint8_t rpl_dao_kd_flags(const uint8_t *rpl);
uint8_t rpl_dao_sequence(const uint8_t *rpl);
const uint8_t *rpl_dao_dodagid(const uint8_t *rpl);
const uint8_t *rpl_dao_tail(const uint8_t *rpl);
uint8_t *rpl_dao_tail_mut(uint8_t *rpl);
void rpl_dao_write_base(uint8_t *rpl, uint8_t instance,
			uint8_t kd_flags, uint8_t seq,
			const uint8_t dodagid[16]);

/* ─── validation (schc_helpers.c) ────────────────────────────────────────── */

int validate_ipv6_transport_lengths(const uint8_t *packet, size_t pkt_len);
bool schc_coap_has_valid_oscore(uint8_t first_byte,
				const uint8_t *tail, size_t tail_len);

/* ─── checksum helpers (schc_checksum.c) ─────────────────────────────────── */

int udp_checksum(const uint8_t src[16], const uint8_t dst[16],
		 uint16_t src_port, uint16_t dst_port,
		 const uint8_t *payload, size_t payload_len,
		 uint16_t *cksum_out);

uint16_t icmpv6_checksum(const uint8_t src[16], const uint8_t dst[16],
			 const uint8_t *icmpv6_payload, uint16_t len);
bool icmpv6_checksum_valid(const uint8_t src[16], const uint8_t dst[16],
			   const uint8_t *icmpv6_payload, uint16_t len);

/* ─── compression (schc_compress.c) ──────────────────────────────────────── */

int compress_coap(const uint8_t *packet, size_t pkt_len,
		  uint8_t *out, size_t out_len, uint8_t rule_id);
int compress_icmpv6_echo(const uint8_t *packet, size_t pkt_len,
			 uint8_t *out, size_t out_len);
int compress_rpl_dio(const uint8_t *packet, size_t pkt_len,
		     uint8_t *out, size_t out_len);
int compress_rpl_dao(const uint8_t *packet, size_t pkt_len,
		     uint8_t *out, size_t out_len);
int compress_mqtt_sn(const uint8_t *packet, size_t pkt_len,
		     uint8_t *out, size_t out_len);

/* ─── decompression (schc_decompress.c) ──────────────────────────────────── */

int decompress_coap(const uint8_t *data, size_t data_len,
		    uint8_t *out, size_t out_len, uint8_t rule_id);
int decompress_icmpv6_echo(const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len);
int decompress_rpl_dio(const uint8_t *data, size_t data_len,
		       uint8_t *out, size_t out_len);
int decompress_rpl_dao(const uint8_t *data, size_t data_len,
		       uint8_t *out, size_t out_len);
int decompress_mqtt_sn(const uint8_t *data, size_t data_len,
		       uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* SCHC_INTERNAL_H_ */
