/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_decompress.c
 * @brief SCHC decompression functions for CoAP, ICMPv6 Echo, and RPL.
 */

#include "schc_internal.h"
#include <string.h>

/* ─── per-rule decompress ─────────────────────────────────────────────────── */

static int decompress_global_coap_v3(const uint8_t *data, size_t data_len,
				     uint8_t *out, size_t out_len,
				     uint8_t rule_id)
{
	if (rule_id != SCHC_RULE_GLOBAL_COAP &&
	    rule_id != SCHC_RULE_GLOBAL_OSCORE) {
		return SCHC_ERR_UNKNOWN_RULE_ID;
	}
	if (data_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	if (data_len < 37u) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1);
	uint64_t hop_limit;
	uint8_t src[16] = { 0x02 };
	uint8_t dst[16] = { 0x02 };
	uint64_t src_lsb, dst_lsb, type, tkl, code, mid;

	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0 ||
	    schc_bit_reader_read_bytes(&r, 120, &src[1], 15) < 0 ||
	    schc_bit_reader_read_bytes(&r, 120, &dst[1], 15) < 0 ||
	    schc_bit_reader_read(&r, 4, &src_lsb) < 0 ||
	    schc_bit_reader_read(&r, 4, &dst_lsb) < 0 ||
	    schc_bit_reader_read(&r, 2, &type) < 0 ||
	    schc_bit_reader_read(&r, 4, &tkl) < 0 ||
	    schc_bit_reader_read(&r, 8, &code) < 0 ||
	    schc_bit_reader_read(&r, 16, &mid) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}
	if (r.pos != 286u || (r.buf[r.pos / 8u] & 0x03u) != 0u) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1u + residue_end];
	size_t tail_len = data_len - 1u - residue_end;
	if (tkl > 8u || tail_len < tkl) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	uint8_t coap_first = (uint8_t)((1u << 6) | ((type & 0x03u) << 4) |
					 (tkl & 0x0Fu));
	bool has_oscore = schc_coap_has_valid_oscore(coap_first, tail, tail_len);
	if ((rule_id == SCHC_RULE_GLOBAL_OSCORE && !has_oscore) ||
	    (rule_id == SCHC_RULE_GLOBAL_COAP && has_oscore)) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	size_t coap_len = SCHC_COAP_FIXED_LEN + tail_len;
	if (coap_len > UINT16_MAX - UDP_HDR_LEN) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	size_t total = IPV6_HDR_LEN + UDP_HDR_LEN + coap_len;
	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	uint16_t src_port = (uint16_t)((5683u & 0xFFF0u) | src_lsb);
	uint16_t dst_port = (uint16_t)((5683u & 0xFFF0u) | dst_lsb);
	uint16_t udp_length = (uint16_t)(UDP_HDR_LEN + coap_len);
	ipv6_write_base(out, udp_length, IPV6_NH_UDP, (uint8_t)hop_limit, src, dst);
	uint8_t *udp = ipv6_payload_mut(out);
	udp_write_header(udp, src_port, dst_port, udp_length, 0);
	uint8_t *coap = udp_payload_mut(udp);
	coap_write_fixed(coap, (uint8_t)type, (uint8_t)tkl,
			 (uint8_t)code, (uint16_t)mid);
	if (tail_len > 0) {
		memcpy(coap_tail_mut(coap), tail, tail_len);
	}
	uint16_t checksum;
	/* coap_len was bounded above, so this helper cannot fail here. */
	(void)udp_checksum(src, dst, src_port, dst_port, coap, coap_len,
			   &checksum);
	udp_write_checksum(udp, checksum);
	return (int)total;
}

static int decompress_link_local_coap_v3(const uint8_t *data, size_t data_len,
					 uint8_t *out, size_t out_len,
					 uint8_t rule_id)
{
	enum { LINK_LOCAL_FIXED_LEN = 23 };

	if (rule_id != SCHC_RULE_LINK_LOCAL_COAP &&
	    rule_id != SCHC_RULE_LINK_LOCAL_OSCORE) {
		return SCHC_ERR_UNKNOWN_RULE_ID;
	}

	if (data_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	if (data_len < LINK_LOCAL_FIXED_LEN) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1u);
	uint64_t hop_limit, src_iid, dst_iid, src_port_lsb, dst_port_lsb;
	uint64_t type, tkl, code, mid;
	uint8_t src[16] = { 0xFE, 0x80 };
	uint8_t dst[16] = { 0xFE, 0x80 };

	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0 ||
	    schc_bit_reader_read(&r, 64, &src_iid) < 0 ||
	    schc_bit_reader_read(&r, 64, &dst_iid) < 0 ||
	    schc_bit_reader_read(&r, 4, &src_port_lsb) < 0 ||
	    schc_bit_reader_read(&r, 4, &dst_port_lsb) < 0 ||
	    schc_bit_reader_read(&r, 2, &type) < 0 ||
	    schc_bit_reader_read(&r, 4, &tkl) < 0 ||
	    schc_bit_reader_read(&r, 8, &code) < 0 ||
	    schc_bit_reader_read(&r, 16, &mid) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}
	/* Rule 5 carries exactly 174 meaningful residue bits. */
	if (r.pos != 174u || (r.buf[r.pos / 8u] & 0x03u) != 0u) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	for (size_t i = 0; i < 8u; i++) {
		src[15u - i] = (uint8_t)(src_iid >> (i * 8u));
		dst[15u - i] = (uint8_t)(dst_iid >> (i * 8u));
	}
	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1u + residue_end];
	size_t tail_len = data_len - 1u - residue_end;
	uint8_t coap_first = (uint8_t)((1u << 6) | ((type & 0x03u) << 4) |
					 (tkl & 0x0Fu));
	bool has_oscore = schc_coap_has_valid_oscore(coap_first, tail, tail_len);
	if (tkl > 8u || tail_len < tkl ||
	    (rule_id == SCHC_RULE_LINK_LOCAL_OSCORE && !has_oscore) ||
	    (rule_id == SCHC_RULE_LINK_LOCAL_COAP && has_oscore)) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	size_t coap_len = SCHC_COAP_FIXED_LEN + tail_len;
	if (coap_len > UINT16_MAX - UDP_HDR_LEN) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	size_t total = IPV6_HDR_LEN + UDP_HDR_LEN + coap_len;
	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	uint16_t src_port = (uint16_t)((5683u & 0xFFF0u) | src_port_lsb);
	uint16_t dst_port = (uint16_t)((5683u & 0xFFF0u) | dst_port_lsb);
	uint16_t udp_length = (uint16_t)(UDP_HDR_LEN + coap_len);
	/* Every error path is above this first write, preserving caller output. */
	ipv6_write_base(out, udp_length, IPV6_NH_UDP, (uint8_t)hop_limit, src, dst);
	uint8_t *udp = ipv6_payload_mut(out);
	udp_write_header(udp, src_port, dst_port, udp_length, 0);
	uint8_t *coap = udp_payload_mut(udp);
	coap_write_fixed(coap, (uint8_t)type, (uint8_t)tkl,
			 (uint8_t)code, (uint16_t)mid);
	if (tail_len > 0) {
		memcpy(coap_tail_mut(coap), tail, tail_len);
	}
	uint16_t checksum;
	/* coap_len was bounded above, so this helper cannot fail here. */
	(void)udp_checksum(src, dst, src_port, dst_port, coap, coap_len,
			   &checksum);
	udp_write_checksum(udp, checksum);
	return (int)total;
}

int decompress_coap(const uint8_t *data, size_t data_len,
			    uint8_t *out, size_t out_len, uint8_t rule_id)
{
	if (rule_id == SCHC_RULE_LINK_LOCAL_COAP ||
	    rule_id == SCHC_RULE_LINK_LOCAL_OSCORE) {
		return decompress_link_local_coap_v3(data, data_len, out, out_len,
					     rule_id);
	}
	if (rule_id == SCHC_RULE_GLOBAL_COAP ||
	    rule_id == SCHC_RULE_GLOBAL_OSCORE) {
		return decompress_global_coap_v3(data, data_len, out, out_len,
						 rule_id);
	}
	return SCHC_ERR_UNKNOWN_RULE_ID;
}

int decompress_icmpv6_echo(const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 16 + 16 = 176 bits = 22 bytes
	 */
	if (data_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	if (data_len < 1u + 22u) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (schc_bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    schc_bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t icmp_type, icmp_id, icmp_seq;
	if (schc_bit_reader_read(&r, 8, &icmp_type) < 0 ||
	    schc_bit_reader_read(&r, 16, &icmp_id) < 0 ||
	    schc_bit_reader_read(&r, 16, &icmp_seq) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}
	if (icmp_type != ICMPV6_TYPE_ECHO_REQUEST &&
	    icmp_type != ICMPV6_TYPE_ECHO_REPLY) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	/* Rule 2's fixed residue is exactly 176 bits.  It has no padding; every
	 * following octet is the opaque Echo payload. */
	if (r.pos != 176u) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t icmp_len = SCHC_ICMPV6_ECHO_TAIL_OFFSET + tail_len;
	if (icmp_len > UINT16_MAX) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	size_t total = IPV6_HDR_LEN + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	ipv6_write_base(out, (uint16_t)icmp_len, IPV6_NH_ICMPV6,
			(uint8_t)hop_limit, src, dst);
	uint8_t *icmp = ipv6_payload_mut(out);
	icmpv6_write_header(icmp, (uint8_t)icmp_type, 0, 0);
	icmpv6_echo_write_body(icmp, (uint16_t)icmp_id, (uint16_t)icmp_seq);
	if (tail_len > 0) {
		memcpy(icmpv6_echo_tail_mut(icmp), tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp, (uint16_t)icmp_len);
	icmpv6_write_checksum(icmp, cksum);

	return (int)total;
}

int decompress_rpl_dio(const uint8_t *data, size_t data_len,
		       uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 8 + 16 + 8 + 8 + 128 = 312 bits = 39 bytes
	 */
	if (data_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	if (data_len < 1u + 39u) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (schc_bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    schc_bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t instance, version, rank, gmop, dtsn;
	uint8_t dodagid[16];

	if (schc_bit_reader_read(&r, 8, &instance) < 0 ||
	    schc_bit_reader_read(&r, 8, &version) < 0 ||
	    schc_bit_reader_read(&r, 16, &rank) < 0 ||
	    schc_bit_reader_read(&r, 8, &gmop) < 0 ||
	    schc_bit_reader_read(&r, 8, &dtsn) < 0 ||
	    schc_bit_reader_read_bytes(&r, 128, dodagid, 16) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}
	/* Rule 3's fixed residue is exactly 312 bits.  It has no padding; every
	 * following octet is the opaque RPL option tail. */
	if (r.pos != 312u) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t rpl_body_len = SCHC_RPL_DIO_BASE_LEN + tail_len;
	size_t icmp_len = SCHC_ICMPV6_BODY_OFFSET + rpl_body_len;
	if (icmp_len > UINT16_MAX) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	size_t total = IPV6_HDR_LEN + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	ipv6_write_base(out, (uint16_t)icmp_len, IPV6_NH_ICMPV6,
			(uint8_t)hop_limit, src, dst);
	uint8_t *icmp = ipv6_payload_mut(out);
	icmpv6_write_header(icmp, ICMPV6_TYPE_RPL, ICMPV6_CODE_RPL_DIO, 0);
	uint8_t *rpl = icmpv6_body_mut(icmp);
	rpl_dio_write_base(rpl, (uint8_t)instance, (uint8_t)version,
			   (uint16_t)rank, (uint8_t)gmop, (uint8_t)dtsn,
			   dodagid);
	if (tail_len > 0) {
		memcpy(rpl_dio_tail_mut(rpl), tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp, (uint16_t)icmp_len);
	icmpv6_write_checksum(icmp, cksum);

	return (int)total;
}

int decompress_rpl_dao(const uint8_t *data, size_t data_len,
		       uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 8 + 8 + 128 = 288 bits = 36 bytes
	 */
	if (data_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	if (data_len < 1u + 36u) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	uint8_t src[16], dst[16];

	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	memset(src, 0, 16);
	memset(dst, 0, 16);
	src[0] = 0xFE;
	src[1] = 0x80;
	dst[0] = 0xFE;
	dst[1] = 0x80;

	if (schc_bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    schc_bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t instance, kd_flags, seq;
	uint8_t dodagid[16];

	if (schc_bit_reader_read(&r, 8, &instance) < 0 ||
	    schc_bit_reader_read(&r, 8, &kd_flags) < 0 ||
	    schc_bit_reader_read(&r, 8, &seq) < 0 ||
	    schc_bit_reader_read_bytes(&r, 128, dodagid, 16) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}
	/* Rule 4 always carries a DODAGID, so D=0 has no canonical meaning. */
	if ((kd_flags & 0x40u) == 0u) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}
	/* The Rule 4 residue is exactly 288 bits, hence byte-aligned with no
	 * padding bits.  All following octets are the opaque DAO option tail. */
	if (r.pos != 288u) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t rpl_body_len = SCHC_RPL_DAO_BASE_WITH_DODAGID_LEN + tail_len;
	size_t icmp_len = SCHC_ICMPV6_BODY_OFFSET + rpl_body_len;
	if (icmp_len > UINT16_MAX) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	size_t total = IPV6_HDR_LEN + icmp_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	ipv6_write_base(out, (uint16_t)icmp_len, IPV6_NH_ICMPV6,
			(uint8_t)hop_limit, src, dst);
	uint8_t *icmp = ipv6_payload_mut(out);
	icmpv6_write_header(icmp, ICMPV6_TYPE_RPL, ICMPV6_CODE_RPL_DAO, 0);
	uint8_t *rpl = icmpv6_body_mut(icmp);
	rpl_dao_write_base(rpl, (uint8_t)instance, (uint8_t)kd_flags,
			   (uint8_t)seq, dodagid);
	if (tail_len > 0) {
		memcpy(rpl_dao_tail_mut(rpl), tail, tail_len);
	}

	uint16_t cksum = icmpv6_checksum(src, dst, icmp, (uint16_t)icmp_len);
	icmpv6_write_checksum(icmp, cksum);

	return (int)total;
}

/**
 * Rule 7: reconstruct IPv6 + UDP + MQTT-SN from its canonical residue.
 */
int decompress_mqtt_sn(const uint8_t *data, size_t data_len,
		       uint8_t *out, size_t out_len)
{
	if (data_len > SCHC_FRAGMENT_MAX_PACKET_SIZE) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	if (data_len < 1u + 20u) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1);
	uint64_t hop_limit;
	uint64_t address_mode;
	uint8_t src[16] = { 0 };
	uint8_t dst[16] = { 0 };

	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0 ||
	    schc_bit_reader_read(&r, 1, &address_mode) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}
	if (address_mode == 0) {
		src[0] = dst[0] = 0xFE;
		src[1] = dst[1] = 0x80;
		if (schc_bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
		    schc_bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
			return SCHC_ERR_TOO_SHORT;
		}
	} else {
		if (data_len < 1u + 36u ||
		    schc_bit_reader_read_bytes(&r, 128, src, sizeof(src)) < 0 ||
		    schc_bit_reader_read_bytes(&r, 128, dst, sizeof(dst)) < 0) {
			return SCHC_ERR_TOO_SHORT;
		}
	}

	if (validate_rule7_addresses(src, dst) < 0 ||
	    (address_mode == 1 && is_canonical_link_local(src) &&
	     is_canonical_link_local(dst))) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	uint64_t direction;
	uint64_t other_port;
	if (schc_bit_reader_read(&r, 1, &direction) < 0 ||
	    schc_bit_reader_read(&r, 16, &other_port) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}
	if (direction == 1 && other_port == MQTT_SN_PORT) {
		return SCHC_ERR_INVALID_ARGUMENT;
	}

	/* The residue ends after two meaningful bits in its final octet. */
	if ((r.pos % 8u) != 0u) {
		uint8_t padding_mask = (uint8_t)((1u << (8u - r.pos % 8u)) - 1u);

		if ((r.buf[r.pos / 8u] & padding_mask) != 0u) {
			return SCHC_ERR_INVALID_ARGUMENT;
		}
	}

	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	size_t tail_len = data_len - 1u - residue_end;
	if (tail_len > UINT16_MAX - UDP_HDR_LEN) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	size_t total = IPV6_HDR_LEN + UDP_HDR_LEN + tail_len;
	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	uint16_t src_port = direction == 0 ? MQTT_SN_PORT : (uint16_t)other_port;
	uint16_t dst_port = direction == 0 ? (uint16_t)other_port : MQTT_SN_PORT;
	uint16_t udp_length = (uint16_t)(UDP_HDR_LEN + tail_len);
	const uint8_t *tail = &data[1u + residue_end];
	uint16_t checksum;
	if (udp_checksum(src, dst, src_port, dst_port, tail, tail_len,
			 &checksum) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	ipv6_write_base(out, udp_length, IPV6_NH_UDP, (uint8_t)hop_limit, src, dst);
	uint8_t *udp = ipv6_payload_mut(out);
	udp_write_header(udp, src_port, dst_port, udp_length, checksum);
	if (tail_len > 0) {
		memcpy(udp_payload_mut(udp), tail, tail_len);
	}

	return (int)total;
}
