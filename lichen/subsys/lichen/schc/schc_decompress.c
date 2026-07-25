/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_decompress.c
 * @brief SCHC decompression functions for CoAP, ICMPv6 Echo, and RPL.
 */

#include "schc_internal.h"
#include <string.h>

/* ─── per-rule decompress ─────────────────────────────────────────────────── */

int decompress_coap(const uint8_t *data, size_t data_len,
		    uint8_t *out, size_t out_len, uint8_t rule_id)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * - Rule 0 (link-local): 8 + 64 + 64 + 16 + 16 + 2 + 4 + 8 + 16 = 198 bits = 25 bytes
	 * - Rule 1 (global):     8 + 64 + 64 + 16 + 16 + 2 + 4 + 8 + 16 = 198 bits = 25 bytes
	 */
	size_t min_residue = 25;
	if (data_len < 1 + min_residue) {
		return SCHC_ERR_TOO_SHORT;
	}

	struct schc_bit_reader r;
	schc_bit_reader_init(&r, &data[1], data_len - 1);

	uint64_t hop_limit;
	if (schc_bit_reader_read(&r, 8, &hop_limit) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint8_t src[16], dst[16];

	memset(src, 0, 16);
	memset(dst, 0, 16);
	if (rule_id == SCHC_RULE_LINK_LOCAL_COAP || rule_id == SCHC_RULE_LINK_LOCAL_OSCORE) {
		src[0] = 0xFE;
		src[1] = 0x80;
		dst[0] = 0xFE;
		dst[1] = 0x80;
	} else {
		/* ULA mesh prefix fd00::/64 */
		src[0] = 0xFD;
		dst[0] = 0xFD;
	}
	if (schc_bit_reader_read_bytes(&r, 64, &src[8], 8) < 0 ||
	    schc_bit_reader_read_bytes(&r, 64, &dst[8], 8) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	uint64_t src_port, dst_port, coap_type_val, coap_tkl_val, coap_code_val, coap_mid_val;
	if (schc_bit_reader_read(&r, 16, &src_port) < 0 ||
	    schc_bit_reader_read(&r, 16, &dst_port) < 0 ||
	    schc_bit_reader_read(&r, 2, &coap_type_val) < 0 ||
	    schc_bit_reader_read(&r, 4, &coap_tkl_val) < 0 ||
	    schc_bit_reader_read(&r, 8, &coap_code_val) < 0 ||
	    schc_bit_reader_read(&r, 16, &coap_mid_val) < 0) {
		return SCHC_ERR_TOO_SHORT;
	}

	size_t residue_end = schc_bit_reader_residue_byte_end(&r);
	const uint8_t *tail = &data[1 + residue_end];
	size_t tail_len = data_len - 1 - residue_end;

	size_t coap_len = SCHC_COAP_FIXED_LEN + tail_len;
	if (coap_len > UINT16_MAX - UDP_HDR_LEN) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}
	uint16_t udp_length = UDP_HDR_LEN + coap_len;
	uint16_t ipv6_len = udp_length;
	size_t total = IPV6_HDR_LEN + UDP_HDR_LEN + coap_len;

	if (total > out_len) {
		return SCHC_ERR_BUFFER_TOO_SMALL;
	}

	ipv6_write_base(out, ipv6_len, IPV6_NH_UDP, (uint8_t)hop_limit, src, dst);
	uint8_t *udp = ipv6_payload_mut(out);
	udp_write_header(udp, (uint16_t)src_port, (uint16_t)dst_port, udp_length, 0);
	uint8_t *coap = udp_payload_mut(udp);
	coap_write_fixed(coap, (uint8_t)coap_type_val, (uint8_t)coap_tkl_val,
			 (uint8_t)coap_code_val, (uint16_t)coap_mid_val);
	if (tail_len > 0) {
		memcpy(coap_tail_mut(coap), tail, tail_len);
	}

	uint16_t udp_cksum;
	if (udp_checksum(src, dst, (uint16_t)src_port, (uint16_t)dst_port,
			 coap, coap_len, &udp_cksum) < 0) {
		return SCHC_ERR_BUFFER_TOO_SMALL;  /* Payload too large for UDP */
	}
	udp_write_checksum(udp, udp_cksum);

	return (int)total;
}

int decompress_icmpv6_echo(const uint8_t *data, size_t data_len,
			   uint8_t *out, size_t out_len)
{
	/*
	 * Minimum residue size (excluding rule ID byte):
	 * 8 + 64 + 64 + 8 + 16 + 16 = 176 bits = 22 bytes
	 */
	if (data_len < 1 + 22) {
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
	if (data_len < 1 + 39) {
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
	if (data_len < 1 + 36) {
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
