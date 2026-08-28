/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <string.h>
#include <zephyr/ztest.h>

#include <lichen/oscore.h>
#include <lichen/schc.h>

#include "oscore_schc_vectors.h"
#include "schc_internal.h"

#define TEST_OSCORE_OPTION_CAPACITY 32

static const uint8_t link_src[16] = {
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};
static const uint8_t link_dst[16] = {
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
};

static struct oscore_ctx *make_ctx(const struct oscore_schc_vector *vector,
				   bool receiver, const uint8_t secret[16])
{
	struct oscore_ctx *ctx = NULL;
	const uint8_t *sender = receiver ? vector->recipient_id : vector->sender_id;
	size_t sender_len = receiver ? vector->recipient_id_len : vector->sender_id_len;
	const uint8_t *recipient = receiver ? vector->sender_id : vector->recipient_id;
	size_t recipient_len = receiver ? vector->sender_id_len : vector->recipient_id_len;

	zassert_equal(oscore_ctx_create(secret, vector->salt, vector->salt_len,
					sender, sender_len, recipient, recipient_len,
					&ctx), OSCORE_OK);
	zassert_not_null(ctx);
	return ctx;
}

static void extract_protected(const uint8_t *packet, size_t packet_len,
			      const uint8_t **option, size_t *option_len,
			      const uint8_t **ciphertext, size_t *ciphertext_len)
{
	zassert_true(packet_len >= IPV6_HDR_LEN + UDP_HDR_LEN + SCHC_COAP_FIXED_LEN);
	const uint8_t *coap = &packet[IPV6_HDR_LEN + UDP_HDR_LEN];
	size_t coap_len = packet_len - IPV6_HDR_LEN - UDP_HDR_LEN;
	size_t offset = SCHC_COAP_FIXED_LEN + coap_tkl(coap);
	zassert_true(offset < coap_len);
	zassert_equal(coap[offset] >> 4, COAP_OPTION_OSCORE);
	*option_len = coap[offset] & 0x0f;
	zassert_true(*option_len <= 12 && offset + 1 + *option_len < coap_len);
	*option = &coap[offset + 1];
	offset += 1 + *option_len;
	zassert_equal(coap[offset], 0xff);
	*ciphertext = &coap[offset + 1];
	*ciphertext_len = coap_len - offset - 1;
}

static size_t build_packet(uint8_t *packet, size_t capacity,
			   const uint8_t *option, size_t option_len,
			   const uint8_t *ciphertext, size_t ciphertext_len)
{
	if (option_len > 12 || ciphertext_len > UINT16_MAX - UDP_HDR_LEN - 6 ||
	    capacity < IPV6_HDR_LEN + UDP_HDR_LEN + 6 + option_len + ciphertext_len) {
		return 0;
	}
	size_t coap_len = 6 + option_len + ciphertext_len;
	uint16_t udp_len = (uint16_t)(UDP_HDR_LEN + coap_len);
	ipv6_write_base(packet, udp_len, IPV6_NH_UDP, 64, link_src, link_dst);
	uint8_t *udp = ipv6_payload_mut(packet);
	udp_write_header(udp, 5683, 5683, udp_len, 0);
	uint8_t *coap = udp_payload_mut(udp);
	coap_write_fixed(coap, 0, 0, 2, 0x1234);
	coap[4] = (uint8_t)(0x90u | option_len);
	memcpy(&coap[5], option, option_len);
	coap[5 + option_len] = 0xff;
	memcpy(&coap[6 + option_len], ciphertext, ciphertext_len);
	uint16_t checksum = 0;
	zassert_equal(udp_checksum(link_src, link_dst, 5683, 5683, coap, coap_len,
				   &checksum), 0);
	udp_write_checksum(udp, checksum);
	return IPV6_HDR_LEN + udp_len;
}

ZTEST(oscore_schc_roundtrip, test_shared_protect_compress_decompress_unprotect)
{
	for (size_t i = 0; i < OSCORE_SCHC_VECTOR_COUNT; i++) {
		const struct oscore_schc_vector *vector = &oscore_schc_vectors[i];
		struct oscore_ctx *sender = make_ctx(vector, false, vector->secret);
		struct oscore_ctx *receiver = make_ctx(vector, true, vector->secret);
		uint8_t ciphertext[96];
		size_t ciphertext_len = sizeof(ciphertext);
		uint8_t option[TEST_OSCORE_OPTION_CAPACITY];
		size_t option_len = sizeof(option);
		zassert_equal(oscore_ctx_set_sender_seq(sender, vector->sender_seq), OSCORE_OK);
		zassert_equal(oscore_protect_request(sender, vector->plaintext_code,
						     vector->plaintext_options,
						     vector->plaintext_options_len,
						     vector->plaintext_payload,
						     vector->plaintext_payload_len,
						     ciphertext, &ciphertext_len,
						     option, &option_len), OSCORE_OK,
			      "%s protect", vector->name);
		zassert_equal(option_len, vector->oscore_option_len);
		zassert_mem_equal(option, vector->oscore_option, option_len);
		zassert_equal(ciphertext_len, vector->ciphertext_len);
		zassert_mem_equal(ciphertext, vector->ciphertext, ciphertext_len);

		uint8_t compressed[160];
		int compressed_len = lichen_schc_compress(vector->packet,
							 vector->packet_len,
							 compressed, sizeof(compressed));
		zassert_equal(compressed_len, vector->compressed_len);
		zassert_mem_equal(compressed, vector->compressed, compressed_len);
		uint8_t restored[160];
		int restored_len = lichen_schc_decompress(compressed, compressed_len,
							 restored, sizeof(restored));
		zassert_equal(restored_len, vector->packet_len);
		zassert_mem_equal(restored, vector->packet, restored_len);

		const uint8_t *wire_option;
		size_t wire_option_len;
		const uint8_t *wire_ciphertext;
		size_t wire_ciphertext_len;
		extract_protected(restored, restored_len, &wire_option, &wire_option_len,
				  &wire_ciphertext, &wire_ciphertext_len);
		uint8_t code = 0xa5;
		uint8_t options[32];
		size_t options_len = sizeof(options);
		uint8_t payload[64];
		size_t payload_len = sizeof(payload);
		zassert_equal(oscore_unprotect_request(receiver,
						       wire_option, wire_option_len,
						       wire_ciphertext, wire_ciphertext_len,
						       &code, options, &options_len,
						       payload, &payload_len), OSCORE_OK);
		zassert_equal(code, vector->plaintext_code);
		zassert_equal(options_len, vector->plaintext_options_len);
		zassert_mem_equal(options, vector->plaintext_options, options_len);
		zassert_equal(payload_len, vector->plaintext_payload_len);
		zassert_mem_equal(payload, vector->plaintext_payload, payload_len);
		options_len = sizeof(options);
		payload_len = sizeof(payload);
		zassert_equal(oscore_unprotect_request(receiver,
						       wire_option, wire_option_len,
						       wire_ciphertext, wire_ciphertext_len,
						       &code, options, &options_len,
						       payload, &payload_len), OSCORE_ERR_REPLAY);
		oscore_ctx_free(sender);
		oscore_ctx_free(receiver);
	}
}

ZTEST(oscore_schc_roundtrip, test_failures_are_atomic_before_valid_delivery)
{
	const struct oscore_schc_vector *vector = &oscore_schc_vectors[0];
	uint8_t restored[160];
	int restored_len = lichen_schc_decompress(vector->compressed,
						  vector->compressed_len,
						  restored, sizeof(restored));
	zassert_true(restored_len > 0);
	const uint8_t *option;
	size_t option_len;
	const uint8_t *ciphertext;
	size_t ciphertext_len;
	extract_protected(restored, restored_len, &option, &option_len,
			  &ciphertext, &ciphertext_len);
	struct oscore_ctx *receiver = make_ctx(vector, true, vector->secret);
	uint8_t corrupt[96];
	memcpy(corrupt, ciphertext, ciphertext_len);
	corrupt[ciphertext_len - 1] ^= 0x80;
	uint8_t code = 0xa5;
	uint8_t options[32];
	uint8_t payload[64];
	memset(options, 0xa5, sizeof(options));
	memset(payload, 0xa5, sizeof(payload));
	size_t options_len = sizeof(options);
	size_t payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(receiver, option, option_len,
					       corrupt, ciphertext_len, &code,
					       options, &options_len,
					       payload, &payload_len), OSCORE_ERR_DECRYPT_FAILED);
	zassert_equal(code, 0xa5);
	zassert_true(options_len == sizeof(options) && payload_len == sizeof(payload));
	zassert_equal(oscore_unprotect_request(receiver, option, option_len,
					       ciphertext, ciphertext_len - 1, &code,
					       options, &options_len,
					       payload, &payload_len), OSCORE_ERR_DECRYPT_FAILED);

	uint8_t wrong_secret[16];
	memcpy(wrong_secret, vector->secret, sizeof(wrong_secret));
	wrong_secret[0] ^= 1;
	struct oscore_ctx *wrong = make_ctx(vector, true, wrong_secret);
	zassert_equal(oscore_unprotect_request(wrong, option, option_len,
					       ciphertext, ciphertext_len, &code,
					       options, &options_len,
					       payload, &payload_len), OSCORE_ERR_DECRYPT_FAILED);
	oscore_ctx_free(wrong);

	options_len = sizeof(options);
	payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(receiver, option, option_len,
					       ciphertext, ciphertext_len, &code,
					       options, &options_len,
					       payload, &payload_len), OSCORE_OK);

	uint8_t noncanonical[160];
	memcpy(noncanonical, vector->compressed, vector->compressed_len);
	noncanonical[22] |= 1;
	memset(restored, 0xa5, sizeof(restored));
	zassert_true(lichen_schc_decompress(noncanonical, vector->compressed_len,
						 restored, sizeof(restored)) < 0);
	for (size_t i = 0; i < sizeof(restored); i++) zassert_equal(restored[i], 0xa5);
	oscore_ctx_free(receiver);
}

ZTEST(oscore_schc_roundtrip, test_max_sequence_crosses_rule5_once_then_exhausts)
{
	const struct oscore_schc_vector *vector = &oscore_schc_vectors[0];
	struct oscore_ctx *sender = make_ctx(vector, false, vector->secret);
	struct oscore_ctx *receiver = make_ctx(vector, true, vector->secret);
	zassert_equal(oscore_ctx_set_sender_seq(sender, OSCORE_SSN_MAX), OSCORE_OK);
	uint8_t ciphertext[96];
	size_t ciphertext_len = sizeof(ciphertext);
	uint8_t option[TEST_OSCORE_OPTION_CAPACITY];
	size_t option_len = sizeof(option);
	zassert_equal(oscore_protect_request(sender, vector->plaintext_code,
					     vector->plaintext_options,
					     vector->plaintext_options_len,
					     vector->plaintext_payload,
					     vector->plaintext_payload_len,
					     ciphertext, &ciphertext_len,
					     option, &option_len), OSCORE_OK);
	zassert_equal(option[0] & 7, OSCORE_PIV_MAX_LEN);
	size_t retry_ct_len = sizeof(ciphertext);
	size_t retry_opt_len = sizeof(option);
	zassert_equal(oscore_protect_request(sender, vector->plaintext_code,
					     vector->plaintext_options,
					     vector->plaintext_options_len,
					     vector->plaintext_payload,
					     vector->plaintext_payload_len,
					     ciphertext, &retry_ct_len,
					     option, &retry_opt_len), OSCORE_ERR_SEQ_EXHAUSTED);

	uint8_t packet[160];
	size_t packet_len = build_packet(packet, sizeof(packet), option, option_len,
				       ciphertext, ciphertext_len);
	zassert_true(packet_len > 0);
	uint8_t compressed[160];
	int compressed_len = lichen_schc_compress(packet, packet_len,
						  compressed, sizeof(compressed));
	zassert_true(compressed_len > 0);
	zassert_equal(compressed[0], SCHC_RULE_LINK_LOCAL_OSCORE);
	uint8_t restored[160];
	int restored_len = lichen_schc_decompress(compressed, compressed_len,
						  restored, sizeof(restored));
	zassert_equal(restored_len, packet_len);
	const uint8_t *wire_option;
	size_t wire_option_len;
	const uint8_t *wire_ciphertext;
	size_t wire_ciphertext_len;
	extract_protected(restored, restored_len, &wire_option, &wire_option_len,
			  &wire_ciphertext, &wire_ciphertext_len);
	uint8_t code;
	uint8_t options[32];
	size_t options_len = sizeof(options);
	uint8_t payload[64];
	size_t payload_len = sizeof(payload);
	zassert_equal(oscore_unprotect_request(receiver, wire_option, wire_option_len,
					       wire_ciphertext, wire_ciphertext_len,
					       &code, options, &options_len,
					       payload, &payload_len), OSCORE_OK);
	oscore_ctx_free(sender);
	oscore_ctx_free(receiver);
}

static void *setup(void)
{
	zassert_equal(oscore_init(), OSCORE_OK);
	oscore_nvm_register_callbacks(NULL, NULL);
	return NULL;
}

ZTEST_SUITE(oscore_schc_roundtrip, NULL, setup, NULL, NULL, NULL);
