/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_codec.h
 * @brief Bounded CoAP message codec (RFC 7252 sections 3 and 3.1)
 */

#ifndef LICHEN_COAP_CODEC_H_
#define LICHEN_COAP_CODEC_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_COAP_VERSION 1U
#define LICHEN_COAP_TOKEN_MAX 8U
#define LICHEN_COAP_OPTIONS_MAX 16U
#define LICHEN_COAP_PAYLOAD_MARKER 0xffU

enum lichen_coap_type {
	LICHEN_COAP_TYPE_CON = 0,
	LICHEN_COAP_TYPE_NON = 1,
	LICHEN_COAP_TYPE_ACK = 2,
	LICHEN_COAP_TYPE_RST = 3,
};

/** Zero-copy decoded option. Value storage remains owned by the wire buffer. */
struct lichen_coap_option {
	uint16_t number;
	const uint8_t *value;
	size_t length;
};

/**
 * Zero-copy decoded message, or input description for serialization.
 *
 * Parsing stores pointers into the caller-owned immutable wire buffer. For
 * serialization, token, option values, and payload must remain valid until the
 * function returns.
 */
struct lichen_coap_packet {
	enum lichen_coap_type type;
	uint8_t code;
	uint16_t message_id;
	const uint8_t *token;
	size_t token_len;
	struct lichen_coap_option options[LICHEN_COAP_OPTIONS_MAX];
	size_t option_count;
	const uint8_t *payload;
	size_t payload_len;
};

/**
 * Parse and validate one complete CoAP datagram.
 *
 * The output structure is unchanged on every failure. Options and payload are
 * zero-copy views into @p wire. Empty-code messages are accepted only when
 * they have no token, options, or payload, as required by RFC 7252 section 4.1.
 *
 * @return 0, -EINVAL for NULL arguments, -EBADMSG for malformed input,
 *         -E2BIG for more than LICHEN_COAP_OPTIONS_MAX options, or -EOVERFLOW
 *         when the cumulative option number exceeds 65535.
 */
int lichen_coap_parse(const uint8_t *wire, size_t wire_len,
		      struct lichen_coap_packet *packet);

/**
 * Serialize one canonical CoAP datagram.
 *
 * Options must be in nondecreasing number order; repeated option numbers are
 * allowed. Extended delta/length encodings are emitted minimally. On failure,
 * both the output buffer and @p out_len are unchanged. Input value storage must
 * not overlap the output buffer.
 *
 * @param[in] packet   Message to encode
 * @param[out] out     Output buffer
 * @param[in,out] out_len Input capacity; exact encoded size on success
 * @return 0, -EINVAL for invalid state/order/pointers, -EMSGSIZE for values
 *         outside RFC 7252 option encoding bounds, -EOVERFLOW for size
 *         arithmetic overflow, or -ENOMEM when the output is too small.
 */
int lichen_coap_serialize(const struct lichen_coap_packet *packet,
			 uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_CODEC_H_ */
