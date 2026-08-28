/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/*
 * Cross-language consumer for test/vectors/link_frame_signed_modes.json.
 * The expected signatures were produced by reference_schnorr48.py using
 * PyNaCl, independently of this C implementation.  Rust's shared_vectors
 * test consumes the same records.  The two signed records from link_frame.json
 * are included as well, so every canonical signed frame is exercised here.
 */

#include <lichen/schnorr48.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct vector {
	const char *name;
	uint8_t length;
	uint8_t llsec;
	uint8_t epoch;
	uint16_t seqnum;
	const char *dst_hex;
	const char *payload_hex;
	uint8_t payload_fill;
	size_t payload_len;
	const char *signature_hex;
};

static const struct vector vectors[] = {
	{
		"broadcast_signed", 0x3f, 0xa0, 0x01, 0x0002,
		"", "616263", 0, 0,
		"1d8efcec77d664081e6f0bdcfe1e444688aab91502ebe4680d67a4e0d1b158ea4"
		"7cac9c1b0417489a603751692869508",
	},
	{
		"short_addr_signed", 0x44, 0xa1, 0x01, 0x0002,
		"abcd", "68656c6c6f21", 0, 0,
		"c15f23c6e53eebc34ae79d38284a8da8ff0469d6bdcc176e55bfd2585fc450f8a"
		"191804e7d0f184cfc5038f309f2b906",
	},
	{
		"extended_addr_signed", 0x47, 0xa6, 0x07, 0x0203,
		"0011223344556677", "657874", 0, 0,
		"bdff43b6532ecbe228f4df787d1b660cf3f1dba88a600a4c3901da1c24011ff6"
		"ea7d40f3aeae137d96ecaed26ebbc70c",
	},
	{
		"elided_addr_signed", 0x3f, 0xa3, 0x09, 0x00ff,
		"", "656c64", 0, 0,
		"afe131f7cf2dea9060cf68111d8e8c9ff6b5f5757e51d61d8f4377727e1e87d7"
		"9503b0cba4825e54c01e8357e46c2908",
	},
	{
		"broadcast_signed_max_payload", 0xfe, 0xa0, 0xff, 0xffff,
		"", NULL, 0xa0, 194,
		"4ddc35b8a08f2c64728cd2053105041ee76d82e689b627f4466c81607410e89b7"
		"d20df6303235683be7b896a3a6d0f02",
	},
	{
		"short_signed_max_payload", 0xfe, 0xa5, 0xfe, 0xfffe,
		"abcd", NULL, 0xa1, 192,
		"f6a16880e0494c6f4bfa46eaf851efcd438697117c3dfc8c3e38acaf8409430a5"
		"cbc780b9adbd8e7d0dd2947e9eca10e",
	},
	{
		"extended_signed_max_payload", 0xfe, 0xa2, 0xfd, 0xfffd,
		"0011223344556677", NULL, 0xa2, 186,
		"203bfb26f35e5823e3ef57cb36f6ba2a3e544f794de1766fa6cbbd15e54ca3f7"
		"645ed1df1528f39cc87edfcca2ef1d0a",
	},
	{
		"elided_signed_max_payload", 0xfe, 0xa7, 0xfc, 0xfffc,
		"", NULL, 0xa3, 194,
		"5f71858b6fe98a6117d838bcc7eb7e8fca86a04fcbbc181826579192effda6b9a7"
		"ab6f7e9ed06be08d3ebe333bd4bb04",
	},
};

static int hex_digit(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	return -1;
}

static size_t decode_hex(const char *hex, uint8_t *out, size_t capacity)
{
	size_t length = strlen(hex);

	if ((length & 1U) != 0U || length / 2U > capacity) {
		return SIZE_MAX;
	}
	for (size_t i = 0; i < length / 2U; ++i) {
		int high = hex_digit(hex[2U * i]);
		int low = hex_digit(hex[2U * i + 1U]);

		if (high < 0 || low < 0) {
			return SIZE_MAX;
		}
		out[i] = (uint8_t)((high << 4) | low);
	}
	return length / 2U;
}

static int expect_rejected(const char *name, const char *component,
			   uint8_t length, uint8_t llsec, uint8_t epoch,
			   uint16_t seqnum, const uint8_t *destination,
			   size_t destination_len, const uint8_t *signer_iid,
			   size_t signer_iid_len, const uint8_t *payload,
			   size_t payload_len, const uint8_t signature[48],
			   const uint8_t public_key[32])
{
	int result = schnorr48_verify_frame(length, llsec, epoch, seqnum,
					    destination, destination_len,
					    signer_iid, signer_iid_len,
					    payload, payload_len, signature, 48U,
					    public_key);

	if (result == 1) {
		printf("%s: C accepted %s mutation\n", name, component);
		return 0;
	}
	return 1;
}

static int run_vector(const struct vector *vector, const uint8_t private_key[32],
		      const uint8_t public_key[32], const uint8_t signer_iid[8])
{
	uint8_t destination[8];
	uint8_t payload[194];
	uint8_t expected[48];
	uint8_t actual[48];
	uint8_t mutated_destination[8];
	uint8_t mutated_signer[8];
	uint8_t mutated_payload[194];
	uint8_t mutated_signature[48];
	size_t destination_len = decode_hex(vector->dst_hex, destination,
					    sizeof(destination));
	size_t payload_len;

	if (vector->payload_hex != NULL) {
		payload_len = decode_hex(vector->payload_hex, payload,
					 sizeof(payload));
	} else {
		payload_len = vector->payload_len;
		memset(payload, vector->payload_fill, payload_len);
	}
	if (destination_len == SIZE_MAX || payload_len == SIZE_MAX ||
	    decode_hex(vector->signature_hex, expected, sizeof(expected)) !=
		    sizeof(expected)) {
		return 0;
	}

	if (schnorr48_verify_frame(vector->length, vector->llsec, vector->epoch,
				   vector->seqnum, destination, destination_len,
				   signer_iid, 8U, payload, payload_len,
				   expected, sizeof(expected), public_key) != 1) {
		printf("%s: C rejected independent Python signature\n", vector->name);
		return 0;
	}
	if (schnorr48_sign_frame(vector->length, vector->llsec, vector->epoch,
				 vector->seqnum, destination, destination_len,
				 signer_iid, 8U, payload, payload_len,
				 private_key, public_key, actual) != 0 ||
	    memcmp(actual, expected, sizeof(actual)) != 0) {
		printf("%s: C signature differs from Python/Rust canonical bytes\n",
		       vector->name);
		return 0;
	}

	/* Every canonical transcript field must be authenticated.  DST_LEN is
	 * passed separately because it is the sole non-wire transcript octet. */
	memcpy(mutated_destination, destination, destination_len);
	if (destination_len > 0U) {
		mutated_destination[0] ^= 1U;
	} else {
		mutated_destination[0] = 1U;
	}
	memcpy(mutated_signer, signer_iid, sizeof(mutated_signer));
	mutated_signer[0] ^= 1U;
	memcpy(mutated_payload, payload, payload_len);
	mutated_payload[0] ^= 1U;
	memcpy(mutated_signature, expected, sizeof(mutated_signature));
	mutated_signature[0] ^= 1U;

	if (!expect_rejected(vector->name, "LENGTH", vector->length ^ 1U,
			     vector->llsec, vector->epoch, vector->seqnum,
			     destination, destination_len, signer_iid, 8U,
			     payload, payload_len, expected, public_key) ||
	    !expect_rejected(vector->name, "LLSec", vector->length,
			     vector->llsec ^ 4U, vector->epoch, vector->seqnum,
			     destination, destination_len, signer_iid, 8U,
			     payload, payload_len, expected, public_key) ||
	    !expect_rejected(vector->name, "epoch", vector->length,
			     vector->llsec, vector->epoch ^ 1U, vector->seqnum,
			     destination, destination_len, signer_iid, 8U,
			     payload, payload_len, expected, public_key) ||
	    !expect_rejected(vector->name, "sequence", vector->length,
			     vector->llsec, vector->epoch,
			     (uint16_t)(vector->seqnum + 1U), destination,
			     destination_len, signer_iid, 8U, payload,
			     payload_len, expected, public_key) ||
	    !expect_rejected(vector->name, "DST_LEN", vector->length,
			     vector->llsec, vector->epoch, vector->seqnum,
			     mutated_destination,
			     destination_len == 0U ? 1U : destination_len - 1U,
			     signer_iid, 8U, payload, payload_len, expected,
			     public_key) ||
	    (destination_len > 0U &&
	     !expect_rejected(vector->name, "DST", vector->length,
			      vector->llsec, vector->epoch, vector->seqnum,
			      mutated_destination, destination_len, signer_iid,
			      8U, payload, payload_len, expected, public_key)) ||
	    (destination_len > 0U &&
	     !expect_rejected(vector->name, "omitted DST", vector->length,
			      vector->llsec, vector->epoch, vector->seqnum,
			      NULL, 0U, signer_iid, 8U, payload, payload_len,
			      expected, public_key)) ||
	    !expect_rejected(vector->name, "SIID", vector->length,
			     vector->llsec, vector->epoch, vector->seqnum,
			     destination, destination_len, mutated_signer, 8U,
			     payload, payload_len, expected, public_key) ||
	    !expect_rejected(vector->name, "payload", vector->length,
			     vector->llsec, vector->epoch, vector->seqnum,
			     destination, destination_len, signer_iid, 8U,
			     mutated_payload, payload_len, expected, public_key) ||
	    !expect_rejected(vector->name, "omitted payload byte", vector->length,
			     vector->llsec, vector->epoch, vector->seqnum,
			     destination, destination_len, signer_iid, 8U,
			     payload, payload_len - 1U, expected, public_key) ||
	    !expect_rejected(vector->name, "signature", vector->length,
			     vector->llsec, vector->epoch, vector->seqnum,
			     destination, destination_len, signer_iid, 8U,
			     payload, payload_len, mutated_signature, public_key)) {
		return 0;
	}
	if (schnorr48_verify_frame(vector->length, vector->llsec, vector->epoch,
				   vector->seqnum, destination, destination_len,
				   NULL, 8U, payload, payload_len, expected,
				   sizeof(expected), public_key) != -EINVAL ||
	    schnorr48_verify_frame(vector->length, vector->llsec, vector->epoch,
				   vector->seqnum, destination, destination_len,
				   signer_iid, 7U, payload, payload_len, expected,
				   sizeof(expected), public_key) != -EINVAL) {
		printf("%s: C accepted malformed signer identifier input\n",
		       vector->name);
		return 0;
	}

	return 1;
}

static size_t append_bytes(uint8_t *output, size_t offset, size_t capacity,
			   const uint8_t *input, size_t input_len)
{
	if (offset > capacity || input_len > capacity - offset) {
		return SIZE_MAX;
	}
	memcpy(output + offset, input, input_len);
	return offset + input_len;
}

static int reject_noncanonical_transcripts(const uint8_t private_key[32],
					   const uint8_t public_key[32],
					   const uint8_t signer_iid[8])
{
	static const uint8_t domain[] = "LICHEN-LINK-v1";
	static const uint8_t destination[] = { 0x00, 0x11, 0x22, 0x33,
					       0x44, 0x55, 0x66, 0x77 };
	static const uint8_t payload[] = { 'e', 'x', 't' };
	static const uint8_t header[] = { 0x47, 0xa6, 0x07, 0x02, 0x03 };
	uint8_t transcript[300];
	uint8_t wrong_signature[48];
	size_t offset;

	/* Legacy transcript: no versioned application domain. */
	offset = append_bytes(transcript, 0U, sizeof(transcript), header,
			      sizeof(header));
	transcript[offset++] = sizeof(destination);
	offset = append_bytes(transcript, offset, sizeof(transcript), destination,
			      sizeof(destination));
	offset = append_bytes(transcript, offset, sizeof(transcript), signer_iid, 8U);
	offset = append_bytes(transcript, offset, sizeof(transcript), payload,
			      sizeof(payload));
	if (schnorr48_sign(private_key, public_key, transcript, offset,
			   wrong_signature) != 0 ||
	    !expect_rejected("extended_addr_signed", "legacy-domain transcript",
			     header[0], header[1], header[2], 0x0203,
			     destination, sizeof(destination), signer_iid, 8U,
			     payload, sizeof(payload), wrong_signature, public_key)) {
		return 0;
	}

	/* Omit the mandatory non-wire DST_LEN delimiter. */
	offset = append_bytes(transcript, 0U, sizeof(transcript), domain,
			      sizeof(domain));
	offset = append_bytes(transcript, offset, sizeof(transcript), header,
			      sizeof(header));
	offset = append_bytes(transcript, offset, sizeof(transcript), destination,
			      sizeof(destination));
	offset = append_bytes(transcript, offset, sizeof(transcript), signer_iid, 8U);
	offset = append_bytes(transcript, offset, sizeof(transcript), payload,
			      sizeof(payload));
	if (schnorr48_sign(private_key, public_key, transcript, offset,
			   wrong_signature) != 0 ||
	    !expect_rejected("extended_addr_signed", "omitted DST_LEN",
			     header[0], header[1], header[2], 0x0203,
			     destination, sizeof(destination), signer_iid, 8U,
			     payload, sizeof(payload), wrong_signature, public_key)) {
		return 0;
	}

	/* Reorder SIID before DST instead of canonical DST || SIID. */
	offset = append_bytes(transcript, 0U, sizeof(transcript), domain,
			      sizeof(domain));
	offset = append_bytes(transcript, offset, sizeof(transcript), header,
			      sizeof(header));
	transcript[offset++] = sizeof(destination);
	offset = append_bytes(transcript, offset, sizeof(transcript), signer_iid, 8U);
	offset = append_bytes(transcript, offset, sizeof(transcript), destination,
			      sizeof(destination));
	offset = append_bytes(transcript, offset, sizeof(transcript), payload,
			      sizeof(payload));
	if (schnorr48_sign(private_key, public_key, transcript, offset,
			   wrong_signature) != 0 ||
	    !expect_rejected("extended_addr_signed", "reordered DST/SIID",
			     header[0], header[1], header[2], 0x0203,
			     destination, sizeof(destination), signer_iid, 8U,
			     payload, sizeof(payload), wrong_signature, public_key)) {
		return 0;
	}

	/* The MIC is an input to verification, never part of its transcript. */
	offset = append_bytes(transcript, 0U, sizeof(transcript), domain,
			      sizeof(domain));
	offset = append_bytes(transcript, offset, sizeof(transcript), header,
			      sizeof(header));
	transcript[offset++] = sizeof(destination);
	offset = append_bytes(transcript, offset, sizeof(transcript), destination,
			      sizeof(destination));
	offset = append_bytes(transcript, offset, sizeof(transcript), signer_iid, 8U);
	offset = append_bytes(transcript, offset, sizeof(transcript), payload,
			      sizeof(payload));
	memset(transcript + offset, 0xa5, 48U);
	offset += 48U;
	if (schnorr48_sign(private_key, public_key, transcript, offset,
			   wrong_signature) != 0 ||
	    !expect_rejected("extended_addr_signed", "MIC-included transcript",
			     header[0], header[1], header[2], 0x0203,
			     destination, sizeof(destination), signer_iid, 8U,
			     payload, sizeof(payload), wrong_signature, public_key)) {
		return 0;
	}

	return 1;
}

static int reject_noncanonical_profiles(const uint8_t private_key[32],
					const uint8_t public_key[32],
					const uint8_t signer_iid[8])
{
	static const uint8_t destination[8] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
	};
	static const uint8_t payload[3] = { 'e', 'x', 't' };
	static const uint8_t invalid_llsec[] = {
		0x26U, /* S without SI */
		0x86U, /* SI without S */
		0xe6U, /* encrypted */
		0xaaU, /* reserved MIC selector 2 */
		0xbeU, /* reserved MIC selector 7 */
	};
	uint8_t signature[48];
	uint8_t sentinel[48];

	memset(signature, 0xa5, sizeof(signature));
	memcpy(sentinel, signature, sizeof(sentinel));
	for (size_t i = 0U; i < sizeof(invalid_llsec); ++i) {
		if (schnorr48_sign_frame(0x47U, invalid_llsec[i], 0x07U,
					  0x0203U, destination,
					  sizeof(destination), signer_iid, 8U,
					  payload, sizeof(payload), private_key,
					  public_key, signature) != -EINVAL ||
		    memcmp(signature, sentinel, sizeof(signature)) != 0) {
			printf("noncanonical LLSec 0x%02x was signed or modified output\n",
			       invalid_llsec[i]);
			return 0;
		}
	}

	/* The extended mode requires exactly eight destination bytes and LENGTH
	 * must account for all canonical fields, including the 48-byte MIC. */
	if (schnorr48_sign_frame(0x47U, 0xa6U, 0x07U, 0x0203U,
				 destination, 2U, signer_iid, 8U, payload,
				 sizeof(payload), private_key, public_key,
				 signature) != -EINVAL ||
	    schnorr48_sign_frame(0x46U, 0xa6U, 0x07U, 0x0203U,
				 destination, sizeof(destination), signer_iid, 8U,
				 payload, sizeof(payload), private_key, public_key,
				 signature) != -EINVAL ||
	    schnorr48_sign_frame(0x47U, 0xa6U, 0x07U, 0x0203U,
				 destination, sizeof(destination), NULL, 8U,
				 payload, sizeof(payload), private_key, public_key,
				 signature) != -EINVAL ||
	    schnorr48_sign_frame(0xfeU, 0xa6U, 0x07U, 0x0203U,
				 destination, sizeof(destination), signer_iid, 8U,
				 payload, SIZE_MAX, private_key, public_key,
				 signature) != -EINVAL ||
	    memcmp(signature, sentinel, sizeof(signature)) != 0) {
		printf("noncanonical address, length, or SIID input was accepted\n");
		return 0;
	}

	return 1;
}

int main(void)
{
	static const char private_hex[] =
		"5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f156";
	static const char public_hex[] =
		"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
	static const char signer_hex[] = "7fd5cfc679ab6342";
	uint8_t private_key[32];
	uint8_t public_key[32];
	uint8_t signer_iid[8];

	if (decode_hex(private_hex, private_key, sizeof(private_key)) != 32U ||
	    decode_hex(public_hex, public_key, sizeof(public_key)) != 32U ||
	    decode_hex(signer_hex, signer_iid, sizeof(signer_iid)) != 8U) {
		return 1;
	}
	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
		if (!run_vector(&vectors[i], private_key, public_key, signer_iid)) {
			return 1;
		}
	}
	if (!reject_noncanonical_transcripts(private_key, public_key, signer_iid)) {
		return 1;
	}
	if (!reject_noncanonical_profiles(private_key, public_key, signer_iid)) {
		return 1;
	}

	printf("8/8 cross-language signatures, signed fields, and canonical profile checks passed\n");
	return 0;
}
