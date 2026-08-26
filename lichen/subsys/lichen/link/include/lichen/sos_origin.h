/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/sos_origin.h
 * @brief SOS origin signature verification (spec 18.4.1)
 *
 * Origin signatures authenticate the original sender of SOS messages across
 * relays. While link-layer signatures provide hop-by-hop authentication, the
 * origin signature persists through rebroadcasts so recipients can verify
 * who initiated the emergency.
 *
 * Wire format:
 *   8-byte origin sequence (big-endian) + 48-byte Schnorr48 signature
 *
 * Transcript format:
 *   SHA-512("LICHEN-SOS-ORIGIN-v1" || origin_ipv6 || seq || canonical_cbor)
 *
 * SECURITY: Silent drop on invalid - no error response to prevent enumeration.
 */

#ifndef LICHEN_SOS_ORIGIN_H_
#define LICHEN_SOS_ORIGIN_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Domain separator for SOS origin signatures (20 ASCII octets). */
#define SOS_ORIGIN_DOMAIN "LICHEN-SOS-ORIGIN-v1"
#define SOS_ORIGIN_DOMAIN_LEN 20

/** SOS origin signature wire length: 8-byte sequence + 48-byte Schnorr48. */
#define SOS_ORIGIN_SIGNATURE_LEN 56

/** IPv6 address length for origin address. */
#define SOS_ORIGIN_IPV6_LEN 16

/**
 * @brief Parsed SOS origin signature.
 */
struct sos_origin_signature {
	/** 64-bit monotonic origin sequence number. */
	uint64_t origin_sequence;
	/** 48-byte Schnorr48 signature. */
	uint8_t signature[48];
};

/**
 * @brief Parse an SOS origin signature from wire format.
 *
 * @param[out] out     Parsed signature structure
 * @param[in]  data    56-byte wire format data
 * @param[in]  len     Length of data (must be SOS_ORIGIN_SIGNATURE_LEN)
 * @return 0 on success, -EINVAL if len != 56 or NULL pointers
 */
int sos_origin_signature_parse(struct sos_origin_signature *out,
			       const uint8_t *data, size_t len);

/**
 * @brief Serialize an SOS origin signature to wire format.
 *
 * @param[in]  sig   Signature structure to serialize
 * @param[out] out   56-byte output buffer
 * @param[in]  len   Output buffer length (must be >= SOS_ORIGIN_SIGNATURE_LEN)
 * @return 0 on success, -EINVAL if len < 56 or NULL pointers
 */
int sos_origin_signature_serialize(const struct sos_origin_signature *sig,
				   uint8_t *out, size_t len);

/**
 * @brief Compute the SOS origin signature transcript (SHA-512 digest).
 *
 * Transcript = SHA-512(domain || origin_ipv6 || seq_be || cbor_payload)
 *
 * @param[in]  origin_ipv6   16-byte packed IPv6 address of originator
 * @param[in]  origin_seq    64-bit origin sequence number
 * @param[in]  payload_cbor  Canonical CBOR encoding of SOS payload
 * @param[in]  payload_len   Length of CBOR payload
 * @param[out] digest        64-byte SHA-512 output
 * @return 0 on success, -EINVAL on NULL pointers
 */
int sos_origin_compute_transcript(const uint8_t *origin_ipv6,
				  uint64_t origin_seq,
				  const uint8_t *payload_cbor,
				  size_t payload_len,
				  uint8_t *digest);

/**
 * @brief Verify an SOS origin signature.
 *
 * Verifies that the SOS message was signed by the holder of the private key
 * corresponding to the given public key. Silent failure (returns false) on
 * invalid signatures to prevent enumeration attacks.
 *
 * @param[in] pubkey       32-byte Ed25519 public key
 * @param[in] origin_ipv6  16-byte packed IPv6 address of originator
 * @param[in] payload_cbor Canonical CBOR encoding of SOS payload
 * @param[in] payload_len  Length of CBOR payload
 * @param[in] sig          Parsed origin signature
 * @return true if signature is valid, false otherwise
 */
bool sos_origin_verify(const uint8_t *pubkey,
		       const uint8_t *origin_ipv6,
		       const uint8_t *payload_cbor,
		       size_t payload_len,
		       const struct sos_origin_signature *sig);

/**
 * @brief Generate an SOS origin signature.
 *
 * Signs the SOS message with a domain-separated Schnorr48 signature.
 *
 * @param[in]  privkey      32-byte Ed25519 private scalar (clamped)
 * @param[in]  pubkey       32-byte Ed25519 public key
 * @param[in]  origin_ipv6  16-byte packed IPv6 address of originator
 * @param[in]  origin_seq   64-bit origin sequence number
 * @param[in]  payload_cbor Canonical CBOR encoding of SOS payload
 * @param[in]  payload_len  Length of CBOR payload
 * @param[out] sig          Output signature structure
 * @return 0 on success, -EINVAL on NULL pointers, -ENOSYS if signing not built
 */
int sos_origin_sign(const uint8_t *privkey,
		    const uint8_t *pubkey,
		    const uint8_t *origin_ipv6,
		    uint64_t origin_seq,
		    const uint8_t *payload_cbor,
		    size_t payload_len,
		    struct sos_origin_signature *sig);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SOS_ORIGIN_H_ */
