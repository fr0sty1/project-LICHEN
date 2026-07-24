/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/schnorr48.h
 * @brief Schnorr-48 link signatures per draft-lichen-schnorr-00
 *
 * 48-byte deterministic Schnorr signatures over Ed25519:
 *   16-byte truncated challenge (e) || 32-byte response (s)
 *
 * Provides 128-bit security against forgery while saving 16 bytes
 * compared to standard Ed25519 signatures.
 *
 * Security Analysis - Challenge Truncation
 * -----------------------------------------
 * Standard Ed25519/Schnorr uses a 256-bit challenge derived from a 64-byte
 * SHA-512 hash. Schnorr-48 truncates this challenge to 128 bits (16 bytes)
 * to reduce signature size from 64 bytes to 48 bytes, saving 16 bytes per
 * frame on constrained LoRa links.
 *
 * This is an intentional bandwidth/security tradeoff:
 * - 128-bit security against forgery is considered sufficient for link-layer
 *   authentication, comparable to AES-128 which is widely deployed.
 * - An attacker must perform ~2^128 operations to forge a signature, which
 *   is computationally infeasible with foreseeable technology.
 * - The truncation does not affect the discrete-log security of the response
 *   scalar, which remains a full 256-bit value.
 *
 * See draft-lichen-schnorr-00 for formal security analysis and proofs.
 */

#ifndef LICHEN_SCHNORR48_H_
#define LICHEN_SCHNORR48_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Nullability annotations for pointer safety (Clang/GCC compatibility) */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Schnorr-48 signature length */
#define SCHNORR48_SIG_LEN 48

/** Ed25519 private key length */
#define SCHNORR48_PRIVKEY_LEN 32

/** Ed25519 public key length */
#define SCHNORR48_PUBKEY_LEN 32

/** Seed length for key derivation */
#define SCHNORR48_SEED_LEN 32

/** Maximum destination address length for frame signing */
#define SCHNORR48_MAX_ADDR_LEN 8

/**
 * @brief Apply Ed25519 clamping to a scalar.
 *
 * Clears bits 0-2, sets bit 254, clears bit 255.
 * This is the standard Ed25519 scalar clamping operation.
 *
 * @param[in,out] s 32-byte scalar to clamp in place
 */
static inline void schnorr48_clamp_scalar(uint8_t *_Nonnull s)
{
	s[0] &= 248;
	s[31] &= 127;
	s[31] |= 64;
}

/**
 * @brief Derive an Ed25519 keypair from a 32-byte seed.
 *
 * @param[in]  seed    32-byte random seed
 * @param[out] privkey 32-byte private key (clamped scalar)
 * @param[out] pubkey  32-byte public key (compressed point)
 */
void schnorr48_derive_keypair(const uint8_t *_Nonnull seed,
			      uint8_t *_Nonnull privkey,
			      uint8_t *_Nonnull pubkey);

/**
 * @brief Sign a message with Schnorr-48.
 *
 * @param[in]  privkey  32-byte private key
 * @param[in]  pubkey   32-byte public key
 * @param[in]  msg      Message to sign (may be NULL if msg_len is 0)
 * @param[in]  msg_len  Message length
 * @param[out] sig      48-byte signature output
 * @return 0 on success, -EINVAL if msg is NULL with nonzero msg_len
 */
int schnorr48_sign(const uint8_t *_Nonnull privkey,
		   const uint8_t *_Nonnull pubkey,
		   const uint8_t *_Nullable msg, size_t msg_len,
		   uint8_t *_Nonnull sig);

/**
 * @brief Verify a Schnorr-48 signature.
 *
 * @param[in] pubkey   32-byte public key
 * @param[in] msg      Signed message
 * @param[in] msg_len  Message length
 * @param[in] sig      48-byte signature
 * @param[in] sig_len  Signature length (must be SCHNORR48_SIG_LEN)
 * @return true if valid, false if invalid
 */
bool schnorr48_verify(const uint8_t *_Nonnull pubkey,
		      const uint8_t *_Nonnull msg, size_t msg_len,
		      const uint8_t *_Nonnull sig, size_t sig_len);

/**
 * @brief Sign a LICHEN link-layer frame.
 *
 * Builds the signable data (length || LLSec || epoch || seqnum || dst_addr_len(1)
 * || dst_addr || payload) for domain separation and produces a 48-byte signature.
 *
 * @param[in]  length        Frame body length byte
 * @param[in]  llsec         Wire LLSec byte
 * @param[in]  epoch         Epoch byte
 * @param[in]  seqnum        Sequence number (big-endian in signable data)
 * @param[in]  dst_addr      Destination address (may be NULL if dst_addr_len is 0)
 * @param[in]  dst_addr_len  Address length (must be <= SCHNORR48_MAX_ADDR_LEN)
 * @param[in]  payload       Inner payload
 * @param[in]  payload_len   Payload length
 * @param[in]  privkey       32-byte private key
 * @param[in]  pubkey        32-byte public key
 * @param[out] sig           48-byte signature output
 * @return 0 on success, -EINVAL if dst_addr_len > SCHNORR48_MAX_ADDR_LEN
 *         or if NULL pointers are passed with nonzero lengths
 */
int schnorr48_sign_frame(uint8_t length, uint8_t llsec,
			 uint8_t epoch, uint16_t seqnum,
			 const uint8_t *_Nullable dst_addr, size_t dst_addr_len,
			 const uint8_t *_Nonnull payload, size_t payload_len,
			 const uint8_t *_Nonnull privkey,
			 const uint8_t *_Nonnull pubkey,
			 uint8_t *_Nonnull sig);

/**
 * @brief Verify a signed LICHEN link-layer frame.
 *
 * @param[in] length       Frame body length byte
 * @param[in] llsec        Wire LLSec byte
 * @param[in] epoch        Epoch byte
 * @param[in] seqnum       Sequence number
 * @param[in] dst_addr     Destination address (may be NULL if dst_addr_len is 0)
 * @param[in] dst_addr_len Address length (must be <= SCHNORR48_MAX_ADDR_LEN)
 * @param[in] payload      Inner payload (may be NULL if payload_len is 0)
 * @param[in] payload_len  Inner payload length
 * @param[in] sig          48-byte signature from the MIC field
 * @param[in] sig_len      Signature length (must be SCHNORR48_SIG_LEN)
 * @param[in] pubkey       32-byte sender public key
 * @return 1 if valid, 0 if invalid signature,
 *         -EINVAL if dst_addr_len > SCHNORR48_MAX_ADDR_LEN or if NULL
 *         pointers passed with nonzero lengths, or if sig_len != SCHNORR48_SIG_LEN
 */
int schnorr48_verify_frame(uint8_t length, uint8_t llsec,
			   uint8_t epoch, uint16_t seqnum,
			   const uint8_t *_Nullable dst_addr, size_t dst_addr_len,
			   const uint8_t *_Nullable payload, size_t payload_len,
			   const uint8_t *_Nonnull sig, size_t sig_len,
			   const uint8_t *_Nonnull pubkey);

bool schnorr48_pubkey_valid(const uint8_t *_Nonnull pubkey);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SCHNORR48_H_ */
