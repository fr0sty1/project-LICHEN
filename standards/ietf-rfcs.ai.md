# IETF RFCs — AI Reference

Ultra-concise reference for implementing LICHEN. Constants, sizes, pitfalls only.

---

## IPv6 (RFC 8200) + Addressing (RFC 4291, 4193)

- Header: 40 bytes fixed
- Fields: version(4b)=6, traffic-class(8b), flow-label(20b), payload-len(16b), next-hdr(8b), hop-limit(8b), src(128b), dst(128b)
- Next header: 17=UDP, 58=ICMPv6, 43=Routing, 44=Fragment, 59=NoNext
- Min MTU: 1280 bytes
- Link-local: fe80::/10 | Multicast: ff00::/8 | native LICHEN: 0200::/8
- Scope: 1=interface, 2=link, 5=site, e=global
- Multicast: ff02::1 (all-nodes), ff02::2 (all-routers)
- LICHEN link-local IID: SHA-256(public key)[0:8], clear U/L bit

## UDP (RFC 768)

- Header: 8 bytes — src-port(16b), dst-port(16b), length(16b), checksum(16b)
- Checksum: mandatory in IPv6, uses pseudo-header

## ICMPv6 (RFC 4443)

- Type(8b) + Code(8b) + Checksum(16b) + Body
- Echo: 128/129 | Dest Unreachable: 1 | Too Big: 2 | Time Exceeded: 3

---

## SCHC (RFC 8724)

- Primary compression for LICHEN (not 6LoWPAN)
- Rule ID: variable length, context-specific
- Compression: field-by-field with CDA (Compression/Decompression Actions)
- CDAs: not-sent, value-sent, mapping-sent, LSB, compute-*, DevIID, AppIID
- Fragmentation modes: No-ACK, ACK-Always, ACK-on-Error
- Fragment header: Rule ID + DTAG + W + FCN
- FCN=all-1s: last fragment
- MIC: CRC-32 over reassembled packet

## 6LoRH (RFC 8138)

- RPL artifacts compression
- RPI (RPL Packet Info): Instance + Rank
- SRH compression for downward routes

---

## RPL (RFC 6550) + MRHOF (RFC 6719)

- ICMPv6 type=155, codes: 0=DIS, 1=DIO, 2=DAO, 3=DAO-ACK
- Rank: 16-bit, lower=closer to root (0=root, 0xFFFF=infinite)
- LICHEN: Non-Storing mode with source routing
- MRHOF: ETX-based path cost with hysteresis

## Trickle (RFC 6206)

- Params: Imin, Imax, k (redundancy constant)
- Consistent: double interval | Inconsistent: reset to Imin

## RPL Source Routing (RFC 6554)

- Routing Header type=3, addresses root-to-leaf

---

## CoAP (RFC 7252)

- Port: 5683 (unsecured), 5684 (DTLS)
- Header: 4 bytes — Ver(2b)=1, T(2b), TKL(4b), Code(8b), Message-ID(16b)
- Types: 0=CON, 1=NON, 2=ACK, 3=RST | Token: 0-8 bytes
- Methods: 0.01=GET, 0.02=POST, 0.03=PUT, 0.04=DELETE
- Success: 2.01=Created, 2.02=Deleted, 2.04=Changed, 2.05=Content
- Key options: 6=Observe, 11=Uri-Path, 12=Content-Format, 23=Block2, 27=Block1
- Content-Format: 0=text, 42=octet-stream, 50=JSON, 60=CBOR

## CoAP Block (RFC 7959)

- Block value: NUM(variable) + M(1b) + SZX(3b), size=2^(SZX+4), range 16-1024
- Block1=request payload, Block2=response payload, M=1 means more blocks

## CoRE Link Format (RFC 6690)

- Discovery: /.well-known/core | Format: `<uri>;rt=type;ct=fmt`

---

## CBOR (RFC 8949)

- Major types (3 high bits): 0=uint, 1=negint, 2=bstr, 3=tstr, 4=array, 5=map, 6=tag, 7=float/simple
- Length encoding: 0-23=inline, 24=1byte, 25=2byte, 26=4byte, 27=8byte, 31=indefinite
- Simple values: 20=false, 21=true, 22=null, 23=undefined
- Float16/32/64: type 7 with length 25/26/27
- Tags: 0=datetime-string, 1=epoch, 2=positive-bignum, 3=negative-bignum, 32=URI
- Canonical: shortest encoding, map keys sorted

## SenML (RFC 8428)

- JSON or CBOR array of records
- Base: bn=base-name, bt=base-time, bu=base-unit, bv=base-value
- Record: n=name, u=unit, v=value, vs=string-value, vb=bool-value, vd=data-value, t=time, s=sum
- CBOR labels: -2=bv, -3=bs, -4=bt, -5=bu, -6=bn, 0=n, 1=u, 2=v, 3=vs, 4=vb, 5=s, 6=t, 8=vd

---

## OSCORE (RFC 8613)

- E2E security for CoAP over untrusted proxies
- Option 9, OSCORE flag byte + PIV + KID context
- Encrypts: Code, Options (except outer), Payload
- Algorithms: AES-CCM-16-64-128 (default)
- Contexts: Sender ID, Recipient ID, Master Secret, Master Salt
- Sequence number: Partial IV, must not repeat with same key
- Replay window: server tracks

## Group OSCORE (RFC 9594)

- Group ID in KID context
- Signature mode for source authentication
- Pairwise mode for efficiency

## EDHOC (RFC 9528)

- 3-message key exchange
- Cipher suites: 0=X25519+AES-CCM, 2=P-256+AES-CCM
- Output: OSCORE Master Secret + Master Salt
- Compact: ~100 bytes total

## COSE (RFC 9052/9053)

- COSE_Sign1: [protected, unprotected, payload, signature]
- COSE_Encrypt0: [protected, unprotected, ciphertext]
- COSE_Mac0: [protected, unprotected, payload, tag]
- Headers: 1=alg, 2=crit, 3=content-type, 4=kid, 5=IV, 6=partial-IV
- Algorithms: -7=ES256, -8=EdDSA, -25=ECDH-ES+HKDF-256, 10=AES-CCM-16-64-128

---

## Ed25519 (RFC 8032)

- Curve: Edwards 25519
- Private key: 32 bytes (seed)
- Public key: 32 bytes (compressed point)
- Signature: 64 bytes (R + S)
- Deterministic: no random nonce needed
- LICHEN uses: link signatures (compressed to 48 bytes via Schnorr variant)

## X25519 (RFC 7748)

- ECDH key agreement
- Private key: 32 bytes (clamped scalar)
- Public key: 32 bytes (u-coordinate)
- Shared secret: 32 bytes

---

## Common Pitfalls

- IPv6 checksum: includes pseudo-header (src, dst, length, next-hdr)
- CBOR map keys: must be sorted by encoded length, then lexicographically
- CoAP Message-ID: for deduplication, token for request/response matching
- OSCORE PIV: MUST increment, never reuse with same Sender ID
- RPL Rank: 0 = DODAG root, 0xFFFF = INFINITE_RANK
- Trickle: reset on ANY inconsistency (new version, new DODAG, etc.)
- SCHC Rule ID 0: typically reserved for uncompressed packets
- Block-wise: can't mix Block1 and Block2 in same message
- SenML base values: apply to ALL subsequent records until overwritten
