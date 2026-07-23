# LICHEN IETF Drafts Reference (AI-Optimized)

## draft-lichen-schnorr-00: Truncated Schnorr Signatures
```
SIZE=48B (e=16B + s=32B)  SECURITY=128-bit  CURVE=Ed25519  HASH=SHA-512
NONCE=H(privkey||msg) mod L  # deterministic

sign(privkey, pubkey, msg):
  r = H(privkey || msg) mod L; R = r * B
  e = H(R || pubkey || msg)[0:16]
  s = (r + (e||zeros(16)) * privkey) mod L
  return e || s  # 48 bytes

verify(pubkey, msg, sig):
  e, s = sig[0:16], sig[16:48]
  R' = s*B - (e||zeros(16))*pubkey
  return H(R' || pubkey || msg)[0:16] == e
```

## draft-lichen-link-01: Link Layer Frame Format
```
+--------+-------+------+-------+-------+--------+-----+
| LENGTH | LLSec | EPO  | SEQ   |  DST  |  PLD   | MIC |
+--------+-------+------+-------+-------+--------+-----+
   1B       1B     1B     2B    0/2/8B   var   0/4/8B

LLSec: [R:1][E:1][S:1][MicLen:3][AddrMode:2]
  R=reserved(0)  E=encrypted  S=signed  MicLen: 0=4B,1=8B
  AddrMode: 0=None(bcast), 1=Short(2B), 2=Extended(EUI-64,8B), 3=Elided

EPO = epoch (wraps 256, inc on reboot)
SEQ = sequence (big-endian, wraps 65536)
MIC_INPUT = LENGTH || LLSec || EPO || SEQ || DST || PLD

MIN_HEADER=5B  REPLAY_WINDOW>=64  EPO_JUMP_MAX=4
```

## draft-lichen-schc-lora-00: SCHC Profile
```
RULE_ID = 8 bits

RULE 0: Link-local IPv6+UDP    | fe80:: src+dst, port 5683±15 | 2B
RULE 1: Mesh-local IPv6+UDP    | fd00::/8 same prefix         | 10B
RULE 2: Global IPv6+UDP        | 2000::/3                     | 41B
RULE 3: ICMPv6 RPL (DIO/DAO)   | NH=58, Type=155              | 2B
RULE 255: No compression (fallback)

FRAGMENTATION (ACK-on-Error M=1 N=6 T=0 from constants.toml [schc.fragment], RuleIDs per schc.rule_id, bitmap MSB-first, MIC=RCS=CRC32/4B, timers 10s/3/60s):
  Regular: RuleID(8) + W(1) + FCN(6) + Tile
  All-1:   RuleID(8) + W(1) + 0b111111 + RCS(32) + Tile
  ACK:     RuleID(8) + control(8) + len(8) + bitmap
  Vectors: test/vectors/ + bead hwx9-vectors
```

## draft-lichen-rpl-lora-00: RPL Configuration
```
MODE = Non-Storing (MOP=1)

TRICKLE: Imin=4s  Imax=2^8*Imin=17min  k=10
MRHOF: MinHopRankInc=256  ETX_factor=0.5  RTT_factor=0.1  SWITCH_THRESH=192
RANK = Rank(parent) + 256 * (1 + 0.5*ETX + 0.1*RTT)

DAO: Initial=0-2s  Retry=4/8/16s  Refresh=30min  Lifetime=1hr
DIS: rate limit 1/10s
BIDIRECTIONAL: DIO->DAO->DAO-ACK

SECURITY: Unsecured (link-layer sigs provide auth)

DIO OPTIONS (types TBD):
  SCHC Version: T(1)+L(1)+Ver(1)
  Time Sync:    T(1)+L(1)+Stratum(1)+Rsv(1)+Timestamp(4)
  Congestion:   T(1)+L(1)+Level(1)

MEMORY: ~300B (DODAG~100 + Parents~150 + Trickle~20 + DAO~20)
```

## LoRa PHY Reference
```
DEFAULT: SF10/125kHz/CR4-5  MTU=50-250B

SF7:  5470bps  72ms/50B   RTT 200-500ms
SF9:  1760bps  206ms/50B  RTT 500-1500ms
SF12: 293bps   1319ms/50B RTT 3-10s

DUTY: EU868-g1=1%(36pkt/hr) EU868-g3=10% US/AU915=none
```

## Size Quick Reference
```
Ed25519 sig:     64B    Schnorr48:    48B (25% less)
IPv6 hdr:        40B    UDP hdr:       8B    CoAP base: 4B

Link min hdr:     5B    +EUI-64:      13B   +sig: 53-57B

SCHC Rule 0:      2B (link-local, was 48B)
SCHC Rule 1:     10B (mesh-local)
SCHC Rule 3:      2B (RPL control)
```
