# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Short address assignment (spec 02-physical-link.md 4.5, 04-network.md 12.3).

Implements:

- Derived short address via ``crc32_ieee(EUI-64, key=0x4c494348454e)``
  truncated to 16 bits (spec 4.5 top pseudocode, 04-network 12.3,
  06-security 15.5). The duplicate 4.5 section at the end of
  02-physical-link.md uses ``fnv1a32`` with the same XOR-seed convention;
  this module follows the canonical ``crc32_ieee`` form per the
  ``project-LICHEN-bo37`` fix and exposes the FNV variant via
  :func:`hash_32` for oracle parity.

- DAD retry with seed mixing (``mixed[4..8] ^= seed.to_le_bytes()``)
  across 1..255 (256 total candidates including seedless base).

- Coordinator-managed assignment via DAO / DAO-ACK abstraction and
  table maintenance.

- DAD probe schedule with 0-500 ms jitter (3 probes).

- Conflict resolution via ``+1 mod 0xffef`` fallback (bd 1.8.2.6) in
  addition to the canonical seed-mixing retry.

- Collision detection via multi-pubkey tracking per short address
  (signature-mismatch safety net).

- Transition helper from self-assigned to coordinator-managed addresses.
"""

from __future__ import annotations

import binascii
import logging
import random
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_LICHEN_KEY = 0x4C494348454E  # ASCII "LICHEN"
_LICHEN_CRC32_INIT = _LICHEN_KEY & 0xFFFFFFFF  # 0x4348454E

# 802.15.4 reserves 0xFFFF (broadcast) and 0xFFFE (unspecified); LICHEN
# uses 0xffef as the wrap boundary for the +1 mod fallback per
# bd project-LICHEN-worker6-l1qw.1.8.2.6 (65519 values, 0x0000..0xFFEF).
# Additionally, 0x0000 is reserved as null/unspecified in LICHEN.
SHORT_ADDR_MAX_INCREMENTAL = 0xFFEF
SHORT_ADDR_RESERVED_NULL = 0x0000
SHORT_ADDR_RESERVED_UNSPECIFIED = 0xFFFE
SHORT_ADDR_RESERVED_BROADCAST = 0xFFFF
SHORT_ADDR_RESERVED = frozenset({
    SHORT_ADDR_RESERVED_NULL,
    SHORT_ADDR_RESERVED_UNSPECIFIED,
    SHORT_ADDR_RESERVED_BROADCAST,
})
DAD_MAX_SEED = 255
DAD_PROBE_COUNT = 3
DAD_JITTER_MIN_MS = 0
DAD_JITTER_MAX_MS = 500


def is_reserved_addr(addr: int) -> bool:
    """Check if a short address is in the reserved range.

    Reserved addresses per 802.15.4 and LICHEN spec:
    - 0x0000: null/unspecified
    - 0xFFFE: 802.15.4 unspecified
    - 0xFFFF: 802.15.4 broadcast
    """
    return addr in SHORT_ADDR_RESERVED


def _check_eui64(eui64: bytes) -> None:
    if not isinstance(eui64, (bytes, bytearray)):
        raise TypeError("eui64 must be bytes")
    if len(eui64) != 8:
        raise ValueError(f"EUI-64 must be 8 bytes, got {len(eui64)}")


def crc32_ieee(data: bytes, init: int = _LICHEN_CRC32_INIT) -> int:
    """CRC32-IEEE (ISO HDLC, poly 0xedb88320) with initial value ``init``.

    Uses :func:`binascii.crc32` which implements the ISO HDLC variant
    (init, xorout, refin). The ``init`` defaults to the LICHEN key
    ``0x4348454e`` (low 32 bits of ASCII "LICHEN").
    """
    return binascii.crc32(data, init) & 0xFFFFFFFF


def hash_32_fnv1a(data: bytes) -> int:
    """FNV-1a32 hash (basis 0x811c9dc5) for oracle parity with the stale 4.5.

    This is the ``hash_32`` used for TDMA / channel selection and was the
    earlier short-address primitive before ``project-LICHEN-bo37`` switched
    DAD to ``crc32_ieee``. Exposed so vectors can cross-check both.
    """
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def derive_short_addr(eui64: bytes) -> int:
    """Derive a 16-bit short address from EUI-64 (spec 4.5).

    ``hash = crc32_ieee(eui64, key=0x4c494348454e); return hash & 0xFFFF``.
    """
    _check_eui64(eui64)
    return crc32_ieee(bytes(eui64)) & 0xFFFF


def derive_short_addr_with_seed(eui64: bytes, seed: int) -> int:
    """Derive with seed mixing: ``mixed[4..8] ^= seed.to_le_bytes()``."""
    _check_eui64(eui64)
    if not 0 <= seed <= 0xFFFFFFFF:
        raise ValueError(f"seed out of range: {seed}")
    mixed = bytearray(eui64)
    seed_le = seed.to_bytes(4, "little")
    for i in range(4):
        mixed[4 + i] ^= seed_le[i]
    return crc32_ieee(bytes(mixed)) & 0xFFFF


def derive_short_addr_crc16(eui64: bytes) -> int:
    """CRC16-CCITT candidate (bd 1.8.2.4 alternative oracle).

    Uses ``binascii.crc_hqx`` (poly 0x1021, init 0xFFFF) over the 8-byte
    EUI-64. This satisfies the "CRC16(EUI-64) candidate computation"
    description while the canonical :func:`derive_short_addr` remains
    CRC32-based per spec. Both map to 16 bits.
    """
    _check_eui64(eui64)
    return binascii.crc_hqx(bytes(eui64), 0xFFFF) & 0xFFFF


def dad_retry(eui64: bytes, existing_addrs: set[int]) -> int | None:
    """DAD retry per spec 4.5 pseudocode.

    Tries the base derivation then seeds 1..255 with XOR mixing.
    Automatically skips reserved addresses (0x0000, 0xFFFE, 0xFFFF).
    Returns the first non-colliding, non-reserved address or ``None``
    if all 256 candidates are exhausted or reserved (caller must fall
    back to extended mode).
    """
    _check_eui64(eui64)
    addr = derive_short_addr(eui64)
    if addr not in existing_addrs and not is_reserved_addr(addr):
        return addr
    for seed in range(1, DAD_MAX_SEED + 1):
        addr = derive_short_addr_with_seed(eui64, seed)
        if addr not in existing_addrs and not is_reserved_addr(addr):
            return addr
    return None


def dad_retry_incremental(start: int, existing_addrs: set[int]) -> int | None:
    """Conflict resolution via ``+1 mod 0xffef`` (bd 1.8.2.6).

    Starting from ``(start + 1) % 0xFFF0`` probes up to ``0xFFEF`` distinct
    values. Skips reserved addresses (0x0000). Returns ``None`` if all
    non-reserved addresses are taken. This is the incremental fallback
    described in the beads child; the canonical retry is :func:`dad_retry`
    (seed mixing). Both are provided for compliance.
    """
    if not 0 <= start <= 0xFFFF:
        raise ValueError(f"start out of range: {start}")
    for offset in range(1, SHORT_ADDR_MAX_INCREMENTAL + 1):
        cand = (start + offset) % (SHORT_ADDR_MAX_INCREMENTAL + 1)
        # Skip reserved null address (0x0000); 0xFFFE/0xFFFF already excluded
        # by SHORT_ADDR_MAX_INCREMENTAL boundary
        if cand not in existing_addrs and cand != SHORT_ADDR_RESERVED_NULL:
            return cand
    return None


def dad_jitter_ms(rng: random.Random | None = None) -> int:
    """Random jitter for DAD probes (0..500 ms, bd 1.8.2.5)."""
    r = rng if rng is not None else random
    return r.randint(DAD_JITTER_MIN_MS, DAD_JITTER_MAX_MS)


def dad_probe_schedule(
    count: int = DAD_PROBE_COUNT,
    rng: random.Random | None = None,
) -> list[int]:
    """Return ``count`` jitter values for the 3-probe DAD sequence."""
    if count < 1:
        raise ValueError(f"count must be >=1, got {count}")
    return [dad_jitter_ms(rng) for _ in range(count)]


# ---------------------------------------------------------------------------
# DAD message abstraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DadProbe:
    """DAD probe announcing a candidate short address."""

    eui64: bytes
    short_addr: int
    jitter_ms: int = 0


@dataclass(frozen=True)
class DadConflict:
    """DAD conflict: ``existing_short`` already owned by ``owner_eui64``."""

    short_addr: int
    owner_eui64: bytes
    challenger_eui64: bytes


# ---------------------------------------------------------------------------
# Coordinator-managed assignment (DAO / DAO-ACK)
# ---------------------------------------------------------------------------


@dataclass
class DaoRequest:
    """DAO carrying an address assignment request (simplified)."""

    eui64: bytes
    requested_short: int | None = None
    dao_sequence: int = 0


@dataclass
class DaoAck:
    """DAO-ACK carrying the coordinator's assigned short address."""

    eui64: bytes
    assigned_short: int | None
    status: int = 0  # 0 = accepted, 1 = rejected (fallback to extended)
    dao_sequence: int = 0


class CoordinatorAddressTable:
    """Coordinator address table (bd 1.8.1.4 / RPL DAO-ACK).

    Maintains bidirectional mapping short <-> EUI-64 for the mesh.
    Allocation prefers the spec DAD derivation; on collision uses
    :func:`dad_retry` (seed mixing) then the ``+1 mod 0xffef`` fallback
    for full coverage, and returns ``None`` if the pool is exhausted.
    """

    def __init__(self) -> None:
        self._by_short: dict[int, bytes] = {}
        self._by_eui: dict[bytes, int] = {}

    def lookup_by_short(self, short_addr: int) -> bytes | None:
        return self._by_short.get(short_addr)

    def lookup_by_eui(self, eui64: bytes) -> int | None:
        return self._by_eui.get(bytes(eui64))

    def allocate(self, eui64: bytes) -> int | None:
        _check_eui64(eui64)
        key = bytes(eui64)
        if key in self._by_eui:
            return self._by_eui[key]
        existing = set(self._by_short.keys())
        cand = dad_retry(key, existing)
        if cand is None:
            # Seed space exhausted but pool may still have free slots via
            # incremental scan (bd 1.8.2.6 coverage).
            base = derive_short_addr(key)
            cand = dad_retry_incremental(base, existing)
        if cand is None:
            logger.warning("coordinator pool exhausted for %s", key.hex())
            return None
        self._by_short[cand] = key
        self._by_eui[key] = cand
        return cand

    def release(self, eui64: bytes) -> bool:
        key = bytes(eui64)
        short = self._by_eui.pop(key, None)
        if short is None:
            return False
        self._by_short.pop(short, None)
        return True

    def handle_dao(self, req: DaoRequest) -> DaoAck:
        """Process a DAO and return a DAO-ACK (bd 1.8.1.1)."""
        _check_eui64(req.eui64)
        key = bytes(req.eui64)
        if key in self._by_eui:
            return DaoAck(
                eui64=key,
                assigned_short=self._by_eui[key],
                status=0,
                dao_sequence=req.dao_sequence,
            )
        # If requester asked for a specific address and it is free, grant it.
        if req.requested_short is not None:
            req_s = req.requested_short
            if not 0 <= req_s <= 0xFFFF:
                raise ValueError(f"requested_short out of range: {req_s}")
            # SECURITY: Explicit requests for reserved addresses (0x0000, 0xFFFE,
            # 0xFFFF) MUST be rejected with status=1 per 802.15.4 and LICHEN spec.
            # Do NOT silently substitute a different address when the client
            # explicitly requested a specific (reserved) address (r2-P1-11).
            if is_reserved_addr(req_s):
                return DaoAck(
                    eui64=key,
                    assigned_short=None,
                    status=1,
                    dao_sequence=req.dao_sequence,
                )
            if req_s not in self._by_short:
                self._by_short[req_s] = key
                self._by_eui[key] = req_s
                return DaoAck(
                    eui64=key,
                    assigned_short=req_s,
                    status=0,
                    dao_sequence=req.dao_sequence,
                )
            # Requested address is taken; fall through to allocation.
        assigned = self.allocate(key)
        if assigned is None:
            return DaoAck(
                eui64=key,
                assigned_short=None,
                status=1,
                dao_sequence=req.dao_sequence,
            )
        return DaoAck(eui64=key, assigned_short=assigned, status=0, dao_sequence=req.dao_sequence)

    def handle_dao_ack(
        self, ack: DaoAck, *, self_eui64: bytes | None = None
    ) -> bool:
        """Apply a received DAO-ACK at the node side (store assignment).

        Args:
            ack: The DAO-ACK message from the coordinator.
            self_eui64: The node's own EUI-64 for identity validation. When
                provided, the ACK is rejected if ``ack.eui64`` does not match.
                This SHOULD be provided in production to prevent address table
                corruption from spoofed or misdirected DAO-ACKs (r2-P2-31).

        Returns:
            True if the ACK was accepted (status 0, short present, valid).

        SECURITY: This method trusts that the DAO-ACK originates from an
        authenticated coordinator. The caller MUST verify the link-layer
        signature before calling this method (per spec 8.10: link-layer
        signatures REQUIRED on all RPL control frames). A DAO-ACK received
        without link-layer authentication MUST NOT be processed.
        """
        # SECURITY: Validate ack.eui64 format early to reject malformed DAO-ACKs
        # before any table mutation (r3-P1-6).
        _check_eui64(ack.eui64)

        if ack.status != 0 or ack.assigned_short is None:
            return False
        if not 0 <= ack.assigned_short <= 0xFFFF:
            raise ValueError(f"assigned_short out of range: {ack.assigned_short}")

        # SECURITY: Reject reserved addresses (0x0000, 0xFFFE, 0xFFFF) even if
        # the coordinator sends them. A malicious or buggy coordinator must not
        # be able to assign reserved addresses to nodes (r2-P2-32, r2-P2-33).
        # Per 802.15.4 and LICHEN spec (see handle_dao for the request-side check).
        if is_reserved_addr(ack.assigned_short):
            logger.warning(
                "rejecting DAO-ACK with reserved address 0x%04x for %s",
                ack.assigned_short,
                ack.eui64.hex(),
            )
            return False

        key = bytes(ack.eui64)

        # SECURITY: When self_eui64 is provided, reject DAO-ACKs for other
        # identities. This prevents address table corruption from spoofed
        # or misdirected DAO-ACKs (r2-P2-31).
        if self_eui64 is not None:
            _check_eui64(self_eui64)
            if key != bytes(self_eui64):
                logger.warning(
                    "rejecting DAO-ACK for different identity: ack.eui64=%s, self=%s",
                    key.hex(),
                    self_eui64.hex(),
                )
                return False

        # Idempotent update.
        old = self._by_eui.get(key)
        if old is not None and old != ack.assigned_short:
            self._by_short.pop(old, None)
        self._by_short[ack.assigned_short] = key
        self._by_eui[key] = ack.assigned_short
        return True

    def table_snapshot(self) -> dict[int, str]:
        """Snapshot for vectors: short -> eui64 hex."""
        return {k: v.hex() for k, v in self._by_short.items()}

    def __len__(self) -> int:
        return len(self._by_short)


# ---------------------------------------------------------------------------
# Collision detection (safety net)
# ---------------------------------------------------------------------------


@dataclass
class CollisionEvent:
    """Recorded short-address collision (multiple pubkeys)."""

    short_addr: int
    pubkeys: set[bytes] = field(default_factory=set)
    count: int = 0


class ShortAddressCollisionDetector:
    """Safety-net collision detector (bd 1.8.3).

    Tracks ``short_addr -> set(pubkey)``. A collision is when the same
    16-bit address is observed signed by distinct public keys
    (signature-mismatch implication). Also logs warnings.
    """

    def __init__(self) -> None:
        self._by_short: dict[int, set[bytes]] = {}
        self._events: list[CollisionEvent] = []

    def observe(self, short_addr: int, pubkey: bytes) -> bool:
        """Observe ``pubkey`` using ``short_addr``.

        Returns True if this observation creates or confirms a collision
        (more than one distinct pubkey for the address).
        """
        if not 0 <= short_addr <= 0xFFFF:
            raise ValueError(f"short_addr out of range: {short_addr}")
        if len(pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
        bucket = self._by_short.setdefault(short_addr, set())
        is_new_key = pubkey not in bucket
        bucket.add(bytes(pubkey))
        is_collision = len(bucket) > 1
        if is_collision:
            # Record event
            if is_new_key:
                logger.warning(
                    "short address collision: 0x%04x now has %d pubkeys",
                    short_addr,
                    len(bucket),
                )
            # Update or append event list
            for ev in self._events:
                if ev.short_addr == short_addr:
                    ev.pubkeys = set(bucket)
                    ev.count += 1
                    break
            else:
                self._events.append(
                    CollisionEvent(short_addr=short_addr, pubkeys=set(bucket), count=1)
                )
        return is_collision

    def is_collision(self, short_addr: int) -> bool:
        b = self._by_short.get(short_addr)
        return b is not None and len(b) > 1

    def pubkeys_for(self, short_addr: int) -> set[bytes]:
        return set(self._by_short.get(short_addr, set()))

    def collisions(self) -> list[CollisionEvent]:
        return list(self._events)

    def clear(self, short_addr: int | None = None) -> None:
        if short_addr is None:
            self._by_short.clear()
            self._events.clear()
        else:
            self._by_short.pop(short_addr, None)
            self._events = [e for e in self._events if e.short_addr != short_addr]


# ---------------------------------------------------------------------------
# Transition: self-assigned -> coordinator-managed
# ---------------------------------------------------------------------------


def transition_to_coordinator_managed(
    eui64: bytes,
    self_assigned: int | None,
    coordinator: CoordinatorAddressTable,
    dao_sequence: int = 0,
) -> DaoAck:
    """Transition helper (bd 1.8.4).

    The node previously used ``self_assigned`` (derived via DAD or random).
    It now requests a coordinator-managed address via DAO. If the
    self-assigned address is still free at the coordinator it is retained;
    otherwise a new address is allocated. Returns the DAO-ACK.
    """
    _check_eui64(eui64)
    req = DaoRequest(
        eui64=bytes(eui64),
        requested_short=self_assigned,
        dao_sequence=dao_sequence,
    )
    return coordinator.handle_dao(req)


__all__ = [
    "SHORT_ADDR_MAX_INCREMENTAL",
    "SHORT_ADDR_RESERVED",
    "SHORT_ADDR_RESERVED_BROADCAST",
    "SHORT_ADDR_RESERVED_NULL",
    "SHORT_ADDR_RESERVED_UNSPECIFIED",
    "CoordinatorAddressTable",
    "CollisionEvent",
    "DadConflict",
    "DadProbe",
    "DaoAck",
    "DaoRequest",
    "ShortAddressCollisionDetector",
    "crc32_ieee",
    "dad_jitter_ms",
    "dad_probe_schedule",
    "dad_retry",
    "dad_retry_incremental",
    "derive_short_addr",
    "derive_short_addr_crc16",
    "derive_short_addr_with_seed",
    "hash_32_fnv1a",
    "is_reserved_addr",
    "transition_to_coordinator_managed",
]
