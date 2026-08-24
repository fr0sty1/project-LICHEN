# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SCHC rule context and selection (RFC 8724 section 7).

A :class:`SchcContext` holds the active rule set and selects a matching rule for
a set of field values: the first rule (by ascending rule ID) whose every
descriptor is satisfied — EQUAL/MSB constraints hold and all fields needed for
the residue are present. If no compression rule matches, selection falls back to
the uncompressed rule (ID 255).

This is the piece the compressor/decompressor build on: given parsed header
fields, pick a rule, then call :func:`lichen.schc.codec.compress`.
"""

from __future__ import annotations

import threading
import weakref
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from lichen.schc.codec import SchcError, compress, decompress
from lichen.schc.rules import (
    GLOBAL_OSCORE_RULE,
    LINK_LOCAL_OSCORE_RULE,
    MO,
    RULE_ID_UNCOMPRESSED,
    RULE_SET_REGISTRIES,
    RULE_SET_VERSION,
    Rule,
    SchcRuleVersionOption,
)

if TYPE_CHECKING:
    from lichen.schc.headers import PacketProfile


def rule_matches(rule: Rule, fields: dict[str, int]) -> bool:
    for fd in rule.fields:
        value = fields.get(fd.field_id)
        if value is None:
            if fd.requires_value():
                return False
            continue
        if type(value) is not int or not 0 <= value < (1 << fd.length_bits):
            return False
        if fd.mo == MO.EQUAL and value != fd.target_value:
            return False
        if fd.mo == MO.MSB:
            if fd.mo_arg is None or fd.mo_arg > fd.length_bits:
                return False
            shift = fd.length_bits - fd.mo_arg
            if (value >> shift) != (fd.target_value >> shift):
                return False
        if fd.mo == MO.MATCH_MAPPING and (fd.mapping is None or value not in fd.mapping):
            return False
    return True


class SchcContext:
    def __init__(
        self,
        rules: Mapping[int, Rule] | None = None,
        version: int | None = None,
    ) -> None:
        if rules is None:
            resolved = RULE_SET_VERSION if version is None else version
            if type(resolved) is not int or resolved not in RULE_SET_REGISTRIES:
                raise ValueError(
                    f"unsupported local SCHC rule set version {resolved}; "
                    f"implemented versions: {tuple(RULE_SET_REGISTRIES)}"
                )
            source = RULE_SET_REGISTRIES[resolved]
            self._version: int | None = resolved
        else:
            if version is not None:
                raise ValueError("custom SCHC rules cannot claim a standardized rule set version")
            source = rules
            self._version = None
        _oscore_ids = {LINK_LOCAL_OSCORE_RULE.rule_id, GLOBAL_OSCORE_RULE.rule_id}

        def _rule_sort_key(item: tuple[int, Rule]) -> tuple[int, int]:
            rid = item[0]
            return (0 if rid in _oscore_ids else 1, rid)

        self._rules: dict[int, Rule] = dict(sorted(source.items(), key=_rule_sort_key))

    @property
    def version(self) -> int | None:
        """Rule set version (8-bit, per spec section 5.7).

        Version 3 is the only operational registry. Custom contexts are
        deliberately unversioned and return ``None``.
        """
        return self._version

    def get(self, rule_id: int) -> Rule | None:
        return self._rules.get(rule_id)

    def select_rule(self, fields: dict[str, int]) -> Rule | None:
        for rule in self._rules.values():
            # Generic field dictionaries carry no authenticated/parsed proof
            # that CoAP content is OSCORE protected.  Rules 5/6 are therefore
            # selected only by the whole-packet profiles in headers.py, which
            # parse and validate the Object-Security option before labeling
            # the wire packet.  Rule 255 likewise requires whole-IPv6
            # validation and is never a descriptor fallback.
            if rule.rule_id == RULE_ID_UNCOMPRESSED or (
                self._version is not None
                and rule.rule_id
                in {LINK_LOCAL_OSCORE_RULE.rule_id, GLOBAL_OSCORE_RULE.rule_id}
            ):
                continue
            if rule_matches(rule, fields):
                return rule
        return None

    def compress(self, fields: dict[str, int]) -> bytes:
        rule = self.select_rule(fields)
        if rule is None:
            raise NoMatchingRuleError("no SCHC rule matches the given fields")
        return compress(rule, fields)

    def decompress(self, data: bytes) -> tuple[int, dict[str, int | None]]:
        if not data:
            raise NoMatchingRuleError("empty SCHC packet")
        rule = self._rules.get(data[0])
        if rule is None:
            raise NoMatchingRuleError(f"unknown rule ID {data[0]}")
        if self._version is not None and rule.rule_id in {
            LINK_LOCAL_OSCORE_RULE.rule_id,
            GLOBAL_OSCORE_RULE.rule_id,
        }:
            raise NoMatchingRuleError(
                "standardized OSCORE rules require validated whole-packet decompression"
            )
        if rule.rule_id == RULE_ID_UNCOMPRESSED:
            raise NoMatchingRuleError(
                "Rule 255 requires validated whole-packet decompression"
            )
        return decompress(data, rule)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules.values())

    def __len__(self) -> int:
        return len(self._rules)


class NoMatchingRuleError(SchcError):
    pass


class VersionMismatchError(SchcError):
    """Raised when SCHC rule set versions are incompatible."""

    def __init__(self, local: int, remote: int) -> None:
        self.local = local
        self.remote = remote
        super().__init__(f"rule set version mismatch: local={local}, remote={remote}")


def versions_compatible(local: int, remote: int) -> bool:
    """Check whether two rule set versions are compatible.

    Per spec section 5.7, versions must match exactly for full interoperability.
    Rule 255 (uncompressed fallback) is always supported regardless of version
    for unfragmented packets, but this function checks compression compatibility.

    Args:
        local: The local node's rule set version.
        remote: The remote node's advertised rule set version.

    Returns:
        True if the versions are compatible for full SCHC operation.
    """
    return (
        type(local) is int
        and type(remote) is int
        and local == remote == RULE_SET_VERSION
        and local in RULE_SET_REGISTRIES
    )


def check_version_compatibility(
    local: int,
    remote: int,
    *,
    raise_on_mismatch: bool = True,
) -> bool:
    """Check and optionally enforce rule set version compatibility.

    Args:
        local: The local node's rule set version.
        remote: The remote node's advertised rule set version (e.g., from DIO).
        raise_on_mismatch: If True, raise VersionMismatchError on mismatch.

    Returns:
        True if versions are compatible.

    Raises:
        VersionMismatchError: If versions mismatch and raise_on_mismatch is True.
    """
    if versions_compatible(local, remote):
        return True
    if raise_on_mismatch:
        raise VersionMismatchError(local, remote)
    return False


class RuleVersionFailureTracker:
    """Bounded per-signer tracker for repeated decompression failures.

    ``record_failure`` returns ``True`` exactly once when a source reaches the
    configured consecutive-failure threshold. A successful decompression
    clears that source, allowing a later run of failures to notify again.
    """

    def __init__(self, threshold: int, *, max_sources: int = 16) -> None:
        if type(threshold) is not int or not 1 <= threshold <= 0xFFFF:
            raise ValueError("failure threshold must be an integer in 1..65535")
        if type(max_sources) is not int or not 1 <= max_sources <= 0xFFFF:
            raise ValueError("max_sources must be an integer in 1..65535")
        self._threshold = threshold
        self._max_sources = max_sources
        self._failures: OrderedDict[bytes, tuple[int, bool]] = OrderedDict()
        self._lock = threading.RLock()

    def record_failure(self, source: bytes) -> bool:
        """Record one failure and report a newly crossed notification threshold."""
        if type(source) is not bytes or len(source) != 32:
            raise ValueError("failure source must be a 32-byte signer public key")
        with self._lock:
            current = self._failures.get(source)
            if current is None and len(self._failures) >= self._max_sources:
                raise RuleVersionFailureTrackerFull("SCHC failure tracker source capacity is full")
            count, notified = (0, False) if current is None else current
            count = min(count + 1, self._threshold)
            notify = count == self._threshold and not notified
            self._failures[source] = (count, notified or notify)
            return notify

    def record_success(self, source: bytes) -> None:
        """Clear consecutive failures after a successful decompression."""
        if type(source) is not bytes or len(source) != 32:
            raise ValueError("failure source must be a 32-byte signer public key")
        with self._lock:
            self._failures.pop(source, None)

    def _retry_notification(self, source: bytes) -> None:
        """Return a failed notification delivery to the pending state."""
        if type(source) is not bytes or len(source) != 32:
            raise ValueError("failure source must be a 32-byte signer public key")
        with self._lock:
            current = self._failures.get(source)
            if current is not None and current[0] >= self._threshold:
                self._failures[source] = (current[0], False)


class RuleVersionFailureTrackerFull(RuntimeError):  # noqa: N818 - public compatibility
    """A new authenticated signer cannot be tracked without unsafe eviction."""


def create_rule_version_option(version: int | None = None) -> SchcRuleVersionOption:
    """Create a SCHC Rule Version Option for DIO messages.

    Args:
        version: Rule set version to advertise. Defaults to RULE_SET_VERSION.

    Returns:
        Option ready to be serialized and included in a DIO message.
    """
    return SchcRuleVersionOption.local(version if version is not None else RULE_SET_VERSION)


_AUTHENTICATED_PEER_OWNERS_LOCK = threading.RLock()
_AUTHENTICATED_PEER_OWNERS: weakref.WeakKeyDictionary[
    AuthenticatedPeerSchcContext, weakref.ReferenceType[object]
] = weakref.WeakKeyDictionary()


def _validated_authenticated_peer_policy(
    value: AuthenticatedPeerSchcContext,
) -> tuple[int, bytes]:
    """Resolve policy only through the exact LinkLayer that issued ``value``."""
    with _AUTHENTICATED_PEER_OWNERS_LOCK:
        owner_reference = _AUTHENTICATED_PEER_OWNERS.get(value)
    owner = None if owner_reference is None else owner_reference()
    validator = getattr(owner, "_validated_authenticated_peer_schc_context", None)
    if not callable(validator):
        raise ValueError("SCHC peer context is not a live LinkLayer issuance")
    policy = validator(value)
    if (
        type(policy) is not tuple
        or len(policy) != 2
        or type(policy[0]) is not int
        or type(policy[1]) is not bytes
        or len(policy[1]) != 32
    ):
        raise ValueError("SCHC peer context owner returned an invalid policy snapshot")
    return policy


@dataclass(frozen=True, init=False, eq=False)
class AuthenticatedPeerSchcContext:
    """SCHC policy bound to a version learned from an authenticated DIO.

    The link/RPL caller creates this value only after signature verification
    and replay acceptance. Keeping the remote version and signer identity in
    one immutable object prevents later code from substituting an unauthenticated
    version byte. A mismatch never enables compressed or fragmented operation;
    it permits only a validated Rule 255 packet that fits one link frame.
    """

    def __new__(cls) -> AuthenticatedPeerSchcContext:
        raise TypeError(
            "AuthenticatedPeerSchcContext values are issued only from a "
            "LinkLayer replay-accepted DIO"
        )

    @classmethod
    def _issue_from_verified_dio(
        cls,
        option: SchcRuleVersionOption,
        signer_identity: bytes,
        *,
        owner: object,
    ) -> AuthenticatedPeerSchcContext:
        """Issue an opaque policy handle after LinkLayer consumed its receipt."""
        from lichen.link.link_layer import LinkLayer

        if type(signer_identity) is not bytes or len(signer_identity) != 32:
            raise ValueError("authenticated signer identity must be a 32-byte public key")
        if type(owner) is not LinkLayer:
            raise TypeError("authenticated SCHC policy owner must be an exact LinkLayer")
        value = object.__new__(cls)
        with _AUTHENTICATED_PEER_OWNERS_LOCK:
            _AUTHENTICATED_PEER_OWNERS[value] = weakref.ref(owner)
        return value

    def _policy(self) -> tuple[int, bytes]:
        return _validated_authenticated_peer_policy(self)

    @property
    def remote_version(self) -> int:
        """Authenticated remote registry version from the owner's snapshot."""
        return self._policy()[0]

    @property
    def signer_identity(self) -> bytes:
        """Authenticated signer identity from the owner's snapshot."""
        return self._policy()[1]

    @property
    def allows_dodag_join(self) -> bool:
        """Whether this peer advertises the sole implemented v3 registry."""
        remote_version, _ = self._policy()
        return versions_compatible(RULE_SET_VERSION, remote_version)

    def compress_packet(
        self,
        raw: bytes,
        *,
        single_frame_limit: int,
        profiles: tuple[PacketProfile, ...] | None = None,
    ) -> bytes:
        """Compress for this peer, failing closed on a version mismatch."""
        from lichen.schc.headers import DEFAULT_PROFILES, compress_packet, encode_rule255

        remote_version, _ = self._policy()
        if versions_compatible(RULE_SET_VERSION, remote_version):
            selected_profiles = DEFAULT_PROFILES if profiles is None else profiles
            return compress_packet(raw, profiles=selected_profiles)
        return encode_rule255(raw, single_frame_limit=single_frame_limit)

    def decompress_packet(
        self,
        data: bytes,
        *,
        single_frame_limit: int,
        profiles: tuple[PacketProfile, ...] | None = None,
    ) -> bytes:
        """Decode for this peer; mismatch accepts validated Rule 255 only."""
        from lichen.schc.headers import DEFAULT_PROFILES, decode_rule255, decompress_packet

        remote_version, _ = self._policy()
        if versions_compatible(RULE_SET_VERSION, remote_version):
            selected_profiles = DEFAULT_PROFILES if profiles is None else profiles
            return decompress_packet(data, profiles=selected_profiles)
        return decode_rule255(data, single_frame_limit=single_frame_limit)
