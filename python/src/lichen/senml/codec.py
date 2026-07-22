# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SenML codec — RFC 8428 CBOR pack/unpack (Content-Format 112).

SenML represents sensor measurements as a pack (array) of records.  Each
record is a map; CBOR encoding uses numeric keys per RFC 8428 Table 4.

Typical usage::

    from lichen.senml.codec import SenmlRecord, pack, unpack

    records = [
        SenmlRecord(bn="urn:dev:mac:0102030405060708:", bt=1_700_000_000.0),
        SenmlRecord(n="temperature", u="Cel", v=23.4),
        SenmlRecord(n="rel-humidity", u="%RH", v=61.0),
    ]
    payload = pack(records)          # bytes, Content-Format 112
    decoded = unpack(payload)        # list[SenmlRecord]
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any

import cbor2

# RFC 8428 Table 4: CBOR numeric label → SenML field name
_LABEL_TO_FIELD: dict[int, str] = {
    -2: "bn",
    -3: "bt",
    -4: "bu",
    -5: "bv",
    -6: "bs",
    -1: "bver",
     0: "n",
     1: "u",
     2: "v",
     3: "vs",
     4: "vb",
     5: "s",
     6: "t",
     7: "ut",
     8: "vd",
}

_FIELD_TO_LABEL: dict[str, int] = {v: k for k, v in _LABEL_TO_FIELD.items()}

_FIELD_TYPES: dict[str, str] = {
    "bn": "str", "n": "str", "bu": "str", "u": "str", "vs": "str",
    "bt": "num", "bv": "num", "bs": "num", "v": "num", "s": "num", "t": "num", "ut": "num",
    "bver": "int",
    "vb": "bool",
    "vd": "bytes",
}

_VALUE_FIELDS: set[str] = {"v", "vs", "vb", "vd"}


def _validate_field_type(name: str, value: object) -> None:
    """Validate that a SenML field value has the correct type per RFC 8428.

    Raises:
        ValueError: If the value type does not match the field's expected type.
    """
    expected = _FIELD_TYPES.get(name)
    if expected is None:
        return  # Unknown field, skip validation

    if expected == "str":
        if not isinstance(value, str):
            raise ValueError(
                f"SenML field '{name}' must be a string, got {type(value).__name__}"
            )
    elif expected == "num":
        # Accept int or float, but not bool (bool is subclass of int in Python)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                f"SenML field '{name}' must be a number, got {type(value).__name__}"
            )
    elif expected == "int":
        # Must be int, not float, not bool
        if isinstance(value, bool) or not isinstance(value, int) or isinstance(value, float):
            raise ValueError(
                f"SenML field '{name}' must be an integer, got {type(value).__name__}"
            )
        if name == "bver" and not (1 <= value <= 10):
            raise ValueError(f"SenML bver must be in range [1, 10], got {value}")
    elif expected == "bool":
        if not isinstance(value, bool):
            raise ValueError(
                f"SenML field '{name}' must be a boolean, got {type(value).__name__}"
            )
    elif expected == "bytes" and not isinstance(value, bytes):
        raise ValueError(
            f"SenML field '{name}' must be bytes, got {type(value).__name__}"
        )


@dataclass
class SenmlRecord:
    """One SenML record (RFC 8428 §4).

    Base fields (apply to all subsequent records until overridden):

    * ``bn``   — base name, e.g. ``"urn:dev:mac:0102030405060708:"``
    * ``bt``   — base time (Unix seconds, float)
    * ``bu``   — base unit
    * ``bv``   — base value
    * ``bs``   — base sum
    * ``bver`` — base version (integer [1,10] per RFC 8428 §4.4; > current version rejected)

    Per-record fields:

    * ``n``  — name (appended to bn to form the full resource name)
    * ``u``  — unit (overrides bu for this record)
    * ``v``  — numeric value (float)
    * ``vs`` — string value
    * ``vb`` — boolean value
    * ``vd`` — data value (bytes)
    * ``s``  — sum (running total)
    * ``t``  — time offset from bt (seconds, float)
    * ``ut`` — update time (seconds, float)
    """

    bn: str | None = None
    bt: float | None = None
    bu: str | None = None
    bv: float | None = None
    bs: float | None = None
    bver: int | None = None
    n: str | None = None
    u: str | None = None
    v: float | None = None
    vs: str | None = None
    vb: bool | None = None
    vd: bytes | None = None
    s: float | None = None
    t: float | None = None
    ut: float | None = None

    def to_cbor_map(self) -> dict[int, Any]:
        """Serialise to a dict with numeric CBOR keys (omits None fields)."""
        value_count = sum(
            1
            for f in fields(self)
            if f.name in _VALUE_FIELDS and getattr(self, f.name) is not None
        )
        if value_count > 1:
            raise ValueError("SenML record must have at most one value field")
        out: dict[int, Any] = {}
        for f in fields(self):
            val = getattr(self, f.name)
            if val is None:
                continue
            label = _FIELD_TO_LABEL[f.name]
            out[label] = val
        return out

    @classmethod
    def from_cbor_map(cls, m: dict[int, Any]) -> SenmlRecord:
        """Deserialise from a numeric-keyed CBOR map.

        Raises:
            ValueError: If a field value has the wrong type per RFC 8428.
        """
        kwargs: dict[str, Any] = {}
        for label, val in m.items():
            name = _LABEL_TO_FIELD.get(label)
            if name is not None:
                _validate_field_type(name, val)
                if name == "bver" and not (1 <= val <= 10):
                    raise ValueError(f"'bver' must be an integer in [1,10], got {val}")
                kwargs[name] = val
        value_count = sum(1 for k in _VALUE_FIELDS if k in kwargs)
        if value_count > 1:
            raise ValueError("SenML record must have at most one value field")
        return cls(**kwargs)


def pack(records: list[SenmlRecord]) -> bytes:
    """Encode a SenML pack to CBOR bytes (Content-Format 112).

    Args:
        records: List of :class:`SenmlRecord`.  The first record typically
            carries base fields (``bn``, ``bt``); subsequent records carry
            per-measurement fields.

    Returns:
        CBOR-encoded byte string ready to send as a CoAP payload.
    """
    return cbor2.dumps([r.to_cbor_map() for r in records])


def unpack(data: bytes) -> list[SenmlRecord]:
    """Decode a CBOR SenML pack into records.

    Args:
        data: CBOR-encoded SenML pack (Content-Format 112).

    Returns:
        List of :class:`SenmlRecord`.

    Raises:
        ValueError: If ``data`` is not a valid CBOR array of maps.
    """
    try:
        raw = cbor2.loads(data)
    except Exception as exc:
        raise ValueError(f"SenML CBOR decode failed: {exc}") from exc
    if not isinstance(raw, list):
        raise ValueError(f"SenML pack must be a CBOR array, got {type(raw).__name__}")
    records = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"SenML record {i} must be a map, got {type(item).__name__}")
        records.append(SenmlRecord.from_cbor_map(item))
    return records


def make_base_name(eui64: bytes) -> str:
    """Build a SenML base name from an 8-byte EUI-64.

    Returns ``"urn:dev:mac:<hex>:"`` where ``<hex>`` is the lower-case
    hex encoding of the EUI-64, e.g. ``"urn:dev:mac:0102030405060708:"``.
    """
    if len(eui64) != 8:
        raise ValueError(f"EUI-64 must be 8 bytes, got {len(eui64)}")
    return "urn:dev:mac:" + eui64.hex() + ":"
