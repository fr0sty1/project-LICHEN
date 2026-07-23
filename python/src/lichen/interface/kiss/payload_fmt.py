# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
Condensed payload formatter for unknown data types.

When we receive non-APRS data, format it readably so APRSDroid users
see something useful instead of binary garbage.

Format priorities:
1. Valid UTF-8 text → show as-is
2. CBOR → decode to compact JSON-like
3. JSON → show compact
4. Binary → hex with structure hints
"""

from __future__ import annotations

import json
import re

from lichen.constants import L2_DISPATCH_ROUTING, L2_DISPATCH_SCHC

# Try to import cbor2 for CBOR decoding (optional dependency)
try:
    import cbor2
    HAS_CBOR = True
except ImportError:
    HAS_CBOR = False


def format_payload(data: bytes, max_len: int = 200) -> str:
    """Format binary payload as human-readable string.

    Args:
        data: Raw payload bytes
        max_len: Maximum output length (truncate if longer)

    Returns:
        Human-readable string representation
    """
    if not data:
        return "[empty]"

    # Try UTF-8 text first
    text = _try_utf8(data)
    if text is not None:
        return _truncate(text, max_len)

    # Try CBOR
    if HAS_CBOR:
        decoded = _try_cbor(data)
        if decoded is not None:
            return _truncate(decoded, max_len)

    # Try JSON (might be ASCII subset)
    decoded = _try_json(data)
    if decoded is not None:
        return _truncate(decoded, max_len)

    # Fall back to hex with structure
    return _format_hex(data, max_len)


def _try_utf8(data: bytes) -> str | None:
    """Try to decode as UTF-8 text.

    Only accepts if 100% of chars are printable or allowed whitespace.
    Rejects binary data with high printable ratio.
    """
    try:
        text = data.decode("utf-8")
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        if printable == len(text):  # 100% printable
            return text
    except UnicodeDecodeError:
        pass
    return None


def _try_cbor(data: bytes) -> str | None:
    """Try to decode as CBOR and format compactly."""
    if not HAS_CBOR:
        return None

    try:
        obj = cbor2.loads(data)
        return _compact_repr(obj)
    except Exception:
        return None


def _try_json(data: bytes) -> str | None:
    """Try to decode as JSON."""
    try:
        # Check for JSON markers
        if data[0:1] not in (b"{", b"[", b'"'):
            return None
        obj = json.loads(data)
        return _compact_repr(obj)
    except Exception:
        return None


def _compact_repr(obj, depth: int = 0) -> str:
    """Compact JSON-like representation.

    More readable than json.dumps for display in TNC apps.
    """
    if depth > 5:
        return "..."

    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        # Compact number formatting
        if isinstance(obj, float):
            if obj == int(obj):
                return str(int(obj))
            return f"{obj:.3g}"
        return str(obj)
    if isinstance(obj, str):
        # Short strings without quotes, long with
        if len(obj) <= 20 and re.match(r"^[\w\-_.]+$", obj):
            return obj
        return json.dumps(obj)
    if isinstance(obj, bytes):
        return f"<{len(obj)}B>"
    if isinstance(obj, (list, tuple)):
        if len(obj) == 0:
            return "[]"
        items = [_compact_repr(x, depth + 1) for x in obj[:10]]
        if len(obj) > 10:
            items.append(f"...+{len(obj) - 10}")
        return "[" + ",".join(items) + "]"
    if isinstance(obj, dict):
        if len(obj) == 0:
            return "{}"
        items = []
        for k, v in list(obj.items())[:10]:
            key = k if isinstance(k, str) and re.match(r"^[\w\-_.]+$", k) else json.dumps(k)
            items.append(f"{key}:{_compact_repr(v, depth + 1)}")
        if len(obj) > 10:
            items.append(f"...+{len(obj) - 10}")
        return "{" + ",".join(items) + "}"

    # Unknown type
    return f"<{type(obj).__name__}>"


def _format_hex(data: bytes, max_len: int) -> str:
    """Format binary as hex with structure hints."""
    length = len(data)

    # Detect common patterns
    prefix = ""
    if length >= 2:
        # CoAP header detection (Ver=1, Type in 0-3)
        if (data[0] & 0xC0) == 0x40:
            prefix = "[CoAP] "
        elif data[0] == L2_DISPATCH_SCHC:
            prefix = "[L2/SCHC] "
        elif data[0] == L2_DISPATCH_ROUTING:
            prefix = "[L2/Routing] "
        # SCHC detection (rule ID patterns)
        elif data[0] in (0x00, 0x01):
            prefix = "[SCHC] "

    # Format hex
    hex_str = data.hex()

    # Add spacing every 4 chars for readability
    spaced = " ".join(hex_str[i:i+4] for i in range(0, len(hex_str), 4))

    result = f"{prefix}{length}B: {spaced}"
    return _truncate(result, max_len)


def _truncate(s: str, max_len: int) -> str:
    """Truncate string with ellipsis if too long."""
    if len(s) <= max_len:
        return s
    return s[:max_len - 3] + "..."


def is_printable_text(data: bytes) -> bool:
    """Check if data is likely printable text."""
    return _try_utf8(data) is not None
