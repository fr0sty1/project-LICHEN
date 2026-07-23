# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Gateway translation between LICHEN mesh formats and external protocols."""

from .compact_cot import (
    CompactCotType,
    DecodeError,
    DestType,
    Team,
    compress_cot_xml,
    decode_compact_cot,
    encode_compact_cot,
    expand_cot_to_xml,
    parse_cot_xml,
)

__all__ = [
    "CompactCotType",
    "DecodeError",
    "DestType",
    "Team",
    "compress_cot_xml",
    "decode_compact_cot",
    "encode_compact_cot",
    "expand_cot_to_xml",
    "parse_cot_xml",
]
