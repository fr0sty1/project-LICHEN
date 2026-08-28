# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

import json
from pathlib import Path

import pytest

from lichen.l2_payload import (
    L2PayloadKind,
    classify_l2_payload,
    l2_payload_body,
)

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"


def _load_l2_vectors():
    with open(VECTORS_DIR / "l2_payload.json") as f:
        return json.load(f)["vectors"]


@pytest.mark.parametrize("vector", _load_l2_vectors())
def test_l2_payload_vector_oracle(vector):
    """Updated to use only l2_payload.json as oracle. Covers announce routing dispatch per spec."""
    wrapped = bytes.fromhex(vector["wrapped"])
    body = bytes.fromhex(vector["body"])
    expected_kind = {
        "schc": L2PayloadKind.SCHC,
        "routing": L2PayloadKind.ROUTING,
        "unknown": L2PayloadKind.UNKNOWN,
    }[vector["kind"]]
    assert classify_l2_payload(wrapped) is expected_kind
    assert l2_payload_body(wrapped) == body


@pytest.mark.parametrize("dispatch", range(256))
def test_dispatch_namespace_is_exhaustive_and_single_octet_is_malformed(dispatch):
    expected = {
        0x14: L2PayloadKind.SCHC,
        0x15: L2PayloadKind.ROUTING,
    }.get(dispatch, L2PayloadKind.UNKNOWN)

    assert classify_l2_payload(bytes([dispatch, 0x00])) is expected
    assert classify_l2_payload(bytes([dispatch])) is L2PayloadKind.UNKNOWN
