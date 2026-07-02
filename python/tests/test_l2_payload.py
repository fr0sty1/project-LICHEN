# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from lichen.announce.messages import ANNOUNCE_TYPE
from lichen.constants import SCHC_RULE_GLOBAL_COAP
from lichen.l2_payload import (
    L2PayloadKind,
    classify_l2_payload,
    l2_payload_body,
    wrap_routing_payload,
    wrap_schc_payload,
)


def test_dispatch_distinguishes_global_coap_rule_from_announce() -> None:
    schc = bytes([SCHC_RULE_GLOBAL_COAP, 0x40, 0x20])
    announce = bytes([ANNOUNCE_TYPE, 0x00, 0x00])

    wrapped_schc = wrap_schc_payload(schc)
    wrapped_announce = wrap_routing_payload(announce)

    assert classify_l2_payload(wrapped_schc) is L2PayloadKind.SCHC
    assert l2_payload_body(wrapped_schc) == schc
    assert classify_l2_payload(wrapped_announce) is L2PayloadKind.ROUTING
    assert l2_payload_body(wrapped_announce) == announce
    assert wrapped_schc[1] == wrapped_announce[1] == 0x01


def test_unwrapped_first_byte_is_unknown() -> None:
    assert classify_l2_payload(bytes([SCHC_RULE_GLOBAL_COAP, 0x00])) is L2PayloadKind.UNKNOWN
    assert classify_l2_payload(b"") is L2PayloadKind.UNKNOWN
