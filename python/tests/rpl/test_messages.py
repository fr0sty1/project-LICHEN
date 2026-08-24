# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for RPL control message codecs (RFC 6550).

Byte oracles are hand-constructed from the RFC 6550 base-object layouts.
"""

from __future__ import annotations

from collections.abc import Iterator
from ipaddress import IPv6Address

import pytest

from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.rpl.messages import (
    DAO,
    DIO,
    DIS,
    DAOAck,
    ModeOfOperation,
    RplCode,
    RplError,
    RplMessage,
    RplOption,
    RplOptionType,
    from_icmpv6,
    to_icmpv6,
)

DODAG = IPv6Address("fd00::1")
DODAG_PACKED = DODAG.packed  # fd00 then 13 zero bytes then 01


def test_dis_known_vector() -> None:
    assert DIS().to_bytes() == bytes([0x00, 0x00])


def test_dis_round_trip_with_options() -> None:
    dis = DIS(flags=0x01, reserved=0x00, options=[RplOption(RplOptionType.PADN, b"\x00")])
    assert DIS.from_bytes(dis.to_bytes()) == dis


def test_dio_known_vector() -> None:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=256,
        dtsn=0,
        dodag_id=DODAG,
        grounded=True,
        mode_of_operation=ModeOfOperation.NON_STORING,
        preference=0,
    )
    expected = (
        bytes([0x00, 0x01])  # instance, version
        + bytes([0x01, 0x00])  # rank = 256
        + bytes([0x88])  # G=1 (0x80) | MOP=1 (<<3 = 0x08) | Prf=0
        + bytes([0x00, 0x00, 0x00])  # dtsn, flags, reserved
        + DODAG_PACKED
        + bytes.fromhex("130103")  # exactly one current SCHC version option
    )
    assert dio.to_bytes() == expected
    assert len(dio.to_bytes()) == 27
    assert DIO.from_bytes(expected) == DIO(
        rpl_instance_id=0,
        version=1,
        rank=256,
        dtsn=0,
        dodag_id=DODAG,
        grounded=True,
        mode_of_operation=ModeOfOperation.NON_STORING,
        preference=0,
        options=[RplOption(0x13, b"\x03")],
    )


@pytest.mark.parametrize("length", range(24))
def test_dio_rejects_every_truncated_base_length(length: int) -> None:
    complete_base = bytes.fromhex("0001020008000000") + DODAG_PACKED
    assert len(complete_base) == 24

    with pytest.raises(RplError, match=rf"DIO too short: {length} bytes"):
        DIO.from_bytes(complete_base[:length])


def test_dio_exact_base_length_parse_preserves_full_dodag_id() -> None:
    encoded_base = bytes.fromhex("0001020008000000") + DODAG_PACKED
    dio = DIO.from_bytes(encoded_base)

    assert len(encoded_base) == 24
    assert dio.dodag_id == DODAG
    assert dio.options == []
    assert dio.to_bytes() == encoded_base + bytes.fromhex("130103")


def test_dio_serializer_rejects_duplicate_schc_version_options() -> None:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=256,
        dtsn=0,
        dodag_id=DODAG,
        options=[RplOption(0x13, b"\x02"), RplOption(0x13, b"\x03")],
    )
    with pytest.raises(RplError, match="at most one"):
        dio.to_bytes()


@pytest.mark.parametrize("data", [b"", b"\x03\x03"])
def test_dio_serializer_rejects_noncanonical_schc_version_length(data: bytes) -> None:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=256,
        dtsn=0,
        dodag_id=DODAG,
        options=[RplOption(0x13, data)],
    )

    with pytest.raises(RplError, match="exactly one version byte"):
        dio.to_bytes()


def test_dio_serializer_preserves_explicit_remote_rule_version() -> None:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=256,
        dtsn=0,
        dodag_id=DODAG,
        options=[RplOption(0x13, b"\x02")],
    )
    assert DIO.from_bytes(dio.to_bytes()).options == [RplOption(0x13, b"\x02")]


def test_dio_serializer_rejects_stateful_options_iterable() -> None:
    class StatefulOptions(list[RplOption]):
        def __iter__(self) -> Iterator[RplOption]:
            yield RplOption(0x13, b"\x03")
            yield RplOption(0x13, b"\x02")

    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=256,
        dtsn=0,
        dodag_id=DODAG,
        options=StatefulOptions([RplOption(0x13, b"\x03")]),
    )

    with pytest.raises(RplError, match="options must be an exact list"):
        dio.to_bytes()


def test_dio_parser_rejects_reserved_g_mop_preference_bit() -> None:
    encoded = bytearray(DIO(0, 1, 256, 0, DODAG).to_bytes())
    encoded[4] |= 0x40

    with pytest.raises(RplError, match="reserved bit"):
        DIO.from_bytes(bytes(encoded))


def test_dio_serializer_never_invokes_mutable_option_encoder() -> None:
    option = RplOption(0x13, b"\x03")
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=256,
        dtsn=0,
        dodag_id=DODAG,
        options=[option],
    )

    def mutate_dio_during_option_encoding() -> bytes:
        dio.rank = 0xFFFF
        dio.options.append(RplOption(0x13, b"\x02"))
        return b"\x13\x01\x02"

    option.to_bytes = mutate_dio_during_option_encoding  # type: ignore[method-assign]
    encoded = dio.to_bytes()

    assert int.from_bytes(encoded[2:4], "big") == 256
    assert encoded[24:] == bytes.fromhex("130103")
    assert dio.rank == 256
    assert dio.options == [option]


def test_dio_serializer_rejects_option_aliases_and_mutable_data() -> None:
    class AliasedOption(RplOption):
        pass

    aliased = DIO(0, 1, 256, 0, DODAG, options=[AliasedOption(0x13, b"\x03")])
    with pytest.raises(RplError, match="exact RplOption"):
        aliased.to_bytes()

    mutable_data = RplOption(0x13, b"\x03")
    mutable_data.data = bytearray(b"\x03")  # type: ignore[assignment]
    malformed = DIO(0, 1, 256, 0, DODAG, options=[mutable_data])
    with pytest.raises(RplError, match="option data must be exact bytes"):
        malformed.to_bytes()


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("rank", True, "rank out of range"),
        ("grounded", 1, "grounded must be a bool"),
        ("dodag_id", "fd00::1", "dodag_id must be an IPv6Address"),
    ],
)
def test_dio_serializer_rejects_mutated_noncanonical_scalar_state(
    field: str, replacement: object, message: str
) -> None:
    dio = DIO(0, 1, 256, 0, DODAG)
    setattr(dio, field, replacement)

    with pytest.raises(RplError, match=message):
        dio.to_bytes()


@pytest.mark.parametrize("rank", [256, 512, 0xFFFF])
def test_every_admission_capable_dio_serializes_one_current_version(rank: int) -> None:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=rank,
        dtsn=0,
        dodag_id=DODAG,
        options=[],
    )
    parsed = DIO.from_bytes(dio.to_bytes())

    assert [option for option in parsed.options if option.type == 0x13] == [
        RplOption(0x13, b"\x03")
    ]


def test_dio_flag_field_decoding() -> None:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=512,
        dtsn=3,
        dodag_id=DODAG,
        grounded=False,
        mode_of_operation=ModeOfOperation.STORING_NO_MULTICAST,
        preference=5,
        options=[RplOption(0x13, b"\x03")],
    )
    parsed = DIO.from_bytes(dio.to_bytes())
    assert parsed.grounded is False
    assert parsed.mode_of_operation == ModeOfOperation.STORING_NO_MULTICAST
    assert parsed.preference == 5
    assert parsed == dio


def test_dio_round_trip_with_options() -> None:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=512,
        dtsn=0,
        dodag_id=DODAG,
        options=[
            RplOption(RplOptionType.PAD1),
            RplOption(RplOptionType.DODAG_CONFIGURATION, b"\x01\x02\x03\x04"),
            RplOption(0x13, b"\x03"),
        ],
    )
    assert DIO.from_bytes(dio.to_bytes()) == dio


def test_dao_with_dodagid_known_vector() -> None:
    dao = DAO(rpl_instance_id=0, dao_sequence=5, dodag_id=DODAG)
    expected = bytes([0x00, 0x40, 0x00, 0x05]) + DODAG_PACKED  # D flag = 0x40
    assert dao.to_bytes() == expected


def test_dao_without_dodagid_ack_requested() -> None:
    dao = DAO(rpl_instance_id=0, dao_sequence=5, ack_requested=True)
    expected = bytes([0x00, 0x80, 0x00, 0x05])  # K flag = 0x80, no DODAGID
    assert dao.to_bytes() == expected
    parsed = DAO.from_bytes(expected)
    assert parsed.ack_requested is True
    assert parsed.dodag_id is None
    assert parsed == dao


def test_dao_round_trip_with_dodagid() -> None:
    dao = DAO(
        rpl_instance_id=0,
        dao_sequence=9,
        dodag_id=DODAG,
        options=[RplOption(RplOptionType.RPL_TARGET, b"\xaa\xbb")],
    )
    assert DAO.from_bytes(dao.to_bytes()) == dao


def test_dao_ack_known_vector() -> None:
    ack = DAOAck(rpl_instance_id=0, dao_sequence=5, status=0)
    assert ack.to_bytes() == bytes([0x00, 0x00, 0x05, 0x00])


def test_dao_ack_round_trip_with_dodagid() -> None:
    ack = DAOAck(rpl_instance_id=0, dao_sequence=5, status=0, dodag_id=DODAG)
    expected = bytes([0x00, 0x80, 0x05, 0x00]) + DODAG_PACKED  # D flag = 0x80
    assert ack.to_bytes() == expected
    assert DAOAck.from_bytes(expected) == ack


def test_option_pad1_and_padn_parsing() -> None:
    # Pad1 (single 0x00) followed by PadN(type=1,len=2,data=00 00).
    raw = bytes([0x00, 0x01, 0x02, 0x00, 0x00])
    dis = DIS.from_bytes(bytes([0x00, 0x00]) + raw)
    assert dis.options[0].type == RplOptionType.PAD1
    assert dis.options[1] == RplOption(RplOptionType.PADN, b"\x00\x00")


def test_option_truncated_rejected() -> None:
    # Option type 5 claims length 4 but only 1 data byte present.
    with pytest.raises(RplError):
        DIS.from_bytes(bytes([0x00, 0x00, 0x05, 0x04, 0x01]))


def test_icmpv6_wrap_and_dispatch() -> None:
    messages: list[tuple[RplMessage, RplCode]] = [
        (DIS(), RplCode.DIS),
        (DIO(0, 1, 512, 0, DODAG, options=[RplOption(0x13, b"\x03")]), RplCode.DIO),
        (DAO(0, 5, dodag_id=DODAG), RplCode.DAO),
        (DAOAck(0, 5), RplCode.DAO_ACK),
    ]
    for message, code in messages:
        icmp = to_icmpv6(message)
        assert icmp.type == 155
        assert icmp.code == code
        assert from_icmpv6(icmp) == message


def test_from_icmpv6_rejects_non_rpl() -> None:
    with pytest.raises(RplError):
        from_icmpv6(Icmpv6Message(type=128, code=0, body=b""))


def test_from_icmpv6_rejects_unknown_code() -> None:
    with pytest.raises(RplError):
        from_icmpv6(Icmpv6Message(type=155, code=99, body=b""))


def test_dao_coerces_str_dodag_id() -> None:
    # DAO/DAO-ACK accept a string dodag_id like DIO (coerced to IPv6Address).
    dao = DAO(rpl_instance_id=0, dao_sequence=5, dodag_id="fd00::1")  # type: ignore[arg-type]
    assert dao.dodag_id == IPv6Address("fd00::1")
    assert DAO.from_bytes(dao.to_bytes()) == dao

    ack = DAOAck(
        rpl_instance_id=0,
        dao_sequence=5,
        dodag_id="fd00::1",  # type: ignore[arg-type]
    )
    assert ack.dodag_id == IPv6Address("fd00::1")
    assert DAOAck.from_bytes(ack.to_bytes()) == ack
