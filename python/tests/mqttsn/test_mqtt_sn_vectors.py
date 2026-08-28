# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume test/vectors/mqtt_sn.json via lichen.mqttsn.

Wire bytes are independently hand-derived from OASIS MQTT-SN 1.2
(Length-MsgType-payload). encode()/decode() are the implementation under test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from lichen.mqttsn import (
    Connack,
    Connect,
    MqttSnError,
    MsgType,
    Puback,
    Publish,
    Regack,
    Register,
    Suback,
    Subscribe,
    decode,
    encode,
)

_VECTORS_PATH = Path(__file__).resolve().parents[3] / "test" / "vectors" / "mqtt_sn.json"
_SCHEMA_PATH = _VECTORS_PATH.with_name("mqtt_sn.schema.json")


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_VECTORS_PATH.read_text(encoding="utf-8")))


def _schema() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SCHEMA_PATH.read_text(encoding="utf-8")))


def test_schema_accepts_document() -> None:
    schema = _schema()
    document = _document()
    Draft7Validator.check_schema(schema)
    errors = sorted(Draft7Validator(schema).iter_errors(document), key=lambda e: e.path)
    assert not errors, [error.message for error in errors]
    assert document["format_version"] == 2
    assert document["name"] == "mqtt_sn"


def test_spec_10_4_message_type_table() -> None:
    document = _document()
    table = next(v for v in document["vectors"] if v["name"] == "spec_10_4_message_types")
    expected = {row["name"]: row["code"] for row in table["types"]}
    assert expected == {
        "CONNECT": int(MsgType.CONNECT),
        "CONNACK": int(MsgType.CONNACK),
        "REGISTER": int(MsgType.REGISTER),
        "REGACK": int(MsgType.REGACK),
        "PUBLISH": int(MsgType.PUBLISH),
        "PUBACK": int(MsgType.PUBACK),
        "SUBSCRIBE": int(MsgType.SUBSCRIBE),
        "SUBACK": int(MsgType.SUBACK),
    }


def test_wire_vectors_round_trip() -> None:
    document = _document()
    seen: set[str] = set()
    for vector in document["vectors"]:
        if vector["kind"] != "wire":
            continue
        raw = bytes.fromhex(vector["encoded"])
        assert raw[1] == vector["msg_type"]
        decoded = decode(raw)
        assert int(decoded.msg_type) == vector["msg_type"]
        assert encode(decoded) == raw
        fields = vector["fields"]
        if isinstance(decoded, Connect):
            assert decoded.client_id == bytes.fromhex(str(fields["client_id_hex"]))
            assert decoded.duration == fields["duration"]
            assert decoded.clean_session is fields["clean_session"]
            assert decoded.will is fields["will"]
        elif isinstance(decoded, Connack):
            assert decoded.return_code == fields["return_code"]
        elif isinstance(decoded, Register):
            assert decoded.topic_id == fields["topic_id"]
            assert decoded.msg_id == fields["msg_id"]
            assert decoded.topic_name == bytes.fromhex(str(fields["topic_name_hex"]))
        elif isinstance(decoded, Regack):
            assert decoded.topic_id == fields["topic_id"]
            assert decoded.msg_id == fields["msg_id"]
            assert decoded.return_code == fields["return_code"]
        elif isinstance(decoded, Publish):
            assert decoded.topic_id == fields["topic_id"]
            assert decoded.msg_id == fields["msg_id"]
            assert decoded.qos == fields["qos"]
            assert decoded.data == bytes.fromhex(str(fields["data_hex"]))
        elif isinstance(decoded, Puback):
            assert decoded.topic_id == fields["topic_id"]
            assert decoded.msg_id == fields["msg_id"]
            assert decoded.return_code == fields["return_code"]
        elif isinstance(decoded, Subscribe):
            assert decoded.msg_id == fields["msg_id"]
            assert decoded.qos == fields["qos"]
            assert decoded.topic == bytes.fromhex(str(fields["topic_hex"]))
        elif isinstance(decoded, Suback):
            assert decoded.topic_id == fields["topic_id"]
            assert decoded.msg_id == fields["msg_id"]
            assert decoded.qos == fields["qos"]
            assert decoded.return_code == fields["return_code"]
        else:
            raise AssertionError(f"unhandled type {type(decoded).__name__}")
        seen.add(vector["name"])
    assert seen == {
        "connect_clean_test",
        "connack_accepted",
        "register_sensors_temp",
        "regack_assigned",
        "publish_qos1_hello",
        "publish_qos_minus_one",
        "puback_topic256",
        "subscribe_topic_name",
        "suback_qos2",
    }


def test_reject_vectors() -> None:
    document = _document()
    seen = 0
    for vector in document["vectors"]:
        if vector["kind"] != "reject":
            continue
        raw = bytes.fromhex(vector["encoded"])
        try:
            decode(raw)
        except MqttSnError:
            seen += 1
            continue
        raise AssertionError(f"{vector['name']} should reject {vector['reason']}")
    assert seen == 3
