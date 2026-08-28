# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

import json
import pathlib
import sys


def emit_array(name: str, value: str) -> str:
    data = bytes.fromhex(value)
    body = ", ".join(f"0x{byte:02x}" for byte in data)
    return f"static const uint8_t {name}[] = {{{body}}};\n"


source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
wire = json.loads(source.read_text(encoding="utf-8"))["wire"]
target.write_text(
    "/* Generated from test/vectors/short_addr_assignment.json. */\n"
    "#ifndef SHORT_ASSIGNMENT_VECTORS_H_\n"
    "#define SHORT_ASSIGNMENT_VECTORS_H_\n"
    "#include <stdint.h>\n"
    + emit_array("allocate_ack", wire["allocate_ack_hex"])
    + emit_array("release_ack", wire["release_ack_hex"])
    + "#endif\n",
    encoding="utf-8",
)
