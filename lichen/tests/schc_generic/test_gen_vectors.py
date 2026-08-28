#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
GENERATOR = HERE / "gen_vectors.py"
CANONICAL = HERE / "../../../test/vectors/schc_fragmentation.json"


class GeneratorV2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(CANONICAL.read_text())

    def generate(self, document):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "vectors.json"
            output = Path(directory) / "vectors.h"
            source.write_text(json.dumps(document))
            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(source), str(output)],
                capture_output=True,
                check=False,
                text=True,
            )
            generated = output.read_bytes() if output.exists() else None
            return result, generated

    def test_canonical_v2_is_deterministic(self):
        first, first_output = self.generate(self.document)
        second, second_output = self.generate(self.document)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_output, second_output)

    def assert_rejected(self, mutate):
        document = copy.deepcopy(self.document)
        mutate(document)
        result, output = self.generate(document)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(output)

    def test_rejects_old_version(self):
        self.assert_rejected(lambda document: document.__setitem__("format_version", 1))

    def test_rejects_extra_field(self):
        self.assert_rejected(lambda document: document["vectors"][0].__setitem__("extra", 0))

    def test_rejects_missing_field(self):
        self.assert_rejected(lambda document: document["vectors"][0].pop("provenance"))

    def test_rejects_boolean_integer(self):
        self.assert_rejected(
            lambda document: document["vectors"][0].__setitem__("packet_length", True)
        )

    def test_rejects_malformed_hex(self):
        self.assert_rejected(
            lambda document: document["vectors"][-1].__setitem__("wire", "78 00")
        )

    def test_rejects_zero_repeat_count(self):
        self.assert_rejected(
            lambda document: document["vectors"][0]["packet"]["parts"][0].__setitem__(
                "count", 0
            )
        )

    def test_rejects_inconsistent_packet_length(self):
        self.assert_rejected(
            lambda document: document["vectors"][0].__setitem__("packet_length", 360)
        )

    def test_rejects_rule_id_out_of_range(self):
        self.assert_rejected(
            lambda document: document["vectors"][0].__setitem__("rule_id", 256)
        )

    def test_rejects_inconsistent_retransmission(self):
        self.assert_rejected(
            lambda document: document["vectors"][0]["loss"].__setitem__(
                "retransmission", "787a00"
            )
        )

    def test_rejects_inconsistent_fixed_deadlines(self):
        self.assert_rejected(
            lambda document: document["vectors"][3].__setitem__(
                "timer_deadlines_s", [10, 20, 31, 40]
            )
        )

    def test_rejects_duplicate_assigned_fcn(self):
        self.assert_rejected(
            lambda document: document["vectors"][-1].__setitem__(
                "assigned_fcns", [62, 62, 63]
            )
        )


if __name__ == "__main__":
    unittest.main()
