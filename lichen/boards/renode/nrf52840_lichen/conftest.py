# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Pytest options for the Renode nRF52840 mesh tests.

pytest only collects ``pytest_addoption`` from ``conftest.py`` / plugins, not
from ordinary test modules, so the ``--board`` / ``--nodes`` options live here.
"""


def pytest_addoption(parser):
    parser.addoption("--board", default="t_echo", help="Board type (t_echo, rak4631)")
    parser.addoption("--nodes", default=2, type=int, help="Number of nodes")
