# SPDX-License-Identifier: GPL-3.0-or-later
# Flash via J-Link or nrfjprog (SWD).
# For UF2 drag-and-drop: double-tap RESET to enter bootloader, copy .uf2 file.

board_runner_args(jlink "--device=nRF52840_xxAA" "--speed=4000")
board_runner_args(pyocd "--target=nrf52840" "--frequency=4000000")
include(${ZEPHYR_BASE}/boards/common/nrfjprog.board.cmake)
include(${ZEPHYR_BASE}/boards/common/nrfutil.board.cmake)
include(${ZEPHYR_BASE}/boards/common/jlink.board.cmake)
include(${ZEPHYR_BASE}/boards/common/pyocd.board.cmake)
