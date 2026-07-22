# SPDX-License-Identifier: GPL-3.0-or-later
zephyr_library()
zephyr_library_sources_ifdef(CONFIG_INPUT_LILYGO_TDECK_KEYBOARD lilygo_tdeck_keyboard.c)
