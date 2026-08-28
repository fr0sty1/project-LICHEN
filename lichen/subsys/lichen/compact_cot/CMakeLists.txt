# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library_named(lichen_compact_cot)
zephyr_library_sources_ifdef(CONFIG_LICHEN_COMPACT_COT_PLI compact_cot_pli.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_COMPACT_COT_CHAT compact_cot_chat.c)
zephyr_include_directories(include)
