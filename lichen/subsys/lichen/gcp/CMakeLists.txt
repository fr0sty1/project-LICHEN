# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# GCP (Gateway Coordination Protocol) subsystem

zephyr_include_directories(include)

zephyr_library()
zephyr_library_sources_ifdef(CONFIG_LICHEN_GCP_TRUST gcp_trust.c)
