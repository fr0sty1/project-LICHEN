# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN crypto subsystem

zephyr_library()

zephyr_library_sources_ifdef(CONFIG_LICHEN_CRYPTO_MONOCYPHER
  monocypher.c
  monocypher-ed25519.c
)

# Vendored Monocypher exceeds the module-wide 2KB -Wstack-usage budget:
# crypto_argon2 (monocypher.c:749) — measured at 2464B on one 64-bit
# toolchain and 3424B on the AWS gcc11 native_sim/native/64 build.  Keep
# the warning visible but non-fatal for this vendored file only; first-party
# code stays at -Werror=stack-usage with the 2048B limit set in
# lichen/zephyr/CMakeLists.txt.
# The trailing '=' is required: -Wstack-usage is a parameterized GCC option,
# and GCC rejects the unparameterized -Wno-error=stack-usage spelling.
set_source_files_properties(monocypher.c PROPERTIES
  COMPILE_OPTIONS "-Wno-error=stack-usage="
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_CRYPTO_AES_CCM
  aes_ccm.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})
