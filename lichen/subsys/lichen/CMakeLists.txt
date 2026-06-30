# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN protocol subsystem for Zephyr

add_subdirectory_ifdef(CONFIG_LICHEN_COAP coap)
if(CONFIG_LICHEN_CRYPTO_MONOCYPHER OR CONFIG_LICHEN_CRYPTO_AES_CCM)
  add_subdirectory(crypto)
endif()
add_subdirectory_ifdef(CONFIG_LICHEN_EDHOC edhoc)
add_subdirectory_ifdef(CONFIG_LICHEN_HAL hal)
add_subdirectory_ifdef(CONFIG_LICHEN_LINK link)
add_subdirectory_ifdef(CONFIG_LICHEN_MESHTASTIC_CODEC meshtastic)
add_subdirectory_ifdef(CONFIG_LICHEN_IPV6 l2)
add_subdirectory_ifdef(CONFIG_LICHEN_OSCORE oscore)
add_subdirectory_ifdef(CONFIG_LICHEN_SCHC schc)
add_subdirectory_ifdef(CONFIG_LICHEN_SENML senml)
add_subdirectory_ifdef(CONFIG_LICHEN_RPL rpl)
