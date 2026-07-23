cmake_minimum_required(VERSION 3.20.0)
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/lichen_build_epoch.cmake)
lichen_configure_time_build_epoch()
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lichen_gateway)

target_include_directories(app PRIVATE
  ../../subsys/lichen/transport/include)

target_sources(app PRIVATE
  src/main.c
  src/config_apply.c
  src/config_cbor.c
  src/network_location.c
  src/status_cbor.c)
target_sources_ifdef(CONFIG_LICHEN_ROUTING app PRIVATE
  src/announce_ingest.c)
target_sources_ifdef(CONFIG_LORA_LICHEN_BLE app PRIVATE
  src/ble_app_owner.c
  src/ble_uart.c
  src/ble_lci_netif.c
  src/ble_ingress.c
  src/inbound_coap.c
  src/inbound_events.c)
target_sources_ifdef(CONFIG_LORA_LICHEN_MESHTASTIC_BLE app PRIVATE
  src/ble_app_owner.c
  src/ble_meshtastic.c
  src/inbound_coap.c
  src/inbound_events.c
  src/message_contract.c
  src/meshtastic_adapter.c)
target_sources_ifdef(CONFIG_LORA_LICHEN_MESHCORE_BLE app PRIVATE
  src/ble_app_owner.c
  src/ble_meshcore.c
  src/gateway_identity.c
  src/message_contract.c
  src/meshcore_adapter.c)

target_sources_ifdef(CONFIG_LORA_LICHEN_GATEWAY_RPL_ROOT app PRIVATE
  src/rpl_root.c)

# Register the lichen_coap (modular, not _server) iterable section so
# the linker resolves _coap_resource_lichen_coap_list_start / _list_end.
# Standalone server conditionalized off via Kconfig for single owner.
zephyr_linker_sources(DATA_SECTIONS sections-ram.ld)
zephyr_iterable_section(
  NAME coap_resource_lichen_coap
  GROUP DATA_REGION ${XIP_ALIGN_WITH_INPUT}
  SUBALIGN CONFIG_LINKER_ITERABLE_SUBALIGN)
