cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lichen_gateway)

target_sources(app PRIVATE
  src/main.c
  src/config_apply.c
  src/config_cbor.c
  src/status_cbor.c)
target_sources_ifdef(CONFIG_LORA_LICHEN_BLE app PRIVATE
  src/ble_app_owner.c
  src/ble_uart.c
  src/ble_lci_netif.c
  src/ble_ingress.c)
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

# Register the lichen_coap iterable section so the linker resolves
# _coap_resource_lichen_coap_list_start / _list_end symbols.
zephyr_linker_sources(DATA_SECTIONS sections-ram.ld)
zephyr_iterable_section(
  NAME coap_resource_lichen_coap
  GROUP DATA_REGION ${XIP_ALIGN_WITH_INPUT}
  SUBALIGN CONFIG_LINKER_ITERABLE_SUBALIGN)
