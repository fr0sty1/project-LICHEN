cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lichen_gateway)

target_sources(app PRIVATE src/main.c)

# Register the lichen_coap iterable section so the linker resolves
# _coap_resource_lichen_coap_list_start / _list_end symbols.
zephyr_linker_sources(DATA_SECTIONS sections-ram.ld)
zephyr_iterable_section(
  NAME coap_resource_lichen_coap
  GROUP DATA_REGION ${XIP_ALIGN_WITH_INPUT}
  SUBALIGN CONFIG_LINKER_ITERABLE_SUBALIGN)
