zephyr_library()

set(LR1110_DRV_DIR
	${ZEPHYR_LORAMAC_NODE_MODULE_DIR}/src/radio/lr1110/lr1110_driver/src)

zephyr_library_sources(
	lr1110.c
	lr1110_hal.c
	${LR1110_DRV_DIR}/lr1110_radio.c
	${LR1110_DRV_DIR}/lr1110_regmem.c
	${LR1110_DRV_DIR}/lr1110_system.c
)

zephyr_library_include_directories(${LR1110_DRV_DIR})
