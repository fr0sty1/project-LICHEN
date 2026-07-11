zephyr_library()

set(LR1110_DRV_DIR
	${ZEPHYR_LORAMAC_NODE_MODULE_DIR}/src/radio/lr1110/lr1110_driver/src)

if(NOT EXISTS ${LR1110_DRV_DIR}/lr1110_radio.c)
	message(FATAL_ERROR
		"loramac-node LR1110 driver sources are missing at ${LR1110_DRV_DIR}. "
		"Run west update or tools/zephyr-clean-worktree.sh setup/create so the "
		"loramac-node src/radio/lr1110/lr1110_driver submodule is initialized.")
endif()

zephyr_library_sources(
	lr1110.c
	lr1110_hal.c
	${LR1110_DRV_DIR}/lr1110_radio.c
	${LR1110_DRV_DIR}/lr1110_regmem.c
	${LR1110_DRV_DIR}/lr1110_system.c
)

# Vendored Semtech driver sources are not written to the LICHEN C safety
# policy (-Wconversion etc.); exempt them so the hardening flags applied to
# this library don't fail third-party code we don't modify.
set_source_files_properties(
	${LR1110_DRV_DIR}/lr1110_radio.c
	${LR1110_DRV_DIR}/lr1110_regmem.c
	${LR1110_DRV_DIR}/lr1110_system.c
	PROPERTIES COMPILE_OPTIONS "-Wno-conversion;-Wno-shadow;-Wno-extra"
)

zephyr_library_include_directories(${LR1110_DRV_DIR})
