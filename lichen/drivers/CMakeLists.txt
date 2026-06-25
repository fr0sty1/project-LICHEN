if (CONFIG_LORA_LICHEN_SIM OR CONFIG_LORA_LR1110)
	add_subdirectory(lora)
endif()

if (CONFIG_GNSS_AG3335)
	add_subdirectory(gnss)
endif()
