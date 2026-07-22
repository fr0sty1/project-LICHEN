if(CONFIG_LORA_LICHEN_SIM OR CONFIG_LORA_LICHEN_RENODE OR CONFIG_LORA_LR1110)
  add_subdirectory(lora)
endif()
add_subdirectory_ifdef(CONFIG_LORA_LOOPBACK lora_loopback)

if (CONFIG_GNSS_AG3335)
	add_subdirectory(gnss)
endif()
add_subdirectory_ifdef(CONFIG_INPUT_LILYGO_TDECK_KEYBOARD input)
