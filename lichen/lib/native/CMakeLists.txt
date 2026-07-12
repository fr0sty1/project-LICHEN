zephyr_library_named(lichen_native)
zephyr_library_sources_ifdef(CONFIG_LICHEN_NATIVE native.c)
zephyr_library_include_directories_ifdef(CONFIG_LICHEN_NATIVE
	include
	../../subsys/lichen/hal/include
)
zephyr_include_directories_ifdef(CONFIG_LICHEN_NATIVE include)
