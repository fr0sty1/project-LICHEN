zephyr_library_named(lichen_native)
zephyr_library_sources(native.c)
zephyr_library_include_directories(
	include
	../../subsys/lichen/hal/include
)
zephyr_include_directories(include)
