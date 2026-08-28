/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TEST_ZEPHYR_SETTINGS_H_
#define TEST_ZEPHYR_SETTINGS_H_

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

typedef ssize_t (*settings_read_cb)(void *cb_arg, void *data, size_t len);
typedef int (*test_settings_set_handler_t)(const char *name, size_t len,
					   settings_read_cb read_cb, void *cb_arg);

extern test_settings_set_handler_t test_settings_set_handler;

#define SETTINGS_STATIC_HANDLER_DEFINE(_name, _subtree, _get, _set, _commit, _export) \
	test_settings_set_handler_t test_settings_set_handler = (_set)

int settings_subsys_init(void);
int settings_load_subtree(const char *subtree);
int settings_save_one(const char *name, const void *value, size_t len);
bool settings_name_steq(const char *name, const char *key, const char **next);

#endif
