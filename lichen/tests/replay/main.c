/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <assert.h>
#include <lichen/replay.h>

static void test_finite_ordering(void)
{
	struct lichen_replay_window window;

	lichen_replay_init(&window);
	assert(lichen_replay_check(&window, 3, 65535));
	assert(!lichen_replay_check(&window, 3, 0));
	assert(lichen_replay_check(&window, 4, 0));
	assert(!lichen_replay_check(&window, 3, 65535));

	lichen_replay_init(&window);
	assert(lichen_replay_check(&window, 255, 65535));
	assert(!lichen_replay_check(&window, 0, 0));
}

static void test_same_epoch_window(void)
{
	struct lichen_replay_window window;

	lichen_replay_init(&window);
	assert(lichen_replay_check(&window, 7, 100));
	assert(lichen_replay_check(&window, 7, 102));
	assert(lichen_replay_check(&window, 7, 101));
	assert(!lichen_replay_check(&window, 7, 101));
	assert(lichen_replay_check(&window, 7, 71));
	assert(!lichen_replay_check(&window, 7, 70));
}

static void test_public_key_identity(void)
{
	struct lichen_replay_table table;
	const uint8_t key_a[LICHEN_PK_LEN] = { [0] = 0x11, [31] = 0xa1 };
	const uint8_t key_b[LICHEN_PK_LEN] = { [0] = 0x11, [31] = 0xb2 };
	struct lichen_replay_window *window_a;
	struct lichen_replay_window *window_b;

	lichen_replay_table_init(&table);
	window_a = lichen_replay_get(&table, key_a);
	assert(window_a != NULL);
	assert(lichen_replay_check(window_a, 9, 42));
	assert(!lichen_replay_check(lichen_replay_get(&table, key_a), 9, 42));

	window_b = lichen_replay_get(&table, key_b);
	assert(window_b != NULL);
	assert(window_b != window_a);
	assert(lichen_replay_check(window_b, 9, 42));

	lichen_replay_remove(&table, key_a);
	assert(lichen_replay_check(lichen_replay_get(&table, key_a), 9, 42));
}

static void test_full_table_retains_replay_state(void)
{
	struct lichen_replay_table table;
	uint8_t keys[CONFIG_LICHEN_LINK_MAX_NEIGHBORS + 1][LICHEN_PK_LEN] = { 0 };
	struct lichen_replay_window *first;

	lichen_replay_table_init(&table);
	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		keys[i][0] = (uint8_t)(i + 1);
		assert(lichen_replay_get(&table, keys[i]) != NULL);
	}
	first = lichen_replay_get(&table, keys[0]);
	assert(first != NULL);
	assert(lichen_replay_check(first, 255, 65535));

	keys[CONFIG_LICHEN_LINK_MAX_NEIGHBORS][0] = 0xff;
	assert(lichen_replay_get(&table,
		keys[CONFIG_LICHEN_LINK_MAX_NEIGHBORS]) == NULL);
	assert(lichen_replay_get(&table, keys[0]) == first);
	assert(!lichen_replay_check(first, 0, 0));
}

int main(void)
{
	test_finite_ordering();
	test_same_epoch_window();
	test_public_key_identity();
	test_full_table_retains_replay_state();
	return 0;
}
