/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2_stats.c
 * @brief LICHEN L2 stats and test hooks
 *
 * Contains lichen_l2_get_tx_stats(), lichen_l2_get_rx_stats(),
 * tx_stat_result(), and test hook functions.
 */

#include "lichen_l2_internal.h"

LOG_MODULE_DECLARE(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

void lichen_l2_get_tx_stats(uint32_t *attempts, uint32_t *errors, int *last_err)
{
	if (attempts != NULL) {
		*attempts = (uint32_t)atomic_get(&tx_stat_attempts);
	}
	if (errors != NULL) {
		*errors = (uint32_t)atomic_get(&tx_stat_errors);
	}
	if (last_err != NULL) {
		*last_err = (int)atomic_get(&tx_stat_last_err);
	}
}

void lichen_l2_get_rx_stats(uint32_t *frames, uint32_t *accepted, int *last_err)
{
	if (frames != NULL) {
		*frames = (uint32_t)atomic_get(&rx_stat_frames);
	}
	if (accepted != NULL) {
		*accepted = (uint32_t)atomic_get(&rx_stat_accepted);
	}
	if (last_err != NULL) {
		*last_err = (int)atomic_get(&rx_stat_last_err);
	}
}

void tx_stat_result(int ret)
{
	if (ret < 0) {
		atomic_inc(&tx_stat_errors);
		atomic_set(&tx_stat_last_err, ret);
	}
}

#ifdef CONFIG_LICHEN_L2_TEST_HOOKS
int lichen_l2_test_load_key(const uint8_t seed[32], uint8_t pubkey[32])
{
	return lichen_l2_load_key(seed, pubkey);
}

int lichen_l2_test_load_link_key(const uint8_t link_key[LICHEN_LINK_KEY_LEN])
{
	return lichen_l2_load_link_key(link_key);
}

void lichen_l2_test_reset_stats(void)
{
	k_mutex_lock(&test_stats_mutex, K_FOREVER);
	atomic_set(&test_tx_packets, 0);
	atomic_set(&test_rx_frames, 0);
	atomic_set(&test_rx_injected_packets, 0);
	memset(test_last_injected, 0, sizeof(test_last_injected));
	test_last_injected_len = 0;
	k_mutex_unlock(&test_stats_mutex);
}

void lichen_l2_test_get_stats(struct lichen_l2_test_stats *stats)
{
	if (stats == NULL) {
		return;
	}

	stats->tx_packets = (uint32_t)atomic_get(&test_tx_packets);
	stats->rx_frames = (uint32_t)atomic_get(&test_rx_frames);
	stats->rx_injected_packets =
		(uint32_t)atomic_get(&test_rx_injected_packets);
	k_mutex_lock(&test_stats_mutex, K_FOREVER);
	stats->last_injected_len = (uint32_t)test_last_injected_len;
	memcpy(stats->last_injected, test_last_injected,
	       sizeof(stats->last_injected));
	k_mutex_unlock(&test_stats_mutex);
}
#endif
