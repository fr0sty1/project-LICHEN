/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_LINK_LOAD_BALANCE_H_
#define LICHEN_LINK_LOAD_BALANCE_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_LB_FP_SCALE         65536u
#define LICHEN_LB_EMA_ALPHA_SHIFT  2u
#define LICHEN_LB_DENSITY_CRITICAL 20u
#define LICHEN_LB_DENSITY_HIGH     8u
#define LICHEN_LB_DENSITY_LOW      5u
#define LICHEN_LB_SNR_CRITICAL    -5
#define LICHEN_LB_SNR_POOR         0
#define LICHEN_LB_SNR_GOOD         8
#define LICHEN_LB_LOAD_HIGH        (LICHEN_LB_FP_SCALE * 4u / 5u)
#define LICHEN_LB_LOAD_REBALANCE   (LICHEN_LB_FP_SCALE * 2u / 5u)

struct lichen_lb_snr_stats {
	int8_t min;
	int8_t max;
	int32_t avg_fp;
	uint32_t count;
};

struct lichen_lb_metrics {
	uint32_t packets_tx;
	uint32_t packets_rx;
	uint32_t tx_failures;
	struct lichen_lb_snr_stats snr;
	uint8_t density;
	uint32_t load_factor_fp;
};

void lichen_lb_metrics_init(struct lichen_lb_metrics *m);
void lichen_lb_record_tx(struct lichen_lb_metrics *m);
void lichen_lb_record_rx(struct lichen_lb_metrics *m, int8_t snr);
void lichen_lb_record_tx_fail(struct lichen_lb_metrics *m);
void lichen_lb_record_density(struct lichen_lb_metrics *m, uint8_t density);
void lichen_lb_record_load_factor(struct lichen_lb_metrics *m, uint32_t load_fp);
uint8_t lichen_lb_packet_loss_pct(const struct lichen_lb_metrics *m);
uint32_t lichen_lb_packet_loss_fp(const struct lichen_lb_metrics *m);
uint8_t lichen_lb_adaptive_sf(const struct lichen_lb_metrics *m);
bool lichen_lb_should_rebalance(const struct lichen_lb_metrics *m);
uint8_t lichen_lb_select_channel(const struct lichen_lb_metrics *m,
				 const uint8_t eui64[8], uint32_t epoch,
				 uint8_t n_channels);

#ifdef __cplusplus
}
#endif

#endif
