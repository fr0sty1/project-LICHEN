/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_RF_HEALTH_H_
#define LICHEN_RF_HEALTH_H_

#include <stdint.h>
#include <stdbool.h>

#define LICHEN_RF_EMA_ALPHA_SHIFT 2
#define LICHEN_RF_DENSITY_CRITICAL 20
#define LICHEN_RF_DENSITY_HIGH 8
#define LICHEN_RF_DENSITY_LOW 5
#define LICHEN_RF_SNR_CRITICAL (-5)
#define LICHEN_RF_SNR_POOR 0
#define LICHEN_RF_SNR_GOOD 8
#define LICHEN_RF_LOAD_HIGH_FP 0xCCCC
#define LICHEN_RF_LOAD_REBALANCE_FP 0x6666

struct lichen_snr_stats {
	int8_t min;
	int8_t max;
	int32_t avg_fp;
	uint32_t count;
};

struct lichen_rf_health {
	uint32_t packets_tx;
	uint32_t packets_rx;
	uint32_t tx_failures;
	struct lichen_snr_stats snr;
	uint8_t density;
	uint32_t load_factor_fp;
};

void lichen_rf_health_init(struct lichen_rf_health *h);
void lichen_rf_health_record_tx(struct lichen_rf_health *h);
void lichen_rf_health_record_rx(struct lichen_rf_health *h, int8_t snr);
void lichen_rf_health_record_tx_fail(struct lichen_rf_health *h);
void lichen_rf_health_record_density(struct lichen_rf_health *h, uint8_t density);
void lichen_rf_health_record_load_factor(struct lichen_rf_health *h, uint32_t load_fp);
uint32_t lichen_rf_health_packet_loss_rate_fp(const struct lichen_rf_health *h);
uint8_t lichen_rf_health_packet_loss_rate_pct(const struct lichen_rf_health *h);
uint16_t lichen_rf_health_packet_loss_permille(const struct lichen_rf_health *h);
int8_t lichen_rf_health_snr_avg(const struct lichen_rf_health *h);
uint8_t lichen_rf_health_adaptive_sf(const struct lichen_rf_health *h);
bool lichen_rf_health_should_rebalance(const struct lichen_rf_health *h);
void lichen_rf_health_reset(struct lichen_rf_health *h);

#endif
