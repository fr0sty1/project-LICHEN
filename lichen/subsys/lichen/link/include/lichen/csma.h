/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_CSMA_H_
#define LICHEN_CSMA_H_

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lichen_csma_phase {
	LICHEN_CSMA_IDLE,
	LICHEN_CSMA_BACKOFF,
	LICHEN_CSMA_CAD,
	LICHEN_CSMA_TX_ALLOWED,
	LICHEN_CSMA_EXHAUSTED,
	LICHEN_CSMA_CANCELLED,
	LICHEN_CSMA_ERROR,
};

enum lichen_csma_result {
	LICHEN_CSMA_RESULT_BACKOFF = 1,
	LICHEN_CSMA_RESULT_TX_ALLOWED,
	LICHEN_CSMA_RESULT_CAD_BUSY,
	LICHEN_CSMA_RESULT_CAD_TIMEOUT,
	LICHEN_CSMA_RESULT_RETRY_EXHAUSTED,
	LICHEN_CSMA_RESULT_CANCELLED,
};

typedef int (*lichen_csma_rng_fn)(void *user, uint32_t *value);
typedef int (*lichen_csma_wait_fn)(void *user, uint32_t delay_ms);
typedef int (*lichen_csma_cad_fn)(void *user, uint8_t timeout_symbols,
				 bool *channel_busy);

struct lichen_csma {
	atomic_bool locked;
	atomic_bool cancel_requested;
	enum lichen_csma_phase phase;
	int last_error;
	uint8_t backoff_exponent;
	uint8_t retries;
};

struct lichen_csma_snapshot {
	enum lichen_csma_phase phase;
	int last_error;
	uint8_t backoff_exponent;
	uint8_t retries;
	bool cancel_requested;
};

void lichen_csma_init(struct lichen_csma *csma);

int lichen_csma_start(struct lichen_csma *csma, uint8_t initial_exponent,
		      lichen_csma_rng_fn rng, void *rng_user,
		      uint32_t *backoff_ms);

int lichen_csma_cad_begin(struct lichen_csma *csma);

int lichen_csma_cad_complete(struct lichen_csma *csma, int cad_status,
			     bool channel_busy, lichen_csma_rng_fn rng,
			     void *rng_user, uint32_t *backoff_ms);

int lichen_csma_tx_complete(struct lichen_csma *csma, int tx_status);

void lichen_csma_cancel(struct lichen_csma *csma);

int lichen_csma_reset(struct lichen_csma *csma);

int lichen_csma_snapshot(const struct lichen_csma *csma,
			 struct lichen_csma_snapshot *snapshot);

/**
 * Run the complete bounded CSMA/CA acquisition sequence.
 *
 * Returns zero only after a clear CAD result transitions @p csma to
 * LICHEN_CSMA_TX_ALLOWED. Busy/timeout results back off and retry up to the
 * protocol limit. Driver errors and cancellation are propagated fail-closed.
 */
int lichen_csma_acquire(struct lichen_csma *csma, uint8_t initial_exponent,
		       lichen_csma_rng_fn rng, void *rng_user,
		       lichen_csma_wait_fn wait, void *wait_user,
		       lichen_csma_cad_fn cad, void *cad_user);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_CSMA_H_ */
