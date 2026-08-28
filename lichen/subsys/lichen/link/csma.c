/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/csma.h>
#include <lichen/link.h>

#include <errno.h>
#include <limits.h>

BUILD_ASSERT(LICHEN_CSMA_BACKOFF_MAX_EXPONENT < 32U,
	     "CSMA exponent must fit a 32-bit contention window");
BUILD_ASSERT(LICHEN_CSMA_RETRY_LIMIT < UINT8_MAX,
	     "CSMA retry counter must not wrap at exhaustion");

static bool csma_try_lock(struct lichen_csma *csma)
{
	bool expected = false;

	return atomic_compare_exchange_strong_explicit(&csma->locked, &expected, true,
						       memory_order_acquire,
						       memory_order_relaxed);
}

static void csma_unlock(struct lichen_csma *csma)
{
	atomic_store_explicit(&csma->locked, false, memory_order_release);
}

static int csma_cancel_locked(struct lichen_csma *csma)
{
	if (!atomic_load_explicit(&csma->cancel_requested, memory_order_acquire)) {
		return 0;
	}
	csma->phase = LICHEN_CSMA_CANCELLED;
	csma->last_error = 0;
	return LICHEN_CSMA_RESULT_CANCELLED;
}

static int csma_backoff_ms(struct lichen_csma *csma, uint8_t exponent,
			   lichen_csma_rng_fn rng, void *rng_user,
			   uint32_t *backoff_ms)
{
	uint32_t random_value;
	uint32_t slots;

	if (exponent > LICHEN_CSMA_BACKOFF_MAX_EXPONENT) {
		return -EINVAL;
	}
	if (exponent == 0U) {
		*backoff_ms = 0U;
		return 0;
	}
	if (rng == NULL) {
		return -EINVAL;
	}
	int ret = rng(rng_user, &random_value);
	if (ret < 0) {
		return ret;
	}
	if (ret > 0) {
		return -EIO;
	}
	int cancelled = csma_cancel_locked(csma);
	if (cancelled != 0) {
		return cancelled;
	}

	/* Multiplication-high maps the entire uint32_t range uniformly onto
	 * [0, 2^BE), including the canonical 0, half, and maximum fixtures. */
	slots = (uint32_t)(((uint64_t)random_value *
			      (UINT64_C(1) << exponent)) >> 32);
	if (slots > UINT32_MAX / LICHEN_CSMA_BACKOFF_UNIT_MS) {
		return -EOVERFLOW;
	}
	*backoff_ms = slots * LICHEN_CSMA_BACKOFF_UNIT_MS;
	return 0;
}

void lichen_csma_init(struct lichen_csma *csma)
{
	if (csma == NULL) {
		return;
	}
	atomic_init(&csma->locked, false);
	atomic_init(&csma->cancel_requested, false);
	csma->phase = LICHEN_CSMA_IDLE;
	csma->last_error = 0;
	csma->backoff_exponent = 0U;
	csma->retries = 0U;
}

int lichen_csma_start(struct lichen_csma *csma, uint8_t initial_exponent,
		      lichen_csma_rng_fn rng, void *rng_user,
		      uint32_t *backoff_ms)
{
	if (csma == NULL || backoff_ms == NULL ||
	    initial_exponent > LICHEN_CSMA_BACKOFF_MAX_EXPONENT) {
		return -EINVAL;
	}
	if (!csma_try_lock(csma)) {
		return -EBUSY;
	}
	if (csma->phase == LICHEN_CSMA_BACKOFF || csma->phase == LICHEN_CSMA_CAD ||
	    csma->phase == LICHEN_CSMA_TX_ALLOWED) {
		csma_unlock(csma);
		return -EALREADY;
	}

	atomic_store_explicit(&csma->cancel_requested, false, memory_order_release);
	int ret = csma_backoff_ms(csma, initial_exponent, rng, rng_user, backoff_ms);
	if (ret < 0) {
		csma->phase = LICHEN_CSMA_ERROR;
		csma->last_error = ret;
		csma_unlock(csma);
		return ret;
	}
	csma->phase = LICHEN_CSMA_BACKOFF;
	csma->last_error = 0;
	csma->backoff_exponent = initial_exponent;
	csma->retries = 0U;
	csma_unlock(csma);
	return LICHEN_CSMA_RESULT_BACKOFF;
}

int lichen_csma_cad_begin(struct lichen_csma *csma)
{
	if (csma == NULL) {
		return -EINVAL;
	}
	if (!csma_try_lock(csma)) {
		return -EBUSY;
	}
	int cancelled = csma_cancel_locked(csma);
	if (cancelled != 0) {
		csma_unlock(csma);
		return cancelled;
	}
	if (csma->phase != LICHEN_CSMA_BACKOFF) {
		csma_unlock(csma);
		return -EPROTO;
	}
	csma->phase = LICHEN_CSMA_CAD;
	csma_unlock(csma);
	return 0;
}

int lichen_csma_cad_complete(struct lichen_csma *csma, int cad_status,
			     bool channel_busy, lichen_csma_rng_fn rng,
			     void *rng_user, uint32_t *backoff_ms)
{
	if (csma == NULL || backoff_ms == NULL || cad_status > 0) {
		return -EINVAL;
	}
	if (!csma_try_lock(csma)) {
		return -EBUSY;
	}
	int cancelled = csma_cancel_locked(csma);
	if (cancelled != 0) {
		csma_unlock(csma);
		return cancelled;
	}
	if (csma->phase != LICHEN_CSMA_CAD) {
		csma_unlock(csma);
		return -EPROTO;
	}
	*backoff_ms = 0U;
	if (cad_status < 0 && cad_status != -ETIMEDOUT) {
		csma->phase = LICHEN_CSMA_ERROR;
		csma->last_error = cad_status;
		csma_unlock(csma);
		return cad_status;
	}
	if (cad_status == 0 && !channel_busy) {
		csma->phase = LICHEN_CSMA_TX_ALLOWED;
		csma->last_error = 0;
		csma->backoff_exponent = 0U;
		csma->retries = 0U;
		csma_unlock(csma);
		return LICHEN_CSMA_RESULT_TX_ALLOWED;
	}

	uint8_t retries = (uint8_t)(csma->retries + 1U);
	if (retries > LICHEN_CSMA_RETRY_LIMIT) {
		csma->phase = LICHEN_CSMA_EXHAUSTED;
		csma->last_error = 0;
		csma->retries = retries;
		csma_unlock(csma);
		return LICHEN_CSMA_RESULT_RETRY_EXHAUSTED;
	}
	uint8_t exponent = csma->backoff_exponent;
	if (exponent < LICHEN_CSMA_BACKOFF_MAX_EXPONENT) {
		exponent++;
	}
	int ret = csma_backoff_ms(csma, exponent, rng, rng_user, backoff_ms);
	if (ret == LICHEN_CSMA_RESULT_CANCELLED) {
		csma_unlock(csma);
		return ret;
	}
	if (ret < 0) {
		csma->phase = LICHEN_CSMA_ERROR;
		csma->last_error = ret;
		csma_unlock(csma);
		return ret;
	}
	csma->phase = LICHEN_CSMA_BACKOFF;
	csma->last_error = 0;
	csma->backoff_exponent = exponent;
	csma->retries = retries;
	csma_unlock(csma);
	return cad_status == -ETIMEDOUT ? LICHEN_CSMA_RESULT_CAD_TIMEOUT :
					    LICHEN_CSMA_RESULT_CAD_BUSY;
}

int lichen_csma_tx_complete(struct lichen_csma *csma, int tx_status)
{
	if (csma == NULL || tx_status > 0) {
		return -EINVAL;
	}
	if (!csma_try_lock(csma)) {
		return -EBUSY;
	}
	int cancelled = csma_cancel_locked(csma);
	if (cancelled != 0) {
		csma_unlock(csma);
		return cancelled;
	}
	if (csma->phase != LICHEN_CSMA_TX_ALLOWED) {
		csma_unlock(csma);
		return -EPROTO;
	}
	csma->phase = tx_status == 0 ? LICHEN_CSMA_IDLE : LICHEN_CSMA_ERROR;
	csma->last_error = tx_status;
	csma_unlock(csma);
	return tx_status;
}

void lichen_csma_cancel(struct lichen_csma *csma)
{
	if (csma == NULL) {
		return;
	}
	atomic_store_explicit(&csma->cancel_requested, true, memory_order_release);
	if (csma_try_lock(csma)) {
		csma->phase = LICHEN_CSMA_CANCELLED;
		csma->last_error = 0;
		csma_unlock(csma);
	}
}

int lichen_csma_reset(struct lichen_csma *csma)
{
	if (csma == NULL) {
		return -EINVAL;
	}
	if (!csma_try_lock(csma)) {
		return -EBUSY;
	}
	atomic_store_explicit(&csma->cancel_requested, false, memory_order_release);
	csma->phase = LICHEN_CSMA_IDLE;
	csma->last_error = 0;
	csma->backoff_exponent = 0U;
	csma->retries = 0U;
	csma_unlock(csma);
	return 0;
}

int lichen_csma_snapshot(const struct lichen_csma *csma,
			 struct lichen_csma_snapshot *snapshot)
{
	if (csma == NULL || snapshot == NULL) {
		return -EINVAL;
	}
	struct lichen_csma *mutable_csma = (struct lichen_csma *)csma;
	if (!csma_try_lock(mutable_csma)) {
		return -EBUSY;
	}
	snapshot->phase = csma->phase;
	snapshot->last_error = csma->last_error;
	snapshot->backoff_exponent = csma->backoff_exponent;
	snapshot->retries = csma->retries;
	snapshot->cancel_requested = atomic_load_explicit(&csma->cancel_requested,
							 memory_order_acquire);
	csma_unlock(mutable_csma);
	return 0;
}

int lichen_csma_acquire(struct lichen_csma *csma, uint8_t initial_exponent,
		       lichen_csma_rng_fn rng, void *rng_user,
		       lichen_csma_wait_fn wait, void *wait_user,
		       lichen_csma_cad_fn cad, void *cad_user)
{
	uint32_t backoff_ms;
	int ret;

	if (csma == NULL || wait == NULL || cad == NULL) {
		return -EINVAL;
	}

	ret = lichen_csma_start(csma, initial_exponent, rng, rng_user,
				&backoff_ms);
	if (ret < 0) {
		return ret;
	}

	for (;;) {
		ret = wait(wait_user, backoff_ms);
		if (ret != 0) {
			lichen_csma_cancel(csma);
			return ret < 0 ? ret : -EIO;
		}

		ret = lichen_csma_cad_begin(csma);
		if (ret == LICHEN_CSMA_RESULT_CANCELLED) {
			return -ECANCELED;
		}
		if (ret < 0) {
			return ret;
		}

		bool channel_busy = true;
		int cad_status = cad(cad_user, LICHEN_CSMA_CAD_TIMEOUT_SYMBOLS,
				     &channel_busy);
		if (cad_status > 0) {
			cad_status = -EIO;
		}
		ret = lichen_csma_cad_complete(csma, cad_status, channel_busy,
					      rng, rng_user, &backoff_ms);
		switch (ret) {
		case LICHEN_CSMA_RESULT_TX_ALLOWED:
			return 0;
		case LICHEN_CSMA_RESULT_CAD_BUSY:
		case LICHEN_CSMA_RESULT_CAD_TIMEOUT:
			break;
		case LICHEN_CSMA_RESULT_RETRY_EXHAUSTED:
			return -EBUSY;
		case LICHEN_CSMA_RESULT_CANCELLED:
			return -ECANCELED;
		default:
			return ret < 0 ? ret : -EIO;
		}
	}
}
