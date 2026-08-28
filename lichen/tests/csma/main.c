/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/csma.h>
#include <lichen/link.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

struct rng_fixture {
	uint32_t value;
	int error;
};

static int fixed_rng(void *user, uint32_t *value)
{
	struct rng_fixture *fixture = user;

	if (fixture->error != 0) {
		return fixture->error;
	}
	*value = fixture->value;
	return 0;
}

static struct lichen_csma_snapshot snapshot(struct lichen_csma *csma)
{
	struct lichen_csma_snapshot value;

	assert(lichen_csma_snapshot(csma, &value) == 0);
	return value;
}

static void test_canonical_backoff_and_clear(void)
{
	struct lichen_csma csma;
	struct rng_fixture rng = { .value = 0U };
	uint32_t delay = UINT32_MAX;

	lichen_csma_init(&csma);
	assert(lichen_csma_start(&csma, 0U, fixed_rng, &rng, &delay) ==
	       LICHEN_CSMA_RESULT_BACKOFF);
	assert(delay == 0U);
	assert(lichen_csma_cad_begin(&csma) == 0);
	assert(lichen_csma_cad_complete(&csma, 0, true, fixed_rng, &rng, &delay) ==
	       LICHEN_CSMA_RESULT_CAD_BUSY);
	assert(delay == 0U);
	struct lichen_csma_snapshot state = snapshot(&csma);
	assert(state.backoff_exponent == 1U && state.retries == 1U);

	rng.value = UINT32_MAX;
	assert(lichen_csma_cad_begin(&csma) == 0);
	assert(lichen_csma_cad_complete(&csma, 0, true, fixed_rng, &rng, &delay) ==
	       LICHEN_CSMA_RESULT_CAD_BUSY);
	assert(delay == 30U);
	state = snapshot(&csma);
	assert(state.backoff_exponent == 2U && state.retries == 2U);

	assert(lichen_csma_cad_begin(&csma) == 0);
	assert(lichen_csma_cad_complete(&csma, 0, false, fixed_rng, &rng, &delay) ==
	       LICHEN_CSMA_RESULT_TX_ALLOWED);
	state = snapshot(&csma);
	assert(state.phase == LICHEN_CSMA_TX_ALLOWED);
	assert(state.backoff_exponent == 0U && state.retries == 0U);
	assert(lichen_csma_tx_complete(&csma, 0) == 0);
	assert(snapshot(&csma).phase == LICHEN_CSMA_IDLE);
}

static void test_exponent_mapping_timeout_and_exhaustion(void)
{
	struct lichen_csma csma;
	struct rng_fixture rng = { .value = UINT32_C(0x80000000) };
	uint32_t delay;

	lichen_csma_init(&csma);
	assert(lichen_csma_start(&csma, 5U, fixed_rng, &rng, &delay) ==
	       LICHEN_CSMA_RESULT_BACKOFF);
	assert(delay == 160U);
	for (uint8_t retry = 1U; retry <= LICHEN_CSMA_RETRY_LIMIT; retry++) {
		assert(lichen_csma_cad_begin(&csma) == 0);
		int result = lichen_csma_cad_complete(&csma, -ETIMEDOUT, false,
						      fixed_rng, &rng, &delay);
		assert(result == LICHEN_CSMA_RESULT_CAD_TIMEOUT);
		assert(delay == 160U);
		struct lichen_csma_snapshot state = snapshot(&csma);
		assert(state.backoff_exponent == 5U && state.retries == retry);
	}
	assert(lichen_csma_cad_begin(&csma) == 0);
	assert(lichen_csma_cad_complete(&csma, 0, true, fixed_rng, &rng, &delay) ==
	       LICHEN_CSMA_RESULT_RETRY_EXHAUSTED);
	struct lichen_csma_snapshot state = snapshot(&csma);
	assert(state.phase == LICHEN_CSMA_EXHAUSTED);
	assert(state.backoff_exponent == 5U && state.retries == 4U);
}

static void test_errors_and_invalid_transitions(void)
{
	struct lichen_csma csma;
	struct rng_fixture rng = { .value = 0U };
	uint32_t delay = 0U;

	lichen_csma_init(&csma);
	assert(lichen_csma_start(&csma, 6U, fixed_rng, &rng, &delay) == -EINVAL);
	assert(lichen_csma_cad_begin(&csma) == -EPROTO);
	assert(lichen_csma_start(&csma, 0U, fixed_rng, &rng, &delay) ==
	       LICHEN_CSMA_RESULT_BACKOFF);
	assert(lichen_csma_start(&csma, 0U, fixed_rng, &rng, &delay) == -EALREADY);
	assert(lichen_csma_cad_begin(&csma) == 0);
	assert(lichen_csma_cad_complete(&csma, -EIO, false, fixed_rng, &rng, &delay) ==
	       -EIO);
	struct lichen_csma_snapshot state = snapshot(&csma);
	assert(state.phase == LICHEN_CSMA_ERROR && state.last_error == -EIO);

	assert(lichen_csma_reset(&csma) == 0);
	assert(lichen_csma_start(&csma, 0U, fixed_rng, &rng, &delay) ==
	       LICHEN_CSMA_RESULT_BACKOFF);
	assert(lichen_csma_cad_begin(&csma) == 0);
	rng.error = -EIO;
	assert(lichen_csma_cad_complete(&csma, 0, true, fixed_rng, &rng, &delay) ==
	       -EIO);
	state = snapshot(&csma);
	assert(state.phase == LICHEN_CSMA_ERROR && state.last_error == -EIO);
	assert(state.backoff_exponent == 0U && state.retries == 0U);
}

struct blocking_rng {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool entered;
	bool release;
};

struct worker_args {
	struct lichen_csma *csma;
	struct blocking_rng *rng;
	int result;
};

static int wait_rng(void *user, uint32_t *value)
{
	struct blocking_rng *rng = user;

	assert(pthread_mutex_lock(&rng->mutex) == 0);
	rng->entered = true;
	assert(pthread_cond_broadcast(&rng->cond) == 0);
	while (!rng->release) {
		assert(pthread_cond_wait(&rng->cond, &rng->mutex) == 0);
	}
	assert(pthread_mutex_unlock(&rng->mutex) == 0);
	*value = 0U;
	return 0;
}

static void *complete_busy(void *user)
{
	struct worker_args *args = user;
	uint32_t delay;

	args->result = lichen_csma_cad_complete(args->csma, 0, true, wait_rng,
						args->rng, &delay);
	return NULL;
}

static void test_concurrent_cancel(void)
{
	struct lichen_csma csma;
	struct blocking_rng rng = {
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.cond = PTHREAD_COND_INITIALIZER,
	};
	struct worker_args args = { .csma = &csma, .rng = &rng };
	uint32_t delay;
	pthread_t worker;

	lichen_csma_init(&csma);
	assert(lichen_csma_start(&csma, 0U, NULL, NULL, &delay) ==
	       LICHEN_CSMA_RESULT_BACKOFF);
	assert(lichen_csma_cad_begin(&csma) == 0);
	assert(pthread_create(&worker, NULL, complete_busy, &args) == 0);
	assert(pthread_mutex_lock(&rng.mutex) == 0);
	while (!rng.entered) {
		assert(pthread_cond_wait(&rng.cond, &rng.mutex) == 0);
	}
	assert(lichen_csma_cad_begin(&csma) == -EBUSY);
	lichen_csma_cancel(&csma);
	rng.release = true;
	assert(pthread_cond_broadcast(&rng.cond) == 0);
	assert(pthread_mutex_unlock(&rng.mutex) == 0);
	assert(pthread_join(worker, NULL) == 0);
	assert(args.result == LICHEN_CSMA_RESULT_CANCELLED);
	struct lichen_csma_snapshot state = snapshot(&csma);
	assert(state.phase == LICHEN_CSMA_CANCELLED && state.cancel_requested);
	assert(lichen_csma_reset(&csma) == 0);
	assert(snapshot(&csma).phase == LICHEN_CSMA_IDLE);
	assert(pthread_cond_destroy(&rng.cond) == 0);
	assert(pthread_mutex_destroy(&rng.mutex) == 0);
}

struct acquire_fixture {
	struct lichen_csma *csma;
	int cad_status[5];
	bool busy[5];
	size_t cad_count;
	size_t cad_index;
	uint32_t waits[5];
	size_t wait_count;
	bool cancel_on_wait;
};

static int record_wait(void *user, uint32_t delay_ms)
{
	struct acquire_fixture *fixture = user;

	assert(fixture->wait_count < 5U);
	fixture->waits[fixture->wait_count++] = delay_ms;
	if (fixture->cancel_on_wait) {
		lichen_csma_cancel(fixture->csma);
	}
	return 0;
}

static int scripted_cad(void *user, uint8_t timeout_symbols, bool *busy)
{
	struct acquire_fixture *fixture = user;

	assert(timeout_symbols == LICHEN_CSMA_CAD_TIMEOUT_SYMBOLS);
	assert(fixture->cad_index < fixture->cad_count);
	*busy = fixture->busy[fixture->cad_index];
	return fixture->cad_status[fixture->cad_index++];
}

static void test_acquire_clear_busy_timeout_error_and_cancel(void)
{
	struct lichen_csma csma;
	struct rng_fixture rng = { .value = UINT32_MAX };
	struct acquire_fixture fixture = {
		.csma = &csma,
		.cad_status = { 0, -ETIMEDOUT, 0 },
		.busy = { true, true, false },
		.cad_count = 3U,
	};

	lichen_csma_init(&csma);
	assert(lichen_csma_acquire(&csma, 0U, fixed_rng, &rng,
				   record_wait, &fixture,
				   scripted_cad, &fixture) == 0);
	assert(fixture.cad_index == 3U && fixture.wait_count == 3U);
	assert(fixture.waits[0] == 0U);
	assert(fixture.waits[1] == 10U);
	assert(fixture.waits[2] == 30U);
	assert(snapshot(&csma).phase == LICHEN_CSMA_TX_ALLOWED);
	assert(lichen_csma_tx_complete(&csma, 0) == 0);

	memset(&fixture, 0, sizeof(fixture));
	fixture.csma = &csma;
	fixture.cad_status[0] = -EIO;
	fixture.cad_count = 1U;
	assert(lichen_csma_acquire(&csma, 0U, fixed_rng, &rng,
				   record_wait, &fixture,
				   scripted_cad, &fixture) == -EIO);
	assert(snapshot(&csma).phase == LICHEN_CSMA_ERROR);

	assert(lichen_csma_reset(&csma) == 0);
	memset(&fixture, 0, sizeof(fixture));
	fixture.csma = &csma;
	fixture.cancel_on_wait = true;
	assert(lichen_csma_acquire(&csma, 0U, fixed_rng, &rng,
				   record_wait, &fixture,
				   scripted_cad, &fixture) == -ECANCELED);
	assert(fixture.cad_index == 0U);
	assert(snapshot(&csma).phase == LICHEN_CSMA_CANCELLED);
}

int main(void)
{
	test_canonical_backoff_and_clear();
	test_exponent_mapping_timeout_and_exhaustion();
	test_errors_and_invalid_transitions();
	test_concurrent_cancel();
	test_acquire_clear_busy_timeout_error_and_cancel();
	return 0;
}
