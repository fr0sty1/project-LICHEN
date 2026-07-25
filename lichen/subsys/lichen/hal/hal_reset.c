/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#if IS_ENABLED(CONFIG_HWINFO)
#include <zephyr/drivers/hwinfo.h>
#endif
#include <zephyr/kernel.h>
#if IS_ENABLED(CONFIG_REBOOT)
#include <zephyr/sys/reboot.h>
#endif
#include <zephyr/sys/util.h>

#include <lichen/hal.h>
#include "hal_internal.h"

#if IS_ENABLED(CONFIG_HWINFO)
static bool s_reset_cause_clear_proven;
#endif

#ifdef CONFIG_ZTEST
bool lichen_hal_test_reset_request_valid;
enum lichen_hal_reset_request lichen_hal_test_reset_request;
#endif

int lichen_hal_reboot_status(void)
{
	return IS_ENABLED(CONFIG_REBOOT) ? 0 : -ENOTSUP;
}

#if IS_ENABLED(CONFIG_HWINFO)
static uint32_t reset_cause_from_zephyr(uint32_t cause)
{
	uint32_t out = 0U;

	if ((cause & RESET_PIN) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_PIN;
	}
	if ((cause & RESET_SOFTWARE) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_SOFTWARE;
	}
	if ((cause & RESET_BROWNOUT) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_BROWNOUT;
	}
	if ((cause & RESET_POR) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_POWER_ON;
	}
	if ((cause & RESET_WATCHDOG) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_WATCHDOG;
	}
	if ((cause & RESET_DEBUG) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_DEBUG;
	}
	if ((cause & RESET_SECURITY) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_SECURITY;
	}
	if ((cause & RESET_LOW_POWER_WAKE) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_LOW_POWER_WAKE;
	}
	if ((cause & RESET_CPU_LOCKUP) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_CPU_LOCKUP;
	}
	if ((cause & RESET_PARITY) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_PARITY;
	}
	if ((cause & RESET_PLL) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_PLL;
	}
	if ((cause & RESET_CLOCK) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_CLOCK;
	}
	if ((cause & RESET_HARDWARE) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_HARDWARE;
	}
	if ((cause & RESET_USER) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_USER;
	}
	if ((cause & RESET_TEMPERATURE) != 0U) {
		out |= LICHEN_HAL_RESET_CAUSE_TEMPERATURE;
	}

	return out;
}
#endif

static bool valid_reset_request(enum lichen_hal_reset_request request)
{
	return request >= LICHEN_HAL_RESET_REQUEST_COLD_REBOOT &&
	       request <= LICHEN_HAL_RESET_REQUEST_FACTORY_RESET;
}

int lichen_hal_reset_request(enum lichen_hal_reset_request request)
{
	if (!valid_reset_request(request)) {
		return -EINVAL;
	}
	if (request == LICHEN_HAL_RESET_REQUEST_FACTORY_RESET) {
		return -ENOTSUP;
	}
	if (!IS_ENABLED(CONFIG_REBOOT)) {
		return -ENOTSUP;
	}

#ifdef CONFIG_ZTEST
	lichen_hal_test_reset_request = request;
	lichen_hal_test_reset_request_valid = true;
	return 0;
#else
#if IS_ENABLED(CONFIG_REBOOT)
	if (request == LICHEN_HAL_RESET_REQUEST_WARM_REBOOT) {
		sys_reboot(SYS_REBOOT_WARM);
	} else {
		sys_reboot(SYS_REBOOT_COLD);
	}

	return -EIO;
#else
	return -ENOTSUP;
#endif
#endif
}

int lichen_hal_reset_diagnostics_snapshot_get(
	struct lichen_hal_reset_diagnostics_snapshot *snapshot)
{
	if (snapshot == NULL) {
		return -EINVAL;
	}

	*snapshot = (struct lichen_hal_reset_diagnostics_snapshot){ 0 };
	snapshot->reboot_supported = lichen_hal_reboot_status() == 0;
	snapshot->warm_reboot_best_effort = snapshot->reboot_supported;

#if IS_ENABLED(CONFIG_HWINFO)
	uint32_t reset_cause = 0U;
	uint32_t supported_reset_cause = 0U;
	int ret;

	ret = hwinfo_get_supported_reset_cause(&supported_reset_cause);
	if (ret == 0) {
		snapshot->reset_cause_supported = true;
		snapshot->supported_reset_cause_valid = true;
		snapshot->supported_reset_cause =
			reset_cause_from_zephyr(supported_reset_cause);
		snapshot->supported_reset_cause_raw_valid = true;
		snapshot->supported_reset_cause_raw = supported_reset_cause;
	}

	ret = hwinfo_get_reset_cause(&reset_cause);
	if (ret == 0) {
		snapshot->reset_cause_supported = true;
		snapshot->reset_cause_valid = true;
		snapshot->reset_cause = reset_cause_from_zephyr(reset_cause);
		snapshot->reset_cause_raw_valid = true;
		snapshot->reset_cause_raw = reset_cause;
	}

	/*
	 * Prove backend clear support: data is already captured in the
	 * snapshot above, so a single clear attempt is safe. Once proven,
	 * subsequent calls to lichen_hal_reset_diagnostics_clear() use
	 * the real backend instead of returning -ENOTSUP.
	 */
	if (!s_reset_cause_clear_proven) {
		s_reset_cause_clear_proven =
			(hwinfo_clear_reset_cause() == 0);
	}
	snapshot->reset_cause_clear_supported = s_reset_cause_clear_proven;
#endif

	return 0;
}

int lichen_hal_reset_diagnostics_clear(void)
{
#if IS_ENABLED(CONFIG_HWINFO)
	if (s_reset_cause_clear_proven) {
		return hwinfo_clear_reset_cause();
	}
#endif
	return -ENOTSUP;
}

#ifdef CONFIG_ZTEST
bool lichen_hal_reset_test_last_request_valid(void)
{
	return lichen_hal_test_reset_request_valid;
}

enum lichen_hal_reset_request lichen_hal_reset_test_last_request(void)
{
	return lichen_hal_test_reset_request;
}

void lichen_hal_reset_test_clear_request(void)
{
	lichen_hal_test_reset_request_valid = false;
	lichen_hal_test_reset_request = LICHEN_HAL_RESET_REQUEST_COLD_REBOOT;
}
#endif
