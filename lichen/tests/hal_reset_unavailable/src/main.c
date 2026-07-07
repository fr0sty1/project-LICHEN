/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>

#include <zephyr/sys/printk.h>

#include <lichen/hal.h>

static int expect_unsupported(const char *what, int ret)
{
	if (ret != -ENOTSUP) {
		printk("%s returned %d\n", what, ret);
		return 1;
	}

	return 0;
}

int main(void)
{
	struct lichen_hal_reset_diagnostics_snapshot snapshot = { 0 };

	if (IS_ENABLED(CONFIG_REBOOT)) {
		printk("CONFIG_REBOOT unexpectedly enabled\n");
		return 1;
	}

	if (expect_unsupported("lichen_hal_reboot_status",
			       lichen_hal_reboot_status()) != 0) {
		return 1;
	}
	if (expect_unsupported("cold reboot",
			       lichen_hal_reset_request(
				       LICHEN_HAL_RESET_REQUEST_COLD_REBOOT)) != 0) {
		return 1;
	}
	if (expect_unsupported("warm reboot",
			       lichen_hal_reset_request(
				       LICHEN_HAL_RESET_REQUEST_WARM_REBOOT)) != 0) {
		return 1;
	}
	if (expect_unsupported("factory reset",
			       lichen_hal_reset_request(
				       LICHEN_HAL_RESET_REQUEST_FACTORY_RESET)) != 0) {
		return 1;
	}
	if (expect_unsupported("reset diagnostics clear",
			       lichen_hal_reset_diagnostics_clear()) != 0) {
		return 1;
	}
	if (lichen_hal_reset_diagnostics_snapshot_get(&snapshot) != 0) {
		printk("reset diagnostics snapshot failed\n");
		return 1;
	}
	if (snapshot.reboot_supported || snapshot.warm_reboot_best_effort ||
	    snapshot.factory_reset_supported ||
	    snapshot.reset_cause_clear_supported ||
	    snapshot.retained_diagnostics_supported ||
	    snapshot.retained_crash_valid) {
		printk("unsupported reset fields were advertised\n");
		return 1;
	}

	printk("HAL reset unavailable PASS\n");
	return 0;
}
