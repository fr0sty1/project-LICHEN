#include "crash_info.h"
#include <stdbool.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(crash_info, LOG_LEVEL_INF);

#define CRASH_MAGIC 0xDEAD0001

/* BSS flag tracks whether __noinit crash_info has been checked this boot.
 * BSS is zero-initialized by the C runtime, so this is 0 on every power-on
 * or warm reset, avoiding any read of uninitialized __noinit memory. */
static bool crash_retain_checked;

/* Retained RAM section - survives warm reset but not power cycle */
__noinit static struct {
    uint32_t magic;
    uint32_t reason;
    uint32_t location;
    uint32_t extra;
    uint32_t count;
} crash_info;

void crash_info_store(enum crash_reason reason, uint32_t location, uint32_t extra)
{
    /*
     * DESIGN: No mutex protection is intentional.
     *
     * This function is called from error paths (including CRASH_MUTEX_FAILURE)
     * where the system may be in an unstable state. Taking a mutex here could:
     * - Deadlock if the mutex itself is corrupted
     * - Deadlock if we're in ISR context or scheduler is broken
     * - Delay crash recording when we need it most
     *
     * The 32-bit writes to retained RAM are atomic on Cortex-M, and a torn
     * write during concurrent crashes is acceptable - we'd still capture
     * evidence that something crashed.
     */

    /* If magic invalid, this is first crash since power cycle - init count */
    if (!crash_retain_checked || crash_info.magic != CRASH_MAGIC) {
        crash_info.magic = CRASH_MAGIC;
        crash_info.count = 0;
    }
    crash_retain_checked = true;
    crash_info.magic = CRASH_MAGIC;
    crash_info.reason = reason;
    crash_info.location = location;
    crash_info.extra = extra;
    if (crash_info.count < UINT32_MAX) {
        crash_info.count++;
    }
    LOG_ERR("crash_info: stored (reason=%u, loc=%u, extra=%u)", reason, location, extra);
    /* Don't reset here - let watchdog do it, or caller returns error */
}

void crash_info_check_and_clear(void)
{
    if (crash_retain_checked && crash_info.magic == CRASH_MAGIC) {
        if (crash_info.reason <= CRASH_UNKNOWN) {
            LOG_WRN("crash_info: previous crash (reason=%u, loc=%u, extra=%u, count=%u)",
                    crash_info.reason, crash_info.location, crash_info.extra, crash_info.count);
        } else {
            LOG_WRN("crash_info: corrupt retained crash info "
                    "(raw_reason=%u, raw_loc=%u, raw_extra=%u, raw_count=%u)",
                    crash_info.reason, crash_info.location, crash_info.extra, crash_info.count);
        }
        /* Clear crash details after logging. Count is preserved for lifetime
         * tracking - it accumulates across warm resets until power cycle. */
        crash_info.magic = 0;
        crash_info.reason = CRASH_NONE;
        crash_info.location = 0;
        crash_info.extra = 0;
    } else {
        /* First boot or power cycle: __noinit RAM contains garbage.
         * The retain-checked guard ensures we never compare __noinit
         * memory that may be uninitialized — BSS is zeroed by the C
         * runtime, so crash_retain_checked starts as false. */
        crash_info.magic = 0;
        crash_info.count = 0;
    }
    crash_retain_checked = true;
}
