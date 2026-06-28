#include "crash_info.h"
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(crash_info, LOG_LEVEL_INF);

#define CRASH_MAGIC 0xDEAD0001

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
    if (crash_info.magic == CRASH_MAGIC) {
        LOG_WRN("crash_info: previous crash (reason=%u, loc=%u, extra=%u, count=%u)",
                crash_info.reason, crash_info.location, crash_info.extra, crash_info.count);
        /* Clear magic but keep count for lifetime tracking */
        crash_info.magic = 0;
        crash_info.reason = CRASH_NONE;
    }
}
