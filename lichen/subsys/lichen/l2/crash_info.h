#ifndef LICHEN_CRASH_INFO_H
#define LICHEN_CRASH_INFO_H

#include <stdint.h>

/* Crash reason codes */
enum crash_reason {
    CRASH_NONE = 0,
    CRASH_DRIVER_OVERFLOW,
    CRASH_STATE_CORRUPTION,
    CRASH_MUTEX_FAILURE,
    CRASH_UNKNOWN,
};

/* Store crash info in retained RAM and prepare for watchdog reset */
void crash_info_store(enum crash_reason reason, uint32_t location, uint32_t extra);

/* Check and log any crash info from previous boot, then clear it */
void crash_info_check_and_clear(void);

#endif
