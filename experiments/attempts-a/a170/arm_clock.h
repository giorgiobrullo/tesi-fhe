#ifndef A170_ARM_CLOCK_H
#define A170_ARM_CLOCK_H
#include <mach/mach_time.h>
#include <stdint.h>
/* Future paired executor: initialize timebase before timing, call this exact
 * clock immediately around each full endpoint, save raw ticks after the pair.
 * Do not substitute process-local Instant offsets or use UTC for durations.
 * This function neither writes nor samples CPU nor converts to floating point. */
static inline uint64_t a170_arm_clock(void) { return mach_absolute_time(); }
#endif
