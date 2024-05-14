/*******************************************************************************
 * # License
 * <b>Copyright 2024 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * License: MSLA
 *
 * The licensor of this software is Silicon Laboratories Inc.
 *
 * Your use of this software is governed by the terms of Silicon Labs Master
 * Software License Agreement (MSLA) available at
 *
 * https://www.silabs.com/about-us/legal/master-software-license-agreement
 *
 * This software is distributed to you in Source Code format and is governed by
 * the sections of the MSLA applicable to Source Code.
 *
 * By installing, copying or otherwise using this software, you agree to the
 * terms of the MSLA.
 *
 ******************************************************************************/

#include "port/oc_assert.h"
#include "port/oc_clock.h"

#include "sl_sleeptimer.h"

void oc_clock_init(void)
{
    sl_status_t status = sl_sleeptimer_init();
    oc_assert(status == SL_STATUS_OK);
}

oc_clock_time_t oc_clock_time(void)
{
    return sl_sleeptimer_get_tick_count64();
}

unsigned long oc_clock_seconds(void)
{
    return (unsigned long)(oc_clock_time() / OC_CLOCK_SECOND);
}

void oc_clock_wait(oc_clock_time_t ticks)
{
    sl_status_t status;
    uint64_t    milliseconds;

    status = sl_sleeptimer_tick64_to_ms(ticks, &milliseconds);
    oc_assert(status == SL_STATUS_OK);

    // Since we should only delay for a short period of time and the
    // delay function takes a uint16_t ensure that the delay value
    // passed in to this function is not too large.
    oc_assert(milliseconds <= 0xFFFF);
    sl_sleeptimer_delay_millisecond((uint16_t)milliseconds);
}
