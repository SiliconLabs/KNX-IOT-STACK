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

#include "dns-sd.h"

int knx_publish_service(char *serial_no, uint64_t iid, uint32_t ia, bool pm)
{
    (void)serial_no;
    (void)iid;
    (void)ia;
    (void)pm;

    return 0;
}

void knx_service_sleep_period(uint32_t sp)
{
    (void)sp;
}
