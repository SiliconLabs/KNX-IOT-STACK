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

#include "oc_assert.h"
#include <openthread/random_crypto.h>

void oc_random_init(void)
{
    // Intentionally empty
}

unsigned int oc_random_value(void)
{
    unsigned int randomValue;
    otError      error = OT_ERROR_NONE;

    error = otRandomCryptoFillBuffer((uint8_t *)&randomValue, sizeof(randomValue));
    oc_assert(error == OT_ERROR_NONE);

    return randomValue;
}

void oc_random_destroy(void)
{
    // Intentionally empty
}
