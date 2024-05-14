/*******************************************************************************
 * @file
 * @brief Common application KNX functions.
 *******************************************************************************
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

#include "app.h"
#include <stddef.h>

#include "oc_api.h"
#include "oc_helpers.h"
#include "oc_log.h"
#include "oc_ri.h"
#include "api/oc_knx_dev.h"

/**
 * @brief initiate preset for device
 * current implementation: device reset as command line argument
 * @param device_index the device identifier of the list of devices
 * @param data the supplied data.
 */
void factory_presets_cb(size_t device_index, void *data)
{
    (void)data;

    if (g_reset)
    {
        PRINT("factory_presets_cb: resetting device\n");
        oc_knx_device_storage_reset(device_index, 2);
    }
}

/**
 * @brief application reset
 *
 * @param device_index the device identifier of the list of devices
 * @param reset_value the knx reset value
 * @param data the supplied data.
 */
void reset_cb(size_t device_index, int reset_value, void *data)
{
    (void)device_index;
    (void)data;

    PRINT("reset_cb %d\n", reset_value);
}

/**
 * @brief restart the device (application depended)
 *
 * @param device_index the device identifier of the list of devices
 * @param data the supplied data.
 */
void restart_cb(size_t device_index, void *data)
{
    (void)device_index;
    (void)data;

    PRINT("-----restart_cb -------\n");
    // TODO: Restart the device using NVIC restart
    // exit(0);
}

/**
 * @brief set the host name on the device (application depended)
 *
 * @param device_index the device identifier of the list of devices
 * @param host_name the host name to be set on the device
 * @param data the supplied data.
 */
void hostname_cb(size_t device_index, oc_string_t host_name, void *data)
{
    (void)device_index;
    (void)data;

    PRINT("-----host name ------- %s\n", oc_string_checked(host_name));
}

static oc_event_callback_retval_t send_delayed_response(void *context)
{
    oc_separate_response_t *response = (oc_separate_response_t *)context;

    if (response->active)
    {
        oc_set_separate_response_buffer(response);
        oc_send_separate_response(response, OC_STATUS_CHANGED);
        PRINT("Delayed response sent\n");
    }
    else
    {
        PRINT("Delayed response NOT active\n");
    }

    return OC_EVENT_DONE;
}
