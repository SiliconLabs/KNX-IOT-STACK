/*******************************************************************************
 * @file
 * @brief Application interface provided to main().
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

#ifndef APP_H
#define APP_H
#include "oc_helpers.h"
#include <stdbool.h>
#include <openthread/instance.h>

/******************************************************************************
 * Global variables
 *****************************************************************************/
extern bool g_reset;

/******************************************************************************
 * Application Init.
 *****************************************************************************/
void app_init(void);
void app_knx_init(void);

/******************************************************************************
 * Application Exit.
 *****************************************************************************/
void app_exit(void);

/******************************************************************************
 * Application Process Action.
 *****************************************************************************/
void app_process_action(void);

/******************************************************************************
 * Application Callacks
 *****************************************************************************/
void factory_presets_cb(size_t device_index, void *data);
void reset_cb(size_t device_index, int reset_value, void *data);
void restart_cb(size_t device_index, void *data);
void hostname_cb(size_t device_index, oc_string_t host_name, void *data);

/******************************************************************************
 * Other functions
 *****************************************************************************/
otInstance *otGetInstance(void);
void        setNetworkConfiguration(void);

#endif
