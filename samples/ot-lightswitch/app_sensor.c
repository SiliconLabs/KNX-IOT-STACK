/*******************************************************************************
 * @file
 * @brief Sensor application logic
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

// OpenThread Includes
#include <openthread-core-config.h>
#include <openthread-system.h>
#include <openthread/config.h>
#include <openthread/ip6.h>
#include <openthread/tasklet.h>
#include <openthread/thread.h>

// KNX Includes
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_log.h"
#include "oc_rep.h"
#include "api/oc_knx_fp.h"
#ifdef OC_SPAKE
#include "security/oc_spake2plus.h"
#endif

// Other Includes
#include "app.h"
#include "platform-efr32.h"
#include <stddef.h>

#if defined(SL_COMPONENT_CATALOG_PRESENT)
#include "sl_component_catalog.h"
#endif

#if defined(SL_CATALOG_SIMPLE_BUTTON_PRESENT)
#include "sl_button.h"
#include "sl_simple_button.h"
#endif

/******************************************************************************
 * Global variables
 *****************************************************************************/
static bool g_mystate      = false; /**< the state of the dpa 417.61 */
bool        g_reset        = false; /**< reset the device (from startup) */
static bool sButtonPressed = false;

/******************************************************************************
 * Forward declarations
 *****************************************************************************/
static void oc_add_s_mode_response_cb(char *url, oc_rep_t *rep, oc_rep_t *rep_value);
void        app_knx_init(void);
void        applicationTick(void);

/******************************************************************************
 * Application Init.
 *****************************************************************************/
void app_init(void)
{
    // TODO: Is this needed?
    // OT_SETUP_RESET_JUMP(argv);

    setNetworkConfiguration();
    assert(otIp6SetEnabled(otGetInstance(), true) == OT_ERROR_NONE);
    assert(otThreadSetEnabled(otGetInstance(), true) == OT_ERROR_NONE);

    efr32PrintResetInfo();

    PRINT("OpenThread stack initialized\n");
    PRINT("Waiting for network attach before starting the KNX stack...\n");
    PRINT("> ");
}

/**
 *  @brief function to set up the device.
 *
 * sets the:
 * - serial number
 * - base path
 * - knx spec version
 * - hardware version
 * - firmware version
 * - hardware type
 * - device model
 *
 */
#define MY_NAME "Sensor (LSSB) 421.61" /**< The name of the application */

int app_knx_init_device_info(void)
{
    // Set the manufacturer name
    int ret = oc_init_platform("Silicon Labs", NULL, NULL);

    // Set the application name, version, base url, device serial number
    ret |= oc_add_device(MY_NAME, "1.0.0", "//", "0000DEADBEEF", NULL, NULL);

    oc_device_info_t *device = oc_core_get_device_info(0);
    PRINT("Serial Number: %s\n", oc_string_checked(device->serialnumber));

    // Set the hardware version
    oc_core_set_device_hwv(0, 1, 0, 0);

    // Set the firmware version
    oc_core_set_device_fwv(0, 1, 0, 0);

    // Set the hardware type
    oc_core_set_device_hwt(0, "EFR32");

    // Set the application info
    oc_core_set_device_ap(0, 1, 0, 0);

    // Set the manufacturer info
    // TODO: Change the manufacturer ID once Silicon Labs has one
    oc_core_set_device_mid(0, 343);

    // Set the model
    oc_core_set_device_model(0, "EFR32 Actuator");

    // Set the installation id
    oc_core_set_device_iid(0, 0x1234);

    oc_set_s_mode_response_cb(oc_add_s_mode_response_cb);

#ifdef OC_SPAKE
#define PASSWORD "LETTUCE"
    oc_spake_set_password(PASSWORD);
    PRINT(" SPAKE password %s\n", PASSWORD);
#endif
}

/******************************************************************************
 * Application Process Action.
 *****************************************************************************/
void app_process_action(void)
{
    otTaskletsProcess(otGetInstance());
    otSysProcessDrivers(otGetInstance());

    applicationTick();
}

void applicationTick(void)
{
    // Check for button press
    if (sButtonPressed)
    {
        sButtonPressed = false;

#ifdef OC_USE_MULTICAST_SCOPE_2
        oc_do_s_mode_with_scope_no_check(2, "/p/o_1_1", "w");
#else
        oc_do_s_mode_with_scope_no_check(5, "/p/o_1_1", "w");
#endif
    }

    // Handle the next KNX event
    oc_clock_time_t next_event;
    next_event = oc_main_poll();
}

/******************************************************************************
 * Application Exit.
 *****************************************************************************/
void app_exit(void)
{
    /* shut down the stack */
    oc_main_shutdown();

    otInstanceFinalize(otGetInstance());
#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    free(otInstanceBuffer);
#endif

    // TODO : pseudo reset?
}
/******************************************************************************
 * Button Functions
 *****************************************************************************/
#if defined(SL_CATALOG_SIMPLE_BUTTON_PRESENT)
void sl_button_on_change(const sl_button_t *handle)
{
    if (sl_button_get_state(handle) == SL_SIMPLE_BUTTON_PRESSED)
    {
        sButtonPressed = true;
        g_mystate      = !g_mystate;
        otSysEventSignalPending();
    }
}
#endif

/******************************************************************************
 * KNX Functions
 *****************************************************************************/
/**
 * @brief Example device implementing Function Block LSSB
 * @file
 *  Example code for Function Block LSSB
 *  Implements only data point 61: switch on/off
 *  This implementation is a sensor, e.g. transmits data
 *
 * ## Application Design
 *
 * Support functions:
 *
 * - app_init:
 *   - initializes the stack values.
 * - register_resources:
 *   - function that registers all endpoints,
 *   - sets the GET/PUT/POST/DELETE handlers for each end point
 *
 * - main:
 *   - starts the stack, with the registered resources.
 *   - can be compiled out with NO_MAIN
 *
 *  handlers for the implemented methods (get/post):
 *   - get_[path]:
 *     - function that is being called when a GET is called on [path]
 *     - set the global variables in the output
 *   - post_[path]:
 *     - function that is being called when a POST is called on [path]
 *     - checks the input data
 *     - if input data is correct
 *       - updates the global variables
 */

/**
 * @brief s-mode response callback
 * will be called when a response is received on an s-mode read request
 *
 * @param url the url
 * @param rep the full response
 * @param rep_value the parsed value of the response
 */
static void oc_add_s_mode_response_cb(char *url, oc_rep_t *rep, oc_rep_t *rep_value)
{
    (void)rep;
    (void)rep_value;

    PRINT("oc_add_s_mode_response_cb %s\n", url);
}

/**
 * @brief GET method for "p/o_1_1" resource.
 *
 * This function is called to initialize the return values of the GET method.
 * Initialization of the returned values are done from the global property
 * values.
 *
 * Resource Description: This Resource describes a binary switch (on/off).
 *
 * The Property "value" is a boolean.
 * A value of 'true' means that the switch is on.
 * A value of 'false' means that the switch is off.
 *
 * @param request the request representation.
 * @param interfaces the interface used for this call
 * @param user_data the user data.
 */
static void get_o_1_1(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
    (void)user_data; // variable not used

    bool error_state    = false; /* the error state, the generated code */
    int  oc_status_code = OC_STATUS_OK;

    OC_DBG("-- Begin get_dpa_421_61: interface %d\n", interfaces);

    // Check if the accept header is CBOR
    if (oc_check_accept_header(request, APPLICATION_CBOR) == false)
    {
        oc_send_response_no_format(request, OC_STATUS_BAD_OPTION);
        return;
    }

    // Check the query parameter m with the various values
    char  *m;
    char  *m_key;
    size_t m_key_len;
    size_t m_len = oc_get_query_value(request, "m", &m);
    if (m_len != -1)
    {
        OC_DBG("  Query param: %.*s", (int)m_len, m);
        oc_init_query_iterator();
        size_t            device_index = request->resource->device;
        oc_device_info_t *device       = oc_core_get_device_info(device_index);
        if (device != NULL)
        {
            oc_rep_begin_root_object();
            while (oc_iterate_query(request, &m_key, &m_key_len, &m, &m_len) != -1)
            {
                // unique identifier
                if ((strncmp(m, "id", m_len) == 0) | (strncmp(m, "*", m_len) == 0))
                {
                    char mystring[100];
                    snprintf(mystring,
                             99,
                             "urn:knx:sn:%s%s",
                             oc_string(device->serialnumber),
                             oc_string(request->resource->uri));
                    oc_rep_i_set_text_string(root, 0, mystring);
                }
                // resource types
                if ((strncmp(m, "rt", m_len) == 0) | (strncmp(m, "*", m_len) == 0))
                {
                    oc_rep_set_text_string(root, rt, "urn:knx:dpa.421.61");
                }
                // interfaces
                if ((strncmp(m, "if", m_len) == 0) | (strncmp(m, "*", m_len) == 0))
                {
                    oc_rep_set_text_string(root, if, "if.s");
                }
                if ((strncmp(m, "dpt", m_len) == 0) | (strncmp(m, "*", m_len) == 0))
                {
                    oc_rep_set_text_string(root, dpt, oc_string(request->resource->dpt));
                }
                // ga
                if ((strncmp(m, "ga", m_len) == 0) | (strncmp(m, "*", m_len) == 0))
                {
                    int index = oc_core_find_group_object_table_url(oc_string(request->resource->uri));
                    if (index > -1)
                    {
                        oc_group_object_table_t *got_table_entry = oc_core_get_group_object_table_entry(index);
                        if (got_table_entry)
                        {
                            oc_rep_set_int_array(root, ga, got_table_entry->ga, got_table_entry->ga_len);
                        }
                    }
                }
            } /* query iterator */
            oc_rep_end_root_object();
        }
        else
        {
            /* device is NULL */
            oc_send_response_no_format(request, OC_STATUS_BAD_OPTION);
        }
        oc_send_cbor_response(request, OC_STATUS_OK);
        return;
    }

    CborError error;
    oc_rep_begin_root_object();
    oc_rep_i_set_boolean(root, 1, g_mystate);
    oc_rep_end_root_object();
    error = g_err;

    if (error)
    {
        oc_status_code = true;
    }
    OC_DBG("CBOR encoder size %d\n", oc_rep_get_encoded_payload_size());

    if (error_state == false)
    {
        oc_send_cbor_response(request, oc_status_code);
    }
    else
    {
        oc_send_response_no_format(request, OC_STATUS_BAD_OPTION);
    }
    OC_DBG("-- End get_dpa_421_61\n");
}

/**
 * @brief register all the resources to the stack
 *
 * This function registers all application level resources:
 * - each resource path is bound to a specific function for the supported methods (GET, POST, PUT, DELETE)
 * - each resource is:
 *   - secure
 *   - observable
 *   - discoverable
 *   - used interfaces
 *
 * URL Table
 * | resource url |  functional block/dpa  | GET | PUT  |
 * | ------------ | ---------------------- | ----| ---- |
 * | p/o_1_1      | urn:knx:dpa.421.61     | Yes | No   |
 */
void register_resources(void)
{
    PRINT("Register Resource with local path \"/p/o_1_1\"\n");
    PRINT("Light Switching Sensor 421.61 (LSSB) : SwitchOnOff \n");
    PRINT("Data point 421.61 (DPT_Switch) \n");
    PRINT("Register Resource with local path \"/p/o_1_1\"\n");

    oc_resource_t *res_pushbutton = oc_new_resource("push button", "/p/o_1_1", 2, 0);
    oc_resource_bind_resource_type(res_pushbutton, "urn:knx:dpa.421.61");
    oc_resource_bind_dpt(res_pushbutton, "urn:knx:dpt.Switch");
    oc_resource_bind_content_type(res_pushbutton, APPLICATION_CBOR);
    oc_resource_bind_resource_interface(res_pushbutton, OC_IF_S); /* if.s */
    oc_resource_set_discoverable(res_pushbutton, true);

    /* periodic observable
      to be used when one wants to send an event per time slice
      period is 1 second */
    // oc_resource_set_periodic_observable(res_pushbutton, 1);

    /* set observable
      events are send when oc_notify_observers(oc_resource_t *resource) is
      called. this function must be called when the value changes, preferable on
      an interrupt when something is read from the hardware. */
    // oc_resource_set_observable(res_pushbutton, true);

    // Set the GET handler
    oc_resource_set_request_handler(res_pushbutton, OC_GET, get_o_1_1, NULL);

    // Register this resource
    // This means that the resource will be listed in /.well-known/core
    oc_add_resource(res_pushbutton);
}

/**
 * @brief Initializes global variables
 */
void initialize_variables(void)
{
    // Intentionally empty
}

/**
 * @brief signal the event loop (efr32)
 * wakes up the main function to handle the next callback
 */
static void signal_event_loop(void)
{
    // TODO: I don't know if this is necessary
}

/**
 *  @brief send a multicast s-mode message
 */
static void issue_requests_s_mode(void)
{
    PRINT("issue_requests_s_mode: Demo \n\n");

    oc_do_s_mode_with_scope(2, "p/o_1_1", "w");
    oc_do_s_mode_with_scope(5, "p/o_1_1", "w");
}

/**
 * @brief Initialize the KNX stack
 *
 * - Initializes the global variables
 * - Registers and starts the handler
 */
void app_knx_init(void)
{
    int             init;
    oc_clock_time_t next_event;

    PRINT("KNX-IOT Server name : \"%s\"\n", MY_NAME);

    // Initialize the storage
    const char *filename = "./LSSB_minimal_creds";
    OC_DBG("\tStorage at '%s' \n", filename);
    oc_storage_config(filename);

    // Initialize the global variables
    initialize_variables();

    // Initializes the handlers structure
    static const oc_handler_t handler = {.init               = app_knx_init_device_info,
                                         .signal_event_loop  = signal_event_loop,
                                         .register_resources = register_resources,
                                         .requests_entry     = issue_requests_s_mode};

    // Set the application callbacks
    oc_set_hostname_cb(hostname_cb, NULL);
    oc_set_reset_cb(reset_cb, NULL);
    oc_set_restart_cb(restart_cb, NULL);
    oc_set_factory_presets_cb(factory_presets_cb, NULL);

    // Start the stack
    init = oc_main_init(&handler);
    oc_a_lsm_set_state(0, LSM_S_LOADED);

    if (init < 0)
    {
        OC_ERR("oc_main_init failed %d, exiting.\n", init);
        assert(1);
    }
#ifdef OC_OSCORE
    PRINT("OSCORE - Enabled\n");
#else
    PRINT("OSCORE - Disabled\n");
#endif /* OC_OSCORE */

    oc_device_info_t *device = oc_core_get_device_info(0);
    PRINT("Serial Number: %s\n", oc_string_checked(device->serialnumber));

    // Print all endpoints
    oc_endpoint_t *my_ep = oc_connectivity_get_endpoints(0);
    while (my_ep != NULL)
    {
        PRINTipaddr(*my_ep);
        PRINT("\n");
        my_ep = my_ep->next;
    }

    PRINT("Server \"%s\" running, waiting on incoming "
          "connections.\n",
          MY_NAME);
    PRINT("> ");

    return;
}
