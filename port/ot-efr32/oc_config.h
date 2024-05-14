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

#ifndef OC_CONFIG_H
#define OC_CONFIG_H

/* Time resolution */
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#define oc_success_or_exit(status) \
    do                             \
    {                              \
        if ((status) != 0)         \
        {                          \
            goto exit;             \
        }                          \
    } while (false)

#define oc_verify_or_exit(condition, action) \
    do                                       \
    {                                        \
        if (!(condition))                    \
        {                                    \
            action;                          \
            goto exit;                       \
        }                                    \
    } while (0)

typedef uint64_t oc_clock_time_t;
/* Sets one clock tick to 1 ms */
#define OC_CLOCK_CONF_TICKS_PER_SECOND 1000

/* Security Layer */
/* Max inactivity timeout before tearing down DTLS connection */
#define OC_DTLS_INACTIVITY_TIMEOUT (600)

/* Maximum wait time for select function */
#define SELECT_TIMEOUT_SEC (1)

/* Add support for passing network up/down events to the application */
#define OC_NETWORK_MONITOR

/* Add support for passing TCP/TLS/DTLS session connection events to the
 * application */
#define OC_SESSION_EVENTS

/* Add request history for deduplicate UDP/DTLS messages */
#define OC_REQUEST_HISTORY

/* Add support for dns lookup to the endpoint */
#define OC_DNS_LOOKUP
#define OC_DNS_CACHE
#define OC_MAX_DNS_CACHE_ENTRIES 20
#define OC_DNS_LOOKUP_IPV6

/* If we selected support for dynamic memory allocation */
#ifdef OC_DYNAMIC_ALLOCATION
#define OC_BLOCK_WISE

// The maximum size of a response to an OBSERVE request, in bytes
#define OC_MAX_OBSERVE_SIZE 512

#else /* OC_DYNAMIC_ALLOCATION */
/* List of constraints below for a build that does not employ dynamic
   memory allocation
*/
/* Memory pool sizes */
#define OC_BYTES_POOL_SIZE (1800)
#define OC_INTS_POOL_SIZE (100)
#define OC_DOUBLES_POOL_SIZE (4)

/* Server-side parameters */
/* Maximum number of server resources */
#define OC_MAX_APP_RESOURCES (4)

#define OC_MAX_NUM_COLLECTIONS (1)

/* Common parameters */
/* Prescriptive lower layers MTU size, enable block-wise transfers */
#define OC_BLOCK_WISE_SET_MTU (700)

/* Maximum size of request/response payloads */
#define OC_MAX_APP_DATA_SIZE (2048)

/* Maximum number of concurrent requests */
/* #define OC_MAX_NUM_CONCURRENT_REQUESTS (5) */
#define OC_MAX_NUM_CONCURRENT_REQUESTS (20)

/* Maximum number of nodes in a payload tree structure */
#define OC_MAX_NUM_REP_OBJECTS (150)

/* Number of devices on the platform */
#define OC_MAX_NUM_DEVICES (1)

/* Maximum number of endpoints */
#define OC_MAX_NUM_ENDPOINTS (20)

/* Security layer */
/* Maximum number of authorized clients */
#define OC_MAX_NUM_SUBJECTS (2)

/* Maximum number of concurrent (D)TLS sessions */
#define OC_MAX_TLS_PEERS (1)

/* Maximum number of peer for TCP channel */
#define OC_MAX_TCP_PEERS (2)

#endif /* !OC_DYNAMIC_ALLOCATION */

/* Maximum number of interfaces for IP adapter */
#define OC_MAX_IP_INTERFACES (3)

/* Maximum number of callbacks for Network interface event monitoring */
#define OC_MAX_NETWORK_INTERFACE_CBS (4)

/* Maximum number of callbacks for connection of session */
#define OC_MAX_SESSION_EVENT_CBS (2)

/* library features that require persistent storage */
#ifdef OC_SECURITY
#define OC_STORAGE
#endif
#define OC_STORAGE

/* Maximum number of storage files (aka keys for embedded devices) */
#define OC_STORAGE_MAX_FILES 512
/* Maximum name length of a storage file */
#define OC_STORAGE_MAX_FILENAME_LENGTH (32)

#ifdef __cplusplus
}
#endif

#endif /* OC_CONFIG_H */
