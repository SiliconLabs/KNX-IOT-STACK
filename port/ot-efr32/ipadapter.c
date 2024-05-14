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

#include "oc_buffer.h"
#include "oc_connectivity.h"
#include "oc_endpoint.h"
#include "oc_log.h"

#include <stdio.h>

#include "openthread/coap.h"
#include "openthread/dns_client.h"
#include "openthread/error.h"
#include "openthread/instance.h"
#include "openthread/ip6.h"
#include "openthread/message.h"
#include "openthread/udp.h"

#if defined(SL_CATALOG_KERNEL_PRESENT)
#include "cmsis_os2.h"
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

extern otInstance *otGetInstance(void);

static otUdpSocket udpSocket               = {0};
static uint32_t    otCoapPort              = OT_DEFAULT_COAP_PORT;
static bool        connectivityInitialized = false;
static size_t      ocDevice                = 0;

OC_LIST(device_eps_list);
OC_MEMB(device_eps, oc_endpoint_t, 8 * OC_MAX_NUM_DEVICES);

#ifdef OC_NETWORK_MONITOR
OC_LIST(network_interface_cb_list);
OC_MEMB(network_interface_cb_s, oc_network_interface_cb_t, OC_MAX_NETWORK_INTERFACE_CBS);
#endif // OC_NETWORK_MONITOR

#ifdef OC_SESSION_EVENTS
OC_LIST(session_event_cb_list);
OC_MEMB(session_event_cb_s, oc_session_event_cb_t, OC_MAX_SESSION_EVENT_CBS);
#endif // OC_SESSION_EVENTS

#if defined(SL_CATALOG_KERNEL_PRESENT)
static osMutexId_t         network_event_handler_mutex;
static const osMutexAttr_t network_event_handler_mutex_attributes = {
    .name      = "KNX Network Event Handler Mutex",
    .attr_bits = osMutexRecursive | osMutexPrioInherit,
};

#ifdef OC_NETWORK_MONITOR
static osMutexId_t         network_interface_cb_mutex;
static const osMutexAttr_t network_interface_cb_mutex_attributes = {
    .name      = "KNX Network Interface CB Mutex",
    .attr_bits = osMutexRecursive | osMutexPrioInherit,
};
#endif // OC_NETWORK_MONITOR

#ifdef OC_SESSION_EVENTS
static osMutexId_t         session_event_cb_mutex;
static const osMutexAttr_t session_event_cb_mutex_attributes = {
    .name      = "KNX Session Event CB Mutex",
    .attr_bits = osMutexRecursive | osMutexPrioInherit,
};
#endif // OC_SESSION_EVENTS
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

static void free_endpoints_list(void);

int oc_send_buffer(oc_message_t *message)
{
    otMessage    *udpMessage = NULL;
    otInstance   *instance   = otGetInstance();
    otError       error      = OT_ERROR_NONE;
    otMessageInfo udpMessageInfo;

    udpMessage = otUdpNewMessage(instance, NULL);
    oc_verify_or_exit(udpMessage != NULL, error = OT_ERROR_NO_BUFS);

    oc_success_or_exit(error = otMessageAppend(udpMessage, message->data, message->length));

    memset(&udpMessageInfo, 0, sizeof(udpMessageInfo));
    _Static_assert(sizeof(message->endpoint.addr.ipv6.address) <= sizeof(udpMessageInfo.mPeerAddr));
    memcpy(&udpMessageInfo.mPeerAddr, message->endpoint.addr.ipv6.address, sizeof(message->endpoint.addr.ipv6.address));
    udpMessageInfo.mSockPort = udpSocket.mSockName.mPort;
    udpMessageInfo.mPeerPort = message->endpoint.addr.ipv6.port;

    oc_success_or_exit(error = otUdpSend(instance, &udpSocket, udpMessage, &udpMessageInfo));

exit:
    if (error != OT_ERROR_NONE)
    {
        OC_ERR("oc_send_buffer: openthread error %s", otThreadErrorToString(error));
        if (udpMessage != NULL)
        {
            otMessageFree(udpMessage);
        }
        return -1;
    }

    return 0;
}

int oc_connectivity_set_port(uint32_t port)
{
    otCoapPort = port;
}

static void udp_receive_callback(void *context, otMessage *udpMessage, const otMessageInfo *udpMessageInfo)
{
    (void)context;

    oc_message_t *message;
    otError       error = OT_ERROR_NONE;

    message = oc_allocate_message();
    oc_verify_or_exit(message != NULL, error = OT_ERROR_NO_BUFS);

    message->endpoint.device = ocDevice;
    message->endpoint.flags  = IPV6;
#ifdef OC_INOUT_BUFFER_SIZE
    message->length = otMessageRead(udpMessage, otMessageGetOffset(udpMessage), message->data, OC_INOUT_BUFFER_SIZE);
#else
    message->length = otMessageRead(udpMessage, otMessageGetOffset(udpMessage), message->data, OC_PDU_SIZE);
#endif
    message->endpoint.addr.ipv6.port = udpMessageInfo->mPeerPort;
    memcpy(message->endpoint.addr.ipv6.address, udpMessageInfo->mPeerAddr.mFields.m8, 16);

    OC_DBG("Incoming message of size %d bytes from ", message->length);
    OC_LOGipaddr(message->endpoint);
    OC_DBG("\n");

    oc_network_event(message);

exit:
    if (error != OT_ERROR_NONE)
    {
        OC_ERR("udp_receive_callback: openthread error %s", otThreadErrorToString(error));
    }
}

int oc_connectivity_init(size_t device)
{
    otInstance *instance = otGetInstance();
    otError     error    = OT_ERROR_NONE;
    otSockAddr  bindAddr;

    OC_DBG("Initializing connectivity for device %zd", device);

    // We support one device so if this function is called more than
    // once we view that as an error.
    oc_verify_or_exit(!connectivityInitialized, error = OT_ERROR_INVALID_STATE);

    memset(&bindAddr, 0, sizeof(bindAddr));
    bindAddr.mPort = otCoapPort;

    oc_success_or_exit(error = otUdpOpen(instance, &udpSocket, &udp_receive_callback, NULL));

    oc_success_or_exit(error = otUdpBind(instance, &udpSocket, &bindAddr, OT_NETIF_THREAD));

exit:
    if (error != OT_ERROR_NONE)
    {
        OC_ERR("oc_connectivity_init: openthread error %s", otThreadErrorToString(error));
        return -1;
    }

    ocDevice                = device;
    connectivityInitialized = true;
    return 0;
}

void oc_connectivity_shutdown(size_t device)
{
    otInstance *instance = otGetInstance();
    otError     error    = OT_ERROR_NONE;

    OC_DBG("Shutting down connectivity for device %zd", device);

    oc_verify_or_exit((connectivityInitialized && device == ocDevice), error = OT_ERROR_INVALID_STATE);

    oc_success_or_exit(error = otUdpClose(instance, &udpSocket));

exit:
    if (error != OT_ERROR_NONE)
    {
        OC_ERR("oc_connectivity_shutdown: openthread error %s", otThreadErrorToString(error));
        // Fall through and cleanup even when there's an error
    }

    free_endpoints_list();
    memset(&udpSocket, 0, sizeof(udpSocket));
    ocDevice                = 0;
    connectivityInitialized = false;
}

void oc_send_discovery_request(oc_message_t *message)
{
    OC_DBG("oc_send_discovery_request: Outgoing message of size %d bytes to ", message->length);
    OC_LOGipaddr(message->endpoint);
    OC_DBG("\n");

    // We currently only support end devices running in an SoC environment so there
    // should be only one network interface to send the discovery request. This is
    // unlike the linux and wondows examples where the request is sent out over all
    // network interfaces known to the system.
    // TODO: does this need to be sent as a multicast?
    oc_send_buffer(message);
}

#ifdef OC_TCP
void oc_connectivity_end_session(oc_endpoint_t *endpoint)
{
    (void)endpoint;

    // TBD
}
#endif /* OC_TCP */

#ifdef OC_DNS_LOOKUP
#ifdef OC_DNS_CACHE
typedef struct oc_dns_cache_t
{
    struct oc_dns_cache_t *next;
    oc_string_t            domain;
    oc_string_t            ip6Address;
} oc_dns_cache_t;

OC_LIST(dns_cache);
OC_MEMB(dns_s, oc_dns_cache_t, OC_MAX_DNS_CACHE_ENTRIES);

static oc_dns_cache_t *dns_lookup_cache(const char *domain)
{
    oc_dns_cache_t *dnsCacheEntry = NULL;

    if (oc_list_length(dns_cache) > 0)
    {
        oc_dns_cache_t *dnsCacheEntry = (oc_dns_cache_t *)oc_list_head(dns_cache);
        while (dnsCacheEntry != NULL)
        {
            if (strlen(domain) == oc_string_len(dnsCacheEntry->domain)
                && memcmp(domain, oc_string(dnsCacheEntry->domain), oc_string_len(dnsCacheEntry->domain)) == 0)
            {
                break;
            }
            dnsCacheEntry = dnsCacheEntry->next;
        }
    }

    return dnsCacheEntry;
}

static int dns_cache_domain(const char *domain, const char *ip6Address)
{
    oc_dns_cache_t *dnsCacheEntry;
    otError         error = OT_ERROR_NONE;

    dnsCacheEntry = (oc_dns_cache_t *)oc_memb_alloc(&dns_s);
    oc_verify_or_exit(dnsCacheEntry != NULL, error = OT_ERROR_NO_BUFS);

    oc_new_string(&dnsCacheEntry->domain, domain, strlen(domain));
    oc_new_string(&dnsCacheEntry->ip6Address, domain, strlen(ip6Address));
    oc_list_add(dns_cache, dnsCacheEntry);

exit:
    if (error != OT_ERROR_NONE)
    {
        OC_ERR("dns_cache_domain: openthread error %s", otThreadErrorToString(error));
        return -1;
    }

    return 0;
}

static void dns_clear_cache(void)
{
    oc_dns_cache_t *dnsCacheEntry;

    dnsCacheEntry = (oc_dns_cache_t *)oc_list_pop(dns_cache);
    while (dnsCacheEntry != NULL)
    {
        oc_free_string(&dnsCacheEntry->domain);
        oc_free_string(&dnsCacheEntry->ip6Address);
        oc_memb_free(&dns_s, dnsCacheEntry);
        dnsCacheEntry = (oc_dns_cache_t *)oc_list_pop(dns_cache);
    }
}

static void dns_address_callback(otError error, const otDnsAddressResponse *response, void *context)
{
    (void)context;

    char         domain[OT_DNS_MAX_NAME_SIZE];
    otIp6Address ip6Address;
    char         ip6AddressString[OT_IP6_ADDRESS_STRING_SIZE + 3];
    size_t       ip6AddressLen;

    oc_success_or_exit(error);

    oc_success_or_exit(error = otDnsAddressResponseGetHostName(response, domain, sizeof(domain)));

    // We are only using the first address returned
    oc_success_or_exit(error = otDnsAddressResponseGetAddress(response, 0, &ip6Address, NULL));

    // The convention is to add '[' and ']' characters before and after ipV6 addresses
    ip6AddressString[0] = '[';
    otIp6AddressToString(&ip6Address, &ip6AddressString[1], OT_IP6_ADDRESS_STRING_SIZE);
    ip6AddressLen                       = strlen(ip6AddressString);
    ip6AddressString[ip6AddressLen]     = ']';
    ip6AddressString[ip6AddressLen + 1] = '\0';

    dns_cache_domain(domain, ip6AddressString);

    OC_DBG("DNS response for %s - %s", domain, ip6AddressString);

exit:
    if (error != OT_ERROR_NONE)
    {
        OC_ERR("dns_address_callback: openthread error %s", otThreadErrorToString(error));
    }
}
#endif /* OC_DNS_CACHE */

int oc_dns_lookup(const char *domain, oc_string_t *addr, enum transport_flags flags)
{
    (void)flags;

    otInstance     *instance = otGetInstance();
    otError         error    = OT_ERROR_NONE;
    oc_dns_cache_t *dnsCacheEntry;
    otIp6Address    ip6Address;

    oc_verify_or_exit((domain != NULL && addr != NULL), error = OT_ERROR_INVALID_ARGS);

#ifdef OC_DNS_CACHE
    dnsCacheEntry = dns_lookup_cache(domain);
    oc_verify_or_exit(dnsCacheEntry != NULL,
                      error = otDnsClientResolveAddress(instance, domain, &dns_address_callback, NULL, NULL));
#else
    // There's an issue here due to the fact that the KNX IOT api is synchronous but
    // the OT api is asynchronous.  What this means is that if the program needs DNS
    // resolution then it must enable OC_DNS_CACHE and the first call to oc_dns_lookup
    // function for a specific domain will always fail but subsequent calls for the
    // same domain should succeed as long as the OT DNS query has responded and found
    // an address and has it stored in cache.
    oc_assert(false);
#endif /* OC_DNS_CACHE */

exit:
    if (error != OT_ERROR_NONE)
    {
        OC_ERR("oc_dns_lookup: openthread error %s", otThreadErrorToString(error));
        return -1;
    }

    if (dnsCacheEntry == NULL)
    {
        return -1;
    }

    oc_new_string(addr, oc_string(dnsCacheEntry->ip6Address), oc_string_len(dnsCacheEntry->ip6Address));
    return 0;
}
#endif /* OC_DNS_LOOKUP */

static void free_endpoints_list(void)
{
    oc_endpoint_t *ep;

    oc_network_event_handler_mutex_lock();
    ep = oc_list_pop(device_eps_list);
    while (ep != NULL)
    {
        oc_memb_free(&device_eps, ep);
        ep = oc_list_pop(device_eps_list);
    }
    oc_network_event_handler_mutex_unlock();
}

static void refresh_endpoints_list(void)
{
    otInstance           *instance = otGetInstance();
    const otNetifAddress *unicastAddrs;

    free_endpoints_list();

    unicastAddrs = otIp6GetUnicastAddresses(instance);

    // Iterate through the list of unicast addresses and add them to the list of endpoints
    // TODO: check this logic. I think we only need to add the first unicast address
    // for (const otNetifAddress *addr = unicastAddrs; addr; addr = addr->mNext)
    for (const otNetifAddress *addr = unicastAddrs; false; addr = addr->mNext)
    {
        // Allocate a new endpoint
        oc_endpoint_t *ep;
        oc_success_or_exit(ep = oc_memb_alloc(&device_eps));
        memset(ep, 0, sizeof(oc_endpoint_t));

        // Fill in endpoint info
        _Static_assert(sizeof(&addr->mAddress) <= sizeof(ep->addr.ipv6.address));
        memcpy(ep->addr.ipv6.address, &addr->mAddress, sizeof(&addr->mAddress));
        ep->flags |= IPV6;
        ep->addr.ipv6.port  = otCoapPort;
        ep->addr.ipv6.scope = (addr->mScopeOverrideValid) ? addr->mScopeOverride : 0; // TODO: check this logic

        // Add the endpoint to list of endpoints
        oc_network_event_handler_mutex_lock();
        oc_list_add(device_eps_list, ep);
        oc_network_event_handler_mutex_unlock();
    }
exit:
    return;
}

oc_endpoint_t *oc_connectivity_get_endpoints(size_t device)
{
    if (device != ocDevice)
    {
        return NULL;
    }

    if (oc_list_length(device_eps_list) == 0)
    {
        refresh_endpoints_list();
    }

    return oc_list_head(device_eps_list);
}

#ifdef OC_NETWORK_MONITOR
static void remove_all_network_interface_cbs(void)
{
    oc_network_interface_cb_t *cb_item;
    oc_network_interface_cb_t *next;

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexAcquire(network_interface_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    cb_item = oc_list_head(network_interface_cb_list);
    while (cb_item != NULL)
    {
        next = cb_item->next;
        oc_list_remove(network_interface_cb_list, cb_item);
        oc_memb_free(&network_interface_cb_s, cb_item);
        cb_item = next;
    }

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexRelease(network_interface_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)
}

int oc_add_network_interface_event_callback(interface_event_handler_t cb)
{
    if (!cb)
        return -1;

    oc_network_interface_cb_t *cb_item = oc_memb_alloc(&network_interface_cb_s);
    if (!cb_item)
    {
        OC_ERR("network interface callback item alloc failed");
        return -1;
    }

    cb_item->handler = cb;

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexAcquire(network_interface_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    oc_list_add(network_interface_cb_list, cb_item);

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexRelease(network_interface_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    return 0;
}

int oc_remove_network_interface_event_callback(interface_event_handler_t cb)
{
    if (!cb)
        return -1;

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexAcquire(network_interface_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    oc_network_interface_cb_t *cb_item = oc_list_head(network_interface_cb_list);
    while (cb_item != NULL && cb_item->handler != cb)
    {
        cb_item = cb_item->next;
    }

    if (cb_item)
    {
        oc_list_remove(network_interface_cb_list, cb_item);
        oc_memb_free(&network_interface_cb_s, cb_item);
    }

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexRelease(network_interface_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    return 0;
}

void handle_network_interface_event_callback(oc_interface_event_t event)
{
#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexAcquire(network_interface_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    if (oc_list_length(network_interface_cb_list) > 0)
    {
        oc_network_interface_cb_t *cb_item = oc_list_head(network_interface_cb_list);
        while (cb_item)
        {
            cb_item->handler(event);
            cb_item = cb_item->next;
        }
    }

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexRelease(network_interface_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)
}
#endif /* OC_NETWORK_MONITOR */

#ifdef OC_SESSION_EVENTS
static void remove_all_session_event_cbs(void)
{
    oc_session_event_cb_t *cb_item;
    oc_session_event_cb_t *next;

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexAcquire(session_event_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    cb_item = oc_list_head(session_event_cb_list);
    while (cb_item != NULL)
    {
        next = cb_item->next;
        oc_list_remove(session_event_cb_list, cb_item);
        oc_memb_free(&session_event_cb_s, cb_item);
        cb_item = next;
    }

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexRelease(session_event_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)
}

int oc_add_session_event_callback(session_event_handler_t cb)
{
    if (!cb)
        return -1;

    oc_session_event_cb_t *cb_item = oc_memb_alloc(&session_event_cb_s);
    if (!cb_item)
    {
        OC_ERR("session event callback item alloc failed");
        return -1;
    }

    cb_item->handler = cb;

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexAcquire(session_event_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    oc_list_add(session_event_cb_list, cb_item);

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexRelease(session_event_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    return 0;
}

int oc_remove_session_event_callback(session_event_handler_t cb)
{
    if (!cb)
        return -1;

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexAcquire(session_event_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    oc_session_event_cb_t *cb_item = oc_list_head(session_event_cb_list);
    while (cb_item != NULL && cb_item->handler != cb)
    {
        cb_item = cb_item->next;
    }

    if (cb_item)
    {
        oc_list_remove(session_event_cb_list, cb_item);
        oc_memb_free(&session_event_cb_s, cb_item);
    }

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexRelease(session_event_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    return 0;
}

void handle_session_event_callback(const oc_endpoint_t *endpoint, oc_session_state_t state)
{
#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexAcquire(session_event_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)

    if (oc_list_length(session_event_cb_list) > 0)
    {
        oc_session_event_cb_t *cb_item = oc_list_head(session_event_cb_list);
        while (cb_item)
        {
            cb_item->handler(endpoint, state);
            cb_item = cb_item->next;
        }
    }

#if defined(SL_CATALOG_KERNEL_PRESENT)
    osMutexRelease(session_event_cb_mutex);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)
}
#endif // OC_SESSION_EVENTS

void oc_connectivity_subscribe_mcast_ipv6(oc_endpoint_t *address)
{
    otInstance  *instance = otGetInstance();
    otError      error    = OT_ERROR_NONE;
    otIp6Address ip6Address;

    memcpy(ip6Address.mFields.m8, address->addr.ipv6.address, OT_IP6_ADDRESS_SIZE);
    oc_success_or_exit(error = otIp6SubscribeMulticastAddress(instance, &ip6Address));

exit:
    if (error != OT_ERROR_NONE)
    {
        char addressString[OT_IP6_ADDRESS_STRING_SIZE];
        otIp6AddressToString(&ip6Address, addressString, OT_IP6_ADDRESS_STRING_SIZE);
        OC_ERR("oc_connectivity_subscribe_mcast_ipv6: openthread error %s, address: %s",
               otThreadErrorToString(error),
               addressString);
    }
}

void oc_connectivity_unsubscribe_mcast_ipv6(oc_endpoint_t *address)
{
    otInstance  *instance = otGetInstance();
    otError      error    = OT_ERROR_NONE;
    otIp6Address ip6Address;

    memcpy(ip6Address.mFields.m8, address->addr.ipv6.address, OT_IP6_ADDRESS_SIZE);
    oc_success_or_exit(error = otIp6UnsubscribeMulticastAddress(instance, &ip6Address));

exit:
    if (error != OT_ERROR_NONE)
    {
        OC_ERR("oc_connectivity_unsubscribe_mcast_ipv6: openthread error %s", otThreadErrorToString(error));
    }
}

#ifdef OC_TCP
tcp_csm_state_t oc_tcp_get_csm_state(oc_endpoint_t *endpoint)
{
    (void)endpoint;

    // TBD
}

int oc_tcp_update_csm_state(oc_endpoint_t *endpoint, tcp_csm_state_t csm)
{
    (void)endpoint;
    (void)csm;

    // TBD
}
#endif /* OC_TCP */

void oc_network_event_handler_mutex_init(void)
{
#if defined(SL_CATALOG_KERNEL_PRESENT)
    network_event_handler_mutex = osMutexNew(&network_event_handler_mutex_attributes);
    oc_assert(network_event_handler_mutex != NULL);
#ifdef OC_NETWORK_MONITOR
    network_event_handler_mutex = osMutexNew(&network_interface_cb_mutex);
    oc_assert(network_interface_cb_mutex != NULL);
#endif // OC_NETWORK_MONITOR
#endif // defined(SL_CATALOG_KERNEL_PRESENT)
}

void oc_network_event_handler_mutex_lock(void)
{
#if defined(SL_CATALOG_KERNEL_PRESENT)
    osStatus_t error = osMutexAcquire(network_event_handler_mutex, 0);
    oc_assert(error == osOK);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)
}

void oc_network_event_handler_mutex_unlock(void)
{
#if defined(SL_CATALOG_KERNEL_PRESENT)
    osStatus_t error = osMutexRelease(network_event_handler_mutex);
    oc_assert(error == osOK);
#endif // defined(SL_CATALOG_KERNEL_PRESENT)
}

void oc_network_event_handler_mutex_destroy(void)
{
#if defined(SL_CATALOG_KERNEL_PRESENT)
    osStatus_t error = osMutexDelete(network_event_handler_mutex);
    oc_assert(error == osOK);
#ifdef OC_NETWORK_MONITOR
    osStatus_t error = osMutexDelete(network_interface_cb_mutex);
    oc_assert(error == osOK);
    remove_all_network_interface_cbs();
#endif // OC_NETWORK_MONITOR
#ifdef OC_SESSION_EVENTS
    remove_all_session_event_cbs();
#endif // OC_SESSION_EVENTS
#endif // defined(SL_CATALOG_KERNEL_PRESENT)
}
