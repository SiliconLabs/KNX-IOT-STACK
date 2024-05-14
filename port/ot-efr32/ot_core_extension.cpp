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

/**
 * @file
 *   This file provides an example on how to implement an OpenThread vendor extension.
 */

#include "openthread-core-config.h"
#include <openthread/cli.h>

#include <stdbool.h>
#include <stdint.h>

#include "common/code_utils.hpp"
#include "common/new.hpp"
#include "instance/extension.hpp"
#include "instance/instance.hpp"

extern "C" {
OT_TOOL_WEAK void app_knx_init(void)
{
    // Intentionally empty.
}
}

namespace ot {
namespace Extension {

/**
 * Defines the vendor extension object.
 *
 */
class Extension : public ExtensionBase
{
public:
    explicit Extension(Instance &aInstance)
        : ExtensionBase(aInstance)
    {
    }

    // TODO: Add vendor extension code (add methods and/or member variables).
};

// ----------------------------------------------------------------------------
// `ExtensionBase` API
// ----------------------------------------------------------------------------

static OT_DEFINE_ALIGNED_VAR(sExtensionRaw, sizeof(Extension), uint64_t);

ExtensionBase &ExtensionBase::Init(Instance &aInstance)
{
    ExtensionBase *ext = reinterpret_cast<ExtensionBase *>(&sExtensionRaw);

    VerifyOrExit(!ext->mIsInitialized);

    ext = new (&sExtensionRaw) Extension(aInstance);

exit:
    return *ext;
}

void ExtensionBase::SignalInstanceInit(void)
{
    // OpenThread instance is initialized and ready.

    // TODO: Implement vendor extension code here and start interaction with OpenThread instance.
}

void ExtensionBase::SignalNcpInit(Ncp::NcpBase &aNcpBase)
{
    // NCP instance is initialized and ready.

    // TODO: Implement vendor extension code here and start interaction with NCP instance.

    OT_UNUSED_VARIABLE(aNcpBase);
}

void ExtensionBase::HandleNotifierEvents(Events aEvents)
{
    static bool knx_initialized = false;

    VerifyOrExit(!knx_initialized);

    if (aEvents.Contains(kEventThreadRoleChanged))
    {
        switch (otThreadGetDeviceRole(reinterpret_cast<otInstance *>(&InstanceLocator::GetInstance())))
        {
        case OT_DEVICE_ROLE_CHILD:
        case OT_DEVICE_ROLE_ROUTER:
        case OT_DEVICE_ROLE_LEADER:
            otCliOutputFormat("Attached to Thread network, initializing KNX\n");
            app_knx_init();
            knx_initialized = true;
            break;
        default:
            break;
        }
    }
exit:
    return;
}

} // namespace Extension
} // namespace ot
