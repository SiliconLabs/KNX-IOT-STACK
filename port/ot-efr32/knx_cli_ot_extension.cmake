# ******************************************************************************
#  # License
#  <b>Copyright 2024 Silicon Laboratories Inc. www.silabs.com</b>
# ******************************************************************************
#
# License: MSLA
#
# The licensor of this software is Silicon Laboratories Inc.
#
# Your use of this software is governed by the terms of the Silicon Labs Master
# Software License Agreement (MSLA) available at
#
# https://www.silabs.com/about-us/legal/master-software-license-agreement
#
# This software is distributed to you in Source Code format and is governed by
# the sections of the MSLA applicable to Source Code.
#
# By installing, copying or otherwise using this software, you agree to the
# terms of the MSLA.
#
# ******************************************************************************

set(KNX_DIR ${CMAKE_CURRENT_LIST_DIR}/../..)
set(KNX_INC_DIR ${KNX_DIR}/include)
set(KNX_PORT_DIR ${KNX_DIR}/port/ot-efr32)

target_compile_definitions(ot-config INTERFACE "OPENTHREAD_CONFIG_CLI_MAX_USER_CMD_ENTRIES=2")

add_library(knx_cli_ot_extension
    ${CMAKE_CURRENT_LIST_DIR}/knx_cli.c
    ${KNX_DIR}/deps/ot-efr32/third_party/silabs/gecko_sdk/protocol/openthread/src/cli/cli_utils.c
    )

target_link_libraries(knx_cli_ot_extension PRIVATE ot-config)
target_link_libraries(knx_cli_ot_extension PRIVATE ${OT_PLATFORM_LIB})
target_link_libraries(knx_cli_ot_extension PRIVATE kisClientServer)

target_include_directories(knx_cli_ot_extension
    PUBLIC
        ${OT_PUBLIC_INCLUDES}
    PRIVATE
        ${KNX_DIR}/deps/ot-efr32/third_party/silabs/gecko_sdk/protocol/openthread/include
        ${KNX_DIR}
        ${KNX_INC_DIR}
        ${KNX_PORT_DIR})

set(OT_CLI_VENDOR_TARGET knx_cli_ot_extension)
