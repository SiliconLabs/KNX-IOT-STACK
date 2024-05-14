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

add_executable(ot-lightswitch-sensor
    app_sensor.c
    app_common_knx.c
    app_common.c
    main.c
    ${PROJECT_SOURCE_DIR}/deps/ot-efr32/openthread/examples/apps/cli/cli_uart.cpp
)

# Enable PRINT macro for app sources
target_compile_definitions(ot-lightswitch-sensor PRIVATE OC_PRINT)

target_compile_definitions(ot-lightswitch-sensor PRIVATE OC_CLIENT OC_SERVER)

target_include_directories(ot-lightswitch-sensor PRIVATE ${COMMON_INCLUDES})
target_include_directories(ot-lightswitch-sensor PRIVATE
    .
    ${PROJECT_SOURCE_DIR}/deps/ot-efr32/openthread/src/lib/platform
)

if(NOT DEFINED OT_PLATFORM_LIB_FTD)
    set(OT_PLATFORM_LIB_FTD ${OT_PLATFORM_LIB})
endif()
message(STATUS "OT_PLATFORM_LIB_FTD = ${OT_PLATFORM_LIB_FTD}")
message(STATUS "OT_EXTERNAL_MBEDTLS = ${OT_EXTERNAL_MBEDTLS}")
message(STATUS "OT_MBEDTLS = ${OT_MBEDTLS}")

target_link_libraries(ot-lightswitch-sensor PRIVATE
    kisClientServer
    openthread-cli-ftd
    ${OT_PLATFORM_LIB_FTD}
    openthread-ftd
    ${OT_PLATFORM_LIB_FTD}
    openthread-cli-ftd
    kisClientServer
    ${OT_MBEDTLS}
    ot-config-ftd
    ot-config
)

if(OT_LINKER_MAP)
    if("${CMAKE_CXX_COMPILER_ID}" MATCHES "AppleClang")
        target_link_libraries(ot-lightswitch-sensor PRIVATE -Wl,-map,ot-lightswitch-sensor.map)
    else()
        target_link_libraries(ot-lightswitch-sensor PRIVATE -Wl,-Map=ot-lightswitch-sensor.map)
    endif()
endif()

install(TARGETS ot-lightswitch-sensor
    DESTINATION bin)

# Generate S37 file
add_custom_command(TARGET ot-lightswitch-sensor POST_BUILD
    COMMAND arm-none-eabi-objcopy -O srec ot-lightswitch-sensor ot-lightswitch-sensor.s37)