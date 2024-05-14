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

set(COMMON_INCLUDES
    ${OT_PUBLIC_INCLUDES}
    ${PROJECT_SOURCE_DIR}/examples/platforms
    ${PROJECT_SOURCE_DIR}/src/core
)

option(ACTUATOR_APP "Build KNX OT Light Switch Actuator application" ON)
if (ACTUATOR_APP)
    include(actuator.cmake)
endif()

option(SENSOR_APP "Build FTD OT Light Switch Sensor application" ON)
if (SENSOR_APP)
    include(sensor.cmake)
endif()
