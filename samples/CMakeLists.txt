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

option(OT_LIGHTSWITCH_APPS "Build lightswitch applications" ON)
if (OT_LIGHTSWITCH_APPS)
    add_subdirectory(ot-lightswitch)
endif()
