project(knx-iot-stack-deps)

if(EFR32)
    set(OT_PLATFORM external CACHE STRING "OpenThread platform")
    set(OT_FTD ON CACHE BOOL "Full Thread Device")
    set(OT_MTD OFF CACHE BOOL "Minimal Thread Device")
    set(OT_RCP OFF CACHE BOOL "Radio Co-Processor")
    set(OT_APP_RCP OFF CACHE BOOL "Build ot-rcp-* apps")
    set(OT_APP_NCP OFF CACHE BOOL "Build ot-ncp-* apps")
    set(OT_APP_CLI OFF CACHE BOOL "Build ot-cli-* apps")
    set(OT_TCP OFF CACHE BOOL "Enable TCP")

    add_subdirectory(ot-efr32)
endif()

if(KNX_BUILTIN_TINYCBOR)
    add_library(tinycbor-master
        ${PROJECT_SOURCE_DIR}/tinycbor/src/cborerrorstrings.c
        ${PROJECT_SOURCE_DIR}/tinycbor/src/cborencoder.c
        ${PROJECT_SOURCE_DIR}/tinycbor/src/cborencoder_close_container_checked.c
        ${PROJECT_SOURCE_DIR}/tinycbor/src/cborparser.c
        ${PROJECT_SOURCE_DIR}/tinycbor/src/cborpretty.c
    )

    target_include_directories(tinycbor-master PUBLIC
        ${PROJECT_SOURCE_DIR}/tinycbor/src
    )
endif()