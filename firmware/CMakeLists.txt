#
# IoT Honeypot Monitor — FRDM-RW612 Firmware Build Configuration
#

cmake_minimum_required(VERSION 3.22.0)

include(${SdkRootDirPath}/cmake/extension/mcux.cmake)

project(iot_honeypot LANGUAGES C CXX ASM PROJECT_BOARD_PORT_PATH ${board_root}/${board}/wifi_examples/wifi_httpsrv)

include(${SdkRootDirPath}/CMakeLists.txt)

mcux_add_source(
    SOURCES
        src/main.c
        src/detection_rules.c
        src/honeypot_server.c
        src/telemetry_client.c
        FreeRTOSConfig.h
        lwipopts.h
        lwippools.h
        wifi_config.h
)

mcux_add_source(
    BASE_PATH ${SdkRootDirPath}
    SOURCES
        ${board_root}/${board}/FreeRTOSConfigBoard.h
        ${board_root}/${board}/wifi_examples/common/pin_mux.c
        ${board_root}/${board}/wifi_examples/common/pin_mux.h
)

mcux_add_include(
    INCLUDES
        include
        src
        .
)

mcux_add_include(
    BASE_PATH ${SdkRootDirPath}
    INCLUDES
        ${board_root}/${board}/wifi_examples/common
)

# Macro configuration
mcux_add_macro(
    CC "-DUSE_RTOS=1\
       -DPRINTF_ADVANCED_ENABLE=1"
)

mcux_add_armgcc_linker_script(
    BASE_PATH ${SdkRootDirPath}
    TARGETS debug release flexspi_nor_debug flexspi_nor_release flash_debug flash_release
    LINKER ${board_root}/${board}/wifi_examples/common/linker/${CONFIG_MCUX_TOOLCHAIN_LINKER_DEVICE_PREFIX}_wifi.ld
)

include(${SdkRootDirPath}/${board_root}/${board}/wifi_examples/wifi_httpsrv/reconfig.cmake OPTIONAL)

mcux_convert_binary(BINARY ${APPLICATION_BINARY_DIR}/${MCUX_SDK_PROJECT_NAME}.bin)
