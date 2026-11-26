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
        src/ip_profile.c
        src/sequence_detection.c
        src/threat_memory_manager.c
        src/offline_buffer.c
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

include(${SdkRootDirPath}/${board_root}/${board}/wifi_examples/wifi_httpsrv/reconfig.cmake OPTIONAL)

# Explicitly remove fallback single-core linker scripts and enforce RW610_flash.ld
# for all targets (including debug and release) to ensure .smu_cpu13_mbox is placed in
# hardware shared mailbox m_mbox1 @ 0x41380000.
mcux_remove_armgcc_linker_script(
    BASE_PATH ${SdkRootDirPath}
    TARGETS debug release flexspi_nor_debug flexspi_nor_release flash_debug flash_release
    LINKER ${device_root}/Wireless/RW/${CONFIG_MCUX_TOOLCHAIN_LINKER_DEVICE_PREFIX}/gcc/${CONFIG_MCUX_TOOLCHAIN_LINKER_DEVICE_PREFIX}_ram.ld
)
mcux_remove_armgcc_linker_script(
    BASE_PATH ${SdkRootDirPath}
    TARGETS debug release flexspi_nor_debug flexspi_nor_release flash_debug flash_release
    LINKER ${device_root}/Wireless/RW/${CONFIG_MCUX_TOOLCHAIN_LINKER_DEVICE_PREFIX}/gcc/${CONFIG_MCUX_TOOLCHAIN_LINKER_DEVICE_PREFIX}_flash.ld
)
mcux_remove_armgcc_linker_script(
    BASE_PATH ${SdkRootDirPath}
    TARGETS debug release flexspi_nor_debug flexspi_nor_release flash_debug flash_release
    LINKER ${board_root}/${board}/wifi_examples/common/linker/${CONFIG_MCUX_TOOLCHAIN_LINKER_DEVICE_PREFIX}_wifi.ld
)
mcux_add_armgcc_linker_script(
    BASE_PATH ${SdkRootDirPath}
    TARGETS debug release flexspi_nor_debug flexspi_nor_release flash_debug flash_release
    LINKER ${board_root}/${board}/wifi_examples/common/linker/RW610_flash.ld
)

mcux_convert_binary(BINARY ${APPLICATION_BINARY_DIR}/${MCUX_SDK_PROJECT_NAME}.bin)
