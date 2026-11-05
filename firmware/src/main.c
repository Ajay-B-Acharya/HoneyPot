/*
 * IoT Honeypot Monitor — FRDM-RW612 Embedded Honeypot Firmware Entry Point
 *
 * Implements:
 * - NXP WPL Wi-Fi connectivity
 * - FreeRTOS multitasking
 * - Honeypot decoy HTTP server (port 80)
 * - Edge threat detection (Rule R1 unknown endpoint, R2 rate, R3 repeated probes)
 * - Telemetry reporting to central FastAPI backend
 */

#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"

#include "lwip/tcpip.h"
#include "lwip/netif.h"

#include "board.h"
#include "app.h"
#include "wpl.h"
#include "fsl_debug_console.h"

#include "honeypot_config.h"
#include "detection_rules.h"
#include "honeypot_server.h"
#include "telemetry_client.h"

#include <stdio.h>
#include <string.h>

/* Link state callback */
static void LinkStatusChangeCallback(bool linkState)
{
    if (!linkState) {
        PRINTF("[Wi-Fi] Link Lost! Will attempt automatic reconnect.\r\n");
    } else {
        PRINTF("[Wi-Fi] Link Re-established successfully.\r\n");
    }
}

/* Connect to Access Point */
static bool WiFi_ConnectAP(void)
{
    int32_t result;

    PRINTF("[Wi-Fi] Initializing NXP WPL stack...\r\n");
    result = WPL_Init();
    PRINTF("[Wi-Fi] WPL_Init returned %ld\r\n", (long)result);
    if (result != WPLRET_SUCCESS) {
        PRINTF("[Wi-Fi] WPL_Init failed with code %ld!\r\n", (long)result);
        return false;
    }

    PRINTF("[Wi-Fi] Starting WPL module...\r\n");
    result = WPL_Start(LinkStatusChangeCallback);
    PRINTF("[Wi-Fi] WPL_Start returned %ld\r\n", (long)result);
    if (result != WPLRET_SUCCESS) {
        PRINTF("[Wi-Fi] WPL_Start failed with code %ld!\r\n", (long)result);
        return false;
    }
    PRINTF("[Wi-Fi] WPL module started successfully.\r\n");

    PRINTF("[Wi-Fi] Adding AP network credentials: %s\r\n", HONEYPOT_WIFI_SSID);
    result = WPL_AddNetwork(HONEYPOT_WIFI_SSID, HONEYPOT_WIFI_PASS, HONEYPOT_WIFI_LABEL);
    PRINTF("[Wi-Fi] WPL_AddNetwork returned %ld\r\n", (long)result);
    if (result != WPLRET_SUCCESS) {
        PRINTF("[Wi-Fi] WPL_AddNetwork failed with code %ld!\r\n", (long)result);
        return false;
    }

    PRINTF("[Wi-Fi] Joining network '%s'...\r\n", HONEYPOT_WIFI_SSID);
    result = WPL_Join(HONEYPOT_WIFI_LABEL);
    PRINTF("[Wi-Fi] WPL_Join returned %ld\r\n", (long)result);
    if (result != WPLRET_SUCCESS) {
        PRINTF("[Wi-Fi] Association failed (code %ld). Running in standalone honeypot mode.\r\n", (long)result);
        return false;
    }

    char ip_str[16];
    WPL_GetIP(ip_str, 1);
    PRINTF("[Wi-Fi] Associated successfully! Local IP: %s\r\n", ip_str);
    return true;
}

/* Main supervisor task */
static void Main_Supervisor_Task(void *arg)
{
    (void)arg;

    PRINTF("\r\n=======================================================\r\n");
    PRINTF("  IoT Honeypot Monitor — NXP FRDM-RW612 Firmware\r\n");
    PRINTF("  Device ID   : %s\r\n", HONEYPOT_DEVICE_ID);
    PRINTF("  Firmware    : %s\r\n", HONEYPOT_FW_VERSION);
    PRINTF("  Backend Host: %s:%d\r\n", BACKEND_HOST_IP, BACKEND_HOST_PORT);
    PRINTF("=======================================================\r\n\r\n");

    /* 1. Initialize Edge Detection System */
    Detection_Init();

    /* 2. Initialize Telemetry Dispatcher */
    if (!Telemetry_Init()) {
        PRINTF("[Main] Telemetry initialization failed!\r\n");
    }

    /* 3. Connect to Wi-Fi */
    WiFi_ConnectAP();

    /* 4. Start Telemetry Dispatcher Task */
    BaseType_t status = xTaskCreate(Telemetry_Task,
                                    "telemetry_tx",
                                    2048,
                                    NULL,
                                    configMAX_PRIORITIES - 5,
                                    NULL);
    if (status != pdPASS) {
        PRINTF("[Main] Failed to create Telemetry Dispatcher Task!\r\n");
    }

    /* 5. Start Honeypot HTTP Server Task */
    status = xTaskCreate(Honeypot_Server_Task,
                         "honeypot_srv",
                         2048,
                         NULL,
                         configMAX_PRIORITIES - 4,
                         NULL);
    if (status != pdPASS) {
        PRINTF("[Main] Failed to create Honeypot Server Task!\r\n");
    }

    PRINTF("[Main] All honeypot services active. Awaiting network interactions.\r\n");
    vTaskDelete(NULL);
}

int main(void)
{
    /* Initialize NXP Board Peripherals, Clocks, and UART Debug Console */
    BOARD_InitHardware();

    /* Create Main Supervisor Task */
    if (xTaskCreate(Main_Supervisor_Task,
                    "main_sup",
                    2048,
                    NULL,
                    configMAX_PRIORITIES - 4,
                    NULL) != pdPASS) {
        PRINTF("[Main] Main task creation failed!\r\n");
        for (;;) {
            __BKPT(0);
        }
    }

    /* Start FreeRTOS Kernel Scheduler */
    vTaskStartScheduler();

    /* Execution should never reach here */
    for (;;) {
        ;
    }
}
