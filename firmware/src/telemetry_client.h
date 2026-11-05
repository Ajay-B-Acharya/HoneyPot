/*
 * IoT Honeypot Monitor — FRDM-RW612 Telemetry Dispatcher Header
 */

#ifndef TELEMETRY_CLIENT_H_
#define TELEMETRY_CLIENT_H_

#include "detection_rules.h"
#include <stdbool.h>

/* Initialize telemetry client queue and FreeRTOS task */
bool Telemetry_Init(void);

/* Enqueue an observed request for backend reporting */
bool Telemetry_Enqueue(const RequestRecord_t *record);

/* Task entry point for FreeRTOS */
void Telemetry_Task(void *param);

#endif /* TELEMETRY_CLIENT_H_ */
