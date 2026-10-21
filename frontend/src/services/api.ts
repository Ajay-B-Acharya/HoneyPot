import {
  HealthResponse,
  DashboardStats,
  DeviceStatusResponse,
  PaginatedResponse,
  RequestLog,
  SecurityEvent,
  CreateRequestLogPayload,
  CreateSecurityEventPayload,
} from "../types/api";

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL}${path}`;
  const response = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status} ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (typeof errJson.detail === "string") {
        errorDetail = errJson.detail;
      } else if (Array.isArray(errJson.detail)) {
        errorDetail = errJson.detail
          .map((e: any) => `${e.loc?.join(".") ?? "field"}: ${e.msg}`)
          .join(", ");
      }
    } catch {
      // Body not JSON
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

/** Check backend health */
export async function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

/** Fetch dashboard aggregated statistics */
export async function fetchDashboardStats(): Promise<DashboardStats> {
  return request<DashboardStats>("/stats");
}

/** Fetch status of connected or recorded IoT devices */
export async function fetchDeviceStatuses(): Promise<DeviceStatusResponse> {
  return request<DeviceStatusResponse>("/device/status");
}

/** Fetch paginated security events */
export async function fetchSecurityEvents(params: {
  skip?: number;
  limit?: number;
  severity?: string;
  event_type?: string;
  device_id?: string;
} = {}): Promise<PaginatedResponse<SecurityEvent>> {
  const query = new URLSearchParams();
  if (params.skip !== undefined) query.set("skip", params.skip.toString());
  if (params.limit !== undefined) query.set("limit", params.limit.toString());
  if (params.severity) query.set("severity", params.severity);
  if (params.event_type) query.set("event_type", params.event_type);
  if (params.device_id) query.set("device_id", params.device_id);

  const qs = query.toString();
  return request<PaginatedResponse<SecurityEvent>>(`/events${qs ? `?${qs}` : ""}`);
}

/** Fetch paginated request logs */
export async function fetchRequestLogs(params: {
  skip?: number;
  limit?: number;
  classification?: string;
  device_id?: string;
} = {}): Promise<PaginatedResponse<RequestLog>> {
  const query = new URLSearchParams();
  if (params.skip !== undefined) query.set("skip", params.skip.toString());
  if (params.limit !== undefined) query.set("limit", params.limit.toString());
  if (params.classification) query.set("classification", params.classification);
  if (params.device_id) query.set("device_id", params.device_id);

  const qs = query.toString();
  return request<PaginatedResponse<RequestLog>>(`/logs${qs ? `?${qs}` : ""}`);
}

/** Submit a request log (which evaluates security detection rules on the backend) */
export async function createRequestLog(
  payload: CreateRequestLogPayload
): Promise<RequestLog> {
  return request<RequestLog>("/logs", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/** Manually create a security event */
export async function createSecurityEvent(
  payload: CreateSecurityEventPayload
): Promise<SecurityEvent> {
  return request<SecurityEvent>("/events", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
