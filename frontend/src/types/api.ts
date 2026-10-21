/**
 * IoT Honeypot Monitor — API TypeScript Type Definitions
 * Directly corresponds to the backend Pydantic schemas and API contracts.
 */

export interface HealthResponse {
  status: string;
  service: string;
}

export type EventSeverity = "informational" | "warning" | "critical";

export type SecurityEventType =
  | "unknown_endpoint"
  | "high_request_rate"
  | "repeated_requests"
  | string;

export type RequestClassification = "normal" | "unusual" | "suspicious";

export type DeviceState = "active" | "inactive" | "unknown";

export interface RequestLog {
  id: number;
  timestamp: string; // ISO 8601 UTC
  device_id: string;
  source_ip: string | null;
  method: string;
  endpoint: string;
  response_code: number | null;
  classification: RequestClassification;
  created_at: string;
}

export interface SecurityEvent {
  id: number;
  timestamp: string; // ISO 8601 UTC
  device_id: string;
  event_type: string;
  severity: EventSeverity;
  description: string;
  source_ip: string | null;
  request_count: number | null;
  time_window_seconds: number | null;
  metadata: Record<string, any> | null;
  created_at: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  skip: number;
  limit: number;
}

export interface EventsBySeverity {
  informational: number;
  warning: number;
  critical: number;
}

export interface RequestsByClassification {
  normal: number;
  unusual: number;
  suspicious: number;
}

export interface DashboardStats {
  total_requests: number;
  normal_requests: number;
  unusual_requests: number;
  suspicious_requests: number;
  total_security_events: number;
  events_by_severity: EventsBySeverity;
  requests_by_classification: RequestsByClassification;
}

export interface DeviceStatusItem {
  device_id: string;
  status: DeviceState;
  last_seen: string | null;
  last_activity: string | null;
}

export interface DeviceStatusResponse {
  devices: DeviceStatusItem[];
}

export interface CreateRequestLogPayload {
  timestamp: string;
  device_id: string;
  source_ip?: string | null;
  method: string;
  endpoint: string;
  response_code?: number | null;
  classification?: RequestClassification;
}

export interface CreateSecurityEventPayload {
  timestamp: string;
  device_id: string;
  event_type: string;
  severity: EventSeverity;
  description: string;
  source_ip?: string | null;
  request_count?: number | null;
  time_window_seconds?: number | null;
  metadata?: Record<string, any> | null;
}
