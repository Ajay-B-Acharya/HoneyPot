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
  | "attack_sequence"
  | string;

export type RequestClassification = "normal" | "unusual" | "suspicious";

export type DeviceState =
  | "online"
  | "connection_unstable"
  | "offline"
  | "not_registered"
  | "active"
  | "inactive"
  | "unknown";

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
  last_heartbeat?: string | null;
  last_activity: string | null;
  device_ip?: string | null;
  uptime_seconds?: number | null;
  wifi_connected?: boolean;
  free_heap_bytes?: number | null;
  firmware_version?: string | null;
  heartbeat_seq?: number | null;
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

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface IPProfile {
  id: number;
  ip_address: string;
  device_id: string;
  total_requests: number;
  suspicious_requests: number;
  repeated_requests: number;
  unique_endpoints_count: number;
  unique_endpoints: string[];
  request_frequency: number;
  threat_score: number;
  risk_level: RiskLevel;
  correlation_confidence?: number;
  shared_ip_suspected?: boolean;
  transition_fingerprint?: string | null;
  first_seen: string;
  last_seen: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface IPProfileSummary {
  total_profiles: number;
  active_profiles: number;
  critical_threats: number;
  high_threats: number;
  medium_threats: number;
  low_threats: number;
  top_threat_ip: string | null;
  max_threat_score: number;
}

export interface ThreatEvictionSummary {
  total_evicted_count: number;
  evicted_benign_count: number;
  evicted_suspicious_count: number;
  aggregate_evicted_requests: number;
  aggregate_suspicious_requests: number;
  highest_evicted_threat_score: number;
  last_evicted_ip: string | null;
}

export interface DeviceMemoryStats {
  device_id: string;
  total_security_bss_bytes: number;
  active_profiles: number;
  max_profiles: number;
  profile_bytes_used: number;
  free_heap_bytes: number;
  min_ever_free_heap_bytes: number;
  pressure_level: "normal" | "moderate" | "high" | "critical";
  pending_offline_events: number;
  eviction_summary: ThreatEvictionSummary;
}

export interface BatchSyncResponse {
  received: number;
  inserted: number;
  duplicates: number;
  status: string;
}

export interface EdgeObservation {
  id: number;
  observation_id: string;
  device_id: string;
  source_ip: string;
  endpoint_id: number;
  endpoint: string | null;
  event_timestamp: string;
  sequence_num: number;
  edge_score: number;
  triggered_event: string | null;
  correlation_score: number;
  correlation_confidence: number;
  transition_fingerprint: string | null;
  shared_ip_suspected: boolean;
  derived_event_id?: number | null;
  duplicate?: boolean;
}
