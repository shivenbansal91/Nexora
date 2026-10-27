// Canonical data contract — mirrors p2-pipeline/schema/event_schema.json and
// the backend Pydantic models. This is the single source of truth on the
// frontend; all live data from the backend matches these shapes exactly.

export type EventType =
  | "auth_login_success"
  | "auth_login_failure"
  | "auth_logout"
  | "api_call"
  | "db_query"
  | "file_access"
  | "connection_attempt"
  | "port_scan"
  | "brute_force_attempt"
  | "data_exfiltration"
  | "api_abuse";

export type AttackLabel =
  | "benign"
  | "brute_force"
  | "port_scan"
  | "data_exfiltration"
  | "api_abuse"
  | null;

export type IncidentSeverity = "low" | "medium" | "high" | "critical";

/** One security event, exactly as the backend emits it (severity is a float 0–1). */
export interface NexoraEvent {
  id: string;
  event_type: EventType;
  timestamp: string;
  user: string;
  ip: string;
  session: string;
  severity: number;
  anomaly_score?: number | null;
  attack_label?: AttackLabel;
  flagged?: boolean;
  metadata?: Record<string, string | number | boolean>;
}

export interface EvidenceRow {
  id: string;
  timestamp: string;
  event_type: EventType;
  user?: string;
  ip?: string;
  reason: string;
  score?: number | null;
}

/** A reconstructed incident, exactly as the correlation engine outputs it. */
export interface Incident {
  id: string;
  attack_type: string;
  attack_pattern: string;
  description: string;
  severity: IncidentSeverity;
  severity_score: number;
  confidence: number;
  timeline: { started_at: string; ended_at: string };
  entities: { users: string[]; ips: string[]; sessions: string[] };
  events: NexoraEvent[];
  evidence: EvidenceRow[];
  recommended_action: string;
}

export interface LiveStats {
  events: number;
  anomalies: number;
  active_threats: number;
  ws_clients: number;
  window_size: number;
}
