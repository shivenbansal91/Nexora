import { useMemo } from "react";
import type { SimulationState } from "../hooks/useAttackSimulation";
import type { GraphNodeDef, AttackEvent, ThreatInfo } from "../engine/attackEngine";
import type { Incident, NexoraEvent } from "../types/nexora";

// ── event → live-stream row ───────────────────────────────────────────────────
const TYPE_LABEL: Record<string, string> = {
  auth_login_success: "Login Success",
  auth_login_failure: "Auth Failure",
  auth_logout: "Logout",
  api_call: "API Request",
  db_query: "DB Query",
  file_access: "File Access",
  connection_attempt: "Port Probe",
};

const ATTACK_LABEL: Record<string, string> = {
  brute_force: "Brute Force",
  port_scan: "Port Scan",
  data_exfiltration: "Data Exfiltration",
  api_abuse: "API Abuse",
};

function sev(e: NexoraEvent): AttackEvent["severity"] {
  const s = e.anomaly_score ?? e.severity ?? 0;
  if (e.flagged) return s >= 0.8 ? "critical" : "high";
  // Model-only anomalies need review; only detector flags are confirmed alerts.
  if (s >= 0.4) return "medium";
  return "info";
}

function detailFor(e: NexoraEvent): string {
  const m = (e.metadata ?? {}) as Record<string, string | number | boolean>;
  switch (e.event_type) {
    case "auth_login_failure":
      return `401 — failed login (${m.reason ?? "bad credentials"})`;
    case "auth_login_success":
      return m.new_source ? "Successful login from a new source" : "200 — successful login";
    case "db_query":
      return `${m.query_type ?? "SELECT"} on ${m.table ?? "table"}${m.rows ? ` · ${m.rows} rows` : ""}`;
    case "file_access":
      return `${m.action ?? "read"} ${m.path ?? "file"}${m.bytes ? ` · ${fmtBytes(Number(m.bytes))}` : ""}`;
    case "connection_attempt":
      return `probe ${m.dest_host ?? ""}:${m.dest_port ?? ""} (${m.state ?? ""})`;
    case "api_call":
      return `${m.method ?? "GET"} ${m.endpoint ?? "/"} → ${m.status_code ?? 200}`;
    default:
      return e.flagged ? "flagged by detection engine" : "normal event";
  }
}

function fmtBytes(n: number): string {
  if (!n) return "";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(0)}${u[i]}`;
}

function pathFor(e: NexoraEvent): string {
  const m = (e.metadata ?? {}) as Record<string, string | number>;
  if (m.endpoint) return String(m.endpoint);
  if (m.path) return String(m.path);
  if (m.dest_host) return `${m.dest_host}:${m.dest_port ?? ""}`;
  if (m.table) return String(m.table);
  return "—";
}

export function toAttackEvent(e: NexoraEvent): AttackEvent {
  const label = e.flagged && e.attack_label && e.attack_label !== "benign"
    ? ATTACK_LABEL[e.attack_label] ?? "Threat"
    : TYPE_LABEL[e.event_type] ?? e.event_type;
  return {
    id: e.id,
    time: new Date(e.timestamp).toLocaleTimeString("en-US", { hour12: false }),
    severity: sev(e),
    label,
    method: (e.metadata?.method as string) ?? "—",
    path: pathFor(e),
    ip: e.ip,
    detail: detailFor(e),
    delayMs: 0,
  };
}

// ── incident → graph chain ────────────────────────────────────────────────────
function badgeColor(severity: string): string {
  return severity === "critical" ? "rose"
    : severity === "high" ? "amber"
    : severity === "medium" ? "violet" : "indigo";
}

function chainFor(inc: Incident): GraphNodeDef[] {
  const ip = inc.entities.ips[0] ?? "external";
  const user = inc.entities.users[0] ?? "unknown";
  const ipNode: GraphNodeDef = { id: `ip-${ip}`, type: "external_ip", label: ip, sublabel: "External source" };

  switch (inc.attack_type) {
    case "brute_force":
      return [
        ipNode,
        { id: `usr-${user}`, type: "user", label: user, sublabel: "Target account" },
        { id: "srv-auth", type: "server", label: "auth-server", sublabel: "Identity service" },
        { id: "db-prod", type: "database", label: "db-prod-01", sublabel: "Sensitive data" },
      ];
    case "data_exfiltration":
      return [
        ipNode,
        { id: `usr-${user}`, type: "user", label: user, sublabel: "Account" },
        { id: "db-prod", type: "database", label: "db-prod-01", sublabel: "Customer data" },
      ];
    case "port_scan":
      return [
        ipNode,
        { id: "srv-gw", type: "server", label: "api-gateway", sublabel: "Edge gateway" },
        { id: "db-subnet", type: "database", label: "10.0.0.0/24", sublabel: "Scanned hosts" },
      ];
    case "api_abuse": {
      const ep = (inc.events.find((e) => e.metadata?.endpoint)?.metadata?.endpoint as string) ?? "/api";
      return [
        ipNode,
        { id: "api-ep", type: "api", label: ep, sublabel: "Abused endpoint" },
        { id: "srv-gw", type: "server", label: "api-gateway", sublabel: "Rate limiter" },
      ];
    }
    default:
      return [ipNode];
  }
}

function threatFor(inc: Incident): ThreatInfo {
  const subtitle = inc.attack_type === "api_abuse"
    ? (inc.events.find((e) => e.metadata?.endpoint)?.metadata?.endpoint as string) ?? inc.entities.ips[0] ?? ""
    : inc.entities.ips[0] ?? inc.entities.users[0] ?? "";
  return {
    badge: inc.attack_pattern.toUpperCase(),
    badgeColor: badgeColor(inc.severity),
    title: inc.attack_pattern,
    subtitle: String(subtitle),
    confidence: Math.round(inc.confidence * 100),
    relatedEvents: inc.events.length,
    chain: inc.id,
    firstSeen: new Date(inc.timeline.started_at).toLocaleString(),
  };
}

const IDLE: SimulationState = {
  phase: "idle",
  chainNodes: [],
  revealedEdgeCount: 0,
  activeNodeIds: new Set<string>(),
  threatNodeId: null,
  threatInfo: null,
  liveEvents: [],
  statsDeltas: { events: 0, anomalies: 0, threats: 0 },
  scenarioName: null,
};

/**
 * Maps the latest backend incident to the dashboard's display state immediately.
 */
export function useChoreography(latestIncident: Incident | null): SimulationState {
  return useMemo(() => {
    if (!latestIncident) return IDLE;
    const nodes = chainFor(latestIncident);
    return {
      ...IDLE, phase: "resolved", chainNodes: nodes,
      revealedEdgeCount: nodes.length - 1,
      activeNodeIds: new Set(nodes.map(n => n.id)),
      threatNodeId: nodes.at(-1)?.id ?? null,
      threatInfo: threatFor(latestIncident), scenarioName: latestIncident.attack_pattern,
    };
  }, [latestIncident]);
}
