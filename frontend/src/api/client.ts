// REST + WebSocket client for the Nexora backend.
//
// Base URL resolution:
//   - VITE_API_BASE env wins if set (e.g. http://localhost:8000)
//   - else, when running the Vite dev server (port 5173), talk to :8000
//   - else (served by the backend itself) use same-origin ("")

import type { Incident, LiveStats, NexoraEvent } from "../types/nexora";

function resolveBase(): string {
  const env = import.meta.env.VITE_API_BASE as string | undefined;
  if (env !== undefined && env !== "") return env.replace(/\/$/, "");
  if (import.meta.env.DEV && typeof window !== "undefined") {
    return `${window.location.protocol}//${window.location.hostname}:8000`;
  }
  return "";
}

export const API_BASE = resolveBase();

export function wsUrl(path = "/ws/events"): string {
  if (API_BASE) {
    return API_BASE.replace(/^http/, "ws") + path;
  }
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}${path}`;
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => getJSON<{ status: string; ml_models_loaded: boolean }>("/api/health"),
  events: (limit = 50, flaggedOnly = false) =>
    getJSON<NexoraEvent[]>(`/api/events?limit=${limit}&flagged_only=${flaggedOnly}`),
  incidents: (limit = 50) => getJSON<Incident[]>(`/api/incidents?limit=${limit}`),
  incident: (id: string) => getJSON<Incident>(`/api/incidents/${id}`),
  entities: () =>
    getJSON<{ users: string[]; ips: string[]; sessions: string[]; services: string[] }>(
      "/api/entities",
    ),
  metrics: () => getJSON<MetricsResponse>("/api/metrics"),
  attackTypes: () => getJSON<{ attack_types: string[] }>("/api/simulate/attack-types"),
  injectAttack: async (type: string) => {
    const res = await fetch(`${API_BASE}/api/simulate/attack/${type}`, { method: "POST" });
    if (!res.ok) throw new Error(`inject ${type} -> ${res.status}`);
    return res.json() as Promise<{ status: string; attack_type: string; injected: number }>;
  },
};

// ── Metrics response shape (from /api/metrics) ──────────────────────────────
export interface PerClassMetric {
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export interface MetricsResponse {
  detection: {
    source?: string;
    note?: string;
    model?: string;
    macro_f1?: number;
    accuracy?: number;
    n_train?: number;
    n_validation?: number;
    n_test?: number;
    evaluated_at?: string;
    attack_detection?: { precision: number; recall: number; f1: number; false_positive_rate_benign: number };
    false_positive_rate_benign?: number | null;
    labels?: string[];
    per_class?: Record<string, PerClassMetric>;
    anomaly_detection?: {
      model: string;
      threshold: number;
      precision: number;
      recall: number;
      f1: number;
      preprocessing?: string;
      validation_fpr_budget?: number;
    } | null;
    confusion_matrix?: number[][];
  };
  correlation: {
    attacks_tested: number;
    correctly_reconstructed: number;
    accuracy: number;
    per_type: Record<string, boolean>;
  };
  runtime: {
    ml_models_loaded: boolean;
    max_detection_latency_seconds: number;
  } & LiveStats;
}

// ── WebSocket with auto-reconnect ────────────────────────────────────────────
export type WsMessage =
  | { type: "event"; data: NexoraEvent }
  | { type: "incident"; data: Incident }
  | { type: "stats"; data: LiveStats };

export function openEventSocket(
  onMessage: (msg: WsMessage) => void,
  onStatus?: (connected: boolean) => void,
): () => void {
  let ws: WebSocket | null = null;
  let closed = false;
  let retry = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const connect = () => {
    if (closed) return;
    ws = new WebSocket(wsUrl());
    ws.onopen = () => {
      retry = 0;
      onStatus?.(true);
    };
    ws.onmessage = (ev) => {
      try {
        onMessage(JSON.parse(ev.data) as WsMessage);
      } catch {
        /* ignore malformed */
      }
    };
    ws.onclose = () => {
      onStatus?.(false);
      if (closed) return;
      retry = Math.min(retry + 1, 6);
      timer = setTimeout(connect, 500 * retry);
    };
    ws.onerror = () => ws?.close();
  };

  connect();

  return () => {
    closed = true;
    if (timer) clearTimeout(timer);
    ws?.close();
  };
}
