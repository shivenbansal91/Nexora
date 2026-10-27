import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { api, openEventSocket } from "../api/client";
import type { Incident, LiveStats, NexoraEvent } from "../types/nexora";

interface LiveContextValue {
  connected: boolean;
  events: NexoraEvent[];
  incidents: Incident[];
  latestIncident: Incident | null;
  stats: LiveStats;
  injectAttack: (type?: string) => Promise<void>;
  attackTypes: string[];
}

const DEFAULT_STATS: LiveStats = {
  events: 0,
  anomalies: 0,
  active_threats: 0,
  ws_clients: 0,
  window_size: 0,
};

const SCOPED_ATTACKS = ["brute_force", "port_scan", "data_exfiltration", "api_abuse"];

const LiveContext = createContext<LiveContextValue | null>(null);

export const LiveProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<NexoraEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [stats, setStats] = useState<LiveStats>(DEFAULT_STATS);
  const [attackTypes, setAttackTypes] = useState<string[]>(SCOPED_ATTACKS);
  const [error, setError] = useState<string | null>(null);

  // Refresh snapshots on every connection, merging live messages that arrive during fetch.
  useEffect(() => {
    const mergeEvents = (incoming: NexoraEvent[], current: NexoraEvent[]) =>
      [...new Map([...incoming, ...current].map(e => [e.id, e])).values()]
        .sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 200);
    const mergeIncidents = (incoming: Incident[], current: Incident[]) =>
      [...new Map([...incoming, ...current].map(i => [i.id, i])).values()]
        .sort((a, b) => b.timeline.started_at.localeCompare(a.timeline.started_at)).slice(0, 100);
    let disposed = false;
    const refresh = () => {
      api.events(200).then(evs => { if (!disposed) setEvents(prev => mergeEvents(evs, prev)); }).catch(() => {});
      api.incidents(100).then(incs => {
        if (!disposed) setIncidents(prev => mergeIncidents(incs, prev));
      }).catch(() => {});
      api.attackTypes().then(r => { if (!disposed) setAttackTypes(r.attack_types); }).catch(() => {});
    };
    const close = openEventSocket(msg => {
      if (msg.type === "event") setEvents(prev => mergeEvents(prev, [msg.data]));
      else if (msg.type === "incident") setIncidents(prev => mergeIncidents(prev, [msg.data]));
      else if (msg.type === "stats") setStats(msg.data);
    }, online => {
      if (disposed) return;
      setConnected(online);
      if (online) refresh();
    });
    return () => { disposed = true; close(); };
  }, []);

  const latestIncident = incidents[0] ?? null;

  const injectAttack = useCallback(
    async (type?: string) => {
      const t = type ?? SCOPED_ATTACKS[Math.floor(Math.random() * SCOPED_ATTACKS.length)];
      setError(null);
      try {
        await api.injectAttack(t);
      } catch {
        setError("Attack injection failed. Check the backend connection and try again.");
      }
    },
    [],
  );

  const value: LiveContextValue = {
    connected,
    events,
    incidents,
    latestIncident,
    stats,
    injectAttack,
    attackTypes,
  };

  return <LiveContext.Provider value={value}>
    {error && <div role="alert" className="fixed bottom-5 right-5 z-50 bg-rose-50 border border-rose-200 text-rose-800 p-4 rounded-xl shadow-lg text-sm">
      {error} <button onClick={() => setError(null)} className="ml-3 underline">Dismiss</button>
    </div>}{children}
  </LiveContext.Provider>;
};

// Context hooks are intentionally colocated with their provider.
// eslint-disable-next-line react-refresh/only-export-components
export function useLive(): LiveContextValue {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive must be used within <LiveProvider>");
  return ctx;
}
