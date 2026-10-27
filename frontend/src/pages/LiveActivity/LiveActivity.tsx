import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useLive } from '../../live/LiveContext';
import { toAttackEvent } from '../../live/useChoreography';
import type { AttackEvent } from '../../engine/attackEngine';

type Sev = AttackEvent['severity'];

const SEV_CONFIG: Record<Sev, { label: string; color: string; bg: string; dot: string }> = {
  critical: { label: 'Threat',     color: 'text-rose-600',   bg: 'bg-rose-50',   dot: 'bg-rose-500' },
  high:     { label: 'Anomaly',    color: 'text-amber-600',  bg: 'bg-amber-50',  dot: 'bg-amber-500' },
  medium:   { label: 'Suspicious', color: 'text-violet-600', bg: 'bg-violet-50', dot: 'bg-violet-500' },
  info:     { label: 'Normal',     color: 'text-slate-500',  bg: 'bg-slate-100', dot: 'bg-slate-400' },
};

const FILTERS: (Sev | 'all')[] = ['all', 'critical', 'high', 'medium', 'info'];

const LiveActivityPage: React.FC = () => {
  const { events, connected, injectAttack } = useLive();
  const [filter, setFilter] = useState<Sev | 'all'>('all');
  const [expanded, setExpanded] = useState<string | null>(null);

  const rows = events.map((e) => ({ raw: e, ev: toAttackEvent(e) }));
  const filtered = filter === 'all' ? rows : rows.filter((r) => r.ev.severity === filter);

  return (
    <div className="min-h-screen flex flex-col">
      <div className="flex-shrink-0 px-8 py-6 border-b border-slate-200/60 bg-white/30 backdrop-blur-sm">
        <div className="flex items-end justify-between flex-wrap gap-3">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="relative flex h-2 w-2">
                <span className={`absolute inline-flex h-full w-full rounded-full ${connected ? 'bg-emerald-400 animate-ping' : 'bg-slate-300'} opacity-75`} />
                <span className={`relative inline-flex rounded-full h-2 w-2 ${connected ? 'bg-emerald-500' : 'bg-slate-400'}`} />
              </span>
              <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 font-semibold">
                {connected ? 'Simulated telemetry · streaming' : 'Reconnecting…'}
              </span>
            </div>
            <h1 className="text-3xl font-serif italic text-slate-900 font-normal">Live Event Stream</h1>
            <p className="text-xs text-slate-500 mt-1">Every event the detection engine scores, in real time. Flagged events feed the correlation engine.</p>
          </div>
          <button onClick={() => injectAttack()}
            className="px-4 py-2 rounded-xl text-[12px] font-semibold bg-slate-900 text-white hover:bg-slate-700 transition">
            Inject Random Attack
          </button>
        </div>

        <div className="flex items-center gap-2 mt-4">
          {FILTERS.map((f) => (
            <button key={f} onClick={() => setFilter(f)}
              aria-pressed={filter === f}
              className={`px-3 py-1 rounded-full text-[11px] font-semibold capitalize transition ${
                filter === f ? 'bg-slate-900 text-white' : 'bg-slate-100/80 text-slate-500 hover:bg-slate-200'
              }`}>
              {f === 'all' ? 'All' : SEV_CONFIG[f].label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 px-8 py-5 overflow-auto">
        <div className="bg-white/90 rounded-2xl border border-slate-200/60 shadow-sm overflow-hidden">
          <AnimatePresence initial={false}>
            {filtered.length === 0 && (
              <div className="px-6 py-10 text-center text-[13px] text-slate-400">
                {connected ? 'No events match this filter yet.' : 'Connecting to backend…'}
              </div>
            )}
            {filtered.map(({ raw, ev }) => {
              const cfg = SEV_CONFIG[ev.severity];
              const open = expanded === raw.id;
              return (
                <motion.div key={raw.id} layout
                  initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                  className="border-b border-slate-100 last:border-0">
                  <button onClick={() => setExpanded(open ? null : raw.id)}
                    aria-expanded={open}
                    className="w-full flex items-center gap-4 px-6 py-3 hover:bg-slate-50/70 transition text-left">
                    <span className="font-mono text-[11px] text-slate-400 w-[72px]">{ev.time}</span>
                    <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
                    <span className={`text-[12px] font-semibold w-[130px] ${cfg.color}`}>{ev.label}</span>
                    <span className="font-mono text-[11px] text-slate-500 w-[180px] truncate">{ev.path}</span>
                    <span className="font-mono text-[11px] text-slate-400 w-[110px]">{ev.ip}</span>
                    <span className="text-[12px] text-slate-500 flex-1 truncate">{ev.detail}</span>
                    {raw.flagged && (
                      <span className="text-[9px] font-mono font-bold uppercase bg-rose-50 text-rose-600 border border-rose-200 px-1.5 py-0.5 rounded">flagged</span>
                    )}
                  </button>
                  {open && (
                    <div className="px-6 pb-4 pt-1 bg-slate-50/60 text-[11px] font-mono text-slate-500 grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1">
                      <div><span className="text-slate-400">user:</span> {raw.user}</div>
                      <div><span className="text-slate-400">session:</span> {raw.session.slice(0, 10)}</div>
                      <div><span className="text-slate-400">anomaly:</span> {raw.anomaly_score ?? '—'}</div>
                      <div><span className="text-slate-400">label:</span> {raw.attack_label ?? 'benign'}</div>
                    </div>
                  )}
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
};

export default LiveActivityPage;
