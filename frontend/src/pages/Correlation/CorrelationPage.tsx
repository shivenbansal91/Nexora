import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { CorrelationGraph } from '../../components/CorrelationGraph';
import { useLive } from '../../live/LiveContext';
import { Globe, User, Database, Zap } from 'lucide-react';

const SEV_DOT: Record<string, string> = {
  critical: 'bg-rose-500', high: 'bg-amber-500', medium: 'bg-violet-500', low: 'bg-cyan-500',
};

const CorrelationPage: React.FC = () => {
  const { incidents, latestIncident, connected, injectAttack } = useLive();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = incidents.find(i => i.id === selectedId) ?? latestIncident;

  return (
    <div className="px-8 py-8 space-y-6 max-w-[1440px] mx-auto">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-slate-200/80 pb-5">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 font-semibold">Threat Intelligence & Graph Analysis</span>
          <h1 className="text-3xl font-serif italic text-slate-900 font-normal mt-1">Event Correlation Topology</h1>
          <p className="text-xs text-slate-500 max-w-xl mt-1">
            Detected events linked by account, session or source IP. Select a node to inspect the evidence and its metadata.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="bg-white/80 border border-slate-200 rounded-2xl px-4 py-2 flex items-center gap-3 text-xs shadow-sm">
            <span className="flex h-2 w-2 relative">
              <span className={`${connected ? 'animate-ping' : ''} absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75`} />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500" />
            </span>
            <span className="font-semibold text-slate-700">{incidents.length} Recorded Correlation{incidents.length === 1 ? '' : 's'}</span>
          </div>
          <button onClick={() => injectAttack()} className="px-4 py-2 rounded-xl text-[12px] font-semibold bg-slate-900 text-white hover:bg-slate-700 transition">
            Inject Attack
          </button>
        </div>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white/80 rounded-3xl border border-slate-200/60 shadow-sm px-4 pt-2 pb-4">
          <CorrelationGraph incident={selected} />
        </div>

        <div className="space-y-3">
          <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Recent correlations</h3>
          {incidents.length === 0 && (
            <div className="rounded-2xl border border-dashed border-slate-200 px-4 py-8 text-center text-[12px] text-slate-400">
              {connected ? 'Inject an attack to populate the graph.' : 'Connecting…'}
            </div>
          )}
          {incidents.slice(0, 8).map((inc) => (
            <motion.button onClick={() => setSelectedId(inc.id)} aria-pressed={selected?.id === inc.id} key={inc.id} initial={{ opacity: 0, x: 8 }} animate={{ opacity: 1, x: 0 }}
              className="w-full text-left rounded-2xl bg-white border border-slate-200/70 shadow-sm p-4">
              <div className="flex items-center gap-2 mb-2">
                <span className={`w-2 h-2 rounded-full ${SEV_DOT[inc.severity] ?? 'bg-slate-400'}`} />
                <span className="font-semibold text-[13px] text-slate-900">{inc.attack_pattern}</span>
                <span className="ml-auto font-mono text-[10px] text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded">{inc.id}</span>
              </div>
              <div className="grid grid-cols-2 gap-y-1 text-[11px] text-slate-500 font-mono">
                <span className="flex items-center gap-1"><Globe className="w-3 h-3" /> {inc.entities.ips[0] ?? '—'}</span>
                <span className="flex items-center gap-1"><User className="w-3 h-3" /> {inc.entities.users[0] ?? '—'}</span>
                <span className="flex items-center gap-1"><Zap className="w-3 h-3" /> {Math.round(inc.confidence * 100)}% conf</span>
                <span className="flex items-center gap-1"><Database className="w-3 h-3" /> {inc.events.length} linked</span>
              </div>
            </motion.button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default CorrelationPage;
