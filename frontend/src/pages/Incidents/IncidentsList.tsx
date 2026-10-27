import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronRight, Clock, Shield, Target, Users } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';
import { useLive } from '../../live/LiveContext';
import type { Incident, IncidentSeverity } from '../../types/nexora';

const SEV: Record<IncidentSeverity, { color: string; bg: string; border: string; text: string; label: string }> = {
  critical: { color: '#ef4444', bg: 'bg-rose-50',   border: 'border-rose-200',   text: 'text-rose-600',   label: 'Critical' },
  high:     { color: '#f59e0b', bg: 'bg-amber-50',  border: 'border-amber-200',  text: 'text-amber-600',  label: 'High' },
  medium:   { color: '#8b5cf6', bg: 'bg-violet-50', border: 'border-violet-200', text: 'text-violet-600', label: 'Medium' },
  low:      { color: '#06b6d4', bg: 'bg-cyan-50',   border: 'border-cyan-200',   text: 'text-cyan-600',   label: 'Low' },
};

const fmt = (iso: string) => {
  try { return new Date(iso).toLocaleString('en-US', { hour12: false }); } catch { return iso; }
};

const IncidentCard: React.FC<{ inc: Incident; open: boolean; onToggle: () => void }> = ({ inc, open, onToggle }) => {
  const cfg = SEV[inc.severity] ?? SEV.low;
  return (
    <motion.div layout className={`rounded-2xl border ${cfg.border} bg-white/90 shadow-sm overflow-hidden`}>
      <button onClick={onToggle} className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-slate-50/60 transition">
        <span className={`w-9 h-9 rounded-xl ${cfg.bg} flex items-center justify-center shrink-0`}>
          <Shield className="w-4 h-4" style={{ color: cfg.color }} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="font-semibold text-[14px] text-slate-900 truncate">{inc.attack_pattern}</h3>
            <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${cfg.bg} ${cfg.text} border ${cfg.border}`}>{cfg.label}</span>
          </div>
          <p className="text-[11px] text-slate-500 truncate mt-0.5">{inc.description}</p>
        </div>
        <div className="hidden md:flex items-center gap-6 text-[11px] text-slate-500 font-mono shrink-0">
          <span className="flex items-center gap-1"><Target className="w-3 h-3" /> {inc.events.length} evts</span>
          <span className="flex items-center gap-1"><Shield className="w-3 h-3" /> {Math.round(inc.confidence * 100)}%</span>
          <span className="text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded">{inc.id}</span>
        </div>
        <ChevronRight className={`w-4 h-4 text-slate-400 transition-transform ${open ? 'rotate-90' : ''}`} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
            className="border-t border-slate-100 overflow-hidden">
            <div className="px-5 py-4 grid lg:grid-cols-3 gap-5">
              {/* Evidence chain */}
              <div className="lg:col-span-2">
                <h4 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">Reconstructed evidence chain</h4>
                <ol className="relative border-l border-slate-200 ml-2 space-y-2">
                  {inc.evidence.map((ev, i) => (
                    <li key={ev.id} className="ml-4">
                      <span className="absolute -left-[5px] w-2.5 h-2.5 rounded-full" style={{ background: cfg.color }} />
                      <div className="flex items-center gap-2 text-[11px]">
                        <span className="font-mono text-slate-400">{new Date(ev.timestamp).toLocaleTimeString('en-US', { hour12: false })}</span>
                        <span className="font-semibold text-slate-700">{ev.reason}</span>
                        {i > 0 && <span className="text-[9px] font-mono text-indigo-500">↳ linked</span>}
                        {ev.score != null && <span className="ml-auto font-mono text-slate-400">score {Number(ev.score).toFixed(2)}</span>}
                      </div>
                    </li>
                  ))}
                </ol>
              </div>

              {/* Side panel */}
              <div className="space-y-3">
                <div className="text-[11px] space-y-1.5">
                  <div className="flex items-center gap-2 text-slate-500"><Clock className="w-3 h-3" /> {fmt(inc.timeline.started_at)}</div>
                  <div className="flex items-center gap-2 text-slate-500"><Users className="w-3 h-3" /> {inc.entities.users.join(', ') || '—'}</div>
                  <div className="font-mono text-slate-400">IPs: {inc.entities.ips.join(', ') || '—'}</div>
                </div>
                <div className={`rounded-xl ${cfg.bg} border ${cfg.border} p-3`}>
                  <div className="text-[9px] font-bold uppercase tracking-widest text-slate-500 mb-1">Recommended action</div>
                  <p className="text-[11px] text-slate-700 leading-relaxed">{inc.recommended_action}</p>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

const IncidentsPage: React.FC = () => {
  const { incidents, injectAttack, connected } = useLive();
  const [params, setParams] = useSearchParams();
  const openId = params.get('incident');

  return (
    <div className="px-8 py-8 max-w-[1200px] mx-auto space-y-5">
      <div className="flex items-end justify-between border-b border-slate-200/80 pb-5 flex-wrap gap-3">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 font-semibold">Incident Response</span>
          <h1 className="text-3xl font-serif italic text-slate-900 font-normal mt-1">Reconstructed Incidents</h1>
          <p className="text-xs text-slate-500 mt-1">
            {incidents.length} incident{incidents.length === 1 ? '' : 's'} assembled from correlated events — not a pile of independent alerts.
          </p>
        </div>
        <button onClick={() => injectAttack()} className="px-4 py-2 rounded-xl text-[12px] font-semibold bg-slate-900 text-white hover:bg-slate-700 transition">
          Inject Random Attack
        </button>
      </div>

      {incidents.length === 0 && (
        <div className="rounded-2xl border border-dashed border-slate-200 bg-white/60 px-6 py-12 text-center">
          <p className="text-[13px] text-slate-500">
            {connected ? 'No incidents yet — inject an attack to see one reconstructed live.' : 'Connecting to backend…'}
          </p>
        </div>
      )}

      <div className="space-y-3">
        {incidents.map((inc) => (
          <IncidentCard key={inc.id} inc={inc} open={openId === inc.id} onToggle={() => setParams(openId === inc.id ? {} : { incident: inc.id })} />
        ))}
      </div>
    </div>
  );
};

export default IncidentsPage;
