import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import { useLive } from '../../live/LiveContext';
import { Server, User, Globe, Database } from 'lucide-react';

interface Entities { users: string[]; ips: string[]; sessions: string[]; services: string[]; }

const Column: React.FC<{ title: string; icon: React.ReactNode; items: string[]; accent: string }> = ({ title, icon, items, accent }) => (
  <div className="bg-white/90 rounded-2xl border border-slate-200/60 shadow-sm p-5">
    <div className="flex items-center gap-2 mb-3">
      <span className={`w-7 h-7 rounded-lg flex items-center justify-center ${accent}`}>{icon}</span>
      <h3 className="text-[12px] font-semibold text-slate-900">{title}</h3>
      <span className="ml-auto text-[11px] font-mono text-slate-400">{items.length}</span>
    </div>
    <div className="space-y-1 max-h-[320px] overflow-auto">
      {items.length === 0 && <div className="text-[11px] text-slate-400">none yet</div>}
      {items.map((it) => (
        <div key={it} className="font-mono text-[11px] text-slate-600 px-2 py-1 rounded hover:bg-slate-50 truncate">{it}</div>
      ))}
    </div>
  </div>
);

const InfrastructurePage: React.FC = () => {
  const { stats, connected } = useLive();
  const [ent, setEnt] = useState<Entities>({ users: [], ips: [], sessions: [], services: [] });
  const [error, setError] = useState(false);

  useEffect(() => {
    const load = () => api.entities().then(data => { setEnt(data); setError(false); }).catch(() => setError(true));
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="px-8 py-8 max-w-[1200px] mx-auto space-y-6">
      <div className="border-b border-slate-200/80 pb-5">
        <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 font-semibold">Monitored Environment</span>
        <h1 className="text-3xl font-serif italic text-slate-900 font-normal mt-1">Infrastructure & Entities</h1>
        <p className="text-xs text-slate-500 mt-1">The simulated organisation (ACME-NET) the pipeline watches — entities seen in the recent event window.</p>
      </div>

      {error && <p role="status" className="text-xs text-amber-700">Unable to refresh entities. Showing the last received snapshot; retrying automatically.</p>}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white/90 rounded-2xl border border-slate-200/60 shadow-sm p-5">
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Events processed</div>
          <div className="text-[26px] font-bold tabular-nums mt-1 text-slate-900">{stats.events.toLocaleString()}</div>
        </div>
        <div className="bg-white/90 rounded-2xl border border-slate-200/60 shadow-sm p-5">
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Window size</div>
          <div className="text-[26px] font-bold tabular-nums mt-1 text-slate-900">{stats.window_size}</div>
        </div>
        <div className="bg-white/90 rounded-2xl border border-slate-200/60 shadow-sm p-5">
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Anomalies</div>
          <div className="text-[26px] font-bold tabular-nums mt-1 text-amber-600">{stats.anomalies}</div>
        </div>
        <div className="bg-white/90 rounded-2xl border border-slate-200/60 shadow-sm p-5">
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Pipeline</div>
          <div className={`text-[26px] font-bold mt-1 ${connected ? 'text-emerald-600' : 'text-slate-400'}`}>{connected ? 'Live' : 'Offline'}</div>
        </div>
      </div>

      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Column title="Users" icon={<User className="w-4 h-4 text-blue-600" />} items={ent.users} accent="bg-blue-50" />
        <Column title="Source IPs" icon={<Globe className="w-4 h-4 text-indigo-600" />} items={ent.ips} accent="bg-indigo-50" />
        <Column title="Services" icon={<Server className="w-4 h-4 text-emerald-600" />} items={ent.services} accent="bg-emerald-50" />
        <Column title="Sessions" icon={<Database className="w-4 h-4 text-violet-600" />} items={ent.sessions.slice(0, 40)} accent="bg-violet-50" />
      </div>
    </div>
  );
};

export default InfrastructurePage;
