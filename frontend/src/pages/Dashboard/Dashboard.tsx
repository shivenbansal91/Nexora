import React, { useState, useEffect, useRef } from 'react';
import { CorrelationGraph } from '../../components/CorrelationGraph';
import { useLive } from '../../live/LiveContext';
import { toAttackEvent } from '../../live/useChoreography';
import type { AttackEvent } from '../../engine/attackEngine';
import MountainImg from '../../assets/Mountain.png';
import SideGlobeImg from '../../assets/side_globe_dashboard.png';

function formatEvents(n: number): string {
  return n >= 1_000_000 ? `${(n / 1_000_000).toFixed(2)}M` : n.toLocaleString();
}

const SEV_CONFIG = {
  critical: { typeColor: 'text-rose-600',   dot: 'bg-rose-500',   detailColor: 'text-rose-600 font-semibold' },
  high:     { typeColor: 'text-amber-600',  dot: 'bg-amber-400',  detailColor: 'text-slate-500' },
  medium:   { typeColor: 'text-violet-600', dot: 'bg-violet-500', detailColor: 'text-slate-500' },
  info:     { typeColor: 'text-slate-400',  dot: 'bg-slate-300',  detailColor: 'text-slate-400' },
} as const;

const ATTACK_MENU: { key: string; label: string }[] = [
  { key: 'brute_force', label: 'Brute Force' },
  { key: 'port_scan', label: 'Port Scan' },
  { key: 'data_exfiltration', label: 'Data Exfiltration' },
  { key: 'api_abuse', label: 'API Abuse' },
];

function useAnimatedCount(target: number, duration = 600) {
  const [display, setDisplay] = useState(target);
  const prev = useRef(target);
  useEffect(() => {
    const start = prev.current;
    prev.current = target;
    const startTime = performance.now();
    const raf = (now: number) => {
      const p = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(Math.round(start + (target - start) * eased));
      if (p < 1) frame = requestAnimationFrame(raf);
    };
    let frame = requestAnimationFrame(raf);
    return () => cancelAnimationFrame(frame);
  }, [target, duration]);
  return display;
}

const Dashboard: React.FC = () => {
  const { stats, events, latestIncident, injectAttack, connected } = useLive();
  const [isInjecting, setIsInjecting] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  const displayEvents: AttackEvent[] = events.slice(0, 6).map(toAttackEvent);

  const eventCount   = useAnimatedCount(stats.events);
  const anomalyCount = useAnimatedCount(stats.anomalies);
  const threatCount  = useAnimatedCount(stats.active_threats);

  const trigger = async (key?: string) => {
    setMenuOpen(false);
    setIsInjecting(true);
    try { await injectAttack(key); } finally { setIsInjecting(false); }
  };

  return (
    <div className="dashboard-shell">
      <div className="dashboard-hero relative mb-6">
        {/* Giant Globe Watermark */}
        <div className="dashboard-globe pointer-events-none select-none" aria-hidden="true">
          <img src={SideGlobeImg} alt="" className="w-full h-full object-contain"
            style={{ opacity: 0.5, mixBlendMode: 'multiply',
              WebkitMaskImage: 'radial-gradient(circle, black 35%, transparent 68%)',
              maskImage: 'radial-gradient(circle, black 35%, transparent 68%)' }} />
        </div>

        {/* TOP ROW */}
        <div className="dashboard-intro relative z-10">
          <div className="max-w-[400px]">
            <span className="text-[9px] uppercase font-bold tracking-[0.28em] text-slate-400 block mb-3">
              Real-time simulation · threat intelligence
            </span>
            <h1 className="dashboard-title font-serif font-normal tracking-tight text-slate-900">
              See what<br />others miss.
            </h1>
            <p className="text-[13px] text-slate-500 mt-2.5 font-light">
              Uncover hidden connections. Stop attacks before they escalate.
            </p>

            <div className="flex items-end gap-8 mt-7">
              <div>
                <div className="text-[26px] font-bold tracking-tight text-slate-900 tabular-nums">{formatEvents(eventCount)}</div>
                <div className="text-[11px] text-slate-500 mt-0.5 flex items-center gap-1.5">
                  Events <span className="text-[10px] font-mono font-semibold text-emerald-500">live</span>
                </div>
              </div>
              <div>
                <div className="text-[26px] font-bold tracking-tight tabular-nums text-amber-600">{anomalyCount}</div>
                <div className="text-[11px] text-slate-500 mt-0.5 flex items-center gap-1.5">
                  Anomalies <span className="text-[10px] font-mono font-semibold text-amber-500">live</span>
                </div>
              </div>
              <div>
                <div className={`text-[26px] font-bold tracking-tight tabular-nums transition-colors ${threatCount > 0 ? 'text-rose-600' : 'text-slate-900'}`}>{threatCount}</div>
                <div className="text-[11px] text-slate-500 mt-0.5 flex items-center gap-1.5">
                  Incidents <span className="text-[10px] font-mono font-semibold text-rose-500">{threatCount > 0 ? 'recorded' : '—'}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="dashboard-quote max-w-[220px] text-right mt-2 shrink-0">
            <p className="font-serif italic text-[14.5px] text-slate-600 leading-relaxed">
              "It's not just about detecting threats, but understanding how they connect."
            </p>
            <div className="flex items-center justify-end gap-2 mt-3">
              <div className="w-6 h-px bg-slate-400" />
              <span className="text-[7.5px] tracking-[0.22em] font-bold text-slate-400 uppercase">Intelligence Creates Clarity</span>
            </div>
          </div>
        </div>

        {/* GRAPH */}
        <div className="dashboard-network relative z-10">
          <CorrelationGraph incident={latestIncident} />
        </div>

        <div className="dashboard-tagline absolute bottom-14 left-0 z-10 pointer-events-none">
          <p className="font-serif text-[17px] text-slate-700 leading-snug">A clearer view<br />of a safer world.</p>
          <div className="w-6 h-px bg-slate-400 mt-2.5" />
        </div>
      </div>

      {/* BOTTOM — Live Event Stream + Mountain */}
      <section aria-label="Event Telemetry" className="flex flex-col lg:flex-row gap-5">
        <div className="flex-[3] bg-white/90 rounded-3xl border border-slate-200/60 shadow-sm overflow-hidden backdrop-blur-sm">
          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100">
            <div className="flex items-center gap-2.5">
              <span className="relative flex h-2.5 w-2.5">
                <span className={`absolute inline-flex h-full w-full rounded-full ${connected ? 'bg-rose-400 animate-ping' : 'bg-slate-300'} opacity-75`} />
                <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${connected ? 'bg-rose-500' : 'bg-slate-400'}`} />
              </span>
              <h3 className="font-semibold text-[13px] text-slate-900 tracking-tight">Live Event Stream</h3>
              {latestIncident && (
                <span className="ml-1 px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-rose-50 text-rose-600 border border-rose-200 uppercase tracking-wider">
                  {latestIncident.attack_type.replaceAll('_', ' ')}
                </span>
              )}
            </div>

            <div className="flex items-center gap-3">
              {/* Inject-attack dropdown — triggers the real backend pipeline */}
              <div className="relative">
                <button
                  onClick={() => setMenuOpen((o) => !o)}
                  aria-expanded={menuOpen}
                  disabled={isInjecting || !connected}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-[11px] font-semibold border transition-all ${
                    isInjecting
                      ? 'bg-rose-50 text-rose-500 border-rose-200'
                      : 'bg-white text-slate-600 border-slate-200 hover:border-rose-300 hover:text-rose-600 hover:bg-rose-50/60 active:scale-95'
                  }`}
                  title="Inject a scoped attack into the live pipeline"
                >
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                  </svg>
                  {isInjecting ? 'Detecting…' : 'Inject Attack'}
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9" /></svg>
                </button>
                {menuOpen && (
                  <div className="absolute right-0 mt-1 w-48 bg-white border border-slate-200 rounded-xl shadow-xl z-40 overflow-hidden py-1">
                    {ATTACK_MENU.map((a) => (
                      <button key={a.key} onClick={() => trigger(a.key)}
                        className="w-full text-left px-3 py-2 text-[11px] font-medium text-slate-600 hover:bg-rose-50 hover:text-rose-600 transition">
                        {a.label}
                      </button>
                    ))}
                    <div className="border-t border-slate-100 my-1" />
                    <button onClick={() => trigger()} className="w-full text-left px-3 py-2 text-[11px] font-semibold text-slate-500 hover:bg-slate-50">
                      Random attack
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="overflow-x-auto"><table className="w-full text-left">
            <tbody className="divide-y divide-slate-100/80">
              {displayEvents.length === 0 && (
                <tr><td className="px-5 py-6 text-[12px] text-slate-400" colSpan={6}>
                  {connected ? 'Waiting for events…' : 'Connecting to backend…'}
                </td></tr>
              )}
              {displayEvents.map((row, i) => {
                const cfg = SEV_CONFIG[row.severity] ?? SEV_CONFIG.info;
                return (
                  <tr key={row.id} className="hover:bg-slate-50/80 transition-colors cursor-default"
                    style={{ animation: i === 0 ? 'fadeInRow 0.4s ease both' : undefined }}>
                    <td className="px-5 py-3 font-mono text-[11px] text-slate-400 whitespace-nowrap w-[80px]">{row.time}</td>
                    <td className="px-2 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot}`} />
                        <span className={`text-[12px] font-semibold ${cfg.typeColor}`}>{row.label}</span>
                      </div>
                    </td>
                    <td className="px-2 py-3 font-mono text-[11px] text-slate-500 w-[48px]">{row.method ?? '—'}</td>
                    <td className="px-2 py-3 font-mono text-[11px] text-slate-500 truncate max-w-[160px]">{row.path ?? '—'}</td>
                    <td className="px-2 py-3 font-mono text-[11px] text-slate-400 w-[110px]">{row.ip ?? '—'}</td>
                    <td className={`px-2 py-3 text-[12px] ${cfg.detailColor} truncate max-w-[200px] pr-5`}>{row.detail}</td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        </div>

        <div className="flex-1 min-w-[180px] rounded-3xl overflow-hidden relative flex flex-col justify-end border border-slate-200/50 shadow-sm" style={{ minHeight: 240 }}>
          <img src={MountainImg} alt="Mountain" className="absolute inset-0 w-full h-full object-cover" />
          <div className="absolute inset-0 bg-gradient-to-t from-white/95 via-white/40 to-white/10" />
          <div className="relative z-10 p-6">
            <h4 className="font-serif text-[22px] font-normal leading-tight tracking-tight text-slate-900">Turning<br />Data into<br />Security.</h4>
            <div className="w-5 h-px bg-slate-700 mt-3" />
          </div>
        </div>
      </section>

      <style>{`@keyframes fadeInRow { from { opacity: 0; background: rgba(239,68,68,0.05); } to { opacity: 1; background: transparent; } }`}</style>
    </div>
  );
};

export default Dashboard;
