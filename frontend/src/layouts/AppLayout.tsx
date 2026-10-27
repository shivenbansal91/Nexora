import React from 'react';
import { Outlet, NavLink, Link } from 'react-router-dom';
import WaveImg from './../assets/Wave.png';
import { useLive } from '../live/LiveContext';
import { Bell } from 'lucide-react';

/**
 * AppLayout — Fixed sidebar + fixed topbar, window scrolls naturally.
 * This is required for Lenis root-mode smooth scroll to work.
 * ReactLenis root targets window.scrollY, so the window must be the scroller.
 */
const AppLayout: React.FC = () => {
  const { stats, connected, incidents } = useLive();
  const threatCount = stats.active_threats;
  return (
    <div className="antialiased text-slate-800">

      {/* ── Sidebar (fixed) ── */}
      <aside className="app-sidebar fixed top-0 left-0 bottom-0 w-[220px] flex flex-col justify-between bg-white/70 backdrop-blur-2xl border-r border-slate-200/60 z-40 select-none overflow-hidden">
        
        {/* Wave ambient background — multiply blend makes it feel like part of the wall */}
        <div className="absolute bottom-0 left-0 w-full h-[380px] pointer-events-none select-none z-0" aria-hidden="true">
          <img
            src={WaveImg}
            alt=""
            className="w-full h-full object-cover object-bottom"
            style={{
              opacity: 0.3,
              mixBlendMode: 'multiply',
              filter: 'saturate(0.6) brightness(1.1)',
            }}
          />
        </div>

        {/* Content above the wave */}
        <div className="relative z-10 flex flex-col justify-between h-full">
          {/* Logo */}
          <div className="px-5 pt-6 pb-2">
            <div className="flex items-center gap-2.5 mb-8">
              <div className="h-7 w-7 rounded-lg bg-slate-950 flex items-center justify-center shadow-sm">
                <span className="text-white font-bold text-[13px] font-serif tracking-tight">N</span>
              </div>
              <div>
                <div className="text-[11px] font-extrabold tracking-[0.2em] text-slate-900 uppercase">N E X O R A</div>
                <div className="text-[7.5px] tracking-[0.16em] text-slate-400 font-semibold uppercase">See. Connect. Prevent.</div>
              </div>
            </div>

            <nav className="space-y-0.5">
              {[
                { to: '/dashboard',      label: 'Overview',       icon: 'M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z M9 22V12h6v10' },
                { to: '/live',           label: 'Live Events',    icon: 'M22 12h-4l-3 9L9 3l-3 9H2' },
                { to: '/infrastructure', label: 'Infrastructure', icon: 'M2 3h20v7H2z M2 14h20v7H2z M6 6v.01 M6 17v.01' },
                { to: '/incidents',      label: 'Incidents',      icon: 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z M12 9v4 M12 17h.01' },
                { to: '/correlation',    label: 'Correlation',    icon: 'M18 5a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M6 12a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M18 19a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M8.59 13.51l6.83 3.98 M15.41 6.51l-6.82 3.98' },
                { to: '/analytics',      label: 'Analytics',      icon: 'M18 20V10 M12 20V4 M6 20v-6' },
              ].map(({ to, label, icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  aria-label={label}
                  title={label}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2.5 rounded-xl text-[13px] font-medium transition-all duration-150 ${
                      isActive
                        ? 'bg-white text-slate-900 shadow-sm border border-slate-200/70'
                        : 'text-slate-500 hover:text-slate-800 hover:bg-white/60'
                    }`
                  }
                >
                  {() => (
                    <>
                      <svg className="w-[15px] h-[15px] shrink-0" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" viewBox="0 0 24 24">
                        <path d={icon} />
                      </svg>
                      <span>{label}</span>
                      {label === 'Incidents' && threatCount > 0 && (
                        <span className="ml-auto bg-rose-500 text-white text-[9px] font-bold min-w-4 h-4 px-1 rounded-full flex items-center justify-center">{threatCount}</span>
                      )}
                      {label === 'Live Events' && (
                        <span className={`ml-auto w-1.5 h-1.5 rounded-full ${connected ? 'bg-emerald-500' : 'bg-amber-400'}`}></span>
                      )}
                    </>
                  )}
                </NavLink>
              ))}
            </nav>
          </div>

          {/* Bottom — Settings + tagline */}
          <div className="px-5 pb-6 space-y-4 pt-8">


            <div className="border-t border-slate-200/60 pt-3">
              <p className="font-serif text-[14px] leading-snug text-slate-800">
                Smarter Security<br/>
                <span className="italic text-slate-400 font-light">for a Safer Tomorrow.</span>
              </p>
              <div className="w-5 h-px bg-slate-300 mt-2"></div>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Topbar (fixed) ── */}
      <header className="app-header fixed top-0 left-[220px] right-0 h-14 border-b border-slate-200/60 bg-white/70 backdrop-blur-md px-6 flex items-center justify-between z-30">
<div className="text-[11px] font-semibold tracking-widest uppercase text-indigo-600">Security operations <span className="text-slate-400">/ Live simulation</span></div>
        <div className="flex items-center gap-5">
          <div className="flex items-center gap-1.5 text-[11px] font-medium text-slate-600">
            <span className="relative flex h-1.5 w-1.5">
              <span className={`absolute inline-flex h-full w-full rounded-full ${connected ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'} opacity-75`}></span>
              <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${connected ? 'bg-emerald-500' : 'bg-amber-500'}`}></span>
            </span>
            {connected ? 'Event stream connected' : 'Reconnecting to pipeline…'}
          </div>
          <details className="relative">
            <summary aria-label={`Notifications, ${incidents.length} incidents`} className="relative cursor-pointer list-none p-2 text-slate-700"><Bell size={18}/>{incidents.length > 0 && <span className="absolute -top-1 -right-1 rounded-full bg-rose-500 text-white text-[9px] px-1">{incidents.length}</span>}</summary>
            <div className="absolute right-0 top-10 w-80 max-h-96 overflow-auto bg-white border border-slate-200 shadow-xl rounded-2xl p-3">
              <h2 className="text-sm font-semibold p-2">Detected incidents</h2>
              {incidents.length === 0 && <p className="text-xs text-slate-500 p-2">No incident notifications yet.</p>}
              {incidents.slice(0, 10).map(inc => <Link key={inc.id} to={`/incidents?incident=${encodeURIComponent(inc.id)}`} onClick={event => event.currentTarget.closest('details')?.removeAttribute('open')}
                className="block p-3 hover:bg-indigo-50 rounded-xl text-xs">
                <span className="font-semibold text-slate-900">{inc.attack_pattern}</span>
                <span className="block text-slate-500 mt-1">{inc.severity} · {new Date(inc.timeline.started_at).toLocaleString()}</span>
              </Link>)}
            </div>
          </details>
          <div className="w-px h-4 bg-slate-200"></div>
<span className="text-xs text-slate-500">Analyst workspace</span>
        </div>
      </header>

      {/* ── Page content — offset for fixed sidebar+topbar, window scrolls ── */}
      <div className="app-content ml-[220px] pt-14 min-h-screen">
        <Outlet />
      </div>

    </div>
  );
};

export default AppLayout;
