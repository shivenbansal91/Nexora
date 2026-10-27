import { useState, type CSSProperties } from 'react';
import { Link } from 'react-router-dom';
import { Globe2, UserRound, Database, FileText, Server, ShieldAlert, Network, ArrowRight } from 'lucide-react';
import type { Incident } from '../types/nexora';

const icons = [Globe2, UserRound, ShieldAlert, Server, Database, FileText, Network];
const kinds = ['Source IP', 'User account', 'Authentication', 'API endpoint', 'Database', 'File', 'Target host'];
const positions = [[32, 20], [20, 56], [52, 42], [70, 61], [49, 76], [79, 25], [83, 78]];

export const CorrelationGraph = ({ incident }: { incident?: Incident | null }) => {
  const [selectedId, setSelectedId] = useState('');
  const [eventId, setEventId] = useState('');
  const nodes = new Map<string, { id: string; label: string; kind: string; ids: string[] }>();
  const add = (kind: string, label: string, id: string) => {
    const key = `${kind}:${label}`;
    if (!nodes.has(key)) nodes.set(key, { id: key, label, kind, ids: [] });
    nodes.get(key)!.ids.push(id);
  };
  for (const e of incident?.events ?? []) {
    if (e.ip) add('Source IP', e.ip, e.id);
    if (e.user && e.user !== 'unknown') add('User account', e.user, e.id);
    const m = e.metadata ?? {};
    if (e.event_type.startsWith('auth_')) add('Authentication', 'Account access', e.id);
    if (m.endpoint) add('API endpoint', String(m.endpoint), e.id);
    if (m.table) add('Database', String(m.table), e.id);
    if (m.path) add('File', String(m.path), e.id);
    if (m.dest_host) add('Target host', String(m.dest_host), e.id);
  }
  const all = [...nodes.values()];
  const selected = nodes.get(selectedId) ?? all.find(n => n.kind !== 'Source IP' && n.kind !== 'User account') ?? all[0];
  const evidence = incident?.evidence.filter(e => selected?.ids.includes(e.id)) ?? [];
  const event = evidence.find(e => e.id === eventId) ?? evidence[0];
  const raw = incident?.events.find(e => e.id === event?.id);
  const visible = all.slice(0, 7);
  return <section className="entity-graph" aria-label="Correlation evidence graph">
    <div className="entity-map">
      <div className="graph-caption">ENTITY RELATIONSHIPS <span>{incident ? `${all.length} entities · ${incident.events.length} events` : 'Awaiting a detected incident'}</span></div>
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="entity-orbits" aria-hidden="true">
        <defs><linearGradient id="evidence-link"><stop stopColor="#a78bfa"/><stop offset="1" stopColor="#f87171"/></linearGradient></defs>
        {[22, 33, 44].map(r => <ellipse key={r} cx="50" cy="52" rx={r} ry={r} fill="none" stroke="#cbd5e1" strokeWidth=".12"/>)}
        {visible.slice(1).map((n, i) => { const [x,y] = positions[i + 1]; return <path key={n.id} d={`M32 20 Q${x + 14} ${y - 20} ${x} ${y}`} fill="none" stroke="url(#evidence-link)" strokeWidth=".35"/>; })}
        {[[8,38],[17,20],[45,8],[91,48],[28,87],[63,94],[94,15]].map(([x,y]) => <g key={x}><circle cx={x} cy={y} r="1.6" fill="#e0e7ff"/><circle cx={x} cy={y} r=".6" fill="#c7d2fe"/></g>)}
      </svg>
      {visible.map((n, i) => {
        const Icon = icons[kinds.indexOf(n.kind)] ?? Network;
        const [x,y] = positions[i];
        return <button key={n.id} className={`entity-node ${selected?.id === n.id ? 'selected' : ''}`} style={{ left:`${x}%`, top:`${y}%`, '--node-color': n.kind === 'Source IP' ? '#8b5cf6' : n.kind === 'User account' ? '#3b82f6' : ['Database','Authentication','File'].includes(n.kind) ? '#ef4444' : '#a855f7' } as CSSProperties}
          onClick={() => { setSelectedId(n.id); setEventId(''); }} aria-pressed={selected?.id === n.id} aria-label={`${n.kind}: ${n.label}, ${n.ids.length} related events`}>
          <span className="entity-icon"><Icon size={27} strokeWidth={1.6}/></span><span className="entity-label" title={n.label}>{n.kind === 'File' ? n.label.split('/').pop() : n.label}<small>{n.kind} · {n.ids.length} events</small></span>
        </button>;
      })}
      {!incident && <div className="graph-empty"><ShieldAlert size={38}/><h3>Follow the evidence.</h3><p>Inject a simulated attack to reveal its connected entities.</p></div>}
      <p className="graph-footnote">Shared incident evidence · select an entity to inspect</p>
    </div>
    <aside className="entity-inspector" aria-live="polite">
      <div className="inspector-status"><ShieldAlert size={15}/> {incident ? incident.severity + ' severity' : 'Monitoring simulation'}</div>
      <h3>{incident?.attack_type.replaceAll('_', ' ') ?? 'A clearer view of your security.'}</h3>
      <p className="text-xs text-slate-500 leading-relaxed">{incident?.description ?? 'Connected events become an evidence trail. No incident is shown until the correlation engine reconstructs one.'}</p>
      {incident && <><dl className="inspector-facts"><div><dt>Confidence</dt><dd>{Math.round(incident.confidence * 100)}%</dd></div><div><dt>Related events</dt><dd>{incident.events.length}</dd></div><div><dt>First seen</dt><dd>{new Date(incident.timeline.started_at).toLocaleTimeString()}</dd></div></dl>
        {selected && <div className="node-evidence"><strong>{selected.label}</strong><small>{selected.kind}</small>
          {evidence.length > 0 && <select aria-label="Related evidence event" value={event?.id ?? ''} onChange={e => setEventId(e.target.value)}>{evidence.map(e => <option key={e.id} value={e.id}>{new Date(e.timestamp).toLocaleTimeString()} · {e.event_type.replaceAll('_',' ')}</option>)}</select>}
          <p>{event?.reason ?? 'Linked through the same incident.'}</p>
          {raw?.metadata && <dl className="node-metadata">{Object.entries(raw.metadata).map(([k,v]) => <div key={k}><dt>{k.replaceAll('_',' ')}</dt><dd>{String(v)}</dd></div>)}</dl>}
        </div>}
        <Link className="investigate-link" to={`/incidents?incident=${encodeURIComponent(incident.id)}`}>Investigate <ArrowRight size={16}/></Link>
      </>}
    </aside>
    {all.length > 7 && <div className="extra-entities">{all.slice(7).map(n => <button key={n.id} onClick={() => {setSelectedId(n.id); setEventId('');}}>{n.kind}: {n.label}</button>)}</div>}
  </section>;
};
export default CorrelationGraph;
