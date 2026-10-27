import React, { useEffect, useState } from 'react';
import { api, type MetricsResponse } from '../../api/client';

const Tile: React.FC<{ label: string; value: string; sub?: string; accent?: string }> = ({ label, value, sub, accent }) => (
  <div className="bg-white/90 rounded-2xl border border-slate-200/60 shadow-sm p-5">
    <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">{label}</div>
    <div className={`text-[30px] font-bold tracking-tight tabular-nums mt-1 ${accent ?? 'text-slate-900'}`}>{value}</div>
    {sub && <div className="text-[11px] text-slate-500 mt-0.5">{sub}</div>}
  </div>
);

const pct = (n?: number | null) => (n == null ? '—' : `${(n * 100).toFixed(1)}%`);

const AnalyticsPage: React.FC = () => {
  const [m, setM] = useState<MetricsResponse | null>(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    api.metrics().then(setM).catch(() => setErr(true));
  }, []);

  if (err) return <div className="px-8 py-10 text-[13px] text-slate-400">Backend offline — metrics unavailable.</div>;
  if (!m) return <div className="px-8 py-10 text-[13px] text-slate-400">Loading evaluation metrics…</div>;

  const det = m.detection;
  const anom = det.anomaly_detection;
  const perClass = det.per_class ?? {};

  return (
    <div className="px-8 py-8 max-w-[1200px] mx-auto space-y-6">
      <div className="border-b border-slate-200/80 pb-5">
        <span className="text-[11px] font-mono uppercase tracking-widest text-slate-400 font-semibold">Measured evaluation</span>
        <h1 className="text-3xl font-serif italic text-slate-900 font-normal mt-1">Benchmarks & Metrics</h1>
        <p className="text-xs text-slate-500 mt-1">Detection, classification and correlation performance. Detection numbers are measured; source is labelled.</p>
      </div>

      {/* Headline tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Tile label="Anomaly F1" value={anom ? anom.f1.toFixed(2) : '—'} sub="IsolationForest · attack vs benign" accent="text-indigo-600" />
        <Tile label="Correlation accuracy" value={pct(m.correlation.accuracy)} sub={`${m.correlation.correctly_reconstructed}/${m.correlation.attacks_tested} attacks reconstructed`} accent="text-emerald-600" />
        <Tile label="Benign FPR" value={pct(det.false_positive_rate_benign)} sub="false positives on normal traffic" accent="text-rose-600" />
        <Tile label="Max processing time" value={`${m.runtime.max_detection_latency_seconds.toFixed(3)}s`} sub="observed detection + correlation + storage" />
      </div>

      {/* Honest framing */}
      {det.note && (
        <div className="rounded-2xl bg-amber-50/70 border border-amber-200 p-4 text-[12px] text-amber-800 leading-relaxed">
          <span className="font-bold uppercase tracking-wide text-[10px] mr-2">Source: {det.source ?? 'n/a'}</span>
          {det.note}
        </div>
      )}

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Anomaly detection (the transferable headline) */}
        <div className="bg-white/90 rounded-2xl border border-slate-200/60 shadow-sm p-5">
          <h3 className="text-[12px] font-semibold text-slate-900 mb-1">Anomaly Detection · validation calibrated</h3>
          <p className="text-[11px] text-slate-500 mb-3">{anom?.model ?? 'IsolationForest'} · held-out evaluation.</p>
          <div className="grid grid-cols-3 gap-3">
            <Tile label="Precision" value={anom ? anom.precision.toFixed(2) : '—'} />
            <Tile label="Recall" value={anom ? anom.recall.toFixed(2) : '—'} />
            <Tile label="F1" value={anom ? anom.f1.toFixed(2) : '—'} />
          </div>
          {anom?.preprocessing && <p className="text-[11px] text-slate-500 mt-3">Preprocessing: {anom.preprocessing}. Validation false-positive budget: {pct(anom.validation_fpr_budget)}. Reported scores use the held-out test split.</p>}
        </div>

        {/* Correlation self-check */}
        <div className="bg-white/90 rounded-2xl border border-slate-200/60 shadow-sm p-5">
          <h3 className="text-[12px] font-semibold text-slate-900 mb-1">Correlation · simulated self-check</h3>
          <p className="text-[11px] text-slate-500 mb-3">Each scoped attack injected into benign traffic, reconstructed into one incident.</p>
          <div className="space-y-2">
            {Object.entries(m.correlation.per_type).map(([k, ok]) => (
              <div key={k} className="flex items-center justify-between text-[12px]">
                <span className="font-mono text-slate-600">{k}</span>
                <span className={`font-semibold ${ok ? 'text-emerald-600' : 'text-rose-600'}`}>{ok ? 'reconstructed ✓' : 'missed ✗'}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {det.attack_detection && <div className="bg-white/90 rounded-2xl border border-slate-200/60 p-5">
        <h3 className="text-sm font-semibold mb-2">Supervised attack detection · offline network flows</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Tile label="Precision" value={pct(det.attack_detection.precision)}/>
          <Tile label="Recall" value={pct(det.attack_detection.recall)}/>
          <Tile label="F1" value={pct(det.attack_detection.f1)}/>
          <Tile label="Benign FPR" value={pct(det.attack_detection.false_positive_rate_benign)}/>
        </div>
        <p className="text-[11px] text-slate-500 mt-3">Train: {det.n_train?.toLocaleString()} · validation: {det.n_validation?.toLocaleString()} · test: {det.n_test?.toLocaleString()} flows. Evaluated {det.evaluated_at ? new Date(det.evaluated_at).toLocaleString() : '—'}. The live application-event detector uses a separate feature schema.</p>
      </div>}

      {/* Supervised per-class table */}
      <div className="bg-white/90 rounded-2xl border border-slate-200/60 shadow-sm p-5 overflow-x-auto">
        <h3 className="text-[12px] font-semibold text-slate-900 mb-1">Supervised Classifier — per-class ({det.source})</h3>
        <p className="text-[11px] text-slate-500 mb-3">Macro-F1 {det.macro_f1 ?? '—'} · accuracy {pct(det.accuracy)}. See the source note for dataset and evaluation scope.</p>
        <table className="w-full text-left text-[12px]">
          <thead>
            <tr className="text-[10px] uppercase tracking-widest text-slate-400 border-b border-slate-100">
              <th className="py-2">Class</th><th className="py-2">Precision</th><th className="py-2">Recall</th><th className="py-2">F1</th><th className="py-2">Support</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {Object.entries(perClass).map(([k, v]) => (
              <tr key={k}>
                <td className="py-2 font-mono text-slate-700">{k.replaceAll('ï¿½', '–')}</td>
                <td className="py-2 font-mono">{v.precision.toFixed(3)}</td>
                <td className="py-2 font-mono">{v.recall.toFixed(3)}</td>
                <td className="py-2 font-mono">{v.f1.toFixed(3)}</td>
                <td className="py-2 font-mono text-slate-400">{v.support}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AnalyticsPage;
