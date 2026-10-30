import React from 'react';
import { ShieldAlert, ShieldCheck, AlertCircle, CheckCircle2, RefreshCw, FileText, Info } from 'lucide-react';
import type { ScanSummary } from '../types';

interface SafetySummaryProps {
  summary: ScanSummary;
  onViewReport: () => void;
}

export const SafetySummary: React.FC<SafetySummaryProps> = ({ summary, onViewReport }) => {
  const isFullyFixed = summary.fixed === summary.confirmed && summary.confirmed > 0;

  return (
    <div className="bg-white rounded-3xl border border-surface-border p-6 sm:p-8 shadow-card mb-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold uppercase tracking-wider text-brand-blue bg-brand-blue-light px-2.5 py-0.5 rounded-full border border-brand-blue-soft">
              Scan Summary & Status
            </span>
            <span className="text-xs font-semibold text-slate-500">
              Noise Filter Active
            </span>
          </div>
          <h3 className="text-2xl font-black text-slate-900 mt-1">
            {summary.safety_rating}
          </h3>
        </div>

        <button
          onClick={onViewReport}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl border border-slate-200 text-slate-700 font-bold text-xs hover:bg-slate-50 transition-colors"
        >
          <FileText className="w-4 h-4 text-brand-blue" />
          <span>Export Security Report</span>
        </button>
      </div>

      {/* 5 Clean Metrics Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3.5 my-6">
        {/* Candidates */}
        <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 text-center">
          <div className="text-2xl font-black text-slate-800">{summary.candidates}</div>
          <div className="text-xs font-semibold text-slate-500 mt-1">Candidates Found</div>
          <div className="text-[11px] text-slate-400 mt-0.5">Static AST pattern matches</div>
        </div>

        {/* Confirmed Real Flaws */}
        <div className="p-4 rounded-2xl bg-red-50/70 border border-red-200 text-center">
          <div className="text-2xl font-black text-red-600">{summary.confirmed}</div>
          <div className="text-xs font-semibold text-red-800 mt-1">Confirmed Flaws</div>
          <div className="text-[11px] text-red-600/70 mt-0.5">Exploit test succeeded</div>
        </div>

        {/* False Alarms Filtered */}
        <div className="p-4 rounded-2xl bg-emerald-50/70 border border-emerald-200 text-center">
          <div className="text-2xl font-black text-emerald-600">{summary.false_positives}</div>
          <div className="text-xs font-semibold text-emerald-800 mt-1">False Alarms Filtered</div>
          <div className="text-[11px] text-emerald-700/70 mt-0.5">Exploit failed (safe code)</div>
        </div>

        {/* Fixes Verified & Proven */}
        <div className={`p-4 rounded-2xl border text-center transition-all ${
          isFullyFixed
            ? 'bg-emerald-100 border-emerald-300'
            : 'bg-blue-50/70 border-blue-200'
        }`}>
          <div className={`text-2xl font-black ${isFullyFixed ? 'text-emerald-700' : 'text-brand-blue'}`}>
            {summary.fixed} / {summary.confirmed}
          </div>
          <div className={`text-xs font-semibold mt-1 ${isFullyFixed ? 'text-emerald-900' : 'text-blue-900'}`}>
            Fixes Verified
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5">Exploit blocked & tested</div>
        </div>

        {/* Regressions Passed */}
        <div className="p-4 rounded-2xl bg-amber-50/60 border border-amber-200 text-center col-span-2 sm:col-span-1">
          <div className="text-2xl font-black text-amber-700">
            {summary.regressions_passed} / {summary.regressions_total}
          </div>
          <div className="text-xs font-semibold text-amber-900 mt-1">Features Preserved</div>
          <div className="text-[11px] text-amber-700/70 mt-0.5">Legitimate behavior passes</div>
        </div>
      </div>

      {/* Explanatory disclaimer banner */}
      <div className="flex items-start gap-3 p-4 rounded-2xl bg-slate-50 border border-slate-200 text-xs text-slate-600">
        <Info className="w-4 h-4 text-slate-500 flex-shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="font-semibold text-slate-800">Understanding your score:</strong> DAMage CTRL filters out false alarms by running real exploit checks against local fixtures. When you apply and verify a patch, it re-runs both the attack test (which must fail) and your legitimate feature tests (which must pass). Remember: a clean scan is a huge victory, but no automated tool guarantees 100% security against unknown zero-day attacks.
        </p>
      </div>
    </div>
  );
};
