import React from 'react';
import { FileText, Download, Printer, ShieldCheck, CheckCircle2, AlertTriangle, ArrowLeft } from 'lucide-react';
import type { ProjectInfo, ScanResult } from '../types';
import { getPatchedZipDownloadUrl, getPrintableReportUrl } from '../api/client';

interface SecurityReportViewProps {
  project: ProjectInfo | null;
  scanResult: ScanResult | null;
  onBackToWorkspace: () => void;
}

export const SecurityReportView: React.FC<SecurityReportViewProps> = ({
  project,
  scanResult,
  onBackToWorkspace,
}) => {
  if (!project || !scanResult) {
    return (
      <div className="max-w-4xl mx-auto py-12 text-center bg-white rounded-3xl border border-slate-200 p-8 shadow-soft">
        <FileText className="w-12 h-12 text-slate-300 mx-auto mb-3" />
        <h3 className="text-lg font-bold text-slate-800">No active audit report yet</h3>
        <p className="text-xs text-slate-500 mt-1 mb-6">
          Please select or scan a project in the workspace to view and export its security report.
        </p>
        <button
          onClick={onBackToWorkspace}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand-blue text-white text-xs font-bold shadow-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Go to Workspace</span>
        </button>
      </div>
    );
  }

  const s = scanResult.summary;
  const isFullyFixed = s.fixed === s.confirmed && s.confirmed > 0;
  const printableUrl = getPrintableReportUrl(project.id);
  const downloadZipUrl = getPatchedZipDownloadUrl(project.id);

  return (
    <div className="max-w-5xl mx-auto py-4">
      {/* Top action bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-slate-200">
        <div>
          <button
            onClick={onBackToWorkspace}
            className="inline-flex items-center gap-1.5 text-xs font-bold text-slate-500 hover:text-slate-800 mb-2"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Workspace</span>
          </button>
          <h2 className="text-2xl font-black text-slate-900 tracking-tight">Security Audit Report</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Project: <strong className="text-slate-800">{project.name}</strong> &bull; Generated {new Date(scanResult.scanned_at).toLocaleString()}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Printable HTML / Save as PDF */}
          <a
            href={printableUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900 text-white text-xs font-bold hover:bg-slate-800 transition-colors shadow-sm"
          >
            <Printer className="w-4 h-4" />
            <span>Print / Save PDF</span>
          </a>

          {/* Download patched ZIP */}
          <a
            href={downloadZipUrl}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-brand-mint text-white text-xs font-bold hover:bg-emerald-600 transition-colors shadow-soft"
          >
            <Download className="w-4 h-4" />
            <span>Download Patched Project (ZIP)</span>
          </a>
        </div>
      </div>

      {/* Main Report Document Paper */}
      <div className="bg-white rounded-3xl border border-slate-200 p-8 sm:p-12 shadow-card">
        {/* Executive Header */}
        <div className="border-b border-slate-200 pb-8 mb-8 flex flex-col sm:flex-row sm:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2 text-brand-blue font-bold text-xs uppercase tracking-wider mb-2">
              <ShieldCheck className="w-4 h-4 text-brand-mint" />
              <span>Official Verification Certificate</span>
            </div>
            <h3 className="text-3xl font-extrabold text-slate-900 tracking-tight">
              PATCH<span className="text-brand-mint">PROOF</span> Audit Report
            </h3>
            <p className="text-xs text-slate-500 mt-1 max-w-xl">
              Deterministic source-code security scan, noise filtering, and sandboxed patch verification proof.
            </p>
          </div>

          <div className="p-4 rounded-2xl bg-[#FAF9F5] border border-cream-200 text-center sm:text-right min-w-[180px]">
            <div className="text-xs font-semibold text-slate-400 uppercase">Overall Safety Rating</div>
            <div className="text-2xl font-black text-slate-900 mt-1">{s.safety_percentage}%</div>
            <div className="text-[11px] font-bold text-brand-mint mt-0.5">
              {isFullyFixed ? '100% Verified Safe' : `${s.fixed}/${s.confirmed} Fixes Proven`}
            </div>
          </div>
        </div>

        {/* 4 Stats Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
          <div className="p-4 rounded-2xl bg-slate-50 border border-slate-200 text-center">
            <div className="text-2xl font-black text-slate-800">{s.candidates}</div>
            <div className="text-xs font-semibold text-slate-500 mt-1">Candidates Identified</div>
          </div>
          <div className="p-4 rounded-2xl bg-red-50 border border-red-200 text-center">
            <div className="text-2xl font-black text-red-600">{s.confirmed}</div>
            <div className="text-xs font-semibold text-red-800 mt-1">Confirmed Flaws</div>
          </div>
          <div className="p-4 rounded-2xl bg-emerald-50 border border-emerald-200 text-center">
            <div className="text-2xl font-black text-emerald-600">{s.false_positives}</div>
            <div className="text-xs font-semibold text-emerald-800 mt-1">False Alarms Filtered</div>
          </div>
          <div className="p-4 rounded-2xl bg-blue-50 border border-blue-200 text-center">
            <div className="text-2xl font-black text-brand-blue">{s.fixed}</div>
            <div className="text-xs font-semibold text-blue-900 mt-1">Fixes Verified</div>
          </div>
        </div>

        {/* Findings List */}
        <div className="space-y-6 mb-8">
          <h4 className="text-base font-bold text-slate-900 uppercase tracking-wider text-xs border-b border-slate-100 pb-2">
            Detailed Verified Findings & Patches
          </h4>

          {scanResult.findings.map((f) => {
            const isProven = f.fixed && f.verified_status === 'fixed_verified';
            return (
              <div
                key={f.id}
                className="p-5 rounded-2xl border border-slate-200 bg-slate-50/50 space-y-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-200 text-slate-700">
                      {f.id}
                    </span>
                    <strong className="text-sm text-slate-900">{f.title}</strong>
                  </div>
                  <span className={`text-[11px] font-bold px-2.5 py-0.5 rounded-full ${
                    isProven
                      ? 'bg-emerald-100 text-emerald-800'
                      : f.status === 'confirmed'
                      ? 'bg-red-100 text-red-800'
                      : 'bg-blue-100 text-blue-800'
                  }`}>
                    {isProven ? 'PATCH PROVEN' : f.status === 'confirmed' ? 'CONFIRMED' : 'FILTERED'}
                  </span>
                </div>

                <div className="text-xs text-slate-600">
                  <span className="font-semibold text-slate-700">Location:</span> {f.file}:{f.line} &bull; <span className="font-semibold text-slate-700">Function:</span> {f.function}() &bull; <span className="font-semibold text-slate-700">CWE:</span> {f.cwe}
                </div>

                <div className="p-3 rounded-xl bg-purple-50 text-xs text-purple-900 leading-relaxed border border-purple-100">
                  <strong>Analogy:</strong> {f.eli12.analogy_story}
                </div>

                {f.diff && (
                  <div>
                    <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-1">
                      Applied Patch Unified Diff:
                    </div>
                    <pre className="p-3 rounded-xl bg-slate-900 text-slate-200 font-mono text-xs overflow-x-auto leading-relaxed">
                      {f.diff}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Disclaimer & Limitations */}
        <div className="p-5 rounded-2xl bg-slate-100 text-slate-600 text-xs leading-relaxed">
          <strong className="text-slate-800 block mb-1">Security Limitations & Disclaimer:</strong>
          DAMage CTRL verifies source-code vulnerability remediation against reproducible, deterministic test cases. Passing all tests confirms that targeted attack patterns and feature regressions have succeeded in isolated sandboxes. However, automated testing cannot guarantee immunity against all possible unknown vulnerabilities, system misconfigurations, or operational risks.
        </div>
      </div>
    </div>
  );
};
