import React, { useState } from 'react';
import { X, Wrench, CheckCircle2, Shield, ArrowRight, Loader2, AlertCircle, FileDiff } from 'lucide-react';
import type { Finding } from '../types';

interface FixAssistantModalProps {
  finding: Finding | null;
  onClose: () => void;
  onApplyAndVerify: (findingId: string) => Promise<void>;
  isApplying: boolean;
}

export const FixAssistantModal: React.FC<FixAssistantModalProps> = ({
  finding,
  onClose,
  onApplyAndVerify,
  isApplying,
}) => {
  const [approvedCopy, setApprovedCopy] = useState(false);

  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-white rounded-3xl border border-surface-border max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-100 bg-[#FAF9F5]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-brand-blue-light text-brand-blue flex items-center justify-center border border-brand-blue-soft">
              <Wrench className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-slate-900">Defensive Fix Assistant</h3>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-brand-blue-light text-brand-blue">
                  {finding.id}
                </span>
              </div>
              <p className="text-xs text-slate-500">
                Proposed minimal patch for <span className="font-mono">{finding.function}()</span>
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Plain-English Explanation */}
          <div className="p-4 rounded-2xl bg-blue-50/70 border border-blue-200">
            <h4 className="text-xs font-bold uppercase text-brand-blue tracking-wider mb-1">
              What does this fix do?
            </h4>
            <p className="text-xs sm:text-sm text-blue-950 leading-relaxed">
              {finding.patch_plain_english}
            </p>
          </div>

          {/* Side-by-side or Unified Diff View */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-1.5">
                <FileDiff className="w-4 h-4 text-brand-blue" />
                <span>Side-by-Side Comparison</span>
              </span>
              <span className="text-[11px] text-slate-400 font-mono">
                {finding.file}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
              {/* Original Code */}
              <div className="rounded-xl border border-red-200 overflow-hidden bg-red-50/30">
                <div className="bg-red-100/70 px-3 py-1.5 text-red-800 font-bold border-b border-red-200 text-[11px] flex justify-between">
                  <span>BEFORE (Vulnerable)</span>
                  <span className="text-red-600">- Removed</span>
                </div>
                <pre className="p-3 text-red-900 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                  <code>{finding.patch_original}</code>
                </pre>
              </div>

              {/* Corrected Code */}
              <div className="rounded-xl border border-emerald-200 overflow-hidden bg-emerald-50/30">
                <div className="bg-emerald-100/70 px-3 py-1.5 text-emerald-800 font-bold border-b border-emerald-200 text-[11px] flex justify-between">
                  <span>AFTER (Defensive Patch)</span>
                  <span className="text-emerald-600">+ Added</span>
                </div>
                <pre className="p-3 text-emerald-900 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                  <code>{finding.patch_corrected}</code>
                </pre>
              </div>
            </div>
          </div>

          {/* Unified Diff Box */}
          {finding.diff && (
            <div>
              <div className="text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
                Standard Unified Patch Diff
              </div>
              <pre className="p-3 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs overflow-x-auto leading-relaxed border border-slate-800">
                {finding.diff.split('\n').map((line, idx) => {
                  const isAdd = line.startsWith('+') && !line.startsWith('+++');
                  const isDel = line.startsWith('-') && !line.startsWith('---');
                  const isHunk = line.startsWith('@@');
                  return (
                    <div
                      key={idx}
                      className={isAdd ? 'text-emerald-400' : isDel ? 'text-red-400' : isHunk ? 'text-blue-400' : 'text-slate-400'}
                    >
                      {line || ' '}
                    </div>
                  );
                })}
              </pre>
            </div>
          )}

          {/* Explicit User Approval Toggle */}
          <div className="p-4 rounded-2xl bg-amber-50 border border-amber-200">
            <label className="flex items-start gap-3 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={approvedCopy}
                onChange={(e) => setApprovedCopy(e.target.checked)}
                className="mt-1 w-4 h-4 rounded text-brand-blue focus:ring-brand-blue border-amber-300"
              />
              <div className="text-xs text-amber-900 leading-relaxed">
                <strong className="font-bold">Required Safety Confirmation:</strong> I approve testing and applying this defensive patch to an <span className="underline font-semibold">isolated working copy</span> in temporary storage. I understand my original repository files will remain 100% untouched.
              </div>
            </label>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-6 border-t border-slate-100 bg-[#FAF9F5] flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2.5 rounded-xl border border-slate-300 text-slate-700 text-xs font-bold hover:bg-slate-100 transition-colors"
          >
            Cancel
          </button>

          <button
            disabled={!approvedCopy || isApplying}
            onClick={async () => {
              await onApplyAndVerify(finding.id);
              onClose();
            }}
            className="inline-flex items-center gap-2 px-6 py-2.5 rounded-xl bg-brand-mint text-white text-xs font-bold shadow-soft hover:bg-emerald-600 active:scale-95 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {isApplying ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Applying & Verifying...</span>
              </>
            ) : (
              <>
                <span>Apply Patch & Run Verification Proof</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
